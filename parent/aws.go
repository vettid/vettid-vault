package parent

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/aws/smithy-go"
)

// AWSConfig configures the AWS backends.
type AWSConfig struct {
	Region      string
	Credentials aws.CredentialsProvider
	// Endpoint overrides every service endpoint (LocalStack in tests).
	Endpoint string
	// Bucket is the vault data bucket.
	Bucket string
	// Table names (vettid.org SSM refs data/vaults-table-name, ...).
	VaultsTable, InstancesTable, RequestsTable string
	// DLQARN is the dead-letter queue for the instance queue (optional).
	DLQARN string
	// EmulateConditionalDelete replaces S3's If-Match delete by a
	// compare-then-delete (not atomic) where the service does not
	// implement it (LocalStack). Never set against AWS.
	EmulateConditionalDelete bool
	HTTPClient               *http.Client
}

// AWS implements Objects, Queues and Tables with the AWS SDK. It is the
// only part of the vault code base that links the SDK; the enclave never
// does (make check-tcb).
type AWS struct {
	cfg AWSConfig
	s3  *s3.Client
	sqs *sqs.Client
	ddb *dynamodb.Client
}

var (
	_ Objects = (*AWS)(nil)
	_ Queues  = (*AWS)(nil)
	_ Tables  = (*AWS)(nil)
)

// NewAWS builds the clients.
func NewAWS(c AWSConfig) (*AWS, error) {
	if c.Region == "" || c.Credentials == nil || c.Bucket == "" || c.VaultsTable == "" || c.InstancesTable == "" || c.RequestsTable == "" {
		return nil, ErrConfig
	}
	ac := aws.Config{Region: c.Region, Credentials: c.Credentials,
		RequestChecksumCalculation: aws.RequestChecksumCalculationWhenRequired,
		ResponseChecksumValidation: aws.ResponseChecksumValidationWhenRequired}
	if c.HTTPClient != nil {
		ac.HTTPClient = c.HTTPClient
	}
	a := &AWS{cfg: c}
	a.s3 = s3.NewFromConfig(ac, func(o *s3.Options) {
		if c.Endpoint != "" {
			o.BaseEndpoint = aws.String(c.Endpoint)
			o.UsePathStyle = true
		}
	})
	a.sqs = sqs.NewFromConfig(ac, func(o *sqs.Options) {
		if c.Endpoint != "" {
			o.BaseEndpoint = aws.String(c.Endpoint)
		}
	})
	a.ddb = dynamodb.NewFromConfig(ac, func(o *dynamodb.Options) {
		if c.Endpoint != "" {
			o.BaseEndpoint = aws.String(c.Endpoint)
		}
	})
	return a, nil
}

func apiCode(err error) string {
	var ae smithy.APIError
	if errors.As(err, &ae) {
		return ae.ErrorCode()
	}
	return ""
}

// errClass reduces an SDK error to its API code (SDK errors can carry
// request ids and URLs, never our payloads, but the code is all the logs
// need).
func errClass(op string, err error) error {
	if c := apiCode(err); c != "" {
		return errors.New(op + ": " + c)
	}
	return errors.New(op + ": request failed")
}

// --- S3 ---

// MaxObject bounds an object read for the enclave.
const MaxObject = 48 << 20

// Get implements Objects.
func (a *AWS) Get(ctx context.Context, key string) ([]byte, string, error) {
	out, err := a.s3.GetObject(ctx, &s3.GetObjectInput{Bucket: &a.cfg.Bucket, Key: &key})
	if err != nil {
		switch apiCode(err) {
		case "NoSuchKey", "NotFound":
			return nil, "", ErrNotFound
		}
		return nil, "", errClass("s3 get", err)
	}
	defer out.Body.Close()
	b, err := io.ReadAll(io.LimitReader(out.Body, MaxObject+1))
	if err != nil || len(b) > MaxObject || out.ETag == nil {
		return nil, "", errors.New("s3 get: bad body")
	}
	return b, *out.ETag, nil
}

func conflict(err error) bool {
	switch apiCode(err) {
	case "PreconditionFailed", "ConditionalRequestConflict":
		return true
	}
	return false
}

// Put implements Objects: If-None-Match "*" for create-only, If-Match on
// the ETag otherwise.
func (a *AWS) Put(ctx context.Context, key string, data []byte, ifMatch string) (string, error) {
	in := &s3.PutObjectInput{Bucket: &a.cfg.Bucket, Key: &key, Body: bytes.NewReader(data), ContentLength: aws.Int64(int64(len(data))),
		ContentType: aws.String("application/octet-stream")}
	if ifMatch == "" {
		in.IfNoneMatch = aws.String("*")
	} else {
		in.IfMatch = aws.String(ifMatch)
	}
	out, err := a.s3.PutObject(ctx, in)
	if err != nil {
		if conflict(err) {
			return "", ErrConflict
		}
		if ifMatch != "" && apiCode(err) == "NoSuchKey" {
			return "", ErrConflict
		}
		return "", errClass("s3 put", err)
	}
	if out.ETag == nil {
		return "", errors.New("s3 put: no etag")
	}
	return *out.ETag, nil
}

// Delete implements Objects (conditional on the ETag).
func (a *AWS) Delete(ctx context.Context, key, ifMatch string) error {
	in := &s3.DeleteObjectInput{Bucket: &a.cfg.Bucket, Key: &key}
	if ifMatch == "" {
		return ErrConflict
	}
	if a.cfg.EmulateConditionalDelete {
		h, err := a.s3.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &a.cfg.Bucket, Key: &key})
		if err != nil {
			switch apiCode(err) {
			case "NoSuchKey", "NotFound":
				return ErrNotFound
			}
			return errClass("s3 head", err)
		}
		if aws.ToString(h.ETag) != ifMatch {
			return ErrConflict
		}
	} else {
		in.IfMatch = aws.String(ifMatch)
	}
	if _, err := a.s3.DeleteObject(ctx, in); err != nil {
		if conflict(err) {
			return ErrConflict
		}
		switch apiCode(err) {
		case "NoSuchKey", "NotFound":
			return ErrNotFound
		}
		return errClass("s3 delete", err)
	}
	return nil
}

// --- SQS ---

// Create implements Queues: retention 5 min (§11.5), visibility 120 s,
// long polling, and a redrive to the DLQ after 3 receives.
func (a *AWS) Create(ctx context.Context, name string) (string, error) {
	attrs := map[string]string{
		string(sqstypes.QueueAttributeNameMessageRetentionPeriod):        "300",
		string(sqstypes.QueueAttributeNameVisibilityTimeout):             "120",
		string(sqstypes.QueueAttributeNameReceiveMessageWaitTimeSeconds): "20",
		string(sqstypes.QueueAttributeNameSqsManagedSseEnabled):          "true",
	}
	if a.cfg.DLQARN != "" {
		attrs[string(sqstypes.QueueAttributeNameRedrivePolicy)] = `{"deadLetterTargetArn":"` + a.cfg.DLQARN + `","maxReceiveCount":"3"}`
	}
	out, err := a.sqs.CreateQueue(ctx, &sqs.CreateQueueInput{QueueName: &name, Attributes: attrs})
	if err != nil {
		return "", errClass("sqs create", err)
	}
	return *out.QueueUrl, nil
}

// Receive implements Queues (long poll, up to 10 messages).
func (a *AWS) Receive(ctx context.Context, url string) ([]QueueMessage, error) {
	out, err := a.sqs.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{QueueUrl: &url, MaxNumberOfMessages: 10, WaitTimeSeconds: 20})
	if err != nil {
		return nil, errClass("sqs receive", err)
	}
	msgs := make([]QueueMessage, 0, len(out.Messages))
	for _, m := range out.Messages {
		if m.Body == nil || m.ReceiptHandle == nil {
			continue
		}
		msgs = append(msgs, QueueMessage{ID: aws.ToString(m.MessageId), Body: []byte(*m.Body), Receipt: *m.ReceiptHandle})
	}
	return msgs, nil
}

// DeleteMessage implements Queues.
func (a *AWS) DeleteMessage(ctx context.Context, url, receipt string) error {
	_, err := a.sqs.DeleteMessage(ctx, &sqs.DeleteMessageInput{QueueUrl: &url, ReceiptHandle: &receipt})
	if err != nil {
		return errClass("sqs delete", err)
	}
	return nil
}

// Destroy implements Queues.
func (a *AWS) Destroy(ctx context.Context, url string) error {
	if _, err := a.sqs.DeleteQueue(ctx, &sqs.DeleteQueueInput{QueueUrl: &url}); err != nil {
		return errClass("sqs delete queue", err)
	}
	return nil
}

// List implements Queues.
func (a *AWS) List(ctx context.Context, prefix string) (map[string]time.Time, error) {
	out := map[string]time.Time{}
	var next *string
	for {
		r, err := a.sqs.ListQueues(ctx, &sqs.ListQueuesInput{QueueNamePrefix: &prefix, NextToken: next, MaxResults: aws.Int32(1000)})
		if err != nil {
			return nil, errClass("sqs list", err)
		}
		for _, u := range r.QueueUrls {
			at, err := a.sqs.GetQueueAttributes(ctx, &sqs.GetQueueAttributesInput{QueueUrl: aws.String(u),
				AttributeNames: []sqstypes.QueueAttributeName{sqstypes.QueueAttributeNameCreatedTimestamp}})
			if err != nil {
				continue
			}
			sec, err := strconv.ParseInt(at.Attributes[string(sqstypes.QueueAttributeNameCreatedTimestamp)], 10, 64)
			if err != nil {
				continue
			}
			out[u] = time.Unix(sec, 0)
		}
		if r.NextToken == nil {
			return out, nil
		}
		next = r.NextToken
	}
}

// --- DynamoDB (shapes of vettid.org lambda/member/vault.ts) ---

func s(v string) ddbtypes.AttributeValue { return &ddbtypes.AttributeValueMemberS{Value: v} }
func n(v int64) ddbtypes.AttributeValue {
	return &ddbtypes.AttributeValueMemberN{Value: strconv.FormatInt(v, 10)}
}

func isoNow(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }

func condFailed(err error) bool { return apiCode(err) == "ConditionalCheckFailedException" }

// PutInstance implements Tables.
func (a *AWS) PutInstance(ctx context.Context, r InstanceRow) error {
	_, err := a.ddb.PutItem(ctx, &dynamodb.PutItemInput{TableName: &a.cfg.InstancesTable, Item: map[string]ddbtypes.AttributeValue{
		"instance_id":  s(r.InstanceID),
		"release":      s(r.Release),
		"queue_url":    s(r.QueueURL),
		"descriptor":   s(base64.StdEncoding.EncodeToString(r.Descriptor)),
		"attestation":  s(base64.StdEncoding.EncodeToString(r.Attestation)),
		"heartbeat_at": n(r.HeartbeatAt),
		"expires_at":   n(r.ExpiresAt),
		"load":         n(int64(r.Load)),
	}})
	if err != nil {
		return errClass("ddb put instance", err)
	}
	return nil
}

// DeleteInstance implements Tables.
func (a *AWS) DeleteInstance(ctx context.Context, id string) error {
	_, err := a.ddb.DeleteItem(ctx, &dynamodb.DeleteItemInput{TableName: &a.cfg.InstancesTable,
		Key: map[string]ddbtypes.AttributeValue{"instance_id": s(id)}})
	if err != nil {
		return errClass("ddb delete instance", err)
	}
	return nil
}

// InstanceHeartbeat implements Tables.
func (a *AWS) InstanceHeartbeat(ctx context.Context, id string) (int64, error) {
	out, err := a.ddb.GetItem(ctx, &dynamodb.GetItemInput{TableName: &a.cfg.InstancesTable,
		Key: map[string]ddbtypes.AttributeValue{"instance_id": s(id)}})
	if err != nil {
		return 0, errClass("ddb get instance", err)
	}
	hb, ok := out.Item["heartbeat_at"].(*ddbtypes.AttributeValueMemberN)
	if !ok {
		return 0, ErrNotFound
	}
	return strconv.ParseInt(hb.Value, 10, 64)
}

func leaseValue(instanceID string, expires int64) ddbtypes.AttributeValue {
	return &ddbtypes.AttributeValueMemberM{Value: map[string]ddbtypes.AttributeValue{"instance_id": s(instanceID), "lease_expires_at": n(expires)}}
}

var leaseNames = map[string]string{"#lease": "lease", "#iid": "instance_id", "#exp": "lease_expires_at"}

// names returns the lease placeholders an expression uses plus extra
// (DynamoDB rejects unused placeholders).
func names(expr string, extra map[string]string) map[string]string {
	m := map[string]string{}
	for k, v := range leaseNames {
		if strings.Contains(expr, k) {
			m[k] = v
		}
	}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

func (a *AWS) updateVault(ctx context.Context, id, update, cond string, nm map[string]string, vals map[string]ddbtypes.AttributeValue) error {
	_, err := a.ddb.UpdateItem(ctx, &dynamodb.UpdateItemInput{TableName: &a.cfg.VaultsTable, Key: map[string]ddbtypes.AttributeValue{"vault_id": s(id)},
		UpdateExpression: &update, ConditionExpression: &cond, ExpressionAttributeNames: nm, ExpressionAttributeValues: vals})
	if err != nil {
		if condFailed(err) {
			return ErrLeaseHeld
		}
		return errClass("ddb update vault", err)
	}
	return nil
}

// AcquireLease implements Tables: absent, expired or already ours (§11.1).
func (a *AWS) AcquireLease(ctx context.Context, vaultID, instanceID string, now, expires int64) error {
	const cond = "attribute_exists(vault_id) AND (attribute_not_exists(#lease) OR #lease.#exp <= :now OR #lease.#iid = :me)"
	return a.updateVault(ctx, vaultID, "SET #lease = :l, #u = :u", cond, names(cond, map[string]string{"#u": "updated_at"}),
		map[string]ddbtypes.AttributeValue{":l": leaseValue(instanceID, expires), ":u": s(isoNow(time.Unix(now, 0))), ":now": n(now), ":me": s(instanceID)})
}

// Lease implements Tables.
func (a *AWS) Lease(ctx context.Context, vaultID string) (string, int64, error) {
	out, err := a.ddb.GetItem(ctx, &dynamodb.GetItemInput{TableName: &a.cfg.VaultsTable, ConsistentRead: aws.Bool(true),
		Key: map[string]ddbtypes.AttributeValue{"vault_id": s(vaultID)}})
	if err != nil {
		return "", 0, errClass("ddb get vault", err)
	}
	l, ok := out.Item["lease"].(*ddbtypes.AttributeValueMemberM)
	if !ok {
		return "", 0, nil
	}
	iid, _ := l.Value["instance_id"].(*ddbtypes.AttributeValueMemberS)
	exp, _ := l.Value["lease_expires_at"].(*ddbtypes.AttributeValueMemberN)
	if iid == nil || exp == nil {
		return "", 0, nil
	}
	e, err := strconv.ParseInt(exp.Value, 10, 64)
	if err != nil {
		return "", 0, err
	}
	return iid.Value, e, nil
}

// TakeoverLease implements Tables.
func (a *AWS) TakeoverLease(ctx context.Context, vaultID, me, oldInstance string, oldExpires, expires int64) error {
	const cond = "attribute_exists(vault_id) AND #lease.#iid = :old AND #lease.#exp = :oldexp"
	return a.updateVault(ctx, vaultID, "SET #lease = :l", cond, names(cond, nil),
		map[string]ddbtypes.AttributeValue{":l": leaseValue(me, expires), ":old": s(oldInstance), ":oldexp": n(oldExpires)})
}

// RenewLease implements Tables.
func (a *AWS) RenewLease(ctx context.Context, vaultID, instanceID string, expires int64) error {
	const cond = "attribute_exists(vault_id) AND #lease.#iid = :me"
	return a.updateVault(ctx, vaultID, "SET #lease = :l", cond, names(cond, nil),
		map[string]ddbtypes.AttributeValue{":l": leaseValue(instanceID, expires), ":me": s(instanceID)})
}

// ReleaseLease implements Tables: removes this instance's lease (and the
// unlocked state with it).
func (a *AWS) ReleaseLease(ctx context.Context, vaultID, instanceID string, now time.Time) error {
	const cond = "attribute_exists(vault_id) AND #lease.#iid = :me"
	return a.updateVault(ctx, vaultID, "SET #u = :u REMOVE #lease", cond, names(cond, map[string]string{"#u": "updated_at"}),
		map[string]ddbtypes.AttributeValue{":u": s(isoNow(now)), ":me": s(instanceID)})
}

// Lifecycle implements Tables (§11.5). Only the lease holder (or anyone
// while no lease exists) writes lifecycle values, so a vault's loser in
// a split brain cannot overwrite the winner's.
func (a *AWS) Lifecycle(ctx context.Context, ev Lifecycle, instanceID string, now time.Time) error {
	const cond = "attribute_exists(vault_id) AND (attribute_not_exists(#lease) OR #lease.#iid = :me)"
	nm := names(cond, map[string]string{"#u": "updated_at", "#vv": "vault_version", "#sv": "state_version"})
	vals := map[string]ddbtypes.AttributeValue{":u": s(isoNow(now)), ":me": s(instanceID), ":vv": s(ev.VaultVersion), ":sv": n(int64(ev.StateVersion))}
	var update string
	switch ev.Event {
	case "enrolled", "moved":
		nm["#sr"] = "sealed_release"
		vals[":sr"] = s(ev.Release)
		update = "SET #sr = :sr, #vv = :vv, #sv = :sv, #u = :u"
	case "unlocked":
		nm["#st"] = "state"
		vals[":st"] = s("unlocked")
		update = "SET #st = :st, #vv = :vv, #sv = :sv, #u = :u"
	case "locked", "deleted":
		nm["#st"] = "state"
		vals[":st"] = s(ev.Event)
		update = "SET #st = :st, #vv = :vv, #sv = :sv, #u = :u REMOVE #lease"
	default:
		return nil
	}
	err := a.updateVault(ctx, ev.VaultID, update, cond, nm, vals)
	if errors.Is(err, ErrLeaseHeld) {
		return nil // another instance holds the vault now
	}
	return err
}

// WriteSlot implements Tables: only a slot still queued is answered.
func (a *AWS) WriteSlot(ctx context.Context, requestID string, sl Slot) error {
	update := "SET #s = :st"
	vals := map[string]ddbtypes.AttributeValue{":st": s(sl.Status), ":q": s("queued")}
	if len(sl.Envelope) > 0 {
		update += ", envelope = :e"
		vals[":e"] = s(base64.StdEncoding.EncodeToString(sl.Envelope))
	}
	if sl.Code != "" {
		update += ", code = :c"
		vals[":c"] = s(sl.Code)
	}
	cond := "attribute_exists(request_id) AND #s = :q"
	_, err := a.ddb.UpdateItem(ctx, &dynamodb.UpdateItemInput{TableName: &a.cfg.RequestsTable,
		Key: map[string]ddbtypes.AttributeValue{"request_id": s(requestID)}, UpdateExpression: &update, ConditionExpression: &cond,
		ExpressionAttributeNames: map[string]string{"#s": "status"}, ExpressionAttributeValues: vals})
	if err != nil && !condFailed(err) {
		return errClass("ddb write slot", err)
	}
	return nil
}

// ProviderCredentials hands an SDK credentials provider's credentials to
// the enclave (the instance role in production).
type ProviderCredentials struct{ P aws.CredentialsProvider }

// Retrieve implements CredentialSource.
func (p ProviderCredentials) Retrieve(ctx context.Context) (Credentials, error) {
	c, err := p.P.Retrieve(ctx)
	if err != nil {
		return Credentials{}, errClass("credentials", err)
	}
	out := Credentials{AccessKeyID: c.AccessKeyID, SecretAccessKey: c.SecretAccessKey, SessionToken: c.SessionToken}
	if c.CanExpire {
		out.Expires = c.Expires
	}
	return out, nil
}
