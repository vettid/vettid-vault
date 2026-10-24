package parent

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
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

	"github.com/vettid/vettid-vault/internal/hostproto"
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
	// QueuePolicy is the instance queue's access policy (vettid.org SSM
	// vault/control-queue-policy: SendMessage for the member API's roles
	// in their account). Create refuses to make a queue without it.
	QueuePolicy string
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

// MaxVersion is the longest version (the S3 ETag) of a stored object that
// the enclave accepts in a StoreGet reply (VAULT-HOST-PROTOCOL §5.2).
const MaxVersion = 256

// storeGetReplyOverhead is what a StoreGet reply [status, data, version]
// adds to the object it carries: the frame's kind, id and field count,
// the three fields' lengths, the status "ok" and a version of up to
// MaxVersion bytes (hostproto's frame layout; a test compares it with
// what Frame.Marshal accepts).
const storeGetReplyOverhead = (1 + 8 + 2) + 3*4 + len(hostproto.StatusOK) + MaxVersion

// MaxObject is the largest stored object: the largest that a StoreGet
// reply can carry to the enclave, whatever its version. The parent
// neither reads nor writes a larger one (a StorePut frame could carry a
// few more bytes than a reply can), so every object it has written can
// be read back, and what no reply could carry is not read into memory.
const MaxObject = hostproto.MaxFrame - storeGetReplyOverhead

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
	b, err := io.ReadAll(io.LimitReader(out.Body, int64(MaxObject)+1))
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
// long polling, a redrive to the DLQ after 3 receives, and vettid.org's
// queue policy. Without a policy it fails closed (ErrConfig, no call).
func (a *AWS) Create(ctx context.Context, name string) (string, error) {
	if a.cfg.QueuePolicy == "" {
		return "", fmt.Errorf("%w: no control-queue policy", ErrConfig)
	}
	attrs := map[string]string{
		string(sqstypes.QueueAttributeNameMessageRetentionPeriod):        "300",
		string(sqstypes.QueueAttributeNameVisibilityTimeout):             "120",
		string(sqstypes.QueueAttributeNameReceiveMessageWaitTimeSeconds): "20",
		string(sqstypes.QueueAttributeNameSqsManagedSseEnabled):          "true",
		string(sqstypes.QueueAttributeNamePolicy):                        a.cfg.QueuePolicy,
	}
	if a.cfg.DLQARN != "" {
		attrs[string(sqstypes.QueueAttributeNameRedrivePolicy)] = `{"deadLetterTargetArn":"` + a.cfg.DLQARN + `","maxReceiveCount":"3"}`
	}
	out, err := a.sqs.CreateQueue(ctx, &sqs.CreateQueueInput{QueueName: &name, Attributes: attrs})
	if err != nil {
		if queueDeletedRecently(err) {
			return "", fmt.Errorf("%w: %w", ErrQueueDeletedRecently, errClass("sqs create", err))
		}
		return "", errClass("sqs create", err)
	}
	return *out.QueueUrl, nil
}

// queueDeletedRecently reports SQS's refusal to recreate a queue within
// 60 s of its deletion (the JSON protocol's code, or the query-compatible
// one).
func queueDeletedRecently(err error) bool {
	var qd *sqstypes.QueueDeletedRecently
	if errors.As(err, &qd) {
		return true
	}
	switch apiCode(err) {
	case "QueueDeletedRecently", "AWS.SimpleQueueService.QueueDeletedRecently":
		return true
	}
	return false
}

// queueNotFound reports SQS's answer for a queue that does not exist
// (the JSON protocol's code, or the query-compatible one).
func queueNotFound(err error) bool {
	var qn *sqstypes.QueueDoesNotExist
	if errors.As(err, &qn) {
		return true
	}
	switch apiCode(err) {
	case "QueueDoesNotExist", "AWS.SimpleQueueService.NonExistentQueue":
		return true
	}
	return false
}

// queueNotFoundError is ErrQueueNotFound to errors.Is, with the text of
// the error it wraps (the log line of a failed receive keeps its form).
type queueNotFoundError struct{ err error }

func (e queueNotFoundError) Error() string { return e.err.Error() }
func (queueNotFoundError) Is(t error) bool { return t == ErrQueueNotFound }

// Receive implements Queues (long poll, up to 10 messages).
func (a *AWS) Receive(ctx context.Context, url string) ([]QueueMessage, error) {
	out, err := a.sqs.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{QueueUrl: &url, MaxNumberOfMessages: 10, WaitTimeSeconds: 20})
	if err != nil {
		if queueNotFound(err) {
			return nil, queueNotFoundError{errClass("sqs receive", err)}
		}
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
	item := map[string]ddbtypes.AttributeValue{
		"instance_id":  s(r.InstanceID),
		"release":      s(r.Release),
		"queue_url":    s(r.QueueURL),
		"descriptor":   s(base64.StdEncoding.EncodeToString(r.Descriptor)),
		"attestation":  s(base64.StdEncoding.EncodeToString(r.Attestation)),
		"heartbeat_at": n(r.HeartbeatAt),
		"expires_at":   n(r.ExpiresAt),
		"load":         n(int64(r.Load)),
	}
	if r.HeavyKDFFree != nil {
		item["heavy_kdf_free"] = &ddbtypes.AttributeValueMemberBOOL{Value: *r.HeavyKDFFree}
	}
	_, err := a.ddb.PutItem(ctx, &dynamodb.PutItemInput{TableName: &a.cfg.InstancesTable, Item: item})
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

// ReleaseLease implements Tables: removes this instance's lease, then marks
// the vault locked if it is still "unlocked" and nobody took a new lease
// meanwhile (a failed condition there is not an error: another instance
// holds it, or a lifecycle write already set the state).
func (a *AWS) ReleaseLease(ctx context.Context, vaultID, instanceID string, now time.Time) error {
	const cond = "attribute_exists(vault_id) AND #lease.#iid = :me"
	if err := a.updateVault(ctx, vaultID, "SET #u = :u REMOVE #lease", cond, names(cond, map[string]string{"#u": "updated_at"}),
		map[string]ddbtypes.AttributeValue{":u": s(isoNow(now)), ":me": s(instanceID)}); err != nil {
		return err
	}
	const lcond = "attribute_exists(vault_id) AND attribute_not_exists(#lease) AND #st = :unl"
	err := a.updateVault(ctx, vaultID, "SET #st = :lk, #u = :u", lcond, names(lcond, map[string]string{"#u": "updated_at", "#st": "state"}),
		map[string]ddbtypes.AttributeValue{":u": s(isoNow(now)), ":unl": s("unlocked"), ":lk": s("locked")})
	if errors.Is(err, ErrLeaseHeld) {
		return nil
	}
	return err
}

// Lifecycle implements Tables (§11.5). Only the lease holder (or anyone
// while no lease exists) writes lifecycle values, so a vault's loser in
// a split brain cannot overwrite the winner's.
func (a *AWS) Lifecycle(ctx context.Context, ev Lifecycle, instanceID string, now time.Time) error {
	if ev.Event == EventAlarmCredentialClone {
		return a.alarm(ctx, ev.VaultID, "credential_clone", now)
	}
	if ev.Event == EventAccountName {
		return a.nameChange(ctx, ev, now)
	}
	// app_key and app_key_next first, then the rest of the event; a failure
	// of the first does not hold the second back, and is returned as an
	// AppKeyWriteError so that the parent writes the keys again.
	var keyErr error
	if err := a.appKey(ctx, ev, now); err != nil {
		keyErr = err
	}
	switch ev.Event {
	case EventAppKey, EventAppKeyNext, EventAppKeyAssert, EventAppKeyNextAssert:
		return appKeyResult(keyErr, nil)
	}
	return appKeyResult(keyErr, a.lifecycleRest(ctx, ev, instanceID, now))
}

// lifecycleRest writes an event but its app keys.
func (a *AWS) lifecycleRest(ctx context.Context, ev Lifecycle, instanceID string, now time.Time) error {
	if ev.Event == EventCredentialBackup {
		// 0.16.0 (§11.5): the bit alone, under the lease rule.
		const cond = "attribute_exists(vault_id) AND (attribute_not_exists(#lease) OR #lease.#iid = :me)"
		err := a.updateVault(ctx, ev.VaultID, "SET #cb = :cb, #u = :u", cond, names(cond, map[string]string{"#cb": "credential_backup", "#u": "updated_at"}),
			map[string]ddbtypes.AttributeValue{":cb": &ddbtypes.AttributeValueMemberBOOL{Value: *ev.CredentialBackup}, ":u": s(isoNow(now)), ":me": s(instanceID)})
		if errors.Is(err, ErrLeaseHeld) {
			return nil
		}
		return err
	}
	const cond = "attribute_exists(vault_id) AND (attribute_not_exists(#lease) OR #lease.#iid = :me)"
	nm := names(cond, map[string]string{"#u": "updated_at", "#vv": "vault_version", "#sv": "state_version"})
	vals := map[string]ddbtypes.AttributeValue{":u": s(isoNow(now)), ":me": s(instanceID), ":vv": s(ev.VaultVersion), ":sv": n(int64(ev.StateVersion))}
	var update string
	switch ev.Event {
	case "enrolled", "moved":
		nm["#sr"] = "sealed_release"
		vals[":sr"] = s(ev.Release)
		update = "SET #sr = :sr, #vv = :vv, #sv = :sv, #u = :u"
		if ev.Event == "enrolled" {
			// A vault id enrolled again: no sweep of its old attachments
			// is pending for it any more (P15; the sweep stops too).
			nm["#asp"] = AttrSweepPending
			update += " REMOVE #asp"
		}
	case "unlocked":
		// 0.51.0 (VAULT-HOST-PROTOCOL 0.1.14 §6.1): a vault that runs is
		// not being deleted, so a deletion mark there is stale or forged.
		nm["#st"] = "state"
		nm["#da"] = AttrDeletingAt
		vals[":st"] = s("unlocked")
		update = "SET #st = :st, #vv = :vv, #sv = :sv, #u = :u REMOVE #da"
	case "locked", "deleted":
		nm["#st"] = "state"
		vals[":st"] = s(ev.Event)
		update = "SET #st = :st, #vv = :vv, #sv = :sv, #u = :u REMOVE #lease"
		if ev.Event == "deleted" {
			// P15: the sweep is pending until done, in the same update that
			// marks the row (resumed after a restart from it).
			nm["#asp"] = AttrSweepPending
			vals[":t"] = &ddbtypes.AttributeValueMemberBOOL{Value: true}
			update = "SET #st = :st, #vv = :vv, #sv = :sv, #u = :u, #asp = :t REMOVE #lease"
		}
		if ev.Event == "locked" && ev.KeepLease {
			update = "SET #st = :st, #vv = :vv, #sv = :sv, #u = :u"
		}
	default:
		return nil
	}
	if ev.CredentialBackup != nil {
		nm["#cb"] = "credential_backup"
		vals[":cb"] = &ddbtypes.AttributeValueMemberBOOL{Value: *ev.CredentialBackup}
		update = strings.Replace(update, "SET ", "SET #cb = :cb, ", 1)
	}
	if ev.CancelledRecoveryID != "" && (ev.Event == "unlocked" || ev.Event == "moved") {
		// 0.49.0 (VAULT-HOST-PROTOCOL 0.1.13 §7.2, MEMBER-API 2.9.0): the
		// recovery the unlock ended, in the same update as the event,
		// overwritten by the next such unlock and never cleared here.
		nm["#rc"] = "recovery_cancelled"
		vals[":rc"] = &ddbtypes.AttributeValueMemberM{Value: map[string]ddbtypes.AttributeValue{
			"recovery_id": s(ev.CancelledRecoveryID), "at": n(now.Unix())}}
		update = strings.Replace(update, "SET ", "SET #rc = :rc, ", 1)
	}
	err := a.updateVault(ctx, ev.VaultID, update, cond, nm, vals)
	held := errors.Is(err, ErrLeaseHeld)
	if held {
		err = nil // another instance holds the vault now
	}
	if err == nil && ev.Event == "deleted" {
		// The member is told (§12.5): the vault's own audit log is gone.
		if aerr := a.alarm(ctx, ev.VaultID, "vault_deleted", now); aerr != nil {
			if held {
				return aerr
			}
			// The row is marked: the sweep goes ahead whatever the alarm.
			return errors.Join(ErrAlarmNotWritten, aerr)
		}
		if held {
			err = ErrNotMarked // no attachment sweep (P15)
		}
	}
	return err
}

// AttrDeletingAt is the vault row attribute that records a deletion whose
// marking flush is stored (VAULT-MESSAGING 0.51.0 §11.5): the parent's
// Unix seconds, written by MarkDeleting and removed by an unlocked event.
const AttrDeletingAt = "deleting_at"

// MarkDeleting implements Tables (VAULT-HOST-PROTOCOL 0.1.14 §5.6): the
// one attribute, whatever the lease, never moved once written.
func (a *AWS) MarkDeleting(ctx context.Context, vaultID string, now time.Time) error {
	const cond = "attribute_exists(vault_id) AND (attribute_not_exists(#st) OR #st <> :del) AND attribute_not_exists(#da)"
	update := "SET #da = :at"
	_, err := a.ddb.UpdateItem(ctx, &dynamodb.UpdateItemInput{TableName: &a.cfg.VaultsTable, Key: map[string]ddbtypes.AttributeValue{"vault_id": s(vaultID)},
		UpdateExpression: &update, ConditionExpression: aws.String(cond),
		ExpressionAttributeNames:  map[string]string{"#st": "state", "#da": AttrDeletingAt},
		ExpressionAttributeValues: map[string]ddbtypes.AttributeValue{":del": s("deleted"), ":at": n(now.Unix())}})
	if err != nil {
		if condFailed(err) {
			return ErrConflict
		}
		return errClass("ddb mark deleting", err)
	}
	return nil
}

// AttrSweepPending is the vault row attribute that records a P15 sweep not
// yet finished (VAULT-HOST-PROTOCOL 0.1.9): set with state deleted,
// removed once vaults/<vault_id>/att/ is empty.
const AttrSweepPending = "att_sweep_pending"

// VaultState implements SweepTables: the row's state ("" with exists
// false for no row).
func (a *AWS) VaultState(ctx context.Context, vaultID string) (string, bool, error) {
	out, err := a.ddb.GetItem(ctx, &dynamodb.GetItemInput{TableName: &a.cfg.VaultsTable, ConsistentRead: aws.Bool(true),
		Key: map[string]ddbtypes.AttributeValue{"vault_id": s(vaultID)}, ProjectionExpression: aws.String("#st"),
		ExpressionAttributeNames: map[string]string{"#st": "state"}})
	if err != nil {
		return "", false, errClass("ddb get vault", err)
	}
	if out.Item == nil {
		return "", false, nil
	}
	st, _ := out.Item["state"].(*ddbtypes.AttributeValueMemberS)
	if st == nil {
		return "", true, nil
	}
	return st.Value, true, nil
}

// PendingSweeps implements SweepTables: the vault ids whose row records a
// sweep not yet finished (a Scan with a filter, at the parent's start).
func (a *AWS) PendingSweeps(ctx context.Context) ([]string, error) {
	var out []string
	var start map[string]ddbtypes.AttributeValue
	for {
		r, err := a.ddb.Scan(ctx, &dynamodb.ScanInput{TableName: &a.cfg.VaultsTable, ExclusiveStartKey: start,
			FilterExpression: aws.String("attribute_exists(#asp)"), ProjectionExpression: aws.String("vault_id"),
			ExpressionAttributeNames: map[string]string{"#asp": AttrSweepPending}})
		if err != nil {
			return out, errClass("ddb scan vaults", err)
		}
		for _, it := range r.Items {
			if id, ok := it["vault_id"].(*ddbtypes.AttributeValueMemberS); ok {
				out = append(out, id.Value)
			}
		}
		if len(r.LastEvaluatedKey) == 0 {
			return out, nil
		}
		start = r.LastEvaluatedKey
	}
}

// SweepDone implements SweepTables: the sweep's record goes (a row that is
// gone, or no longer deleted, is left alone).
func (a *AWS) SweepDone(ctx context.Context, vaultID string, now time.Time) error {
	err := a.updateVault(ctx, vaultID, "REMOVE #asp SET #u = :u", "attribute_exists(vault_id) AND #st = :del",
		map[string]string{"#asp": AttrSweepPending, "#u": "updated_at", "#st": "state"},
		map[string]ddbtypes.AttributeValue{":u": s(isoNow(now)), ":del": s("deleted")})
	if errors.Is(err, ErrLeaseHeld) {
		return nil
	}
	return err
}

// ListObjects implements ObjectLister: every object under prefix, with its ETag.
func (a *AWS) ListObjects(ctx context.Context, prefix string) ([]ObjectRef, error) {
	var out []ObjectRef
	var token *string
	for {
		r, err := a.s3.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: &a.cfg.Bucket, Prefix: &prefix, ContinuationToken: token})
		if err != nil {
			return out, errClass("s3 list", err)
		}
		for _, o := range r.Contents {
			if o.Key != nil && o.ETag != nil {
				out = append(out, ObjectRef{Key: *o.Key, ETag: *o.ETag})
			}
		}
		if r.IsTruncated == nil || !*r.IsTruncated || r.NextContinuationToken == nil {
			return out, nil
		}
		token = r.NextContinuationToken
	}
}

// AppKeys implements Tables: the app_key and app_key_next parts of an
// event, and nothing else, so that they can be written again until they
// are (the parent keeps trying; the enclave asserts them after a connect).
func (a *AWS) AppKeys(ctx context.Context, ev Lifecycle, now time.Time) error {
	return a.appKey(ctx, ev, now)
}

// putAppKey writes app_key = {key, kid, seq} and removes app_key_next in
// ONE UpdateItem, so that no failure between two writes can leave the row
// without the key. enrolled: whatever the row has (a replaced provisional
// vault starts again at 1), and the next key goes; otherwise only when seq
// is higher than the row's, and the next key goes only if its seq is not
// above this one (a replacement begun since stays). A failed condition is
// ErrLeaseHeld.
func (a *AWS) putAppKey(ctx context.Context, vaultID string, key []byte, seq uint64, enrolled bool, now time.Time) error {
	ak := &ddbtypes.AttributeValueMemberM{Value: map[string]ddbtypes.AttributeValue{
		"key": s(base64.StdEncoding.EncodeToString(key)), "kid": s(AppKeyID(key)), "seq": n(int64(seq))}}
	nm := map[string]string{"#ak": "app_key", "#akn": "app_key_next", "#u": "updated_at"}
	vals := map[string]ddbtypes.AttributeValue{":ak": ak, ":u": s(isoNow(now))}
	if enrolled {
		return a.updateVault(ctx, vaultID, "SET #ak = :ak, #u = :u REMOVE #akn", "attribute_exists(vault_id)", nm, vals)
	}
	nm["#seq"] = "seq"
	vals[":seq"] = n(int64(seq))
	const cond = "attribute_exists(vault_id) AND (attribute_not_exists(#ak) OR #ak.#seq < :seq)"
	err := a.updateVault(ctx, vaultID, "SET #ak = :ak, #u = :u REMOVE #akn", cond+" AND (attribute_not_exists(#akn) OR #akn.#seq <= :seq)", nm, vals)
	if !errors.Is(err, ErrLeaseHeld) {
		return err
	}
	// The next key is above this seq (or the report is stale): the key
	// alone, in its own single update.
	delete(nm, "#akn")
	return a.updateVault(ctx, vaultID, "SET #ak = :ak, #u = :u", cond, nm, vals)
}

// appKey writes the reported app key (0.15.0, §11.5): app_key = {key,
// kid, seq} whatever the lease, when seq is higher than the row's;
// enrolled always replaces it (a replaced provisional vault starts at 1).
// app_key and the removal of app_key_next are one update (putAppKey), and
// app_key goes first: a failure leaves the row naming the key. A failed
// condition (an older report, a missing row) is not an error. The
// app_key_assert and app_key_next_assert events are written as app_key and
// app_key_next.
func (a *AWS) appKey(ctx context.Context, ev Lifecycle, now time.Time) error {
	switch ev.Event {
	case EventAppKeyAssert:
		ev.Event = EventAppKey
	case EventAppKeyNextAssert:
		ev.Event = EventAppKeyNext
	}
	if ev.Event == EventAppKeyNext || ev.NextCleared {
		return a.appKeyNext(ctx, ev, now)
	}
	if len(ev.AppKey) > 0 {
		err := a.putAppKey(ctx, ev.VaultID, ev.AppKey, ev.AppKeySeq, ev.Event == "enrolled", now)
		if err != nil && !errors.Is(err, ErrLeaseHeld) {
			return err
		}
	}
	return a.appKeyNext(ctx, ev, now)
}

// ConfirmAppKey implements Tables (hostproto.KindAppKeyNext): nil once the
// row names the key, as app_key_next (mode next) or app_key (mode enroll)
// or, in mode next, already as app_key at that seq or higher; ErrConflict
// if the row names another key at that seq or higher, or is gone.
func (a *AWS) ConfirmAppKey(ctx context.Context, vaultID, mode string, key []byte, seq, headerSeq uint64, now time.Time) error {
	if mode == "enroll" {
		err := a.putAppKey(ctx, vaultID, key, seq, true, now)
		if errors.Is(err, ErrLeaseHeld) {
			return ErrConflict // no such vault row
		}
		return err
	}
	err := a.appKeyNext(ctx, Lifecycle{Event: EventAppKeyNext, VaultID: vaultID, AppKey: key, AppKeySeq: seq, HeaderSeq: headerSeq}, now)
	if err != nil {
		return err
	}
	// The write is conditional: read the row to tell "written" from "not
	// needed" from "refused".
	out, gerr := a.ddb.GetItem(ctx, &dynamodb.GetItemInput{TableName: &a.cfg.VaultsTable, ConsistentRead: aws.Bool(true),
		Key: map[string]ddbtypes.AttributeValue{"vault_id": s(vaultID)}, ProjectionExpression: aws.String("app_key, app_key_next")})
	if gerr != nil {
		return errClass("ddb get vault", gerr)
	}
	kid := AppKeyID(key)
	named := func(attr string, minSeq uint64) bool {
		m, ok := out.Item[attr].(*ddbtypes.AttributeValueMemberM)
		if !ok {
			return false
		}
		k, _ := m.Value["kid"].(*ddbtypes.AttributeValueMemberS)
		sq, _ := m.Value["seq"].(*ddbtypes.AttributeValueMemberN)
		var have uint64
		if sq != nil {
			have, _ = strconv.ParseUint(sq.Value, 10, 64)
		}
		return k != nil && k.Value == kid && have >= minSeq
	}
	if out.Item != nil && (named("app_key", seq) || named("app_key_next", seq)) {
		return nil
	}
	return ErrConflict
}

// appKeyNext applies release R's app_key_next (VAULT-HOST-PROTOCOL 0.1.10
// §6.1, VAULT-MESSAGING §11.5, §11.14.2): app_key_next is written from
// its event when its seq is above app_key's; it is cleared when app_key
// reaches its seq, when an app_key event carries next_cleared (whose own
// write is skipped), or when an unlocked or locked report says next:
// false with an app_key_seq at least the next key's seq or a header_seq
// at least that of the write that carried it; never on time alone. A
// failed condition is not an error.
func (a *AWS) appKeyNext(ctx context.Context, ev Lifecycle, now time.Time) error {
	ignore := func(err error) error {
		if errors.Is(err, ErrLeaseHeld) {
			return nil
		}
		return err
	}
	switch {
	case ev.Event == EventAppKeyNext:
		akn := &ddbtypes.AttributeValueMemberM{Value: map[string]ddbtypes.AttributeValue{
			"key": s(base64.StdEncoding.EncodeToString(ev.AppKey)), "kid": s(AppKeyID(ev.AppKey)), "seq": n(int64(ev.AppKeySeq)),
			"header_seq": n(int64(ev.HeaderSeq))}}
		return ignore(a.updateVault(ctx, ev.VaultID, "SET #akn = :akn, #u = :u",
			"attribute_exists(vault_id) AND (attribute_not_exists(#ak) OR #ak.#seq < :seq)",
			map[string]string{"#akn": "app_key_next", "#ak": "app_key", "#seq": "seq", "#u": "updated_at"},
			map[string]ddbtypes.AttributeValue{":akn": akn, ":seq": n(int64(ev.AppKeySeq)), ":u": s(isoNow(now))}))
	case ev.Event == EventAppKey && ev.NextCleared:
		return ignore(a.updateVault(ctx, ev.VaultID, "REMOVE #akn SET #u = :u", "attribute_exists(#akn)",
			map[string]string{"#akn": "app_key_next", "#u": "updated_at"}, map[string]ddbtypes.AttributeValue{":u": s(isoNow(now))}))
	case (ev.Event == "unlocked" || ev.Event == "locked") && ev.Next != nil && !*ev.Next:
		return ignore(a.updateVault(ctx, ev.VaultID, "REMOVE #akn SET #u = :u",
			"attribute_exists(#akn) AND (#akn.#seq <= :aks OR #akn.#hs <= :hs)",
			map[string]string{"#akn": "app_key_next", "#seq": "seq", "#hs": "header_seq", "#u": "updated_at"},
			map[string]ddbtypes.AttributeValue{":aks": n(int64(ev.AppKeySeq)), ":hs": n(int64(ev.HeaderSeq)), ":u": s(isoNow(now))}))
	}
	return nil
}

// nameChange writes the member's name request (0.18.0, §11.5, MEMBER-API
// 2.2.0 "Name changes from the vault"): name_change = {seq, first_name,
// last_name, at (epoch s)} and name_change_pending = true, whatever the
// lease, when seq is higher than the row's (absent: 0), so a stale
// instance can only report an older request. The member API's
// vault-names job picks it up from the table's stream. A failed
// condition (an older report, a missing row) is not an error.
func (a *AWS) nameChange(ctx context.Context, ev Lifecycle, now time.Time) error {
	nc := &ddbtypes.AttributeValueMemberM{Value: map[string]ddbtypes.AttributeValue{
		"seq": n(int64(ev.Name.Seq)), "first_name": s(ev.Name.FirstName), "last_name": s(ev.Name.LastName), "at": n(now.Unix())}}
	err := a.updateVault(ctx, ev.VaultID, "SET #nc = :nc, #ncp = :t, #u = :u",
		"attribute_exists(vault_id) AND (attribute_not_exists(#nc) OR #nc.#seq < :seq)",
		map[string]string{"#nc": "name_change", "#ncp": "name_change_pending", "#seq": "seq", "#u": "updated_at"},
		map[string]ddbtypes.AttributeValue{":nc": nc, ":t": &ddbtypes.AttributeValueMemberBOOL{Value: true},
			":seq": n(int64(ev.Name.Seq)), ":u": s(isoNow(now))})
	if errors.Is(err, ErrLeaseHeld) {
		return nil
	}
	return err
}

// alarm records a host alarm (credential_clone) or notice (vault_deleted) on the vault row (VAULT-MESSAGING §11.5,
// MEMBER-API "Vault alarms"): alarm = {kind, alarm_id (ULID), at (epoch
// s)} and alarm_pending = true, which the member API's alarm mailer picks
// up from the table's stream. It is not conditional on the lease: an
// alarm is never lost to a lease race. A missing row is ignored.
func (a *AWS) alarm(ctx context.Context, vaultID, kind string, now time.Time) error {
	id, err := newULID(now)
	if err != nil {
		return err
	}
	al := &ddbtypes.AttributeValueMemberM{Value: map[string]ddbtypes.AttributeValue{
		"kind": s(kind), "alarm_id": s(id), "at": n(now.Unix())}}
	err = a.updateVault(ctx, vaultID, "SET #al = :al, #ap = :t, #u = :u", "attribute_exists(vault_id)",
		map[string]string{"#al": "alarm", "#ap": "alarm_pending", "#u": "updated_at"},
		map[string]ddbtypes.AttributeValue{":al": al, ":t": &ddbtypes.AttributeValueMemberBOOL{Value: true}, ":u": s(isoNow(now))})
	if errors.Is(err, ErrLeaseHeld) {
		return nil // no such vault row
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
	for _, f := range []struct{ n, v string }{{"not_before", sl.NotBefore}, {"expires", sl.Expires}, {"retry_at", sl.RetryAt}, {"reason", sl.Reason}} {
		if f.v != "" {
			update += ", " + f.n + " = :" + f.n
			vals[":"+f.n] = s(f.v)
		}
	}
	if sl.Earliest {
		update += ", earliest = :ea"
		vals[":ea"] = &ddbtypes.AttributeValueMemberBOOL{Value: true}
	}
	if sl.CancelledRecoveryID != "" {
		// 0.49.0 (VAULT-HOST-PROTOCOL 0.1.13 §6.1): with the code
		// recovery_cancelled on an unlock slot.
		update += ", cancelled_recovery_id = :crid"
		vals[":crid"] = s(sl.CancelledRecoveryID)
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

// newULID returns a ULID (26 Crockford base32 characters, upper case): a
// 48-bit millisecond time and 80 random bits.
func newULID(now time.Time) (string, error) {
	var b [16]byte
	ms := uint64(now.UnixMilli())
	for i := 5; i >= 0; i-- {
		b[i] = byte(ms)
		ms >>= 8
	}
	if _, err := rand.Read(b[6:]); err != nil {
		return "", err
	}
	const alpha = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	out := make([]byte, 26)
	hi := uint64(b[0])<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 | uint64(b[3])<<32 | uint64(b[4])<<24 | uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7])
	lo := uint64(b[8])<<56 | uint64(b[9])<<48 | uint64(b[10])<<40 | uint64(b[11])<<32 | uint64(b[12])<<24 | uint64(b[13])<<16 | uint64(b[14])<<8 | uint64(b[15])
	// 128 bits as 26 five-bit groups, the first group holding 3 bits.
	for i := 25; i >= 0; i-- {
		out[i] = alpha[lo&31]
		lo = lo>>5 | hi<<59
		hi >>= 5
	}
	return string(out), nil
}
