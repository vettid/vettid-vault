// Package memberapitest is a TEST-ONLY stand-in for the vettid.org member
// API's vault routes (vettid.org lambda/member/vault.ts, MEMBER-API.md
// "Vault"): the same routing rules, over the same DynamoDB tables and
// SQS queues, with the same item shapes. It lets the integration test run
// the real parent and enclave against LocalStack exactly as they will run
// against the member API.
//
// Left out: sessions (a portal member is named by "Authorization: Bearer
// <user_guid>" and is always a member who accepted the current terms),
// rate limits, the typed redeem's flat timing, the audit log, email and
// the recovery cancel link. Apps sign every request with their app key
// (MEMBER-API 2.0.0, appkeys.go).
package memberapitest

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/smithy-go"
)

// Wire constants (vault.ts).
const (
	sealedOverhead     = 1156
	envelopeLarge      = 12288 + sealedOverhead // 13,444
	resultEnvelope     = 4096 + sealedOverhead  // 5,252
	liveHeartbeatS     = 90
	startRetryAfterS   = 30
	requestTTLS        = 15 * 60
	queueRetentionS    = 5 * 60
	expirySlackS       = 30
	pointerKeyPrefix   = "user#"
	statusIndex        = "status-index"
	releaseIndex       = "release-index"
	enclavePath        = "/api/vault/enclave"
	manifestPath       = "/.well-known/vettid/pcr-manifest.json"
	requestsPathPrefix = "/api/vault/requests/"
)

var (
	ulidRE       = regexp.MustCompile(`^[0-7][0-9A-HJKMNP-TV-Z]{25}$`)
	vaultIDRE    = regexp.MustCompile(`^[0-9a-f]{32}$`)
	kidRE        = regexp.MustCompile(`^[0-9a-f]{16}$`)
	sha256RE     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	pcr0RE       = regexp.MustCompile(`^[0-9a-f]{96}$`)
	instanceIDRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,48}$`)
	codeRE       = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,63}$`)
)

// Tables names the four vault tables.
type Tables struct {
	Vaults, Instances, Requests, Releases string
}

// Config configures the stand-in.
type Config struct {
	DDB    *dynamodb.Client
	SQS    *sqs.Client
	Tables Tables
	// QueueURLPrefix is VAULT_QUEUE_URL_PREFIX: queue URL of an instance
	// = prefix + instance_id.
	QueueURLPrefix string
	// Manifest returns the served release manifest.
	Manifest func() []byte
	Now      func() time.Time
	// Sent, if set, sees every queue message sent (tests that replay one
	// as a dishonest host would).
	Sent func(requestID, queueURL, body string)
	// RecoveryNow, if set, is the clock of the recovery's times (requested,
	// available, expires; DEVELOPMENT: the dev stack moves it forward
	// together with the enclave's recovery clock). Default Now.
	RecoveryNow func() time.Time
	// Origin is the member API origin the setup code's QR names (§11.12.1);
	// default http://<Host>.
	Origin string
	// Email returns a member's email (setup codes, the redeem and claim
	// answers' email_hint, the snapshot's email since 0.20.0); default
	// <guid>@example.org.
	Email func(guid string) string
	// Names returns a member's registration names (0.18.0, the snapshot's
	// first_name and last_name); default Test Member.
	Names func(guid string) (first, last string)
}

// API serves the vault routes.
type API struct {
	cfg Config
	mu  sync.Mutex
	// StartRequests records on-demand start requests per release.
	StartRequests map[string]int
	ks            *keyStore
	// The members' names and the vaults' name change results (0.18.0),
	// by user_guid (names.go).
	nm map[string]*memberNames
	nr map[string]*nameResult
}

// New returns the stand-in.
func New(cfg Config) *API {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.RecoveryNow == nil {
		cfg.RecoveryNow = cfg.Now
	}
	return &API{cfg: cfg, StartRequests: map[string]int{}}
}

type apiError struct {
	status int
	code   string
	msg    string
	extra  map[string]any
}

func (e *apiError) Error() string { return e.code }

func vaultError(status int, code, msg string, extra map[string]any) *apiError {
	return &apiError{status: status, code: code, msg: msg, extra: extra}
}

func badRequest(msg string) *apiError { return vaultError(400, "bad_request", msg, nil) }
func notFound(msg string) *apiError   { return vaultError(404, "not_found", msg, nil) }
func instanceMoved() *apiError {
	return vaultError(409, "instance_moved", "The vault is now served by another enclave instance", nil)
}

func (a *API) nowS() int64 { return a.cfg.Now().Unix() }
func (a *API) nowISO() string {
	return a.cfg.Now().UTC().Format("2006-01-02T15:04:05.000Z")
}

func s(v string) ddbtypes.AttributeValue { return &ddbtypes.AttributeValueMemberS{Value: v} }
func n(v int64) ddbtypes.AttributeValue {
	return &ddbtypes.AttributeValueMemberN{Value: strconv.FormatInt(v, 10)}
}

func str(m map[string]ddbtypes.AttributeValue, k string) string {
	if v, ok := m[k].(*ddbtypes.AttributeValueMemberS); ok {
		return v.Value
	}
	return ""
}

func num(m map[string]ddbtypes.AttributeValue, k string) (int64, bool) {
	if v, ok := m[k].(*ddbtypes.AttributeValueMemberN); ok {
		x, err := strconv.ParseInt(v.Value, 10, 64)
		return x, err == nil
	}
	return 0, false
}

func code(err error) string {
	var ae smithy.APIError
	if errors.As(err, &ae) {
		return ae.ErrorCode()
	}
	return ""
}

// ServeHTTP routes a request.
func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var out any
	var err error
	status := http.StatusOK
	ctx := r.Context()
	if r.Method == http.MethodGet && r.URL.Path == manifestPath {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(a.cfg.Manifest())
		return
	}
	var body map[string]any
	var raw []byte
	if r.Method == http.MethodPost {
		b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64*1024))
		if err != nil || len(b) > 0 && json.Unmarshal(b, &body) != nil {
			writeJSON(w, 400, map[string]any{"error": "bad_request", "message": "invalid JSON"})
			return
		}
		raw = b
		if body == nil {
			body = map[string]any{}
		}
	}
	c, err := a.authenticate(ctx, r, raw, body)
	if err != nil {
		a.writeErr(w, err)
		return
	}
	ctx = context.WithValue(ctx, callerCtxKey{}, c)
	guid := c.guid
	switch {
	case r.URL.Path == "/api/vault/enroll-code" && r.Method == http.MethodPost:
		out, err = a.enrollCodeIssue(guid, a.origin(r))
		status = 201
	case r.URL.Path == "/api/vault/enroll-code" && r.Method == http.MethodGet:
		out, err = a.enrollCodeGet(guid)
	case r.URL.Path == "/api/vault/enroll-code" && r.Method == http.MethodDelete:
		out, err = a.enrollCodeRevoke(guid)
	case r.Method == http.MethodPost && r.URL.Path == "/api/vault/enroll/redeem":
		out, err = a.redeem(ctx, c, body)
	case r.Method == http.MethodPost && r.URL.Path == "/api/vault/recovery/claim":
		out, err = a.recoveryClaim(ctx, c, body)
	case r.Method == http.MethodGet && r.URL.Path == "/api/vault/status":
		out, err = a.status(ctx, guid)
	case r.Method == http.MethodGet && r.URL.Path == enclavePath:
		var rel *string
		if r.URL.Query().Has("release") {
			v := r.URL.Query().Get("release")
			rel = &v
		}
		out, err = a.enclave(ctx, guid, rel)
	case r.Method == http.MethodPost && r.URL.Path == "/api/vault/enroll":
		out, err = a.enroll(ctx, guid, body)
		status = 202
	case r.Method == http.MethodPost && r.URL.Path == "/api/vault/unlock":
		out, err = a.unlock(ctx, guid, body)
		status = 202
	case r.Method == http.MethodPost && r.URL.Path == "/api/vault/lock":
		out, err = a.lock(ctx, guid, body)
		status = 202
	case r.Method == http.MethodPost && r.URL.Path == "/api/vault/recovery":
		out, err = a.recoveryRequest(ctx, guid, body)
		status = 202
	case r.Method == http.MethodGet && r.URL.Path == "/api/vault/recovery":
		out, err = a.recoveryStatus(ctx, guid)
	case r.Method == http.MethodPost && r.URL.Path == "/api/vault/recovery/cancel":
		out, err = a.recoveryCancel(ctx, guid, body)
	case r.Method == http.MethodPost && r.URL.Path == "/api/vault/recovery/register":
		out, err = a.recoveryRegister(ctx, guid, body)
		status = 202
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, requestsPathPrefix):
		out, err = a.request(ctx, guid, strings.TrimPrefix(r.URL.Path, requestsPathPrefix))
	default:
		err = notFound("No such route")
	}
	if err != nil {
		a.writeErr(w, err)
		return
	}
	writeJSON(w, status, out)
}

func (a *API) writeErr(w http.ResponseWriter, err error) {
	var ae *apiError
	if !errors.As(err, &ae) {
		ae = &apiError{status: 500, code: "internal", msg: "internal error"}
	}
	b := map[string]any{"error": ae.code, "message": ae.msg}
	if ae.status != 500 && ae.code != "bad_request" && ae.code != "not_found" && ae.code != "unauthorized" {
		b["code"] = ae.code
	}
	for k, v := range ae.extra {
		b[k] = v
	}
	writeJSON(w, ae.status, b)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func field(body map[string]any, key string, re *regexp.Regexp, what string) (string, error) {
	v, ok := body[key].(string)
	if !ok || !re.MatchString(v) {
		return "", badRequest(key + " must be " + what)
	}
	return v, nil
}

// checkEnvelope is vault.ts checkEnvelope: canonical base64 of exactly the
// padded size, sealed v2 suite 2 header with an anonymous sender and the
// named ETK kid. The ciphertext is never inspected.
func checkEnvelope(v any, expected int, kid string) (string, error) {
	b64, ok := v.(string)
	if !ok {
		return "", badRequest("envelope is required")
	}
	buf, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(buf) != expected || base64.StdEncoding.EncodeToString(buf) != b64 {
		return "", badRequest("envelope has the wrong size or encoding")
	}
	h := buf[:20]
	okh := h[0] == 2 && h[1] == 2 && h[2] == 2 && h[3] == 0 && hex.EncodeToString(h[4:12]) == "0000000000000000" && hex.EncodeToString(h[12:20]) == kid
	if !okh {
		return "", badRequest("envelope header does not match a sealed request to etk_kid")
	}
	return b64, nil
}

// --- rows ---

type lease struct {
	instanceID string
	expires    int64
}

type vaultRow struct {
	VaultID, UserGUID, State, SealedRelease, VaultVersion string
	StateVersion                                          any
	Lease                                                 *lease
	Recovery                                              *recoveryRow
	// AppKey is the app_key the host wrote from the enclave's reports.
	AppKey *appKey
	// CredentialBackup is the backup bit the host wrote (0.16.0); nil
	// until a 0.16.0 release reports it.
	CredentialBackup     *bool
	CreatedAt, UpdatedAt string
}

func parseVault(it map[string]ddbtypes.AttributeValue) *vaultRow {
	if it == nil {
		return nil
	}
	v := &vaultRow{VaultID: str(it, "vault_id"), UserGUID: str(it, "user_guid"), State: str(it, "state"),
		SealedRelease: str(it, "sealed_release"), VaultVersion: str(it, "vault_version"), CreatedAt: str(it, "created_at"), UpdatedAt: str(it, "updated_at")}
	if x, ok := num(it, "state_version"); ok {
		v.StateVersion = x
	} else if sv := str(it, "state_version"); sv != "" {
		v.StateVersion = sv
	}
	if m, ok := it["recovery"].(*ddbtypes.AttributeValueMemberM); ok {
		r := &recoveryRow{ID: str(m.Value, "recovery_id"), State: str(m.Value, "state")}
		r.RequestedAt, _ = num(m.Value, "requested_at")
		r.AvailableAt, _ = num(m.Value, "available_at")
		r.ExpiresAt, _ = num(m.Value, "expires_at")
		if l, ok := m.Value["register_ids"].(*ddbtypes.AttributeValueMemberL); ok {
			for _, x := range l.Value {
				if id, ok := x.(*ddbtypes.AttributeValueMemberS); ok {
					r.RegisterIDs = append(r.RegisterIDs, id.Value)
				}
			}
		}
		if r.ID != "" {
			v.Recovery = r
		}
	}
	if b, ok := it["credential_backup"].(*ddbtypes.AttributeValueMemberBOOL); ok {
		x := b.Value
		v.CredentialBackup = &x
	}
	if m, ok := it["app_key"].(*ddbtypes.AttributeValueMemberM); ok {
		if k, ok := parseKey(str(m.Value, "key")); ok && k.kid == str(m.Value, "kid") {
			v.AppKey = k
		}
	}
	if m, ok := it["lease"].(*ddbtypes.AttributeValueMemberM); ok {
		l := &lease{instanceID: str(m.Value, "instance_id")}
		if e, ok := num(m.Value, "lease_expires_at"); ok {
			l.expires = e
			v.Lease = l
		}
	}
	return v
}

type instanceRow struct {
	InstanceID, Release, QueueURL, Descriptor, Attestation string
	HeartbeatAt, Load                                      int64
}

func (a *API) currentVault(ctx context.Context, guid string) (string, *vaultRow, error) {
	p, err := a.cfg.DDB.GetItem(ctx, &dynamodb.GetItemInput{TableName: &a.cfg.Tables.Vaults, ConsistentRead: aws.Bool(true),
		Key: map[string]ddbtypes.AttributeValue{"vault_id": s(pointerKeyPrefix + guid)}})
	if err != nil {
		return "", nil, err
	}
	pointer := str(p.Item, "current_vault_id")
	if pointer == "" {
		return "", nil, nil
	}
	v, err := a.cfg.DDB.GetItem(ctx, &dynamodb.GetItemInput{TableName: &a.cfg.Tables.Vaults, ConsistentRead: aws.Bool(true),
		Key: map[string]ddbtypes.AttributeValue{"vault_id": s(pointer)}})
	if err != nil {
		return "", nil, err
	}
	row := parseVault(v.Item)
	if row == nil || row.UserGUID != guid {
		return pointer, nil, nil
	}
	return pointer, row, nil
}

func active(v *vaultRow) *vaultRow {
	if v != nil && v.State != "deleted" {
		return v
	}
	return nil
}

func randomVaultID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (a *API) vaultForEnrollment(ctx context.Context, guid, pointer string, cur *vaultRow) (*vaultRow, error) {
	if v := active(cur); v != nil {
		return v, nil
	}
	id := randomVaultID()
	now := a.nowISO()
	cond := "attribute_not_exists(vault_id)"
	vals := map[string]ddbtypes.AttributeValue{":new": s(id), ":now": s(now)}
	if pointer != "" {
		cond = "current_vault_id = :old"
		vals[":old"] = s(pointer)
	}
	_, err := a.cfg.DDB.UpdateItem(ctx, &dynamodb.UpdateItemInput{TableName: &a.cfg.Tables.Vaults,
		Key:              map[string]ddbtypes.AttributeValue{"vault_id": s(pointerKeyPrefix + guid)},
		UpdateExpression: aws.String("SET current_vault_id = :new, updated_at = :now"), ConditionExpression: &cond, ExpressionAttributeValues: vals})
	if err != nil {
		if code(err) == "ConditionalCheckFailedException" {
			return nil, vaultError(409, "conflict", "Another enrollment is in progress; try again", nil)
		}
		return nil, err
	}
	row := &vaultRow{VaultID: id, UserGUID: guid, State: "enrolling", CreatedAt: now, UpdatedAt: now}
	_, err = a.cfg.DDB.PutItem(ctx, &dynamodb.PutItemInput{TableName: &a.cfg.Tables.Vaults, ConditionExpression: aws.String("attribute_not_exists(vault_id)"),
		Item: map[string]ddbtypes.AttributeValue{"vault_id": s(id), "user_guid": s(guid), "state": s("enrolling"), "created_at": s(now), "updated_at": s(now)}})
	return row, err
}

func (a *API) expectedQueueURL(id string) string { return a.cfg.QueueURLPrefix + id }

func (a *API) isLive(it map[string]ddbtypes.AttributeValue, now int64) (*instanceRow, bool) {
	if it == nil {
		return nil, false
	}
	r := &instanceRow{InstanceID: str(it, "instance_id"), Release: str(it, "release"), QueueURL: str(it, "queue_url"),
		Descriptor: str(it, "descriptor"), Attestation: str(it, "attestation")}
	hb, ok := num(it, "heartbeat_at")
	r.HeartbeatAt = hb
	r.Load, _ = num(it, "load")
	_, hasDesc := it["descriptor"].(*ddbtypes.AttributeValueMemberS)
	_, hasAtt := it["attestation"].(*ddbtypes.AttributeValueMemberS)
	return r, instanceIDRE.MatchString(r.InstanceID) && ok && hb >= now-liveHeartbeatS && r.QueueURL == a.expectedQueueURL(r.InstanceID) && hasDesc && hasAtt
}

func (a *API) liveInstance(ctx context.Context, id string, now int64) (*instanceRow, error) {
	if !instanceIDRE.MatchString(id) {
		return nil, nil
	}
	r, err := a.cfg.DDB.GetItem(ctx, &dynamodb.GetItemInput{TableName: &a.cfg.Tables.Instances, Key: map[string]ddbtypes.AttributeValue{"instance_id": s(id)}})
	if err != nil {
		return nil, err
	}
	i, ok := a.isLive(r.Item, now)
	if !ok {
		return nil, nil
	}
	return i, nil
}

func (a *API) liveLease(ctx context.Context, v *vaultRow, now int64) (*instanceRow, error) {
	if v == nil || v.Lease == nil || v.Lease.expires <= now {
		return nil, nil
	}
	return a.liveInstance(ctx, v.Lease.instanceID, now)
}

type releaseRow struct {
	release   string
	number    int64
	status    string
	available *bool
}

func (a *API) releaseRow(ctx context.Context, release string) (*releaseRow, error) {
	r, err := a.cfg.DDB.GetItem(ctx, &dynamodb.GetItemInput{TableName: &a.cfg.Tables.Releases, Key: map[string]ddbtypes.AttributeValue{"release": s(release)}})
	if err != nil || r.Item == nil {
		return nil, err
	}
	return parseRelease(r.Item), nil
}

func parseRelease(it map[string]ddbtypes.AttributeValue) *releaseRow {
	rr := &releaseRow{release: str(it, "release"), status: str(it, "status")}
	rr.number, _ = num(it, "release_number")
	if b, ok := it["available"].(*ddbtypes.AttributeValueMemberBOOL); ok {
		rr.available = &b.Value
	}
	return rr
}

func (a *API) pickInstance(ctx context.Context, release string, now int64) (*instanceRow, error) {
	r, err := a.cfg.DDB.Query(ctx, &dynamodb.QueryInput{TableName: &a.cfg.Tables.Instances, IndexName: aws.String(releaseIndex),
		KeyConditionExpression:    aws.String("#r = :r AND heartbeat_at >= :cut"),
		ExpressionAttributeNames:  map[string]string{"#r": "release"},
		ExpressionAttributeValues: map[string]ddbtypes.AttributeValue{":r": s(release), ":cut": n(now - liveHeartbeatS)}})
	if err != nil {
		return nil, err
	}
	type cand struct {
		id     string
		hb, ld int64
	}
	var cs []cand
	for _, it := range r.Items {
		c := cand{id: str(it, "instance_id")}
		c.hb, _ = num(it, "heartbeat_at")
		c.ld, _ = num(it, "load")
		cs = append(cs, c)
	}
	sort.Slice(cs, func(i, j int) bool {
		if cs[i].ld != cs[j].ld {
			return cs[i].ld < cs[j].ld
		}
		return cs[i].hb > cs[j].hb
	})
	for i, c := range cs {
		if i == 5 {
			break
		}
		inst, err := a.liveInstance(ctx, c.id, now)
		if err != nil {
			return nil, err
		}
		if inst != nil && inst.Release == release {
			return inst, nil
		}
	}
	return nil, nil
}

func (a *API) requestStart(release string) {
	a.mu.Lock()
	a.StartRequests[release]++
	a.mu.Unlock()
}

func describe(i *instanceRow) map[string]any {
	return map[string]any{"instance_id": i.InstanceID, "release": i.Release, "descriptor": i.Descriptor, "attestation": i.Attestation}
}

func releaseStarting(release string) *apiError {
	return vaultError(503, "release_starting", "An enclave for this vault is starting; retry shortly.",
		map[string]any{"release": release, "retry_after": startRetryAfterS})
}

func (a *API) routeToRelease(ctx context.Context, release string, now int64) (any, error) {
	rel, err := a.releaseRow(ctx, release)
	if err != nil {
		return nil, err
	}
	// 0.10.0: a removed release is not routed unless operations reopened
	// it for a rescue (available set explicitly).
	if rel == nil || rel.available != nil && !*rel.available || rel.status == "removed" && rel.available == nil {
		return nil, vaultError(410, "release_unavailable", "The enclave release this vault is sealed to can no longer be started.", nil)
	}
	inst, err := a.pickInstance(ctx, release, now)
	if err != nil {
		return nil, err
	}
	if inst != nil {
		return describe(inst), nil
	}
	a.requestStart(release)
	return nil, releaseStarting(release)
}

func (a *API) routeForEnrollment(ctx context.Context, now int64) (any, error) {
	r, err := a.cfg.DDB.Query(ctx, &dynamodb.QueryInput{TableName: &a.cfg.Tables.Releases, IndexName: aws.String(statusIndex),
		KeyConditionExpression: aws.String("#s = :a"), ExpressionAttributeNames: map[string]string{"#s": "status"},
		ExpressionAttributeValues: map[string]ddbtypes.AttributeValue{":a": s("active")}, ScanIndexForward: aws.Bool(false)})
	if err != nil {
		return nil, err
	}
	var act []*releaseRow
	for _, it := range r.Items {
		rr := parseRelease(it)
		if (rr.available == nil || *rr.available) && pcr0RE.MatchString(rr.release) {
			act = append(act, rr)
		}
	}
	if len(act) == 0 {
		return nil, vaultError(503, "vault_unavailable", "The vault service is not available yet", map[string]any{"retry_after": 300})
	}
	for _, rel := range act {
		inst, err := a.pickInstance(ctx, rel.release, now)
		if err != nil {
			return nil, err
		}
		if inst != nil {
			return describe(inst), nil
		}
	}
	a.requestStart(act[0].release)
	return nil, releaseStarting(act[0].release)
}

// --- requests ---

func (a *API) enqueue(ctx context.Context, op, guid string, v *vaultRow, requestID string, inst *instanceRow, kid, env, manifestSHA string) error {
	return a.enqueueWith(ctx, op, guid, v, requestID, inst, kid, env, manifestSHA, "", requestTTLS, nil)
}

// enqueueWith is enqueue with vault.ts's extra fields: the recovery's
// browser_key (after manifest_sha256), the slot's TTL and extra slot
// attributes (a register's recovery_id).
func (a *API) enqueueWith(ctx context.Context, op, guid string, v *vaultRow, requestID string, inst *instanceRow, kid, env, manifestSHA, browserKey string,
	ttlS int64, slot map[string]ddbtypes.AttributeValue) error {
	created := a.nowISO()
	item := map[string]ddbtypes.AttributeValue{"request_id": s(requestID), "vault_id": s(v.VaultID), "user_guid": s(guid), "op": s(op),
		"status": s("queued"), "instance_id": s(inst.InstanceID), "created_at": s(created), "expires_at": n(a.nowS() + ttlS)}
	for k, x := range slot {
		item[k] = x
	}
	c := callerOf(ctx)
	if c != nil && c.app != nil {
		item["app_kid"] = s(c.app.kid) // only this key may poll it (MEMBER-API 2.0.0)
		ks := a.keys()
		a.mu.Lock()
		ks.slotSigner[requestID] = c.app
		a.mu.Unlock()
	}
	_, err := a.cfg.DDB.PutItem(ctx, &dynamodb.PutItemInput{TableName: &a.cfg.Tables.Requests, ConditionExpression: aws.String("attribute_not_exists(request_id)"),
		Item: item})
	if err != nil {
		if code(err) == "ConditionalCheckFailedException" {
			return vaultError(409, "duplicate_request", "request_id has already been used", nil)
		}
		return err
	}
	// §11.5 queue message, in the spec's member order (as vault.ts builds
	// it with JSON.stringify).
	var b strings.Builder
	b.WriteString(`{"v":1,"op":` + jsonString(op) + `,"vault_id":` + jsonString(v.VaultID) + `,"user_guid":` + jsonString(guid) +
		`,"request_id":` + jsonString(requestID))
	if env != "" {
		b.WriteString(`,"etk_kid":` + jsonString(kid) + `,"envelope":` + jsonString(env))
	}
	if manifestSHA != "" {
		b.WriteString(`,"manifest_sha256":` + jsonString(manifestSHA)) // enroll and unlock (0.10.0)
	}
	if browserKey != "" {
		b.WriteString(`,"browser_key":` + jsonString(browserKey)) // recovery (§11.11.1)
	}
	if (op == "enroll" || op == "recovery_register") && c != nil && c.app != nil {
		// The key the request was signed with (0.15.0, §11.5).
		b.WriteString(`,"app_key":` + jsonString(base64.StdEncoding.EncodeToString(c.app.der)))
	}
	if op == "enroll" || op == "unlock" || op == "account" {
		b.WriteString(`,"account":` + string(a.Snapshot(guid))) // §11.13; enroll since 0.18.0 (§11.5)
	}
	b.WriteString(`,"enqueued_at":` + jsonString(created) + `}`)
	body := b.String()
	if _, err := a.cfg.SQS.SendMessage(ctx, &sqs.SendMessageInput{QueueUrl: &inst.QueueURL, MessageBody: &body}); err != nil {
		_, _ = a.cfg.DDB.UpdateItem(ctx, &dynamodb.UpdateItemInput{TableName: &a.cfg.Tables.Requests,
			Key: map[string]ddbtypes.AttributeValue{"request_id": s(requestID)}, UpdateExpression: aws.String("SET #s = :e"),
			ExpressionAttributeNames: map[string]string{"#s": "status"}, ExpressionAttributeValues: map[string]ddbtypes.AttributeValue{":e": s("expired")}})
		c := code(err)
		if c == "QueueDoesNotExist" || c == "AWS.SimpleQueueService.NonExistentQueue" {
			return instanceMoved()
		}
		return &apiError{status: 500, code: "internal", msg: "Could not queue the request"}
	}
	if a.cfg.Sent != nil {
		a.cfg.Sent(requestID, inst.QueueURL, body)
	}
	return nil
}

func jsonString(v string) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func (a *API) routeCheck(ctx context.Context, v *vaultRow, instanceID string, now int64) (*instanceRow, error) {
	inst, err := a.liveInstance(ctx, instanceID, now)
	if err != nil {
		return nil, err
	}
	if inst == nil {
		return nil, instanceMoved()
	}
	holder, err := a.liveLease(ctx, v, now)
	if err != nil {
		return nil, err
	}
	if holder != nil && holder.InstanceID != instanceID {
		return nil, instanceMoved()
	}
	return inst, nil
}

// --- routes ---

func (a *API) status(ctx context.Context, guid string) (any, error) {
	_, cur, err := a.currentVault(ctx, guid)
	if err != nil {
		return nil, err
	}
	v := active(cur)
	if v == nil {
		return map[string]any{"vault": nil}, nil
	}
	now := a.nowS()
	nul := func(s string) any {
		if s == "" {
			return nil
		}
		return s
	}
	if err := a.refreshRegistered(ctx, guid, v); err != nil {
		return nil, err
	}
	// A vault runs only under a live lease: unlocked without one is a
	// vault that stopped before its host recorded the lock (0.10.6 §11.5).
	leased := v.Lease != nil && v.Lease.expires > now
	state := v.State
	if state == "unlocked" && !leased {
		state = "locked"
	}
	var rec any
	if rn := a.recoveryNowS(); recoveryActive(v.Recovery, rn) {
		rec = map[string]any{"state": recoveryState(v.Recovery, rn), "available_at": isoS(v.Recovery.AvailableAt)}
	}
	return map[string]any{"vault": map[string]any{"vault_id": v.VaultID, "state": state, "sealed_release": nul(v.SealedRelease),
		"vault_version": nul(v.VaultVersion), "state_version": v.StateVersion, "leased": leased,
		"recovery": rec, "created_at": v.CreatedAt, "updated_at": v.UpdatedAt}}, nil
}

func (a *API) enclave(ctx context.Context, guid string, requested *string) (any, error) {
	now := a.nowS()
	if requested != nil && !pcr0RE.MatchString(*requested) {
		return nil, badRequest("release must be a PCR0 (96 lowercase hex)")
	}
	_, cur, err := a.currentVault(ctx, guid)
	if err != nil {
		return nil, err
	}
	v := active(cur)
	holder, err := a.liveLease(ctx, v, now)
	if err != nil {
		return nil, err
	}
	if requested != nil {
		if v == nil {
			return nil, notFound("No vault is enrolled")
		}
		if holder != nil {
			if holder.Release == *requested {
				return describe(holder), nil
			}
			return nil, vaultError(409, "vault_busy", "The vault is open on another release; retry after its lease ends",
				map[string]any{"retry_after": max(1, v.Lease.expires-now)})
		}
		return a.routeToRelease(ctx, *requested, now)
	}
	if holder != nil {
		return describe(holder), nil
	}
	if v != nil && v.SealedRelease != "" {
		return a.routeToRelease(ctx, v.SealedRelease, now)
	}
	return a.routeForEnrollment(ctx, now)
}

func (a *API) enroll(ctx context.Context, guid string, body map[string]any) (any, error) {
	rid, err := field(body, "request_id", ulidRE, "a ULID")
	if err != nil {
		return nil, err
	}
	iid, err := field(body, "instance_id", instanceIDRE, "an instance id")
	if err != nil {
		return nil, err
	}
	kid, err := field(body, "etk_kid", kidRE, "16 lowercase hex")
	if err != nil {
		return nil, err
	}
	env, err := checkEnvelope(body["envelope"], envelopeLarge, kid)
	if err != nil {
		return nil, err
	}
	ms, err := field(body, "manifest_sha256", sha256RE, "64 lowercase hex")
	if err != nil {
		return nil, err
	}
	now := a.nowS()
	pointer, cur, err := a.currentVault(ctx, guid)
	if err != nil {
		return nil, err
	}
	inst, err := a.routeCheck(ctx, active(cur), iid, now)
	if err != nil {
		return nil, err
	}
	rel, err := a.releaseRow(ctx, inst.Release)
	if err != nil {
		return nil, err
	}
	if rel == nil || rel.status != "active" {
		return nil, instanceMoved()
	}
	v, err := a.vaultForEnrollment(ctx, guid, pointer, cur)
	if err != nil {
		return nil, err
	}
	if err := a.enqueue(ctx, "enroll", guid, v, rid, inst, kid, env, ms); err != nil {
		return nil, err
	}
	return map[string]any{"vault_id": v.VaultID, "request_id": rid}, nil
}

func (a *API) unlock(ctx context.Context, guid string, body map[string]any) (any, error) {
	vid, err := field(body, "vault_id", vaultIDRE, "32 lowercase hex")
	if err != nil {
		return nil, err
	}
	rid, err := field(body, "request_id", ulidRE, "a ULID")
	if err != nil {
		return nil, err
	}
	iid, err := field(body, "instance_id", instanceIDRE, "an instance id")
	if err != nil {
		return nil, err
	}
	kid, err := field(body, "etk_kid", kidRE, "16 lowercase hex")
	if err != nil {
		return nil, err
	}
	env, err := checkEnvelope(body["envelope"], envelopeLarge, kid)
	if err != nil {
		return nil, err
	}
	ms, err := field(body, "manifest_sha256", sha256RE, "64 lowercase hex")
	if err != nil {
		return nil, err
	}
	_, cur, err := a.currentVault(ctx, guid)
	if err != nil {
		return nil, err
	}
	v := active(cur)
	if v == nil || v.VaultID != vid {
		return nil, notFound("No such vault")
	}
	inst, err := a.routeCheck(ctx, v, iid, a.nowS())
	if err != nil {
		return nil, err
	}
	if err := a.enqueue(ctx, "unlock", guid, v, rid, inst, kid, env, ms); err != nil {
		return nil, err
	}
	return map[string]any{"vault_id": v.VaultID, "request_id": rid}, nil
}

func (a *API) lock(ctx context.Context, guid string, body map[string]any) (any, error) {
	vid, err := field(body, "vault_id", vaultIDRE, "32 lowercase hex")
	if err != nil {
		return nil, err
	}
	rid, err := field(body, "request_id", ulidRE, "a ULID")
	if err != nil {
		return nil, err
	}
	_, cur, err := a.currentVault(ctx, guid)
	if err != nil {
		return nil, err
	}
	v := active(cur)
	if v == nil || v.VaultID != vid {
		return nil, notFound("No such vault")
	}
	holder, err := a.liveLease(ctx, v, a.nowS())
	if err != nil {
		return nil, err
	}
	if holder != nil {
		if err := a.enqueue(ctx, "lock", guid, v, rid, holder, "", "", ""); err != nil {
			return nil, err
		}
	} else {
		item := map[string]ddbtypes.AttributeValue{"request_id": s(rid), "vault_id": s(v.VaultID), "user_guid": s(guid), "op": s("lock"),
			"status": s("done"), "created_at": s(a.nowISO()), "expires_at": n(a.nowS() + requestTTLS)}
		if c := callerOf(ctx); c != nil && c.app != nil {
			item["app_kid"] = s(c.app.kid)
		}
		_, err := a.cfg.DDB.PutItem(ctx, &dynamodb.PutItemInput{TableName: &a.cfg.Tables.Requests, ConditionExpression: aws.String("attribute_not_exists(request_id)"),
			Item: item})
		if err != nil {
			if code(err) == "ConditionalCheckFailedException" {
				return nil, vaultError(409, "duplicate_request", "request_id has already been used", nil)
			}
			return nil, err
		}
	}
	return map[string]any{"vault_id": v.VaultID, "request_id": rid}, nil
}

func (a *API) request(ctx context.Context, guid, rid string) (any, error) {
	if !ulidRE.MatchString(rid) {
		return nil, badRequest("Malformed request id")
	}
	r, err := a.cfg.DDB.GetItem(ctx, &dynamodb.GetItemInput{TableName: &a.cfg.Tables.Requests, ConsistentRead: aws.Bool(true),
		Key: map[string]ddbtypes.AttributeValue{"request_id": s(rid)}})
	if err != nil {
		return nil, err
	}
	it := r.Item
	now := a.nowS()
	exp, _ := num(it, "expires_at")
	if it == nil || str(it, "user_guid") != guid || exp <= now {
		return nil, notFound("No such request")
	}
	if c := callerOf(ctx); c != nil && c.app != nil && str(it, "app_kid") != c.app.kid {
		return nil, notFound("No such request") // another key's slot (MEMBER-API 2.0.0)
	}
	st := str(it, "status")
	if st == "queued" {
		if c, err := time.Parse(time.RFC3339Nano, str(it, "created_at")); err == nil && c.Unix()+queueRetentionS+expirySlackS < now {
			st = "expired"
		}
	}
	if st != "queued" && st != "done" && st != "expired" {
		st = "expired"
	}
	out := map[string]any{"status": st}
	if st == "done" {
		if e := str(it, "envelope"); e != "" {
			if b, err := base64.StdEncoding.DecodeString(e); err == nil && len(b) == resultEnvelope && base64.StdEncoding.EncodeToString(b) == e {
				out["envelope"] = e
			}
		}
		if c := str(it, "code"); codeRE.MatchString(c) {
			out["code"] = c
		}
		// The app polls its register result: the moment to retire the
		// code (0.10.6 §11.11.7).
		if isRegisteredSlot(it) && vaultIDRE.MatchString(str(it, "vault_id")) {
			g, err := a.cfg.DDB.GetItem(ctx, &dynamodb.GetItemInput{TableName: &a.cfg.Tables.Vaults, ConsistentRead: aws.Bool(true),
				Key: map[string]ddbtypes.AttributeValue{"vault_id": s(str(it, "vault_id"))}})
			if err != nil {
				return nil, err
			}
			if v := parseVault(g.Item); v != nil && v.Recovery != nil && v.UserGUID == guid && v.Recovery.ID == str(it, "recovery_id") {
				a.registeredBy(v.VaultID, rid)
				if _, err := a.markRegistered(ctx, v, v.Recovery); err != nil {
					return nil, err
				}
			}
		}
	}
	return out, nil
}
