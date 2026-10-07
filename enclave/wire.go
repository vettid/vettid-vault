package enclave

import (
	"errors"
	"strconv"
	"time"

	"github.com/vettid/vettid-vault/internal/hostproto"
	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/altchan"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/manifest"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Queue operations (§11.5).
const (
	OpEnroll = "enroll"
	OpUnlock = "unlock"
	OpLock   = "lock"
	OpDelete = "delete"
	// Recovery (§11.11).
	OpRecovery         = "recovery"
	OpRecoveryCancel   = "recovery_cancel"
	OpRecoveryRegister = "recovery_register"
	// OpAccount carries the member's account snapshot to a running vault
	// (0.15.0, §11.13): no envelope, no lease; dropped without a running
	// vault.
	OpAccount = "account"
)

// Response statuses.
const (
	StatusDone       = "done"
	StatusETKUnknown = "etk_unknown"
)

// CodeRecoveryRegistered is the clear marker on the answer to a
// recovery_register whose sealed result is {"ok": true} (§11.5, §11.11.3,
// 0.10.6): the host copies it into the response slot's code, so that the
// member API stops releasing the spent code. It is the only response code
// that reflects a sealed outcome.
const CodeRecoveryRegistered = "recovery_registered"

// BackupField encodes a lifecycle event's backup bit for the host
// channels: "1", "0", or "" when not reported (0.16.0).
func BackupField(b *bool) string {
	switch {
	case b == nil:
		return ""
	case *b:
		return "1"
	}
	return "0"
}

// LifecycleFields encodes a lifecycle event for the host channels
// (vaultipc 6, hostproto): [event, vault_id, release, vault_version,
// state_version, app_key (SPKI DER or empty), app_key_seq,
// credential_backup, name_seq, first_name, last_name]; the last three
// (0.18.0) are "0", "" and "" except for account_name.
func LifecycleFields(ev vault.LifecycleEvent) [][]byte {
	seq, first, last := "0", "", ""
	if n := ev.Name; n != nil {
		seq, first, last = strconv.FormatUint(n.Seq, 10), n.FirstName, n.LastName
	}
	return append(hostproto.Strings(ev.Event, ev.VaultID, ev.Release, ev.VaultVersion, strconv.Itoa(ev.StateVersion)),
		ev.AppKey, []byte(strconv.FormatUint(ev.AppKeySeq, 10)), []byte(BackupField(ev.CredentialBackup)),
		[]byte(seq), []byte(first), []byte(last))
}

// LifecycleFieldCount is the number of LifecycleFields.
const LifecycleFieldCount = 11

// ParseNameFields decodes LifecycleFields' last three: nil for "0", "",
// "" (no name request); a canonical seq ≥ 1 and two names
// (vault.ValidAccountName) for account_name. ok is false for anything
// else.
func ParseNameFields(seq, first, last []byte) (*vault.NameChange, bool) {
	if string(seq) == "0" && len(first) == 0 && len(last) == 0 {
		return nil, true
	}
	n, err := strconv.ParseUint(string(seq), 10, 53)
	if err != nil || n == 0 || strconv.FormatUint(n, 10) != string(seq) ||
		!vault.ValidAccountName(string(first)) || !vault.ValidAccountName(string(last)) {
		return nil, false
	}
	return &vault.NameChange{Seq: n, FirstName: string(first), LastName: string(last)}, true
}

// ParseBackupField decodes BackupField; ok is false for anything else.
func ParseBackupField(s string) (*bool, bool) {
	switch s {
	case "":
		return nil, true
	case "1", "0":
		b := s == "1"
		return &b, true
	}
	return nil, false
}

// CodeRecoveryUnavailable is the clear marker on the answer to a recovery
// request the vault refused (no credential, or no backup copy of it;
// 0.16.0, §11.5, §11.11.2): the member API ends the recovery at once. It
// says no more than the backup bit the host already has.
const CodeRecoveryUnavailable = "recovery_unavailable"

// ErrMalformed is returned for a malformed queue message.
var ErrMalformed = errors.New("enclave: malformed message")

// maxQueueMessage bounds a queue message (a 13,444-byte envelope in base64
// plus the other members).
const maxQueueMessage = 24 * 1024

// QueueMessage is the SQS message the parent forwards unchanged (§11.5).
type QueueMessage struct {
	Op         string
	VaultID    string
	UserGUID   string
	RequestID  string
	ETKKid     suite.Kid
	Envelope   []byte
	EnqueuedAt time.Time
	// BrowserKey is the member's browser P-256 key (op recovery).
	BrowserKey []byte
	// ManifestSHA256 names the manifest the request was built with (ops
	// enroll and unlock, 0.10.0): the parent supplies that document from
	// manifests/<sha256>.json. A routing value only: the enclave checks
	// the document against the hash inside the sealed request.
	ManifestSHA256 string
	// AppKey is the app key the request was signed with at the API (SPKI
	// DER; enroll and recovery_register, 0.15.0): bound to the sealed
	// app.api_key (§11.3, §11.11.3).
	AppKey []byte
	// Account is the account snapshot (op account, REQUIRED; enroll,
	// REQUIRED since 0.18.0, refused by the enclave with bad_request when
	// absent or invalid; unlock, OPTIONAL; §11.5, §11.13): host data whose
	// names go to the vault's connections (§10.8).
	Account []byte
}

func validID(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

// validGUID accepts printable ASCII without spaces (member GUIDs).
func validGUID(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// ParseQueueMessage parses the queue message strictly. vault_id must be a
// store-safe id ([a-z0-9._-]).
func ParseQueueMessage(b []byte) (*QueueMessage, error) {
	if len(b) == 0 || len(b) > maxQueueMessage {
		return nil, ErrMalformed
	}
	o, err := strictjson.ParseObject(b)
	if err != nil {
		return nil, ErrMalformed
	}
	if v, err := o.Uint("v", 1, 1); err != nil || v != 1 {
		return nil, ErrMalformed
	}
	q := &QueueMessage{}
	if q.Op, err = o.String("op"); err != nil {
		return nil, ErrMalformed
	}
	if q.VaultID, err = o.String("vault_id"); err != nil || !validID(q.VaultID) {
		return nil, ErrMalformed
	}
	if q.UserGUID, err = o.String("user_guid"); err != nil || !validGUID(q.UserGUID) {
		return nil, ErrMalformed
	}
	if q.RequestID, err = o.String("request_id"); err != nil || !envelope.ValidULID(q.RequestID) {
		return nil, ErrMalformed
	}
	ea, err := o.String("enqueued_at")
	if err != nil {
		return nil, ErrMalformed
	}
	if q.EnqueuedAt, err = time.Parse(time.RFC3339Nano, ea); err != nil {
		return nil, ErrMalformed
	}
	kid, kidOK, err := o.OptString("etk_kid")
	if err != nil {
		return nil, ErrMalformed
	}
	if kidOK {
		if q.ETKKid, err = suite.ParseKidHex(kid); err != nil || q.ETKKid.String() != kid {
			return nil, ErrMalformed
		}
	}
	env, envOK, err := o.OptString("envelope")
	if err != nil {
		return nil, ErrMalformed
	}
	bk, bkOK, err := o.OptString("browser_key")
	if err != nil || bkOK != (q.Op == OpRecovery) {
		return nil, ErrMalformed
	}
	if bkOK {
		if q.BrowserKey, err = strictjson.DecodeStd(bk, altchan.BrowserKeySize); err != nil {
			return nil, ErrMalformed
		}
	}
	ms, msOK, err := o.OptString("manifest_sha256")
	if err != nil || msOK != (q.Op == OpEnroll || q.Op == OpUnlock) || msOK && !manifest.ValidSHA256Hex(ms) {
		return nil, ErrMalformed
	}
	q.ManifestSHA256 = ms
	ak, akOK, err := o.OptString("app_key")
	if err != nil || akOK != (q.Op == OpEnroll || q.Op == OpRecoveryRegister) {
		return nil, ErrMalformed
	}
	if akOK {
		if _, q.AppKey, err = altchan.ParseAppKey(ak); err != nil {
			return nil, ErrMalformed
		}
	}
	// An enroll without one parses: the enclave answers it bad_request
	// (§11.5, 0.18.0), which needs the sealed request opened.
	if raw, ok := o["account"]; ok != (q.Op == OpAccount) && !(ok && (q.Op == OpUnlock || q.Op == OpEnroll)) {
		return nil, ErrMalformed
	} else if ok {
		if len(raw) == 0 || raw[0] != '{' || len(raw) > 2*1024 {
			return nil, ErrMalformed // parsed strictly by the vault (§11.13)
		}
		q.Account = append([]byte(nil), raw...)
	}
	switch q.Op {
	case OpEnroll, OpUnlock, OpRecoveryRegister:
		if !envOK || !kidOK {
			return nil, ErrMalformed
		}
		if q.Envelope, err = strictjson.DecodeStd(env, -1); err != nil || len(q.Envelope) != envelope.OverheadSealed+altchan.RequestPaddedSize {
			return nil, ErrMalformed
		}
	case OpLock, OpDelete, OpRecovery, OpRecoveryCancel, OpAccount:
		if envOK || kidOK {
			return nil, ErrMalformed
		}
	default:
		return nil, ErrMalformed
	}
	return q, nil
}

// Marshal encodes the queue message (§11.5 member order).
func (q *QueueMessage) Marshal() []byte {
	b := strictjson.NewBuilder().Uint("v", 1).String("op", q.Op).String("vault_id", q.VaultID).
		String("user_guid", q.UserGUID).String("request_id", q.RequestID)
	if hasEnvelope(q.Op) { // absent for lock, delete, recovery and its cancel (§11.5)
		b.String("etk_kid", q.ETKKid.String()).Base64("envelope", q.Envelope)
	}
	if q.Op == OpEnroll || q.Op == OpUnlock {
		b.String("manifest_sha256", q.ManifestSHA256)
	}
	if q.Op == OpRecovery {
		b.Base64("browser_key", q.BrowserKey)
	}
	if q.Op == OpEnroll || q.Op == OpRecoveryRegister {
		b.Base64("app_key", q.AppKey)
	}
	if len(q.Account) > 0 {
		b.Raw("account", q.Account)
	}
	return b.String("enqueued_at", q.EnqueuedAt.UTC().Format(time.RFC3339)).Bytes()
}

func hasEnvelope(op string) bool { return op == OpEnroll || op == OpUnlock || op == OpRecoveryRegister }

// requestType is the inner type of each op's request.
var requestType = map[string]string{OpEnroll: altchan.TypeEnroll, OpUnlock: altchan.TypeUnlock,
	OpRecovery: altchan.TypeRecoveryRequest, OpRecoveryCancel: altchan.TypeRecoveryCancel,
	OpRecoveryRegister: altchan.TypeRecoveryRegister}

// Response is what the enclave returns for a queue message. The parent
// writes Envelope to the response slot (§11.5); the API and parent see
// only its fixed size.
type Response struct {
	RequestID string
	Status    string
	Envelope  []byte
	// Code is CodeRecoveryRegistered (0.10.6), CodeRecoveryUnavailable
	// (0.16.0) or empty.
	Code string
}

// Marshal encodes the response for the parent.
func (r *Response) Marshal() []byte {
	b := strictjson.NewBuilder().Uint("v", 1).String("request_id", r.RequestID).String("status", r.Status)
	if r.Envelope != nil {
		b.Base64("envelope", r.Envelope)
	}
	if r.Code != "" {
		b.String("code", r.Code)
	}
	return b.Bytes()
}

// opaque returns random bytes of a sealed result's size: the answer to a
// request no authenticated device can read, indistinguishable from a
// sealed result to the API and parent (§11.4, §11.9).
func opaque() []byte {
	b, err := suite.RandomBytes(altchan.ResultEnvelopeSize)
	if err != nil {
		return make([]byte, altchan.ResultEnvelopeSize)
	}
	return b
}

// ParseResponse parses a response (the parent's side).
func ParseResponse(b []byte) (*Response, error) {
	o, err := strictjson.ParseObject(b)
	if err != nil {
		return nil, ErrMalformed
	}
	r := &Response{}
	if r.RequestID, err = o.String("request_id"); err != nil {
		return nil, ErrMalformed
	}
	if r.Status, err = o.String("status"); err != nil {
		return nil, ErrMalformed
	}
	if s, ok, err := o.OptString("envelope"); err != nil {
		return nil, ErrMalformed
	} else if ok {
		if r.Envelope, err = strictjson.DecodeStd(s, altchan.ResultEnvelopeSize); err != nil {
			return nil, ErrMalformed
		}
	}
	if c, ok, err := o.OptString("code"); err != nil || ok && (c != CodeRecoveryRegistered && c != CodeRecoveryUnavailable || r.Envelope == nil) {
		return nil, ErrMalformed
	} else if ok {
		r.Code = c
	}
	return r, nil
}
