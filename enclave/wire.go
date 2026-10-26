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
	"github.com/vettid/vettid-vault/vms/peerwire"
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
	// OpRecoveryOpen is a recovery attempt (0.33.0, release R, §11.14.6):
	// sealed like a register.
	OpRecoveryOpen = "recovery_open"
	// OpAccount carries the member's account snapshot to a running vault
	// (0.15.0, §11.13): no envelope, no lease; dropped without a running
	// vault.
	OpAccount = "account"
	// OpDeleteResume finishes a deletion that the vault itself marked and
	// that stopped before its `deleted` report (0.51.0, §11.5, §12.5): no
	// envelope, no lease, answered done. It is never an authority to
	// delete (VAULT-HOST-PROTOCOL P20).
	OpDeleteResume = "delete_resume"
)

// typeDeleteResume is the job type of a delete_resume inside the enclave
// (supervisor to vault process only; no app sends it).
const typeDeleteResume = "vault.delete_resume"

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

// The lock operation's answers (0.29.0, release L, §11.5), written after
// the lock: the vault ran here and is locked (also when its final flush
// failed); no process for the vault here; the vault runs under a newer
// unlock (another unlock_id, or an unlock queued at or after this lock)
// and nothing was done.
const (
	CodeLocked     = "locked"
	CodeNotRunning = "not_running"
	CodeStale      = "stale"
)

// EnqueuedAtLayout is enqueued_at's form when the enclave writes a queue
// message (tests, tools): RFC 3339 in UTC with milliseconds, as the member
// API writes it.
const EnqueuedAtLayout = "2006-01-02T15:04:05.000Z07:00"

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
// (vaultipc 10, hostproto): [event, vault_id, release, vault_version,
// state_version, app_key (SPKI DER or empty), app_key_seq,
// credential_backup, name_seq, first_name, last_name, next, header_seq,
// next_cleared, cancelled_recovery_id]; name_seq, first_name and
// last_name (0.18.0) are "0", "" and "" except for account_name;
// cancelled_recovery_id (0.49.0) is empty except on the unlocked or moved
// event of an unlock that cancelled a recovery.
func LifecycleFields(ev vault.LifecycleEvent) [][]byte {
	seq, first, last := "0", "", ""
	if n := ev.Name; n != nil {
		seq, first, last = strconv.FormatUint(n.Seq, 10), n.FirstName, n.LastName
	}
	cleared := ""
	if ev.NextCleared {
		cleared = "1"
	}
	return append(hostproto.Strings(ev.Event, ev.VaultID, ev.Release, ev.VaultVersion, strconv.Itoa(ev.StateVersion)),
		ev.AppKey, []byte(strconv.FormatUint(ev.AppKeySeq, 10)), []byte(BackupField(ev.CredentialBackup)),
		[]byte(seq), []byte(first), []byte(last),
		// Release R (§11.5): next ("1", "0" or ""), header_seq, next_cleared ("1" or "").
		[]byte(BackupField(ev.Next)), []byte(strconv.FormatUint(ev.HeaderSeq, 10)), []byte(cleared),
		// 0.49.0 (§11.5): the recovery the unlock behind the event ended.
		[]byte(ev.CancelledRecoveryID))
}

// LifecycleFieldCount is the number of LifecycleFields (release R: 14;
// 0.49.0: 15).
const LifecycleFieldCount = 15

// ParseCancelledField decodes LifecycleFields' cancelled_recovery_id for
// event: empty, or a ULID on unlocked or moved only (VAULT-MESSAGING
// 0.49.0 §11.5, VAULT-HOST-PROTOCOL 0.1.13 §7.2).
func ParseCancelledField(event string, f []byte) (string, bool) {
	if len(f) == 0 {
		return "", true
	}
	id := string(f)
	if !envelope.ValidULID(id) || event != "unlocked" && event != "moved" {
		return "", false
	}
	return id, true
}

// ParseNextFields decodes LifecycleFields' release R members.
func ParseNextFields(next, hseq, cleared []byte) (*bool, uint64, bool, bool) {
	n, ok := ParseBackupField(string(next))
	if !ok {
		return nil, 0, false, false
	}
	hs, err := strconv.ParseUint(string(hseq), 10, 53)
	if err != nil || strconv.FormatUint(hs, 10) != string(hseq) {
		return nil, 0, false, false
	}
	switch string(cleared) {
	case "", "1":
	default:
		return nil, 0, false, false
	}
	return n, hs, string(cleared) == "1", true
}

// ParseNameFields decodes LifecycleFields' last three: nil for "0", "",
// "" (no name request); a canonical seq ≥ 1 and two names
// (peerwire.ValidAccountName) for account_name. ok is false for anything
// else.
func ParseNameFields(seq, first, last []byte) (*vault.NameChange, bool) {
	if string(seq) == "0" && len(first) == 0 && len(last) == 0 {
		return nil, true
	}
	n, err := strconv.ParseUint(string(seq), 10, 53)
	if err != nil || n == 0 || strconv.FormatUint(n, 10) != string(seq) ||
		!peerwire.ValidAccountName(string(first)) || !peerwire.ValidAccountName(string(last)) {
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
	// SignedAt, KeyID and Sig are the member API's signature over a
	// recovery or recovery_cancel (0.33.0, release R, §11.14.8),
	// REQUIRED for both; the enclave verifies them before anything else.
	SignedAt string
	KeyID    string
	Sig      []byte
	// RecoveryID is a recovery_cancel's optional recovery_id (0.49.0,
	// §11.14.8): the recovery it means, covered by the signature (its
	// eighth line). Empty: the cancel ends whatever is in progress.
	RecoveryID string
	// UnlockID is a lock's optional unlock_id (0.29.0, release L, §11.5
	// "The lock operation"): with it the lock is bound to that unlock;
	// without, it is unconditional and ordered by EnqueuedAt.
	UnlockID string
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
	if err != nil || msOK != (q.Op == OpEnroll || q.Op == OpUnlock || q.Op == OpRecoveryOpen) || msOK && !manifest.ValidSHA256Hex(ms) {
		return nil, ErrMalformed
	}
	q.ManifestSHA256 = ms
	signed := q.Op == OpRecovery || q.Op == OpRecoveryCancel
	sa, saOK, err1 := o.OptString("signed_at")
	kid2, kidOK2, err2 := o.OptString("key_id")
	sg, sgOK, err3 := o.OptString("sig")
	if err1 != nil || err2 != nil || err3 != nil || saOK != signed || kidOK2 != signed || sgOK != signed {
		return nil, ErrMalformed
	}
	if signed {
		if len(sa) > 64 || kid2 == "" || len(kid2) > 128 {
			return nil, ErrMalformed
		}
		if q.Sig, err = strictjson.DecodeStd(sg, -1); err != nil || len(q.Sig) == 0 || len(q.Sig) > 80 {
			return nil, ErrMalformed
		}
		q.SignedAt, q.KeyID = sa, kid2
	}
	uid, uidOK, err := o.OptString("unlock_id")
	if err != nil || uidOK && (q.Op != OpLock || !altchan.ValidUnlockID(uid)) {
		return nil, ErrMalformed
	}
	q.UnlockID = uid
	rid, ridOK, err := o.OptString("recovery_id")
	if err != nil || ridOK && (q.Op != OpRecoveryCancel || !envelope.ValidULID(rid)) {
		return nil, ErrMalformed
	}
	q.RecoveryID = rid
	ak, akOK, err := o.OptString("app_key")
	if err != nil || akOK != (q.Op == OpEnroll || q.Op == OpRecoveryRegister || q.Op == OpRecoveryOpen) {
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
	case OpEnroll, OpUnlock, OpRecoveryRegister, OpRecoveryOpen:
		if !envOK || !kidOK {
			return nil, ErrMalformed
		}
		if q.Envelope, err = strictjson.DecodeStd(env, -1); err != nil || len(q.Envelope) != envelope.OverheadSealed+altchan.RequestPaddedSize {
			return nil, ErrMalformed
		}
	case OpLock, OpDelete, OpDeleteResume, OpRecovery, OpRecoveryCancel, OpAccount:
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
	if q.Op == OpEnroll || q.Op == OpUnlock || q.Op == OpRecoveryOpen {
		b.String("manifest_sha256", q.ManifestSHA256)
	}
	if q.Op == OpRecovery {
		b.Base64("browser_key", q.BrowserKey)
	}
	if q.Op == OpEnroll || q.Op == OpRecoveryRegister || q.Op == OpRecoveryOpen {
		b.Base64("app_key", q.AppKey)
	}
	if q.Op == OpRecovery || q.Op == OpRecoveryCancel {
		b.String("signed_at", q.SignedAt).String("key_id", q.KeyID).Base64("sig", q.Sig)
	}
	if q.Op == OpRecoveryCancel && q.RecoveryID != "" {
		b.String("recovery_id", q.RecoveryID)
	}
	if len(q.Account) > 0 {
		b.Raw("account", q.Account)
	}
	if q.Op == OpLock && q.UnlockID != "" {
		b.String("unlock_id", q.UnlockID)
	}
	// Milliseconds, as the member API writes it (new Date().toISOString()):
	// an unconditional lock is ordered by this time (0.29.0, §11.5), and a
	// second-precision copy would make a lock and an unlock of the same
	// second equal, and so stale.
	return b.String("enqueued_at", q.EnqueuedAt.UTC().Format(EnqueuedAtLayout)).Bytes()
}

func hasEnvelope(op string) bool {
	return op == OpEnroll || op == OpUnlock || op == OpRecoveryRegister || op == OpRecoveryOpen
}

// requestType is the inner type of each op's request.
var requestType = map[string]string{OpEnroll: altchan.TypeEnroll, OpUnlock: altchan.TypeUnlock,
	OpRecovery: altchan.TypeRecoveryRequest, OpRecoveryCancel: altchan.TypeRecoveryCancel,
	OpRecoveryRegister: altchan.TypeRecoveryRegister, OpRecoveryOpen: altchan.TypeRecoveryOpen,
	OpDeleteResume: typeDeleteResume}

// Response is what the enclave returns for a queue message. The parent
// writes Envelope to the response slot (§11.5); the API and parent see
// only its fixed size.
type Response struct {
	RequestID string
	Status    string
	Envelope  []byte
	// Code is CodeRecoveryRegistered (0.10.6), CodeRecoveryUnavailable
	// (0.16.0), CodeRecoveryAttempt (0.33.0), CodeRecoveryCancelled or
	// CodeRecoveryNotCurrent (0.49.0), a lock's CodeLocked, CodeNotRunning
	// or CodeStale (0.29.0, release L), or empty.
	Code string
	// The clear members of release R (§11.5, §11.14.5, §11.14.11): a
	// recovery's not_before, expires and earliest; a counted open's
	// retry_at and expires when a wait began; a refusal's reason.
	Clear Marker
}

// Marker is an answer's clear marker and members (release R).
type Marker struct {
	Code      string
	NotBefore time.Time
	Expires   time.Time
	Earliest  bool
	RetryAt   time.Time
	Reason    string
	// CancelledRecoveryID is the recovery an unlock ended, with
	// CodeRecoveryCancelled (0.49.0, §11.5).
	CancelledRecoveryID string
}

// CodeRecoveryAttempt marks the answer to a recovery_open that was counted
// (0.33.0, §11.14.11); it never says whether the guess was right.
const CodeRecoveryAttempt = "recovery_attempt"

// CodeRecoveryCancelled marks the answer to an unlock whose sealed result
// is {"ok": true, "recovery_cancelled": true}, with the clear
// cancelled_recovery_id of the recovery it ended (0.49.0, §11.5,
// §11.11.4).
const CodeRecoveryCancelled = "recovery_cancelled"

// CodeRecoveryNotCurrent marks the answer to a recovery_cancel that named
// a recovery and cancelled nothing (another recovery, or none; 0.49.0,
// §11.14.8). A cancel's answer has no envelope: it is the one code
// without one.
const CodeRecoveryNotCurrent = "recovery_not_current"

func ts(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// Encode encodes the marker for the vault process's Open answer (vaultipc
// 8): "" for none, else compact JSON.
func (m Marker) Encode() []byte {
	if m == (Marker{}) {
		return nil
	}
	b := strictjson.NewBuilder().String("code", m.Code)
	for _, f := range []struct {
		n string
		t time.Time
	}{{"not_before", m.NotBefore}, {"expires", m.Expires}, {"retry_at", m.RetryAt}} {
		if !f.t.IsZero() {
			b.String(f.n, f.t.UTC().Format(time.RFC3339Nano))
		}
	}
	if m.Earliest {
		b.Bool("earliest", true)
	}
	if m.Reason != "" {
		b.String("reason", m.Reason)
	}
	if m.CancelledRecoveryID != "" {
		b.String("cancelled_recovery_id", m.CancelledRecoveryID)
	}
	return b.Bytes()
}

// markerCodes are the codes each op may carry (the supervisor drops any
// other).
var markerCodes = map[string]map[string]bool{
	OpRecovery:         {CodeRecoveryUnavailable: true, "": true},
	OpRecoveryRegister: {CodeRecoveryRegistered: true},
	OpRecoveryOpen:     {CodeRecoveryAttempt: true},
	OpUnlock:           {CodeRecoveryCancelled: true},  // 0.49.0
	OpRecoveryCancel:   {CodeRecoveryNotCurrent: true}, // 0.49.0
}

var markerReasons = map[string]bool{"": true, "no_backup": true, "no_credential": true, "not_offered": true}

// DecodeMarker decodes Encode for op; ok false for anything an op cannot
// carry.
func DecodeMarker(op string, b []byte) (Marker, bool) {
	if len(b) == 0 {
		return Marker{}, true
	}
	o, err := strictjson.ParseObject(b)
	if err != nil {
		return Marker{}, false
	}
	var m Marker
	if m.Code, err = o.String("code"); err != nil || !markerCodes[op][m.Code] {
		return Marker{}, false
	}
	for _, f := range []struct {
		n string
		t *time.Time
	}{{"not_before", &m.NotBefore}, {"expires", &m.Expires}, {"retry_at", &m.RetryAt}} {
		if s, ok, err := o.OptString(f.n); err != nil {
			return Marker{}, false
		} else if ok {
			if *f.t, err = time.Parse(time.RFC3339Nano, s); err != nil {
				return Marker{}, false
			}
		}
	}
	if o.Has("earliest") {
		if m.Earliest, err = o.Bool("earliest"); err != nil {
			return Marker{}, false
		}
	}
	if s, ok, err := o.OptString("reason"); err != nil || ok && !markerReasons[s] {
		return Marker{}, false
	} else if ok {
		m.Reason = s
	}
	// 0.49.0: the cancelled recovery's id, a ULID, with recovery_cancelled
	// only and always.
	if s, ok, err := o.OptString("cancelled_recovery_id"); err != nil || ok != (m.Code == CodeRecoveryCancelled) || ok && !envelope.ValidULID(s) {
		return Marker{}, false
	} else if ok {
		m.CancelledRecoveryID = s
	}
	return m, true
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
	if c := r.Clear; !c.NotBefore.IsZero() {
		b.String("not_before", ts(c.NotBefore))
		if c.Earliest {
			b.Bool("earliest", true)
		}
	}
	if c := r.Clear; !c.RetryAt.IsZero() {
		b.String("retry_at", ts(c.RetryAt))
	}
	if c := r.Clear; !c.Expires.IsZero() {
		b.String("expires", ts(c.Expires))
	}
	if r.Clear.Reason != "" {
		b.String("reason", r.Clear.Reason)
	}
	if r.Clear.CancelledRecoveryID != "" {
		b.String("cancelled_recovery_id", r.Clear.CancelledRecoveryID)
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
	// A code comes with the envelope, except recovery_not_current (0.49.0,
	// a named recovery_cancel's answer), which never has one.
	if c, ok, err := o.OptString("code"); err != nil {
		return nil, ErrMalformed
	} else if ok {
		switch c {
		case CodeRecoveryRegistered, CodeRecoveryUnavailable, CodeRecoveryAttempt, CodeRecoveryCancelled:
			if r.Envelope == nil {
				return nil, ErrMalformed
			}
		case CodeRecoveryNotCurrent, CodeLocked, CodeNotRunning, CodeStale:
			// A lock's answers (0.29.0, release L) have no envelope.
			if r.Envelope != nil {
				return nil, ErrMalformed
			}
		default:
			return nil, ErrMalformed
		}
		r.Code = c
	}
	// 0.49.0: cancelled_recovery_id, a ULID, with recovery_cancelled only
	// and always.
	if v, ok, err := o.OptString("cancelled_recovery_id"); err != nil || ok != (r.Code == CodeRecoveryCancelled) || ok && !envelope.ValidULID(v) {
		return nil, ErrMalformed
	} else if ok {
		r.Clear.CancelledRecoveryID = v
	}
	// Release R's clear members.
	for _, f := range []struct {
		n string
		t *time.Time
	}{{"not_before", &r.Clear.NotBefore}, {"expires", &r.Clear.Expires}, {"retry_at", &r.Clear.RetryAt}} {
		if v, ok, err := o.OptString(f.n); err != nil {
			return nil, ErrMalformed
		} else if ok {
			if *f.t, err = time.Parse(time.RFC3339, v); err != nil {
				return nil, ErrMalformed
			}
		}
	}
	if o.Has("earliest") {
		if r.Clear.Earliest, err = o.Bool("earliest"); err != nil {
			return nil, ErrMalformed
		}
	}
	if v, ok, err := o.OptString("reason"); err != nil {
		return nil, ErrMalformed
	} else if ok {
		r.Clear.Reason = v
	}
	r.Clear.Code = r.Code
	return r, nil
}
