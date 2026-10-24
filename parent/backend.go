// Package parent is the enclave's host side (VAULT-PLAN V3): it runs on
// the EC2 instance, outside the enclave, and is untrusted
// (VAULT-MESSAGING §13.3). It moves opaque bytes and never parses
// envelopes, sealed results or stored objects:
//
//   - a vsock (TCP in development) control server for the enclave's
//     supervisor (package hostproto);
//   - a TCP forwarder from the enclave to an allowlist (relay, regional
//     KMS, Google's attestation status list) on port 443 only; TLS ends in
//     the enclave;
//   - the instance's SQS queue (created at boot, deleted at shutdown) and
//     its consumer, which forwards queue messages unchanged;
//   - the instance registry heartbeat and descriptor publication;
//   - vault leases (acquire, renew, release with conditional writes,
//     §11.1), lifecycle events and response slots in DynamoDB, in exactly
//     the shapes vettid.org's member API reads (lambda/member/vault.ts);
//   - S3 get/put/delete with create-only and version-matched writes for
//     the vault objects;
//   - the instance role's temporary credentials for the enclave's own
//     SigV4-signed KMS calls;
//   - a health endpoint, and structured logs that never contain
//     envelopes, keys or stored objects.
package parent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"
)

// Errors of the backends.
var (
	ErrNotFound = errors.New("parent: not found")
	ErrConflict = errors.New("parent: conditional write failed")
	// ErrLeaseHeld means the vault's lease belongs to another instance
	// (or the vault row does not exist).
	ErrLeaseHeld = errors.New("parent: lease held elsewhere")
	// ErrNotMarked: a `deleted` lifecycle event whose conditional update
	// of the vault row was refused (another instance holds the lease, or
	// there is no row). The parent does not sweep the vault's attachment
	// objects then (VAULT-HOST-PROTOCOL 0.1.9 P15).
	ErrNotMarked = errors.New("parent: vault row not marked deleted")
	// ErrAlarmNotWritten: a `deleted` event marked the row but its
	// vault_deleted notice was not written; the sweep goes ahead.
	ErrAlarmNotWritten = errors.New("parent: vault_deleted notice not written")
	// ErrQueueDeletedRecently means a queue of the same name was deleted
	// less than 60 s ago and SQS refuses to create it yet (a restart right
	// after a clean stop). Queues.Create returns it wrapped.
	ErrQueueDeletedRecently = errors.New("parent: queue deleted recently")
	// ErrQueueNotFound means the queue a receive named does not exist
	// (any more): the parent creates its queue again.
	ErrQueueNotFound = errors.New("parent: queue not found")
)

// Objects is the vault data bucket.
type Objects interface {
	// Get returns the object and its version (ETag).
	Get(ctx context.Context, key string) ([]byte, string, error)
	// Put writes create-only (ifMatch "") or version-matched.
	Put(ctx context.Context, key string, data []byte, ifMatch string) (string, error)
	// Delete deletes if the version matches.
	Delete(ctx context.Context, key string, ifMatch string) error
}

// ObjectRef is a listed object: its key and version (ETag).
type ObjectRef struct {
	Key, ETag string
}

// ObjectLister lists the bucket's objects under a prefix (P15: the host
// role may list vaults/*/att/* only).
type ObjectLister interface {
	ListObjects(ctx context.Context, prefix string) ([]ObjectRef, error)
}

// SweepTables is what P15's sweep needs of the vault table: the row's
// state before each pass, the sweeps left pending by an earlier parent,
// and the end of one.
type SweepTables interface {
	VaultState(ctx context.Context, vaultID string) (state string, exists bool, err error)
	PendingSweeps(ctx context.Context) ([]string, error)
	SweepDone(ctx context.Context, vaultID string, now time.Time) error
}

// QueueMessage is one received SQS message.
type QueueMessage struct {
	ID      string
	Body    []byte
	Receipt string
}

// Queues is the instance's SQS queue.
type Queues interface {
	// Create creates the queue (idempotent) and returns its URL.
	Create(ctx context.Context, name string) (string, error)
	// Receive returns ErrQueueNotFound (to errors.Is) if the queue does
	// not exist.
	Receive(ctx context.Context, url string) ([]QueueMessage, error)
	DeleteMessage(ctx context.Context, url, receipt string) error
	Destroy(ctx context.Context, url string) error
	// List returns the URLs of queues whose name starts with prefix,
	// with their creation times.
	List(ctx context.Context, prefix string) (map[string]time.Time, error)
}

// InstanceRow is a vault-instances item (§11.5; vault.ts InstanceRow).
type InstanceRow struct {
	InstanceID  string
	Release     string
	QueueURL    string
	Descriptor  []byte
	Attestation []byte
	HeartbeatAt int64
	ExpiresAt   int64
	Load        int
	// HeavyKDFFree is the enclave's Stats heavy_kdf_free (release R,
	// VAULT-HOST-PROTOCOL 0.1.10 §6.6): whether a recovery open's heavy
	// derivation could run now; nil when the enclave did not say.
	HeavyKDFFree *bool
}

// EventAlarmCredentialClone is the vault's content-free host alarm of a
// Protean Credential clone (VAULT-MESSAGING §3.5.9, §11.5): the parent
// records it on the vault row (alarm, alarm_pending) and the member API
// emails the member. It is the only alarm kind.
const EventAlarmCredentialClone = "alarm.credential_clone"

// Lifecycle is a lifecycle event for the vault table (§11.5).
type Lifecycle struct {
	Event        string
	VaultID      string
	Release      string
	VaultVersion string
	StateVersion int
	// AppKey (SPKI DER) and AppKeySeq are the vault's app key as the
	// enclave reports it (0.15.0, §11.5): on enrolled, unlocked, locked
	// and app_key. The parent writes app_key = {key, kid, seq} on the
	// vault row whatever the lease, when seq is higher than the row's
	// (enrolled: always).
	AppKey    []byte
	AppKeySeq uint64
	// CredentialBackup is the vault's backup bit (0.16.0, §11.5): on
	// enrolled, unlocked, locked and credential_backup; nil when not
	// reported. Written under the lease rule.
	CredentialBackup *bool
	// Name is the member's name request (0.18.0, §11.5): on account_name
	// only. The parent writes name_change = {seq, first_name, last_name,
	// at} and name_change_pending = true on the vault row whatever the
	// lease, when seq is higher than the row's.
	Name *NameChange
	// Release R (§11.5, §11.14.2): on unlocked and locked, whether the
	// header has a `next` part (nil: not reported) and its header_seq; on
	// app_key_next, the step-1 write's header_seq; NextCleared on an
	// app_key that repeats the current key and only clears app_key_next.
	Next        *bool
	HeaderSeq   uint64
	NextCleared bool
	// CancelledRecoveryID (0.49.0, VAULT-HOST-PROTOCOL 0.1.13 §7.2) is the
	// recovery that the unlock behind an unlocked or moved event ended, a
	// ULID, or empty. The parent writes a non-empty one to the vault row
	// as recovery_cancelled = {recovery_id, at (epoch s)} in the same
	// update as the event.
	CancelledRecoveryID string
	// KeepLease is set by the parent, never parsed from the enclave: a
	// "locked" that the enclave reports while an enroll or unlock of the
	// same vault is in flight here (the enclave locks a running vault
	// before it opens it again) leaves the lease in place. The request
	// took the lease for the vault it is opening; the parent gives it
	// back afterwards if the vault did not open (§11.1).
	KeepLease bool
}

// NameChange is account_name's request (0.18.0, §10.8, §11.5).
type NameChange struct {
	Seq       uint64
	FirstName string
	LastName  string
}

// EventAccountName reports the member's approved name change request
// (0.18.0, §11.5).
const EventAccountName = "account_name"

// EventCredentialBackup reports a changed backup bit (0.16.0, §11.5).
const EventCredentialBackup = "credential_backup"

// EventAppKey is the lifecycle event of a changed app key (a transfer or
// a recovery, §11.5, 0.15.0).
const EventAppKey = "app_key"

// EventAppKeyNext is the next app key of a replacement of the app in
// progress (release R, §11.5): written as app_key_next on the vault row.
const EventAppKeyNext = "app_key_next"

// AppKeyID is akid: the first 16 bytes of SHA-256(SPKI DER), 32 lowercase
// hex (§11.12.2).
func AppKeyID(der []byte) string {
	h := sha256.Sum256(der)
	return hex.EncodeToString(h[:16])
}

// Slot is a response slot update (§11.5): Status "done" with Envelope
// and/or Code, or "expired".
type Slot struct {
	Status   string
	Envelope []byte
	Code     string
	// Release R's clear members (VAULT-HOST-PROTOCOL 0.1.10 §6.1,
	// VAULT-MESSAGING §11.5): a recovery's not_before, expires and
	// earliest; a counted open's retry_at and expires; a refusal's reason.
	// RFC 3339 strings, "" when absent.
	NotBefore, Expires, RetryAt, Reason string
	Earliest                            bool
	// CancelledRecoveryID is an unlock slot's cancelled_recovery_id, with
	// Code recovery_cancelled (0.49.0, VAULT-HOST-PROTOCOL 0.1.13 §6.1).
	CancelledRecoveryID string
}

// Tables are the member API's DynamoDB tables.
type Tables interface {
	PutInstance(ctx context.Context, r InstanceRow) error
	DeleteInstance(ctx context.Context, instanceID string) error
	// InstanceHeartbeat returns an instance row's heartbeat_at, or
	// ErrNotFound.
	InstanceHeartbeat(ctx context.Context, instanceID string) (int64, error)
	// AcquireLease sets the lease if it is absent, expired at now, or
	// already this instance's (§11.1); ErrLeaseHeld otherwise.
	AcquireLease(ctx context.Context, vaultID, instanceID string, now, expires int64) error
	// Lease returns a vault's lease (instance "" if none).
	Lease(ctx context.Context, vaultID string) (instanceID string, expires int64, err error)
	// TakeoverLease replaces a lease held by an instance that is not live,
	// conditional on the exact lease it replaces (§11.1, 0.3.2);
	// ErrLeaseHeld if it changed.
	TakeoverLease(ctx context.Context, vaultID, instanceID, oldInstance string, oldExpires, expires int64) error
	// RenewLease extends this instance's lease; ErrLeaseHeld if it is
	// not this instance's.
	RenewLease(ctx context.Context, vaultID, instanceID string, expires int64) error
	// Lifecycle writes an event (and releases the lease on locked and
	// deleted, if it is this instance's or absent). An alarm is written
	// whoever holds the lease: alarm {kind, alarm_id, at} and
	// alarm_pending true.
	Lifecycle(ctx context.Context, ev Lifecycle, instanceID string, now time.Time) error
	// AppKeys writes the app_key and app_key_next parts of an event and
	// nothing else (the parent's retry of an AppKeyWriteError, and of the
	// enclave's assertions): conditional on seq, whatever the lease,
	// idempotent. app_key and the removal of app_key_next are one update.
	AppKeys(ctx context.Context, ev Lifecycle, now time.Time) error
	// ConfirmAppKey makes the row name a key the vault is about to adopt
	// (hostproto.KindAppKeyNext), and returns nil only when it does:
	// mode "next": as app_key_next {key, kid, seq, header_seq}, unless
	// app_key already is that key at that seq or higher; mode "enroll":
	// as app_key (the enrolled report's write, early). ErrConflict if the
	// row names another key at that seq or higher, or is gone.
	ConfirmAppKey(ctx context.Context, vaultID, mode string, key []byte, seq, headerSeq uint64, attempt int64, now time.Time) error
	// ReleaseLease removes this instance's lease and marks the vault
	// locked (a vault that stopped without a lifecycle "locked").
	ReleaseLease(ctx context.Context, vaultID, instanceID string, now time.Time) error
	// MarkDeleting writes deleting_at = now (Unix seconds) on the vault
	// row, whatever the lease, conditional on the row existing, its state
	// not being deleted and no deleting_at yet; nothing else is written
	// (VAULT-MESSAGING 0.51.0 §11.5, VAULT-HOST-PROTOCOL 0.1.14 §5.6). A
	// refused condition is ErrConflict.
	MarkDeleting(ctx context.Context, vaultID string, now time.Time) error
	// WriteSlot updates a queued response slot; a slot that is gone or
	// no longer queued is left alone.
	WriteSlot(ctx context.Context, requestID string, s Slot) error
}

// Credentials are the instance role's temporary credentials.
type Credentials struct {
	AccessKeyID, SecretAccessKey, SessionToken string
	Expires                                    time.Time
}

// CredentialSource retrieves credentials for the enclave.
type CredentialSource interface {
	Retrieve(ctx context.Context) (Credentials, error)
}

// EventAppKeyAssert is the enclave's repeat of the current app key it last
// reported for a vault, sent after every connect (a parent that restarted
// lost what it had queued): written as app_key.
const EventAppKeyAssert = "app_key_assert"

// EventAppKeyNextClear is a failed step 1's orphan clear: the row's
// app_key_next is removed only if it is the event's key (kid) at the
// event's header_seq.
const EventAppKeyNextClear = "app_key_next_clear"

// AppKeyWriteError is the error of a Lifecycle whose app_key or
// app_key_next write failed: Err is that failure and Rest the error of the
// rest of the event's write (nil if it was written). The parent writes the
// keys again until they are written (Tables.AppKeys).
type AppKeyWriteError struct{ Err, Rest error }

func (e *AppKeyWriteError) Error() string { return "app key not written: " + e.Err.Error() }
func (e *AppKeyWriteError) Unwrap() error { return e.Err }

// appKeyResult is Lifecycle's result for a key error and the rest's.
func appKeyResult(keyErr, rest error) error {
	if keyErr == nil {
		return rest
	}
	return &AppKeyWriteError{Err: keyErr, Rest: rest}
}
