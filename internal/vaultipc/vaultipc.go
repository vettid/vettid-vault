// Package vaultipc is the channel between the enclave's supervisor and
// one vault process (VAULT-MESSAGING §12.4, VAULT-PLAN §5.3): hostproto
// frames over a socketpair, with the message set below. Everything a
// vault process can do outside itself goes through it, and the supervisor
// scopes each request to that vault.
//
// Supervisor → vault (requests):
//
//	Open    [version, instance_id, pcr0, pcr1, pcr2, job (12 fields)] → [ok, result, running "1"|"0", registered "1"|"0"]
//	Lock    [reason]                                                    → [ok | split_brain | not_deleted]
//	Account [snapshot]                                                  → [ok, running "1"|"0"]
//	Recoverable []                                                      → [ok, "" | no_credential | no_backup]
//
// Vault → supervisor (requests; the supervisor answers [status, ...]):
//
//	StoreGet        [key]                         → [status, data, version]
//	StorePut        [key, data, if_match]         → [status, version]
//	StoreDelete     [key, if_match]               → [status]
//	AttestRecipient [RSA public key, DER]         → [status, document]
//	AttestVault     [vault bundle, nonce]         → [status, document]
//	KMS             [op, key_arn, a, b]           → [status, out1, out2]
//	HTTP            [method, url, headers, body]  → [status, code, headers, body]
//	StatusList      []                            → [status, list, fetched_at]
//	Push            [path, headers, body]         → [status, code, headers, body]
//	Transfer        [ticket, priority, wait_ms]   → [status]   (ok: admitted; busy: not within wait_ms)
//	Counter         [op, key, a, b]               → [status, ...] (release R)
//	HeavyPermit     [acquire | release]           → [status, "1" | "0"] (release R)
//	MarkDeleting    [vault_id]                    → [status] (0.51.0; the process's own vault only)
//
// Vault → supervisor (notifications): Lifecycle [event, vault_id,
// release, vault_version, state_version, app_key (SPKI DER or empty),
// app_key_seq, credential_backup ("1", "0" or "" when not reported),
// name_seq, first_name, last_name ("0", "", "" except for account_name),
// next, header_seq, next_cleared, cancelled_recovery_id (a ULID on the
// unlocked or moved event of an unlock that cancelled a recovery, else
// "")], Log
// [level, message, k, v ...], TransferDone [ticket] (a transfer the
// supervisor admitted, or asked for, ended).
//
// No message from the vault to the supervisor carries a DEK, pepper, key
// or plaintext state: stored objects are DEK-encrypted, relay requests are
// signed and their payloads end-to-end encrypted, KMS answers are
// encrypted to the vault process's own Recipient key.
package vaultipc

import (
	"encoding/binary"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/vettid/vettid-vault/internal/hostproto"
)

// Version is the channel version (Open's first field).
// 2: the job carries the manifest document (VAULT-MESSAGING 0.10.0).
// 3: Open's answer says whether a recovery register succeeded (0.10.6).
// 4: the job carries the app key and the account snapshot; Account;
// Lifecycle carries the app key and its sequence (0.15.0).
// 5: Recoverable; Lifecycle carries the backup bit; Open's last field
// is the answer's clear marker (recovery_registered or
// recovery_unavailable) (0.16.0).
// 6: Lifecycle carries a name request (name_seq, first_name, last_name;
// the event account_name, 0.18.0).
// 7: Push (0.24.0).
// 8: Transfer and TransferDone (0.32.0, release A: the instance's
// admission of blob transfers by memory, §10.5.1).
// 9: Counter and HeavyPermit; Lifecycle carries next, header_seq and
// next_cleared; Open's last field is the clear marker as JSON (0.33.0,
// release R).
// 10: Lifecycle carries cancelled_recovery_id; the clear marker may be an
// unlock's recovery_cancelled with cancelled_recovery_id or a cancel's
// recovery_not_current (VAULT-MESSAGING 0.49.0).
// 11: MarkDeleting; the job op delete_resume (VAULT-MESSAGING 0.51.0).
const Version = "11"

// Supervisor → vault.
const (
	KindOpen hostproto.Kind = 0x40
	KindLock hostproto.Kind = 0x41
	// KindSelftest [key_arn] → [ok, report JSON]: the hardware smoke
	// test's vault-process checks (docs/SMOKE.md); only a process started
	// in self-test mode answers it.
	KindSelftest hostproto.Kind = 0x42
	// KindSelftestCapacity [op, arg] → [ok, stats JSON]: the self-test's
	// capacity measurement (docs/SMOKE.md); op "unlock" runs one Argon2id
	// at the release's parameters and, with arg (state bytes) > 0, holds
	// random state of that size with an idle loop; op "stats" reports the
	// process's memory and CPU time. Only a process started in self-test
	// mode answers it.
	KindSelftestCapacity hostproto.Kind = 0x43
	// KindAccount [snapshot] → [ok, running "1"|"0"]: the queue op
	// account for the running vault (0.15.0, §11.13).
	KindAccount hostproto.Kind = 0x44
	// KindRecoverable [] → [ok, "" | "no_credential" | "no_backup"]: does
	// the running vault refuse a recovery (0.16.0, §11.11.1)? Nothing is
	// locked.
	KindRecoverable hostproto.Kind = 0x45
)

// Vault → supervisor requests.
const (
	KindStoreGet        hostproto.Kind = 0x50
	KindStorePut        hostproto.Kind = 0x51
	KindStoreDelete     hostproto.Kind = 0x52
	KindAttestRecipient hostproto.Kind = 0x53
	KindAttestVault     hostproto.Kind = 0x54
	KindKMS             hostproto.Kind = 0x55
	KindHTTP            hostproto.Kind = 0x56
	KindStatusList      hostproto.Kind = 0x57
	// KindPush carries a request to the channel's push gateway (0.24.0,
	// §14): POST to path (/v1/register or /v1/wake) of the gateway URL
	// the supervisor pins, signed by a wake key in this process. The
	// supervisor verifies the signature and, for a registration, attaches
	// the NSM attestation itself (public_key = the wake key, user_data =
	// the request's digest, PUSH-GATEWAY §5.1).
	KindPush hostproto.Kind = 0x58
	// KindTransfer [ticket, priority, wait_ms] → [ok | busy]: admits one
	// blob transfer of this vault process (§10.5.1 "Transfers and memory");
	// the reply comes once it may start, or busy after wait_ms. ticket is
	// 1-32 characters of [0-9a-z] chosen by the process, ended by
	// TransferDone.
	KindTransfer hostproto.Kind = 0x59
	// KindCounter carries one call to the recovery attempt counter's
	// bucket (VAULT-MESSAGING 0.33.0 §11.14.4, VAULT-HOST-PROTOCOL 0.1.10
	// §8.1), which the supervisor signs and sends to the pinned bucket
	// over its TLS: [op, key, a, b] with op one of the Counter* below. The
	// supervisor admits only keys under recovery/v1/ and, once a process
	// has named its vault's prefix, only that prefix.
	KindCounter hostproto.Kind = 0x5b
	// KindHeavyPermit [op] → [status, "1" | "0"]: op "acquire" asks for
	// the one permit for the recovery wrap's heavy derivation (§11.14.3),
	// given only while free memory is at least the memory-pressure floor
	// plus the derivation's need; "release" returns it.
	KindHeavyPermit hostproto.Kind = 0x5c
	// KindMarkDeleting [vault_id] → [ok | error]: the deletion's mark at
	// the host (VAULT-MESSAGING 0.51.0 §12.5, VAULT-HOST-PROTOCOL §5.6),
	// sent once the marking flush is stored. The supervisor refuses any
	// vault_id but the process's own and passes the request to the
	// parent, one try per request: the process retries.
	KindMarkDeleting hostproto.Kind = 0x5d
)

// Bounds the supervisor puts on a vault process's answers, after which it
// kills the process: an Open, and a Lock with the reason delete (the
// host's mark may take 2 minutes and step 4's retries 60 s more,
// VAULT-MESSAGING 0.51.0 §12.5). The process works to a deadline
// DeadlineMargin earlier, so that a deletion's step 2 is never cut by the
// kill (it runs only with time left, or not at all).
const (
	OpenTimeout       = 3 * time.Minute
	DeleteLockTimeout = 4 * time.Minute
	DeadlineMargin    = 15 * time.Second
)

// Counter operations (KindCounter).
const (
	CounterList         = "list"          // [list, prefix] → [ok, listing JSON]
	CounterPutCreate    = "put_create"    // [put_create, key, body, until] → [ok, status, version]
	CounterPut          = "put"           // [put, key, body, until] → [ok, version]
	CounterGetRetention = "get_retention" // [get_retention, key, version] → [ok, mode, until]
	CounterGetVersion   = "get_version"   // [get_version, key, version] → [ok, body]
)

// Heavy permit operations.
const (
	HeavyAcquire = "acquire"
	HeavyRelease = "release"
)

// Vault → supervisor notifications.
const (
	KindLifecycle    hostproto.Kind = 0x60
	KindLog          hostproto.Kind = 0x61
	KindTransferDone hostproto.Kind = 0x62
)

// VaultRequests is every request kind a vault process may send.
var VaultRequests = []hostproto.Kind{KindStoreGet, KindStorePut, KindStoreDelete, KindAttestRecipient, KindAttestVault, KindKMS, KindHTTP, KindStatusList, KindPush, KindTransfer, KindCounter, KindHeavyPermit, KindMarkDeleting}

// KMS operations.
const (
	KMSGenerateDataKey = "GenerateDataKey"
	KMSDecrypt         = "Decrypt"
	KMSDescribeKey     = "DescribeKey"
	KMSGetKeyPolicy    = "GetKeyPolicy"
	KMSListGrants      = "ListGrants"
)

// Statuses beyond hostproto's.
const (
	StatusSplitBrain = "split_brain"
	StatusDenied     = "denied"
	StatusBusy       = "busy"
	// StatusNotDeleted answers a Lock with the reason delete that did not
	// delete the vault (no host mark, VAULT-MESSAGING 0.51.0 §12.5, or a
	// failed erase): the vault is locked, its objects may remain, and the
	// host's deletion falls back to the erase without the DEK.
	StatusNotDeleted = "not_deleted"
)

// Limits.
const (
	MaxHeaders     = 64
	MaxHeaderValue = 8 << 10
	MaxBody        = 16 << 20
)

// ErrHeaders is a malformed header block.
var ErrHeaders = errors.New("vaultipc: malformed headers")

// EncodeHeaders encodes h as count (2) || (name len (2) || name || value
// len (4) || value)*, one entry per value.
func EncodeHeaders(h http.Header) []byte {
	var b []byte
	n := 0
	for _, vs := range h {
		n += len(vs)
	}
	b = binary.BigEndian.AppendUint16(b, uint16(n))
	for k, vs := range h {
		for _, v := range vs {
			b = binary.BigEndian.AppendUint16(b, uint16(len(k)))
			b = append(b, k...)
			b = binary.BigEndian.AppendUint32(b, uint32(len(v)))
			b = append(b, v...)
		}
	}
	return b
}

func tokenOK(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0) {
			return false
		}
	}
	return true
}

func valueOK(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 && c != '\t' || c == 0x7f {
			return false
		}
	}
	return true
}

// DecodeHeaders decodes EncodeHeaders strictly: header names are HTTP
// tokens, values have no control characters, at most MaxHeaders entries,
// no trailing data.
func DecodeHeaders(b []byte) (http.Header, error) {
	if len(b) < 2 {
		return nil, ErrHeaders
	}
	n := int(binary.BigEndian.Uint16(b))
	b = b[2:]
	if n > MaxHeaders {
		return nil, ErrHeaders
	}
	h := http.Header{}
	for i := 0; i < n; i++ {
		if len(b) < 2 {
			return nil, ErrHeaders
		}
		kl := int(binary.BigEndian.Uint16(b))
		b = b[2:]
		if len(b) < kl+4 {
			return nil, ErrHeaders
		}
		k := string(b[:kl])
		b = b[kl:]
		vl := binary.BigEndian.Uint32(b)
		b = b[4:]
		if vl > MaxHeaderValue || uint64(vl) > uint64(len(b)) {
			return nil, ErrHeaders
		}
		v := string(b[:vl])
		b = b[vl:]
		if !tokenOK(k) || !valueOK(v) {
			return nil, ErrHeaders
		}
		h.Add(k, v)
	}
	if len(b) != 0 {
		return nil, ErrHeaders
	}
	return h, nil
}
