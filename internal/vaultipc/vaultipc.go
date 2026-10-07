// Package vaultipc is the channel between the enclave's supervisor and
// one vault process (VAULT-MESSAGING §12.4, VAULT-PLAN §5.3): hostproto
// frames over a socketpair, with the message set below. Everything a
// vault process can do outside itself goes through it, and the supervisor
// scopes each request to that vault.
//
// Supervisor → vault (requests):
//
//	Open    [version, instance_id, pcr0, pcr1, pcr2, job (12 fields)] → [ok, result, running "1"|"0", registered "1"|"0"]
//	Lock    []                                                          → [ok | split_brain]
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
//
// Vault → supervisor (notifications): Lifecycle [event, vault_id,
// release, vault_version, state_version, app_key (SPKI DER or empty),
// app_key_seq, credential_backup ("1", "0" or "" when not reported),
// name_seq, first_name, last_name ("0", "", "" except for account_name)], Log
// [level, message, k, v ...].
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
const Version = "6"

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
)

// Vault → supervisor notifications.
const (
	KindLifecycle hostproto.Kind = 0x60
	KindLog       hostproto.Kind = 0x61
)

// VaultRequests is every request kind a vault process may send.
var VaultRequests = []hostproto.Kind{KindStoreGet, KindStorePut, KindStoreDelete, KindAttestRecipient, KindAttestVault, KindKMS, KindHTTP, KindStatusList}

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
