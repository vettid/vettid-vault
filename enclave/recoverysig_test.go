package enclave

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/enclave/releasecfg"
	"github.com/vettid/vettid-vault/vms/recovery"
)

// Signed recovery requests (VAULT-MESSAGING 0.33.0 §11.14.8): a pinned key,
// the request's own members, 5 minutes, and request_id not seen.
func TestRecoverySignature(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	in := &Instance{cfg: Config{Recovery: RecoveryConfig{RequestKeys: []releasecfg.RequestKey{{KeyID: "k1", Key: &k.PublicKey}}}},
		now: func() time.Time { return now }}
	bk := append([]byte{4}, bytes.Repeat([]byte{1}, 64)...)
	msg := func(op, rid string, signer *ecdsa.PrivateKey, at time.Time) *QueueMessage {
		q := &QueueMessage{Op: op, VaultID: "v1", UserGUID: "u1", RequestID: rid, KeyID: "k1", SignedAt: at.Format(time.RFC3339)}
		if op == OpRecovery {
			q.BrowserKey = bk
		}
		var b []byte
		if op == OpRecovery {
			b = bk
		}
		s, _ := recovery.RequestSigningString(op, q.VaultID, q.UserGUID, rid, q.SignedAt, b, "")
		h := sha256.Sum256([]byte(s))
		q.Sig, _ = ecdsa.SignASN1(rand.Reader, signer, h[:])
		return q
	}
	if !in.verifyRecoverySig(msg(OpRecovery, "01JB2Z6V9K3M4N5P6Q7R8S9T41", k, now)) {
		t.Fatal("a good signature refused")
	}
	if in.verifyRecoverySig(msg(OpRecovery, "01JB2Z6V9K3M4N5P6Q7R8S9T41", k, now)) {
		t.Fatal("a replayed request_id accepted")
	}
	if in.verifyRecoverySig(msg(OpRecovery, "01JB2Z6V9K3M4N5P6Q7R8S9T42", other, now)) {
		t.Fatal("an unpinned key accepted")
	}
	if in.verifyRecoverySig(msg(OpRecovery, "01JB2Z6V9K3M4N5P6Q7R8S9T43", k, now.Add(-6*time.Minute))) {
		t.Fatal("a stale signature accepted")
	}
	q := msg(OpRecovery, "01JB2Z6V9K3M4N5P6Q7R8S9T44", k, now)
	q.BrowserKey = append([]byte{4}, bytes.Repeat([]byte{2}, 64)...) // another browser key
	if in.verifyRecoverySig(q) {
		t.Fatal("a changed browser key accepted")
	}
	q = msg(OpRecoveryCancel, "01JB2Z6V9K3M4N5P6Q7R8S9T45", k, now)
	q.VaultID = "v2"
	if in.verifyRecoverySig(q) {
		t.Fatal("a cancel moved to another vault accepted")
	}
	if !in.verifyRecoverySig(msg(OpRecoveryCancel, "01JB2Z6V9K3M4N5P6Q7R8S9T46", k, now)) {
		t.Fatal("a good cancel refused")
	}
}

// VAULT-MESSAGING 0.49.0 §11.14.8: a cancel that names its recovery is
// signed over eight lines; a host that strips, adds or changes recovery_id
// breaks the signature.
func TestRecoveryCancelNamedSignature(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	in := &Instance{cfg: Config{Recovery: RecoveryConfig{RequestKeys: []releasecfg.RequestKey{{KeyID: "k1", Key: &k.PublicKey}}}},
		now: func() time.Time { return now }}
	const named = "01JB2Z6V9K3M4N5P6Q7R8S9T32"
	cancel := func(rid, signedID string) *QueueMessage {
		q := &QueueMessage{Op: OpRecoveryCancel, VaultID: "v1", UserGUID: "u1", RequestID: rid, KeyID: "k1", SignedAt: now.Format(time.RFC3339)}
		s, err := recovery.RequestSigningString(OpRecoveryCancel, q.VaultID, q.UserGUID, rid, q.SignedAt, nil, signedID)
		if err != nil {
			t.Fatal(err)
		}
		h := sha256.Sum256([]byte(s))
		q.Sig, _ = ecdsa.SignASN1(rand.Reader, k, h[:])
		q.RecoveryID = signedID
		return q
	}
	if !in.verifyRecoverySig(cancel("01JB2Z6V9K3M4N5P6Q7R8S9T51", named)) {
		t.Fatal("a good named cancel refused")
	}
	q := cancel("01JB2Z6V9K3M4N5P6Q7R8S9T52", named)
	q.RecoveryID = "" // stripped: verified as seven lines
	if in.verifyRecoverySig(q) {
		t.Fatal("a cancel with its recovery_id stripped accepted")
	}
	q = cancel("01JB2Z6V9K3M4N5P6Q7R8S9T53", named)
	q.RecoveryID = "01JB2Z6V9K3M4N5P6Q7R8S9T39" // changed
	if in.verifyRecoverySig(q) {
		t.Fatal("a cancel with a changed recovery_id accepted")
	}
	q = cancel("01JB2Z6V9K3M4N5P6Q7R8S9T54", "")
	q.RecoveryID = named // added to a seven-line cancel
	if in.verifyRecoverySig(q) {
		t.Fatal("a seven-line cancel with an added recovery_id accepted")
	}
	if !in.verifyRecoverySig(cancel("01JB2Z6V9K3M4N5P6Q7R8S9T55", "")) {
		t.Fatal("a seven-line cancel refused")
	}
}
