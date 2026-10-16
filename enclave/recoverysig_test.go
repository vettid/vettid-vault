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
		s, _ := recovery.RequestSigningString(op, q.VaultID, q.UserGUID, rid, q.SignedAt, b)
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
