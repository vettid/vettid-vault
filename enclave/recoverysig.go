package enclave

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"time"

	"github.com/vettid/vettid-vault/vms/recovery"
)

// Signed recovery requests (VAULT-MESSAGING 0.33.0 §11.14.8): the member
// API signs every recovery and recovery_cancel with its recovery request
// key; the enclave verifies the signature under a key the release pins,
// the request's members, the time within 5 minutes and that request_id
// has not been seen, before it locks a running vault or touches the
// header.

const (
	recoverySigWindow = 5 * time.Minute
	maxRecoverySeen   = 4096
)

// verifyRecoverySig reports whether q's signature holds; it records the
// request_id as seen.
func (in *Instance) verifyRecoverySig(q *QueueMessage) bool {
	now := in.now()
	at, err := time.Parse(time.RFC3339, q.SignedAt)
	if err != nil || at.Location() != time.UTC || at.UTC().Format(time.RFC3339) != q.SignedAt || at.Sub(now) > recoverySigWindow || now.Sub(at) > recoverySigWindow {
		return false
	}
	var pub *ecdsa.PublicKey
	for _, k := range in.cfg.Recovery.RequestKeys {
		if k.KeyID == q.KeyID {
			pub = k.Key
		}
	}
	if pub == nil {
		return false
	}
	var bk []byte
	if q.Op == OpRecovery {
		bk = q.BrowserKey
	}
	s, err := recovery.RequestSigningString(q.Op, q.VaultID, q.UserGUID, q.RequestID, q.SignedAt, bk)
	if err != nil {
		return false
	}
	h := sha256.Sum256([]byte(s))
	if !ecdsa.VerifyASN1(pub, h[:], q.Sig) {
		return false
	}
	in.mu.Lock()
	defer in.mu.Unlock()
	if in.recoverySeen == nil {
		in.recoverySeen = map[string]time.Time{}
	}
	for id, t := range in.recoverySeen {
		if now.Sub(t) > 2*recoverySigWindow {
			delete(in.recoverySeen, id)
		}
	}
	if _, seen := in.recoverySeen[q.Op+"|"+q.RequestID]; seen || len(in.recoverySeen) >= maxRecoverySeen {
		return false
	}
	in.recoverySeen[q.Op+"|"+q.RequestID] = now
	return true
}
