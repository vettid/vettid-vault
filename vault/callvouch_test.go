package vault

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"github.com/vettid/vettid-vault/vms/callwire"
)

// (VAULT-MESSAGING 0.88.16) The vault vouches for a form 2 share only when
// it names this vault on its own side: the caller in an offer, the callee
// in an answer. Form 1 names neither.
func TestVouchCallShareParties(t *testing.T) {
	d := newDevFixture(t)
	h := managerHost{d.m}
	own := h.IdentityKey()
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x77}, 32)).Public().(ed25519.PublicKey)
	dev := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x11}, 32)).Public().(ed25519.PublicKey)
	const id = "01JABCDEFGHJKMNPQRSTVWXYZ0"
	ek, enc := make([]byte, callwire.EKSize), make([]byte, callwire.EncSize)
	for name, c := range map[string]struct {
		m  []byte
		ok bool
	}{
		"offer, we call":        {callwire.OfferMessage2(id, "audio", []int{1}, callwire.Parties{Caller: own, Callee: other}, ek), true},
		"offer, another caller": {callwire.OfferMessage2(id, "audio", []int{1}, callwire.Parties{Caller: other, Callee: own}, ek), false},
		"answer, we answer":     {callwire.AnswerMessage2(id, 1, []int{1}, callwire.Parties{Caller: other, Callee: own}, enc), true},
		"answer, another":       {callwire.AnswerMessage2(id, 1, []int{1}, callwire.Parties{Caller: own, Callee: other}, enc), false},
		"form 1":                {callwire.ShareMessage(callwire.RoleOffer, id, "audio", ek), true},
	} {
		d.m.mu.Lock()
		_, err := h.VouchCallShare(dev, c.m)
		d.m.mu.Unlock()
		if (err == nil) != c.ok {
			t.Errorf("%s: %v", name, err)
		}
	}
}
