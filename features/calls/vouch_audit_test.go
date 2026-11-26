package calls

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/featuretest"
	"github.com/vettid/vettid-vault/vms/callwire"
)

// auditedShareDrops counts the drop.call_share audited for dev-app.
func (s *side) auditedShareDrops() int {
	n := 0
	for _, a := range s.h.Activities {
		if a.Kind == "drop.call_share" && a.DeviceID == "dev-app" && a.Audit {
			n++
		}
	}
	return n
}

// Every share of our own device that the vault refuses (§10.10 "What each
// party checks": its device_sig not verifying under the device's paired
// ik, or form 2 naming another vault on this side) is audited
// drop.call_share once, naming the device: a call.start is answered
// bad_request, a call.answer call.end{unavailable}. A share vouched for,
// or a failure to sign one, is not audited.
func TestOwnShareRefusalsAudited(t *testing.T) {
	sk, _ := callwire.NewOfferKey()
	ek := sk.Public().Bytes()
	other := featuretest.DeviceKey("dev-desktop")                                                     // another device's key, not dev-app's
	otherVault := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x7e}, 32)).Public().(ed25519.PublicKey) // not the test vault's

	badForm1 := func(id string) string {
		sig, _ := callwire.SignShare(other, callwire.ShareMessage(callwire.RoleOffer, id, "video", ek))
		return `{"connection_id":"cB","call_id":"` + id + `","media":"video","sdp":"` + strings.ReplaceAll(sdpOffer, "\r\n", `\r\n`) +
			`","ek":"` + b64(ek) + `","ek_sig":"` + b64(sig) + `"}`
	}

	t.Run("call.start", func(t *testing.T) {
		for name, c := range map[string]struct {
			setup   func(*side)
			body    func(id string) string
			code    string
			audited int
		}{
			"form 1, another device's signature": {body: badForm1, code: "bad_request", audited: 1},
			"form 2, ek_sig2 by another device": {body: func(id string) string {
				b := startBody2("cB", id, ek, []int{1})
				good, _ := callwire.SignShare(featuretest.DeviceKey("dev-app"), callwire.OfferMessage2(id, "video", []int{1}, outP("cB"), ek))
				bad, _ := callwire.SignShare(other, callwire.OfferMessage2(id, "video", []int{1}, outP("cB"), ek))
				return strings.Replace(b, b64(good), b64(bad), 1)
			}, code: "bad_request", audited: 1},
			// The vault rebuilds m2 from its own records, so the device's
			// signature over another callee doesn't verify.
			"form 2 naming another callee, by its signature": {body: func(id string) string {
				return startBody2P("cB", id, ek, []int{1}, callwire.Parties{Caller: testIK, Callee: otherVault})
			}, code: "bad_request", audited: 1},
			"form 2 the vault won't vouch for": {setup: func(s *side) { s.h.IK = otherVault }, body: func(id string) string {
				// The feature's view of its key differs from the key it signs with.
				return startBody2P("cB", id, ek, []int{1}, callwire.Parties{Caller: otherVault, Callee: peerVault("cB").Public().(ed25519.PublicKey)})
			}, code: "bad_request", audited: 1},
			"a failure to sign": {setup: func(s *side) { s.h.VouchErr = errors.New("signing failed") }, body: func(id string) string {
				return startBody2("cB", id, ek, []int{1})
			}, code: "internal"},
			"vouched": {body: func(id string) string { return startBody2("cB", id, ek, []int{1}) }},
			// Refused before any share is looked at: not audited.
			"busy, another device's signature": {setup: func(s *side) {
				if r := featuretest.Call(s.f, s.h, t0, "app", "call.start", startBody2("cB", newCallID("audit"), ek, []int{1})); !r.OK() {
					t.Fatalf("the first call: %q", r.Code)
				}
				s.h.Reset()
			}, body: badForm1, code: "busy"},
			"calls off, another device's signature": {setup: func(s *side) { s.f.off["cB"] = true }, body: badForm1, code: "calls_off"},
		} {
			a := newSide("cB")
			if c.setup != nil {
				c.setup(a)
			}
			r := featuretest.Call(a.f, a.h, t0, "app", "call.start", c.body(newCallID("audit")))
			if r.Code != c.code || a.auditedShareDrops() != c.audited || (c.code != "") != (len(a.h.SentOfType("call.offer")) == 0) {
				t.Errorf("%s: %q, %d audited, %d offers", name, r.Code, a.auditedShareDrops(), len(a.h.SentOfType("call.offer")))
			}
		}
	})

	t.Run("call.answer", func(t *testing.T) {
		for name, c := range map[string]struct {
			setup   func(*side)
			body    func(id string, enc []byte, confirm []byte) string
			audited int
		}{
			"another device's signature": {body: func(id string, enc, confirm []byte) string {
				return answerBody2("dev-desktop", id, enc, 1, []int{1}, confirm)
			}, audited: 1},
			"form 1, another device's signature": {body: func(id string, enc, _ []byte) string {
				return answerBody("dev-desktop", id, enc)
			}, audited: 1},
			"form 2 naming other parties": {body: func(id string, enc, confirm []byte) string {
				return answerBody2P("dev-app", id, enc, 1, []int{1}, confirm, callwire.Parties{Caller: otherVault, Callee: testIK})
			}, audited: 1},
			"a failure to sign": {setup: func(s *side) { s.h.VouchErr = errors.New("signing failed") }, body: func(id string, enc, confirm []byte) string {
				return answerBody2("dev-app", id, enc, 1, []int{1}, confirm)
			}},
			"vouched": {body: func(id string, enc, confirm []byte) string {
				return answerBody2("dev-app", id, enc, 1, []int{1}, confirm)
			}},
		} {
			b := newSide("cA")
			id := newCallID("cA")
			featuretest.CallExp(b.f, b.h, t0, t0.Add(OfferTTL), "connection:cA", "call.offer", peerOffer2("cA", id, "audio", ek, []int{1}, true, false))
			b.sent(t, "devices", "call.offer")
			if c.setup != nil {
				c.setup(b)
			}
			enc, _, _ := callwire.Answer2(ek, id, inP("cA"))
			b.h.Reset()
			featuretest.Call(b.f, b.h, t0.Add(time.Second), "app", "call.answer", c.body(id, enc, make([]byte, callwire.ConfirmSize)))
			passed := len(b.h.SentOfType("call.answer")) == 1
			end := b.h.SentOfType("call.end")
			refusedToDevice := len(end) == 1 && end[0].To == "dev-app" && strings.Contains(string(end[0].Body), `"unavailable"`)
			if b.auditedShareDrops() != c.audited || passed != (name == "vouched") || refusedToDevice == (name == "vouched") {
				t.Errorf("%s: %d audited, passed on %v, unavailable to the device %v", name, b.auditedShareDrops(), passed, refusedToDevice)
			}
		}
	})
}
