package calls

import (
	"context"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/featuretest"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/callwire"
)

// §3.6.3, §10.10 (0.13.0): a held vault rings no device and does not
// answer an offer, not even busy; it records a missed call. A call ringing
// when the hold begins stops ringing on the devices (call.end
// {unavailable} to them only); a call answered before it continues, and
// its device's call.ice and call.end pass the gate.
func TestCallsWhileHeld(t *testing.T) {
	b := newSide("cA")
	sk, _ := callwire.NewOfferKey()
	id := newCallID("cA")
	b.h.Hold = vault.OwnerCheckHeld
	if r := featuretest.CallExp(b.f, b.h, t0, t0.Add(OfferTTL), "connection:cA", "call.offer", peerOffer("cA", id, "audio", sk.Public().Bytes())); !r.OK() {
		t.Fatal(r.Code)
	}
	b.none(t, "call.offer")
	b.none(t, "call.end")
	if !b.h.HasActivity("call.missed") {
		t.Fatal("missed call not recorded")
	}
	if c, _ := b.f.Get(id); c.State != StateEnded {
		t.Fatalf("held offer left %+v", c)
	}
	// With the hold off (due) the call rings (on the app too, which cannot
	// answer before a check: the runtime's gate drops its call.answer).
	b.h.Hold = vault.OwnerCheckDue
	id2 := newCallID("cA")
	featuretest.CallExp(b.f, b.h, t0, t0.Add(OfferTTL), "connection:cA", "call.offer", peerOffer("cA", id2, "audio", sk.Public().Bytes()))
	b.sent(t, "devices", "call.offer")
	// The hold begins while it rings: it stops ringing, the caller is not told.
	b.h.Reset()
	b.f.OwnerHoldStarted(vault.NewSession(context.Background(), b.h, vault.PeerInfo{}, t0.Add(time.Second), nil))
	if e := b.sent(t, "devices", "call.end"); str(t, e.Body, "reason") != "unavailable" || str(t, e.Body, "call_id") != id2 {
		t.Fatalf("ringing call: %s", e.Body)
	}
	if len(b.h.SentOfType("call.end")) != 1 || !b.h.HasActivity("call.missed") {
		t.Fatal("caller told, or not missed")
	}
	// A call answered before the deadline: its device passes the gate.
	b.h.Hold = ""
	id3 := newCallID("cA")
	featuretest.CallExp(b.f, b.h, t0, t0.Add(OfferTTL), "connection:cA", "call.offer", peerOffer("cA", id3, "audio", sk.Public().Bytes()))
	enc, _, err := callwire.Answer(sk.Public().Bytes(), id3)
	if err != nil {
		t.Fatal(err)
	}
	if r := featuretest.Call(b.f, b.h, t0.Add(2*time.Second), "desktop", "call.answer", answerBody("dev-desktop", id3, enc)); !r.OK() {
		t.Fatal(r.Code)
	}
	if !b.f.CallAnsweredBefore("dev-desktop", t0.Add(time.Minute)) || b.f.CallAnsweredBefore("dev-desktop", t0) ||
		b.f.CallAnsweredBefore("dev-app", t0.Add(time.Minute)) {
		t.Fatal("CallAnsweredBefore")
	}
	b.h.Reset()
	b.f.OwnerHoldStarted(vault.NewSession(context.Background(), b.h, vault.PeerInfo{}, t0.Add(3*time.Second), nil))
	b.none(t, "call.end")
}
