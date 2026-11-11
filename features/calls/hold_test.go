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
	now := t0.Add(time.Minute)
	if !b.f.CallAnsweredBefore("dev-desktop", id3, t0.Add(time.Minute), now) || b.f.CallAnsweredBefore("dev-desktop", id3, t0, now) ||
		b.f.CallAnsweredBefore("dev-app", id3, t0.Add(time.Minute), now) || b.f.CallAnsweredBefore("dev-desktop", id2, t0.Add(time.Minute), now) {
		t.Fatal("CallAnsweredBefore")
	}
	// The 12 h limit: a stale active record keeps nothing open (L1).
	if b.f.CallAnsweredBefore("dev-desktop", id3, t0.Add(time.Minute), t0.Add(MaxCallDuration+time.Minute)) {
		t.Fatal("a call past the 12 h limit still passes the hold")
	}
	b.h.Reset()
	b.f.OwnerHoldStarted(vault.NewSession(context.Background(), b.h, vault.PeerInfo{}, t0.Add(3*time.Second), nil))
	b.none(t, "call.end")
}

// §3.6.8 (0.29.0, release L): the idle lock waits for a call in progress,
// ringing or answered, and not for an ended or timed-out one.
func TestCallInProgress(t *testing.T) {
	b := newSide("cA")
	var _ vault.CallActivity = b.f
	if b.f.CallInProgress(t0) {
		t.Fatal("no call")
	}
	sk, _ := callwire.NewOfferKey()
	id := newCallID("cA")
	featuretest.CallExp(b.f, b.h, t0, t0.Add(OfferTTL), "connection:cA", "call.offer", peerOffer("cA", id, "audio", sk.Public().Bytes()))
	if !b.f.CallInProgress(t0.Add(time.Second)) {
		t.Fatal("a ringing call")
	}
	if b.f.CallInProgress(t0.Add(OfferTTL + time.Second)) {
		t.Fatal("a timed-out offer")
	}
	enc, _, err := callwire.Answer(sk.Public().Bytes(), id)
	if err != nil {
		t.Fatal(err)
	}
	if r := featuretest.Call(b.f, b.h, t0.Add(2*time.Second), "desktop", "call.answer", answerBody("dev-desktop", id, enc)); !r.OK() {
		t.Fatal(r.Code)
	}
	if !b.f.CallInProgress(t0.Add(time.Hour)) || b.f.CallInProgress(t0.Add(2*time.Second+MaxCallDuration)) {
		t.Fatal("an answered call, and its 12 h bound")
	}
}

// §3.6.3 (owner decision 2026-11-11): when the hold begins, a call answered
// at or after the deadline ends unavailable at once, with the peer and the
// devices told; one answered before continues. CallActive is the device's
// live active call (an expired access session passes its signals, §6.8).
func TestHoldEndsCallsAnsweredFromTheDeadline(t *testing.T) {
	b := newSide("cA")
	sk, _ := callwire.NewOfferKey()
	id := newCallID("cA")
	featuretest.CallExp(b.f, b.h, t0, t0.Add(OfferTTL), "connection:cA", "call.offer", peerOffer("cA", id, "audio", sk.Public().Bytes()))
	enc, _, err := callwire.Answer(sk.Public().Bytes(), id)
	if err != nil {
		t.Fatal(err)
	}
	answered := t0.Add(2 * time.Second)
	if r := featuretest.Call(b.f, b.h, answered, "desktop", "call.answer", answerBody("dev-desktop", id, enc)); !r.OK() {
		t.Fatal(r.Code)
	}
	now := t0.Add(time.Minute)
	if !b.f.CallActive("dev-desktop", id, now) || b.f.CallActive("dev-app", id, now) || b.f.CallActive("dev-desktop", newCallID("cA"), now) ||
		b.f.CallActive("dev-desktop", id, answered.Add(MaxCallDuration)) {
		t.Fatal("CallActive")
	}
	// Answered before the deadline: it continues.
	b.h.Reset()
	b.f.EndCallsAnsweredFrom(vault.NewSession(context.Background(), b.h, vault.PeerInfo{}, now, nil), answered.Add(time.Nanosecond))
	b.none(t, "call.end")
	if c, _ := b.f.Get(id); c.State != StateActive {
		t.Fatalf("a call answered before the deadline ended: %+v", c)
	}
	// Answered at the deadline: ended, the peer and the devices told.
	b.f.EndCallsAnsweredFrom(vault.NewSession(context.Background(), b.h, vault.PeerInfo{}, now, nil), answered)
	if c, _ := b.f.Get(id); c.State != StateEnded || c.Reason != "unavailable" {
		t.Fatalf("a call answered at the deadline: %+v", c)
	}
	if e := b.sent(t, "cA", "call.end"); str(t, e.Body, "reason") != "unavailable" {
		t.Fatalf("peer: %s", e.Body)
	}
	if e := b.sent(t, "dev-desktop", "call.end"); str(t, e.Body, "reason") != "unavailable" {
		t.Fatalf("the call device: %s", e.Body)
	}
	if e := b.sent(t, "devices-except:dev-desktop", "call.end"); str(t, e.Body, "reason") != "unavailable" {
		t.Fatalf("devices: %s", e.Body)
	}
	if b.h.HasActivity("call.missed") {
		t.Fatal("an answered call recorded as missed")
	}
	if b.f.CallActive("dev-desktop", id, now) {
		t.Fatal("an ended call is still active")
	}
}

// §3.6.3 (0.88.13): an outgoing call the peer answers after the hold
// began was answered after the deadline: it is ended unavailable, the
// peer and the devices told, never made active.
func TestHeldCallerAnswerEndsTheCall(t *testing.T) {
	a, b := newSide("cB"), newSide("cA")
	link(a, b)
	sk, _ := callwire.NewOfferKey()
	r := featuretest.Call(a.f, a.h, t0, "app", "call.start", startBody("cB", sk.Public().Bytes()))
	if !r.OK() {
		t.Fatal(r.Code)
	}
	callID := str(t, r.Body, "call_id")
	off := a.sent(t, "cB", "call.offer")
	featuretest.CallExp(b.f, b.h, t0, off.Opt.Exp, "connection:cA", "call.offer", string(off.Body))
	ring := b.sent(t, "devices", "call.offer")
	ek, _ := obj(t, ring.Body).Base64("ek", callwire.EKSize)
	enc, _, err := callwire.Answer(ek, callID)
	if err != nil {
		t.Fatal(err)
	}
	featuretest.Call(b.f, b.h, t0.Add(5*time.Second), "app", "call.answer", answerBody("dev-app", callID, enc))
	fwd := b.sent(t, "cA", "call.answer")
	a.h.Reset()
	a.h.Hold = vault.OwnerCheckHeld
	featuretest.Call(a.f, a.h, t0.Add(5*time.Second), "connection:cB", "call.answer", string(fwd.Body))
	a.none(t, "call.answer")
	if c, _ := a.f.Get(callID); c.State != StateEnded || c.Reason != "unavailable" {
		t.Fatalf("answered while held: %+v", c)
	}
	if e := a.sent(t, "cB", "call.end"); str(t, e.Body, "reason") != "unavailable" {
		t.Fatal("the peer was not told")
	}
	a.sent(t, "dev-app", "call.end")
	a.sent(t, "devices-except:dev-app", "call.end")
}

// §6.8 (0.88.13, owner decision 2026-11-11): access ended on purpose ends
// that desktop's call, the peer and every device (the desktop too) told;
// another device's end changes nothing.
func TestAccessEndedEndsTheCall(t *testing.T) {
	b := newSide("cA")
	sk, _ := callwire.NewOfferKey()
	id := newCallID("cA")
	featuretest.CallExp(b.f, b.h, t0, t0.Add(OfferTTL), "connection:cA", "call.offer", peerOffer("cA", id, "audio", sk.Public().Bytes()))
	enc, _, err := callwire.Answer(sk.Public().Bytes(), id)
	if err != nil {
		t.Fatal(err)
	}
	if r := featuretest.Call(b.f, b.h, t0.Add(2*time.Second), "desktop", "call.answer", answerBody("dev-desktop", id, enc)); !r.OK() {
		t.Fatal(r.Code)
	}
	b.h.Reset()
	b.f.AccessEnded(vault.NewSession(context.Background(), b.h, vault.PeerInfo{}, t0.Add(time.Minute), nil), "dev-other")
	b.none(t, "call.end")
	b.f.AccessEnded(vault.NewSession(context.Background(), b.h, vault.PeerInfo{}, t0.Add(time.Minute), nil), "dev-desktop")
	if c, _ := b.f.Get(id); c.State != StateEnded || c.Reason != "unavailable" {
		t.Fatalf("%+v", c)
	}
	if e := b.sent(t, "cA", "call.end"); str(t, e.Body, "reason") != "unavailable" {
		t.Fatal("the peer was not told")
	}
	b.sent(t, "dev-desktop", "call.end")
	b.sent(t, "devices-except:dev-desktop", "call.end")
}

// §7.4 (0.88.13): a device unlinked (or an app a transfer replaced) loses
// its call in progress, the peer and the devices told.
func TestDeviceRemovedEndsTheCall(t *testing.T) {
	b := newSide("cA")
	sk, _ := callwire.NewOfferKey()
	id := newCallID("cA")
	featuretest.CallExp(b.f, b.h, t0, t0.Add(OfferTTL), "connection:cA", "call.offer", peerOffer("cA", id, "audio", sk.Public().Bytes()))
	enc, _, err := callwire.Answer(sk.Public().Bytes(), id)
	if err != nil {
		t.Fatal(err)
	}
	featuretest.Call(b.f, b.h, t0.Add(2*time.Second), "desktop", "call.answer", answerBody("dev-desktop", id, enc))
	b.h.Reset()
	var _ vault.DeviceRemovedObserver = b.f
	b.f.DeviceRemoved(vault.NewSession(context.Background(), b.h, vault.PeerInfo{}, t0.Add(time.Minute), nil), "dev-desktop")
	if c, _ := b.f.Get(id); c.State != StateEnded || c.Reason != "unavailable" {
		t.Fatalf("%+v", c)
	}
	if e := b.sent(t, "cA", "call.end"); str(t, e.Body, "reason") != "unavailable" {
		t.Fatal("the peer was not told")
	}
	b.sent(t, "devices-except:dev-desktop", "call.end")
}

// An outgoing call whose answer can't reach its caller device (a desktop
// whose session ended while it rang) is ended, the peer told.
func TestCallerAnswerUndeliverableEndsTheCall(t *testing.T) {
	a, b := newSide("cB"), newSide("cA")
	link(a, b)
	sk, _ := callwire.NewOfferKey()
	r := featuretest.Call(a.f, a.h, t0, "app", "call.start", startBody("cB", sk.Public().Bytes()))
	if !r.OK() {
		t.Fatal(r.Code)
	}
	callID := str(t, r.Body, "call_id")
	off := a.sent(t, "cB", "call.offer")
	featuretest.CallExp(b.f, b.h, t0, off.Opt.Exp, "connection:cA", "call.offer", string(off.Body))
	ring := b.sent(t, "devices", "call.offer")
	ek, _ := obj(t, ring.Body).Base64("ek", callwire.EKSize)
	enc, _, err := callwire.Answer(ek, callID)
	if err != nil {
		t.Fatal(err)
	}
	featuretest.Call(b.f, b.h, t0.Add(5*time.Second), "app", "call.answer", answerBody("dev-app", callID, enc))
	fwd := b.sent(t, "cA", "call.answer")
	a.h.Reset()
	delete(a.h.Devices, "dev-app") // the answer can't reach it
	featuretest.Call(a.f, a.h, t0.Add(5*time.Second), "connection:cB", "call.answer", string(fwd.Body))
	if c, _ := a.f.Get(callID); c.State != StateEnded || c.Reason != "unavailable" || !c.Answered.IsZero() {
		t.Fatalf("%+v", c)
	}
	if e := a.sent(t, "cB", "call.end"); str(t, e.Body, "reason") != "unavailable" {
		t.Fatal("the peer was not told")
	}
}

// §3.6.3 (0.88.13, owner decision 2026-11-11): an outgoing call still
// ringing when the hold begins ends, the peer told and the devices once.
func TestHoldEndsOutgoingRinging(t *testing.T) {
	a, b := newSide("cB"), newSide("cA")
	link(a, b)
	sk, _ := callwire.NewOfferKey()
	r := featuretest.Call(a.f, a.h, t0, "app", "call.start", startBody("cB", sk.Public().Bytes()))
	if !r.OK() {
		t.Fatal(r.Code)
	}
	callID := str(t, r.Body, "call_id")
	a.h.Reset()
	a.f.OwnerHoldStarted(vault.NewSession(context.Background(), a.h, vault.PeerInfo{}, t0.Add(time.Second), nil))
	if c, _ := a.f.Get(callID); c.State != StateEnded || c.Reason != "unavailable" {
		t.Fatalf("%+v", c)
	}
	if e := a.sent(t, "cB", "call.end"); str(t, e.Body, "reason") != "unavailable" {
		t.Fatal("the peer was not told")
	}
	if n := len(a.h.SentOfType("call.end")); n != 3 { // the peer, the caller's device, the others
		t.Fatalf("%d call.end", n)
	}
	if a.h.HasActivity("call.missed") {
		t.Fatal("an outgoing call recorded as missed")
	}
}

// CallActive is an active call only, not a ringing one; access ended on
// purpose also ends the device's ringing outgoing call.
func TestCallActiveAndRingingOutgoing(t *testing.T) {
	a, b := newSide("cB"), newSide("cA")
	link(a, b)
	sk, _ := callwire.NewOfferKey()
	r := featuretest.Call(a.f, a.h, t0, "app", "call.start", startBody("cB", sk.Public().Bytes()))
	if !r.OK() {
		t.Fatal(r.Code)
	}
	callID := str(t, r.Body, "call_id")
	if a.f.CallActive("dev-app", callID, t0.Add(time.Second)) {
		t.Fatal("a ringing call counted as active")
	}
	a.h.Reset()
	a.f.AccessEnded(vault.NewSession(context.Background(), a.h, vault.PeerInfo{}, t0.Add(time.Second), nil), "dev-app")
	if c, _ := a.f.Get(callID); c.State != StateEnded || c.Reason != "unavailable" {
		t.Fatalf("%+v", c)
	}
	a.sent(t, "cB", "call.end")
	a.sent(t, "dev-app", "call.end")
}

// CallRingingOut: only the device's own outgoing call while it rings.
func TestCallRingingOut(t *testing.T) {
	a, b := newSide("cB"), newSide("cA")
	link(a, b)
	sk, _ := callwire.NewOfferKey()
	r := featuretest.Call(a.f, a.h, t0, "app", "call.start", startBody("cB", sk.Public().Bytes()))
	if !r.OK() {
		t.Fatal(r.Code)
	}
	callID := str(t, r.Body, "call_id")
	now := t0.Add(time.Second)
	if !a.f.CallRingingOut("dev-app", callID, now) || a.f.CallRingingOut("dev-desktop", callID, now) ||
		a.f.CallRingingOut("dev-app", newCallID("cB"), now) || a.f.CallRingingOut("dev-app", callID, t0.Add(OfferTTL)) {
		t.Fatal("CallRingingOut")
	}
	// An incoming ringing call is not one's own outgoing call.
	id := newCallID("cA")
	featuretest.CallExp(b.f, b.h, t0, t0.Add(OfferTTL), "connection:cA", "call.offer", peerOffer("cA", id, "audio", sk.Public().Bytes()))
	if b.f.CallRingingOut("dev-app", id, now) || b.f.CallRingingOut("", id, now) {
		t.Fatal("an incoming call counted as one's own outgoing")
	}
}

// A stale record (an outgoing call past its exp, not yet swept) ended by
// the peer goes out by the usual fan-out only, never straight to its
// device past an expired session.
func TestStaleEndNotSentToTheDevice(t *testing.T) {
	a, b := newSide("cB"), newSide("cA")
	link(a, b)
	sk, _ := callwire.NewOfferKey()
	r := featuretest.Call(a.f, a.h, t0, "app", "call.start", startBody("cB", sk.Public().Bytes()))
	if !r.OK() {
		t.Fatal(r.Code)
	}
	callID := str(t, r.Body, "call_id")
	a.h.Reset()
	featuretest.Call(a.f, a.h, t0.Add(OfferTTL+time.Second), "connection:cB", "call.end", `{"call_id":"`+callID+`","reason":"hangup"}`)
	for _, e := range a.h.SentOfType("call.end") {
		if e.To == "dev-app" {
			t.Fatal("a stale record's end went straight to its device")
		}
	}
	a.sent(t, "devices", "call.end")
}

// A removed connection's stale record (an outgoing call past its exp, not
// yet swept) ends by the usual fan-out only, never straight to its device.
func TestStaleConnectionRemovedNotSentToTheDevice(t *testing.T) {
	a, b := newSide("cB"), newSide("cA")
	link(a, b)
	sk, _ := callwire.NewOfferKey()
	if r := featuretest.Call(a.f, a.h, t0, "app", "call.start", startBody("cB", sk.Public().Bytes())); !r.OK() {
		t.Fatal(r.Code)
	}
	a.h.Reset()
	a.f.ConnectionRemoved(vault.NewSession(context.Background(), a.h, vault.PeerInfo{}, t0.Add(OfferTTL+time.Second), nil), "cB")
	for _, e := range a.h.SentOfType("call.end") {
		if e.To == "dev-app" {
			t.Fatal("a stale record's end went straight to its device")
		}
	}
	a.sent(t, "devices", "call.end")
}

// §10.10 "Glare" (C2, CALLS-PLAN V6, D21): two members calling each other
// at once. Both vaults compare the two call_ids and the lower wins, so one
// call connects: the winning side drops the losing offer (no ringing, no
// answer, no record, no missed call; drop.call_glare), and the losing side
// ends its own call busy with superseded_by and rings for the winner.
func TestGlare(t *testing.T) {
	a, b := newSide("cB"), newSide("cA")
	link(a, b)
	lo, hi := newCallID("glare"), newCallID("glare")
	if !(lo < hi) {
		t.Fatal("test ids out of order")
	}
	ska, _ := callwire.NewOfferKey()
	skb, _ := callwire.NewOfferKey()
	if r := featuretest.Call(a.f, a.h, t0, "app", "call.start", startBodyID("cB", lo, ska.Public().Bytes())); !r.OK() {
		t.Fatal(r.Code)
	}
	if r := featuretest.Call(b.f, b.h, t0, "app", "call.start", startBodyID("cA", hi, skb.Public().Bytes())); !r.OK() {
		t.Fatal(r.Code)
	}
	offLo, offHi := a.sent(t, "cB", "call.offer"), b.sent(t, "cA", "call.offer")
	a.h.Reset()
	b.h.Reset()

	// a's own call (lo) wins over b's offer (hi): dropped silently.
	featuretest.CallExp(a.f, a.h, t0.Add(time.Second), offHi.Opt.Exp, "connection:cB", "call.offer", string(offHi.Body))
	if _, ok := a.f.Get(hi); ok {
		t.Fatal("the losing offer got a call record")
	}
	if c, _ := a.f.Get(lo); c.State != StateRinging {
		t.Fatalf("a's own call: %+v", c)
	}
	if len(a.h.Sent) != 0 || a.h.HasActivity("call.missed") || !a.h.HasActivity("drop.call_glare") {
		t.Fatalf("a after the losing offer: sent %+v", a.h.Sent)
	}

	// b's own call (hi) loses to a's offer (lo): ended busy, its devices
	// told with superseded_by, the peer vault nothing; lo rings.
	featuretest.CallExp(b.f, b.h, t0.Add(time.Second), offLo.Opt.Exp, "connection:cA", "call.offer", string(offLo.Body))
	if c, _ := b.f.Get(hi); c.State != StateEnded || c.Reason != "busy" {
		t.Fatalf("b's own call: %+v", c)
	}
	e := b.sent(t, "dev-app", "call.end")
	if str(t, e.Body, "call_id") != hi || str(t, e.Body, "reason") != "busy" || str(t, e.Body, "superseded_by") != lo {
		t.Fatalf("the superseded end: %s", e.Body)
	}
	b.sent(t, "devices-except:dev-app", "call.end")
	for _, m := range b.h.Sent {
		if m.To == "cA" {
			t.Fatalf("the peer vault was told: %+v", m)
		}
	}
	if c, _ := b.f.Get(lo); c.State != StateRinging {
		t.Fatalf("the winning offer: %+v", c)
	}
	b.sent(t, "devices", "call.offer")
	if b.h.HasActivity("call.missed") {
		t.Fatal("a glare recorded a missed call")
	}
}

// Not a glare: an offer from another connection, or one after our own
// call was answered, is handled as before (busy).
func TestNotAGlare(t *testing.T) {
	a := newSide("cB")
	a.addConn("cC")
	sk, _ := callwire.NewOfferKey()
	lo, hi := newCallID("notglare"), newCallID("notglare")
	if r := featuretest.Call(a.f, a.h, t0, "app", "call.start", startBodyID("cB", hi, sk.Public().Bytes())); !r.OK() {
		t.Fatal(r.Code)
	}
	a.h.Reset()
	featuretest.CallExp(a.f, a.h, t0.Add(time.Second), t0.Add(OfferTTL), "connection:cC", "call.offer", peerOffer("cC", lo, "audio", sk.Public().Bytes()))
	if c, _ := a.f.Get(hi); c.State != StateRinging {
		t.Fatalf("our call to cB was ended by cC's offer: %+v", c)
	}
	if e := a.sent(t, "cC", "call.end"); str(t, e.Body, "reason") != "busy" {
		t.Fatal("cC's offer not busy")
	}
	if a.h.HasActivity("drop.call_glare") {
		t.Fatal("another connection's offer taken as a glare")
	}
}
