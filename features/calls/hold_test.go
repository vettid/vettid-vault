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
	if c, _ := a.f.Get(callID); c.State != StateEnded || c.Reason != "unavailable" {
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
