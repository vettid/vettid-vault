package calls

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/featuretest"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/callwire"
)

// tickAt runs the feature's housekeeping at now.
func tickAt(s *side, now time.Time) {
	s.f.Tick(vault.NewSession(context.Background(), s.h, vault.PeerInfo{}, now, nil))
}

func missedCount(s *side) int {
	n := 0
	for _, a := range s.h.Activities {
		if a.Kind == "call.missed" {
			n++
		}
	}
	return n
}

// An incoming ringing call (§10.10 "Ring timer", C2): ended at its exp by
// housekeeping with reason timeout, call.end{timeout} to every owner
// device, a missed call; the caller's vault is told nothing. Not before exp.
// A later call.end from the caller records no second missed call.
func TestRingTimerIncoming(t *testing.T) {
	b := newSide("cA")
	sk, _ := callwire.NewOfferKey()
	id := "01JB2Z6V9K3M4N5P6Q7R8S9T0A"
	featuretest.CallExp(b.f, b.h, t0, t0.Add(OfferTTL), "connection:cA", "call.offer", peerOffer("cA", id, "audio", sk.Public().Bytes()))
	b.h.Reset()
	tickAt(b, t0.Add(OfferTTL-time.Millisecond))
	if c, _ := b.f.Get(id); c.State != StateRinging || len(b.h.Sent) != 0 {
		t.Fatal("ended before its exp")
	}
	tickAt(b, t0.Add(OfferTTL))
	c, _ := b.f.Get(id)
	if c.State != StateEnded || c.Reason != "timeout" {
		t.Fatalf("not ended timeout at exp: %+v", c)
	}
	if e := b.sent(t, "devices", "call.end"); str(t, e.Body, "reason") != "timeout" {
		t.Fatal("the devices were not told timeout")
	}
	for _, m := range b.h.Sent {
		if m.To == "cA" {
			t.Fatalf("the caller's vault was told: %+v", m)
		}
	}
	if missedCount(b) != 1 {
		t.Fatal("no missed call")
	}
	featuretest.Call(b.f, b.h, t0.Add(OfferTTL+time.Second), "connection:cA", "call.end", `{"call_id":"`+id+`","reason":"timeout"}`)
	tickAt(b, t0.Add(2*OfferTTL))
	if missedCount(b) != 1 {
		t.Fatal("a second missed call for one call")
	}
}

// An outgoing ringing call: ended timeout at its exp, call.end{timeout} to
// the owner devices and to the peer vault; no missed call.
func TestRingTimerOutgoing(t *testing.T) {
	a := newSide("cB")
	sk, _ := callwire.NewOfferKey()
	id := newCallID("cB")
	if r := featuretest.Call(a.f, a.h, t0, "app", "call.start", startBodyID("cB", id, sk.Public().Bytes())); !r.OK() {
		t.Fatalf("start: %s", r.Code)
	}
	a.h.Reset()
	tickAt(a, t0.Add(OfferTTL))
	if c, _ := a.f.Get(id); c.State != StateEnded || c.Reason != "timeout" {
		t.Fatalf("not ended at exp: %+v", c)
	}
	if e := a.sent(t, "cB", "call.end"); str(t, e.Body, "reason") != "timeout" {
		t.Fatal("the peer vault was not told timeout")
	}
	a.sent(t, "devices", "call.end")
	if missedCount(a) != 0 {
		t.Fatal("an outgoing call recorded as missed")
	}
}

// answerKA is a device's call.answer with keepalive: true.
func answerKA(dev, id string, enc []byte) string {
	b := answerBody(dev, id, enc)
	return strings.TrimSuffix(b, "}") + `,"keepalive":true}`
}

// watchedCall rings b with an incoming call and has dev-app answer it,
// saying it sends keep-alives when ka is set.
func watchedCall(t *testing.T, ka bool) (*side, string) {
	t.Helper()
	b := newSide("cA")
	sk, _ := callwire.NewOfferKey()
	id := "01JB2Z6V9K3M4N5P6Q7R8S9T0A"
	featuretest.CallExp(b.f, b.h, t0, t0.Add(OfferTTL), "connection:cA", "call.offer", peerOffer("cA", id, "audio", sk.Public().Bytes()))
	enc := make([]byte, callwire.EncSize)
	body := answerBody("dev-app", id, enc)
	if ka {
		body = answerKA("dev-app", id, enc)
	}
	if r := featuretest.Call(b.f, b.h, t0.Add(time.Second), "app", "call.answer", body); r.Code != "" {
		t.Fatalf("answer: %s", r.Code)
	}
	if c, _ := b.f.Get(id); c.State != StateActive || c.Watched != ka {
		t.Fatalf("setup: %+v", c)
	}
	return b, id
}

// (§10.10 "Liveness", C2) A watched active call ends when its device has
// been silent more than 90 s (from the answer until the first keep-alive):
// reason failed, call.end{failed} to the peer vault and the owner devices,
// audited call.ended. A keep-alive restarts the count.
func TestKeepaliveSilenceEndsAWatchedCall(t *testing.T) {
	b, id := watchedCall(t, true)
	answered := t0.Add(time.Second)
	tickAt(b, answered.Add(80*time.Second))
	featuretest.Call(b.f, b.h, answered.Add(80*time.Second), "app", "call.keepalive", `{"call_id":"`+id+`"}`)
	tickAt(b, answered.Add(170*time.Second))
	if c, _ := b.f.Get(id); c.State != StateActive {
		t.Fatal("ended within 90 s of a keep-alive")
	}
	b.h.Reset()
	tickAt(b, answered.Add(171*time.Second))
	c, _ := b.f.Get(id)
	if c.State != StateEnded || c.Reason != "failed" {
		t.Fatalf("not ended failed after 90 s of silence: %+v", c)
	}
	if e := b.sent(t, "cA", "call.end"); str(t, e.Body, "reason") != "failed" {
		t.Fatal("the peer vault was not told")
	}
	b.sent(t, "devices", "call.end")
	if !b.h.HasActivity("call.ended") {
		t.Fatal("not audited")
	}
}

// A call whose device did not say it sends keep-alives keeps S10's rule.
func TestUnwatchedCallKeepsLiving(t *testing.T) {
	b, id := watchedCall(t, false)
	tickAt(b, t0.Add(10*time.Minute))
	if c, _ := b.f.Get(id); c.State != StateActive {
		t.Fatal("an unwatched call was ended by the 90 s rule")
	}
}

// A keep-alive from another device is dropped (no effect, no answer); one
// for a call that is not active is answered call.end{unavailable}.
func TestKeepaliveFromOthersAndForEndedCalls(t *testing.T) {
	b, id := watchedCall(t, true)
	answered := t0.Add(time.Second)
	b.h.Reset()
	featuretest.Call(b.f, b.h, answered.Add(80*time.Second), "desktop", "call.keepalive", `{"call_id":"`+id+`"}`)
	if len(b.h.Sent) != 0 {
		t.Fatalf("answered another device's keep-alive: %+v", b.h.Sent)
	}
	tickAt(b, answered.Add(91*time.Second))
	if c, _ := b.f.Get(id); c.State != StateEnded {
		t.Fatal("another device's keep-alive kept the call alive")
	}
	b.h.Reset()
	featuretest.Call(b.f, b.h, answered.Add(100*time.Second), "app", "call.keepalive", `{"call_id":"`+id+`"}`)
	if e := b.sent(t, "dev-app", "call.end"); str(t, e.Body, "reason") != "unavailable" {
		t.Fatal("a keep-alive for an ended call not answered unavailable")
	}
}

// The keep-alive times are memory only: after the state is loaded again
// (an unlock) the 90 s count from the first look.
func TestKeepaliveCountsFromTheUnlock(t *testing.T) {
	b, id := watchedCall(t, true)
	state, err := b.f.Save()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(state), "alive") {
		t.Fatal("keep-alive times in the state")
	}
	f2 := New(Options{})
	if err := f2.Load(state); err != nil {
		t.Fatal(err)
	}
	b.f = f2
	unlock := t0.Add(time.Hour)
	tickAt(b, unlock)
	tickAt(b, unlock.Add(90*time.Second))
	if c, _ := b.f.Get(id); c.State != StateActive {
		t.Fatal("ended within 90 s of the unlock")
	}
	tickAt(b, unlock.Add(91*time.Second))
	if c, _ := b.f.Get(id); c.State != StateEnded || c.Reason != "failed" {
		t.Fatal("not ended 90 s after the unlock")
	}
}

// keepalive in call.start makes an outgoing call watched; any value but
// true is refused.
func TestStartKeepaliveFlag(t *testing.T) {
	a := newSide("cB")
	sk, _ := callwire.NewOfferKey()
	id := newCallID("cB")
	body := strings.TrimSuffix(startBodyID("cB", id, sk.Public().Bytes()), "}")
	if r := featuretest.Call(a.f, a.h, t0, "app", "call.start", body+`,"keepalive":false}`); r.Code != "bad_request" {
		t.Fatalf("keepalive false: %q", r.Code)
	}
	if r := featuretest.Call(a.f, a.h, t0, "app", "call.start", body+`,"keepalive":true}`); !r.OK() {
		t.Fatalf("start: %s", r.Code)
	}
	if c, _ := a.f.Get(id); !c.Watched {
		t.Fatal("not watched")
	}
}
