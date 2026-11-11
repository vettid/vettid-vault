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

// tickAt runs one empty batch at now: the housekeeping (Tick) and the end
// of the batch (BatchEnd).
func tickAt(s *side, now time.Time) {
	sess := vault.NewSession(context.Background(), s.h, vault.PeerInfo{}, now, nil)
	s.f.Tick(sess)
	s.f.BatchEnd(sess)
}

// collect runs empty batches every 20 s from after `from` up to and
// including `to` (a vault collecting without a gap).
func collect(s *side, from, to time.Time) {
	for t := from.Add(20 * time.Second); t.Before(to); t = t.Add(20 * time.Second) {
		tickAt(s, t)
	}
	tickAt(s, to)
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
	a.sent(t, "dev-app", "call.end") // the caller's device directly (a desktop without a session too, §6.8)
	a.sent(t, "devices-except:dev-app", "call.end")
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
	collect(b, answered, answered.Add(80*time.Second))
	featuretest.Call(b.f, b.h, answered.Add(80*time.Second), "app", "call.keepalive", `{"call_id":"`+id+`"}`)
	collect(b, answered.Add(80*time.Second), answered.Add(170*time.Second))
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
	b.sent(t, "dev-app", "call.end")
	b.sent(t, "devices-except:dev-app", "call.end")
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
	collect(b, answered, answered.Add(80*time.Second))
	b.h.Reset()
	featuretest.Call(b.f, b.h, answered.Add(80*time.Second), "desktop", "call.keepalive", `{"call_id":"`+id+`"}`)
	if len(b.h.Sent) != 0 {
		t.Fatalf("answered another device's keep-alive: %+v", b.h.Sent)
	}
	collect(b, answered.Add(80*time.Second), answered.Add(91*time.Second))
	if c, _ := b.f.Get(id); c.State != StateEnded {
		t.Fatal("another device's keep-alive kept the call alive")
	}
	b.h.Reset()
	featuretest.Call(b.f, b.h, answered.Add(100*time.Second), "app", "call.keepalive", `{"call_id":"`+id+`"}`)
	if e := b.sent(t, "dev-app", "call.end"); str(t, e.Body, "reason") != "unavailable" || !e.Opt.MemoryOnly || e.Opt.Exp.IsZero() {
		t.Fatalf("a keep-alive for an ended call not answered with an ephemeral unavailable: %+v", e.Opt)
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
	collect(b, unlock, unlock.Add(90*time.Second))
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

// An outgoing watched call answered by the peer: keep-alives come from the
// caller's device and count from the peer's answer; silence ends it failed
// and the peer vault is told. A second housekeeping sends nothing more.
func TestOutgoingWatchedCall(t *testing.T) {
	a, b := newSide("cB"), newSide("cA")
	link(a, b)
	sk, _ := callwire.NewOfferKey()
	start := strings.TrimSuffix(startBody("cB", sk.Public().Bytes()), "}") + `,"keepalive":true}`
	r := featuretest.Call(a.f, a.h, t0, "app", "call.start", start)
	if !r.OK() {
		t.Fatalf("start: %s", r.Code)
	}
	id := str(t, r.Body, "call_id")
	off := a.sent(t, "cB", "call.offer")
	featuretest.CallExp(b.f, b.h, t0, off.Opt.Exp, "connection:cA", "call.offer", string(off.Body))
	ring := b.sent(t, "devices", "call.offer")
	ek, _ := obj(t, ring.Body).Base64("ek", callwire.EKSize)
	enc, _, err := callwire.Answer(ek, id)
	if err != nil {
		t.Fatal(err)
	}
	featuretest.Call(b.f, b.h, t0.Add(5*time.Second), "app", "call.answer", answerBody("dev-app", id, enc))
	fwd := b.sent(t, "cA", "call.answer")
	answered := t0.Add(5 * time.Second)
	featuretest.Call(a.f, a.h, answered, "connection:cB", "call.answer", string(fwd.Body))
	if c, _ := a.f.Get(id); c.State != StateActive || !c.Watched || c.Device != "dev-app" {
		t.Fatalf("caller's record: %+v", c)
	}
	collect(a, answered, answered.Add(60*time.Second))
	featuretest.Call(a.f, a.h, answered.Add(60*time.Second), "app", "call.keepalive", `{"call_id":"`+id+`"}`)
	collect(a, answered.Add(60*time.Second), answered.Add(150*time.Second))
	if c, _ := a.f.Get(id); c.State != StateActive {
		t.Fatal("ended within 90 s of the caller's keep-alive")
	}
	a.h.Reset()
	tickAt(a, answered.Add(151*time.Second))
	if c, _ := a.f.Get(id); c.State != StateEnded || c.Reason != "failed" {
		t.Fatalf("not ended failed: %+v", c)
	}
	if e := a.sent(t, "cB", "call.end"); str(t, e.Body, "reason") != "failed" {
		t.Fatal("the peer vault was not told")
	}
	a.h.Reset()
	tickAt(a, answered.Add(300*time.Second))
	if len(a.h.Sent) != 0 {
		t.Fatalf("a second housekeeping sent: %+v", a.h.Sent)
	}
}

// A keep-alive for a ringing call or an unknown call_id is answered
// call.end{unavailable}; a ring timeout is sent once.
func TestKeepaliveForRingingAndUnknown(t *testing.T) {
	b := newSide("cA")
	sk, _ := callwire.NewOfferKey()
	id := "01JB2Z6V9K3M4N5P6Q7R8S9T0A"
	featuretest.CallExp(b.f, b.h, t0, t0.Add(OfferTTL), "connection:cA", "call.offer", peerOffer("cA", id, "audio", sk.Public().Bytes()))
	for _, cid := range []string{id, "01JB2Z6V9K3M4N5P6Q7R8S9T0B"} {
		b.h.Reset()
		featuretest.Call(b.f, b.h, t0.Add(time.Second), "app", "call.keepalive", `{"call_id":"`+cid+`"}`)
		if e := b.sent(t, "dev-app", "call.end"); str(t, e.Body, "reason") != "unavailable" {
			t.Fatalf("%s: not answered unavailable", cid)
		}
	}
	if c, _ := b.f.Get(id); c.State != StateRinging {
		t.Fatal("a keep-alive changed a ringing call")
	}
	tickAt(b, t0.Add(OfferTTL))
	if missedCount(b) != 1 {
		t.Fatal("no missed call")
	}
	b.h.Reset()
	tickAt(b, t0.Add(2*OfferTTL))
	if len(b.h.Sent) != 0 || missedCount(b) != 0 {
		t.Fatalf("a second housekeeping after the timeout: %+v", b.h.Sent)
	}
}

// keepalive in call.answer: any value but true is refused.
func TestAnswerKeepaliveFlag(t *testing.T) {
	b := newSide("cA")
	sk, _ := callwire.NewOfferKey()
	id := "01JB2Z6V9K3M4N5P6Q7R8S9T0A"
	featuretest.CallExp(b.f, b.h, t0, t0.Add(OfferTTL), "connection:cA", "call.offer", peerOffer("cA", id, "audio", sk.Public().Bytes()))
	body := strings.TrimSuffix(answerBody("dev-app", id, make([]byte, callwire.EncSize)), "}")
	for _, v := range []string{"false", `"true"`, "1"} {
		if r := featuretest.Call(b.f, b.h, t0.Add(time.Second), "app", "call.answer", body+`,"keepalive":`+v+`}`); r.Code != "bad_request" {
			t.Fatalf("keepalive %s: %q", v, r.Code)
		}
	}
	if c, _ := b.f.Get(id); c.State != StateRinging {
		t.Fatal("a refused answer changed the call")
	}
}

// A collect gap (M1, the lead's review): the vault did not collect for
// 100 s, so the device's keep-alives may not have reached it. The batch
// that ends the gap counts its own keep-alive before the silence is judged
// (BatchEnd after the messages), and without one the count starts again at
// the gap's end, as at the unlock.
func TestCollectGapDoesNotEndLiveCalls(t *testing.T) {
	for _, withKA := range []bool{true, false} {
		b, id := watchedCall(t, true)
		answered := t0.Add(time.Second)
		collect(b, answered, answered.Add(20*time.Second))
		after := answered.Add(120 * time.Second) // 100 s with no collect
		sess := vault.NewSession(context.Background(), b.h, vault.PeerInfo{}, after, nil)
		b.f.Tick(sess)
		if withKA {
			featuretest.Call(b.f, b.h, after, "app", "call.keepalive", `{"call_id":"`+id+`"}`)
		}
		b.f.BatchEnd(sess)
		if c, _ := b.f.Get(id); c.State != StateActive {
			t.Fatalf("keep-alive %v: a collect gap ended a live call", withKA)
		}
		collect(b, after, after.Add(90*time.Second))
		if c, _ := b.f.Get(id); c.State != StateActive {
			t.Fatalf("keep-alive %v: ended within 90 s of the gap's end", withKA)
		}
		tickAt(b, after.Add(91*time.Second))
		if c, _ := b.f.Get(id); c.State != StateEnded || c.Reason != "failed" {
			t.Fatalf("keep-alive %v: not ended 90 s after the gap's end", withKA)
		}
	}
}

// The count of an outgoing watched call starts at the peer's answer: still
// active at answer + 90 s with no keep-alive, failed at + 91 s. An outgoing
// call started without keepalive is not watched.
func TestOutgoingCountFromThePeersAnswer(t *testing.T) {
	for _, ka := range []bool{true, false} {
		a, b := newSide("cB"), newSide("cA")
		link(a, b)
		sk, _ := callwire.NewOfferKey()
		start := startBody("cB", sk.Public().Bytes())
		if ka {
			start = strings.TrimSuffix(start, "}") + `,"keepalive":true}`
		}
		r := featuretest.Call(a.f, a.h, t0, "app", "call.start", start)
		id := str(t, r.Body, "call_id")
		off := a.sent(t, "cB", "call.offer")
		featuretest.CallExp(b.f, b.h, t0, off.Opt.Exp, "connection:cA", "call.offer", string(off.Body))
		ring := b.sent(t, "devices", "call.offer")
		ek, _ := obj(t, ring.Body).Base64("ek", callwire.EKSize)
		enc, _, _ := callwire.Answer(ek, id)
		featuretest.Call(b.f, b.h, t0.Add(5*time.Second), "app", "call.answer", answerBody("dev-app", id, enc))
		answered := t0.Add(5 * time.Second)
		featuretest.Call(a.f, a.h, answered, "connection:cB", "call.answer", string(b.sent(t, "cA", "call.answer").Body))
		if c, _ := a.f.Get(id); c.Watched != ka {
			t.Fatalf("keepalive %v: watched %v", ka, c.Watched)
		}
		collect(a, answered, answered.Add(90*time.Second))
		if c, _ := a.f.Get(id); c.State != StateActive {
			t.Fatalf("keepalive %v: ended within 90 s of the peer's answer", ka)
		}
		tickAt(a, answered.Add(91*time.Second))
		c, _ := a.f.Get(id)
		if ka && (c.State != StateEnded || c.Reason != "failed") {
			t.Fatal("not ended 91 s after the peer's answer")
		}
		if !ka && c.State != StateActive {
			t.Fatal("an unwatched outgoing call was ended")
		}
	}
}

// A keep-alive for an active call past the 12 h limit (L1) is answered
// unavailable and does not count.
func TestKeepalivePastTheCallLimit(t *testing.T) {
	b, id := watchedCall(t, true)
	late := t0.Add(MaxCallDuration + 2*time.Second)
	b.h.Reset()
	featuretest.Call(b.f, b.h, late, "app", "call.keepalive", `{"call_id":"`+id+`"}`)
	if e := b.sent(t, "dev-app", "call.end"); str(t, e.Body, "reason") != "unavailable" || !e.Opt.MemoryOnly {
		t.Fatal("a keep-alive past 12 h not answered with an ephemeral unavailable")
	}
}
