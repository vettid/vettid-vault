package calls

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/featuretest"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/callwire"
	"github.com/vettid/vettid-vault/vms/envelope"
)

func (s *side) permEvents() int {
	n := 0
	for _, m := range s.h.Sent {
		if m.Type == "sync.event" && strings.Contains(string(m.Body), `"kind":"call.permission"`) {
			n++
		}
	}
	return n
}

func (s *side) countActivity(kind string) int {
	n := 0
	for _, a := range s.h.Activities {
		if a.Kind == kind {
			n++
		}
	}
	return n
}

// §10.10 "Permission and limits" (C2, V5): calls allowed or off per
// connection; a change is audited and announced; the list gives the
// connections that differ from the default.
func TestCallPermission(t *testing.T) {
	b := newSide("cA")
	set := func(body string) featuretest.Result {
		return featuretest.Call(b.f, b.h, t0, "app", "call.permission.set", body)
	}
	list := func() string {
		r := featuretest.Call(b.f, b.h, t0, "app", "call.permission.list", `{}`)
		if !r.OK() {
			t.Fatal(r.Code)
		}
		return string(r.Body)
	}
	if got := list(); got != `{"connections":[]}` {
		t.Fatalf("default: %s", got)
	}
	if r := set(`{"connection_id":"nope","allowed":false}`); r.Code != "not_found" {
		t.Fatalf("unknown connection: %q", r.Code)
	}
	if r := set(`{"connection_id":"cA"}`); r.Code != "bad_request" {
		t.Fatalf("no allowed: %q", r.Code)
	}
	if r := set(`{"connection_id":"cA","allowed":false}`); !r.OK() || string(r.Body) != `{}` {
		t.Fatalf("off: %q %s", r.Code, r.Body)
	}
	if !b.h.HasActivity("call.permission_off") || b.permEvents() != 1 {
		t.Fatal("off not audited or not announced")
	}
	if got := list(); got != `{"connections":[{"connection_id":"cA","allowed":false,"limited":false}]}` {
		t.Fatalf("off listed: %s", got)
	}
	set(`{"connection_id":"cA","allowed":false}`) // no change
	if b.permEvents() != 1 || b.countActivity("call.permission_off") != 1 {
		t.Fatal("an unchanged setting announced again")
	}
	set(`{"connection_id":"cA","allowed":true}`)
	if !b.h.HasActivity("call.permission_on") || b.permEvents() != 2 || list() != `{"connections":[]}` {
		t.Fatal("on")
	}
}

// Off: an offer rings nothing and is not answered, with no record, no
// missed call and no wake (drop.call_off); the member's own call to the
// connection is calls_off.
func TestCallsOff(t *testing.T) {
	b := newSide("cA")
	featuretest.Call(b.f, b.h, t0, "app", "call.permission.set", `{"connection_id":"cA","allowed":false}`)
	b.h.Reset()
	sk, _ := callwire.NewOfferKey()
	id := newCallID("cA")
	featuretest.CallExp(b.f, b.h, t0, t0.Add(OfferTTL), "connection:cA", "call.offer", peerOffer("cA", id, "audio", sk.Public().Bytes()))
	if _, ok := b.f.Get(id); ok || len(b.h.Sent) != 0 || b.h.HasActivity("call.missed") || !b.h.HasActivity("drop.call_off") {
		t.Fatalf("an offer with calls off: sent %+v", b.h.Sent)
	}
	if r := featuretest.Call(b.f, b.h, t0, "app", "call.start", startBody("cA", sk.Public().Bytes())); r.Code != "calls_off" {
		t.Fatalf("a call to it: %q", r.Code)
	}
}

// missOne is an incoming offer from cA that rings and then times out.
func missOne(t *testing.T, b *side, at time.Time) string {
	t.Helper()
	sk, _ := callwire.NewOfferKey()
	id := newCallID("cA")
	featuretest.CallExp(b.f, b.h, at, at.Add(OfferTTL), "connection:cA", "call.offer", peerOffer("cA", id, "audio", sk.Public().Bytes()))
	featuretest.Call(b.f, b.h, at.Add(time.Second), "connection:cA", "call.end", `{"call_id":"`+id+`","reason":"hangup"}`)
	return id
}

// Unanswered calls are limited: 3 in 10 minutes silence the next offer
// (ended unavailable, missed, drop.call_rate; limited listed and
// announced); a call the member places clears it; the limit lapses with
// time and the lapse is announced at housekeeping.
func TestUnansweredLimit(t *testing.T) {
	b := newSide("cA")
	for i := 0; i < 3; i++ { // the spec's 3 in 10 minutes
		if i == 2 && b.f.limited("cA", t0.Add(2*time.Minute)) {
			t.Fatal("limited after 2")
		}
		missOne(t, b, t0.Add(time.Duration(i)*time.Minute))
	}
	if !b.f.limited("cA", t0.Add(3*time.Minute)) || b.permEvents() != 1 {
		t.Fatalf("becoming limited announced %d times", b.permEvents())
	}
	b.h.Reset()
	sk, _ := callwire.NewOfferKey()
	id := newCallID("cA")
	at := t0.Add(4 * time.Minute)
	featuretest.CallExp(b.f, b.h, at, at.Add(OfferTTL), "connection:cA", "call.offer", peerOffer("cA", id, "audio", sk.Public().Bytes()))
	if c, _ := b.f.Get(id); c.State != StateEnded || c.Reason != "unavailable" {
		t.Fatalf("a limited offer: %+v", c)
	}
	if !b.h.HasActivity("drop.call_rate") || !b.h.HasActivity("call.missed") || len(b.h.SentOfType("call.offer")) != 0 || len(b.h.SentOfType("call.end")) != 0 {
		t.Fatal("a limited offer rang, was answered, or wasn't recorded")
	}
	r := featuretest.Call(b.f, b.h, at, "app", "call.permission.list", `{}`)
	if string(r.Body) != `{"connections":[{"connection_id":"cA","allowed":true,"limited":true}]}` {
		t.Fatalf("limited listed: %s", r.Body)
	}
	// The limit lapses with time; housekeeping announces it.
	b.h.Reset()
	b.f.Tick(vault.NewSession(context.Background(), b.h, vault.PeerInfo{}, at.Add(LimitShortWindow+time.Minute), nil))
	if b.permEvents() != 1 || b.f.limited("cA", at.Add(LimitShortWindow+time.Minute)) {
		t.Fatal("the lapse not announced")
	}
	// A call the member places clears the counts.
	missOne(t, b, at.Add(20*time.Minute))
	if len(b.f.unanswered["cA"]) == 0 {
		t.Fatal("no counts")
	}
	featuretest.Call(b.f, b.h, at.Add(21*time.Minute), "app", "call.start", startBody("cA", sk.Public().Bytes()))
	if len(b.f.unanswered["cA"]) != 0 {
		t.Fatal("a call the member placed didn't clear the counts")
	}
}

// 10 in 24 hours, spread out, limit too; at most 10 times are kept.
func TestUnansweredLimitLong(t *testing.T) {
	b := newSide("cA")
	for i := 0; i < 10; i++ { // the spec's 10 in 24 hours
		if i == 9 && b.f.limited("cA", t0.Add(9*time.Hour)) {
			t.Fatal("limited after 9")
		}
		missOne(t, b, t0.Add(time.Duration(i)*time.Hour))
	}
	now := t0.Add(9*time.Hour + time.Minute)
	if !b.f.limited("cA", now) || b.f.limited("cA", t0.Add(24*time.Hour+time.Minute)) {
		t.Fatal("the 24 h limit")
	}
	missOne(t, b, t0.Add(10*time.Hour))
	if len(b.f.unanswered["cA"]) != LimitLong {
		t.Fatalf("%d times kept", len(b.f.unanswered["cA"]))
	}
}

// An answered call from the connection clears the counts.
func TestAnsweredClearsCounts(t *testing.T) {
	b := newSide("cA")
	missOne(t, b, t0)
	sk, _ := callwire.NewOfferKey()
	id := newCallID("cA")
	at := t0.Add(time.Minute)
	featuretest.CallExp(b.f, b.h, at, at.Add(OfferTTL), "connection:cA", "call.offer", peerOffer("cA", id, "audio", sk.Public().Bytes()))
	enc, _, _ := callwire.Answer(sk.Public().Bytes(), id)
	featuretest.Call(b.f, b.h, at.Add(time.Second), "app", "call.answer", answerBody("dev-app", id, enc))
	if len(b.f.unanswered["cA"]) != 0 {
		t.Fatal("an answered call didn't clear the counts")
	}
}

// A missed call asks the feed to merge it into the connection's active
// call.missed item of the last 24 hours.
func TestMissedCallMerges(t *testing.T) {
	b := newSide("cA")
	missOne(t, b, t0)
	for _, a := range b.h.Activities {
		if a.Kind == "call.missed" && (a.Batch != MissedMergeWindow || !a.BatchWhileActive) {
			t.Fatalf("%+v", a)
		}
	}
}

// The state: the earlier form (the calls map alone) still loads; the new
// form keeps the permission and counts; a removed connection's go.
func TestCallStateFormsAndRemoval(t *testing.T) {
	b := newSide("cA")
	missOne(t, b, t0)
	featuretest.Call(b.f, b.h, t0, "app", "call.permission.set", `{"connection_id":"cA","allowed":false}`)
	saved, err := b.f.Save()
	if err != nil || !strings.Contains(string(saved), `"v":2`) {
		t.Fatalf("%s %v", saved, err)
	}
	g := New(Options{})
	if err := g.Load(saved); err != nil || !g.off["cA"] || len(g.unanswered["cA"]) != 1 || len(g.calls) != 1 {
		t.Fatalf("round trip: %v", err)
	}
	old, _ := json.Marshal(b.f.calls)
	h := New(Options{})
	if err := h.Load(old); err != nil || len(h.calls) != 1 || len(h.off) != 0 {
		t.Fatalf("the earlier form: %v", err)
	}
	b.f.ConnectionRemoved(vault.NewSession(context.Background(), b.h, vault.PeerInfo{}, t0, nil), "cA")
	if b.f.off["cA"] || len(b.f.unanswered["cA"]) != 0 {
		t.Fatal("a removed connection's permission or counts kept")
	}
}

// What counts toward the limit: a decline does; an incoming call the vault
// ends for its own reasons (no ICE configuration) doesn't.
func TestUnansweredWhatCounts(t *testing.T) {
	b := newSide("cA")
	sk, _ := callwire.NewOfferKey()
	id := newCallID("cA")
	featuretest.CallExp(b.f, b.h, t0, t0.Add(OfferTTL), "connection:cA", "call.offer", peerOffer("cA", id, "audio", sk.Public().Bytes()))
	featuretest.Call(b.f, b.h, t0.Add(time.Second), "app", "call.end", `{"call_id":"`+id+`","reason":"decline"}`)
	if len(b.f.unanswered["cA"]) != 1 {
		t.Fatalf("a decline counted %d", len(b.f.unanswered["cA"]))
	}
	c := newSide("cA")
	c.f = New(Options{ICE: failingICE{}})
	featuretest.CallExp(c.f, c.h, t0, t0.Add(OfferTTL), "connection:cA", "call.offer", peerOffer("cA", newCallID("cA"), "audio", sk.Public().Bytes()))
	if len(c.f.unanswered["cA"]) != 0 {
		t.Fatal("a call the vault ended for its own reasons counted")
	}
}

type failingICE struct{}

func (failingICE) Issue(context.Context, string, time.Duration) ([]callwire.ICEServer, error) {
	return nil, context.DeadlineExceeded
}

// Calls off is checked before glare: an off connection's offer can't end
// the member's own call to it, placed before calls were turned off.
func TestOffBeforeGlare(t *testing.T) {
	a := newSide("cB")
	sk, _ := callwire.NewOfferKey()
	lo, hi := newCallID("obg"), newCallID("obg")
	if r := featuretest.Call(a.f, a.h, t0, "app", "call.start", startBodyID("cB", hi, sk.Public().Bytes())); !r.OK() {
		t.Fatal(r.Code)
	}
	featuretest.Call(a.f, a.h, t0, "app", "call.permission.set", `{"connection_id":"cB","allowed":false}`)
	a.h.Reset()
	featuretest.CallExp(a.f, a.h, t0.Add(time.Second), t0.Add(OfferTTL), "connection:cB", "call.offer", peerOffer("cB", lo, "audio", sk.Public().Bytes()))
	if c, _ := a.f.Get(hi); c.State != StateRinging || !a.h.HasActivity("drop.call_off") || a.h.HasActivity("drop.call_glare") {
		t.Fatalf("our call after an off connection's offer: %+v", c)
	}
}

// The limited state is kept, so a limit that lapsed while the vault was
// locked is announced after the unlock, at housekeeping.
func TestLimitedSurvivesALoad(t *testing.T) {
	b := newSide("cA")
	for i := 0; i < 3; i++ {
		missOne(t, b, t0.Add(time.Duration(i)*time.Minute))
	}
	saved, _ := b.f.Save()
	g := New(Options{})
	if err := g.Load(saved); err != nil || !g.limitedSent["cA"] {
		t.Fatalf("limited not kept: %v", err)
	}
	b.h.Reset()
	g.Tick(vault.NewSession(context.Background(), b.h, vault.PeerInfo{}, t0.Add(time.Hour), nil))
	if b.permEvents() != 1 || g.limitedSent["cA"] {
		t.Fatal("a lapse during the lock not announced")
	}
}

// Busy and suppressed calls count; a limited offer is silent even when the
// vault is busy (limited before busy: the caller learns nothing).
func TestBusyAndSuppressedCount(t *testing.T) {
	b := newSide("cA")
	b.addConn("cC")
	sk, _ := callwire.NewOfferKey()
	active := newCallID("cC")
	featuretest.CallExp(b.f, b.h, t0, t0.Add(OfferTTL), "connection:cC", "call.offer", peerOffer("cC", active, "audio", sk.Public().Bytes()))
	enc, _, _ := callwire.Answer(sk.Public().Bytes(), active)
	featuretest.Call(b.f, b.h, t0, "app", "call.answer", answerBody("dev-app", active, enc))
	// While busy: each offer from cA is answered busy and counts.
	for i := 0; i < 3; i++ {
		at := t0.Add(time.Duration(i+1) * time.Second)
		featuretest.CallExp(b.f, b.h, at, at.Add(OfferTTL), "connection:cA", "call.offer", peerOffer("cA", newCallID("cA"), "audio", sk.Public().Bytes()))
	}
	if len(b.f.unanswered["cA"]) != 3 {
		t.Fatalf("busy calls counted %d", len(b.f.unanswered["cA"]))
	}
	// Now limited, and still busy: no busy reply, an unavailable record.
	b.h.Reset()
	id := newCallID("cA")
	at := t0.Add(5 * time.Second)
	featuretest.CallExp(b.f, b.h, at, at.Add(OfferTTL), "connection:cA", "call.offer", peerOffer("cA", id, "audio", sk.Public().Bytes()))
	if len(b.h.SentOfType("call.end")) != 0 || !b.h.HasActivity("drop.call_rate") {
		t.Fatal("a limited offer while busy was answered busy")
	}
	if c, _ := b.f.Get(id); c.Reason != "unavailable" || len(b.f.unanswered["cA"]) != 4 {
		t.Fatalf("a suppressed call: %+v, counted %d", c, len(b.f.unanswered["cA"]))
	}
}

// The windows' exact ends: 10 minutes and 24 hours, "in the last".
func TestLimitWindowBoundaries(t *testing.T) {
	f := New(Options{})
	f.unanswered["c"] = []time.Time{t0, t0.Add(time.Minute), t0.Add(2 * time.Minute)}
	if !f.limited("c", t0.Add(10*time.Minute-time.Nanosecond)) || f.limited("c", t0.Add(10*time.Minute)) {
		t.Fatal("the 10 minute window")
	}
	var ten []time.Time
	for i := 0; i < 10; i++ {
		ten = append(ten, t0.Add(time.Duration(i)*time.Hour))
	}
	f.unanswered["c"] = ten
	if !f.limited("c", t0.Add(24*time.Hour-time.Nanosecond)) || f.limited("c", t0.Add(24*time.Hour)) {
		t.Fatal("the 24 hour window")
	}
	if MissedMergeWindow != 24*time.Hour || LimitShortWindow != 10*time.Minute || LimitLongWindow != 24*time.Hour {
		t.Fatal("the spec's windows")
	}
}

// A clock stepped back doesn't lengthen a limit: a count later than now is
// moved to now once and ages from there.
func TestLimitClockStepBack(t *testing.T) {
	f := New(Options{})
	future := t0.Add(time.Hour)
	f.unanswered["c"] = []time.Time{future, future, future}
	if !f.limited("c", t0) {
		t.Fatal("counts from before the step")
	}
	if f.limited("c", t0.Add(10*time.Minute)) {
		t.Fatal("a limit lengthened by a clock stepped back")
	}
}

// Only the owner's own devices: an agent or a connection is refused.
func TestCallPermissionSenders(t *testing.T) {
	b := newSide("cA")
	for _, from := range []string{"agent", "connection:cA"} {
		for _, typ := range []string{"call.permission.set", "call.permission.list"} {
			body := `{}`
			if typ == "call.permission.set" {
				body = `{"connection_id":"cA","allowed":false}`
			}
			if r := featuretest.Call(b.f, b.h, t0, from, typ, body); r.Code != "forbidden" {
				t.Errorf("%s from %s: %q", typ, from, r.Code)
			}
		}
	}
	if b.f.off["cA"] {
		t.Fatal("set by another sender")
	}
	if r := featuretest.Call(b.f, b.h, t0, "app", "call.permission.list", `{"x":1}`); r.Code != "bad_request" {
		t.Fatalf("list with a member: %q", r.Code)
	}
}

// Clearing the counts of a limited connection announces it; the list
// leaves out a connection with counts that isn't limited.
func TestClearAnnouncesAndListLeavesOut(t *testing.T) {
	b := newSide("cA")
	b.addConn("cC")
	missOne(t, b, t0) // cA: one, not limited
	for i := 0; i < 3; i++ {
		sk, _ := callwire.NewOfferKey()
		id := newCallID("cC")
		at := t0.Add(time.Duration(i) * time.Minute)
		featuretest.CallExp(b.f, b.h, at, at.Add(OfferTTL), "connection:cC", "call.offer", peerOffer("cC", id, "audio", sk.Public().Bytes()))
		featuretest.Call(b.f, b.h, at.Add(time.Second), "connection:cC", "call.end", `{"call_id":"`+id+`","reason":"hangup"}`)
	}
	r := featuretest.Call(b.f, b.h, t0.Add(3*time.Minute), "app", "call.permission.list", `{}`)
	if string(r.Body) != `{"connections":[{"connection_id":"cC","allowed":true,"limited":true}]}` {
		t.Fatalf("list: %s", r.Body)
	}
	b.h.Reset()
	sk, _ := callwire.NewOfferKey()
	featuretest.Call(b.f, b.h, t0.Add(4*time.Minute), "app", "call.start", startBody("cC", sk.Public().Bytes()))
	if b.permEvents() != 1 {
		t.Fatalf("clearing a limit announced %d times", b.permEvents())
	}
}

// A state from a later release is refused, never loaded without what it
// doesn't know.
func TestCallStateLaterVersion(t *testing.T) {
	if err := New(Options{}).Load([]byte(`{"v":3,"calls":{}}`)); err == nil {
		t.Fatal("a later state version loaded")
	}
}

// The handler itself refuses another sender kind (a second guard beside
// the type's registration).
func TestCallPermissionHandlerGuard(t *testing.T) {
	b := newSide("cA")
	s := vault.NewSession(context.Background(), b.h, vault.PeerInfo{ID: "agent1", Kind: vault.KindAgent, State: vault.PeerActive}, t0, nil)
	for _, in := range []*envelope.Inner{
		{Type: "call.permission.set", Body: []byte(`{"connection_id":"cA","allowed":false}`)},
		{Type: "call.permission.list", Body: []byte(`{}`)},
	} {
		if _, err := b.f.Handle(context.Background(), s, in); err == nil || !strings.Contains(err.Error(), "forbidden") {
			t.Errorf("%s from an agent: %v", in.Type, err)
		}
	}
	if b.f.off["cA"] {
		t.Fatal("set by an agent")
	}
}
