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
