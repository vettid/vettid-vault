package leash

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/vettid/vettid-vault/features/itemspec"
	"github.com/vettid/vettid-vault/internal/featuretest"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// §8.2 Exception (owner decision a, #14595): an answer that carries a
// secret value is sent with it, and cached for a retransmission as a copy
// without it. item.get keeps the item's id, name, category and fields
// without their values, and no notes. (#15273) Every copy carries
// "withheld": true, and the live answer does not.
func TestItemGetCachedWithoutValue(t *testing.T) {
	r := newRig(t)
	r.rule(t, Auto, 0, 60, r.wifi)
	r.reveal(r.wifi)
	r.it.items[r.wifi].Notes = "notes-hunter22"
	res := featuretest.Call(r.f, r.h, t0, vault.KindAgent, "agent.request", `{"op":"item.get","item_id":"`+r.wifi+`"}`)
	if !res.OK() || !strings.Contains(string(res.Body), "hunter22") || strings.Contains(string(res.Body), "withheld") {
		t.Fatalf("answer: %q %s", res.Code, res.Body)
	}
	want := `{"item_id":"` + r.wifi + `","name":"wifi","category":"login","fields":[{"field_id":"f1","label":"Password","kind":"password"},` +
		`{"field_id":"f2","label":"Address","kind":"address"}],"withheld":true}`
	if string(res.Cached) != want || !res.SentOnce {
		t.Fatalf("cached:\n%s\nwant\n%s\nsent once %v", res.Cached, want, res.SentOnce)
	}
	if c := r.it.lastRead; len(c) == 0 || !bytes.Equal(c, make([]byte, len(c))) {
		t.Fatalf("the item's content read for the answer was not wiped: %q", c)
	}
}

// A notes-only item (no fields): the copy has no field without a value to
// mark it, so only "withheld" tells it from an item without notes (#15273).
func TestItemGetNotesOnlyCachedWithheld(t *testing.T) {
	r := newRig(t)
	r.rule(t, Auto, 0, 60, r.wifi)
	r.reveal(r.wifi)
	r.it.items[r.wifi].Fields = nil
	r.it.items[r.wifi].Notes = "notes-hunter22"
	res := featuretest.Call(r.f, r.h, t0, vault.KindAgent, "agent.request", `{"op":"item.get","item_id":"`+r.wifi+`"}`)
	if !res.OK() || !strings.Contains(string(res.Body), "notes-hunter22") || strings.Contains(string(res.Body), "withheld") {
		t.Fatalf("answer: %q %s", res.Code, res.Body)
	}
	c := string(res.Cached)
	if strings.Contains(c, "hunter22") || strings.Contains(c, `"notes"`) || !strings.HasSuffix(c, `,"withheld":true}`) {
		t.Fatalf("cached %s", c)
	}
}

// item.run: the cached copy is {item_id, field_id, withheld: true}.
func TestItemRunCachedWithoutValue(t *testing.T) {
	r := newRig(t)
	r.rule(t, Auto, 0, 60, r.wifi)
	r.setRun(r.wifi, 1, false, itemspec.Program{Program: "/usr/bin/git", SHA256: shaA, Path: "/usr/bin/git"})
	res := featuretest.Call(r.f, r.h, t0, vault.KindAgent, "agent.request", runBody(r.wifi, "/usr/bin/git", shaA, ""))
	if !res.OK() || !strings.Contains(string(res.Body), "hunter22") || strings.Contains(string(res.Body), "withheld") {
		t.Fatalf("answer: %q %s", res.Code, res.Body)
	}
	if want := `{"item_id":"` + r.wifi + `","field_id":"f1","withheld":true}`; string(res.Cached) != want || !res.SentOnce {
		t.Fatalf("cached %s, want %s, sent once %v", res.Cached, want, res.SentOnce)
	}
}

// item.run approved after a referral (the pin recorded): the cached copy is
// still {item_id, field_id, withheld: true}.
func TestItemRunApprovedCachedWithoutValue(t *testing.T) {
	r := newRig(t)
	r.rule(t, Auto, 0, 60, r.wifi)
	r.setRun(r.wifi, 1, false, itemspec.Program{Program: "git"})
	body := runBody(r.wifi, "/usr/bin/git", shaA, "")
	d, held := r.decideS(t0, body)
	if d != vault.AgentAsk {
		t.Fatal(d)
	}
	in := &envelope.Inner{ID: "01JB2Z6V9K3M4N5P6Q7R8S9T0V", Type: "agent.request", TS: t0, Body: json.RawMessage(body)}
	from, _ := r.h.Device(agent)
	s := vault.NewApprovedSession(context.Background(), r.h, from, t0, in, held.HeldApproval().Note)
	res, err := r.f.Handle(context.Background(), s, in)
	if err != nil || !strings.Contains(string(res), "hunter22") || strings.Contains(string(res), "withheld") {
		t.Fatalf("answer: %v %s", err, res)
	}
	if r.stored(r.wifi).Version != 2 {
		t.Fatal("pin not recorded")
	}
	if got, want := string(s.CachedResponseBody()), `{"item_id":"`+r.wifi+`","field_id":"f1","withheld":true}`; got != want || !s.SentOnce() {
		t.Fatalf("cached %s, want %s, sent once %v", got, want, s.SentOnce())
	}
}

// item.proxy: the cached copy is the answer without value, with
// "withheld": true; the live answer has no "withheld".
func TestItemProxyCachedWithoutValue(t *testing.T) {
	r := proxyRig(t)
	body := proxyBody(r.wifi, "f1", "api.example.com", "")
	in := &envelope.Inner{ID: "01JB2Z6V9K3M4N5P6Q7R8S9T0V", Type: "agent.request", TS: t0, Body: json.RawMessage(body)}
	from, _ := r.h.Device(agent)
	s := vault.NewApprovedSession(context.Background(), r.h, from, t0, in, json.RawMessage(heldNote))
	res, err := r.f.Handle(context.Background(), s, in)
	if err != nil || !strings.Contains(string(res), "hunter22") || strings.Contains(string(res), "withheld") {
		t.Fatalf("answer: %v %s", err, res)
	}
	want := `{"item_id":"` + r.wifi + `","field_id":"f1","header":"Authorization","prefix":"Bearer ",` +
		`"host":"api.example.com","expires_at":"2026-10-03T12:15:00.000Z","withheld":true}`
	if got := string(s.CachedResponseBody()); got != want || !s.SentOnce() {
		t.Fatalf("cached %s, want %s, sent once %v", got, want, s.SentOnce())
	}
}

// getCached never returns the answer it cannot read; its copy is then
// {"withheld":true}.
func TestGetCachedMalformed(t *testing.T) {
	for _, in := range []string{`not json`, `{"item_id":"x","fields":"hunter22"}`, `{"item_id":"x","fields":["hunter22"]}`} {
		if got := string(getCached([]byte(in))); got != `{"withheld":true}` {
			t.Fatalf("%s: %s", in, got)
		}
	}
}

// item.get approved after its referral (as runHeld runs it): the cached
// copy has no value and no notes.
func TestItemGetApprovedCachedWithoutValue(t *testing.T) {
	r := newRig(t)
	r.rule(t, Auto, 0, 60, r.wifi)
	r.reveal(r.wifi)
	r.it.items[r.wifi].Notes = "notes-hunter22"
	body := `{"op":"item.get","item_id":"` + r.wifi + `"}`
	d, held := r.decideS(t0, body)
	if d != vault.AgentAsk {
		t.Fatal(d)
	}
	in := &envelope.Inner{ID: "01JB2Z6V9K3M4N5P6Q7R8S9T0V", Type: "agent.request", TS: t0, Body: json.RawMessage(body)}
	from, _ := r.h.Device(agent)
	s := vault.NewApprovedSession(context.Background(), r.h, from, t0, in, held.HeldApproval().Note)
	res, err := r.f.Handle(context.Background(), s, in)
	if err != nil || !strings.Contains(string(res), "hunter22") || strings.Contains(string(res), "withheld") {
		t.Fatalf("answer: %v %s", err, res)
	}
	c := string(s.CachedResponseBody())
	if c == "" || strings.Contains(c, "hunter22") || strings.Contains(c, `"value"`) || strings.Contains(c, `"notes"`) ||
		!strings.Contains(c, `"item_id":"`+r.wifi+`"`) || !strings.HasSuffix(c, `,"withheld":true}`) || !s.SentOnce() {
		t.Fatalf("cached %s, sent once %v", c, s.SentOnce())
	}
}

// A value op whose handler set no copy is cached as {"withheld":true}; one
// that did keeps its copy; other ops are cached as answered.
func TestCacheNoValueBackstop(t *testing.T) {
	r := newRig(t)
	from, _ := r.h.Device(agent)
	for _, op := range []string{"item.get", "item.run", "item.proxy"} {
		s := vault.NewSession(context.Background(), r.h, from, t0, nil)
		cacheNoValue(s, op)
		if got := string(s.CachedResponseBody()); got != `{"withheld":true}` || !s.SentOnce() {
			t.Fatalf("%s: cached %q, sent once %v", op, got, s.SentOnce())
		}
		s = vault.NewSession(context.Background(), r.h, from, t0, nil)
		s.CacheResponseAs(json.RawMessage(`{"item_id":"x"}`))
		cacheNoValue(s, op)
		if got := string(s.CachedResponseBody()); got != `{"item_id":"x"}` || !s.SentOnce() {
			t.Fatalf("%s: copy replaced: %q, sent once %v", op, got, s.SentOnce())
		}
	}
	for _, op := range []string{"catalog", "item.use"} {
		s := vault.NewSession(context.Background(), r.h, from, t0, nil)
		cacheNoValue(s, op)
		if s.CachedResponseBody() != nil || s.SentOnce() {
			t.Fatalf("%s: cached %s, sent once %v", op, s.CachedResponseBody(), s.SentOnce())
		}
	}
}

// Through Handle: a value op answered without a copy (answerFor stands in
// for a handler that forgot it) is cached as {"withheld":true}, never as
// the answer.
func TestCacheNoValueThroughHandle(t *testing.T) {
	r := newRig(t)
	r.rule(t, Auto, 0, 60, r.wifi)
	r.reveal(r.wifi)
	r.f.answerFor = func(*vault.Session, *Request) (json.RawMessage, error) {
		return json.RawMessage(`{"item_id":"x","fields":[{"value":"hunter22"}]}`), nil
	}
	body := `{"op":"item.get","item_id":"` + r.wifi + `"}`
	in := &envelope.Inner{ID: "01JB2Z6V9K3M4N5P6Q7R8S9T0V", Type: "agent.request", TS: t0, Body: json.RawMessage(body)}
	from, _ := r.h.Device(agent)
	s := vault.NewApprovedSession(context.Background(), r.h, from, t0, in, nil)
	res, err := r.f.Handle(context.Background(), s, in)
	if err != nil || !strings.Contains(string(res), "hunter22") || strings.Contains(string(res), "withheld") {
		t.Fatalf("answer: %v %s", err, res)
	}
	if got := string(s.CachedResponseBody()); got != `{"withheld":true}` || !s.SentOnce() {
		t.Fatalf("cached %q, sent once %v", got, s.SentOnce())
	}
}
