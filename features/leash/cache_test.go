package leash

import (
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
// without their values, and no notes.
func TestItemGetCachedWithoutValue(t *testing.T) {
	r := newRig(t)
	r.rule(t, Auto, 0, 60, r.wifi)
	r.reveal(r.wifi)
	r.it.items[r.wifi].Notes = "notes-hunter22"
	res := featuretest.Call(r.f, r.h, t0, vault.KindAgent, "agent.request", `{"op":"item.get","item_id":"`+r.wifi+`"}`)
	if !res.OK() || !strings.Contains(string(res.Body), "hunter22") {
		t.Fatalf("answer: %q %s", res.Code, res.Body)
	}
	want := `{"item_id":"` + r.wifi + `","name":"wifi","category":"login","fields":[{"field_id":"f1","label":"Password","kind":"password"},` +
		`{"field_id":"f2","label":"Address","kind":"address"}]}`
	if string(res.Cached) != want {
		t.Fatalf("cached:\n%s\nwant\n%s", res.Cached, want)
	}
}

// item.run: the cached copy is {item_id, field_id}.
func TestItemRunCachedWithoutValue(t *testing.T) {
	r := newRig(t)
	r.rule(t, Auto, 0, 60, r.wifi)
	r.setRun(r.wifi, 1, false, itemspec.Program{Program: "/usr/bin/git", SHA256: shaA, Path: "/usr/bin/git"})
	res := featuretest.Call(r.f, r.h, t0, vault.KindAgent, "agent.request", runBody(r.wifi, "/usr/bin/git", shaA, ""))
	if !res.OK() || !strings.Contains(string(res.Body), "hunter22") {
		t.Fatalf("answer: %q %s", res.Code, res.Body)
	}
	if want := `{"item_id":"` + r.wifi + `","field_id":"f1"}`; string(res.Cached) != want {
		t.Fatalf("cached %s, want %s", res.Cached, want)
	}
}

// item.run approved after a referral (the pin recorded): the cached copy is
// still {item_id, field_id}.
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
	if err != nil || !strings.Contains(string(res), "hunter22") {
		t.Fatalf("answer: %v %s", err, res)
	}
	if r.stored(r.wifi).Version != 2 {
		t.Fatal("pin not recorded")
	}
	if got, want := string(s.CachedResponseBody()), `{"item_id":"`+r.wifi+`","field_id":"f1"}`; got != want {
		t.Fatalf("cached %s, want %s", got, want)
	}
}

// item.proxy: the cached copy is the answer without value.
func TestItemProxyCachedWithoutValue(t *testing.T) {
	r := proxyRig(t)
	body := proxyBody(r.wifi, "f1", "api.example.com", "")
	in := &envelope.Inner{ID: "01JB2Z6V9K3M4N5P6Q7R8S9T0V", Type: "agent.request", TS: t0, Body: json.RawMessage(body)}
	from, _ := r.h.Device(agent)
	s := vault.NewApprovedSession(context.Background(), r.h, from, t0, in, json.RawMessage(heldNote))
	res, err := r.f.Handle(context.Background(), s, in)
	if err != nil || !strings.Contains(string(res), "hunter22") {
		t.Fatalf("answer: %v %s", err, res)
	}
	want := `{"item_id":"` + r.wifi + `","field_id":"f1","header":"Authorization","prefix":"Bearer ",` +
		`"host":"api.example.com","expires_at":"2026-10-03T12:15:00.000Z"}`
	if got := string(s.CachedResponseBody()); got != want {
		t.Fatalf("cached %s, want %s", got, want)
	}
}

// getCached never returns the answer it cannot read.
func TestGetCachedMalformed(t *testing.T) {
	for _, in := range []string{`not json`, `{"item_id":"x","fields":"hunter22"}`, `{"item_id":"x","fields":["hunter22"]}`} {
		if got := string(getCached([]byte(in))); got != `{}` {
			t.Fatalf("%s: %s", in, got)
		}
	}
}
