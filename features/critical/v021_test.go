package critical

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
)

type guard map[string]bool

func (g guard) ItemInUse(id string) bool { return g[id] }

// setupKinds creates the credential and a usable critical item with a
// field of each kind given (f1, f2, ... in order).
func (s *side) setupKinds(fields ...map[string]any) string {
	s.t.Helper()
	if r := s.sealed(s.cred, "app", "credential.create", map[string]any{"password": pw}, nil, false); !r.OK() {
		s.t.Fatalf("create: %s", r.Code)
	}
	item := map[string]any{"name": "Mixed", "fields": fields}
	r := s.sealed(s.items, "app", "item.put", map[string]any{"password": pw, "item": item},
		map[string]any{"sensitivity": "critical", "tags": []string{"signing"}}, true)
	if !r.OK() {
		s.t.Fatalf("item.put: %s", r.Code)
	}
	id, _ := r.Obj(s.t).String("item_id")
	for c := range s.h.Conns {
		b, _ := json.Marshal(map[string]any{"subject": map[string]any{"connection_id": c}, "tags": []string{"signing"}, "mode": "auto"})
		if r := s.call(s.items, "app", "share.rule.set", string(b)); !r.OK() {
			s.t.Fatalf("rule: %s", r.Code)
		}
	}
	return id
}

func (s *side) askField(itemID, fieldID string) string {
	s.t.Helper()
	id := ulid(s.clk.T.Add(time.Hour + time.Duration(len(s.h.Sent))*time.Millisecond))
	b, _ := json.Marshal(map[string]any{"request_id": id, "item_id": itemID, "field_id": fieldID, "operation": "sign",
		"payload": b64.EncodeToString([]byte("p"))})
	if r := s.call(s.f, "connection:conn-b", "critical-secret.use", string(b)); !r.OK() {
		s.t.Fatalf("incoming: %s", r.Code)
	}
	return id
}

// §10.13 (0.21.0): a field is suitable only if it is a password, text or
// multiline field of an item that is not a wallet's; any other is
// answered unsuitable at once, without the member and without the
// credential, audited, and not shown (no .pending, no feed item, not in
// .list); .pending, .list and .get carry the kind.
func TestSuitability(t *testing.T) {
	clk := newClock()
	a := newSide(t, clk, 0x0a)
	a.h.AddConnection("conn-b")
	g := guard{}
	a.items.SetGuard(g)
	seed := b64.EncodeToString(bytes.Repeat([]byte{0x21}, 32))
	sid := a.setupKinds(
		map[string]any{"label": "Seed", "kind": "password", "value": seed},            // f1
		map[string]any{"label": "Count", "kind": "number", "value": "42"},             // f2
		map[string]any{"label": "Home", "kind": "address", "value": map[string]any{}}, // f3
		map[string]any{"label": "Words", "kind": "multiline", "value": "not a seed"},  // f4
		map[string]any{"label": "Code", "kind": "otp", "value": "JBSWY3DPEHPK3PXP"},   // f5
		map[string]any{"label": "Name", "kind": "text", "value": seed},                // f6
	)
	version := func() uint64 {
		v, _ := a.call(a.cred, "app", "credential.version", `{}`).Obj(t).Uint("version", 0, 1<<40)
		return v
	}
	v0 := version()
	for _, fid := range []string{"f2", "f3", "f5"} {
		a.h.Reset()
		id := a.askField(sid, fid)
		res := a.h.SentOfType("critical-secret.result")
		if len(res) != 1 || field(t, res[0].Body, "status") != StatusUnsuitable || field(t, res[0].Body, "request_id") != id {
			t.Fatalf("%s: %+v", fid, res)
		}
		if len(a.h.SentOfType("critical-secret-use.pending")) != 0 || len(a.f.Pending()) != 0 {
			t.Fatalf("%s shown to the member", fid)
		}
		for _, act := range a.h.Activities {
			if act.Feed {
				t.Fatalf("%s: a feed item %+v", fid, act)
			}
		}
		if !a.h.HasActivity("critical-secret.use.requested") || !a.h.HasActivity("critical-secret.use.denied") {
			t.Fatalf("%s not audited: %+v", fid, a.h.Activities)
		}
		if r := a.call(a.f, "app", "critical-secret-use.get", `{"request_id":"`+id+`"}`); r.Code != "not_found" {
			t.Fatalf("%s get: %q", fid, r.Code)
		}
		// A repeated request id stays answered.
		a.h.Reset()
		b, _ := json.Marshal(map[string]any{"request_id": id, "item_id": sid, "field_id": fid, "operation": "sign", "payload": "cA=="})
		a.call(a.f, "connection:conn-b", "critical-secret.use", string(b))
		if len(a.h.Sent) != 0 {
			t.Fatalf("%s answered twice", fid)
		}
	}
	if version() != v0 {
		t.Fatal("the credential was opened for an unsuitable field")
	}
	if l := a.call(a.f, "app", "critical-secret-use.list", `{}`).Obj(t); string(l["incoming"]) != "[]" {
		t.Fatalf("listed: %s", l["incoming"])
	}
	// Suitable kinds are asked, with their kind.
	for fid, kind := range map[string]string{"f1": "password", "f4": "multiline", "f6": "text"} {
		a.h.Reset()
		id := a.askField(sid, fid)
		p := a.h.SentOfType("critical-secret-use.pending")
		if len(p) != 1 || field(t, p[0].Body, "kind") != kind {
			t.Fatalf("%s pending: %+v", fid, p)
		}
		if g := a.call(a.f, "app", "critical-secret-use.get", `{"request_id":"`+id+`"}`); field(t, g.Body, "kind") != kind {
			t.Fatalf("%s get: %s", fid, g.Body)
		}
	}
	l := a.call(a.f, "desktop", "critical-secret-use.list", `{}`).Obj(t)
	in, _ := l.Array("incoming")
	if len(in) != 3 {
		t.Fatalf("incoming: %s", l["incoming"])
	}
	for _, x := range in {
		if o, _ := strictjson.ParseObject(x); !o.Has("kind") {
			t.Fatalf("no kind: %s", x)
		}
	}
	// A suitable field whose value is not a seed is found at the use.
	var multi string
	for _, id := range a.f.Pending() {
		if bytes.Contains(pendingBody(a.f.d.In[id]), []byte(`"multiline"`)) {
			multi = id
		}
	}
	r := a.approve(multi, []byte("p"), "app")
	if st, _ := r.Obj(t).String("status"); st != StatusUnsuitable || version() == v0 {
		t.Fatalf("multiline: %q", st)
	}
	// A wallet's item: unsuitable at once, even a password field.
	g[sid] = true
	a.h.Reset()
	a.askField(sid, "f1")
	if res := a.h.SentOfType("critical-secret.result"); len(res) != 1 || field(t, res[0].Body, "status") != StatusUnsuitable ||
		len(a.h.SentOfType("critical-secret-use.pending")) != 0 {
		t.Fatalf("wallet item: %+v", res)
	}
	// Not usable stays unavailable (an unknown item is not told apart).
	a.h.Reset()
	a.askField(ulid(clk.T), "f1")
	if field(t, a.h.SentOfType("critical-secret.result")[0].Body, "status") != StatusUnavailable {
		t.Fatal("unknown item")
	}
}

// §10.1, §10.13 (0.21.0): 64 outstanding outgoing requests, then limit
// critical_use_requests.
func TestOutgoingLimit(t *testing.T) {
	clk := newClock()
	b := newSide(t, clk, 0x0b)
	b.h.AddConnection("conn-a")
	req := `{"connection_id":"conn-a","item_id":"` + ulid(clk.T) + `","field_id":"f1","operation":"sign","payload":"cA=="}`
	for i := 0; i < MaxOutgoing; i++ {
		if r := b.call(b.f, "app", "critical-secret-use.request", req); !r.OK() {
			t.Fatalf("request %d: %s", i, r.Code)
		}
	}
	r := b.call(b.f, "app", "critical-secret-use.request", req)
	if r.Code != "limit" || string(r.Body) != `{"limit":"critical_use_requests","max":64}` {
		t.Fatalf("limit: %q %s", r.Code, r.Body)
	}
}
