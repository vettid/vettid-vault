package actions

import (
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/featuretest"
	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/envelope"
)

var t0 = time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)

// Connection ids: a's record of b is cB, b's record of a is cA.
var (
	cA = "01JB2Z6V9K3M4N5P6Q7R8S9TAA"
	cB = "01JB2Z6V9K3M4N5P6Q7R8S9TBB"
	cC = "01JB2Z6V9K3M4N5P6Q7R8S9TCC"
)

type side struct {
	f   *Feature
	h   *featuretest.Host
	now time.Time
}

func pair() (a, b *side) {
	a = &side{f: New(), h: featuretest.NewHost(), now: t0}
	b = &side{f: New(), h: featuretest.NewHost(), now: t0}
	a.h.Conns[cB] = vault.PeerInfo{ID: cB, Kind: vault.KindConnection, State: vault.PeerActive}
	a.h.Conns[cC] = vault.PeerInfo{ID: cC, Kind: vault.KindConnection, State: vault.PeerActive}
	b.h.Conns[cA] = vault.PeerInfo{ID: cA, Kind: vault.KindConnection, State: vault.PeerActive}
	return a, b
}

func (x *side) call(kind, typ, body string) featuretest.Result {
	x.now = x.now.Add(time.Millisecond)
	return featuretest.Call(x.f, x.h, x.now, kind, typ, body)
}

func (x *side) ok(t *testing.T, kind, typ, body string) strictjson.Object {
	t.Helper()
	r := x.call(kind, typ, body)
	if !r.OK() {
		t.Fatalf("%s %s: %s", typ, body, r.Code)
	}
	return r.Obj(t)
}

// deliver passes what from queued for the connection `to` (its id on
// from's side) to `dst`, as from's connection id `as` on dst's side.
func deliver(t *testing.T, from *side, to string, dst *side, as string) {
	t.Helper()
	sent := from.h.Sent
	from.h.Sent = nil
	for _, s := range sent {
		if s.To != to {
			from.h.Sent = append(from.h.Sent, s)
			continue
		}
		r := dst.call("connection:"+as, s.Type, string(s.Body))
		if !r.OK() {
			t.Fatalf("deliver %s: %s", s.Type, r.Code)
		}
	}
}

func str(t *testing.T, raw []byte, k string) string {
	t.Helper()
	o, err := strictjson.ParseObject(raw)
	if err != nil {
		t.Fatal(err)
	}
	v, err := o.String(k)
	if err != nil {
		t.Fatalf("no %s in %s", k, raw)
	}
	return v
}

func lastSent(t *testing.T, h *featuretest.Host, typ string) featuretest.Sent {
	t.Helper()
	s := h.SentOfType(typ)
	if len(s) == 0 {
		t.Fatalf("no %s sent: %+v", typ, h.Sent)
	}
	return s[len(s)-1]
}

func define(t *testing.T, a *side, body string) string {
	t.Helper()
	o := a.ok(t, vault.KindApp, "action.define", body)
	id, _ := o.String("action_id")
	return id
}

func TestAuthorization(t *testing.T) {
	a, _ := pair()
	f := a.f
	specs := map[string]vault.TypeSpec{}
	for _, ts := range f.Types() {
		specs[ts.Type] = ts
	}
	if !specs["action.define"].DesktopApproval {
		t.Fatal("action.define must be a desktop step-up type")
	}
	for _, typ := range []string{"action.delete", "action.list", "action.respond", "action.invoke"} {
		if specs[typ].DesktopApproval {
			t.Errorf("%s is not step-up", typ)
		}
	}
	for typ, ts := range specs {
		if ts.Allows(vault.KindAgent) {
			t.Errorf("%s listed for agents (only via LEASH)", typ)
		}
	}
	cases := []struct{ kind, typ string }{
		{vault.KindAgent, "action.define"}, {vault.KindAgent, "action.invoke"}, {vault.KindAgent, "action.list"},
		{"connection:" + cB, "action.define"}, {"connection:" + cB, "action.respond"}, {"connection:" + cB, "action.list"},
		{vault.KindApp, "action.offered"}, {vault.KindDesktop, "action.result"}, {vault.KindApp, "action.invocation"},
		{"connection:" + cB, "action.invoke"},
	}
	for _, c := range cases {
		if r := a.call(c.kind, c.typ, `{}`); r.Code != "forbidden" {
			t.Errorf("%s from %s: %q", c.typ, c.kind, r.Code)
		}
	}
	if r := a.call(vault.KindDesktop, "action.list", `{}`); !r.OK() {
		t.Fatalf("desktop list: %s", r.Code)
	}
}

func TestDefineReplaceDelete(t *testing.T) {
	a, _ := pair()
	id := define(t, a, `{"name":"Pay me","kind":"fixed","mode":"auto","result":{"address":"bc1q"},"connections":["`+cB+`"]}`)
	off := lastSent(t, a.h, "action.offered")
	if off.To != cB || !strings.Contains(string(off.Body), id) || !strings.Contains(string(off.Body), `"name":"Pay me"`) {
		t.Fatalf("offer: %+v", off)
	}
	if strings.Contains(string(off.Body), "bc1q") {
		t.Fatal("the offer reveals the fixed result")
	}
	// The receiving vault keeps the list and tells its owner's devices.
	_, b := pair()
	if r := b.call("connection:"+cA, "action.offered", string(off.Body)); !r.OK() {
		t.Fatal(r.Code)
	}
	if se := b.h.SentOfType("sync.event"); len(se) != 1 || !strings.Contains(string(se[0].Body), `"kind":"action.offers"`) ||
		!strings.Contains(string(se[0].Body), cA) {
		t.Fatalf("offers sync: %+v", se)
	}
	if r := b.call(vault.KindApp, "action.list", `{"connection_id":"`+cA+`"}`); !r.OK() || !strings.Contains(string(r.Body), id) {
		t.Fatalf("offered list: %s %s", r.Code, r.Body)
	}
	if !a.h.HasActivity("action.defined") || len(a.h.SentOfType("sync.event")) == 0 {
		t.Fatal("audit or sync missing")
	}
	// Replace: version required and checked.
	if r := a.call(vault.KindApp, "action.define", `{"action_id":"`+id+`","name":"x","kind":"respond","connections":[]}`); r.Code != "bad_request" {
		t.Fatalf("replace without version: %q", r.Code)
	}
	if r := a.call(vault.KindApp, "action.define", `{"action_id":"`+id+`","version":7,"name":"x","kind":"respond","connections":[]}`); r.Code != "conflict" {
		t.Fatalf("stale version: %q", r.Code)
	}
	a.h.Reset()
	o := a.ok(t, vault.KindApp, "action.define", `{"action_id":"`+id+`","version":1,"name":"Ask me","kind":"respond","connections":["`+cC+`"]}`)
	if v, _ := o.Uint("version", 0, 10); v != 2 {
		t.Fatalf("version %d", v)
	}
	// Both the connection that lost the action and the one that gained it
	// are told their complete lists.
	offs := a.h.SentOfType("action.offered")
	if len(offs) != 2 {
		t.Fatalf("offers: %+v", offs)
	}
	for _, s := range offs {
		switch s.To {
		case cB:
			if string(s.Body) != `{"actions":[]}` {
				t.Fatalf("cB: %s", s.Body)
			}
		case cC:
			if !strings.Contains(string(s.Body), id) {
				t.Fatalf("cC: %s", s.Body)
			}
		default:
			t.Fatalf("offer to %s", s.To)
		}
	}
	l := a.ok(t, vault.KindApp, "action.list", `{}`)
	if !strings.Contains(string(l["actions"]), `"name":"Ask me"`) {
		t.Fatalf("list: %s", l["actions"])
	}
	a.h.Reset()
	a.ok(t, vault.KindApp, "action.delete", `{"action_id":"`+id+`"}`)
	if s := lastSent(t, a.h, "action.offered"); s.To != cC || string(s.Body) != `{"actions":[]}` {
		t.Fatalf("after delete: %+v", s)
	}
	if r := a.call(vault.KindApp, "action.delete", `{"action_id":"`+id+`"}`); r.Code != "not_found" {
		t.Fatalf("delete twice: %q", r.Code)
	}
	// Limit.
	for i := 0; i < MaxActions; i++ {
		define(t, a, `{"name":"n","kind":"respond","connections":[]}`)
	}
	if r := a.call(vault.KindApp, "action.define", `{"name":"n","kind":"respond","connections":[]}`); r.Code != "limit" {
		t.Fatalf("limit: %q", r.Code)
	}
}

func TestBadBodies(t *testing.T) {
	a, _ := pair()
	for _, b := range []string{
		`{}`,
		`{"name":"","kind":"respond","connections":[]}`,
		`{"name":"` + strings.Repeat("n", MaxName+1) + `","kind":"respond","connections":[]}`,
		`{"name":"n","kind":"other","connections":[]}`,
		`{"name":"n","kind":"respond","mode":"auto","connections":[]}`,
		`{"name":"n","kind":"respond","result":{},"connections":[]}`,
		`{"name":"n","kind":"fixed","connections":[]}`,
		`{"name":"n","kind":"fixed","result":[1],"connections":[]}`,
		`{"name":"n","kind":"fixed","result":{"a":"` + strings.Repeat("x", MaxResult) + `"},"connections":[]}`,
		`{"name":"n","kind":"respond"}`,
		`{"name":"n","kind":"respond","connections":["nope"]}`,
		`{"name":"n","kind":"respond","connections":["` + cB + `","` + cB + `"]}`,
		`{"name":"n","kind":"respond","connections":[],"name":"dup"}`,
		`{"version":1,"name":"n","kind":"respond","connections":[]}`,
	} {
		if r := a.call(vault.KindApp, "action.define", b); r.Code != "bad_request" {
			t.Errorf("define %s: %q", b, r.Code)
		}
	}
	for typ, b := range map[string]string{
		"action.invoke":  `{"connection_id":"` + cB + `","action_id":"x"}`,
		"action.respond": `{"invocation_id":"` + cB + `","approve":false,"result":{}}`,
		"action.list":    `{"connection_id":""}`,
		"action.delete":  `{"action_id":1}`,
	} {
		if r := a.call(vault.KindApp, typ, b); r.Code != "bad_request" {
			t.Errorf("%s %s: %q", typ, b, r.Code)
		}
	}
	if r := a.call(vault.KindApp, "action.invoke", `{"connection_id":"`+cB+`","action_id":"`+cA+`","params":{"a":"`+strings.Repeat("p", MaxParams)+`"}}`); r.Code != "bad_request" {
		t.Errorf("oversized params: %q", r.Code)
	}
}

// setup: a offers b a respond action and a fixed auto action; b receives
// the offers.
func setup(t *testing.T) (a, b *side, respond, fixed string) {
	a, b = pair()
	respond = define(t, a, `{"name":"Lunch?","kind":"respond","connections":["`+cB+`"]}`)
	fixed = define(t, a, `{"name":"Address","description":"where to send","kind":"fixed","mode":"auto","result":{"addr":"1 Main St"},"connections":["`+cB+`"]}`)
	deliver(t, a, cB, b, cA)
	l := b.ok(t, vault.KindApp, "action.list", `{"connection_id":"`+cA+`"}`)
	if !strings.Contains(string(l["actions"]), respond) || !strings.Contains(string(l["actions"]), `"description":"where to send"`) {
		t.Fatalf("offers on b: %s", l["actions"])
	}
	return a, b, respond, fixed
}

func TestInvokeRespond(t *testing.T) {
	a, b, respond, _ := setup(t)
	inv := b.ok(t, vault.KindDesktop, "action.invoke", `{"connection_id":"`+cA+`","action_id":"`+respond+`","params":{"when":"noon"}}`)
	iid, _ := inv.String("invocation_id")
	if !b.h.HasActivity("action.invoked") {
		t.Fatal("invoker audit")
	}
	deliver(t, b, cA, a, cB)
	p := lastSent(t, a.h, "action.pending")
	if p.To != "devices" || str(t, p.Body, "invocation_id") != iid || str(t, p.Body, "connection_id") != cB ||
		!strings.Contains(string(p.Body), `"params":{"when":"noon"}`) || str(t, p.Body, "kind") != KindRespond {
		t.Fatalf("pending: %+v", p)
	}
	if !a.h.HasActivity("action.request") || !a.h.HasActivity("action.invoked") {
		t.Fatal("feed or audit missing")
	}
	// Approving a respond action needs a result.
	if r := a.call(vault.KindApp, "action.respond", `{"invocation_id":"`+iid+`","approve":true}`); r.Code != "bad_request" {
		t.Fatalf("approve without result: %q", r.Code)
	}
	a.ok(t, vault.KindDesktop, "action.respond", `{"invocation_id":"`+iid+`","approve":true,"result":{"answer":"yes"}}`)
	if r := a.call(vault.KindApp, "action.respond", `{"invocation_id":"`+iid+`","approve":false}`); r.Code != "not_found" {
		t.Fatalf("answered twice: %q", r.Code)
	}
	deliver(t, a, cB, b, cA)
	res := lastSent(t, b.h, "action.result")
	if res.To != "devices" || str(t, res.Body, "status") != StatusOK || str(t, res.Body, "action_id") != respond ||
		!strings.Contains(string(res.Body), `"result":{"answer":"yes"}`) {
		t.Fatalf("result: %+v", res)
	}
	if !b.h.HasActivity("action.completed") {
		t.Fatal("completed audit")
	}
	// A late repeat of the result is dropped.
	b.h.Reset()
	b.ok(t, "connection:"+cA, "action.result", `{"invocation_id":"`+iid+`","status":"denied"}`)
	if len(b.h.SentOfType("action.result")) != 0 {
		t.Fatal("late result forwarded")
	}
	// A result from another connection for this id is dropped too.
	inv2 := b.ok(t, vault.KindApp, "action.invoke", `{"connection_id":"`+cA+`","action_id":"`+respond+`"}`)
	iid2, _ := inv2.String("invocation_id")
	b.h.Conns[cC] = vault.PeerInfo{ID: cC, Kind: vault.KindConnection, State: vault.PeerActive}
	b.h.Reset()
	b.ok(t, "connection:"+cC, "action.result", `{"invocation_id":"`+iid2+`","status":"denied"}`)
	if len(b.h.SentOfType("action.result")) != 0 {
		t.Fatal("another connection answered")
	}
}

func TestDenyAndFixedAsk(t *testing.T) {
	a, b, respond, _ := setup(t)
	ask := define(t, a, `{"name":"Code","kind":"fixed","result":{"code":"1234"},"connections":["`+cB+`"]}`)
	deliver(t, a, cB, b, cA)
	for _, tc := range []struct {
		action, body, status, want string
	}{
		{respond, `"approve":false`, StatusDenied, ""},
		{ask, `"approve":true`, StatusOK, `"result":{"code":"1234"}`},
	} {
		inv := b.ok(t, vault.KindApp, "action.invoke", `{"connection_id":"`+cA+`","action_id":"`+tc.action+`"}`)
		iid, _ := inv.String("invocation_id")
		deliver(t, b, cA, a, cB)
		if tc.action == ask {
			if r := a.call(vault.KindApp, "action.respond", `{"invocation_id":"`+iid+`","approve":true,"result":{}}`); r.Code != "bad_request" {
				t.Fatalf("fixed with a result: %q", r.Code)
			}
		}
		a.ok(t, vault.KindApp, "action.respond", `{"invocation_id":"`+iid+`",`+tc.body+`}`)
		deliver(t, a, cB, b, cA)
		res := lastSent(t, b.h, "action.result")
		if str(t, res.Body, "status") != tc.status || !strings.Contains(string(res.Body), tc.want) {
			t.Fatalf("%s: %s", tc.status, res.Body)
		}
	}
	if !a.h.HasActivity("action.denied") || !a.h.HasActivity("action.approved") {
		t.Fatal("decision audit")
	}
}

func TestFixedAutoAndUnavailable(t *testing.T) {
	a, b, _, fixed := setup(t)
	inv := b.ok(t, vault.KindApp, "action.invoke", `{"connection_id":"`+cA+`","action_id":"`+fixed+`"}`)
	iid, _ := inv.String("invocation_id")
	deliver(t, b, cA, a, cB)
	if len(a.h.SentOfType("action.pending")) != 0 {
		t.Fatal("auto action asked the member")
	}
	deliver(t, a, cB, b, cA)
	res := lastSent(t, b.h, "action.result")
	if str(t, res.Body, "invocation_id") != iid || !strings.Contains(string(res.Body), `"result":{"addr":"1 Main St"}`) {
		t.Fatalf("auto result: %s", res.Body)
	}
	// B invoking something not offered: not_found locally.
	if r := b.call(vault.KindApp, "action.invoke", `{"connection_id":"`+cA+`","action_id":"`+cC+`"}`); r.Code != "not_found" {
		t.Fatalf("not offered: %q", r.Code)
	}
	if r := b.call(vault.KindApp, "action.invoke", `{"connection_id":"`+cC+`","action_id":"`+fixed+`"}`); r.Code != "not_found" {
		t.Fatalf("unknown connection: %q", r.Code)
	}
	// On the answering side: unknown action, not allowlisted, other
	// version, all `unavailable`.
	newID := func() string {
		id, _ := envelope.NewULID(a.now.Add(time.Second))
		a.now = a.now.Add(time.Second)
		return id
	}
	for _, c := range []struct{ from, body string }{
		{cB, `"action_id":"` + cA + `","version":1`},
		{cC, `"action_id":"` + fixed + `","version":1`},
		{cB, `"action_id":"` + fixed + `","version":2`},
	} {
		a.h.Reset()
		id := newID()
		a.ok(t, "connection:"+c.from, "action.invocation", `{"invocation_id":"`+id+`",`+c.body+`}`)
		s := lastSent(t, a.h, "action.result")
		if s.To != c.from || string(s.Body) != `{"invocation_id":"`+id+`","status":"unavailable"}` {
			t.Fatalf("%s: %+v", c.body, s)
		}
	}
}

func TestPendingLimitExpiryIdempotency(t *testing.T) {
	a, _, respond, _ := setup(t)
	var ids []string
	for i := 0; i < MaxPending+1; i++ {
		a.now = a.now.Add(time.Second)
		id, _ := envelope.NewULID(a.now)
		ids = append(ids, id)
		a.h.Reset()
		a.ok(t, "connection:"+cB, "action.invocation", `{"invocation_id":"`+id+`","action_id":"`+respond+`","version":1,"params":{"i":1}}`)
	}
	if s := lastSent(t, a.h, "action.result"); str(t, s.Body, "status") != StatusUnavailable {
		t.Fatalf("9th pending: %s", s.Body)
	}
	if n := len(a.f.PendingInvocations()); n != MaxPending {
		t.Fatalf("pending %d", n)
	}
	// A repeated invocation_id is ignored (no second pending, no answer).
	a.h.Reset()
	a.ok(t, "connection:"+cB, "action.invocation", `{"invocation_id":"`+ids[0]+`","action_id":"`+respond+`","version":1}`)
	if len(a.h.Sent) != 0 {
		t.Fatalf("repeat handled: %+v", a.h.Sent)
	}
	// State survives a flush and unlock.
	g := New()
	featuretest.RoundTrip(t, a.f, g)
	a.f = g
	// After 24 h every pending invocation is answered `expired`.
	a.now = a.now.Add(PendingTTL)
	a.h.Reset()
	a.ok(t, vault.KindApp, "action.list", `{}`)
	exp := a.h.SentOfType("action.result")
	if len(exp) != MaxPending {
		t.Fatalf("expired answers: %d", len(exp))
	}
	for _, s := range exp {
		if str(t, s.Body, "status") != StatusExpired {
			t.Fatalf("%s", s.Body)
		}
	}
	if r := a.call(vault.KindApp, "action.respond", `{"invocation_id":"`+ids[0]+`","approve":false}`); r.Code != "not_found" {
		t.Fatalf("respond after expiry: %q", r.Code)
	}
}

func TestDeleteAnswersPending(t *testing.T) {
	a, _, respond, _ := setup(t)
	id, _ := envelope.NewULID(a.now)
	a.ok(t, "connection:"+cB, "action.invocation", `{"invocation_id":"`+id+`","action_id":"`+respond+`","version":1}`)
	a.h.Reset()
	a.ok(t, vault.KindApp, "action.delete", `{"action_id":"`+respond+`"}`)
	var got bool
	for _, s := range a.h.SentOfType("action.result") {
		got = got || s.To == cB && str(t, s.Body, "status") == StatusUnavailable
	}
	if !got {
		t.Fatalf("pending invocation not answered: %+v", a.h.Sent)
	}
}

func TestConnectionRemoved(t *testing.T) {
	a, b, respond, _ := setup(t)
	id, _ := envelope.NewULID(a.now)
	a.ok(t, "connection:"+cB, "action.invocation", `{"invocation_id":"`+id+`","action_id":"`+respond+`","version":1}`)
	a.f.ConnectionRemoved(nil, cB)
	if len(a.f.PendingInvocations()) != 0 {
		t.Fatal("pending kept")
	}
	l := a.ok(t, vault.KindApp, "action.list", `{}`)
	if strings.Contains(string(l["actions"]), cB) {
		t.Fatalf("allowlist kept: %s", l["actions"])
	}
	b.ok(t, vault.KindApp, "action.invoke", `{"connection_id":"`+cA+`","action_id":"`+respond+`"}`)
	b.f.ConnectionRemoved(nil, cA)
	lb := b.ok(t, vault.KindApp, "action.list", `{"connection_id":"`+cA+`"}`)
	if string(lb["actions"]) != `[]` {
		t.Fatalf("offers kept: %s", lb["actions"])
	}
}

func FuzzParseDefine(f *testing.F) {
	f.Add([]byte(`{"name":"n","kind":"fixed","mode":"auto","result":{"a":1},"connections":["01JB2Z6V9K3M4N5P6Q7R8S9TBB"]}`))
	f.Add([]byte(`{"action_id":"01JB2Z6V9K3M4N5P6Q7R8S9TBB","version":2,"name":"n","kind":"respond","connections":[]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		d, err := ParseDefine(b)
		if err == nil && (d.Name == "" || d.Kind == KindRespond && d.Mode != ModeAsk || d.Kind == KindFixed && d.Result == nil) {
			t.Fatal("accepted an invalid definition")
		}
	})
}

func FuzzParseInvoke(f *testing.F) {
	f.Add([]byte(`{"connection_id":"c","action_id":"01JB2Z6V9K3M4N5P6Q7R8S9TBB","params":{"x":[1]}}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if v, err := ParseInvoke(b); err == nil && len(v.Params) > MaxParams {
			t.Fatal("params too large")
		}
	})
}

func FuzzParsePeerInvoke(f *testing.F) {
	f.Add([]byte(`{"invocation_id":"01JB2Z6V9K3M4N5P6Q7R8S9TAA","action_id":"01JB2Z6V9K3M4N5P6Q7R8S9TBB","version":1}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if v, err := ParsePeerInvoke(b); err == nil && (v.Version == 0 || !envelope.ValidULID(v.InvocationID)) {
			t.Fatal("accepted an invalid invocation")
		}
	})
}

func FuzzParseRespond(f *testing.F) {
	f.Add([]byte(`{"invocation_id":"01JB2Z6V9K3M4N5P6Q7R8S9TAA","approve":true,"result":{"a":"b"}}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if r, err := ParseRespond(b); err == nil && !r.Approve && r.Result != nil {
			t.Fatal("denial with a result")
		}
	})
}

func FuzzParseResult(f *testing.F) {
	f.Add([]byte(`{"invocation_id":"01JB2Z6V9K3M4N5P6Q7R8S9TAA","status":"ok","result":{}}`))
	f.Add([]byte(`{"invocation_id":"01JB2Z6V9K3M4N5P6Q7R8S9TAA","status":"expired"}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if r, err := ParseResult(b); err == nil && (r.Status == StatusOK) != (r.Result != nil) {
			t.Fatal("status and result disagree")
		}
	})
}

func FuzzParseOffered(f *testing.F) {
	f.Add([]byte(`{"actions":[{"action_id":"01JB2Z6V9K3M4N5P6Q7R8S9TAA","version":1,"name":"n","description":"d"}]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if l, err := ParseOffered(b); err == nil && len(l) > MaxOffers {
			t.Fatal("too many offers")
		}
	})
}

// §10.14: a pending invocation is answered `unavailable` when its action
// is no longer offered to that connection.
func TestRedefineDropsPending(t *testing.T) {
	a, b, respond, _ := setup(t)
	inv := b.ok(t, vault.KindApp, "action.invoke", `{"connection_id":"`+cA+`","action_id":"`+respond+`"}`)
	iid, _ := inv.String("invocation_id")
	deliver(t, b, cA, a, cB)
	a.h.Reset()
	a.ok(t, vault.KindApp, "action.define", `{"action_id":"`+respond+`","version":1,"name":"Lunch?","kind":"respond","connections":["`+cC+`"]}`)
	var got bool
	for _, s := range a.h.SentOfType("action.result") {
		if s.To == cB && str(t, s.Body, "invocation_id") == iid && str(t, s.Body, "status") == StatusUnavailable {
			got = true
		}
	}
	if !got {
		t.Fatalf("pending not answered: %+v", a.h.Sent)
	}
	if r := a.call(vault.KindApp, "action.respond", `{"invocation_id":"`+iid+`","approve":false}`); r.Code != "not_found" {
		t.Fatalf("still pending: %q", r.Code)
	}
}
