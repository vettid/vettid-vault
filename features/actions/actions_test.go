package actions

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/features/audit"
	"github.com/vettid/vettid-vault/features/grants"
	"github.com/vettid/vettid-vault/features/items"
	"github.com/vettid/vettid-vault/internal/featuretest"
	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/sharewire"
	"github.com/vettid/vettid-vault/vms/suite"
)

var t0 = time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)

// Connection ids: on A's side B is cB (and C cC); on B's side A is cA.
const (
	cA = "01JB2Z6V9K3M4N5P6Q7R8S9AAA"
	cB = "01JB2Z6V9K3M4N5P6Q7R8S9BBB"
	cC = "01JB2Z6V9K3M4N5P6Q7R8S9CCC"
)

type window struct{ open bool }

func (w *window) UseKey(time.Time, time.Duration) (ed25519.PrivateKey, bool) {
	if !w.open {
		return nil, false
	}
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32)), true
}

type side struct {
	f   *Feature
	h   *featuretest.Host
	g   *grants.Feature
	au  *audit.Feature
	it  *items.Feature
	w   *window
	now time.Time
}

func newSide() *side {
	x := &side{h: featuretest.NewHost(), it: items.New(nil), au: audit.New(), w: &window{}, now: t0}
	x.g = grants.New(x.it)
	x.it.SetGrants(x.g)
	x.f = New(Deps{Grants: x.g, Audit: x.au, Keys: x.w})
	x.h.Sinks = append(x.h.Sinks, x.au)
	x.h.AddDevice("dev-app", vault.KindApp)
	x.h.AddDevice("dev-desktop", vault.KindDesktop)
	return x
}

// pair returns A (the member offering actions; connections cB and cC) and
// B (invoking; connection cA).
func pair() (a, b *side) {
	a, b = newSide(), newSide()
	for _, c := range []string{cB, cC} {
		a.h.Conns[c] = vault.PeerInfo{ID: c, Kind: vault.KindConnection, State: vault.PeerActive}
	}
	b.h.Conns[cA] = vault.PeerInfo{ID: cA, Kind: vault.KindConnection, State: vault.PeerActive}
	return a, b
}

func (x *side) call(kind, typ, body string) featuretest.Result {
	x.now = x.now.Add(time.Millisecond)
	feat := vault.Feature(x.f)
	if strings.HasPrefix(typ, "grant.") || strings.HasPrefix(typ, "data.") {
		feat = x.g
	}
	if strings.HasPrefix(typ, "item.") {
		feat = x.it
	}
	return featuretest.Call(feat, x.h, x.now, kind, typ, body)
}

func (x *side) ok(t *testing.T, kind, typ, body string) strictjson.Object {
	t.Helper()
	r := x.call(kind, typ, body)
	if !r.OK() {
		t.Fatalf("%s %s: %s", typ, body, r.Code)
	}
	return r.Obj(t)
}

// deliver hands what from sent to connection `to` over to dst, as
// connection `as`.
func deliver(t *testing.T, from *side, to string, dst *side, as string) {
	t.Helper()
	sent := from.h.Sent
	from.h.Sent = nil
	for _, s := range sent {
		if s.To != to {
			from.h.Sent = append(from.h.Sent, s)
			continue
		}
		if r := dst.call("connection:"+as, s.Type, string(s.Body)); !r.OK() {
			t.Fatalf("deliver %s: %s", s.Type, r.Code)
		}
	}
}

func last(t *testing.T, h *featuretest.Host, typ string) featuretest.Sent {
	t.Helper()
	s := h.SentOfType(typ)
	if len(s) == 0 {
		t.Fatalf("no %s in %+v", typ, h.Sent)
	}
	return s[len(s)-1]
}

func str(t *testing.T, raw []byte, k string) string {
	t.Helper()
	o, err := strictjson.ParseObject(raw)
	if err != nil {
		t.Fatal(err)
	}
	v, _ := o.String(k)
	return v
}

// configure sets a mode on A and delivers the offers to B.
func configure(t *testing.T, a, b *side, body string) {
	t.Helper()
	a.ok(t, vault.KindApp, "action.configure", body)
	deliver(t, a, cB, b, cA)
}

// invoke has B invoke an action on A, delivers it, and returns the
// invocation id.
func invoke(t *testing.T, a, b *side, action, params string) string {
	t.Helper()
	o := b.ok(t, vault.KindApp, "action.invoke", `{"connection_id":"`+cA+`","action_id":"`+action+`","params":`+params+`}`)
	id, _ := o.String("invocation_id")
	deliver(t, b, cA, a, cB)
	return id
}

// answer delivers A's result to B and returns B's V→D action.result body.
func answer(t *testing.T, a, b *side) []byte {
	t.Helper()
	b.h.Reset()
	deliver(t, a, cB, b, cA)
	return last(t, b.h, "action.result").Body
}

func TestAuthorization(t *testing.T) {
	a, _ := pair()
	specs := map[string]vault.TypeSpec{}
	for _, ts := range a.f.Types() {
		specs[ts.Type] = ts
	}
	if !specs["action.configure"].DesktopApproval {
		t.Fatal("action.configure must be a desktop step-up type")
	}
	for typ, ts := range specs {
		if ts.Allows(vault.KindAgent) {
			t.Errorf("%s listed for agents (only via LEASH)", typ)
		}
		if ts.Allows(vault.KindConnection) && ts.Request {
			t.Errorf("%s is both a request and a peer type", typ)
		}
	}
	for _, c := range []struct{ kind, typ string }{
		{vault.KindAgent, "action.configure"}, {vault.KindAgent, "action.invoke"}, {vault.KindAgent, "action.list"},
		{"connection:" + cB, "action.configure"}, {"connection:" + cB, "action.respond"}, {"connection:" + cB, "action.list"},
		{"connection:" + cB, "action.invoke"}, {vault.KindApp, "action.offered"}, {vault.KindDesktop, "action.result"},
		{vault.KindApp, "action.invocation"},
	} {
		if r := a.call(c.kind, c.typ, `{}`); r.Code != "forbidden" {
			t.Errorf("%s %s: %q", c.kind, c.typ, r.Code)
		}
	}
}

func TestCatalogAndConfigure(t *testing.T) {
	a, _ := pair()
	l := a.ok(t, vault.KindDesktop, "action.list", `{}`)
	if v, _ := l.Uint("catalog_version", 1, 9); v != CatalogVersion {
		t.Fatal("catalog version")
	}
	arr, _ := l.Array("actions")
	if len(arr) != 4 {
		t.Fatalf("catalog: %d", len(arr))
	}
	for _, d := range Catalog() {
		for _, sc := range []string{d.ParamSchema, d.ResultSchema} {
			if !json.Valid([]byte(sc)) {
				t.Errorf("%s schema not JSON", d.ID)
			}
		}
	}
	if !strings.Contains(string(arr[0]), `"mode":"default-deny"`) {
		t.Fatal("default mode")
	}
	for name, body := range map[string]string{
		"unknown mode":           `{"action_id":"audit.recent","mode":"always"}`,
		"sensitive allow":        `{"action_id":"items.share","mode":"default-allow"}`,
		"critical allow":         `{"action_id":"wallet.request-payment","mode":"default-allow"}`,
		"critical allowlist":     `{"action_id":"wallet.request-payment","mode":"allowlist","connections":["` + cB + `"]}`,
		"items on audit":         `{"action_id":"audit.recent","mode":"allowlist","items":["` + cA + `"]}`,
		"empty items":            `{"action_id":"items.share","mode":"allowlist","items":[]}`,
		"bad item id":            `{"action_id":"items.share","mode":"allowlist","items":["x"]}`,
		"dup connection":         `{"action_id":"audit.recent","mode":"allowlist","connections":["` + cB + `","` + cB + `"]}`,
		"bad connection":         `{"action_id":"audit.recent","mode":"allowlist","connections":["x"]}`,
		"no mode":                `{"action_id":"audit.recent"}`,
		"duplicate member names": `{"action_id":"audit.recent","mode":"allowlist","mode":"default-deny"}`,
	} {
		if r := a.call(vault.KindApp, "action.configure", body); r.Code != "bad_request" {
			t.Errorf("%s: %q", name, r.Code)
		}
	}
	for _, id := range []string{"vote.delegate-proxy", "secrets.share", "profile.fields.read"} { // the last two: catalog version 1
		if r := a.call(vault.KindApp, "action.configure", `{"action_id":"`+id+`","mode":"default-deny"}`); r.Code != "not_found" {
			t.Fatalf("%s not in the catalog: %q", id, r.Code)
		}
	}
	o := a.ok(t, vault.KindApp, "action.configure", `{"action_id":"audit.recent","mode":"allowlist","connections":["`+cB+`"]}`)
	if v, _ := o.Uint("version", 1, 9); v != 1 {
		t.Fatal("first version")
	}
	if r := a.call(vault.KindApp, "action.configure", `{"action_id":"audit.recent","mode":"default-deny","version":0}`); r.Code != "conflict" {
		t.Fatalf("stale version: %q", r.Code)
	}
	a.ok(t, vault.KindApp, "action.configure", `{"action_id":"audit.recent","mode":"default-deny","version":1}`)
	if !a.h.HasActivity("action.configured") {
		t.Fatal("not audited")
	}
	if se := a.h.SentOfType("sync.event"); len(se) == 0 || !strings.Contains(string(se[len(se)-1].Body), `"kind":"action.changed"`) {
		t.Fatal("no sync")
	}
}

// Offers: complete lists to each affected active connection after each
// change and when a connection becomes active; the receiver keeps them.
func TestOffers(t *testing.T) {
	a, b := pair()
	a.ok(t, vault.KindApp, "action.configure", `{"action_id":"audit.recent","mode":"allowlist","connections":["`+cB+`"]}`)
	offs := a.h.SentOfType("action.offered")
	if len(offs) != 1 || offs[0].To != cB || string(offs[0].Body) != `{"actions":[{"action_id":"audit.recent","version":1,"prompt":false}]}` {
		t.Fatalf("offers: %+v", offs)
	}
	a.h.Reset()
	a.ok(t, vault.KindApp, "action.configure", `{"action_id":"items.share","mode":"prompt-each-time"}`)
	if offs := a.h.SentOfType("action.offered"); len(offs) != 2 {
		t.Fatalf("prompt for every connection: %+v", offs)
	}
	deliver(t, a, cB, b, cA)
	if se := b.h.SentOfType("sync.event"); len(se) == 0 || !strings.Contains(string(se[0].Body), `"action.offers"`) {
		t.Fatal("receiver's devices not told")
	}
	l := b.ok(t, vault.KindApp, "action.list", `{"connection_id":"`+cA+`"}`)
	if !strings.Contains(string(l["actions"]), `"items.share"`) || !strings.Contains(string(l["actions"]), `"prompt":true`) {
		t.Fatalf("offers kept: %s", l["actions"])
	}
	// A new connection gets what it is offered.
	a.h.Reset()
	cD := "01JB2Z6V9K3M4N5P6Q7R8S9DDD"
	a.h.Conns[cD] = vault.PeerInfo{ID: cD, Kind: vault.KindConnection, State: vault.PeerActive}
	a.f.ConnectionAdded(vault.NewSession(context.TODO(), a.h, vault.PeerInfo{}, t0, nil), cD)
	if s := last(t, a.h, "action.offered"); s.To != cD || !strings.Contains(string(s.Body), "items.share") {
		t.Fatalf("new connection: %+v", s)
	}
	if r := b.call("connection:"+cA, "action.offered", `{"actions":[{"action_id":"x"}]}`); !r.OK() || !b.h.HasActivity("drop.action_malformed") {
		t.Fatal("malformed offers not dropped and audited")
	}
}

// Each permission mode (§10.14).
func TestModes(t *testing.T) {
	a, b := pair()
	// default-deny: not offered; an invocation anyway is unavailable.
	if r := b.call(vault.KindApp, "action.invoke", `{"connection_id":"`+cA+`","action_id":"audit.recent","params":{}}`); r.Code != "not_found" {
		t.Fatalf("invoke without an offer: %q", r.Code)
	}
	a.ok(t, "connection:"+cB, "action.invocation", `{"invocation_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V","action_id":"audit.recent","version":1,"params":{}}`)
	if s := last(t, a.h, "action.result"); str(t, s.Body, "status") != StatusUnavailable {
		t.Fatalf("default-deny: %s", s.Body)
	}
	// allowlist: runs at once, for listed connections only.
	a.h.Reset()
	a.h.Record(vault.Activity{Kind: "message.received", ConnectionID: cB, Direction: "in", Ref: "m1", Audit: true}, t0)
	a.h.Record(vault.Activity{Kind: "message.received", ConnectionID: cC, Direction: "in", Ref: "m2", Audit: true}, t0)
	a.h.Record(vault.Activity{Kind: "drop.rate_limited", ConnectionID: cB, Audit: true}, t0)
	configure(t, a, b, `{"action_id":"audit.recent","mode":"allowlist","connections":["`+cB+`"]}`)
	invoke(t, a, b, AuditRecent, `{"limit":10}`)
	res := answer(t, a, b)
	if str(t, res, "status") != StatusOK || !strings.Contains(string(res), `"kind":"message.received"`) || strings.Contains(string(res), "m1") ||
		strings.Contains(string(res), "drop.") || strings.Count(string(res), `"kind"`) < 1 {
		t.Fatalf("audit.recent: %s", res)
	}
	if strings.Count(string(res), `"message.received"`) != 1 {
		t.Fatalf("another connection's entries: %s", res)
	}
	if !b.h.HasActivity("action.completed") || !a.h.HasActivity("action.invoked") {
		t.Fatal("audit on both sides")
	}
	// prompt-each-time: held, then approved or denied.
	configure(t, a, b, `{"action_id":"audit.recent","mode":"prompt-each-time","version":1}`)
	id := invoke(t, a, b, AuditRecent, `{}`)
	p := last(t, a.h, "action.pending")
	if p.To != "devices" || str(t, p.Body, "invocation_id") != id || str(t, p.Body, "sensitivity") != Normal || !a.h.HasActivity("action.request") {
		t.Fatalf("pending: %+v", p)
	}
	if len(a.h.SentOfType("action.result")) != 0 {
		t.Fatal("answered before approval")
	}
	o := a.ok(t, vault.KindDesktop, "action.respond", `{"invocation_id":"`+id+`","approve":true}`)
	if st, _ := o.String("status"); st != StatusOK {
		t.Fatalf("approved: %s", st)
	}
	if res := answer(t, a, b); str(t, res, "status") != StatusOK {
		t.Fatalf("approved result: %s", res)
	}
	id = invoke(t, a, b, AuditRecent, `{}`)
	a.ok(t, vault.KindApp, "action.respond", `{"invocation_id":"`+id+`","approve":false}`)
	if res := answer(t, a, b); str(t, res, "status") != StatusDenied || !a.h.HasActivity("action.denied") {
		t.Fatalf("denied: %s", res)
	}
	if r := a.call(vault.KindApp, "action.respond", `{"invocation_id":"`+id+`","approve":true}`); r.Code != "not_found" {
		t.Fatalf("answered twice: %q", r.Code)
	}
	// default-allow: every connection, at once.
	configure(t, a, b, `{"action_id":"audit.recent","mode":"default-allow"}`)
	invoke(t, a, b, AuditRecent, `{}`)
	if res := answer(t, a, b); str(t, res, "status") != StatusOK {
		t.Fatalf("default-allow: %s", res)
	}
}

// items.share makes a one-use grant of a configured, readable item only;
// the invoker fetches the content through grants (§10.14).
func TestSharingThroughGrants(t *testing.T) {
	a, b := pair()
	put := func(sens, name, value string) string {
		r := a.call(vault.KindApp, "item.put", `{"name":"`+name+`","sensitivity":"`+sens+`","tags":["zz-hidden"],`+
			`"fields":[{"label":"Value","kind":"text","value":"`+value+`"},{"label":"Other","kind":"text","value":"other"}]}`)
		id, _ := r.Obj(t).String("item_id")
		return id
	}
	phone := put("data", "Phone", "555")
	wifi := put("secret", "Wi-Fi", "hunter22")
	home := put("data", "Home", "1 Main")
	a.h.Reset()
	configure(t, a, b, `{"action_id":"items.share","mode":"allowlist","connections":["`+cB+`"],"items":["`+phone+`","`+wifi+`"]}`)
	invoke(t, a, b, ItemsShare, `{"item_id":"`+phone+`","fields":["f1"]}`)
	res := answer(t, a, b)
	if str(t, res, "status") != StatusOK || strings.Count(string(res), `"grant_id"`) != 1 || !strings.Contains(string(res), `"ref":"`+phone+`"`) ||
		strings.Contains(string(res), "555") || strings.Contains(string(res), "zz-hidden") || strings.Contains(string(res), "Other") {
		t.Fatalf("items.share: %s", res)
	}
	// B fetches the content through grants, sealed to its device.
	o, _ := strictjson.ParseObject(res)
	r, _ := o.Object("result")
	gs, _ := r.Array("grants")
	gid := str(t, gs[0], "grant_id")
	rk, _ := suite.GeneratePrivateKey()
	defer rk.Destroy()
	b.h.Reset()
	f := b.ok(t, vault.KindApp, "grant.fetch", `{"grant_id":"`+gid+`","reply_key":"`+base64.StdEncoding.EncodeToString(rk.Public().Bytes())+`"}`)
	fid, _ := f.String("fetch_id")
	deliver(t, b, cA, a, cB)
	b.h.Reset()
	deliver(t, a, cB, b, cA)
	gv := last(t, b.h, "grant.value")
	vo, _ := strictjson.ParseObject(gv.Body)
	sealed, err := vo.Base64("value_sealed", -1)
	if err != nil {
		t.Fatalf("grant.value: %s", gv.Body)
	}
	if v, err := sharewire.OpenValue(rk, gid, fid, sealed); err != nil || !strings.Contains(string(v), `"value":"555"`) || strings.Contains(string(v), "Other") {
		t.Fatalf("value: %q %v", v, err)
	}
	// One use only.
	b.ok(t, vault.KindApp, "grant.fetch", `{"grant_id":"`+gid+`","reply_key":"`+base64.StdEncoding.EncodeToString(rk.Public().Bytes())+`"}`)
	deliver(t, b, cA, a, cB)
	b.h.Reset()
	deliver(t, a, cB, b, cA)
	if gv := last(t, b.h, "grant.value"); str(t, gv.Body, "error") != grants.ErrExhausted {
		t.Fatalf("second fetch: %s", gv.Body)
	}
	// An item not configured, or a field it lacks: unavailable.
	invoke(t, a, b, ItemsShare, `{"item_id":"`+home+`"}`)
	if res := answer(t, a, b); str(t, res, "status") != StatusUnavailable {
		t.Fatalf("unconfigured item: %s", res)
	}
	invoke(t, a, b, ItemsShare, `{"item_id":"`+phone+`","fields":["f9"]}`)
	if res := answer(t, a, b); str(t, res, "status") != StatusUnavailable {
		t.Fatalf("missing field: %s", res)
	}
	// prompt-each-time: the member approves; a secret item is shareable too.
	configure(t, a, b, `{"action_id":"items.share","mode":"prompt-each-time","items":["`+wifi+`"]}`)
	id := invoke(t, a, b, ItemsShare, `{"item_id":"`+wifi+`"}`)
	if p := last(t, a.h, "action.pending"); str(t, p.Body, "sensitivity") != Sensitive {
		t.Fatal("sensitivity not shown")
	}
	a.ok(t, vault.KindApp, "action.respond", `{"invocation_id":"`+id+`","approve":true}`)
	if res := answer(t, a, b); str(t, res, "status") != StatusOK || !strings.Contains(string(res), `"kind":"item"`) || strings.Contains(string(res), "hunter22") {
		t.Fatalf("secret item: %s", res)
	}
}

// Critical actions: never default-allow or allowlist; approved only by an
// app within the unlock window; the wallet is not there yet.
func TestCritical(t *testing.T) {
	a, b := pair()
	configure(t, a, b, `{"action_id":"wallet.request-payment","mode":"prompt-each-time"}`)
	id := invoke(t, a, b, WalletPayment, `{"asset":"BTC","amount_sats":1000,"memo":"lunch"}`)
	if p := last(t, a.h, "action.pending"); str(t, p.Body, "sensitivity") != Critical {
		t.Fatal("not critical")
	}
	if r := a.call(vault.KindDesktop, "action.respond", `{"invocation_id":"`+id+`","approve":true}`); r.Code != "forbidden" {
		t.Fatalf("desktop approved: %q", r.Code)
	}
	if r := a.call(vault.KindApp, "action.respond", `{"invocation_id":"`+id+`","approve":true}`); r.Code != "credential_locked" {
		t.Fatalf("outside the window: %q", r.Code)
	}
	if got := a.f.PendingInvocations(); len(got) != 1 {
		t.Fatal("not kept pending")
	}
	a.w.open = true
	o := a.ok(t, vault.KindApp, "action.respond", `{"invocation_id":"`+id+`","approve":true}`)
	if st, _ := o.String("status"); st != StatusUnavailable {
		t.Fatalf("wallet: %s", st)
	}
	if res := answer(t, a, b); str(t, res, "status") != StatusUnavailable {
		t.Fatalf("result: %s", res)
	}
	// Denying a critical action needs neither.
	a.w.open = false
	id = invoke(t, a, b, WalletPayment, `{"asset":"BTC","amount_sats":1}`)
	a.ok(t, vault.KindDesktop, "action.respond", `{"invocation_id":"`+id+`","approve":false}`)
	// Normal wallet action: defined but unavailable.
	configure(t, a, b, `{"action_id":"wallet.request-address","mode":"default-allow"}`)
	invoke(t, a, b, WalletAddress, `{"asset":"BTC"}`)
	if res := answer(t, a, b); str(t, res, "status") != StatusUnavailable {
		t.Fatalf("address: %s", res)
	}
}

// Limits, expiry, idempotency, version and parameter checks.
func TestLimitsExpiryIdempotency(t *testing.T) {
	a, b := pair()
	configure(t, a, b, `{"action_id":"audit.recent","mode":"prompt-each-time"}`)
	inv := func(id, body string) string {
		a.h.Reset()
		a.ok(t, "connection:"+cB, "action.invocation", `{"invocation_id":"`+id+`",`+body+`}`)
		if rs := a.h.SentOfType("action.result"); len(rs) > 0 {
			return str(t, rs[0].Body, "status")
		}
		if len(a.h.SentOfType("action.pending")) > 0 {
			return "pending"
		}
		return "nothing"
	}
	ids := []string{}
	for i := 0; i < MaxPendingPerConn+1; i++ {
		id, _ := envelope.NewULID(t0.Add(time.Duration(i) * time.Second))
		ids = append(ids, id)
	}
	for i := 0; i < MaxPendingPerConn; i++ {
		if got := inv(ids[i], `"action_id":"audit.recent","version":1,"params":{}`); got != "pending" {
			t.Fatalf("invocation %d: %s", i, got)
		}
	}
	if got := inv(ids[MaxPendingPerConn], `"action_id":"audit.recent","version":1,"params":{}`); got != StatusUnavailable {
		t.Fatalf("9th pending: %s", got)
	}
	if got := inv(ids[0], `"action_id":"audit.recent","version":1,"params":{}`); got != "nothing" {
		t.Fatalf("repeat: %s", got)
	}
	for name, body := range map[string]string{
		"other version":  `"action_id":"audit.recent","version":2,"params":{}`,
		"not in catalog": `"action_id":"vote.delegate-proxy","version":1,"params":{}`,
		"not offered":    `"action_id":"items.share","version":1,"params":{"item_id":"` + cA + `"}`,
		"bad params":     `"action_id":"audit.recent","version":1,"params":{"limit":51}`,
		"extra params":   `"action_id":"audit.recent","version":1,"params":{"x":1}`,
		"no params":      `"action_id":"audit.recent","version":1`,
	} {
		id, _ := envelope.NewULID(t0.Add(time.Hour))
		if got := inv(id, body); got != StatusUnavailable {
			t.Errorf("%s: %s", name, got)
		}
	}
	// Expiry after 24 h (lazily, at the next message).
	a.h.Reset()
	a.now = t0.Add(PendingTTL + time.Minute)
	a.ok(t, vault.KindApp, "action.list", `{}`)
	if n := len(a.h.SentOfType("action.result")); n != MaxPendingPerConn {
		t.Fatalf("expired: %d", n)
	}
	for _, s := range a.h.SentOfType("action.result") {
		if str(t, s.Body, "status") != StatusExpired {
			t.Fatalf("status: %s", s.Body)
		}
	}
	// 60 per connection per hour.
	configure(t, a, b, `{"action_id":"audit.recent","mode":"default-allow"}`)
	a.d0()
	var last string
	for i := 0; i < MaxPerHour+1; i++ {
		id, _ := envelope.NewULID(a.now.Add(time.Duration(i) * time.Millisecond))
		last = inv(id, `"action_id":"audit.recent","version":1,"params":{}`)
	}
	if last != StatusUnavailable {
		t.Fatalf("61st in an hour: %s", last)
	}
	// Malformed invocations are dropped and audited.
	a.ok(t, "connection:"+cB, "action.invocation", `{"action_id":"audit.recent"}`)
	if !a.h.HasActivity("drop.action_malformed") {
		t.Fatal("malformed not audited")
	}
	// Results: only for our own invocation, from that connection, once.
	b.h.Reset()
	b.ok(t, "connection:"+cA, "action.result", `{"invocation_id":"`+ids[0]+`","status":"ok","result":{}}`)
	if len(b.h.SentOfType("action.result")) != 0 {
		t.Fatal("unknown result forwarded")
	}
}

// d0 clears the invocation counter history (tests).
func (x *side) d0() { x.f.d.Hits = map[string][]time.Time{} }

func TestBadBodies(t *testing.T) {
	a, _ := pair()
	for typ, body := range map[string]string{
		"action.list":    `{"connection_id":1}`,
		"action.invoke":  `{"connection_id":"` + cB + `"}`,
		"action.respond": `{"invocation_id":"x","approve":true}`,
	} {
		if r := a.call(vault.KindApp, typ, body); r.Code != "bad_request" {
			t.Errorf("%s: %q", typ, r.Code)
		}
	}
	if r := a.call(vault.KindApp, "action.invoke", `{"connection_id":"`+cB+`","action_id":"audit.recent","params":{"a":"`+strings.Repeat("p", MaxParams)+`"}}`); r.Code != "bad_request" {
		t.Fatalf("oversized params: %q", r.Code)
	}
}

func TestConnectionRemovedAndRoundTrip(t *testing.T) {
	a, b := pair()
	configure(t, a, b, `{"action_id":"audit.recent","mode":"prompt-each-time","connections":["`+cB+`","`+cC+`"]}`)
	invoke(t, a, b, AuditRecent, `{}`)
	g := New(Deps{})
	featuretest.RoundTrip(t, a.f, g)
	if len(g.PendingInvocations()) != 1 {
		t.Fatal("state lost in a flush")
	}
	a.f.ConnectionRemoved(nil, cB)
	if len(a.f.PendingInvocations()) != 0 || contains(a.f.d.Configs[AuditRecent].Connections, cB) {
		t.Fatal("removed connection kept")
	}
	b.f.ConnectionRemoved(nil, cA)
	if r := b.call(vault.KindApp, "action.invoke", `{"connection_id":"`+cA+`","action_id":"audit.recent","params":{}}`); r.Code != "not_found" {
		t.Fatalf("offers kept: %q", r.Code)
	}
}

func FuzzParseConfigure(f *testing.F) {
	f.Add([]byte(`{"action_id":"items.share","mode":"allowlist","connections":["01JB2Z6V9K3M4N5P6Q7R8S9BBB"],"items":["01JB2Z6V9K3M4N5P6Q7R8S9BBB"]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		c, err := ParseConfigure(b)
		if err != nil {
			return
		}
		def, _ := Lookup(c.ActionID)
		if c.Mode == ModeAllow && def.Sensitivity != Normal || c.Mode == ModeList && def.Sensitivity == Critical {
			t.Fatalf("accepted %+v", c)
		}
	})
}

func FuzzParseInvoke(f *testing.F) {
	f.Add([]byte(`{"connection_id":"c","action_id":"audit.recent","params":{"limit":3}}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if v, err := ParseInvoke(b); err == nil && len(v.Params) > MaxParams {
			t.Fatal("oversized params")
		}
	})
}

func FuzzParseInvocation(f *testing.F) {
	f.Add([]byte(`{"invocation_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V","action_id":"audit.recent","version":1,"params":{}}`))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = ParseInvocation(b) })
}

func FuzzParseParams(f *testing.F) {
	f.Add(uint8(0), []byte(`{"item_id":"01JB2Z6V9K3M4N5P6Q7R8S9BBB","fields":["f1"]}`))
	f.Add(uint8(3), []byte(`{"asset":"BTC","amount_sats":5,"memo":"x"}`))
	f.Fuzz(func(t *testing.T, i uint8, b []byte) {
		cat := Catalog()
		p, err := ParseParams(cat[int(i)%len(cat)].ID, b)
		if err == nil && (p.Limit > AuditMax || len(p.Memo) > MaxMemo || len(p.Fields) > 64) {
			t.Fatalf("accepted %+v", p)
		}
	})
}

func FuzzParseRespond(f *testing.F) {
	f.Add([]byte(`{"invocation_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V","approve":true}`))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = ParseRespond(b) })
}

func FuzzParseResult(f *testing.F) {
	f.Add([]byte(`{"invocation_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V","status":"ok","result":{"entries":[]}}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if r, err := ParseResult(b); err == nil && r.Status == StatusOK && len(r.Result) == 0 {
			t.Fatal("ok without result")
		}
	})
}

func FuzzParseOffered(f *testing.F) {
	f.Add([]byte(`{"actions":[{"action_id":"audit.recent","version":1,"prompt":false}]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if l, err := ParseOffered(b); err == nil && len(l) > MaxOffers {
			t.Fatal("too many offers")
		}
	})
}

func FuzzDescs(f *testing.F) {
	f.Add([]byte(`{"grants":[{"grant_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V","kind":"item","ref":"01JB2Z6V9K3M4N5P6Q7R8S9T0W","name":"n",` +
		`"category":"c","labels":[{"field_id":"f1","label":"L","kind":"text"}],"uses":1,"expires_at":"2026-10-03T12:00:00.000Z"}]}`))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = Descs(b) })
}
