package grants

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/features/itemspec"
	"github.com/vettid/vettid-vault/internal/featuretest"
	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/sharewire"
	"github.com/vettid/vettid-vault/vms/suite"
)

var t0 = time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)

const (
	s1   = "01JB2Z6V9K3M4N5P6Q7R8S9T01" // a secret item: Wi-Fi (f1 password, f2 SSID)
	s2   = "01JB2Z6V9K3M4N5P6Q7R8S9T02" // a critical item: never readable
	crit = s2
	s3   = "01JB2Z6V9K3M4N5P6Q7R8S9T03" // a data item: Phone (category contact)
)

// fakeItems is the items feature as grants sees it (§10.12).
type fakeItems struct {
	items  map[string]*itemspec.Item
	usable map[string][]itemspec.Meta // by connection
}

func (f *fakeItems) Readable(id string, fields []string) (itemspec.Meta, bool) {
	it := f.items[id]
	if it == nil || it.Sensitivity == itemspec.Critical || !it.HasFields(fields) {
		return itemspec.Meta{}, false
	}
	return itemspec.MetaOf(it, fields), true
}

func (f *fakeItems) Content(id string, fields []string) ([]byte, bool) {
	if _, ok := f.Readable(id, fields); !ok {
		return nil, false
	}
	return f.items[id].Content(fields), true
}

func (f *fakeItems) HasCategory(c string) bool {
	for _, it := range f.items {
		if it.Category == c && it.Sensitivity != itemspec.Critical {
			return true
		}
	}
	return false
}

func (f *fakeItems) Usable(conn string, _ time.Time) []itemspec.Meta { return f.usable[conn] }

func newItems() *fakeItems {
	fl := func(id, label, kind, v string) itemspec.Field {
		return itemspec.Field{ID: id, Label: label, Kind: kind, Value: json.RawMessage(strictjson.MarshalString(v))}
	}
	return &fakeItems{items: map[string]*itemspec.Item{
		s1: {ID: s1, Version: 1, Name: "Wi-Fi", Category: "login", Sensitivity: itemspec.Secret, Tags: []string{"zz-home"},
			Fields: []itemspec.Field{fl("f1", "Password", "password", "hunter22"), fl("f2", "SSID", "text", "net")}},
		s2: {ID: s2, Version: 1, Name: "Signer", Category: "crypto_wallet", Sensitivity: itemspec.Critical,
			Fields: []itemspec.Field{{ID: "f1", Label: "Seed", Kind: "password"}}},
		s3: {ID: s3, Version: 1, Name: "Phone", Category: "contact", Sensitivity: itemspec.Data, Notes: "mobile",
			Fields: []itemspec.Field{fl("f1", "Number", "phone", "+1 555 0100")}},
	}, usable: map[string][]itemspec.Meta{}}
}

type side struct {
	f  *Feature
	h  *featuretest.Host
	it *fakeItems
}

// pair returns the member A (connection "cB" is B) and the asker B
// (connection "cA" is A), each with an app and a desktop.
func pair() (a, b *side) {
	mk := func(conn string) *side {
		s := &side{h: featuretest.NewHost(), it: newItems()}
		s.f = New(s.it)
		s.h.Conns[conn] = vault.PeerInfo{ID: conn, Kind: vault.KindConnection, State: vault.PeerActive}
		s.h.AddDevice("dev-app", vault.KindApp)
		s.h.AddDevice("dev-desktop", vault.KindDesktop)
		return s
	}
	a, b = mk("cB"), mk("cA")
	return a, b
}

func call(t *testing.T, s *side, now time.Time, kind, typ, body string) featuretest.Result {
	t.Helper()
	return featuretest.Call(s.f, s.h, now, kind, typ, body)
}

func ok(t *testing.T, r featuretest.Result) strictjson.Object {
	t.Helper()
	if !r.OK() {
		t.Fatalf("error %s", r.Code)
	}
	return r.Obj(t)
}

func last(t *testing.T, h *featuretest.Host, typ string) featuretest.Sent {
	t.Helper()
	s := h.SentOfType(typ)
	if len(s) == 0 {
		t.Fatalf("no %s in %+v", typ, h.Sent)
	}
	return s[len(s)-1]
}

// relay delivers the last message of typ that from sent to its peer.
func relay(t *testing.T, from, to *side, now time.Time, typ string) {
	t.Helper()
	m := last(t, from.h, typ)
	peer := "cA"
	if m.To == "cA" {
		peer = "cB"
	}
	r := call(t, to, now, "connection:"+peer, typ, string(m.Body))
	if !r.OK() {
		t.Fatalf("%s: %s", typ, r.Code)
	}
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

// share runs a request of the phone item, s1's password field and the
// critical s2, and its approval; it returns the request id.
func share(t *testing.T, a, b *side, decide string) string {
	t.Helper()
	r := ok(t, call(t, b, t0, "app", "grant.request", `{"connection_id":"cA","items":[{"kind":"item","ref":"`+s3+`","label":"phone"},`+
		`{"kind":"item","ref":"`+s1+`","fields":["f1"]},{"kind":"item","ref":"`+s2+`"}],"uses":2,"reason":"dinner"}`))
	rid, _ := r.String("request_id")
	relay(t, b, a, t0, "data.request")
	p := last(t, a.h, "grant.pending")
	if p.To != "devices" || !strings.Contains(string(p.Body), `"available":false`) || !strings.Contains(string(p.Body), `"reason":"dinner"`) {
		t.Fatalf("pending: %s", p.Body)
	}
	if !a.h.HasActivity("grant.request") || !a.h.HasActivity("grant.requested") {
		t.Fatal("feed/audit of the request")
	}
	ok(t, call(t, a, t0, "app", "grant.decide", strings.Replace(decide, "RID", rid, 1)))
	return rid
}

// received returns the grant id of the item ref in the last grant.event.
func received(t *testing.T, b *side, ref string) string {
	t.Helper()
	ev := last(t, b.h, "grant.event")
	var e struct {
		Grants []struct {
			ID  string `json:"grant_id"`
			Ref string `json:"ref"`
		} `json:"grants"`
	}
	if err := json.Unmarshal(ev.Body, &e); err != nil {
		t.Fatal(err)
	}
	for _, g := range e.Grants {
		if g.Ref == ref {
			return g.ID
		}
	}
	t.Fatalf("no grant of %s in %s", ref, ev.Body)
	return ""
}

// fetch fetches a grant from B's app and returns the content or the error.
func fetch(t *testing.T, a, b *side, now time.Time, gid string) (string, string) {
	t.Helper()
	k, err := suite.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	defer k.Destroy()
	fr := ok(t, call(t, b, now, "app", "grant.fetch", `{"grant_id":"`+gid+`","reply_key":"`+base64.StdEncoding.EncodeToString(k.Public().Bytes())+`"}`))
	fid, _ := fr.String("fetch_id")
	relay(t, b, a, now, "data.fetch")
	relay(t, a, b, now, "data.value")
	v := last(t, b.h, "grant.value")
	if v.To != "dev-app" || str(t, v.Body, "fetch_id") != fid {
		t.Fatalf("grant.value: %+v", v)
	}
	if e := str(t, v.Body, "error"); e != "" {
		return "", e
	}
	o, _ := strictjson.ParseObject(v.Body)
	sealed, _ := o.Base64("value_sealed", -1)
	pt, err := sharewire.OpenValue(k, gid, fid, sealed)
	if err != nil {
		t.Fatal(err)
	}
	return string(pt), ""
}

func TestShareFetchRevoke(t *testing.T) {
	a, b := pair()
	share(t, a, b, `{"request_id":"RID","approve":true}`)
	if !a.h.HasActivity("grant.issued") {
		t.Fatal("grant.issued")
	}
	relay(t, a, b, t0, "data.decided")
	ev := last(t, b.h, "grant.event")
	if str(t, ev.Body, "event") != "granted" {
		t.Fatalf("event: %s", ev.Body)
	}
	if strings.Contains(string(ev.Body), s2) {
		t.Fatal("a critical item was granted")
	}
	// The descriptor names the item, its category and the granted fields'
	// labels; never its tags or values.
	dec := string(last(t, a.h, "data.decided").Body)
	if !strings.Contains(dec, `"name":"Wi-Fi"`) || !strings.Contains(dec, `"label":"Password"`) || strings.Contains(dec, "SSID") ||
		strings.Contains(dec, "zz-home") || strings.Contains(dec, "hunter22") {
		t.Fatalf("descriptor: %s", dec)
	}
	sid := received(t, b, s1)
	fid := received(t, b, s3)
	v, e := fetch(t, a, b, t0, sid)
	if e != "" || !strings.Contains(v, "hunter22") || strings.Contains(v, `"net"`) || strings.Contains(v, "zz-home") {
		t.Fatalf("fetch: %q %q", v, e)
	}
	// The data.value went to B's vault sealed: the plaintext is nowhere in
	// what B's vault handled.
	for _, m := range b.h.Sent {
		if strings.Contains(string(m.Body), "hunter22") {
			t.Fatalf("plaintext at the asking vault: %+v", m)
		}
	}
	// A repeated data.fetch (same fetch_id) is answered again, uncounted.
	before := a.f.Given()
	relay(t, b, a, t0, "data.fetch")
	if after := a.f.Given(); after[0].Used+after[1].Used != before[0].Used+before[1].Used {
		t.Fatal("a repeated fetch counted a use")
	}
	if v, _ := fetch(t, a, b, t0, fid); !strings.Contains(v, "+1 555 0100") || !strings.Contains(v, `"notes":"mobile"`) {
		t.Fatalf("whole item: %q", v)
	}
	// uses = 2: the third fetch of the secret is exhausted.
	fetch(t, a, b, t0, sid)
	if _, e := fetch(t, a, b, t0, sid); e != ErrExhausted {
		t.Fatalf("exhausted: %q", e)
	}
	// A revokes the phone grant; B is told and later fetches are refused.
	ok(t, call(t, a, t0, "desktop", "grant.revoke", `{"grant_id":"`+fid+`"}`))
	relay(t, a, b, t0, "data.revoked")
	if ev := last(t, b.h, "grant.event"); str(t, ev.Body, "event") != "revoked" || str(t, ev.Body, "grant_id") != fid {
		t.Fatalf("revoked event: %s", ev.Body)
	}
	if _, e := fetch(t, a, b, t0, fid); e != ErrRevoked {
		t.Fatalf("after revoke: %q", e)
	}
	l := ok(t, call(t, b, t0, "app", "grant.list", `{}`))
	if !strings.Contains(string(l["received"]), `"state":"revoked"`) || !strings.Contains(string(l["requested"]), `"state":"granted"`) {
		t.Fatalf("list: %s", l["received"])
	}
	// Revoking again is a no-op; an unknown grant is not_found.
	ok(t, call(t, a, t0, "app", "grant.revoke", `{"grant_id":"`+fid+`"}`))
	if r := call(t, a, t0, "app", "grant.revoke", `{"grant_id":"`+s1+`"}`); r.Code != "not_found" {
		t.Fatalf("unknown revoke: %s", r.Code)
	}
}

func TestDenyPartialAndUnavailable(t *testing.T) {
	a, b := pair()
	share(t, a, b, `{"request_id":"RID","approve":false}`)
	relay(t, a, b, t0, "data.decided")
	if ev := last(t, b.h, "grant.event"); str(t, ev.Body, "event") != "denied" {
		t.Fatal("denied event")
	}
	if !a.h.HasActivity("grant.denied") || len(a.h.SentOfType("sync.event")) == 0 {
		t.Fatal("denial audit/sync")
	}
	// Partial: only item 1 (the Wi-Fi password), with other uses.
	a, b = pair()
	share(t, a, b, `{"request_id":"RID","approve":true,"items":[1],"uses":5,"expires_in":3600}`)
	g := a.f.Given()
	if len(g) != 1 || g[0].Ref != s1 || g[0].Uses != 5 || !g[0].Expires.Equal(t0.Add(time.Hour)) || len(g[0].Fields) != 1 {
		t.Fatalf("partial: %+v", g)
	}
	// Only unavailable items (a critical item, a missing field): bad_request,
	// and the request stays.
	a, b = pair()
	ok(t, call(t, b, t0, "app", "grant.request", `{"connection_id":"cA","items":[{"kind":"item","ref":"`+s2+`"},{"kind":"item","ref":"`+s1+`","fields":["f9"]}]}`))
	relay(t, b, a, t0, "data.request")
	rid := str(t, last(t, a.h, "grant.pending").Body, "request_id")
	if r := call(t, a, t0, "app", "grant.decide", `{"request_id":"`+rid+`","approve":true}`); r.Code != "bad_request" {
		t.Fatalf("none available: %s", r.Code)
	}
	if r := call(t, a, t0, "app", "grant.decide", `{"request_id":"`+rid+`","approve":true,"items":[3]}`); r.Code != "bad_request" {
		t.Fatalf("index out of range: %s", r.Code)
	}
	// An item deleted (or made critical) after the grant: unavailable.
	a, b = pair()
	share(t, a, b, `{"request_id":"RID","approve":true}`)
	relay(t, a, b, t0, "data.decided")
	sid := received(t, b, s1)
	a.it.items[s1].Sensitivity = itemspec.Critical
	if _, e := fetch(t, a, b, t0, sid); e != ErrUnavailable {
		t.Fatalf("now critical: %q", e)
	}
}

// §10.12: a request by category is answered with the member's item.
func TestCategoryAnswer(t *testing.T) {
	a, b := pair()
	ok(t, call(t, b, t0, "app", "grant.request", `{"connection_id":"cA","items":[{"kind":"category","ref":"contact","label":"your phone"},`+
		`{"kind":"category","ref":"vehicle"}]}`))
	relay(t, b, a, t0, "data.request")
	p := string(last(t, a.h, "grant.pending").Body)
	if !strings.Contains(p, `{"kind":"category","ref":"contact","label":"your phone","available":true}`) ||
		!strings.Contains(p, `{"kind":"category","ref":"vehicle","available":false}`) {
		t.Fatalf("pending: %s", p)
	}
	rid := str(t, p2b(p), "request_id")
	// A category entry without an answer grants nothing.
	if r := call(t, a, t0, "app", "grant.decide", `{"request_id":"`+rid+`","approve":true}`); r.Code != "bad_request" {
		t.Fatalf("no answer: %s", r.Code)
	}
	if r := call(t, a, t0, "app", "grant.decide", `{"request_id":"`+rid+`","approve":true,"answers":[{"index":5,"item_id":"`+s3+`"}]}`); r.Code != "bad_request" {
		t.Fatalf("answer out of range: %s", r.Code)
	}
	ok(t, call(t, a, t0, "app", "grant.decide", `{"request_id":"`+rid+`","approve":true,"answers":[{"index":0,"item_id":"`+s3+`"}]}`))
	relay(t, a, b, t0, "data.decided")
	gid := received(t, b, s3)
	if v, _ := fetch(t, a, b, t0, gid); !strings.Contains(v, "+1 555 0100") {
		t.Fatalf("answered item: %q", v)
	}
}

func p2b(s string) []byte { return []byte(s) }

// §10.12: grants from share rules: data.shared, no use limit or expiry
// unless the rule has one, revocation when the item is withdrawn.
func TestRuleGrants(t *testing.T) {
	a, b := pair()
	s := vault.NewSession(context.TODO(), a.h, vault.PeerInfo{}, t0, nil)
	m, _ := a.it.Readable(s1, nil)
	rule := "01JB2Z6V9K3M4N5P6Q7R8S9T09"
	ids, err := a.f.IssueRuleGrants(s, "cB", rule, []itemspec.Meta{m}, 0, time.Time{})
	if err != nil || len(ids) != 1 {
		t.Fatal(err)
	}
	sh := last(t, a.h, "data.shared")
	if sh.To != "cB" || strings.Contains(string(sh.Body), "uses") || strings.Contains(string(sh.Body), "expires_at") ||
		!strings.Contains(string(sh.Body), `"rule_id":"`+rule+`"`) || strings.Contains(string(sh.Body), "zz-home") {
		t.Fatalf("data.shared: %s", sh.Body)
	}
	relay(t, a, b, t0, "data.shared")
	ev := last(t, b.h, "grant.event")
	if str(t, ev.Body, "event") != "shared" || !b.h.HasActivity("grant.shared") {
		t.Fatalf("shared event: %s", ev.Body)
	}
	// A repeated data.shared is dropped.
	b.h.Reset()
	relay(t, a, b, t0, "data.shared")
	if len(b.h.SentOfType("grant.event")) != 0 {
		t.Fatal("repeated data.shared announced")
	}
	// Fetched many times: not counted against a limit, no uses_left.
	for i := 0; i < 5; i++ {
		if v, e := fetch(t, a, b, t0, ids[0]); e != "" || !strings.Contains(v, "hunter22") {
			t.Fatalf("fetch %d: %q", i, e)
		}
	}
	if strings.Contains(string(last(t, a.h, "data.value").Body), "uses_left") {
		t.Fatal("uses_left for an uncounted grant")
	}
	// The catalog lists it, and the usable critical item, for cB only.
	a.it.usable["cB"] = []itemspec.Meta{itemspec.MetaOf(a.it.items[s2], nil)}
	r := ok(t, call(t, b, t0, "app", "grant.catalog", `{"connection_id":"cA"}`))
	_ = r
	relay(t, b, a, t0, "data.catalog.get")
	c := string(last(t, a.h, "data.catalog").Body)
	if !strings.Contains(c, `"grant_id":"`+ids[0]+`"`) || !strings.Contains(c, `"item_id":"`+s2+`"`) || !strings.Contains(c, `"usable":true`) ||
		strings.Contains(c, "hunter22") || strings.Contains(c, "zz-home") {
		t.Fatalf("catalog: %s", c)
	}
	relay(t, a, b, t0, "data.catalog")
	if res := last(t, b.h, "grant.catalog.result"); !strings.Contains(string(res.Body), ids[0]) {
		t.Fatalf("catalog result: %s", res.Body)
	}
	// Withdrawn: revoked, the connection told.
	a.f.RevokeRuleGrant(s, ids[0])
	relay(t, a, b, t0, "data.revoked")
	if _, e := fetch(t, a, b, t0, ids[0]); e != ErrRevoked {
		t.Fatalf("after withdrawal: %q", e)
	}
	if a.f.GivenRoom() != MaxGiven {
		t.Fatal("room")
	}
}

func TestAuthorization(t *testing.T) {
	a, _ := pair()
	for _, ty := range []string{"grant.request", "grant.decide", "grant.revoke", "grant.list", "grant.fetch", "grant.catalog"} {
		if r := call(t, a, t0, "agent", ty, `{}`); r.Code != "forbidden" {
			t.Errorf("agent %s: %s", ty, r.Code)
		}
		if r := call(t, a, t0, "connection:cB", ty, `{}`); r.Code != "forbidden" {
			t.Errorf("connection %s: %s", ty, r.Code)
		}
	}
	for _, ty := range []string{"data.request", "data.decided", "data.shared", "data.revoked", "data.fetch", "data.value", "data.catalog.get", "data.catalog"} {
		for _, k := range []string{"app", "desktop", "agent"} {
			if r := call(t, a, t0, k, ty, `{}`); r.Code != "forbidden" {
				t.Errorf("%s %s: %s", k, ty, r.Code)
			}
		}
	}
	for _, ts := range a.f.Types() {
		if ts.DesktopApproval != (ts.Type == "grant.decide") {
			t.Errorf("%s step-up %v", ts.Type, ts.DesktopApproval)
		}
	}
}

func TestBadBodies(t *testing.T) {
	a, _ := pair()
	it := `{"kind":"item","ref":"` + s1 + `"}`
	bad := map[string][]string{
		"grant.request": {`{}`, `{"connection_id":"cB","items":[]}`, `{"connection_id":"cB","items":[{"kind":"field","ref":"a"}]}`,
			`{"connection_id":"cB","items":[{"kind":"item","ref":"x"}]}`, `{"connection_id":"cB","items":[{"kind":"other","ref":"a"}]}`,
			`{"connection_id":"cB","items":[{"kind":"category","ref":"Bad"}]}`, `{"connection_id":"cB","items":[{"kind":"category","ref":"a","fields":["f1"]}]}`,
			`{"connection_id":"cB","items":[{"kind":"item","ref":"` + s1 + `","fields":[]}]}`,
			`{"connection_id":"cB","items":[` + it + `],"uses":0}`, `{"connection_id":"cB","items":[` + it + `],"uses":101}`,
			`{"connection_id":"cB","items":[` + it + `],"expires_in":59}`,
			`{"connection_id":"cB","items":[{"kind":"item","ref":"` + s1 + `","label":"` + strings.Repeat("x", 129) + `"}]}`,
			`{"connection_id":"cB","items":[` + it + `],"reason":"` + strings.Repeat("x", 257) + `"}`},
		"grant.decide": {`{}`, `{"request_id":"x","approve":true}`, `{"request_id":"` + s1 + `"}`, `{"request_id":"` + s1 + `","approve":true,"items":[0,0]}`,
			`{"request_id":"` + s1 + `","approve":true,"answers":[{"index":0,"item_id":"x"}]}`,
			`{"request_id":"` + s1 + `","approve":true,"answers":[{"index":0,"item_id":"` + s1 + `"},{"index":0,"item_id":"` + s1 + `"}]}`},
		"grant.fetch":   {`{}`, `{"grant_id":"` + s1 + `","reply_key":"AAAA"}`},
		"grant.revoke":  {`{}`, `{"grant_id":1}`},
		"grant.catalog": {`{}`, `{"connection_id":""}`},
		"grant.list":    {`[]`},
	}
	for ty, bodies := range bad {
		for _, body := range bodies {
			if r := call(t, a, t0, "app", ty, body); r.Code != "bad_request" {
				t.Errorf("%s %s: %s", ty, body, r.Code)
			}
		}
	}
	if r := call(t, a, t0, "app", "grant.request", `{"connection_id":"nope","items":[`+it+`]}`); r.Code != "not_found" {
		t.Errorf("unknown connection: %s", r.Code)
	}
	if r := call(t, a, t0, "app", "grant.decide", `{"request_id":"`+s1+`","approve":true}`); r.Code != "not_found" {
		t.Errorf("unknown request: %s", r.Code)
	}
	// Malformed peer messages are dropped and audited, never answered.
	a.h.Reset()
	for _, ty := range []string{"data.request", "data.decided", "data.shared", "data.fetch", "data.value", "data.catalog", "data.revoked"} {
		ok(t, call(t, a, t0, "connection:cB", ty, `{"request_id":1}`))
	}
	if len(a.h.Sent) != 0 || !a.h.HasActivity("drop.grant_malformed") {
		t.Fatalf("malformed: %+v", a.h.Sent)
	}
}

func TestIdempotencyAndLimits(t *testing.T) {
	a, b := pair()
	ok(t, call(t, b, t0, "app", "grant.request", `{"connection_id":"cA","items":[{"kind":"item","ref":"`+s3+`"}]}`))
	relay(t, b, a, t0, "data.request")
	relay(t, b, a, t0, "data.request") // a repeated request_id is ignored
	if n := len(a.h.SentOfType("grant.pending")); n != 1 {
		t.Fatalf("pending sent %d times", n)
	}
	// The same request_id from another connection is refused.
	a.h.Conns["cC"] = vault.PeerInfo{ID: "cC", Kind: vault.KindConnection, State: vault.PeerActive}
	ok(t, call(t, a, t0, "connection:cC", "data.request", string(last(t, b.h, "data.request").Body)))
	if !a.h.HasActivity("drop.grant_duplicate") {
		t.Fatal("duplicate across connections")
	}
	// At most 16 pending per connection.
	for i := 0; i < MaxPendingPerConn; i++ {
		id, _ := envelope.NewULID(t0.Add(time.Duration(i+1) * time.Second))
		ok(t, call(t, a, t0, "connection:cB", "data.request", `{"request_id":"`+id+`","items":[{"kind":"item","ref":"`+s3+`"}],"uses":1,"expires_in":60}`))
	}
	if !a.h.HasActivity("drop.grant_limit") {
		t.Fatal("pending limit")
	}
	// A decided message for an unknown request or from another connection
	// is dropped; a second decision is ignored.
	b.h.Reset()
	rid := str(t, last(t, a.h, "grant.pending").Body, "request_id")
	ok(t, call(t, b, t0, "connection:cA", "data.decided", `{"request_id":"`+rid+`","approved":false}`))
	if len(b.h.Sent) != 0 {
		t.Fatal("unknown decision acted on")
	}
}

func TestExpiry(t *testing.T) {
	a, b := pair()
	ok(t, call(t, b, t0, "app", "grant.request", `{"connection_id":"cA","items":[{"kind":"item","ref":"`+s3+`"}],"expires_in":60}`))
	relay(t, b, a, t0, "data.request")
	// Undecided for 7 days: answered as denied.
	late := t0.Add(PendingTTL + time.Second)
	ok(t, call(t, a, late, "app", "grant.list", `{}`))
	d := last(t, a.h, "data.decided")
	if !strings.Contains(string(d.Body), `"approved":false`) {
		t.Fatalf("expired pending: %s", d.Body)
	}
	// A grant past expires_at answers expired.
	a, b = pair()
	share(t, a, b, `{"request_id":"RID","approve":true,"expires_in":60}`)
	relay(t, a, b, t0, "data.decided")
	sid := received(t, b, s1)
	if _, e := fetch(t, a, b, t0.Add(2*time.Minute), sid); e != ErrExpired {
		t.Fatalf("expired grant: %q", e)
	}
	// A fetch not answered within 10 minutes is forgotten.
	k, _ := suite.GeneratePrivateKey()
	defer k.Destroy()
	ok(t, call(t, b, t0, "app", "grant.fetch", `{"grant_id":"`+sid+`","reply_key":"`+base64.StdEncoding.EncodeToString(k.Public().Bytes())+`"}`))
	relay(t, b, a, t0, "data.fetch")
	b.h.Reset()
	ok(t, call(t, b, t0.Add(11*time.Minute), "connection:cA", "data.value", string(last(t, a.h, "data.value").Body)))
	if len(b.h.SentOfType("grant.value")) != 0 {
		t.Fatal("late value forwarded")
	}
}

func TestRelinquishAndRemoval(t *testing.T) {
	a, b := pair()
	share(t, a, b, `{"request_id":"RID","approve":true}`)
	relay(t, a, b, t0, "data.decided")
	sid := received(t, b, s1)
	// B gives the grant up: A is told and stops answering.
	ok(t, call(t, b, t0, "app", "grant.revoke", `{"grant_id":"`+sid+`"}`))
	relay(t, b, a, t0, "data.revoked")
	for _, g := range a.f.Given() {
		if g.ID == sid && g.State != StateRevoked {
			t.Fatalf("relinquished: %+v", g)
		}
	}
	if !a.h.HasActivity("grant.revoked") {
		t.Fatal("revocation audit")
	}
	// Removing the connection drops everything of it, without notice.
	a.h.Reset()
	a.f.ConnectionRemoved(nil, "cB")
	b.f.ConnectionRemoved(nil, "cA")
	if len(a.h.Sent) != 0 || len(a.f.Given()) != 0 {
		t.Fatal("removal")
	}
	l := ok(t, call(t, b, t0, "app", "grant.list", `{}`))
	if string(l["received"]) != "[]" || string(l["requested"]) != "[]" {
		t.Fatalf("after removal: %s", l["received"])
	}
	// A data.revoked from another connection does nothing.
	a, _ = pair()
	ok(t, call(t, a, t0, "connection:cB", "data.revoked", `{"grant_id":"`+s1+`"}`))
}

// Each connection sees only its own catalog (§10.12).
func TestCatalog(t *testing.T) {
	a, b := pair()
	share(t, a, b, `{"request_id":"RID","approve":true}`)
	a.h.Conns["cC"] = vault.PeerInfo{ID: "cC", Kind: vault.KindConnection, State: vault.PeerActive}
	r := ok(t, call(t, b, t0, "desktop", "grant.catalog", `{"connection_id":"cA"}`))
	rid, _ := r.String("request_id")
	relay(t, b, a, t0, "data.catalog.get")
	body := string(last(t, a.h, "data.catalog").Body)
	if !strings.Contains(body, s1) || !strings.Contains(body, s3) || strings.Contains(body, s2) || strings.Contains(body, "hunter22") ||
		!strings.Contains(body, `"uses_left":2`) || strings.Contains(body, "SSID") {
		t.Fatalf("catalog: %s", body)
	}
	relay(t, a, b, t0, "data.catalog")
	res := last(t, b.h, "grant.catalog.result")
	if res.To != "dev-desktop" || str(t, res.Body, "request_id") != rid || !strings.Contains(string(res.Body), s1) {
		t.Fatalf("result: %+v", res)
	}
	// Another connection's catalog is empty.
	rq, _ := envelope.NewULID(t0)
	ok(t, call(t, a, t0, "connection:cC", "data.catalog.get", `{"request_id":"`+rq+`"}`))
	if c := last(t, a.h, "data.catalog"); c.To != "cC" || !strings.Contains(string(c.Body), `"items":[]`) {
		t.Fatalf("cC catalog: %s", c.Body)
	}
	// A second answer is dropped.
	b.h.Reset()
	relay(t, a, b, t0, "data.catalog")
	if len(b.h.Sent) != 0 {
		t.Fatal("repeated catalog forwarded")
	}
}

func TestRoundTrip(t *testing.T) {
	a, b := pair()
	share(t, a, b, `{"request_id":"RID","approve":true}`)
	relay(t, a, b, t0, "data.decided")
	g := New(a.it)
	featuretest.RoundTrip(t, a.f, g)
	a.f = g
	sid := received(t, b, s1)
	if v, _ := fetch(t, a, b, t0, sid); !strings.Contains(v, "hunter22") {
		t.Fatal("after reload")
	}
}

func FuzzParseRequest(f *testing.F) {
	f.Add([]byte(`{"connection_id":"c","items":[{"kind":"item","ref":"` + s1 + `","fields":["f1"],"label":"x"},{"kind":"category","ref":"contact"}],"uses":2,"expires_in":60,"reason":"r"}`))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = ParseRequest(b) })
}

func FuzzParseDataRequest(f *testing.F) {
	f.Add([]byte(`{"request_id":"` + s1 + `","items":[{"kind":"item","ref":"` + s1 + `"}],"uses":1,"expires_in":60}`))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = ParseDataRequest(b) })
}

func FuzzParseDecide(f *testing.F) {
	f.Add([]byte(`{"request_id":"` + s1 + `","approve":true,"items":[0,2],"answers":[{"index":1,"item_id":"` + s3 + `","fields":["f1"]}],"uses":3,"expires_in":600}`))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = ParseDecide(b) })
}

const descSeed = `{"grant_id":"` + s2 + `","kind":"item","ref":"` + s1 + `","fields":["f1"],"name":"n","category":"login",` +
	`"labels":[{"field_id":"f1","label":"L","kind":"password"}],"uses":1,"expires_at":"2026-10-03T12:00:00.000Z"}`

func FuzzParseDecided(f *testing.F) {
	f.Add([]byte(`{"request_id":"` + s1 + `","approved":true,"grants":[` + descSeed + `]}`))
	f.Add([]byte(`{"request_id":"` + s1 + `","approved":false}`))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = ParseDecided(b) })
}

func FuzzParseShared(f *testing.F) {
	f.Add([]byte(`{"grants":[` + descSeed + `]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		ds, err := ParseShared(b)
		if err != nil {
			return
		}
		for i := range ds {
			if _, err := ParseDescriptor(ds[i].JSON()); err != nil {
				t.Fatalf("re-encoded descriptor does not parse: %v", err)
			}
		}
	})
}

func FuzzParseFetch(f *testing.F) {
	k, _ := suite.GeneratePrivateKey()
	f.Add([]byte(`{"fetch_id":"` + s1 + `","grant_id":"` + s2 + `","reply_key":"` + base64.StdEncoding.EncodeToString(k.Public().Bytes()) + `"}`))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = ParseFetch(b) })
}

func FuzzParseValue(f *testing.F) {
	f.Add([]byte(`{"fetch_id":"` + s1 + `","grant_id":"` + s2 + `","error":"revoked"}`))
	f.Add([]byte(`{"fetch_id":"` + s1 + `","grant_id":"` + s2 + `","value_sealed":"` + base64.StdEncoding.EncodeToString(make([]byte, 1140)) + `","uses_left":0}`))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = ParseValue(b) })
}

func FuzzParseCatalog(f *testing.F) {
	f.Add([]byte(`{"request_id":"` + s1 + `","items":[{"item_id":"` + s2 + `","name":"n","category":"c","labels":[],"grant_id":"` + s3 + `","uses_left":1},` +
		`{"item_id":"` + s3 + `","name":"n","category":"c","labels":[],"usable":true}],"truncated":true}`))
	f.Fuzz(func(t *testing.T, b []byte) { _, _, _, _ = ParseCatalog(b) })
}

// FuzzPeerMessage feeds arbitrary bodies of every peer type to a vault
// with a pending request and a grant (no panics, no answers to garbage).
func FuzzPeerMessage(f *testing.F) {
	for _, ty := range []string{"data.request", "data.decided", "data.shared", "data.revoked", "data.fetch", "data.value", "data.catalog.get", "data.catalog"} {
		f.Add(ty, []byte(`{"request_id":"`+s1+`","grant_id":"`+s2+`","fetch_id":"`+s1+`"}`))
	}
	f.Fuzz(func(t *testing.T, ty string, body []byte) {
		a, _ := pair()
		_ = featuretest.Call(a.f, a.h, t0, "connection:cB", ty, string(body))
	})
}
