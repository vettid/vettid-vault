package leash

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/features/itemspec"
	"github.com/vettid/vettid-vault/internal/featuretest"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// WindowOpen is the credential's check that does not extend the window.
func (w *window) WindowOpen(time.Time) bool { return w.open }

// noWindow is a key user that cannot say whether the window is open.
type noWindow struct{ w *window }

func (n noWindow) UseKey(now time.Time, ttl time.Duration) (ed25519.PrivateKey, bool) {
	return n.w.UseKey(now, ttl)
}

func (r *rig) itemSet(body string) featuretest.Result {
	return featuretest.Call(r.f, r.h, t0, vault.KindApp, "leash.item.set", body)
}

func (r *rig) stored(item string) *itemspec.ItemWays { return r.it.ways[[2]string{agent, item}] }

// reveal turns on "May be shown to agents" for the item (as staging agents
// and tests that read values must, §10.11 "Migration").
func (r *rig) reveal(item string) {
	if r.it.ways == nil {
		r.it.ways = map[[2]string]*itemspec.ItemWays{}
	}
	r.it.ways[[2]string{agent, item}] = &itemspec.ItemWays{Version: 1, Ways: []string{itemspec.WayUse, itemspec.WayReveal}}
}

func syncKinds(h *featuretest.Host) []string {
	var out []string
	for _, s := range h.SentOfType("sync.event") {
		out = append(out, string(s.Body))
	}
	return out
}

// §10.11 (0.42.0): who may set and list the ways.
func TestItemWaysAuthorization(t *testing.T) {
	r := newRig(t)
	for _, c := range []struct{ kind, typ string }{
		{vault.KindDesktop, "leash.item.set"}, {vault.KindAgent, "leash.item.set"}, {"connection:c1", "leash.item.set"},
		{vault.KindAgent, "leash.item.list"}, {"connection:c1", "leash.item.list"},
	} {
		if res := featuretest.Call(r.f, r.h, t0, c.kind, c.typ, `{"agent_id":"dev-agent","item_id":"`+r.wifi+`","ways":["use"]}`); res.Code != "forbidden" {
			t.Errorf("%s %s: %q", c.kind, c.typ, res.Code)
		}
	}
	if res := featuretest.Call(r.f, r.h, t0, vault.KindDesktop, "leash.item.list", `{"agent_id":"dev-agent"}`); !res.OK() {
		t.Fatalf("desktop list: %s", res.Code)
	}
}

// §10.11: settings exist only for an item a rule of the agent includes, of
// an active agent; versions; the answer, the event and the audit entry.
func TestItemSet(t *testing.T) {
	r := newRig(t)
	if res := r.itemSet(`{"agent_id":"dev-agent","item_id":"` + r.wifi + `","ways":["use","reveal"]}`); res.Code != "not_found" {
		t.Fatalf("no rule: %q", res.Code)
	}
	r.rule(t, Auto, 0, 60, r.wifi)
	r.h.Reset()
	for name, c := range map[string]struct{ body, code string }{
		"not an agent":    {`{"agent_id":"dev-desktop","item_id":"` + r.wifi + `","ways":["use"]}`, "not_found"},
		"nobody":          {`{"agent_id":"nobody","item_id":"` + r.wifi + `","ways":["use"]}`, "not_found"},
		"not included":    {`{"agent_id":"dev-agent","item_id":"` + r.bank + `","ways":["use"]}`, "not_found"},
		"no agent":        {`{"item_id":"` + r.wifi + `","ways":["use"]}`, "bad_request"},
		"bad item id":     {`{"agent_id":"dev-agent","item_id":"x","ways":["use"]}`, "bad_request"},
		"bad version":     {`{"agent_id":"dev-agent","item_id":"` + r.wifi + `","version":0,"ways":["use"]}`, "bad_request"},
		"version on none": {`{"agent_id":"dev-agent","item_id":"` + r.wifi + `","version":1,"ways":["use"]}`, "conflict"},
		"bad ways":        {`{"agent_id":"dev-agent","item_id":"` + r.wifi + `","ways":["reveal"]}`, "bad_request"},
		"not json":        {`{`, "bad_request"},
	} {
		if res := r.itemSet(c.body); res.Code != c.code {
			t.Errorf("%s: %q, want %s", name, res.Code, c.code)
		}
	}
	if r.stored(r.wifi) != nil || len(r.h.Activities) != 0 {
		t.Fatal("a refused set changed something")
	}
	r.h.Reset()
	res := r.itemSet(`{"agent_id":"dev-agent","item_id":"` + r.wifi + `","ways":["use","reveal"]}`)
	if !res.OK() {
		t.Fatalf("set: %s", res.Code)
	}
	o := res.Obj(t)
	if v, _ := o.Uint("version", 1, 1); v != 1 || string(o["ways"]) != `["use","reveal"]` || !o.Has("updated_at") {
		t.Fatalf("answer: %s", res.Body)
	}
	if w := r.stored(r.wifi); w == nil || w.Version != 1 || !w.Has(itemspec.WayReveal) {
		t.Fatalf("stored: %+v", w)
	}
	ev := syncKinds(r.h)
	if len(ev) != 1 || !strings.Contains(ev[0], `"kind":"leash.item.changed"`) || !strings.Contains(ev[0], `"item_id":"`+r.wifi+`"`) ||
		!strings.Contains(ev[0], `"version":1`) || !strings.Contains(ev[0], `"agent_id":"dev-agent"`) {
		t.Fatalf("sync event: %v", ev)
	}
	audited := false
	for _, a := range r.h.Activities {
		if a.Kind == "leash.item.changed" && a.Ref == r.wifi && a.DeviceID == agent && a.Audit {
			audited = true
		}
	}
	if !audited {
		t.Fatalf("not audited: %+v", r.h.Activities)
	}
	if len(r.h.SentOfType("leash.grant.updated")) != 0 {
		t.Fatal("settings are not part of the grants")
	}
	// Replacing: the version is required and must match.
	for _, body := range []string{
		`{"agent_id":"dev-agent","item_id":"` + r.wifi + `","ways":["use"]}`,
		`{"agent_id":"dev-agent","item_id":"` + r.wifi + `","version":2,"ways":["use"]}`,
	} {
		if res := r.itemSet(body); res.Code != "conflict" {
			t.Errorf("%s: %q", body, res.Code)
		}
	}
	if res := r.itemSet(`{"agent_id":"dev-agent","item_id":"` + r.wifi + `","version":1,"ways":["use"]}`); !res.OK() || r.stored(r.wifi).Version != 2 ||
		r.stored(r.wifi).Has(itemspec.WayReveal) {
		t.Fatalf("replace: %s %+v", res.Code, r.stored(r.wifi))
	}
}

// §10.11 "Widening needs the member": a widening outside the unlock window
// is credential_locked and changes nothing; a narrowing needs no window; a
// key user that cannot tell counts as closed.
func TestItemSetWindow(t *testing.T) {
	r := newRig(t)
	r.rule(t, Auto, 0, 60, r.wifi)
	set := `{"agent_id":"dev-agent","item_id":"` + r.wifi + `","ways":["use","run","proxy"],"run":{"programs":[{"program":"git","env":["GH_HOST"]}]},"proxy":{"hosts":["api.example.com"],"header":"Authorization"}}`
	if res := r.itemSet(set); !res.OK() {
		t.Fatal(res.Code)
	}
	r.w.open = false
	r.h.Reset()
	before := r.stored(r.wifi).Clone()
	for name, ways := range map[string]string{
		"reveal":     `"ways":["use","run","proxy","reveal"],"run":{"programs":[{"program":"git","env":["GH_HOST"]}]},"proxy":{"hosts":["api.example.com"],"header":"Authorization"}`,
		"program":    `"ways":["use","run","proxy"],"run":{"programs":[{"program":"git","env":["GH_HOST"]},{"program":"curl"}]},"proxy":{"hosts":["api.example.com"],"header":"Authorization"}`,
		"unbound":    `"ways":["use","run","proxy"],"run":{"programs":[]},"proxy":{"hosts":["api.example.com"],"header":"Authorization"}`,
		"env":        `"ways":["use","run","proxy"],"run":{"programs":[{"program":"git","env":["GH_HOST","GH_REPO"]}]},"proxy":{"hosts":["api.example.com"],"header":"Authorization"}`,
		"each false": `"ways":["use","run","proxy"],"run":{"programs":[{"program":"git","env":["GH_HOST"]}],"each":false},"proxy":{"hosts":["api.example.com"],"header":"Authorization"}`,
		"host":       `"ways":["use","run","proxy"],"run":{"programs":[{"program":"git","env":["GH_HOST"]}]},"proxy":{"hosts":["api.example.com","b.example.com"],"header":"Authorization"}`,
	} {
		if res := r.itemSet(`{"agent_id":"dev-agent","item_id":"` + r.wifi + `","version":1,` + ways + `}`); res.Code != "credential_locked" {
			t.Errorf("%s: %q", name, res.Code)
		}
	}
	if !r.stored(r.wifi).Equal(before) || len(r.h.Sent) != 0 || len(r.h.Activities) != 0 {
		t.Fatalf("a refused widening changed something: %+v %v %v", r.stored(r.wifi), r.h.Sent, r.h.Activities)
	}
	// Narrowing: outside the window.
	if res := r.itemSet(`{"agent_id":"dev-agent","item_id":"` + r.wifi + `","version":1,"ways":["use","run"],"run":{"programs":[{"program":"git"}]}}`); !res.OK() {
		t.Fatalf("narrowing: %s", res.Code)
	}
	// The window open: the widening goes through.
	r.w.open = true
	if res := r.itemSet(`{"agent_id":"dev-agent","item_id":"` + r.wifi + `","version":2,"ways":["use","reveal"]}`); !res.OK() {
		t.Fatalf("widening in the window: %s", res.Code)
	}
	// A key user without WindowOpen: closed.
	r2 := newRig(t)
	r2.f = New(noWindow{r2.w}, r2.it)
	r2.rule(t, Auto, 0, 60, r2.wifi)
	if res := r2.itemSet(`{"agent_id":"dev-agent","item_id":"` + r2.wifi + `","ways":["use","reveal"]}`); res.Code != "credential_locked" {
		t.Fatalf("unknown window: %q", res.Code)
	}
}

// §10.11: leash.item.list lists each included item, absent settings as
// ["use"] without version; item_id narrows; an agent that is not active
// is not_found.
func TestItemList(t *testing.T) {
	r := newRig(t)
	r.rule(t, Auto, 0, 60, r.wifi, r.bank)
	if res := r.itemSet(`{"agent_id":"dev-agent","item_id":"` + r.wifi + `","ways":["use","reveal"]}`); !res.OK() {
		t.Fatal(res.Code)
	}
	res := featuretest.Call(r.f, r.h, t0, vault.KindApp, "leash.item.list", `{"agent_id":"dev-agent"}`)
	if !res.OK() {
		t.Fatal(res.Code)
	}
	items := string(res.Obj(t)["items"])
	wantBank := `{"agent_id":"dev-agent","item_id":"` + r.bank + `","ways":["use"]}`
	if !strings.HasPrefix(items, "["+wantBank+",") || !strings.Contains(items, `"item_id":"`+r.wifi+`","version":1,"ways":["use","reveal"]`) {
		t.Fatalf("list: %s", items)
	}
	res = featuretest.Call(r.f, r.h, t0, vault.KindApp, "leash.item.list", `{"agent_id":"dev-agent","item_id":"`+r.bank+`"}`)
	if string(res.Obj(t)["items"]) != "["+wantBank+"]" {
		t.Fatalf("one item: %s", res.Body)
	}
	for body, code := range map[string]string{`{}`: "bad_request", `{"agent_id":"dev-agent","item_id":"x"}`: "bad_request",
		`{"agent_id":"dev-desktop"}`: "not_found", `{"agent_id":"nobody"}`: "not_found"} {
		if res := featuretest.Call(r.f, r.h, t0, vault.KindApp, "leash.item.list", body); res.Code != code {
			t.Errorf("%s: %q", body, res.Code)
		}
	}
	// Not included any more: not listed.
	r.it.incl = map[string]map[string]bool{}
	if res := featuretest.Call(r.f, r.h, t0, vault.KindApp, "leash.item.list", `{"agent_id":"dev-agent"}`); !bytes.Equal(res.Obj(t)["items"], []byte("[]")) {
		t.Fatalf("withdrawn listed: %s", res.Body)
	}
}

// decideS is decide, also returning the session (its refusal and flags).
func (r *rig) decideS(now time.Time, body string) (vault.AgentDecision, *vault.Session) {
	in := &envelope.Inner{ID: "01JB2Z6V9K3M4N5P6Q7R8S9T0V", Type: "agent.request", TS: now, Body: json.RawMessage(body)}
	from, _ := r.h.Device(agent)
	s := vault.NewSession(context.Background(), r.h, from, now, in)
	return r.f.AgentDecision(s, "agent.request", json.RawMessage(body)), s
}

// §10.11 (0.42.0): item.get only with reveal. Without it: way_not_allowed
// {ways}, counted as refused, with the scope's cooldown. With it: the
// windows count it and it is always referred, flagged history, within the
// referral cap. A use is unaffected; an item no rule includes stays
// forbidden (nothing said about its settings).
func TestRevealDecision(t *testing.T) {
	r := newRig(t)
	gid := r.rule(t, Auto, 0, 3, r.wifi)
	get := `{"op":"item.get","item_id":"` + r.wifi + `"}`
	r.h.Reset()
	d, s := r.decideS(t0, get)
	if d != vault.AgentDeny || s.AgentRefusal() == nil || s.AgentRefusal().Code != "way_not_allowed" || string(s.AgentRefusal().Body) != `{"ways":["use"]}` {
		t.Fatalf("without reveal: %v %+v", d, s.AgentRefusal())
	}
	if !r.h.HasActivity(KindRefused) {
		t.Fatal("not counted as refused")
	}
	if c := r.f.d.Agents[agent].Cool[ScopeItems]; c == nil || !t0.Before(c.Until) {
		t.Fatal("no cooldown")
	}
	// The cooldown throttles the next items.read request, a use included.
	use := `{"op":"item.use","item_id":"` + r.wifi + `","field_id":"f1","action":"hmac-sha256","data":"aGk="}`
	if d, _ := r.decideS(t0.Add(500*time.Millisecond), use); d != vault.AgentDeny {
		t.Fatalf("use within the cooldown: %v", d)
	}
	// Other ways allowed, still no reveal: the answer names them.
	r.it.ways = map[[2]string]*itemspec.ItemWays{{agent, r.wifi}: {Version: 1, Ways: []string{itemspec.WayUse, itemspec.WayProxy},
		Proxy: &itemspec.ProxyWays{Hosts: []string{"api.example.com"}, Header: "X"}}}
	if _, s := r.decideS(t0.Add(time.Hour), get); s.AgentRefusal() == nil || string(s.AgentRefusal().Body) != `{"ways":["use","proxy"]}` {
		t.Fatalf("ways named: %+v", s.AgentRefusal())
	}
	// A use needs no reveal.
	if d, _ := r.decideS(t0.Add(2*time.Hour), use); d != vault.AgentAllow {
		t.Fatalf("use: %v", d)
	}
	// An item no rule includes: forbidden, no refusal named.
	if d, s := r.decideS(t0.Add(3*time.Hour), `{"op":"item.get","item_id":"`+r.bank+`"}`); d != vault.AgentDeny || s.AgentRefusal() != nil {
		t.Fatalf("not included: %v %+v", d, s.AgentRefusal())
	}
	// With reveal: referred every time, flagged; the windows count it.
	r.reveal(r.wifi)
	now := t0.Add(5 * time.Hour)
	g := r.f.d.Grants[gid]
	for i := 0; i < 5; i++ {
		d, s := r.decideS(now.Add(time.Duration(i)*time.Second), get)
		if d != vault.AgentAsk || strings.Join(s.ApprovalFlags(), ",") != FlagHistory || s.AgentRefusal() != nil {
			t.Fatalf("reveal %d: %v %v", i, d, s.ApprovalFlags())
		}
	}
	if g.HourN != 3 {
		t.Fatalf("windows: %d counted, want 3 (per_hour)", g.HourN)
	}
	if !r.h.HasActivity("leash.rate_limited") {
		t.Fatal("past per_hour not recorded")
	}
	// A use is still allowed without approval within its windows (a new
	// hour).
	if d, s := r.decideS(now.Add(time.Hour+time.Minute), use); d != vault.AgentAllow || s.ApprovalFlags() != nil {
		t.Fatalf("use after reveals: %v", d)
	}
	// The referral cap applies to reveals.
	r2 := newRig(t)
	r2.rule(t, Auto, 0, 3600, r2.wifi)
	r2.reveal(r2.wifi)
	for i := 0; i < MaxReferralsPerHour; i++ {
		if d, _ := r2.decideS(t0.Add(time.Duration(i)*time.Second), get); d != vault.AgentAsk {
			t.Fatalf("referral %d: %v", i, d)
		}
	}
	g2 := r2.f.d.Grants[r2.f.itemRules(agent, t0)[0].ID]
	counted := g2.HourN
	if d, _ := r2.decideS(t0.Add(time.Minute), get); d != vault.AgentDeny || !r2.h.HasActivity("leash.referrals_limited") {
		t.Fatalf("past the cap: %v", d)
	}
	// A reveal throttled by the cap uses nothing of the windows.
	if g2.HourN != counted || g2.HourN != MaxReferralsPerHour {
		t.Fatalf("windows counted a throttled reveal: %d, before %d", g2.HourN, counted)
	}
}

// §10.11: a change of the proxy's header or prefix is not a widening (the
// value still goes only to the bound hosts), so it
// needs no unlock window; adding a host does.
func TestItemSetProxyHeaderOutsideWindow(t *testing.T) {
	r := newRig(t)
	r.rule(t, Auto, 0, 60, r.wifi)
	if res := r.itemSet(`{"agent_id":"dev-agent","item_id":"` + r.wifi + `","ways":["use","proxy"],"proxy":{"hosts":["api.example.com"],"header":"Authorization","prefix":"Bearer "}}`); !res.OK() {
		t.Fatal(res.Code)
	}
	r.w.open = false
	if res := r.itemSet(`{"agent_id":"dev-agent","item_id":"` + r.wifi + `","version":1,"ways":["use","proxy"],"proxy":{"hosts":["api.example.com"],"header":"X-Api-Key"}}`); !res.OK() {
		t.Fatalf("header change outside the window: %q", res.Code)
	}
	if w := r.stored(r.wifi); w.Proxy.Header != "X-Api-Key" || w.Proxy.Prefix != "" || w.Version != 2 {
		t.Fatalf("stored: %+v", w.Proxy)
	}
	if res := r.itemSet(`{"agent_id":"dev-agent","item_id":"` + r.wifi + `","version":2,"ways":["use","proxy"],"proxy":{"hosts":["api.example.com","b.example.com"],"header":"X-Api-Key"}}`); res.Code != "credential_locked" {
		t.Fatalf("host added outside the window: %q", res.Code)
	}
}

// §10.11 (0.42.0): an approved reveal is checked again when it runs; if
// reveal was turned off meanwhile, way_not_allowed and nothing is read.
func TestRevealCheckedAtApproval(t *testing.T) {
	r := newRig(t)
	r.rule(t, Auto, 0, 60, r.wifi)
	r.reveal(r.wifi)
	get := `{"op":"item.get","item_id":"` + r.wifi + `"}`
	if d, _ := r.decideS(t0, get); d != vault.AgentAsk {
		t.Fatal("not referred")
	}
	from, _ := r.h.Device(agent)
	if !r.f.AgentCovered(vault.NewSession(context.Background(), r.h, from, t0, nil), "agent.request", json.RawMessage(get)) {
		t.Fatal("not covered at approval")
	}
	delete(r.it.ways, [2]string{agent, r.wifi})
	res := featuretest.Call(r.f, r.h, t0, vault.KindAgent, "agent.request", get)
	if res.Code != "way_not_allowed" || string(res.Body) != `{"ways":["use"]}` || strings.Contains(string(res.Body), "hunter22") || r.it.used[r.wifi] != 0 {
		t.Fatalf("after reveal turned off: %q %s used=%d", res.Code, res.Body, r.it.used[r.wifi])
	}
	r.reveal(r.wifi)
	if res := featuretest.Call(r.f, r.h, t0, vault.KindAgent, "agent.request", get); !res.OK() || !strings.Contains(string(res.Body), "hunter22") {
		t.Fatalf("with reveal: %q", res.Code)
	}
}

// §10.11: the catalog gives each item's ways, programs ({program, env,
// path?}: never the hash) and hosts (never header or prefix).
func TestCatalogWays(t *testing.T) {
	r := newRig(t)
	r.rule(t, Auto, 0, 60, r.wifi, r.bank)
	sha := strings.Repeat("ab", 32)
	r.it.ways = map[[2]string]*itemspec.ItemWays{{agent, r.wifi}: {Version: 2, Ways: []string{itemspec.WayUse, itemspec.WayRun, itemspec.WayProxy},
		Run:   &itemspec.RunWays{Each: true, Programs: []itemspec.Program{{Program: "git", SHA256: sha, Path: "/usr/bin/git", Env: []string{"GH_HOST"}}}},
		Proxy: &itemspec.ProxyWays{Hosts: []string{"api.example.com"}, Header: "X-Secret-Header", Prefix: "Tok "}}}
	res := featuretest.Call(r.f, r.h, t0, vault.KindAgent, "agent.request", `{"op":"catalog"}`)
	if !res.OK() {
		t.Fatal(res.Code)
	}
	body := string(res.Body)
	wantWifi := `"ways":["use","run","proxy"],"programs":[{"program":"git","path":"/usr/bin/git","env":["GH_HOST"]}],"hosts":["api.example.com"]}`
	wantBank := `"labels":[{"field_id":"f1","label":"Password","kind":"password"},{"field_id":"f2","label":"Address","kind":"address"}],"ways":["use"]}`
	if !strings.Contains(body, wantWifi) || !strings.Contains(body, wantBank) {
		t.Fatalf("catalog: %s", body)
	}
	for _, never := range []string{sha, "X-Secret-Header", "Tok ", "hunter22", "s3cret", `"version"`, "updated_at", "each"} {
		if strings.Contains(body, never) {
			t.Fatalf("catalog shows %q: %s", never, body)
		}
	}
}

// 0.85.3: leash.item.set keeps or drops a recorded pin, never sets one.
func TestItemSetPins(t *testing.T) {
	r := newRig(t)
	r.rule(t, Auto, 0, 60, r.wifi)
	sha := strings.Repeat("ab", 32)
	r.it.AgentSetWays(agent, r.f.itemRules(agent, t0), r.wifi, &itemspec.ItemWays{Version: 1, Ways: []string{itemspec.WayUse, itemspec.WayRun},
		Run: &itemspec.RunWays{Each: true, Programs: []itemspec.Program{{Program: "git", SHA256: sha, Path: "/usr/bin/git", Env: []string{}}}}})
	keep := `{"agent_id":"dev-agent","item_id":"` + r.wifi + `","version":1,"ways":["use","run"],"run":{"programs":[{"program":"git","sha256":"` + sha + `","path":"/usr/bin/git"}]}}`
	if res := r.itemSet(keep); !res.OK() || r.stored(r.wifi).Run.Programs[0].SHA256 != sha {
		t.Fatalf("keep: %s", res.Code)
	}
	if res := r.itemSet(`{"agent_id":"dev-agent","item_id":"` + r.wifi + `","version":2,"ways":["use","run"],"run":{"programs":[{"program":"git","sha256":"` +
		strings.Repeat("cd", 32) + `","path":"/usr/bin/git"}]}}`); res.Code != "bad_request" {
		t.Fatalf("other pin: %q", res.Code)
	}
	if res := r.itemSet(`{"agent_id":"dev-agent","item_id":"` + r.wifi + `","version":2,"ways":["use","run"],"run":{"programs":[{"program":"git"}]}}`); !res.OK() ||
		r.stored(r.wifi).Run.Programs[0].SHA256 != "" {
		t.Fatalf("drop: %s", res.Code)
	}
	// Dropped, it cannot come back through leash.item.set.
	if res := r.itemSet(strings.Replace(keep, `"version":1`, `"version":3`, 1)); res.Code != "bad_request" {
		t.Fatalf("pin set again: %q", res.Code)
	}
}
