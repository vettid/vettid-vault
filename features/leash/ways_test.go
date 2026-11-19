package leash

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/features/itemspec"
	"github.com/vettid/vettid-vault/internal/featuretest"
	"github.com/vettid/vettid-vault/vault"
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
