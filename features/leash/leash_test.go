package leash

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
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
	"github.com/vettid/vettid-vault/vms/leashwire"
)

var t0 = time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)

// window is a credential unlock window under test control.
type window struct {
	key  ed25519.PrivateKey
	open bool
}

func (w *window) UseKey(time.Time, time.Duration) (ed25519.PrivateKey, bool) {
	if !w.open {
		return nil, false
	}
	return w.key, true
}

// fakeItems is the items feature as leash sees it: which items each
// agent rule includes (§10.11, §10.12).
type fakeItems struct {
	incl  map[string]map[string]bool // rule → item
	items map[string]*itemspec.Item
	used  map[string]int
}

func (f *fakeItems) AgentIncluded(agent string, rules []itemspec.AgentRule, item string) string {
	for _, r := range rules {
		if r.AgentID == agent && f.incl[r.ID][item] && (r.Terms.Uses == 0 || f.used[item] < int(r.Terms.Uses)) {
			return r.ID
		}
	}
	return ""
}

func (f *fakeItems) AgentCatalog(agent string, rules []itemspec.AgentRule) []itemspec.Meta {
	var out []itemspec.Meta
	for id, it := range f.items {
		if f.AgentIncluded(agent, rules, id) != "" {
			out = append(out, itemspec.MetaOf(it, nil))
		}
	}
	return out
}

func (f *fakeItems) AgentRead(agent string, rules []itemspec.AgentRule, item string, fields []string) ([]byte, bool) {
	it := f.items[item]
	if f.AgentIncluded(agent, rules, item) == "" || !it.HasFields(fields) {
		return nil, false
	}
	f.used[item]++
	return it.Content(fields), true
}

func (f *fakeItems) AgentFieldValue(agent string, rules []itemspec.AgentRule, item, field string) (string, bool) {
	if f.AgentIncluded(agent, rules, item) == "" {
		return "", false
	}
	fl, ok := f.items[item].Field(field)
	if !ok {
		return "", false
	}
	v, ok := itemspec.ValueString(fl.Value)
	if ok {
		f.used[item]++
	}
	return v, ok
}

type rig struct {
	f  *Feature
	h  *featuretest.Host
	w  *window
	it *fakeItems
	// ids of two items: wifi (a rule may include it) and bank
	wifi, bank string
	c1, c2     string // connection ids (ULIDs)
}

const agent = "dev-agent"

func newRig(t *testing.T) *rig {
	t.Helper()
	// Issuing signs with the credential key: the unlock window is open
	// unless a test closes it.
	r := &rig{h: featuretest.NewHost(), w: &window{key: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0xcc}, 32)), open: true},
		it: &fakeItems{incl: map[string]map[string]bool{}, items: map[string]*itemspec.Item{}, used: map[string]int{}}}
	r.f = New(r.w, r.it)
	r.h.AddDevice(agent, vault.KindAgent)
	r.h.AddDevice("dev-desktop", vault.KindDesktop)
	r.c1, r.c2 = "01JB2Z6V9K3M4N5P6Q7R8S9AAA", "01JB2Z6V9K3M4N5P6Q7R8S9BBB"
	for _, c := range []string{r.c1, r.c2} {
		r.h.Conns[c] = vault.PeerInfo{ID: c, Kind: vault.KindConnection, State: vault.PeerActive}
	}
	put := func(id, name, value string) string {
		r.it.items[id] = &itemspec.Item{ID: id, Version: 1, Name: name, Category: "login", Sensitivity: itemspec.Secret, Tags: []string{"zz-tag"},
			Fields: []itemspec.Field{{ID: "f1", Label: "Password", Kind: "password", Value: json.RawMessage(strictjson.MarshalString(value))},
				{ID: "f2", Label: "Address", Kind: "address", Value: json.RawMessage(`{"city":"Oslo"}`)}}}
		return id
	}
	r.wifi = put("01JB2Z6V9K3M4N5P6Q7R8S9W1F", "wifi", "hunter22")
	r.bank = put("01JB2Z6V9K3M4N5P6Q7R8S9BAN", "bank", "s3cret")
	r.h.Reset()
	return r
}

// rule makes an agent share rule (an items.read grant) including items.
func (r *rig) rule(t *testing.T, mode string, uses, perHour uint64, items ...string) string {
	t.Helper()
	id, _ := envelope.NewULID(t0.Add(time.Duration(len(r.it.incl)) * time.Millisecond))
	sess := vault.NewSession(context.Background(), r.h, vault.PeerInfo{ID: "dev-app", Kind: vault.KindApp}, t0, nil)
	ar, err := r.f.SetAgentRule(sess, &itemspec.AgentRule{ID: id, AgentID: agent, PerHour: perHour, PerDay: 1000, StatusTTL: 15 * time.Minute,
		Terms: itemspec.Terms{Tags: []string{"agent ok"}, Match: "any", Access: "read", Mode: mode, Uses: uses, IncludeExisting: true}})
	if err != nil {
		t.Fatal(err)
	}
	r.it.incl[ar.ID] = map[string]bool{}
	for _, i := range items {
		r.it.incl[ar.ID][i] = true
	}
	return ar.ID
}

func (r *rig) issue(t *testing.T, body string) (strictjson.Object, string) {
	t.Helper()
	res := featuretest.Call(r.f, r.h, t0, vault.KindApp, "leash.grant.issue", body)
	if !res.OK() {
		t.Fatalf("issue %s: %s", body, res.Code)
	}
	o := res.Obj(t)
	id, _ := o.String("grant_id")
	return o, id
}

// decide asks the policy as the runtime does for the agent.
func (r *rig) decide(now time.Time, typ, body string) vault.AgentDecision {
	in := &envelope.Inner{ID: "01JB2Z6V9K3M4N5P6Q7R8S9T0V", Type: typ, TS: now, Body: json.RawMessage(body)}
	from, _ := r.h.Device(agent)
	return r.f.AgentDecision(vault.NewSession(context.Background(), r.h, from, now, in), typ, json.RawMessage(body))
}

// §10.11: who may send what.
func TestAuthorization(t *testing.T) {
	r := newRig(t)
	for _, c := range []struct{ kind, typ, want string }{
		{vault.KindDesktop, "leash.grant.issue", "forbidden"},
		{vault.KindAgent, "leash.grant.issue", "forbidden"},
		{vault.KindConnection, "leash.grant.issue", "forbidden"},
		{vault.KindAgent, "leash.grant.revoke", "forbidden"},
		{vault.KindApp, "agent.request", "forbidden"},
		{vault.KindDesktop, "agent.request", "forbidden"},
		{"connection:c1", "agent.request", "forbidden"},
		{"connection:c1", "leash.grant.list", "forbidden"},
	} {
		if res := featuretest.Call(r.f, r.h, t0, c.kind, c.typ, `{}`); res.Code != c.want {
			t.Errorf("%s %s: %q", c.kind, c.typ, res.Code)
		}
	}
	for _, ts := range r.f.Types() {
		if ts.Type == "agent.request" && !ts.AgentPolicy {
			t.Fatal("agent.request must be decided by the policy")
		}
	}
}

func TestIssueValidation(t *testing.T) {
	r := newRig(t)
	for name, body := range map[string]string{
		"unknown scope":          `{"agent_id":"dev-agent","scope":"secrets.get"}`,
		"items.read by issue":    `{"agent_id":"dev-agent","scope":"items.read"}`,
		"app-only type":          `{"agent_id":"dev-agent","scope":"device.pair.create"}`,
		"settings":               `{"agent_id":"dev-agent","scope":"settings.set"}`,
		"bad approval":           `{"agent_id":"dev-agent","scope":"profile.get","approval":"always"}`,
		"connections on list":    `{"agent_id":"dev-agent","scope":"connection.list","connections":["01JB2Z6V9K3M4N5P6Q7R8S9T0V"]}`,
		"empty connections":      `{"agent_id":"dev-agent","scope":"message.send","connections":[]}`,
		"duplicate connection":   `{"agent_id":"dev-agent","scope":"message.send","connections":["01JB2Z6V9K3M4N5P6Q7R8S9T0V","01JB2Z6V9K3M4N5P6Q7R8S9T0V"]}`,
		"limits on ask":          `{"agent_id":"dev-agent","scope":"profile.get","per_hour":5}`,
		"per_hour too high":      `{"agent_id":"dev-agent","scope":"profile.get","approval":"auto","per_hour":3601}`,
		"expired":                `{"agent_id":"dev-agent","scope":"profile.get","expires_at":"2026-10-03T11:00:00.000Z"}`,
		"too far":                `{"agent_id":"dev-agent","scope":"profile.get","expires_at":"2027-10-04T12:00:00.000Z"}`,
		"version without id":     `{"agent_id":"dev-agent","scope":"profile.get","version":1}`,
		"duplicate member names": `{"agent_id":"dev-agent","scope":"profile.get","scope":"connection.list"}`,
	} {
		if res := featuretest.Call(r.f, r.h, t0, vault.KindApp, "leash.grant.issue", body); res.Code != "bad_request" {
			t.Errorf("%s: %q", name, res.Code)
		}
	}
	if res := featuretest.Call(r.f, r.h, t0, vault.KindApp, "leash.grant.issue", `{"agent_id":"dev-desktop","scope":"profile.get"}`); res.Code != "not_found" {
		t.Errorf("grant to a desktop: %q", res.Code)
	}
	if res := featuretest.Call(r.f, r.h, t0, vault.KindApp, "leash.grant.issue", `{"agent_id":"nobody","scope":"profile.get"}`); res.Code != "not_found" {
		t.Errorf("grant to nobody: %q", res.Code)
	}
	for i := 0; i < MaxGrants; i++ {
		r.issue(t, `{"agent_id":"dev-agent","scope":"profile.get"}`)
	}
	if res := featuretest.Call(r.f, r.h, t0, vault.KindApp, "leash.grant.issue", `{"agent_id":"dev-agent","scope":"profile.get"}`); res.Code != "limit" {
		t.Errorf("33rd grant: %q", res.Code)
	}
}

// §10.11 decisions: refuse without a covering grant, allow through an
// auto grant within its limits, refer otherwise; restrictions.
func TestDecisions(t *testing.T) {
	r := newRig(t)
	if d := r.decide(t0, "profile.get", `{}`); d != vault.AgentDeny || !r.h.HasActivity(KindRefused) {
		t.Fatalf("no grant: %v", d)
	}
	if d := r.decide(t0, "settings.get", `{}`); d != vault.AgentDeny {
		t.Fatal("a non-delegable type was not refused")
	}
	r.issue(t, `{"agent_id":"dev-agent","scope":"profile.get"}`)
	at := t0.Add(2 * time.Second) // past profile.get's 1 s cooldown
	if d := r.decide(at, "profile.get", `{}`); d != vault.AgentAsk {
		t.Fatalf("ask grant: %v", d)
	}
	c1 := r.c1
	r.issue(t, `{"agent_id":"dev-agent","scope":"message.send","approval":"auto","per_hour":2,"connections":["`+c1+`"]}`)
	if d := r.decide(at, "message.send", `{"connection_id":"`+c1+`","text":"hi"}`); d != vault.AgentAllow || !r.h.HasActivity(KindAllowed) {
		t.Fatalf("auto grant: %v", d)
	}
	if d := r.decide(at, "message.send", `{"connection_id":"`+r.c2+`","text":"hi"}`); d != vault.AgentDeny {
		t.Fatalf("restricted connection: %v", d)
	}
	at = at.Add(2 * time.Second)
	if d := r.decide(at, "message.send", `{"text":"hi"}`); d != vault.AgentDeny {
		t.Fatalf("missing connection_id: %v", d)
	}
	at = at.Add(4 * time.Second) // past the second refusal's 2 s cooldown
	if d := r.decide(at, "message.send", `{"connection_id":"`+c1+`","text":"hi"}`); d != vault.AgentAllow {
		t.Fatalf("second allowed: %v", d)
	}
	// Past the hourly limit: referred, and the owner told once.
	r.h.Reset()
	if d := r.decide(at.Add(time.Minute), "message.send", `{"connection_id":"`+c1+`","text":"hi"}`); d != vault.AgentAsk {
		t.Fatalf("over the limit: %v", d)
	}
	r.decide(at.Add(2*time.Minute), "message.send", `{"connection_id":"`+c1+`","text":"hi"}`)
	n := 0
	for _, a := range r.h.Activities {
		if a.Kind == "leash.rate_limited" {
			n++
			if !a.Feed || a.Priority != "high" {
				t.Fatal("rate limit not a high-priority feed item")
			}
		}
	}
	if n != 1 {
		t.Fatalf("rate_limited recorded %d times in one window", n)
	}
	// A new window allows again.
	if d := r.decide(at.Add(61*time.Minute), "message.send", `{"connection_id":"`+c1+`","text":"hi"}`); d != vault.AgentAllow {
		t.Fatalf("next window: %v", d)
	}
	// A malformed agent.request is left to the handler (bad_request).
	if d := r.decide(t0, "agent.request", `{"op":"nope"}`); d != vault.AgentAllow {
		t.Fatalf("malformed agent.request: %v", d)
	}
	if res := featuretest.Call(r.f, r.h, t0, vault.KindAgent, "agent.request", `{"op":"nope"}`); res.Code != "bad_request" {
		t.Fatalf("handler: %q", res.Code)
	}
}

// §10.11 anti-spam: an exponential cooldown per agent and scope after a
// refusal, a cap on referrals per hour, suspension after repeated
// refusals until an app resumes the agent.
func TestSpamControls(t *testing.T) {
	r := newRig(t)
	// Cooldown: 1 s, 2 s, 4 s ... capped at 5 min; requests within it are
	// throttled without examination.
	at := t0
	for i, wait := range []time.Duration{time.Second, 2 * time.Second, 4 * time.Second} {
		if d := r.decide(at, "profile.get", `{}`); d != vault.AgentDeny {
			t.Fatalf("refusal %d: %v", i, d)
		}
		if d := r.decide(at.Add(wait-time.Millisecond), "profile.get", `{}`); d != vault.AgentDeny {
			t.Fatal("not throttled")
		}
		at = at.Add(wait)
	}
	st := r.f.d.Agents[agent]
	if st.Counts[KindRefused] != 3 || st.Counts[KindThrottled] != 3 {
		t.Fatalf("counts: %v", st.Counts)
	}
	r.decide(at, "profile.get", `{}`) // a 4th refusal: 8 s
	// Issuing a grant of the scope clears its cooldown.
	if st.Cool["profile.get"] == nil {
		t.Fatal("no cooldown")
	}
	r.issue(t, `{"agent_id":"dev-agent","scope":"profile.get"}`)
	if st.Cool["profile.get"] != nil {
		t.Fatal("cooldown kept after a grant of the scope")
	}
	if d := r.decide(at.Add(time.Second), "profile.get", `{}`); d != vault.AgentAsk {
		t.Fatalf("after the grant: %v", d)
	}
	c := &Cooldown{Step: 30, Last: at}
	st.Cool["x"] = c
	r.decide(at.Add(10*time.Second), "x", `{}`)
	if got := st.Cool["x"].Until.Sub(at.Add(10 * time.Second)); got != CooldownMax {
		t.Fatalf("cooldown not capped: %v", got)
	}

	// Referral cap: MaxReferralsPerHour per agent and hour, then throttled
	// and the owner told once.
	r2 := newRig(t)
	r2.issue(t, `{"agent_id":"dev-agent","scope":"profile.get"}`)
	for i := 0; i < MaxReferralsPerHour; i++ {
		if d := r2.decide(t0.Add(time.Duration(i)*time.Second), "profile.get", `{}`); d != vault.AgentAsk {
			t.Fatalf("referral %d: %v", i, d)
		}
	}
	if d := r2.decide(t0.Add(time.Minute), "profile.get", `{}`); d != vault.AgentDeny || !r2.h.HasActivity("leash.referrals_limited") {
		t.Fatalf("over the referral cap: %v", d)
	}
	if d := r2.decide(t0.Add(61*time.Minute), "profile.get", `{}`); d != vault.AgentAsk {
		t.Fatalf("next hour: %v", d)
	}

	// Suspension after SuspendAfter refusals in the window: every grant
	// paused, the agent and the owner told; only an app resumes.
	r3 := newRig(t)
	r3.issue(t, `{"agent_id":"dev-agent","scope":"profile.get","approval":"auto"}`)
	for i := 0; i < SuspendAfter; i++ {
		r3.decide(t0.Add(time.Duration(i)*time.Millisecond), "settings.get", `{}`)
	}
	if st := r3.f.d.Agents[agent]; !st.Suspended {
		t.Fatal("not suspended")
	}
	up := r3.h.SentOfType("leash.grant.updated")
	if len(up) == 0 || !strings.Contains(string(up[len(up)-1].Body), `"suspended":true`) {
		t.Fatalf("agent not told: %+v", up)
	}
	if !r3.h.HasActivity("leash.agent.suspended") {
		t.Fatal("suspension not recorded")
	}
	if d := r3.decide(t0.Add(time.Hour+time.Minute), "profile.get", `{}`); d != vault.AgentDeny {
		t.Fatal("suspended agent allowed")
	}
	from, _ := r3.h.Device(agent)
	if r3.f.AgentCovered(vault.NewSession(context.Background(), r3.h, from, t0, nil), "profile.get", json.RawMessage(`{}`)) {
		t.Fatal("suspended agent covered on approval")
	}
	if res := featuretest.Call(r3.f, r3.h, t0, vault.KindDesktop, "leash.agent.resume", `{"agent_id":"dev-agent"}`); res.Code != "forbidden" {
		t.Fatalf("desktop resumed: %q", res.Code)
	}
	if res := featuretest.Call(r3.f, r3.h, t0, vault.KindApp, "leash.agent.resume", `{"agent_id":"dev-agent"}`); !res.OK() {
		t.Fatal(res.Code)
	}
	if res := featuretest.Call(r3.f, r3.h, t0, vault.KindApp, "leash.agent.resume", `{"agent_id":"dev-agent"}`); res.Code != "not_found" {
		t.Fatalf("resume twice: %q", res.Code)
	}
	if d := r3.decide(t0.Add(2*time.Hour), "profile.get", `{}`); d != vault.AgentAllow {
		t.Fatalf("after resume: %v", d)
	}
}

// §10.11: agent activity is summarised in the audit log, at most one
// single entry and one summary per kind, agent and hour, so an agent
// cannot push older entries out.
func TestAuditSummaries(t *testing.T) {
	r := newRig(t)
	r.issue(t, `{"agent_id":"dev-agent","scope":"profile.get","approval":"auto","per_hour":3600,"per_day":86400}`)
	for i := 0; i < 100; i++ {
		r.decide(t0.Add(time.Duration(i)*time.Second), "profile.get", `{}`)
	}
	count := func(kind string) (n int, ref string) {
		for _, a := range r.h.Activities {
			if a.Kind == kind {
				n++
				ref = a.Ref
			}
		}
		return
	}
	if n, _ := count(KindAllowed); n != 1 {
		t.Fatalf("%d single allowed entries", n)
	}
	if n, _ := count(KindAllowed + ".summary"); n != 0 {
		t.Fatal("summary before the window ended")
	}
	// The next window writes the summary of the last one.
	r.decide(t0.Add(time.Hour+time.Minute), "profile.get", `{}`)
	if n, ref := count(KindAllowed + ".summary"); n != 1 || ref != "99" {
		t.Fatalf("summary: %d %q", n, ref)
	}
	if n, _ := count(KindAllowed); n != 2 {
		t.Fatal("new window's first entry")
	}
	// Unlinking writes the open summaries.
	r.decide(t0.Add(time.Hour+2*time.Minute), "profile.get", `{}`)
	r.f.DeviceRemoved(vault.NewSession(context.Background(), r.h, vault.PeerInfo{}, t0.Add(time.Hour+3*time.Minute), nil), agent)
	if n, ref := count(KindAllowed + ".summary"); n != 2 || ref != "1" {
		t.Fatalf("summary at unlink: %d %q", n, ref)
	}
}

// §10.11 agent.request: catalog, retrieval and use only of the items the
// agent's share rules include; reads allowed within the rule's limits.
func TestAgentRequest(t *testing.T) {
	r := newRig(t)
	call := func(body string) featuretest.Result {
		if d := r.decide(t0, "agent.request", body); d != vault.AgentAllow {
			return featuretest.Result{Code: "forbidden"}
		}
		return featuretest.Call(r.f, r.h, t0, vault.KindAgent, "agent.request", body)
	}
	if res := call(`{"op":"catalog"}`); res.Code != "forbidden" {
		t.Fatalf("catalog without a rule: %q", res.Code)
	}
	gid := r.rule(t, Ask, 3, 60, r.wifi)
	res := call(`{"op":"catalog"}`)
	if !res.OK() || !strings.Contains(string(res.Body), r.wifi) || strings.Contains(string(res.Body), r.bank) ||
		strings.Contains(string(res.Body), "hunter22") || strings.Contains(string(res.Body), "zz-tag") {
		t.Fatalf("catalog: %s", res.Body)
	}
	if res := call(`{"op":"item.get","item_id":"` + r.wifi + `","fields":["f1"]}`); !res.OK() || !strings.Contains(string(res.Body), `"value":"hunter22"`) ||
		strings.Contains(string(res.Body), `"version"`) || strings.Contains(string(res.Body), "Oslo") {
		t.Fatalf("item.get: %s %s", res.Code, res.Body)
	}
	if !r.h.HasActivity(KindRead) {
		t.Fatal("read not recorded")
	}
	// An item no rule includes is refused like an uncovered request.
	if res := call(`{"op":"item.get","item_id":"` + r.bank + `"}`); res.Code != "forbidden" {
		t.Fatalf("item outside the rule: %q", res.Code)
	}
	res = featuretest.Call(r.f, r.h, t0, vault.KindAgent, "agent.request", `{"op":"item.use","item_id":"`+r.wifi+`","field_id":"f1","action":"hmac-sha256","data":"aGk="}`)
	mac := hmac.New(sha256.New, []byte("hunter22"))
	mac.Write([]byte("hi"))
	if !res.OK() || !strings.Contains(string(res.Body), base64.StdEncoding.EncodeToString(mac.Sum(nil))) || strings.Contains(string(res.Body), "hunter22") {
		t.Fatalf("item.use: %s %s", res.Code, res.Body)
	}
	if !r.h.HasActivity(KindUsed) {
		t.Fatal("use not recorded")
	}
	// An address field cannot be used; an unknown field is not found.
	if res := featuretest.Call(r.f, r.h, t0, vault.KindAgent, "agent.request", `{"op":"item.use","item_id":"`+r.wifi+`","field_id":"f2","action":"hmac-sha256","data":"aGk="}`); res.Code != "not_found" {
		t.Fatalf("address use: %q", res.Code)
	}
	for name, body := range map[string]string{
		"no op":        `{}`,
		"old op":       `{"op":"secret.get","secret_id":"` + r.wifi + `"}`,
		"bad id":       `{"op":"item.get","item_id":"x"}`,
		"bad fields":   `{"op":"item.get","item_id":"` + r.wifi + `","fields":[]}`,
		"no field":     `{"op":"item.use","item_id":"` + r.wifi + `","action":"hmac-sha256","data":"aGk="}`,
		"bad action":   `{"op":"item.use","item_id":"` + r.wifi + `","field_id":"f1","action":"sha1","data":"aGk="}`,
		"empty data":   `{"op":"item.use","item_id":"` + r.wifi + `","field_id":"f1","action":"hmac-sha256","data":""}`,
		"bad base64":   `{"op":"item.use","item_id":"` + r.wifi + `","field_id":"f1","action":"hmac-sha256","data":"!!"}`,
		"not a object": `[]`,
	} {
		if res := featuretest.Call(r.f, r.h, t0, vault.KindAgent, "agent.request", body); res.Code != "bad_request" {
			t.Errorf("%s: %q", name, res.Code)
		}
	}
	// uses = 3: one get, one use, one more get; then not covered.
	if res := featuretest.Call(r.f, r.h, t0, vault.KindAgent, "agent.request", `{"op":"item.get","item_id":"`+r.wifi+`"}`); !res.OK() {
		t.Fatalf("third use: %q", res.Code)
	}
	if d := r.decide(t0.Add(time.Hour), "agent.request", `{"op":"item.get","item_id":"`+r.wifi+`"}`); d != vault.AgentDeny {
		t.Fatalf("uses exhausted: %v", d)
	}
	// Revocation through LEASH deletes the rule at once.
	if res := featuretest.Call(r.f, r.h, t0, vault.KindDesktop, "leash.grant.revoke", `{"grant_id":"`+gid+`"}`); !res.OK() {
		t.Fatal(res.Code)
	}
	if len(r.f.AgentRules(t0)) != 0 {
		t.Fatal("rule after revoke")
	}
}

// §10.11: an agent's share rule is an items.read grant: signed (unlock
// window), delivered to the agent with its tags, replaced by version,
// rate limits on reads (past them referred).
func TestAgentRules(t *testing.T) {
	r := newRig(t)
	sess := vault.NewSession(context.Background(), r.h, vault.PeerInfo{ID: "dev-app", Kind: vault.KindApp}, t0, nil)
	id, _ := envelope.NewULID(t0)
	spec := &itemspec.AgentRule{ID: id, AgentID: agent, PerHour: 2, PerDay: 10, StatusTTL: time.Minute,
		Terms: itemspec.Terms{Tags: []string{"agent ok", "work"}, Match: "all", Access: "read", Mode: Auto, Uses: 5}}
	r.w.open = false
	if _, err := r.f.SetAgentRule(sess, spec); err == nil || err.(*vault.HandlerError).Code != "credential_locked" {
		t.Fatalf("outside the window: %v", err)
	}
	r.w.open = true
	bad := *spec
	bad.AgentID = "dev-desktop"
	if _, err := r.f.SetAgentRule(sess, &bad); err == nil {
		t.Fatal("a rule for a desktop")
	}
	ar, err := r.f.SetAgentRule(sess, spec)
	if err != nil || ar.Version != 1 {
		t.Fatal(err)
	}
	d, err := leashwire.Verify(r.w.key.Public().(ed25519.PublicKey), ar.Delegation, ar.DelegationSig, t0)
	if err != nil || d.Scope.Op != ScopeItems || strings.Join(d.Scope.Tags, ",") != "agent ok,work" || d.Scope.Match != "all" ||
		d.Scope.Uses != 5 || d.Limits == nil || d.Limits.PerHour != 2 || d.Limits.PerDay != 10 || d.Approval != Auto || d.Scope.Connections != nil {
		t.Fatalf("delegation: %+v %v", d, err)
	}
	up := r.h.SentOfType("leash.grant.updated")
	if len(up) != 1 || !strings.Contains(string(up[0].Body), `"scope":"items.read"`) || !strings.Contains(string(up[0].Body), `"tags":["agent ok","work"]`) {
		t.Fatalf("agent told: %+v", up)
	}
	// Replacement: version checked, signed again.
	if _, err := r.f.SetAgentRule(sess, spec); err == nil {
		t.Fatal("version 0 again")
	}
	spec.Version = 1
	spec.Terms.Mode = Ask
	ar, err = r.f.SetAgentRule(sess, spec)
	if err != nil || ar.Version != 2 {
		t.Fatalf("replace: %v", err)
	}
	stale := *spec
	if _, err := r.f.SetAgentRule(sess, &stale); err == nil || err.(*vault.HandlerError).Code != "conflict" {
		t.Fatalf("stale: %v", err)
	}
	// Reads of an included item are allowed whatever the mode (inclusion
	// was the member's decision), within per_hour; then referred.
	r.it.incl[id] = map[string]bool{r.wifi: true}
	body := `{"op":"item.get","item_id":"` + r.wifi + `"}`
	for i := 0; i < 2; i++ {
		if d := r.decide(t0.Add(time.Duration(i)*time.Second), "agent.request", body); d != vault.AgentAllow {
			t.Fatalf("read %d: %v", i, d)
		}
	}
	if d := r.decide(t0.Add(3*time.Second), "agent.request", body); d != vault.AgentAsk {
		t.Fatalf("past per_hour: %v", d)
	}
	from, _ := r.h.Device(agent)
	if !r.f.AgentCovered(vault.NewSession(context.Background(), r.h, from, t0, nil), "agent.request", json.RawMessage(body)) {
		t.Fatal("not covered on approval")
	}
	// Listed among the agent's grants and the owner's.
	if res := featuretest.Call(r.f, r.h, t0, vault.KindAgent, "leash.grant.list", `{}`); !res.OK() || !strings.Contains(string(res.Body), id) {
		t.Fatalf("agent list: %s", res.Body)
	}
	if !r.f.DeleteAgentRule(sess, id) || r.f.DeleteAgentRule(sess, id) {
		t.Fatal("delete")
	}
	if d := r.decide(t0.Add(time.Hour), "agent.request", body); d != vault.AgentDeny {
		t.Fatal("covered after delete")
	}
}

// §10.11: replacement with versions; updates to the agent and sync events
// to the owner's devices; lists.
func TestReplaceListNotify(t *testing.T) {
	r := newRig(t)
	o, gid := r.issue(t, `{"agent_id":"dev-agent","scope":"profile.get"}`)
	if v, _ := o.Uint("version", 1, 10); v != 1 {
		t.Fatal("first version")
	}
	if up := r.h.SentOfType("leash.grant.updated"); len(up) != 1 || up[0].To != agent || !strings.Contains(string(up[0].Body), gid) {
		t.Fatalf("updated: %+v", up)
	}
	if se := r.h.SentOfType("sync.event"); len(se) != 1 || !strings.Contains(string(se[0].Body), `"kind":"leash.grant.changed"`) {
		t.Fatalf("sync: %+v", se)
	}
	if res := featuretest.Call(r.f, r.h, t0, vault.KindApp, "leash.grant.issue", `{"agent_id":"dev-agent","grant_id":"`+gid+`","version":2,"scope":"profile.get"}`); res.Code != "conflict" {
		t.Fatalf("stale version: %q", res.Code)
	}
	o, _ = r.issue(t, `{"agent_id":"dev-agent","grant_id":"`+gid+`","version":1,"scope":"connection.list","approval":"auto"}`)
	if v, _ := o.Uint("version", 1, 10); v != 2 {
		t.Fatal("replacement version")
	}
	if !r.h.HasActivity("leash.grant.updated") {
		t.Fatal("replacement not audited")
	}
	r.h.AddDevice("dev-agent2", vault.KindAgent)
	r.issue(t, `{"agent_id":"dev-agent2","scope":"profile.get"}`)
	if res := featuretest.Call(r.f, r.h, t0, vault.KindAgent, "leash.grant.list", `{}`); !res.OK() || strings.Contains(string(res.Body), "dev-agent2") {
		t.Fatalf("agent sees others' grants: %s", res.Body)
	}
	if res := featuretest.Call(r.f, r.h, t0, vault.KindDesktop, "leash.grant.list", `{"agent_id":"dev-agent2"}`); !res.OK() || strings.Count(string(res.Body), "grant_id") != 1 {
		t.Fatalf("filtered list: %s", res.Body)
	}
	if res := featuretest.Call(r.f, r.h, t0, vault.KindApp, "leash.grant.list", `{}`); !res.OK() || strings.Count(string(res.Body), "grant_id") != 2 {
		t.Fatalf("full list: %s", res.Body)
	}
	g2 := New(r.w, r.it)
	featuretest.RoundTrip(t, r.f, g2)
	if len(g2.Grants()) != 2 {
		t.Fatal("grants lost in a flush")
	}
}

// §10.11: every grant is a delegation signed by the credential key, so
// issuing needs the unlock window; canonical bytes; exp from the grant's
// expiry (LEASH §3.2), none without one.
func TestSignedDelegation(t *testing.T) {
	r := newRig(t)
	r.w.open = false
	body := `{"agent_id":"dev-agent","scope":"connection.list","expires_at":"2026-12-01T00:00:00.000Z"}`
	if res := featuretest.Call(r.f, r.h, t0, vault.KindApp, "leash.grant.issue", body); res.Code != "credential_locked" {
		t.Fatalf("outside the window: %q", res.Code)
	}
	if len(r.f.Grants()) != 0 {
		t.Fatal("a refused grant was stored")
	}
	r.w.open = true
	o, gid := r.issue(t, body)
	stmt, err := o.Base64("delegation", -1)
	if err != nil {
		t.Fatal(err)
	}
	sig, _ := o.Base64("sig", 64)
	if o.Has("key") || o.Has("delegation_sig") {
		t.Fatal("0.12.0: the grant carries sig and no key")
	}
	key := r.w.key.Public().(ed25519.PublicKey)
	d, err := leashwire.Verify(key, stmt, sig, t0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	ag, _ := r.h.Device(agent)
	want := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	if d.GrantID != gid || !bytes.Equal(d.Iss, key) || !bytes.Equal(d.Sub, ag.IK) || !bytes.Equal(d.StatusIssuer, r.h.IK) ||
		!d.Expires.Equal(want) || d.Scope.Op != "connection.list" || d.Approval != "ask" || d.Limits != nil {
		t.Fatalf("delegation: %+v", d)
	}
	if _, err := leashwire.ParseCanonical(stmt); err != nil {
		t.Fatal("not JCS")
	}
	firstNonce := d.Nonce
	if _, err := leashwire.Verify(key, stmt, sig, want); err == nil {
		t.Fatal("delegation valid past the grant's expiry")
	}
	// A grant without expiry: the delegation has none either.
	o, _ = r.issue(t, `{"agent_id":"dev-agent","scope":"profile.get"}`)
	stmt, _ = o.Base64("delegation", -1)
	if bytes.Contains(stmt, []byte(`"exp"`)) {
		t.Fatalf("exp without a grant expiry: %s", stmt)
	}
	// A replacement is signed again, under its new version.
	o, _ = r.issue(t, `{"agent_id":"dev-agent","grant_id":"`+gid+`","version":1,"scope":"connection.list"}`)
	stmt, _ = o.Base64("delegation", -1)
	sig, _ = o.Base64("sig", 64)
	if d, err := leashwire.Verify(key, stmt, sig, t0); err != nil || d.Version != 2 || bytes.Equal(d.Nonce, firstNonce) {
		t.Fatalf("replacement: %v", err)
	}
	// An auto grant carries its limits (0.12.0).
	o, _ = r.issue(t, `{"agent_id":"dev-agent","scope":"profile.get","approval":"auto","per_hour":7}`)
	stmt, _ = o.Base64("delegation", -1)
	if d, err := leashwire.ParseCanonical(stmt); err != nil || d.Limits == nil || d.Limits.PerHour != 7 || d.Limits.PerDay != 1000 {
		t.Fatalf("auto limits: %s", stmt)
	}
}

// Owner decision 8 of 0.12.0: a stored grant whose delegation is in the
// 0.6.0 format is not served (no delegation, no sig, no status statement);
// the member re-issues it, which signs it in the 0.12.0 format.
func TestOldFormatDelegationNotServed(t *testing.T) {
	r := newRig(t)
	_, gid := r.issue(t, `{"agent_id":"dev-agent","scope":"profile.get"}`)
	old := []byte(`{"v":1,"vault_ik":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","agent_ik":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",` +
		`"grant_id":"` + gid + `","version":1,"scope":"profile.get","approval":"ask","status_ttl":900,"iat":1790000000}`)
	r.f.mu.Lock()
	r.f.d.Grants[gid].Delegation = old
	r.f.mu.Unlock()
	res := featuretest.Call(r.f, r.h, t0, vault.KindAgent, "leash.grant.list", `{}`)
	if !res.OK() || strings.Contains(string(res.Body), `"delegation"`) || strings.Contains(string(res.Body), `"status"`) ||
		!strings.Contains(string(res.Body), gid) {
		t.Fatalf("old delegation served: %s %s", res.Code, res.Body)
	}
	if res := featuretest.Call(r.f, r.h, t0, vault.KindAgent, "leash.status.get", `{"grant_id":"`+gid+`"}`); res.Code != "not_found" {
		t.Fatalf("status for an old delegation: %q", res.Code)
	}
	o, _ := r.issue(t, `{"agent_id":"dev-agent","grant_id":"`+gid+`","version":1,"scope":"profile.get"}`)
	stmt, _ := o.Base64("delegation", -1)
	if _, err := leashwire.ParseCanonical(stmt); err != nil {
		t.Fatal("re-issue did not sign in the 0.12.0 format")
	}
	if res := featuretest.Call(r.f, r.h, t0, vault.KindAgent, "leash.status.get", `{"grant_id":"`+gid+`"}`); !res.OK() {
		t.Fatalf("status after re-issue: %q", res.Code)
	}
}

// §6.7, §10.11: initial grants are signed at the pairing approval
// (unlock window), installed with the pairing; unlinking revokes; removing
// a connection revokes the grants that name it.
func TestPairingUnlinkRemoval(t *testing.T) {
	r := newRig(t)
	ag, _ := r.h.Device(agent)
	sess := vault.NewSession(context.Background(), r.h, vault.PeerInfo{ID: "dev-app", Kind: vault.KindApp}, t0, nil)
	for name, raw := range map[string]string{
		"empty":    `[]`,
		"object":   `{}`,
		"bad":      `[{"scope":"settings.set"}]`,
		"too many": "[" + strings.TrimSuffix(strings.Repeat(`{"scope":"profile.get"},`, MaxGrants+1), ",") + "]",
	} {
		if _, err := r.f.PrepareAgentGrants(sess, ag.IK, json.RawMessage(raw)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	c1, c2 := r.c1, r.c2
	initial := `[{"scope":"profile.get","approval":"auto"},{"scope":"message.send","connections":["` + c1 + `","` + c2 + `"]},{"scope":"message.get","connections":["` + c2 + `"]}]`
	r.w.open = false
	if _, err := r.f.PrepareAgentGrants(sess, ag.IK, json.RawMessage(initial)); err == nil || err.(*vault.HandlerError).Code != "credential_locked" {
		t.Fatalf("outside the unlock window: %v", err)
	}
	r.w.open = true
	prepared, err := r.f.PrepareAgentGrants(sess, ag.IK, json.RawMessage(initial))
	if err != nil {
		t.Fatal(err)
	}
	r.f.AgentPaired(sess, agent, prepared)
	gs := r.f.Grants()
	if len(gs) != 3 || len(r.h.SentOfType("leash.grant.updated")) != 1 {
		t.Fatalf("initial grants: %d", len(gs))
	}
	for _, g := range gs {
		d, err := leashwire.Verify(r.w.key.Public().(ed25519.PublicKey), g.Delegation, g.DelegationSig, t0)
		if err != nil || !bytes.Equal(d.Sub, ag.IK) || d.GrantID != g.ID {
			t.Fatalf("initial grant not signed for the agent: %v", err)
		}
	}
	if d := r.decide(t0, "profile.get", `{}`); d != vault.AgentAllow {
		t.Fatalf("initial auto grant: %v", d)
	}
	r.f.ConnectionRemoved(vault.NewSession(context.Background(), r.h, vault.PeerInfo{}, t0, nil), c1)
	if gs := r.f.Grants(); len(gs) != 2 {
		t.Fatalf("after removal: %d grants", len(gs))
	}
	r.f.DeviceRemoved(vault.NewSession(context.Background(), r.h, vault.PeerInfo{}, t0, nil), agent)
	if len(r.f.Grants()) != 0 || !r.h.HasActivity("leash.grant.revoked") {
		t.Fatal("unlinking left grants")
	}
}

// §10.11: expired grants match nothing and are dropped.
func TestExpiry(t *testing.T) {
	r := newRig(t)
	r.issue(t, `{"agent_id":"dev-agent","scope":"profile.get","approval":"auto","expires_at":"2026-10-03T13:00:00.000Z"}`)
	if d := r.decide(t0, "profile.get", `{}`); d != vault.AgentAllow {
		t.Fatal("before expiry")
	}
	if d := r.decide(t0.Add(time.Hour), "profile.get", `{}`); d != vault.AgentDeny {
		t.Fatal("after expiry")
	}
	if len(r.f.Grants()) != 0 {
		t.Fatal("expired grant kept")
	}
}

func FuzzParseSpec(f *testing.F) {
	f.Add([]byte(`{"scope":"profile.get","approval":"auto","per_hour":5,"expires_at":"2026-10-04T00:00:00.000Z"}`))
	f.Add([]byte(`{"scope":"items.read","approval":"auto"}`))
	f.Add([]byte(`{"scope":"message.send","connections":["01JB2Z6V9K3M4N5P6Q7R8S9T0V"],"sign":true}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		o, err := strictjson.ParseObject(b)
		if err != nil {
			return
		}
		sp, err := ParseSpec(o, t0)
		if err != nil {
			return
		}
		if !ValidScope(sp.Scope) || sp.Approval != Ask && sp.Approval != Auto || sp.Approval == Ask && sp.PerHour != 0 {
			t.Fatalf("accepted %+v", sp)
		}
	})
}

func FuzzParseInitialGrants(f *testing.F) {
	f.Add([]byte(`[{"scope":"profile.get"},{"scope":"connection.list","approval":"auto"}]`))
	f.Fuzz(func(t *testing.T, b []byte) {
		sps, err := ParseInitialGrants(json.RawMessage(b), t0)
		if err == nil && (len(sps) == 0 || len(sps) > MaxGrants) {
			t.Fatal("bad count accepted")
		}
	})
}

func FuzzParseRequest(f *testing.F) {
	f.Add([]byte(`{"op":"catalog"}`))
	f.Add([]byte(`{"op":"item.use","item_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V","field_id":"f1","action":"hmac-sha256","data":"aGk="}`))
	f.Add([]byte(`{"op":"item.get","item_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V","fields":["f1","f2"]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := ParseRequest(b)
		if err == nil && opScope[r.Op] == "" {
			t.Fatal("unknown op accepted")
		}
	})
}

// §10.11 status statements: issued by the vault (no credential needed)
// for grants in force; none for revoked, expired or suspended ones;
// verifiable offline with the delegation; status_ttl bounds.
func TestStatusStatements(t *testing.T) {
	r := newRig(t)
	for _, ttl := range []string{"59", "3601"} {
		if res := featuretest.Call(r.f, r.h, t0, vault.KindApp, "leash.grant.issue", `{"agent_id":"dev-agent","scope":"profile.get","status_ttl":`+ttl+`}`); res.Code != "bad_request" {
			t.Fatalf("status_ttl %s: %q", ttl, res.Code)
		}
	}
	_, gid := r.issue(t, `{"agent_id":"dev-agent","scope":"profile.get","status_ttl":120}`)
	up := r.h.SentOfType("leash.grant.updated")
	if len(up) == 0 || !strings.Contains(string(up[len(up)-1].Body), `"status_sig"`) {
		t.Fatalf("no status in leash.grant.updated: %+v", up)
	}
	member := r.w.key.Public().(ed25519.PublicKey)
	r.w.open = false // statements need no credential
	get := func(at time.Time) featuretest.Result {
		return featuretest.Call(r.f, r.h, at, vault.KindAgent, "leash.status.get", `{"grant_id":"`+gid+`"}`)
	}
	res := get(t0.Add(time.Minute))
	if !res.OK() {
		t.Fatal(res.Code)
	}
	o := res.Obj(t)
	g := r.f.Grants()[0]
	st, _ := o.Base64("status", -1)
	ss, _ := o.Base64("status_sig", 64)
	p := &leashwire.Presented{Delegation: g.Delegation, Sig: g.DelegationSig, Status: st, StatusSig: ss}
	if _, err := leashwire.VerifyPresented(member, p, t0.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := leashwire.VerifyPresented(member, p, t0.Add(5*time.Minute)); err == nil {
		t.Fatal("statement outlived its 2-minute ttl")
	}
	if res := featuretest.Call(r.f, r.h, t0, vault.KindApp, "leash.status.get", `{"grant_id":"`+gid+`"}`); res.Code != "forbidden" {
		t.Fatalf("an app asked: %q", res.Code)
	}
	// After the vault's ik rotated, statements carry the chain.
	old := r.h.IK
	r.h.SetIdentity(0x77)
	r.h.ChainFrom, r.h.Chain = old, []json.RawMessage{json.RawMessage(`{"fake":1}`)}
	if res := get(t0.Add(time.Minute)); !res.OK() || !strings.Contains(string(res.Body), `"rotations":[{"fake":1}]`) {
		t.Fatalf("rotation chain: %s %s", res.Code, res.Body)
	}
	// Suspended agent: no statement.
	r.f.d.Agents[agent] = &AgentState{Suspended: true}
	if res := get(t0.Add(time.Minute)); res.Code != "forbidden" {
		t.Fatalf("suspended: %q", res.Code)
	}
	delete(r.f.d.Agents, agent)
	// Revoked: no new statement; the old one simply expires.
	if res := featuretest.Call(r.f, r.h, t0, vault.KindApp, "leash.grant.revoke", `{"grant_id":"`+gid+`"}`); !res.OK() {
		t.Fatal(res.Code)
	}
	if res := get(t0.Add(time.Minute)); res.Code != "not_found" {
		t.Fatalf("revoked: %q", res.Code)
	}
	// Another agent's grant is not found.
	r.h.AddDevice("dev-agent2", vault.KindAgent)
	r.w.open = true
	_, g2 := r.issue(t, `{"agent_id":"dev-agent2","scope":"profile.get","expires_at":"2026-10-03T12:30:00.000Z"}`)
	if res := featuretest.Call(r.f, r.h, t0, vault.KindAgent, "leash.status.get", `{"grant_id":"`+g2+`"}`); res.Code != "not_found" {
		t.Fatalf("another agent's grant: %q", res.Code)
	}
}

// §3.6.3, §10.11 (0.13.0): a held vault issues and renews no status
// statement (grants stay); after the check, agents in a session get
// leash.grant.updated with fresh statements. With the hold off (due)
// statements renew as usual.
func TestStatusWhileHeld(t *testing.T) {
	r := newRig(t)
	_, gid := r.issue(t, `{"agent_id":"dev-agent","scope":"profile.get","status_ttl":120}`)
	get := func() featuretest.Result {
		return featuretest.Call(r.f, r.h, t0.Add(time.Minute), vault.KindAgent, "leash.status.get", `{"grant_id":"`+gid+`"}`)
	}
	r.h.Hold = vault.OwnerCheckHeld
	if res := get(); res.Code != "owner_check_required" {
		t.Fatalf("held: %q", res.Code)
	}
	if res := featuretest.Call(r.f, r.h, t0, vault.KindApp, "leash.grant.list", `{}`); !res.OK() || strings.Contains(string(res.Body), `"status_sig"`) {
		t.Fatalf("list while held: %s %s", res.Code, res.Body)
	}
	if len(r.f.Grants()) != 1 {
		t.Fatal("grant removed by the hold")
	}
	r.h.Hold = vault.OwnerCheckDue
	if res := get(); !res.OK() {
		t.Fatalf("hold off: %q", res.Code)
	}
	r.h.Hold = ""
	r.h.Reset()
	r.f.OwnerHoldEnded(vault.NewSession(context.Background(), r.h, vault.PeerInfo{}, t0.Add(time.Hour), nil))
	up := r.h.SentOfType("leash.grant.updated")
	if len(up) != 1 || up[0].To != "dev-agent" || !strings.Contains(string(up[0].Body), `"status_sig"`) {
		t.Fatalf("after the check: %+v", up)
	}
}
