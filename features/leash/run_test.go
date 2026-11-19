package leash

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/features/itemspec"
	"github.com/vettid/vettid-vault/internal/featuretest"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/envelope"
)

var (
	shaA = strings.Repeat("a", 64)
	shaB = strings.Repeat("b", 64)
)

// runBody is an item.run of the item's field f1 with program and sha256;
// extra members are spliced in as given (`,"env":{…}`).
func runBody(item, program, sha, extra string) string {
	return `{"op":"item.run","item_id":"` + item + `","field_id":"f1","program":"` + program + `","sha256":"` + sha +
		`","argv":["x","push"],"cwd":"/home/a","how":"env","name":"TOKEN"` + extra + `}`
}

// setRun gives the agent's item the run way with programs and each.
func (r *rig) setRun(item string, version uint64, each bool, ps ...itemspec.Program) {
	if r.it.ways == nil {
		r.it.ways = map[[2]string]*itemspec.ItemWays{}
	}
	r.it.ways[[2]string{agent, item}] = &itemspec.ItemWays{Version: version, Ways: []string{itemspec.WayUse, itemspec.WayRun},
		Run: &itemspec.RunWays{Programs: ps, Each: each}}
}

// approved runs the handler as the runtime does for an approved held
// request with note.
func (r *rig) approved(now time.Time, body string, note json.RawMessage) (json.RawMessage, error) {
	in := &envelope.Inner{ID: "01JB2Z6V9K3M4N5P6Q7R8S9T0V", Type: "agent.request", TS: now, Body: json.RawMessage(body)}
	from, _ := r.h.Device(agent)
	return r.f.Handle(context.Background(), vault.NewApprovedSession(context.Background(), r.h, from, now, in, note), in)
}

func codeOf(err error) string {
	var he *vault.HandlerError
	if errors.As(err, &he) {
		return he.Code
	}
	return ""
}

// §10.11: way_not_allowed {ways}, program_not_allowed and env_not_allowed
// {names} are counted as refused, with the scope's cooldown; an item no
// rule includes is forbidden, nothing said about its settings; a
// malformed run is left to the handler (bad_request).
func TestRunRefusals(t *testing.T) {
	r := newRig(t)
	r.rule(t, Auto, 0, 60, r.wifi)
	at := t0
	next := func() time.Time { at = at.Add(time.Hour); return at }
	pinned := itemspec.Program{Program: "/usr/bin/git", SHA256: shaA, Path: "/usr/bin/git", Env: []string{"GH_HOST"}}
	cases := []struct {
		name, body, code, refusal string
		setup                     func()
	}{
		{"absent settings", runBody(r.wifi, "/usr/bin/git", shaA, ""), "way_not_allowed", `{"ways":["use"]}`, func() { r.it.ways = nil }},
		{"no run way", runBody(r.wifi, "/usr/bin/git", shaA, ""), "way_not_allowed", `{"ways":["use","reveal"]}`, func() { r.reveal(r.wifi) }},
		{"not bound to it", runBody(r.wifi, "/usr/local/bin/git", shaA, ""), "program_not_allowed", "", func() { r.setRun(r.wifi, 1, false, pinned) }},
		{"env not listed", runBody(r.wifi, "/usr/bin/git", shaA, `,"env":{"GH_HOST":"x","GH_TOKEN":"y"}`), "env_not_allowed", `{"names":["GH_TOKEN"]}`,
			func() { r.setRun(r.wifi, 1, false, pinned) }},
		{"env unbound", runBody(r.wifi, "/usr/bin/git", shaA, `,"env":{"A":"x"}`), "env_not_allowed", `{"names":["A"]}`, func() { r.setRun(r.wifi, 1, true) }},
	}
	for _, c := range cases {
		c.setup()
		r.h.Reset()
		now := next()
		d, s := r.decideS(now, c.body)
		if d != vault.AgentDeny || s.AgentRefusal() == nil || s.AgentRefusal().Code != c.code || c.refusal != "" && string(s.AgentRefusal().Body) != c.refusal {
			t.Fatalf("%s: %v %+v", c.name, d, s.AgentRefusal())
		}
		if !r.h.HasActivity(KindRefused) {
			t.Fatalf("%s: not counted as refused", c.name)
		}
		if cl := r.f.d.Agents[agent].Cool[ScopeItems]; cl == nil || !now.Before(cl.Until) {
			t.Fatalf("%s: no cooldown", c.name)
		}
		// Approved meanwhile (settings changed back and forth): the handler
		// refuses alike, and nothing is read.
		if _, err := r.approved(now, c.body, json.RawMessage(`{"version":1}`)); codeOf(err) != c.code {
			t.Fatalf("%s at approval: %v", c.name, err)
		}
	}
	if r.it.used[r.wifi] != 0 {
		t.Fatalf("read on a refusal: %d", r.it.used[r.wifi])
	}
	// Not included: forbidden, no refusal named.
	if d, s := r.decideS(next(), runBody(r.bank, "/usr/bin/git", shaA, "")); d != vault.AgentDeny || s.AgentRefusal() != nil {
		t.Fatalf("not included: %v %+v", d, s.AgentRefusal())
	}
	// Malformed: left to the handler, which says bad_request.
	bad := strings.Replace(runBody(r.wifi, "/usr/bin/git", shaA, ""), `"cwd":"/home/a"`, `"cwd":"home"`, 1)
	if d, _ := r.decideS(next(), bad); d != vault.AgentAllow {
		t.Fatalf("malformed decided: %v", d)
	}
	if res := featuretest.Call(r.f, r.h, at, vault.KindAgent, "agent.request", bad); res.Code != "bad_request" {
		t.Fatalf("malformed: %q", res.Code)
	}
}

// §10.11: what is referred, with which flags and previous pin; a pinned
// run with each false is allowed at once and answered the value, counted
// in the windows, the uses and the summarised audit (leash.item.run).
func TestRunReferrals(t *testing.T) {
	git := itemspec.Program{Program: "/usr/bin/git", SHA256: shaA, Path: "/usr/bin/git"}
	cases := []struct {
		name     string
		each     bool
		ps       []itemspec.Program
		program  string
		sha      string
		ask      bool
		flags    string
		previous string
	}{
		{"pinned", false, []itemspec.Program{git}, "/usr/bin/git", shaA, false, "", ""},
		{"pinned, each", true, []itemspec.Program{git}, "/usr/bin/git", shaA, true, "", ""},
		{"unbound", false, nil, "/usr/bin/git", shaA, true, "unbound_program", ""},
		{"unrecorded", false, []itemspec.Program{{Program: "git"}}, "/usr/bin/git", shaA, true, "program_unrecorded", ""},
		{"changed", false, []itemspec.Program{git}, "/usr/bin/git", shaB, true, "program_changed", shaA + " /usr/bin/git"},
		{"moved", false, []itemspec.Program{{Program: "git", SHA256: shaA, Path: "/usr/bin/git"}}, "/tmp/git", shaA, true, "program_changed", shaA + " /usr/bin/git"},
		{"pinned shell", false, []itemspec.Program{{Program: "/bin/sh", SHA256: shaA, Path: "/bin/sh"}}, "/bin/sh", shaA, true, "shell", ""},
		{"pinned interpreter", false, []itemspec.Program{{Program: "python3", SHA256: shaA, Path: "/usr/bin/python3"}}, "/usr/bin/python3", shaA, true, "", ""},
	}
	for _, c := range cases {
		r := newRig(t)
		gid := r.rule(t, Auto, 0, 60, r.wifi)
		r.setRun(r.wifi, 4, c.each, c.ps...)
		body := runBody(r.wifi, c.program, c.sha, "")
		d, s := r.decideS(t0, body)
		if r.f.d.Grants[gid].HourN != 1 {
			t.Fatalf("%s: windows not counted", c.name)
		}
		if !c.ask {
			if d != vault.AgentAllow {
				t.Fatalf("%s: %v", c.name, d)
			}
			res := featuretest.Call(r.f, r.h, t0, vault.KindAgent, "agent.request", body)
			if !res.OK() || string(res.Body) != `{"item_id":"`+r.wifi+`","field_id":"f1","value":"hunter22"}` || r.it.used[r.wifi] != 1 || !r.h.HasActivity(KindRun) {
				t.Fatalf("%s: %q %s used=%d", c.name, res.Code, res.Body, r.it.used[r.wifi])
			}
			continue
		}
		a := s.HeldApproval()
		if d != vault.AgentAsk || strings.Join(a.Flags, ",") != c.flags || strings.TrimSpace(a.PreviousSHA256+" "+a.PreviousPath) != c.previous {
			t.Fatalf("%s: %v %+v", c.name, d, a)
		}
		var n runNote
		if err := json.Unmarshal(a.Note, &n); err != nil || n.Version != 4 || strings.Join(n.Flags, ",") != c.flags {
			t.Fatalf("%s: note %s", c.name, a.Note)
		}
		// A referred run sent straight to the handler (no approval): forbidden,
		// nothing read, no pin recorded.
		if res := featuretest.Call(r.f, r.h, t0, vault.KindAgent, "agent.request", body); res.Code != "forbidden" || r.it.used[r.wifi] != 0 || r.stored(r.wifi).Version != 4 {
			t.Fatalf("%s: unapproved: %q", c.name, res.Code)
		}
	}
	// inline_code: an interpreter with -c (and a shell's -c is not one).
	r := newRig(t)
	r.rule(t, Auto, 0, 60, r.wifi)
	r.setRun(r.wifi, 1, false)
	inline := strings.Replace(runBody(r.wifi, "/usr/bin/node", shaA, ""), `["x","push"]`, `["node","-e","1"]`, 1)
	if _, s := r.decideS(t0, inline); strings.Join(s.ApprovalFlags(), ",") != "inline_code,unbound_program" {
		t.Fatalf("inline: %v", s.ApprovalFlags())
	}
	sh := strings.Replace(runBody(r.wifi, "/bin/bash", shaA, ""), `["x","push"]`, `["bash","-c","x"]`, 1)
	if _, s := r.decideS(t0.Add(time.Second), sh); strings.Join(s.ApprovalFlags(), ",") != "shell,unbound_program" {
		t.Fatalf("shell -c: %v", s.ApprovalFlags())
	}
	// Past the referral cap a referred run is throttled, and nothing is
	// counted in the windows.
	rc := newRig(t)
	gid := rc.rule(t, Auto, 0, 3600, rc.wifi)
	rc.setRun(rc.wifi, 1, true)
	rc.f.agent(vault.NewSession(context.Background(), rc.h, vault.PeerInfo{}, t0, nil), agent).Referred = MaxReferralsPerHour
	g := rc.f.d.Grants[gid]
	hour, day := g.HourN, g.DayN
	if d, _ := rc.decideS(t0, runBody(rc.wifi, "/usr/bin/git", shaA, "")); d != vault.AgentDeny || g.HourN != hour || g.DayN != day {
		t.Fatalf("past the cap: %v, windows %d/%d", d, g.HourN, g.DayN)
	}
	// An address field cannot be used.
	r.setRun(r.wifi, 2, false, itemspec.Program{Program: "/usr/bin/git", SHA256: shaA, Path: "/usr/bin/git"})
	addr := strings.Replace(runBody(r.wifi, "/usr/bin/git", shaA, ""), `"field_id":"f1"`, `"field_id":"f2"`, 1)
	if res := featuretest.Call(r.f, r.h, t0.Add(time.Hour), vault.KindAgent, "agent.request", addr); res.Code != "not_found" {
		t.Fatalf("address field: %q", res.Code)
	}
}

// §10.11 (0.85.3): approving a run flagged program_unrecorded records its
// sha256 and program as the entry's pin (version up, leash.item.changed
// announced and audited), after which the same run goes unasked; one
// flagged program_changed replaces the pin.
func TestRunApprovalRecordsPin(t *testing.T) {
	r := newRig(t)
	r.rule(t, Auto, 0, 60, r.wifi)
	r.setRun(r.wifi, 1, false, itemspec.Program{Program: "git", Env: []string{"GH_HOST"}})
	body := runBody(r.wifi, "/usr/bin/git", shaA, "")
	d, s := r.decideS(t0, body)
	if d != vault.AgentAsk {
		t.Fatal(d)
	}
	r.h.Reset()
	out, err := r.approved(t0, body, s.HeldApproval().Note)
	if err != nil || !strings.Contains(string(out), `"value":"hunter22"`) {
		t.Fatalf("approved: %s %v", out, err)
	}
	w := r.stored(r.wifi)
	if p := w.Run.Programs[0]; p.SHA256 != shaA || p.Path != "/usr/bin/git" || p.Program != "git" || len(p.Env) != 1 || w.Version != 2 {
		t.Fatalf("pin: %+v v%d", p, w.Version)
	}
	if k := syncKinds(r.h); len(k) != 1 || !strings.Contains(k[0], `"kind":"leash.item.changed"`) || !strings.Contains(k[0], `"version":2`) ||
		!r.h.HasActivity("leash.item.changed") {
		t.Fatalf("not announced: %v", k)
	}
	if d, _ := r.decideS(t0.Add(time.Second), body); d != vault.AgentAllow {
		t.Fatalf("after the pin: %v", d)
	}
	// Changed file: approved, the pin is replaced.
	changed := runBody(r.wifi, "/usr/bin/git", shaB, "")
	d, s = r.decideS(t0.Add(2*time.Second), changed)
	if d != vault.AgentAsk || s.HeldApproval().PreviousSHA256 != shaA {
		t.Fatalf("changed: %v %+v", d, s.HeldApproval())
	}
	if _, err := r.approved(t0.Add(2*time.Second), changed, s.HeldApproval().Note); err != nil {
		t.Fatal(err)
	}
	if p := r.stored(r.wifi).Run.Programs[0]; p.SHA256 != shaB || r.stored(r.wifi).Version != 3 {
		t.Fatalf("pin not replaced: %+v", p)
	}
	// An approved run with no pin flag (each true) records nothing.
	r.it.ways[[2]string{agent, r.wifi}].Run.Each = true
	d, s = r.decideS(t0.Add(3*time.Second), changed)
	if d != vault.AgentAsk {
		t.Fatal(d)
	}
	r.h.Reset()
	if _, err := r.approved(t0.Add(3*time.Second), changed, s.HeldApproval().Note); err != nil || r.stored(r.wifi).Version != 3 || len(syncKinds(r.h)) != 0 {
		t.Fatalf("recorded without a pin flag: %v v%d", err, r.stored(r.wifi).Version)
	}
	// An approved run without its note is never run.
	if _, err := r.approved(t0.Add(4*time.Second), changed, nil); codeOf(err) != "forbidden" {
		t.Fatalf("no note: %v", err)
	}
	// An approval that showed another pin situation than the run now has,
	// at the same version (a damaged note): referred again, nothing
	// recorded, nothing read.
	r.it.ways[[2]string{agent, r.wifi}].Run.Each = false
	used := r.it.used[r.wifi]
	other := runBody(r.wifi, "/usr/bin/git", shaA, "")
	_, err = r.approved(t0.Add(5*time.Second), other, json.RawMessage(`{"version":3,"flags":["program_unrecorded"]}`))
	var ra *vault.ReferAgainError
	if !errors.As(err, &ra) || ra.Approval.PreviousSHA256 != shaB || r.stored(r.wifi).Run.Programs[0].SHA256 != shaB || r.it.used[r.wifi] != used {
		t.Fatalf("damaged note: %v", err)
	}
}

// §10.11 (0.85.3): settings that change while a run waits. A change that
// refuses the run: that refusal, never the value. Another approval that
// recorded another pin meanwhile: referred again, a new referral, with the
// new pin as previous, forbidden past the cap; the same pin recorded
// meanwhile: the approval stands, nothing recorded again.
func TestRunSettingsChangedWhileHeld(t *testing.T) {
	r := newRig(t)
	r.rule(t, Auto, 0, 3600, r.wifi)
	r.setRun(r.wifi, 1, false, itemspec.Program{Program: "git"})
	a := runBody(r.wifi, "/usr/bin/git", shaA, "")
	b := runBody(r.wifi, "/usr/bin/git", shaB, "")
	_, sa := r.decideS(t0, a)
	_, sb := r.decideS(t0, b)
	_, sa2 := r.decideS(t0, a)
	if _, err := r.approved(t0, a, sa.HeldApproval().Note); err != nil {
		t.Fatal(err)
	}
	// b was shown as unrecorded; the pin is now a's.
	st := r.f.d.Agents[agent]
	before := st.Referred
	_, err := r.approved(t0, b, sb.HeldApproval().Note)
	var ra *vault.ReferAgainError
	if !errors.As(err, &ra) || strings.Join(ra.Approval.Flags, ",") != "program_changed" || ra.Approval.PreviousSHA256 != shaA ||
		ra.Approval.PreviousPath != "/usr/bin/git" || st.Referred != before+1 {
		t.Fatalf("b: %v", err)
	}
	var n runNote
	if json.Unmarshal(ra.Approval.Note, &n) != nil || n.Version != 2 {
		t.Fatalf("new note: %s", ra.Approval.Note)
	}
	if r.stored(r.wifi).Run.Programs[0].SHA256 != shaA || r.stored(r.wifi).Version != 2 {
		t.Fatal("b's pin recorded on the old approval")
	}
	// Its new approval, approved: records b.
	if _, err := r.approved(t0, b, ra.Approval.Note); err != nil || r.stored(r.wifi).Run.Programs[0].SHA256 != shaB || r.stored(r.wifi).Version != 3 {
		t.Fatalf("b re-approved: %v %+v", err, r.stored(r.wifi).Run.Programs[0])
	}
	// a again (held before b's pin): now program_changed against b: again.
	if _, err := r.approved(t0, a, sa2.HeldApproval().Note); !errors.As(err, &ra) || ra.Approval.PreviousSHA256 != shaB {
		t.Fatalf("a2: %v", err)
	}
	// Past the cap: forbidden, nothing held, nothing counted but the
	// throttled refusal; the member is told once.
	st.Referred = MaxReferralsPerHour
	r.h.Reset()
	if _, err := r.approved(t0, a, sa2.HeldApproval().Note); codeOf(err) != "forbidden" || st.Referred != MaxReferralsPerHour ||
		!r.h.HasActivity("leash.referrals_limited") || st.Counts[KindThrottled] == 0 {
		t.Fatalf("past the cap: %v", err)
	}
	// Two runs held as program_changed against the same pin P0 (a): the
	// first approved records its file; the second's approval showed P0, not
	// the new pin, so it is referred again, showing the new one.
	rc := newRig(t)
	rc.rule(t, Auto, 0, 3600, rc.wifi)
	rc.setRun(rc.wifi, 1, false, itemspec.Program{Program: "git", SHA256: shaA, Path: "/usr/bin/git"})
	shaC := strings.Repeat("c", 64)
	b1 := runBody(rc.wifi, "/usr/bin/git", shaB, "")
	c1 := runBody(rc.wifi, "/usr/bin/git", shaC, "")
	_, sb1 := rc.decideS(t0, b1)
	_, sc1 := rc.decideS(t0, c1)
	if strings.Join(sc1.HeldApproval().Flags, ",") != "program_changed" || sc1.HeldApproval().PreviousSHA256 != shaA {
		t.Fatalf("c1 held: %+v", sc1.HeldApproval())
	}
	if _, err := rc.approved(t0, b1, sb1.HeldApproval().Note); err != nil || rc.stored(rc.wifi).Run.Programs[0].SHA256 != shaB {
		t.Fatalf("b1: %v", err)
	}
	used := rc.it.used[rc.wifi]
	if _, err := rc.approved(t0, c1, sc1.HeldApproval().Note); !errors.As(err, &ra) || ra.Approval.PreviousSHA256 != shaB ||
		rc.stored(rc.wifi).Run.Programs[0].SHA256 != shaB || rc.it.used[rc.wifi] != used {
		t.Fatalf("c1 approved against another pin: %v", err)
	}
	// Moved instead of changed: the same, through the previous path.
	rp := newRig(t)
	rp.rule(t, Auto, 0, 3600, rp.wifi)
	rp.setRun(rp.wifi, 1, false, itemspec.Program{Program: "git", SHA256: shaA, Path: "/usr/bin/git"})
	m1 := runBody(rp.wifi, "/opt/git", shaB, "")
	m2 := runBody(rp.wifi, "/opt/x/git", shaB, "")
	_, sm1 := rp.decideS(t0, m1)
	_, sm2 := rp.decideS(t0, m2)
	if _, err := rp.approved(t0, m1, sm1.HeldApproval().Note); err != nil {
		t.Fatal(err)
	}
	// m2 showed the previous pin (A, /usr/bin/git); it is now (B, /opt/git).
	if _, err := rp.approved(t0, m2, sm2.HeldApproval().Note); !errors.As(err, &ra) || ra.Approval.PreviousPath != "/opt/git" {
		t.Fatalf("m2: %v", err)
	}
	// Only the previous path differs (same hash, another folder).
	rq := newRig(t)
	rq.rule(t, Auto, 0, 3600, rq.wifi)
	rq.setRun(rq.wifi, 1, false, itemspec.Program{Program: "git", SHA256: shaA, Path: "/usr/bin/git"})
	q1 := runBody(rq.wifi, "/opt/git", shaA, "")
	q2 := runBody(rq.wifi, "/opt/y/git", shaA, "")
	_, sq1 := rq.decideS(t0, q1)
	_, sq2 := rq.decideS(t0, q2)
	if _, err := rq.approved(t0, q1, sq1.HeldApproval().Note); err != nil {
		t.Fatal(err)
	}
	if _, err := rq.approved(t0, q2, sq2.HeldApproval().Note); !errors.As(err, &ra) || ra.Approval.PreviousPath != "/opt/git" || ra.Approval.PreviousSHA256 != shaA {
		t.Fatalf("q2: %v", err)
	}
	// The same pin recorded meanwhile: the approval stands.
	r2 := newRig(t)
	r2.rule(t, Auto, 0, 60, r2.wifi)
	r2.setRun(r2.wifi, 1, false, itemspec.Program{Program: "git"})
	_, s1 := r2.decideS(t0, a)
	_, s2 := r2.decideS(t0, a)
	if _, err := r2.approved(t0, a, s1.HeldApproval().Note); err != nil {
		t.Fatal(err)
	}
	r2.h.Reset()
	if out, err := r2.approved(t0, a, s2.HeldApproval().Note); err != nil || !strings.Contains(string(out), "hunter22") || r2.stored(r2.wifi).Version != 2 || len(syncKinds(r2.h)) != 0 {
		t.Fatalf("same pin: %s %v v%d", out, err, r2.stored(r2.wifi).Version)
	}
	// A change that refuses the run while it waits.
	r3 := newRig(t)
	r3.rule(t, Auto, 0, 60, r3.wifi)
	r3.setRun(r3.wifi, 1, false, itemspec.Program{Program: "git", Env: []string{"GH_HOST"}})
	withEnv := runBody(r3.wifi, "/usr/bin/git", shaA, `,"env":{"GH_HOST":"x"}`)
	_, s3 := r3.decideS(t0, withEnv)
	for _, c := range []struct {
		code string
		w    *itemspec.ItemWays
	}{
		{"env_not_allowed", &itemspec.ItemWays{Version: 2, Ways: []string{itemspec.WayUse, itemspec.WayRun}, Run: &itemspec.RunWays{Programs: []itemspec.Program{{Program: "git"}}}}},
		{"program_not_allowed", &itemspec.ItemWays{Version: 3, Ways: []string{itemspec.WayUse, itemspec.WayRun}, Run: &itemspec.RunWays{Programs: []itemspec.Program{{Program: "gh"}}}}},
		{"way_not_allowed", &itemspec.ItemWays{Version: 4, Ways: []string{itemspec.WayUse}}},
	} {
		r3.it.ways[[2]string{agent, r3.wifi}] = c.w
		out, err := r3.approved(t0, withEnv, s3.HeldApproval().Note)
		if codeOf(err) != c.code || out != nil || r3.it.used[r3.wifi] != 0 || r3.stored(r3.wifi).Version != c.w.Version {
			t.Fatalf("%s: %s %v", c.code, out, err)
		}
	}
}
