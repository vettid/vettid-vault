package leash

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/features/itemspec"
	"github.com/vettid/vettid-vault/internal/featuretest"
	"github.com/vettid/vettid-vault/vault"
)

// setFolders gives the agent's item the run way, git pinned, each false,
// with folders fs.
func (r *rig) setFolders(item string, version uint64, fs ...itemspec.Folder) {
	r.setRun(item, version, false, itemspec.Program{Program: "/usr/bin/git", SHA256: shaA, Path: "/usr/bin/git"})
	r.it.ways[[2]string{agent, item}].Run.Folders = fs
}

var (
	workRO = itemspec.Folder{Path: "/home/al/work"}
	outRW  = itemspec.Folder{Path: "/home/al/out", Write: true}
)

// §10.11 (0.93.0): a cwd, an input or an output the folders do not cover
// is answered cwd_not_allowed {where, path}, counted as refused with the
// cooldown, and refused alike when approved.
func TestRunCwdNotAllowed(t *testing.T) {
	r := newRig(t)
	r.rule(t, Auto, 0, 60, r.wifi)
	at := t0
	next := func() time.Time { at = at.Add(time.Hour); return at }
	cases := []struct{ name, extra, want string }{
		{"cwd outside", `,"cwd":"/home/al/work2"`, `{"where":"cwd","path":"/home/al/work2"}`},
		{"cwd case", `,"cwd":"/home/al/Work"`, `{"where":"cwd","path":"/home/al/Work"}`},
		{"input outside", `,"inputs":[{"path":"/home/al/work/a","size":1},{"path":"/tmp/b","size":1}]`, `{"where":"input","path":"/tmp/b"}`},
		{"output read-only", `,"output":{"folder":"/home/al/work","names":["x"]}`, `{"where":"output","path":"/home/al/work"}`},
		{"output outside", `,"output":{"folder":"/tmp","names":["x"]}`, `{"where":"output","path":"/tmp"}`},
	}
	for _, c := range cases {
		r.setFolders(r.wifi, 1, workRO, outRW)
		r.h.Reset()
		now := next()
		body := runBody(r.wifi, "/usr/bin/git", shaA, c.extra)
		d, s := r.decideS(now, body)
		if d != vault.AgentDeny || s.AgentRefusal() == nil || s.AgentRefusal().Code != "cwd_not_allowed" || string(s.AgentRefusal().Body) != c.want {
			t.Fatalf("%s: %v %+v", c.name, d, s.AgentRefusal())
		}
		if !r.h.HasActivity(KindRefused) {
			t.Fatalf("%s: not counted as refused", c.name)
		}
		if cl := r.f.d.Agents[agent].Cool[ScopeItems]; cl == nil || !now.Before(cl.Until) {
			t.Fatalf("%s: no cooldown", c.name)
		}
		if _, err := r.approved(now, body, json.RawMessage(`{"version":1}`)); codeOf(err) != "cwd_not_allowed" {
			t.Fatalf("%s at approval: %v", c.name, err)
		}
	}
	// With no folders, any cwd, input or output is refused.
	r.setFolders(r.wifi, 1)
	if d, s := r.decideS(next(), runBody(r.wifi, "/usr/bin/git", shaA, `,"cwd":"/home/al/work"`)); d != vault.AgentDeny || s.AgentRefusal().Code != "cwd_not_allowed" {
		t.Fatalf("no folders: %v %+v", d, s.AgentRefusal())
	}
	if r.it.used[r.wifi] != 0 {
		t.Fatalf("read on a refusal: %d", r.it.used[r.wifi])
	}
}

// §10.11 (0.93.0): a run with a cwd, inputs or an output is referred even
// pinned with each false, flagged member_folder or member_files, its
// approval carrying the matched folders entries from the settings ({} for
// inputs only); approved, it is answered the value. No cwd: allowed at
// once with no folders.
func TestRunFoldersReferred(t *testing.T) {
	cases := []struct {
		name, extra, flags string
		want               vault.ApprovalFolders
	}{
		{"cwd", `,"cwd":"/home/al/work/site"`, "member_folder", vault.ApprovalFolders{Cwd: &vault.ApprovalFolder{Path: "/home/al/work"}}},
		{"inputs", `,"inputs":[{"path":"/home/al/work/a.pdf","size":3}]`, "member_files", vault.ApprovalFolders{}},
		{"output", `,"output":{"folder":"/home/al/out/sub","names":["r.pdf"]}`, "member_files",
			vault.ApprovalFolders{Output: &vault.ApprovalFolder{Path: "/home/al/out", Write: true}}},
		{"all", `,"cwd":"/home/al/out","inputs":[{"path":"/home/al/work/a","size":0}],"output":{"folder":"/home/al/out","names":["x"]}`,
			"member_folder,member_files", vault.ApprovalFolders{Cwd: &vault.ApprovalFolder{Path: "/home/al/out", Write: true},
				Output: &vault.ApprovalFolder{Path: "/home/al/out", Write: true}}},
	}
	for _, c := range cases {
		r := newRig(t)
		r.rule(t, Auto, 0, 60, r.wifi)
		r.setFolders(r.wifi, 3, workRO, outRW)
		body := runBody(r.wifi, "/usr/bin/git", shaA, c.extra)
		d, s := r.decideS(t0, body)
		a := s.HeldApproval()
		if d != vault.AgentAsk || strings.Join(a.Flags, ",") != c.flags || a.Folders == nil {
			t.Fatalf("%s: %v %+v", c.name, d, a)
		}
		if got, want := foldersOf(a.Folders), foldersOf(&c.want); got != want {
			t.Fatalf("%s: folders %s, want %s", c.name, got, want)
		}
		out, err := r.approved(t0, body, a.Note)
		if err != nil || !strings.Contains(string(out), `"value":"hunter22"`) {
			t.Fatalf("%s approved: %s %v", c.name, out, err)
		}
	}
	// No cwd, no files: allowed at once, no folders needed.
	r := newRig(t)
	r.rule(t, Auto, 0, 60, r.wifi)
	r.setFolders(r.wifi, 1)
	if d, s := r.decideS(t0, runBody(r.wifi, "/usr/bin/git", shaA, "")); d != vault.AgentAllow || s.HeldApproval().Folders != nil {
		t.Fatalf("no cwd: %v %+v", d, s.HeldApproval())
	}
	// A run without folders carries none on its approval.
	r.setRun(r.wifi, 2, true, itemspec.Program{Program: "/usr/bin/git", SHA256: shaA, Path: "/usr/bin/git"})
	if d, s := r.decideS(t0.Add(time.Second), runBody(r.wifi, "/usr/bin/git", shaA, "")); d != vault.AgentAsk || s.HeldApproval().Folders != nil {
		t.Fatalf("each, no cwd: %v %+v", d, s.HeldApproval())
	}
}

func foldersOf(f *vault.ApprovalFolders) string { b, _ := json.Marshal(f); return string(b) }

// §10.11 (0.93.0) "An approval is judged again": a run held in a member
// folder whose entry's write changed is referred again, with the new
// entry; whose entry is gone, or whose output entry lost write, is
// refused cwd_not_allowed at approval, never answered the value.
func TestRunFoldersJudgedAgain(t *testing.T) {
	cwdBody := func(r *rig) string { return runBody(r.wifi, "/usr/bin/git", shaA, `,"cwd":"/home/al/work"`) }
	outBody := func(r *rig) string {
		return runBody(r.wifi, "/usr/bin/git", shaA, `,"output":{"folder":"/home/al/out","names":["x"]}`)
	}
	hold := func(body func(*rig) string) (*rig, string, json.RawMessage) {
		r := newRig(t)
		r.rule(t, Auto, 0, 60, r.wifi)
		r.setFolders(r.wifi, 1, workRO, outRW)
		b := body(r)
		d, s := r.decideS(t0, b)
		if d != vault.AgentAsk {
			t.Fatalf("not held: %v", d)
		}
		return r, b, s.HeldApproval().Note
	}
	// write turned on for the cwd's entry: referred again with it.
	r, b, note := hold(cwdBody)
	r.setFolders(r.wifi, 2, itemspec.Folder{Path: "/home/al/work", Write: true}, outRW)
	_, err := r.approved(t0, b, note)
	var ra *vault.ReferAgainError
	if !errors.As(err, &ra) || ra.Approval.Folders == nil || ra.Approval.Folders.Cwd == nil || !ra.Approval.Folders.Cwd.Write ||
		strings.Join(ra.Approval.Flags, ",") != "member_folder" {
		t.Fatalf("write on: %v", err)
	}
	if r.it.used[r.wifi] != 0 {
		t.Fatal("read on a referral")
	}
	// The re-referral's note is itself one an approval passes.
	if out, err := r.approved(t0, b, ra.Approval.Note); err != nil || !strings.Contains(string(out), "hunter22") {
		t.Fatalf("approved again: %s %v", out, err)
	}
	// The entry removed: refused.
	r, b, note = hold(cwdBody)
	r.setFolders(r.wifi, 2, outRW)
	if _, err := r.approved(t0, b, note); codeOf(err) != "cwd_not_allowed" {
		t.Fatalf("entry removed: %v", err)
	}
	// The output's entry lost write: refused.
	r, b, note = hold(outBody)
	r.setFolders(r.wifi, 2, workRO, itemspec.Folder{Path: "/home/al/out"})
	if _, err := r.approved(t0, b, note); codeOf(err) != "cwd_not_allowed" {
		t.Fatalf("write off: %v", err)
	}
	// The output's entry replaced by a wider one that still covers it with
	// write: another entry than the approval showed, so referred again.
	r, b, note = hold(outBody)
	r.setFolders(r.wifi, 2, itemspec.Folder{Path: "/home", Write: true}) // no nesting: alone
	if _, err := r.approved(t0, b, note); !errors.As(err, &ra) || ra.Approval.Folders.Output == nil || ra.Approval.Folders.Output.Path != "/home" {
		t.Fatalf("output entry replaced: %v", err)
	}
	// Other folders changed, the matched entry not: the approval stands.
	r, b, note = hold(cwdBody)
	r.setFolders(r.wifi, 2, workRO, outRW, itemspec.Folder{Path: "/home/al/more"})
	if out, err := r.approved(t0, b, note); err != nil || !strings.Contains(string(out), "hunter22") {
		t.Fatalf("other entries changed: %s %v", out, err)
	}
	// A note held before 0.93.0 (no folders) for a run with a cwd: referred
	// again, never answered on an approval that showed no folder.
	r, b, _ = hold(cwdBody)
	if _, err := r.approved(t0, b, json.RawMessage(`{"version":1}`)); !errors.As(err, &ra) {
		t.Fatalf("old note: %v", err)
	}
	// Likewise a run with inputs only, which matches no entry: a vault before
	// 0.93.0 ignored the member, so its approval never showed the files.
	r, b, _ = hold(func(r *rig) string {
		return runBody(r.wifi, "/usr/bin/git", shaA, `,"inputs":[{"path":"/home/al/work/a","size":1}]`)
	})
	if _, err := r.approved(t0, b, json.RawMessage(`{"version":1}`)); !errors.As(err, &ra) {
		t.Fatalf("old note, inputs only: %v", err)
	}
}

// §10.11 (0.93.0): a run that would record a pin and whose matched folders
// entry changed while it waited is referred again before anything is
// recorded: the pin is recorded only on an approval that stands.
func TestRunFoldersReferredBeforeThePin(t *testing.T) {
	r := newRig(t)
	r.rule(t, Auto, 0, 60, r.wifi)
	r.setRun(r.wifi, 1, false, itemspec.Program{Program: "git"}) // no pin yet: program_unrecorded
	r.it.ways[[2]string{agent, r.wifi}].Run.Folders = []itemspec.Folder{workRO}
	body := runBody(r.wifi, "/usr/bin/git", shaA, `,"cwd":"/home/al/work"`)
	d, s := r.decideS(t0, body)
	if d != vault.AgentAsk || strings.Join(s.HeldApproval().Flags, ",") != "program_unrecorded,member_folder" {
		t.Fatalf("held: %v %+v", d, s.HeldApproval())
	}
	r.it.ways[[2]string{agent, r.wifi}].Run.Folders = []itemspec.Folder{{Path: "/home/al/work", Write: true}}
	r.h.Reset()
	_, err := r.approved(t0, body, s.HeldApproval().Note)
	var ra *vault.ReferAgainError
	if !errors.As(err, &ra) {
		t.Fatalf("not referred again: %v", err)
	}
	if w := r.stored(r.wifi); w.Version != 1 || w.Run.Programs[0].SHA256 != "" || r.h.HasActivity("leash.item.changed") || len(syncKinds(r.h)) != 0 {
		t.Fatalf("a pin recorded on an approval referred again: %+v v%d", w.Run.Programs[0], w.Version)
	}
}

// §10.11 (0.93.0) "A binding change": adding a folder, changing a path and
// turning write on are widenings, credential_locked outside the unlock
// window; removing one, turning write off and emptying folders are not.
// leash.item.list and .set answer run.folders, an empty list when none.
func TestItemSetFolders(t *testing.T) {
	r := newRig(t)
	r.rule(t, Auto, 0, 60, r.wifi)
	setWith := func(version int, folders string) featuretest.Result {
		v := ""
		if version > 0 {
			v = `"version":` + string(rune('0'+version)) + `,`
		}
		return r.itemSet(`{"agent_id":"dev-agent","item_id":"` + r.wifi + `",` + v + `"ways":["use","run"],"run":{"programs":[{"program":"git"}],"folders":[` + folders + `]}}`)
	}
	res := setWith(0, `{"path":"/home/al/work"},{"path":"/home/al/out","write":true}`)
	if !res.OK() || !strings.Contains(string(res.Body), `"folders":[{"path":"/home/al/work","write":false},{"path":"/home/al/out","write":true}]`) {
		t.Fatalf("set: %s %s", res.Code, res.Body)
	}
	r.w.open = false
	before := r.stored(r.wifi).Clone()
	for name, folders := range map[string]string{
		"added":    `{"path":"/home/al/work"},{"path":"/home/al/out","write":true},{"path":"/home/al/more"}`,
		"path":     `{"path":"/home/al/work2"},{"path":"/home/al/out","write":true}`,
		"write on": `{"path":"/home/al/work","write":true},{"path":"/home/al/out","write":true}`,
	} {
		if res := setWith(1, folders); res.Code != "credential_locked" {
			t.Errorf("%s: %q", name, res.Code)
		}
	}
	if !r.stored(r.wifi).Equal(before) {
		t.Fatal("a refused widening changed the settings")
	}
	for i, folders := range []string{`{"path":"/home/al/work"},{"path":"/home/al/out"}`, `{"path":"/home/al/out"}`, ``} {
		if res := setWith(i+1, folders); !res.OK() {
			t.Fatalf("narrowing %d: %q", i, res.Code)
		}
	}
	if res := setWith(4, `{"path":"/home/al"},{"path":"/home/al/work"}`); res.Code != "bad_request" {
		t.Fatalf("nested: %q", res.Code)
	}
	list := featuretest.Call(r.f, r.h, t0, vault.KindApp, "leash.item.list", `{"agent_id":"dev-agent","item_id":"`+r.wifi+`"}`)
	if !list.OK() || !strings.Contains(string(list.Body), `"folders":[]`) {
		t.Fatalf("list: %s %s", list.Code, list.Body)
	}
}
