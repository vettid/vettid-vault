package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/envelope"
)

// foldersRefer is an AgentPolicy type that refers each request with the
// folders it is given (approval.pending{folders}, §10.11, 0.93.0), and
// whose handler, run on approval, refers it again with again's while set.
type foldersRefer struct {
	recSink
	folders *ApprovalFolders
	again   *ApprovalFolders
}

func (p *foldersRefer) Types() []TypeSpec {
	return []TypeSpec{{Type: "test.folders", Request: true, From: []string{KindAgent}, AgentPolicy: true}}
}

func (p *foldersRefer) AgentDecision(s *Session, _ string, _ json.RawMessage) AgentDecision {
	s.NoteApproval(json.RawMessage(`{"n":1}`))
	if p.folders != nil {
		s.FoldersApproval(*p.folders)
	}
	return AgentAsk
}

func (p *foldersRefer) Handle(_ context.Context, _ *Session, _ *envelope.Inner) (json.RawMessage, error) {
	if p.again != nil {
		return nil, ReferAgain(Approval{Note: json.RawMessage(`{"n":2}`), Folders: p.again})
	}
	return json.RawMessage(`{"ran":true}`), nil
}

// §6.8, §10.11 (0.93.0): an item.run's approval carries folders {cwd?,
// output?}, each {path, write}, in approval.pending and its pending.list
// entry, stored with the held request; {} for a run with inputs only; a
// referral again carries the new entries; the note is never sent; no
// other approval carries folders.
func TestApprovalFolders(t *testing.T) {
	cases := []struct {
		name string
		f    *ApprovalFolders
		want string
	}{
		{"cwd", &ApprovalFolders{Cwd: &ApprovalFolder{Path: "/home/al/work"}}, `"folders":{"cwd":{"path":"/home/al/work","write":false}}`},
		{"output", &ApprovalFolders{Output: &ApprovalFolder{Path: "/home/al/out", Write: true}}, `"folders":{"output":{"path":"/home/al/out","write":true}}`},
		{"both", &ApprovalFolders{Cwd: &ApprovalFolder{Path: "/a"}, Output: &ApprovalFolder{Path: "/b", Write: true}},
			`"folders":{"cwd":{"path":"/a","write":false},"output":{"path":"/b","write":true}}`},
		{"inputs only", &ApprovalFolders{}, `"folders":{}`},
	}
	for _, c := range cases {
		d := newDevFixture(t)
		app := d.self()
		pol := &foldersRefer{folders: c.f}
		d.m.addFeature(pol)
		sinkOf(d)
		ag := d.addDevice(t, "agent1", KindAgent, 0x70)
		ag.peer.Access = &AccessSession{ID: "s", Expires: time.Now().Add(time.Hour)}
		d.sendAs(ag, "test.folders", `{"x":1}`)
		ap := find(d.inbox(app, ag)["dev1"], ofType("approval.pending"))
		if ap == nil || !bytes.HasSuffix(ap.Body, []byte(c.want+"}")) {
			t.Fatalf("%s: approval.pending: %+v", c.name, ap)
		}
		if bytes.Contains(ap.Body, []byte(`"n"`)) {
			t.Fatalf("%s: the note reached the app: %s", c.name, ap.Body)
		}
		raw, _ := json.Marshal(heldOnly(t, d))
		var back HeldRequest
		if err := json.Unmarshal(raw, &back); err != nil || back.Folders == nil {
			t.Fatalf("%s: not stored: %s", c.name, raw)
		}
		if l := pendingListBodies(t, d, app); len(l) != 1 || !bytes.Contains(l[0], []byte(c.want)) {
			t.Fatalf("%s: pending.list: %s", c.name, l)
		}
		if c.name != "both" {
			continue
		}
		// Approved, the handler refers it again with the new entries.
		pol.again = &ApprovalFolders{Cwd: &ApprovalFolder{Path: "/a", Write: true}}
		d.sendAs(app, "approval.decide", `{"approval_id":"`+bodyStr(t, ap, "approval_id")+`","approve":true}`)
		ap2 := find(d.inbox(app, ag)["dev1"], ofType("approval.pending"))
		const want2 = `"folders":{"cwd":{"path":"/a","write":true}}`
		if ap2 == nil || !bytes.Contains(ap2.Body, []byte(want2)) {
			t.Fatalf("second approval.pending: %+v", ap2)
		}
		if l := pendingListBodies(t, d, app); len(l) != 1 || !bytes.Contains(l[0], []byte(want2)) {
			t.Fatalf("second pending.list: %s", l)
		}
	}
	d := newDevFixture(t)
	app := d.self()
	d.m.addFeature(&foldersRefer{})
	sinkOf(d)
	ag := d.addDevice(t, "agent1", KindAgent, 0x70)
	ag.peer.Access = &AccessSession{ID: "s", Expires: time.Now().Add(time.Hour)}
	d.sendAs(ag, "test.folders", `{"x":1}`)
	if ap := find(d.inbox(app, ag)["dev1"], ofType("approval.pending")); ap == nil || bytes.Contains(ap.Body, []byte(`"folders"`)) {
		t.Fatalf("without folders: %+v", ap)
	}
}

// The setter and ReferAgain copy what they are given: a policy that changes
// its value afterwards changes nothing held.
func TestApprovalFoldersCopied(t *testing.T) {
	f := ApprovalFolders{Cwd: &ApprovalFolder{Path: "/a"}}
	err := ReferAgain(Approval{Folders: &f})
	f.Cwd.Path = "/b"
	if ra, ok := err.(*ReferAgainError); !ok || ra.Approval.Folders.Cwd.Path != "/a" {
		t.Fatalf("ReferAgain shares the folders: %+v", err)
	}
}
