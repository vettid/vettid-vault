package vault

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
)

// changeFail stores step 1 of a DEK replacement and then fails, as a
// credential operation whose CEK rotation fails would.
type changeFail struct{}

func (changeFail) Name() string { return "changefail" }
func (changeFail) Types() []TypeSpec {
	return []TypeSpec{{Type: "test.changefail", Request: true, From: []string{KindApp}}}
}
func (changeFail) Load(json.RawMessage) error     { return nil }
func (changeFail) Save() (json.RawMessage, error) { return json.RawMessage(`{}`), nil }
func (changeFail) Handle(_ context.Context, s *Session, _ *envelope.Inner) (json.RawMessage, error) {
	if err := s.ChangeSecrets(SecretChange{Reason: ReplaceRenew, PIN: testPIN, Password: []byte(rPW), NewUnlockSecret: testSecret2}); err != nil {
		return nil, err
	}
	return nil, NewError("internal", "")
}

// F2: a handler that fails after step 1 changes nothing more: the `next`
// part is dropped and the DEK stays the old one.
func TestHandlerErrorAfterStep1(t *testing.T) {
	d := newDevFixture(t)
	d.m.mu.Lock()
	d.m.addFeature(changeFail{})
	d.m.mu.Unlock()
	if c := d.errorCode(t, "test.changefail", `{}`); c != "internal" {
		t.Fatalf("code %q", c)
	}
	d.m.mu.Lock()
	defer d.m.mu.Unlock()
	if d.m.repl != nil || d.m.hdr.Next != nil || d.m.hdr.DEKVersion != 1 {
		t.Fatalf("after the failed handler: repl %v next %v dek %d", d.m.repl != nil, d.m.hdr.Next, d.m.hdr.DEKVersion)
	}
	h := d.storedHeader()
	if h.Next != nil || h.DEKVersion != 1 {
		t.Fatal("the stored header kept the next part")
	}
}

func (d *devFixture) storedHeader() *Header { return d.fixture.storedHeader() }

// approveFail approves the transfer (step 1 stored) and then fails, as a
// credential approval whose CEK rotation fails would.
type approveFail struct{ id string }

func (approveFail) Name() string { return "approvefail" }
func (approveFail) Types() []TypeSpec {
	return []TypeSpec{{Type: "test.approvefail", Request: true, From: []string{KindApp}}}
}
func (approveFail) Load(json.RawMessage) error     { return nil }
func (approveFail) Save() (json.RawMessage, error) { return json.RawMessage(`{}`), nil }
func (a *approveFail) Handle(_ context.Context, s *Session, _ *envelope.Inner) (json.RawMessage, error) {
	if err := s.ApproveTransfer(a.id, testPIN, []byte(rPW), false); err != nil {
		return nil, err
	}
	return nil, NewError("internal", "")
}

// A failed approval after step 1 ends the transfer (the new phone's secret
// was spent); it is never reopened to answer not_found later.
func TestTransferApprovalErrorAfterStep1(t *testing.T) {
	d := newDevFixture(t)
	sinkOf(d)
	attestOK(d)
	inv := d.transferInvite(t)
	n := newNewcomer(t, 0x50)
	n.hsInitAttest(t, d.m, handshake.PurposeApp, inv.ID, "t1", testAttest)
	n.finish(t, d)
	d.m.mu.Lock()
	d.m.addFeature(&approveFail{id: inv.ID})
	d.m.mu.Unlock()
	if c := d.errorCode(t, "test.approvefail", `{}`); c != "internal" {
		t.Fatalf("code %q", c)
	}
	d.m.mu.Lock()
	defer d.m.mu.Unlock()
	if d.m.st.Transfer != nil || d.m.hdr.Next != nil || d.m.repl != nil || d.m.st.Devices["dev1"] == nil {
		t.Fatalf("transfer %+v next %v", d.m.st.Transfer, d.m.hdr.Next)
	}
	if !d.hasActivity("device.transfer.aborted") {
		t.Fatal("not aborted")
	}
}
