package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
)

// keyHolder approves the transfer and holds a credential key rotation
// statement, as the credential feature's approval does (§11.14.10), and
// sends held statements to a connection when the runtime asks.
type keyHolder struct {
	id     string
	stmt   []byte
	fail   bool
	conn   string
	sent   [][]byte
	taken  [][]byte
	rotErr error
}

func (*keyHolder) Name() string { return "keyholder" }
func (*keyHolder) Types() []TypeSpec {
	return []TypeSpec{{Type: "test.approvehold", Request: true, From: []string{KindApp}},
		{Type: "test.takefail", Request: true, From: []string{KindApp}}}
}
func (*keyHolder) Load(json.RawMessage) error     { return nil }
func (*keyHolder) Save() (json.RawMessage, error) { return json.RawMessage(`{}`), nil }
func (k *keyHolder) Handle(_ context.Context, s *Session, in *envelope.Inner) (json.RawMessage, error) {
	if in.Type == "test.takefail" {
		// As credential.rotate: a rotation of ik and kem is refused while
		// a statement is held; the handler takes the statements, then fails.
		k.rotErr = s.RotateIdentity()
		k.taken = s.TakeHeldKeyRotations()
		return nil, NewError("internal", "")
	}
	if err := s.ApproveTransfer(k.id, testPIN, []byte(rPW), false); err != nil {
		return nil, err
	}
	if err := s.HoldKeyRotation(k.stmt); err != nil {
		return nil, err
	}
	if k.fail {
		return nil, NewError("internal", "")
	}
	return json.RawMessage(`{}`), nil
}
func (k *keyHolder) SendKeyRotations(s *Session, stmts [][]byte) {
	for _, st := range stmts {
		k.sent = append(k.sent, st)
		s.Record(Activity{Kind: "test.statement_sent"})
		if k.conn != "" {
			_ = s.SendToConnection(k.conn, "connection.authenticate.rotated", append([]byte(`{"chain":[`), append(st, "]}"...)...))
		}
	}
}

var heldStmt = []byte(`{"v":1,"old_key":"K0","new_key":"K1"}`)

// approvedWithHeld runs a transfer to its approval through a handler that
// holds heldStmt; the batch's flush stores steps 2 and 3.
func approvedWithHeld(t *testing.T, d *devFixture, k *keyHolder) {
	t.Helper()
	attestOK(d)
	inv := d.transferInvite(t)
	n := newNewcomer(t, 0x50)
	n.hsInitAttest(t, d.m, handshake.PurposeApp, inv.ID, "t1", testAttest)
	n.finish(t, d)
	k.id, k.stmt = inv.ID, heldStmt
	d.m.mu.Lock()
	d.m.addFeature(k)
	d.m.mu.Unlock()
	d.fixture.opts.Features = append(d.fixture.opts.Features, k)
	want := ""
	if k.fail {
		want = "internal"
	}
	if c := d.errorCode(t, "test.approvehold", `{}`); c != want {
		t.Fatalf("approval: %q", c)
	}
}

// §11.14.10: the statement is held in the step-2 state, at the transfer's
// dek_version, and nothing is sent at the approval; the new phone's first
// unlock from storage sends it before device.unlinked{transferred}, and
// stops holding it in the same state.
func TestHeldKeyRotationSentBeforeTheUnlink(t *testing.T) {
	d := newDevFixture(t)
	sinkOf(d)
	conn := d.asConnection(t, "c1", 0x70)
	k := &keyHolder{conn: "c1"}
	approvedWithHeld(t, d, k)
	d.m.mu.Lock()
	h := d.m.st.HeldKeyRotation
	if h == nil || len(h.Statements) != 1 || !bytes.Equal(h.Statements[0], heldStmt) || h.DEKVersion != 2 || d.m.hdr.DEKVersion != 2 {
		d.m.mu.Unlock()
		t.Fatalf("held %+v at dek_version %d", h, d.m.hdr.DEKVersion)
	}
	d.m.mu.Unlock()
	if len(k.sent) != 0 || d.depositsTo(conn.peer.Relay.Mailbox) != 0 {
		t.Fatal("the statement was sent at the approval")
	}
	if d.m.st.PendingUnlink == nil {
		t.Fatal("no pending unlink")
	}
	d.relay.mu.Lock()
	d.relay.deposits = nil
	d.relay.mu.Unlock()
	d.m.mu.Lock()
	d.m.pendingUnlinkAtUnlock(d.m.now())
	d.m.drainOutbox(context.Background())
	held, pending := d.m.st.HeldKeyRotation, d.m.st.PendingUnlink
	d.m.mu.Unlock()
	if len(k.sent) != 1 || held != nil || pending != nil {
		t.Fatalf("sent %d, still held %v, pending unlink %v", len(k.sent), held != nil, pending != nil)
	}
	var order []string
	d.relay.mu.Lock()
	for _, dep := range d.relay.deposits {
		switch dep.mailbox {
		case conn.peer.Relay.Mailbox:
			order = append(order, "statement")
		case d.devPeer.Relay.Mailbox:
			order = append(order, "unlinked")
		}
	}
	d.relay.mu.Unlock()
	if len(order) != 2 || order[0] != "statement" || order[1] != "unlinked" {
		t.Fatalf("deposits %v", order)
	}
	// A later unlock sends nothing again.
	d.m.mu.Lock()
	d.m.pendingUnlinkAtUnlock(d.m.now())
	d.m.mu.Unlock()
	if len(k.sent) != 1 {
		t.Fatal("sent again")
	}
}

// A crash after the step-2 write keeps the statement held in the stored
// state; a crash before it stores neither the approval nor the statement.
func TestHeldKeyRotationAcrossCrashes(t *testing.T) {
	d := newDevFixture(t)
	approvedWithHeld(t, d, &keyHolder{})
	d.m.Crash()
	m, _, err := Unlock(context.Background(), UnlockParams{Options: d.fixture.opts, VaultID: d.vid, PIN: testPIN, UnlockSecret: testSecret2})
	if err != nil {
		t.Fatal(err)
	}
	if h := m.st.HeldKeyRotation; h == nil || len(h.Statements) != 1 || !bytes.Equal(h.Statements[0], heldStmt) {
		t.Fatalf("after a crash past step 2: %+v", h)
	}
	m.Crash()

	d2 := newDevFixture(t)
	attestOK(d2)
	inv := d2.transferInvite(t)
	n := newNewcomer(t, 0x50)
	n.hsInitAttest(t, d2.m, handshake.PurposeApp, inv.ID, "t1", testAttest)
	n.finish(t, d2)
	d2.m.mu.Lock()
	if err := d2.m.approveTransfer(context.Background(), inv.ID, testPIN, []byte(rPW), false, d2.m.now()); err != nil {
		d2.m.mu.Unlock()
		t.Fatal(err)
	}
	if err := d2.m.holdKeyRotation(heldStmt); err != nil || d2.m.st.HeldKeyRotation == nil || d2.m.st.HeldKeyRotation.DEKVersion != 2 {
		d2.m.mu.Unlock()
		t.Fatalf("hold: %v", err)
	}
	d2.m.mu.Unlock()
	if h := d2.storedHeader(); h.Next == nil || h.Next.DEKVersion != 2 {
		t.Fatal("step 1 not stored")
	}
	d2.m.Crash() // step 1 stored, step 2 not
	m2, _, err := d2.fixture.unlock(testPIN, 0, 0)
	if err != nil {
		t.Fatalf("the old phone after a crash before step 2: %v", err)
	}
	defer m2.Crash()
	if m2.st.HeldKeyRotation != nil || m2.st.Devices["dev1"] == nil {
		t.Fatalf("after a crash before step 2: held %+v", m2.st.HeldKeyRotation)
	}
}

// A handler that fails after it held a statement holds nothing: the
// runtime drops step 1 and ends the transfer, and the statement with it.
func TestHeldKeyRotationDroppedWhenTheHandlerFails(t *testing.T) {
	d := newDevFixture(t)
	sinkOf(d)
	approvedWithHeld(t, d, &keyHolder{fail: true})
	d.m.mu.Lock()
	defer d.m.mu.Unlock()
	if d.m.st.HeldKeyRotation != nil || d.m.st.Transfer != nil || d.m.st.Devices["dev1"] == nil {
		t.Fatalf("held %+v", d.m.st.HeldKeyRotation)
	}
}

// §11.14.10 "The owed mark": any rotation of the vault's keys while a
// statement is held sends it first (a recovery's, an owed one, one on
// request); credential.rotate takes it itself.
func TestRotationSendsHeldStatementFirst(t *testing.T) {
	d := newDevFixture(t)
	sink := sinkOf(d)
	k := &keyHolder{}
	approvedWithHeld(t, d, k)
	sink.got = nil
	if err := d.m.RotateIdentity(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(k.sent) != 1 || d.m.st.HeldKeyRotation != nil {
		t.Fatalf("sent %d", len(k.sent))
	}
	var kinds []string
	for _, a := range sink.got {
		if a.Kind == "test.statement_sent" || a.Kind == "identity.rotated" {
			kinds = append(kinds, a.Kind)
		}
	}
	if len(kinds) != 2 || kinds[0] != "test.statement_sent" {
		t.Fatalf("order %v", kinds)
	}

	// Taken by credential.rotate: the vault's rotation finds none.
	d2 := newDevFixture(t)
	k2 := &keyHolder{}
	approvedWithHeld(t, d2, k2)
	d2.m.mu.Lock()
	got := d2.m.session(d2.m.now()).TakeHeldKeyRotations()
	err := d2.m.rotateIdentity(d2.m.now())
	d2.m.mu.Unlock()
	if err != nil || len(got) != 1 || !bytes.Equal(got[0], heldStmt) || len(k2.sent) != 0 || d2.m.st.HeldKeyRotation != nil {
		t.Fatalf("taken %d, sent by the vault %d", len(got), len(k2.sent))
	}
}

// A recovery while a transfer's statement is held sends it (its open uses
// the backup copy, which holds the new key), before the old phone's notice
// and before the vault's keys rotate.
func TestRecoverySendsHeldStatement(t *testing.T) {
	sink := &recSink{}
	k := &keyHolder{}
	f := newOpenFixtureWith(t, func(f *openFixture) {
		f.m.mu.Lock()
		f.m.st.HeldKeyRotation = &HeldKeyRotation{TransferID: "t1", DEKVersion: f.m.hdr.DEKVersion + 1, Statements: []json.RawMessage{heldStmt}}
		// The old phone's notice, as a release before 0.55.10 held it.
		f.m.st.PendingUnlink = &PendingUnlink{RelayURL: "https://relay.example.org", Mailbox: "old-phone", Token: "v4.public.T0xE",
			TransferID: "t1", DEKVersion: f.m.hdr.DEKVersion + 1, At: f.clock, TokenExp: f.clock.Add(29 * 24 * time.Hour),
			Payload: []byte("sealed notice")}
		f.m.dirty = true
		f.m.mu.Unlock()
		if err := f.m.Lock(context.Background()); err != nil {
			f.t.Fatal(err)
		}
	})
	f.opts.Features = append(f.opts.Features, sink, k)
	m, out := f.open(testPIN, rPW)
	if m == nil || !out.OK {
		t.Fatalf("open: %+v", out)
	}
	defer m.Crash()
	if len(k.sent) != 1 || m.st.HeldKeyRotation != nil {
		t.Fatalf("sent %d, held %+v", len(k.sent), m.st.HeldKeyRotation)
	}
	if m.st.PendingUnlink != nil {
		t.Fatal("the old phone's notice was not sent")
	}
	var kinds []string
	for _, a := range sink.got {
		if a.Kind == "test.statement_sent" || a.Kind == "device.unlinked_sent" || a.Kind == "identity.rotated" {
			kinds = append(kinds, a.Kind)
		}
	}
	if len(kinds) != 3 || kinds[0] != "test.statement_sent" || kinds[1] != "device.unlinked_sent" || kinds[2] != "identity.rotated" {
		t.Fatalf("order %v", kinds)
	}
}

// A state from before this release (a pending transfer, no held
// statement) behaves as before: the unlock sends the notice only.
func TestNoHeldKeyRotationFromEarlierRelease(t *testing.T) {
	d := newDevFixture(t)
	k := &keyHolder{}
	approvedWithHeld(t, d, k)
	d.m.mu.Lock()
	d.m.st.HeldKeyRotation = nil
	d.m.pendingUnlinkAtUnlock(d.m.now())
	d.m.mu.Unlock()
	if len(k.sent) != 0 || d.m.st.PendingUnlink != nil {
		t.Fatal("not as before")
	}
}

// A credential handler cannot rotate ik and kem while a statement is held
// (the rotation would call back into it); one that takes the statements
// and then fails holds them again.
func TestHeldKeyRotationTakenByAFailingHandler(t *testing.T) {
	d := newDevFixture(t)
	k := &keyHolder{}
	d.m.mu.Lock()
	d.m.addFeature(k)
	d.m.st.HeldKeyRotation = &HeldKeyRotation{TransferID: "t1", DEKVersion: 1, Statements: []json.RawMessage{heldStmt}}
	d.m.mu.Unlock()
	if c := d.errorCode(t, "test.takefail", `{}`); c != "internal" {
		t.Fatalf("code %q", c)
	}
	if k.rotErr == nil || len(d.m.st.Rotations) != 0 || len(k.sent) != 0 {
		t.Fatalf("rotated while held: %v", k.rotErr)
	}
	d.m.mu.Lock()
	defer d.m.mu.Unlock()
	if len(k.taken) != 1 || d.m.st.HeldKeyRotation == nil || len(d.m.st.HeldKeyRotation.Statements) != 1 {
		t.Fatalf("taken %d, held again %+v", len(k.taken), d.m.st.HeldKeyRotation)
	}
}

// Two transfers approved before the first statement went out hold both,
// in order, at the later transfer's dek_version, and send them as one.
func TestHeldKeyRotationTwoTransfers(t *testing.T) {
	d := newDevFixture(t)
	k := &keyHolder{}
	approvedWithHeld(t, d, k)
	d.m.mu.Lock()
	defer d.m.mu.Unlock()
	d.m.st.Transfer = &Transfer{ID: "t2", State: TransferApproved}
	second := []byte(`{"v":1,"old_key":"K1","new_key":"K2"}`)
	if err := d.m.holdKeyRotation(second); err != nil {
		t.Fatal(err)
	}
	d.m.st.Transfer = nil
	h := d.m.st.HeldKeyRotation
	if h == nil || h.TransferID != "t2" || len(h.Statements) != 2 || !bytes.Equal(h.Statements[0], heldStmt) || !bytes.Equal(h.Statements[1], second) {
		t.Fatalf("held %+v", h)
	}
	d.m.sendHeldKeyRotations(d.m.now())
	if len(k.sent) != 2 || d.m.st.HeldKeyRotation != nil {
		t.Fatalf("sent %d", len(k.sent))
	}
}

// The resumed recovery whose first run's step 2 was not stored sends the
// held statement too (it was in the state that was not stored).
func TestResumedRecoverySendsHeldStatement(t *testing.T) {
	k := &keyHolder{}
	f := newOpenFixtureWith(t, func(f *openFixture) {
		f.m.mu.Lock()
		f.m.st.HeldKeyRotation = &HeldKeyRotation{TransferID: "t1", DEKVersion: f.m.hdr.DEKVersion + 1, Statements: []json.RawMessage{heldStmt}}
		f.m.dirty = true
		f.m.mu.Unlock()
		if err := f.m.Lock(context.Background()); err != nil {
			f.t.Fatal(err)
		}
	})
	f.opts.Features = append(f.opts.Features, k)
	f.st.failState = 1
	if m, out := f.open(testPIN, rPW); m != nil || out.Code != OpenRetry {
		t.Fatalf("open stopped after step 1: %+v", out)
	}
	k.sent = nil
	m, out := f.open(testPIN, rPW)
	if m == nil || !out.OK {
		t.Fatalf("resumed: %+v", out)
	}
	defer m.Crash()
	if len(k.sent) != 1 || m.st.HeldKeyRotation != nil {
		t.Fatalf("sent %d, held %+v", len(k.sent), m.st.HeldKeyRotation)
	}
}
