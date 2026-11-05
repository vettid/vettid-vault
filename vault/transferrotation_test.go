package vault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayclient"
	"github.com/vettid/vettid-vault/vault/store"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
)

// §11.14.10 "The vault's keys after a transfer", "The rest, after the new
// phone's first unlock", "What settles the notice", "If the notice is not
// accepted", "The owed mark" and "Failure".

// trWorld is a vault moved to a new phone (steps 1 to 3 stored), with a
// connection c1 that pinned the old credential key, and the old app's
// notice held.
type trWorld struct {
	*devFixture
	t    *testing.T
	conn *tdev
	k    *keyHolder
	sink *recSink
	fs   *faultStore
	old  string // the old app's mailbox
	id   string // the transfer_id
}

func newTRWorld(t *testing.T) *trWorld {
	d := newDevFixture(t)
	w := &trWorld{devFixture: d, t: t, sink: &recSink{}, k: &keyHolder{conn: "c1"}}
	d.m.mu.Lock()
	d.m.addFeature(w.sink)
	d.m.mu.Unlock()
	d.fixture.opts.Features = append(d.fixture.opts.Features, w.sink)
	w.conn = d.asConnection(t, "c1", 0x70)
	w.old = d.devPeer.Relay.Mailbox
	approvedWithHeld(t, d, w.k)
	w.id = w.k.id
	w.fs = &faultStore{Store: d.fixture.store}
	d.fixture.opts.Store = w.fs
	return w
}

// reopen crashes the running vault and opens it again from storage, as
// the new phone's unlock does (its write included), without starting it.
func (w *trWorld) reopen() {
	w.t.Helper()
	w.m.Crash()
	m, _, err := Unlock(context.Background(), UnlockParams{Options: w.fixture.opts, VaultID: w.vid, PIN: testPIN, UnlockSecret: testSecret2})
	if err != nil {
		w.t.Fatal(err)
	}
	w.m = m
	w.sink.got = nil
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pendingUnlinkAtUnlock(m.now()) // the new phone's unlock (Unlock here is PIN only)
	if err := m.persist(context.Background(), false); err != nil {
		w.t.Fatal(err)
	}
}

// start runs the unlocked vault's start: the owed rotation's retry, its
// write, the outbox.
func (w *trWorld) start() {
	w.t.Helper()
	if err := w.m.Start(context.Background()); err != nil {
		w.t.Fatal(err)
	}
}

// connTypes labels the relay's deposits since the last call, in order:
// the connection's messages by type ("statement" for the credential key's),
// "unlinked" for the old app's.
func (w *trWorld) connTypes() []string {
	w.relay.mu.Lock()
	labels := []string{}
	type dep struct{ mailbox string }
	var order []dep
	for _, d := range w.relay.deposits {
		if env, err := envelope.Parse(d.payload); d.mailbox == w.old || err == nil && env.Mode() == envelope.ModeSession {
			order = append(order, dep{d.mailbox}) // inbox opens only session envelopes
		}
	}
	w.relay.mu.Unlock()
	ins := w.inbox(w.conn)["c1"]
	j := 0
	for _, d := range order {
		switch d.mailbox {
		case w.old:
			labels = append(labels, "unlinked")
		case w.conn.peer.Relay.Mailbox:
			if j < len(ins) {
				if l := label(ins[j]); l != "" {
					labels = append(labels, l)
				}
				j++
			}
		}
	}
	return labels
}

// label names the connection's messages these tests follow; the rekey
// that follows a rotation is not among them.
func label(in *envelope.Inner) string {
	switch in.Type {
	case "connection.authenticate.rotated":
		return "statement"
	case "identity.rotate":
		return in.Type
	}
	return ""
}

func (w *trWorld) rotations() int {
	w.m.mu.Lock()
	defer w.m.mu.Unlock()
	return len(w.m.st.Rotations)
}

// activities reads the sink under the manager's lock: Start's attachment
// run drains the outbox, and records, from its own goroutine.
func (w *trWorld) activities(kind string) []Activity {
	w.m.mu.Lock()
	defer w.m.mu.Unlock()
	var out []Activity
	for _, a := range w.sink.got {
		if a.Kind == kind {
			out = append(out, a)
		}
	}
	return out
}

func eq(a []string, b ...string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// The owed mark is written in the step-2 state, atomic with the move: the
// transfer_id, the DEK version of its step 2 and the approval's time. The
// approval rotates nothing but the credential key.
func TestTransferOwedMarkInStep2(t *testing.T) {
	w := newTRWorld(t)
	w.m.mu.Lock()
	o, pu, rot := w.m.st.RotationOwed, w.m.st.PendingUnlink, len(w.m.st.Rotations)
	w.m.mu.Unlock()
	if o == nil || o.Transfer != w.id || o.Recovery != "" || o.DEKVersion != 2 || time.Since(o.At) > time.Minute {
		t.Fatalf("owed mark %+v", o)
	}
	if pu == nil || !pu.Marked || rot != 0 {
		t.Fatalf("pending unlink %+v, %d rotations at the approval", pu, rot)
	}
	w.m.Crash()
	m, _, err := Unlock(context.Background(), UnlockParams{Options: w.fixture.opts, VaultID: w.vid, PIN: testPIN, UnlockSecret: testSecret2})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Crash()
	if o := m.st.RotationOwed; o == nil || o.Transfer != w.id || o.DEKVersion != 2 {
		t.Fatalf("stored mark %+v", o)
	}
}

// "Finish the move": the held statement K0→K1 first, then the old phone's
// notice; ik, kem and the wake key rotate in the state write after the
// relay accepted the notice (its 201), and identity.rotate goes out after
// that write. The rotation clears the mark and is audited with the
// transfer_id.
func TestTransferRotatesAfterTheNotice(t *testing.T) {
	w := newTRWorld(t)
	w.reopen()
	w.m.mu.Lock()
	pu := w.m.st.PendingUnlink
	queued := pu != nil && pu.Queued != "" && w.m.outboxQueued(pu.Queued)
	w.m.mu.Unlock()
	if !queued || w.rotations() != 0 {
		t.Fatalf("after the unlock's write: queued %v, %d rotations", queued, w.rotations())
	}
	w.start()
	if got := w.connTypes(); !eq(got, "statement", "unlinked", "identity.rotate") {
		t.Fatalf("deposits %v", got)
	}
	w.m.mu.Lock()
	o, pu := w.m.st.RotationOwed, w.m.st.PendingUnlink
	w.m.mu.Unlock()
	if w.rotations() != 1 || o != nil || pu != nil {
		t.Fatalf("%d rotations, owed %+v, pending unlink %v", w.rotations(), o, pu != nil)
	}
	if r := w.activities("identity.rotated"); len(r) != 1 || r[0].Ref != w.id {
		t.Fatalf("identity.rotated %+v", r)
	}
	if len(w.activities("device.unlinked_sent")) != 1 {
		t.Fatal("the delivered notice is not audited")
	}
	// Stored; a later unlock rotates nothing more and sends no notice.
	w.reopen()
	w.start()
	if w.rotations() != 1 || len(w.connTypes()) != 0 {
		t.Fatal("rotated or sent again")
	}
}

// A notice the relay did not accept (a timeout, an unreachable relay, a
// 5xx) is kept and deposited again at the next unlock, sealed afresh; the
// rotation waits. An unlock that finds the notice still queued queues no
// second copy.
func TestTransferNoticeNotAccepted(t *testing.T) {
	w := newTRWorld(t)
	w.reopen()
	w.relay.failMailbox = map[string]error{w.old: &relayclient.Error{Status: 503, Code: ""}}
	w.start()
	w.m.mu.Lock()
	pu, o := w.m.st.PendingUnlink, w.m.st.RotationOwed
	var seq uint64
	if pu != nil && pu.Epoch != nil {
		seq = pu.Epoch.Sent
	}
	w.m.mu.Unlock()
	if pu == nil || pu.Queued != "" || o == nil || w.rotations() != 0 {
		t.Fatalf("after a 503: pending %+v, owed %+v, %d rotations", pu, o, w.rotations())
	}
	if got := w.connTypes(); !eq(got, "statement") {
		t.Fatalf("deposits %v", got)
	}

	// Two unlock writes before the outbox runs: one copy.
	w.reopen()
	w.m.mu.Lock()
	w.m.pendingUnlinkAtUnlock(w.m.now())
	n := 0
	for _, e := range w.m.st.Outbox {
		if e.Unlink != "" && !e.Done {
			n++
		}
	}
	if pu := w.m.st.PendingUnlink; pu == nil || pu.Epoch == nil || pu.Epoch.Sent != seq+1 {
		t.Fatalf("the send counter did not move on: %+v", pu)
	}
	w.m.mu.Unlock()
	if n != 1 {
		t.Fatalf("%d copies queued", n)
	}
	w.start()
	if got := w.connTypes(); !eq(got, "unlinked", "identity.rotate") {
		t.Fatalf("deposits %v", got)
	}
	if w.rotations() != 1 {
		t.Fatal("not rotated after the notice was accepted")
	}
}

// A definite refusal (the token expired or revoked, the mailbox gone)
// settles the notice: it is deleted and the keys rotate.
func TestTransferNoticeRefused(t *testing.T) {
	for _, code := range []string{CodeTokenRevoked, CodeTokenExpired, CodeMailboxUnknown} {
		w := newTRWorld(t)
		w.reopen()
		w.relay.failMailbox = map[string]error{w.old: &relayclient.Error{Status: 403, Code: code}}
		w.start()
		w.m.mu.Lock()
		pu := w.m.st.PendingUnlink
		w.m.mu.Unlock()
		if pu != nil || w.rotations() != 1 || len(w.activities("device.unlinked_sent")) != 0 {
			t.Fatalf("%s: pending %v, %d rotations", code, pu != nil, w.rotations())
		}
		w.m.Crash()
	}
}

// The rotation goes ahead at once when the unlock finds no pending unlink
// (its token expired, or the old app had none); the mark outlives it.
func TestTransferRotatesWithoutPendingUnlink(t *testing.T) {
	w := newTRWorld(t)
	w.m.mu.Lock()
	w.m.dropPendingUnlink()
	if err := w.m.persist(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	w.m.mu.Unlock()
	w.reopen()
	w.start()
	if w.rotations() != 1 {
		t.Fatal("not rotated")
	}
	if got := w.connTypes(); !eq(got, "statement", "identity.rotate") {
		t.Fatalf("deposits %v", got)
	}
}

// From 7 days after the approval the next unlock rotates with or without
// the notice; the notice is still deposited at each unlock while its token
// lives.
func TestTransferRotatesAnywayFromDay7(t *testing.T) {
	w := newTRWorld(t)
	w.m.mu.Lock()
	at := w.m.st.RotationOwed.At
	w.m.mu.Unlock()
	for _, c := range []struct {
		after   time.Duration
		rotated int
	}{{TransferRotateAnyway - time.Minute, 0}, {TransferRotateAnyway, 1}} {
		now := at.Add(c.after)
		w.fixture.opts.Now = func() time.Time { return now }
		w.reopen()
		w.relay.failMailbox = map[string]error{w.old: errors.New("unreachable")}
		w.start()
		if w.rotations() != c.rotated {
			t.Fatalf("at %v: %d rotations", c.after, w.rotations())
		}
	}
	w.m.mu.Lock()
	pu := w.m.st.PendingUnlink
	w.m.mu.Unlock()
	if pu == nil {
		t.Fatal("the notice was dropped with the day-7 rotation")
	}
	w.reopen()
	w.start()
	if got := w.connTypes(); !eq(got, "unlinked") || w.rotations() != 1 {
		t.Fatalf("after day 7: deposits %v, %d rotations", got, w.rotations())
	}
}

// No rotation before an unlock from the stored objects under the
// transfer's DEK version.
func TestTransferRotationWaitsForTheNewPhone(t *testing.T) {
	w := newTRWorld(t)
	w.m.mu.Lock()
	w.m.dropPendingUnlink()
	w.m.st.RotationOwed.DEKVersion = w.m.dekVersion() + 1
	w.m.retryOwedRotation(w.m.now())
	n := len(w.m.st.Rotations)
	w.m.mu.Unlock()
	if n != 0 {
		t.Fatal("rotated before the new phone's unlock")
	}
}

// A rotation that cannot be made is audited identity.rotation_failed with
// the transfer_id, keeps the mark and is tried again at the next unlock.
func TestTransferRotationFailureRetried(t *testing.T) {
	w := newTRWorld(t)
	w.fixture.opts.KeyRand = func(int) ([]byte, error) { return nil, errors.New("no entropy") }
	w.reopen()
	w.start()
	if f := w.activities("identity.rotation_failed"); len(f) != 1 || f[0].Ref != w.id {
		t.Fatalf("rotation_failed %+v", f)
	}
	w.m.mu.Lock()
	o, pu := w.m.st.RotationOwed, w.m.st.PendingUnlink
	w.m.mu.Unlock()
	if o == nil || o.Transfer != w.id || pu != nil || w.rotations() != 0 {
		t.Fatalf("owed %+v, pending %v", o, pu != nil)
	}
	w.fixture.opts.KeyRand = nil
	w.reopen()
	w.start()
	if r := w.activities("identity.rotated"); len(r) != 1 || r[0].Ref != w.id || w.rotations() != 1 {
		t.Fatalf("not retried: %+v", r)
	}
}

// Crashes around the notice and the rotation (§11.14.2 order of writes):
// before the 201 the stored notice is still queued and goes out once; after
// the 201 and before the rotation's write nothing of the rotation left, and
// the stored notice is deposited again and settles; after the rotation's
// write the rotation is stored and not made again.
func TestTransferRotationCrashes(t *testing.T) {
	t.Run("before the 201", func(t *testing.T) {
		w := newTRWorld(t)
		w.reopen()
		w.reopen() // the first run crashed before its outbox ran
		w.m.mu.Lock()
		n := 0
		for _, e := range w.m.st.Outbox {
			if e.Unlink != "" && !e.Done {
				n++
			}
		}
		w.m.mu.Unlock()
		if n != 1 {
			t.Fatalf("%d notices queued", n)
		}
		w.start()
		if got := w.connTypes(); !eq(got, "statement", "unlinked", "identity.rotate") || w.rotations() != 1 {
			t.Fatalf("deposits %v, %d rotations", got, w.rotations())
		}
	})
	t.Run("after the 201, before the rotation's write", func(t *testing.T) {
		w := newTRWorld(t)
		w.reopen()
		w.m.mu.Lock()
		w.fs.mu.Lock()
		w.fs.failState = 1
		w.fs.mu.Unlock()
		w.m.drainOutbox(context.Background())
		rot := len(w.m.st.Rotations)
		w.m.mu.Unlock()
		if got := w.connTypes(); !eq(got, "statement", "unlinked") || rot != 1 {
			t.Fatalf("deposits %v, %d rotations in memory", got, rot)
		}
		w.reopen()
		w.m.mu.Lock()
		o, pu, rot := w.m.st.RotationOwed, w.m.st.PendingUnlink, len(w.m.st.Rotations)
		w.m.mu.Unlock()
		if o == nil || pu == nil || rot != 0 {
			t.Fatalf("stored: owed %+v, pending %v, %d rotations", o, pu != nil, rot)
		}
		w.start()
		// The statement and the notice again (the outbox is at least once),
		// then the rotation.
		if got := w.connTypes(); !eq(got, "statement", "unlinked", "identity.rotate") || w.rotations() != 1 {
			t.Fatalf("deposits %v, %d rotations", got, w.rotations())
		}
	})
	t.Run("after the rotation's write", func(t *testing.T) {
		w := newTRWorld(t)
		w.reopen()
		w.start()
		_ = w.connTypes()
		w.reopen()
		w.m.mu.Lock()
		o, pu := w.m.st.RotationOwed, w.m.st.PendingUnlink
		w.m.mu.Unlock()
		if o != nil || pu != nil || w.rotations() != 1 {
			t.Fatalf("stored: owed %+v, pending %v, %d rotations", o, pu != nil, w.rotations())
		}
		w.start()
		if got := w.connTypes(); len(got) != 0 || w.rotations() != 1 {
			t.Fatalf("again: %v", got)
		}
	})
}

// A pending unlink written by a release before the mark existed is treated
// as owing a rotation.
func TestPendingUnlinkBeforeTheMarkOwes(t *testing.T) {
	w := newTRWorld(t)
	w.m.mu.Lock()
	w.m.st.RotationOwed = nil
	w.m.st.PendingUnlink.Marked = false
	if err := w.m.persist(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	w.m.mu.Unlock()
	w.reopen()
	w.start()
	if r := w.activities("identity.rotated"); len(r) != 1 || r[0].Ref != w.id || w.rotations() != 1 {
		t.Fatalf("not rotated: %+v", r)
	}
}

// One rotation clears every owed mark; the transfer_id wins the ref.
func TestRotationClearsBothMarks(t *testing.T) {
	d := newDevFixture(t)
	s := sinkOf(d)
	d.m.mu.Lock()
	d.m.st.RotationOwed = &RotationOwed{Recovery: "r1", Transfer: "t1", DEKVersion: 1}
	err := d.m.rotateIdentity(d.m.now())
	o := d.m.st.RotationOwed
	d.m.mu.Unlock()
	if err != nil || o != nil {
		t.Fatalf("%v, owed %+v", err, o)
	}
	for _, a := range s.got {
		if a.Kind == "identity.rotated" && a.Ref != "t1" {
			t.Fatalf("ref %q", a.Ref)
		}
	}
}

// The wake key rotates with the vault's keys (§3.4, §14.1): the
// registration in force and the pending one are erased with their wake
// keys, and the app is sent push.token-needed{reason: "token_gone"}.
func TestRotationRotatesTheWakeKey(t *testing.T) {
	d := newDevFixture(t)
	d.m.mu.Lock()
	reg := &PushRegistration{DeviceID: d.devPeer.ID, WakeSeed: make([]byte, 32), WakeBlob: "b", State: PushStateActive}
	reg.WakeSeed[0] = 1
	pend := &PushPending{DeviceID: d.devPeer.ID, WakeSeed: make([]byte, 32), Pending: "p"}
	pend.WakeSeed[0] = 1
	d.m.st.Push, d.m.st.PushPending = reg, pend
	err := d.m.rotateIdentity(d.m.now())
	push, pp := d.m.st.Push, d.m.st.PushPending
	d.m.mu.Unlock()
	if err != nil || push != nil || pp != nil {
		t.Fatalf("%v: registration %v, pending %v", err, push != nil, pp != nil)
	}
	if reg.WakeSeed[0] != 0 || pend.WakeSeed[0] != 0 {
		t.Fatal("the wake keys were not zeroized")
	}
	d.m.mu.Lock()
	d.m.flushThenDrain(context.Background())
	d.m.mu.Unlock()
	ins := d.inbox(d.self())[d.devPeer.ID]
	var n int
	for _, in := range ins {
		if in.Type == TypePushTokenNeeded && bodyStr(t, in, "reason") == "token_gone" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("push.token-needed sent %d times", n)
	}
}

// A rotation asked for by the member (credential.rotate, through the
// host's RotateIdentity) while the transfer's notice still waits deposits
// that notice first, then sends identity.rotate (§11.14.10 "The owed
// mark"); it clears the transfer's mark, and the notice's later 201
// rotates nothing more.
func TestMemberRotationSendsThePendingNoticeFirst(t *testing.T) {
	w := newTRWorld(t)
	w.reopen()
	w.relay.failMailbox = map[string]error{w.old: errors.New("unreachable")}
	w.start() // the statement goes; the notice is not accepted
	if got := w.connTypes(); !eq(got, "statement") || w.rotations() != 0 {
		t.Fatalf("at the unlock: %v, %d rotations", got, w.rotations())
	}
	w.relay.failMailbox = nil
	w.m.mu.Lock()
	err := managerHost{w.m}.RotateIdentity(w.m.now())
	o := w.m.st.RotationOwed
	w.m.mu.Unlock()
	if err != nil || o != nil {
		t.Fatalf("rotate: %v, owed %+v", err, o)
	}
	if r := w.activities("identity.rotated"); len(r) != 1 || r[0].Ref != w.id {
		t.Fatalf("identity.rotated %+v", r)
	}
	w.m.mu.Lock()
	if err := w.m.persist(context.Background(), false); err != nil {
		w.m.mu.Unlock()
		t.Fatal(err)
	}
	w.m.drainOutbox(context.Background())
	pu := w.m.st.PendingUnlink
	w.m.mu.Unlock()
	if got := w.connTypes(); !eq(got, "unlinked", "identity.rotate") {
		t.Fatalf("deposits %v", got)
	}
	if pu != nil || w.rotations() != 1 {
		t.Fatalf("pending %v, %d rotations", pu != nil, w.rotations())
	}
}

// A vault being deleted rotates nothing: a queued notice accepted while
// the deletion's step 2 drains the outbox settles, and the keys stay
// (§12.5).
func TestNoRotationWhileDeleting(t *testing.T) {
	w := newTRWorld(t)
	w.reopen()
	w.m.mu.Lock()
	w.m.st.Deleting = &Deletion{At: w.m.now(), Via: "app"}
	w.m.markOK = true
	w.m.drainOutbox(context.Background())
	pu, o, rot := w.m.st.PendingUnlink, w.m.st.RotationOwed, len(w.m.st.Rotations)
	w.m.retryOwedRotation(w.m.now())
	rot2 := len(w.m.st.Rotations)
	w.m.mu.Unlock()
	if pu != nil || o == nil || rot != 0 || rot2 != 0 {
		t.Fatalf("pending %v, owed %+v, %d/%d rotations", pu != nil, o, rot, rot2)
	}
	if got := w.connTypes(); !eq(got, "statement", "unlinked") {
		t.Fatalf("deposits %v", got)
	}
}

// A recovery keeps a transfer's owed mark next to its own; a rotation that
// cannot be made is audited with the transfer_id, the ref a success would
// carry (§11.14.10 "Failure").
func TestRecoveryKeepsTransferMark(t *testing.T) {
	sink := &recSink{}
	at := time.Now().UTC().Truncate(time.Second)
	f := newOpenFixtureWith(t, func(f *openFixture) {
		f.m.mu.Lock()
		f.m.st.RotationOwed = &RotationOwed{Transfer: "t1", DEKVersion: f.m.hdr.DEKVersion, At: at}
		f.m.dirty = true
		f.m.mu.Unlock()
		if err := f.m.Lock(context.Background()); err != nil {
			f.t.Fatal(err)
		}
	})
	f.opts.Features = append(f.opts.Features, sink)
	f.opts.KeyRand = func(int) ([]byte, error) { return nil, errors.New("no entropy") }
	m, out := f.open(testPIN, rPW)
	if m == nil || !out.OK {
		t.Fatalf("open: %+v", out)
	}
	defer m.Crash()
	if o := m.st.RotationOwed; o == nil || o.Recovery != recID || o.Transfer != "t1" || !o.At.Equal(at) {
		t.Fatalf("owed %+v", o)
	}
	var refs []string
	for _, a := range sink.got {
		if a.Kind == "identity.rotation_failed" {
			refs = append(refs, a.Ref)
		}
	}
	if len(refs) != 1 || refs[0] != "t1" {
		t.Fatalf("rotation_failed refs %v", refs)
	}
}

// A rotation rekeys every session under the new keys (§3.4): a rekey
// started under the old ones (each unlock starts the devices') is
// replaced, its unsent hs.init dropped, and the new hs.init, under the new
// ik, follows identity.rotate. The stored state restores it after a crash.
func TestRotationReplacesRekeyUnderOldKeys(t *testing.T) {
	d := newDevFixture(t)
	d.m.mu.Lock()
	now := d.m.now()
	d.m.startRekey(d.devPeer, now)
	var old *OutgoingHS
	for _, og := range d.m.st.Outgoing {
		old = og
	}
	if old == nil {
		d.m.mu.Unlock()
		t.Fatal("no rekey started")
	}
	oldEnv := append([]byte(nil), old.Init.Env...)
	if err := d.m.rotateIdentity(now); err != nil {
		d.m.mu.Unlock()
		t.Fatal(err)
	}
	newIK := d.m.keys.ik.Public().(ed25519.PublicKey)
	var rekeys []*OutgoingHS
	for _, og := range d.m.st.Outgoing {
		if og.PeerID == d.devPeer.ID && og.Purpose == handshake.PurposeRekey {
			rekeys = append(rekeys, og)
		}
	}
	oldSent, initAt := false, -1
	for i, e := range d.m.st.Outbox {
		if bytes.Equal(e.Payload, oldEnv) && !e.Done {
			oldSent = true
		}
		if len(rekeys) == 1 && bytes.Equal(e.Payload, rekeys[0].Init.Env) {
			initAt = i
		}
	}
	d.m.mu.Unlock()
	if len(rekeys) != 1 || rekeys[0].ID == old.ID || oldSent {
		t.Fatalf("%d rekeys, the old one's hs.init still queued %v", len(rekeys), oldSent)
	}
	body, err := handshake.ParseInit(rekeys[0].Init.Body)
	if err != nil || !bytes.Equal(body.From.IK, newIK) {
		t.Fatalf("the rekey is not under the new ik: %v", err)
	}
	rotAt := -1
	d.m.mu.Lock()
	for i, e := range d.m.st.Outbox {
		if e.PeerID != d.devPeer.ID || e.Done || e.Op != OpDeposit {
			continue
		}
		env, err := envelope.Parse(e.Payload)
		if err != nil || env.Mode() != envelope.ModeSession {
			continue
		}
		var kr handshake.Keyring
		kr.Activate(d.ep, time.Now())
		if in, _, err := kr.Open(env, time.Now()); err == nil && in.Type == "identity.rotate" {
			rotAt = i
		}
	}
	d.m.mu.Unlock()
	if initAt < 0 || rotAt < 0 || rotAt > initAt {
		t.Fatalf("identity.rotate at %d, the new hs.init at %d: not queued, or not in that order", rotAt, initAt)
	}
	d.m.mu.Lock()
	if err := d.m.persist(context.Background(), false); err != nil {
		d.m.mu.Unlock()
		t.Fatal(err)
	}
	d.m.mu.Unlock()
	d.m.Crash()
	m, _, err := d.fixture.unlock(testPIN, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Crash()
	if m.outgoing[rekeys[0].ID] == nil {
		t.Fatal("the rekey under the new ik was not restored")
	}
	for _, a := range m.Audit() {
		if a.Event == "handshake_not_restored" {
			t.Fatal("a handshake was not restored")
		}
	}
}

// conflictStateStore lets n state writes through, then answers the next
// one with the store's version conflict: another instance wrote the state
// (a split brain, §12.3).
type conflictStateStore struct {
	store.Store
	mu   sync.Mutex
	pass int
}

func (s *conflictStateStore) Put(ctx context.Context, key string, data []byte, ifMatch store.Version) (store.Version, error) {
	if strings.HasSuffix(key, "/state") {
		s.mu.Lock()
		conflict := s.pass == 0
		s.pass--
		s.mu.Unlock()
		if conflict {
			return "", store.ErrConflict
		}
	}
	return s.Store.Put(ctx, key, data, ifMatch)
}

// A split brain at the rotation's own write (after the notice's 201) zeroizes
// the vault: Start reports ErrSplitBrain, nothing of the unstored rotation is
// sent, and nothing reads the wiped state (it used to panic in persist).
func TestTransferSettledWriteSplitBrain(t *testing.T) {
	w := newTRWorld(t)
	w.reopen()
	// Start's own write passes; the settled write after the 201 conflicts.
	w.m.opt.Store = &conflictStateStore{Store: w.fs, pass: 1}
	err := w.m.Start(context.Background())
	if !errors.Is(err, ErrSplitBrain) {
		t.Fatalf("Start: %v, want ErrSplitBrain", err)
	}
	if !w.m.Locked() {
		t.Fatal("not locked after the split brain")
	}
	if got := w.connTypes(); !eq(got, "statement", "unlinked") {
		t.Fatalf("deposits %v: the unstored rotation's identity.rotate went out", got)
	}
	w.m.mu.Lock()
	err = w.m.flushIfDirty(context.Background())
	w.m.drainOutbox(context.Background())
	w.m.mu.Unlock()
	if !errors.Is(err, ErrSplitBrain) {
		t.Fatalf("a later flush: %v", err)
	}
}

// A lock after a failed write whose own write stores the transfer's notice:
// the drain after it sends the notice, the relay settles it, and the owed
// rotation's write meets a split brain (§12.3). The lock returns
// ErrSplitBrain without reading the wiped state, and nothing more is sent
// (no identity.rotate, no vault.locking).
func TestFailedWriteThenLockSettledWriteSplitBrain(t *testing.T) {
	w := newTRWorld(t)
	w.reopen()
	w.m.mu.Lock()
	// The notice as a batch whose write failed leaves it: queued, unstored.
	w.m.unstored = map[string]bool{}
	for _, e := range w.m.st.Outbox {
		if e.Unlink != "" && !e.Done {
			w.m.unstored[e.ID] = true
		}
	}
	if len(w.m.unstored) == 0 {
		w.m.mu.Unlock()
		t.Fatal("no notice queued")
	}
	// The lock's write passes; the settled write after the 201 conflicts.
	w.m.opt.Store = &conflictStateStore{Store: w.fs, pass: 1}
	w.m.mu.Unlock()
	_ = w.responses(t)
	if err := w.m.Lock(context.Background()); !errors.Is(err, ErrSplitBrain) {
		t.Fatalf("Lock: %v, want ErrSplitBrain", err)
	}
	if !w.m.Locked() {
		t.Fatal("not locked after the split brain")
	}
	if got := w.connTypes(); !eq(got, "statement", "unlinked") {
		t.Fatalf("deposits %v", got)
	}
	for _, in := range w.responses(t) {
		if in.Type == "vault.locking" {
			t.Fatal("vault.locking sent after the split brain")
		}
	}
}

// A lock whose first drain settles the stored notice and meets a split
// brain at the owed rotation's write (§12.3): the lock's own write that
// follows finds the state wiped and returns ErrSplitBrain, without reading
// it (persist's guard), and nothing more is sent.
func TestLockFirstDrainSettledWriteSplitBrain(t *testing.T) {
	w := newTRWorld(t)
	w.reopen() // the notice is queued and stored
	w.m.mu.Lock()
	w.m.opt.Store = &conflictStateStore{Store: w.fs, pass: 0}
	w.m.mu.Unlock()
	_ = w.responses(t)
	if err := w.m.Lock(context.Background()); !errors.Is(err, ErrSplitBrain) {
		t.Fatalf("Lock: %v, want ErrSplitBrain", err)
	}
	if !w.m.Locked() {
		t.Fatal("not locked after the split brain")
	}
	if got := w.connTypes(); !eq(got, "statement", "unlinked") {
		t.Fatalf("deposits %v", got)
	}
	for _, in := range w.responses(t) {
		if in.Type == "vault.locking" {
			t.Fatal("vault.locking sent after the split brain")
		}
	}
}
