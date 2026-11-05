package vault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/peerwire"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Nothing leaves the vault before the write that commits it (§11.14.2
// "order of writes", §8.3): a batch whose state write failed keeps its
// in-memory state, but no drain sends its outbox entries until a later
// write stores them. A lock or crash before that loses them with it.

// failWrites makes the next n state writes of d's vault fail.
func failWrites(d *devFixture, n int) *faultStore {
	fs := &faultStore{Store: d.store, failState: n}
	d.m.mu.Lock()
	d.m.opt.Store = fs
	d.m.mu.Unlock()
	return fs
}

func typesOf(ins []*envelope.Inner) []string {
	out := []string{}
	for _, in := range ins {
		out = append(out, in.Type)
	}
	return out
}

// A batch's write fails, then the vault is locked: nothing of the batch
// (its response) is delivered, no vault.locking is sent for the devices in
// memory, and the vault opens again at the stored state.
func TestFailedWriteThenLockSendsNothing(t *testing.T) {
	d := newDevFixture(t)
	d.m.mu.Lock()
	if err := d.m.persist(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	seq := d.m.st.StateSeq
	d.m.mu.Unlock()
	_ = d.responses(t)
	failWrites(d, 1<<20)
	if err := d.send("vault.status", []byte(`{}`)); err == nil {
		t.Fatal("the batch's write did not fail")
	}
	if got := d.responses(t); len(got) != 0 {
		t.Fatalf("sent after the failed write: %v", typesOf(got))
	}
	var locked []LifecycleEvent
	d.m.mu.Lock()
	d.m.opt.Lifecycle = func(ev LifecycleEvent) { locked = append(locked, ev) }
	d.m.mu.Unlock()
	if err := d.m.Lock(context.Background()); err == nil {
		t.Fatal("the lock's write did not fail")
	}
	if got := d.responses(t); len(got) != 0 {
		t.Fatalf("sent by the lock: %v", typesOf(got))
	}
	if len(locked) != 1 || locked[0].Event != "locked" {
		t.Fatalf("lifecycle %+v", locked)
	}
	d.m.opt.Store = d.store
	m, res, err := Unlock(context.Background(), UnlockParams{Options: d.opts, VaultID: d.vid, PIN: testPIN, UnlockSecret: testSecret})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Crash()
	if res.StateSeq != seq { // a PIN-only unlock writes no state
		t.Fatalf("state_seq %d, stored %d", res.StateSeq, seq)
	}
}

// A transfer's owed rotation (§11.14.10): the relay settles the old
// phone's notice, the rotation is made in memory and its write fails. No
// later drain and no lock sends identity.rotate; the stored state owes the
// rotation still, and the next start makes it and sends it.
func TestSettledRotationFailedWriteThenDrainAndLock(t *testing.T) {
	w := newTRWorld(t)
	w.reopen()
	w.fs.mu.Lock()
	w.fs.failState = 1 << 20
	w.fs.mu.Unlock()
	w.m.mu.Lock()
	w.m.drainOutbox(context.Background())
	rot := len(w.m.st.Rotations)
	w.m.drainOutbox(context.Background())
	w.m.mu.Unlock()
	if got := w.connTypes(); !eq(got, "statement", "unlinked") || rot != 1 {
		t.Fatalf("deposits %v, %d rotations in memory", got, rot)
	}
	if err := w.m.Lock(context.Background()); err == nil {
		t.Fatal("the lock's write did not fail")
	}
	if got := w.connTypes(); len(got) != 0 {
		t.Fatalf("the lock sent %v", got)
	}
	w.fs.mu.Lock()
	w.fs.failState = 0
	w.fs.mu.Unlock()
	w.reopen()
	w.m.mu.Lock()
	o, rot := w.m.st.RotationOwed, len(w.m.st.Rotations)
	w.m.mu.Unlock()
	if o == nil || rot != 0 {
		t.Fatalf("stored: owed %+v, %d rotations", o, rot)
	}
	w.start()
	if got := w.connTypes(); !eq(got, "statement", "unlinked", "identity.rotate") || w.rotations() != 1 {
		t.Fatalf("after the start: %v, %d rotations", got, w.rotations())
	}
}

// A failed write, then a later write that succeeds: the failed batch's
// in-memory state is stored by the later write and only then sent (an
// honest replay: what goes out is what is stored), once.
func TestFailedWriteThenLaterWriteSendsStored(t *testing.T) {
	d := newDevFixture(t)
	_ = d.responses(t)
	failWrites(d, 1)
	if err := d.send("vault.status", []byte(`{}`)); err == nil {
		t.Fatal("the batch's write did not fail")
	}
	d.m.mu.Lock()
	d.m.drainOutbox(context.Background()) // any drain in between (the attachment runner's)
	d.m.mu.Unlock()
	if got := d.responses(t); len(got) != 0 {
		t.Fatalf("sent before a write stored it: %v", typesOf(got))
	}
	if err := d.send("device.list", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	got := typesOf(d.responses(t))
	if len(got) != 2 || got[0] != "vault.status" || got[1] != "device.list" {
		t.Fatalf("after the later write: %v", got)
	}
	d.m.mu.Lock()
	_ = d.m.flushThenDrain(context.Background())
	d.m.mu.Unlock()
	if got := d.responses(t); len(got) != 0 {
		t.Fatalf("sent again: %v", typesOf(got))
	}
}

// A drain that does not write first (SendRaw, the attachment runner)
// sends nothing a failed write left unstored.
func TestFailedWriteSendRawSendsNothing(t *testing.T) {
	d := newDevFixture(t)
	c := d.asConnection(t, "c1", 0x71)
	_ = d.inbox(c)
	failWrites(d, 1<<20)
	if _, err := d.m.SendRaw(context.Background(), "c1", "test.raw", []byte(`{}`)); err == nil {
		t.Fatal("the write did not fail")
	}
	d.m.mu.Lock()
	d.m.attFlushThenDrain(context.Background())
	d.m.mu.Unlock()
	if got := d.inbox(c)["c1"]; len(got) != 0 {
		t.Fatalf("sent: %v", typesOf(got))
	}
}

// A SendRaw whose write succeeds delivers at once: it writes before it
// drains (flushThenDrain), so its deposit is stored when the drain runs.
func TestSendRawWritesThenSends(t *testing.T) {
	d := newDevFixture(t)
	c := d.asConnection(t, "c1", 0x72)
	_ = d.inbox(c)
	if _, err := d.m.SendRaw(context.Background(), "c1", "test.raw", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if got := typesOf(d.inbox(c)["c1"]); len(got) != 1 || got[0] != "test.raw" {
		t.Fatalf("delivered: %v", got)
	}
}

// A lock whose write fails reports in `locked` what the stored header
// says (§11.5): its app key, not one a batch whose write failed adopted in
// memory, and its header_seq, credential_backup and `next`, not the
// values a header write that failed set in memory. Also a deletion whose
// header mark fails (ErrNotMarked), which locks the vault.
func TestFailedLockReportsStoredHeader(t *testing.T) {
	for _, tc := range []struct {
		name   string
		fault  func(*faultStore)
		delete bool
	}{
		{"state write fails", func(s *faultStore) { s.failState = 1 << 20 }, false},
		{"header write fails after the state write", func(s *faultStore) { s.failHeader = 1 << 20 }, false},
		{"deletion's header mark fails", func(s *faultStore) { s.failHeader = 1 << 20 }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := newDevFixture(t)
			k1, k2 := testAppKeyDER(t, 1), testAppKeyDER(t, 2)
			d.m.mu.Lock()
			d.m.setAppKey(k1)
			if err := d.m.persist(context.Background(), false); err != nil {
				d.m.mu.Unlock()
				t.Fatal(err)
			}
			d.m.setAppKey(k2) // a transfer's step 2, in memory
			fs := &faultStore{Store: d.store}
			tc.fault(fs)
			d.m.opt.Store = fs
			var evs []LifecycleEvent
			d.m.opt.Lifecycle = func(ev LifecycleEvent) { evs = append(evs, ev) }
			d.m.mu.Unlock()
			var err error
			if tc.delete {
				err = d.m.Delete(context.Background())
			} else {
				err = d.m.Lock(context.Background())
			}
			if err == nil {
				t.Fatal("the write did not fail")
			}
			h := d.storedHeader()
			if len(evs) != 1 || evs[0].Event != "locked" {
				t.Fatalf("lifecycle %+v", evs)
			}
			ev := evs[0]
			if !bytes.Equal(ev.AppKey, k1) || ev.AppKeySeq != h.AppKeySeq || !bytes.Equal(h.AppKey, k1) {
				t.Fatalf("locked app key seq %d, stored seq %d", ev.AppKeySeq, h.AppKeySeq)
			}
			if ev.HeaderSeq != h.HeaderSeq {
				t.Fatalf("locked header_seq %d, stored %d", ev.HeaderSeq, h.HeaderSeq)
			}
			if ev.Next == nil || *ev.Next != (h.Next != nil) {
				t.Fatalf("locked next %v, stored %v", ev.Next, h.Next != nil)
			}
			if (ev.CredentialBackup == nil) != (h.CredentialBackup == nil) ||
				ev.CredentialBackup != nil && *ev.CredentialBackup != *h.CredentialBackup {
				t.Fatalf("locked credential_backup %v, stored %v", ev.CredentialBackup, h.CredentialBackup)
			}
		})
	}
}

// A host deletion whose marking state write fails (§12.5): the header's
// mark and the host's commit the deletion, and at step 2 everything queued
// goes out in order, also what an earlier write that failed left unstored
// (the vault is erased, and its handshakes let peers read the notices).
func TestFailedWriteThenDeleteSendsAllQueued(t *testing.T) {
	d := newDevFixture(t)
	_ = d.responses(t)
	failWrites(d, 1<<20)
	if err := d.send("vault.status", []byte(`{}`)); err == nil {
		t.Fatal("the batch's write did not fail")
	}
	if err := d.m.Delete(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := typesOf(d.responses(t))
	if len(got) != 2 || got[0] != "vault.status" || got[1] != "device.unlinked" {
		t.Fatalf("sent at the deletion: %v", got)
	}
}

// A reconnect's hs.resp arrives in a batch whose write fails: the vault
// holds the hs.fin (unstored) and its session is in the new epoch in
// memory. A host deletion then seals connection.removed in that epoch;
// step 2 sends the hs.fin first, so the peer opens the notice.
func TestFailedReconnectWriteThenDeleteSendsTheFin(t *testing.T) {
	k0, k1 := rcKey(t, 0x10), rcKey(t, 0x20)
	r1 := rcLink(t, k0, k1)
	d, p, _ := rcSetup(t, k1, rawLinks(r1))
	p.Reconnect = HeldToken{Token: "v4.public.VEVTVA", Exp: time.Now().Add(24 * time.Hour)}
	m := d.m
	vaultRelay := m.keys.relay.Public().(ed25519.PublicKey)
	m.mu.Lock()
	m.startReconnect(p, m.now())
	_ = m.flushThenDrain(context.Background())
	m.mu.Unlock()
	var pi *handshake.PendingInit
	d.relay.mu.Lock()
	for _, dep := range d.relay.deposits {
		if dep.mailbox == p.Relay.Mailbox {
			pi, _ = handshake.OpenInit(dep.payload, func(kid suite.Kid) *suite.PrivateKey {
				if kid.Equal(k1.kem.Public().Kid()) {
					return k1.kem
				}
				return nil
			}, m.now())
		}
	}
	d.relay.deposits = nil
	d.relay.mu.Unlock()
	if pi == nil {
		t.Fatal("no hs.init")
	}
	resp, env, err := pi.Respond(handshake.ResponderConfig{
		Identity: k1.ik, Token: "v4.public.VEVTVA", ReconnectToken: "v4.public.VEVTVA", Policy: policyFor(KindConnection), CollectSender: vaultRelay,
		RecordRelayKey: vaultRelay, KnownInitiatorIK: m.keys.ik.Public().(ed25519.PublicKey),
		ExpectedCtx: handshake.EpochCtx(epochIDOf(p.LastEpochID)), Rotations: []*handshake.Rotation{r1}, Now: m.now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	jti := ""
	m.mu.Lock()
	for _, og := range m.st.Outgoing {
		for _, it := range og.Issued {
			if it.Kind == TokStanding {
				jti = it.JTI
			}
		}
	}
	m.mu.Unlock()
	failWrites(d, 1<<20)
	if err := m.ProcessBatch(context.Background(), &fakeCollector{}, []Message{{MsgID: "rp1", Sender: relayauth.EncodeKey(p.Relay.PK), JTI: jti, Payload: env}}); err == nil {
		t.Fatal("the batch's write did not fail")
	}
	if err := m.Delete(context.Background()); err != nil {
		t.Fatal(err)
	}
	var kr *handshake.Keyring
	var got []string
	d.relay.mu.Lock()
	defer d.relay.mu.Unlock()
	for _, dep := range d.relay.deposits {
		if dep.mailbox != p.Relay.Mailbox {
			continue
		}
		if kr == nil {
			fr, err := resp.HandleFin(dep.payload, vaultRelay, time.Now())
			if err != nil {
				t.Fatalf("the first deposit is not the hs.fin: %v", err)
			}
			kr = &handshake.Keyring{}
			kr.Activate(fr.Epoch, time.Now())
			got = append(got, "hs.fin")
			continue
		}
		e, err := envelope.Parse(dep.payload)
		if err != nil {
			t.Fatal(err)
		}
		in, _, err := kr.Open(e, time.Now())
		if err != nil {
			t.Fatalf("the peer cannot open a deposit: %v", err)
		}
		got = append(got, in.Type)
	}
	if len(got) < 2 || got[0] != "hs.fin" || got[len(got)-1] != peerwire.TypeConnectionRemoved {
		t.Fatalf("deposits to the peer: %v", got)
	}
}

// A volatile answer (pending.list, §8.2) sealed in a batch whose write
// fails is dropped: a later drain on another path that writes first does
// not send it.
func TestFailedWriteDropsVolatileAnswers(t *testing.T) {
	d := newDevFixture(t)
	app := d.self()
	_ = d.inbox(app)
	failWrites(d, 1)
	d.sendAs(app, "pending.list", `{}`)
	d.m.mu.Lock()
	d.m.attFlushThenDrain(context.Background()) // its write succeeds
	d.m.mu.Unlock()
	for _, in := range d.inbox(app)["dev1"] {
		if in.Type == "pending.list" {
			t.Fatal("the volatile answer of the failed batch was sent")
		}
	}
}

// A lock whose own write fails sends no vault.locking, also to a device
// with nothing queued (sendLocking alone would send it there).
func TestFailedLockSendsNoLocking(t *testing.T) {
	d := newDevFixture(t)
	_ = d.responses(t)
	failWrites(d, 1<<20)
	if err := d.m.Lock(context.Background()); err == nil {
		t.Fatal("the lock's write did not fail")
	}
	if got := d.responses(t); len(got) != 0 {
		t.Fatalf("sent by the failed lock: %v", typesOf(got))
	}
}

// A failed write, then a lock whose write succeeds: the lock's write stores
// the failed batch's entries, and they go out before vault.locking.
func TestLockStoresAndSendsBeforeLocking(t *testing.T) {
	d := newDevFixture(t)
	_ = d.responses(t)
	failWrites(d, 1)
	if err := d.send("vault.status", []byte(`{}`)); err == nil {
		t.Fatal("the batch's write did not fail")
	}
	if err := d.m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := typesOf(d.responses(t))
	if len(got) != 2 || got[0] != "vault.status" || got[1] != "vault.locking" {
		t.Fatalf("sent by the lock: %v", got)
	}
}

// The host reports of a batch whose write failed (app_key, an alarm,
// account_name) wait for the write that stores them: a state write that
// fails, or a header write that fails after the state write, then a later
// write that succeeds (a later batch's, or a lock's) reports each once.
func TestFailedWriteKeepsReportsPending(t *testing.T) {
	for _, tc := range []struct {
		name  string
		fault func(*faultStore)
		lock  bool
	}{
		{"state write fails", func(s *faultStore) { s.failState = 1 }, false},
		{"header write fails after the state write", func(s *faultStore) { s.failHeader = 1 }, false},
		{"state write fails, then a lock", func(s *faultStore) { s.failState = 1 }, true},
		{"header write fails, then a lock", func(s *faultStore) { s.failHeader = 1 }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := newDevFixture(t)
			count := map[string]int{}
			var keys [][]byte
			k := testAppKeyDER(t, 3)
			fs := &faultStore{Store: d.store}
			tc.fault(fs)
			d.m.mu.Lock()
			d.m.opt.Store = fs
			early := false
			d.m.opt.Lifecycle = func(ev LifecycleEvent) {
				count[ev.Event]++
				if ev.Event == EventAppKey {
					keys = append(keys, ev.AppKey)
				}
				// Each is reported only once a write stored what it
				// describes, the header included.
				if h := d.storedHeader(); h == nil || !bytes.Equal(h.AppKey, k) {
					early = true
				}
			}
			// What a transfer's step 2, a clone alarm and a name request
			// leave for the batch below to report after its write.
			d.m.setAppKey(k)
			managerHost{d.m}.ReportAlarm(AlarmCredentialClone)
			d.m.requestAccountName("Ada", "Lovelace", "", d.m.now())
			d.m.mu.Unlock()
			if err := d.send("vault.status", []byte(`{}`)); err == nil {
				t.Fatal("the batch's write did not fail")
			}
			if len(count) != 0 {
				t.Fatalf("reported before it was stored: %v", count)
			}
			if tc.lock {
				if err := d.m.Lock(context.Background()); err != nil {
					t.Fatal(err)
				}
			} else if err := d.m.ProcessBatch(context.Background(), &fakeCollector{}, nil); err != nil {
				// An idle batch: nothing collected, the write is still owed.
				t.Fatal(err)
			}
			alarm := "alarm." + AlarmCredentialClone
			if count[EventAppKey] != 1 || !bytes.Equal(keys[0], k) || count[alarm] != 1 || count[EventAccountName] != 1 {
				t.Fatalf("after the later write: %v", count)
			}
			if early {
				t.Fatal("reported before the stored header named the key")
			}
			if tc.lock {
				return
			}
			if err := d.send("vault.status", []byte(`{}`)); err != nil || count[EventAppKey] != 1 || count[alarm] != 1 || count[EventAccountName] != 1 {
				t.Fatalf("reported again: %v %v", err, count)
			}
		})
	}
}

// A state write that fails before a phone move's approval (any batch's,
// such as the write after the drain that sent device.transfer.pending)
// leaves the state behind: the approval's step 1 is refused with retry
// (beginReplace) and nothing of the move is spent, so the old app's
// approval sent again after that batch's write stored the state completes
// the move once, and only then is the new app paired (§11.14.10, §6.7.1).
func TestTransferApprovalRetriedAfterFailedWrite(t *testing.T) {
	d := newDevFixture(t)
	attestOK(d)
	inv := d.transferInvite(t)
	n := newNewcomer(t, 0x50)
	n.hsInitAttest(t, d.m, handshake.PurposeApp, inv.ID, "t1", testAttest)
	n.finish(t, d)
	k := &keyHolder{id: inv.ID, stmt: heldStmt}
	d.m.mu.Lock()
	d.m.addFeature(k)
	d.m.mu.Unlock()
	failWrites(d, 1)
	d.m.mu.Lock()
	d.m.dirty = true
	err := d.m.persist(context.Background(), false)
	behind := d.m.stateBehind
	d.m.mu.Unlock()
	if err == nil || !behind {
		t.Fatalf("the write before the approval: %v, behind %v", err, behind)
	}
	if c := d.errorCode(t, "test.approvehold", `{}`); c != "retry" {
		t.Fatalf("the approval while the state is behind: %q", c)
	}
	d.m.mu.Lock()
	tr, secret, old, behind := d.m.st.Transfer, len(d.m.transferSecret), d.m.st.Devices["dev1"], d.m.stateBehind
	d.m.mu.Unlock()
	if tr == nil || tr.State != TransferOpen || secret == 0 || old == nil {
		t.Fatalf("a refused approval spent the move: transfer %+v, secret %d, old app kept %v", tr, secret, old != nil)
	}
	if behind {
		t.Fatal("the approval's batch did not store the state")
	}
	if got := n.received(d); len(got) != 0 {
		t.Fatalf("the new app was sent %v before the approval", typesOf(got))
	}
	// Sent again: the new app's deposits are read before errorCode's
	// reading of the old app's clears the relay.
	if err := d.send("test.approvehold", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	paired := 0
	for _, in := range n.received(d) {
		if in.Type == "device.paired" {
			paired++
		}
	}
	answered := false
	for _, r := range d.responses(t) {
		answered = answered || r.Type == "test.approvehold" && r.Error == nil
	}
	if !answered {
		t.Fatal("the approval sent again was not answered")
	}
	d.m.mu.Lock()
	tr, old = d.m.st.Transfer, d.m.st.Devices["dev1"]
	d.m.mu.Unlock()
	if tr != nil || old != nil || paired != 1 {
		t.Fatalf("the move: transfer %v, old app kept %v, device.paired sent %d times", tr != nil, old != nil, paired)
	}
}
