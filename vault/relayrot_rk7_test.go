package vault

import (
	"bytes"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"

	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/peerwire"
)

// VAULT-MESSAGING 0.90.4 §3.4.2 RK7: an hs.confirm, and an hs.fin to an
// answer the vault has open, pass Table A's row "Earlier, after its
// cut-off" until a message from a later relay key of the peer's is
// accepted under that epoch or a later one.

// RK7, hs.fin: side 1's rekey hs.fin, deposited with K after side 0's
// cut-off, passes to Table B (the answer pinned the current ik) and
// establishes the epoch.
func TestRK7HsFinToOpenAnswerPassesTheCutoff(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	f.rekey(1)
	if f.deliver(1, 0, kHSInit) != 1 || f.deliver(0, 1, kHSResp) != 1 {
		t.Fatal("setup: no rekey")
	}
	fin := f.rkTake(kHSFin, rkAfter)
	f.rkFollow()
	n, cur := f.answerCount(0), append([]byte(nil), f.cur(0)...)
	f.process(0, fin)
	if f.superseded() != 0 || f.answerCount(0) != n-1 || bytes.Equal(f.cur(0), cur) {
		t.Fatalf("the hs.fin did not pass: refused %d, answers %d -> %d", f.superseded(), n, f.answerCount(0))
	}
}

// RK7, hs.fin: one whose sig_I does not verify (here one that does not
// open) fails RK7's condition and is refused superseded_relay, the answer
// kept.
func TestRK7HsFinThatDoesNotVerifyRefused(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	f.rekey(1)
	if f.deliver(1, 0, kHSInit) != 1 || f.deliver(0, 1, kHSResp) != 1 {
		t.Fatal("setup: no rekey")
	}
	fin := f.rkTake(kHSFin, rkAfter)
	fin.Payload = append([]byte(nil), fin.Payload...)
	fin.Payload[len(fin.Payload)-1] ^= 1
	f.rkFollow()
	n := f.answerCount(0)
	f.process(0, fin)
	if f.superseded() != 1 || f.answerCount(0) != n {
		t.Fatalf("not refused with the answer kept: refused %d, answers %d -> %d", f.superseded(), n, f.answerCount(0))
	}
}

// rk7Confirm runs side 0's rekey up to side 1's hs.confirm, taken with
// msg_id rkAfter, and side 1's note under the new epoch, then makes side
// 0 follow. It returns the confirm and the note.
func (f *r29Fx) rk7Confirm() (confirm, note Message) {
	f.t.Helper()
	f.rekey(0)
	if f.deliver(0, 1, kHSInit) != 1 || f.deliver(1, 0, kHSResp) != 1 || f.deliver(0, 1, kHSFin) != 1 {
		f.t.Fatal("setup: no rekey")
	}
	confirm = f.rkTake(kConfirm, rkAfter)
	f.note(1, "under the new epoch")
	note = f.rkTake(kNote, "rk-0700")
	f.rkFollow()
	if f.p(0).Pending == nil {
		f.t.Fatal("setup: no pending epoch")
	}
	return confirm, note
}

// RK7, hs.confirm: under an epoch a handshake signed by the current ik
// established, deposited with K after the cut-off, it passes and confirms.
func TestRK7HsConfirmPassesTheCutoff(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	confirm, _ := f.rk7Confirm()
	f.process(0, confirm)
	if f.superseded() != 0 || f.p(0).Pending != nil {
		t.Fatal("the hs.confirm after the cut-off did not pass and confirm")
	}
}

// RK7, the pass closes per epoch: once a message from a later relay key
// (K') was accepted under that epoch, an hs.confirm from K under it is
// refused superseded_relay.
func TestRK7HsConfirmClosedByALaterKey(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	confirm, note := f.rk7Confirm()
	note.Sender = relayauth.EncodeKey(f.p(0).Relay.PK) // deposited with K', the current key
	f.process(0, note)
	if f.p(0).Pending != nil || len(f.p(0).RelayClosures) != 1 {
		t.Fatal("setup: the note from K' was not accepted under the pending epoch, or not recorded")
	}
	f.process(0, confirm)
	if f.superseded() != 1 {
		t.Fatal("an hs.confirm from K after a message from K' under its epoch was not refused")
	}
}

// RK7's record: a message from K itself (not later than K) does not close
// K's pass.
func TestRK7NotClosedBySameKey(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	confirm, note := f.rk7Confirm()
	note.MsgID = rkBefore // from K, before the cut-off: accepted
	f.process(0, note)
	f.process(0, confirm)
	if f.superseded() != 0 {
		t.Fatal("a message from K closed K's own pass")
	}
}

// rk7Fx is a connection on K1 with K0 earlier and three epochs signed by
// its ik, established at e1 < e2 < e3.
func rk7Fx(t *testing.T) (*Manager, *Peer, [3][]byte) {
	f := newFixture(t)
	m := f.m
	m.opt.RelayKeyRotation = true
	k0, k1 := rkKey(0x51), rkKey(0x52)
	p := rkPeer(m, "c7", k0)
	p.IK = bytes.Repeat([]byte{7}, 32)
	m.relayAt, m.msgID = testNow().UTC(), "m-0100"
	if err := m.followRelayLinks(p, []*handshake.RelayLink{rkLink(t, k0, k1)}, rkAddr(k1)); err != nil {
		t.Fatal(err)
	}
	var ids [3][]byte
	at := testNow().UTC()
	for i, msg := range []string{"m-0200", "m-0300", "m-0400"} {
		ids[i] = bytes.Repeat([]byte{byte(i + 1)}, 16)
		p.Epochs = append(p.Epochs, EpochMeta{ID: ids[i], Signer: p.IK, EstAt: at, EstMsg: msg})
	}
	return m, p, ids
}

// RK7's order (0.90.2): establishment order by position; a tie is not
// later; an hs.fin's pass is closed only by an epoch established after
// its own position; pending and abandoned-while-pending epochs do not
// count, except the pass's own.
func TestRK7EpochOrder(t *testing.T) {
	m, p, ids := rk7Fx(t)
	k0, k1 := rkPub(rkKey(0x51)), rkPub(rkKey(0x52))
	at := p.Epochs[0].EstAt
	m.rk7Accepted(p, ids[1], k1) // under e2, from K1
	if len(p.RelayClosures) != 1 {
		t.Fatal("not recorded")
	}
	for _, c := range []struct {
		name   string
		epoch  []byte
		msg    string
		fin    bool
		closed bool
	}{
		{"its own epoch", ids[1], "m-0300", false, true},
		{"an earlier epoch", ids[0], "m-0200", false, true},
		{"a later epoch", ids[2], "m-0400", false, false},
		{"hs.fin before e2", nil, "m-0250", true, true},
		{"hs.fin at e2's position (a tie)", nil, "m-0300", true, false},
		{"hs.fin after e2", nil, "m-0350", true, false},
	} {
		if got := p.rk7Closed(c.epoch, at, c.msg, k0, c.fin); got != c.closed {
			t.Fatalf("%s: closed %v", c.name, got)
		}
	}
	if p.rk7Closed(ids[0], at, "m-0200", k1, false) {
		t.Fatal("a pass from K1 closed by a message from K1")
	}
	p.Epochs[1].Abandoned = true
	if p.rk7Closed(ids[0], at, "m-0200", k0, false) {
		t.Fatal("an epoch abandoned while pending counted for another epoch's pass")
	}
	if !p.rk7Closed(ids[1], at, "m-0300", k0, false) {
		t.Fatal("the pass's own epoch did not count")
	}
	p.Epochs[1].Abandoned, p.Epochs[1].Pending = false, true
	if p.rk7Closed(ids[0], at, "m-0200", k0, false) {
		t.Fatal("a pending epoch counted for another epoch's pass")
	}
}

// RK7's records: a record another covers is dropped (an epoch at or after
// it with a key not earlier), the records stay after their epoch is gone
// (a closure is never undone), and they go when no earlier key is kept.
func TestRK7RecordsKeptAndPruned(t *testing.T) {
	m, p, ids := rk7Fx(t)
	k0, k1 := rkPub(rkKey(0x51)), rkPub(rkKey(0x52))
	m.rk7Accepted(p, ids[0], k1)
	m.rk7Accepted(p, ids[0], k0) // covered
	if len(p.RelayClosures) != 1 {
		t.Fatalf("%d records, want 1", len(p.RelayClosures))
	}
	m.rk7Accepted(p, ids[2], k1) // covers the first
	if len(p.RelayClosures) != 1 || !bytes.Equal(p.RelayClosures[0].Epoch, ids[2]) {
		t.Fatal("a covered record was kept")
	}
	at := p.Epochs[0].EstAt
	p.Epochs = nil // destroyed and pruned
	if !p.rk7Closed(ids[0], at, "m-0200", k0, false) {
		t.Fatal("a closure was undone with its epoch")
	}
	p.EarlierRelays = nil
	pruneRelayClosures(p)
	if p.RelayClosures != nil {
		t.Fatal("records kept without an earlier key")
	}
	p.Epochs = append(p.Epochs, EpochMeta{ID: ids[0], Signer: p.IK, EstAt: at, EstMsg: "m-0200"})
	m.rk7Accepted(p, ids[0], k1)
	if p.RelayClosures != nil {
		t.Fatal("recorded without an earlier key")
	}
}

// RK7's first pass needs an epoch a handshake signed by the current ik
// established, and a connection (a device's relay key is not covered).
func TestRK7ConfirmNeedsCurrentSignerAndAVault(t *testing.T) {
	m, p, ids := rk7Fx(t)
	k0 := rkPub(rkKey(0x51))
	if !m.rk7ConfirmPasses(p, ids[0], k0) {
		t.Fatal("setup: does not pass")
	}
	p.Epochs[0].Signer = bytes.Repeat([]byte{8}, 32)
	if m.rk7ConfirmPasses(p, ids[0], k0) {
		t.Fatal("passed under an epoch signed by another ik")
	}
	p.Epochs[0].Signer = p.IK
	p.Kind = KindDesktop
	if m.rk7ConfirmPasses(p, ids[0], k0) {
		t.Fatal("passed for a device")
	}
}

// RK7, hs.fin: the pass is checked at the hs.fin's own position and
// closed only by an epoch established later than it, from a later key.
func TestRK7HsFinPassClosedByLaterEpoch(t *testing.T) {
	m, p, ids := rk7Fx(t)
	k0, k1 := rkPub(rkKey(0x51)), rkPub(rkKey(0x52))
	m.rk7Accepted(p, ids[1], k1) // e2, at m-0300
	aw := &AwaitingHS{Signer: append([]byte(nil), p.IK...)}
	m.relayAt = p.Epochs[0].EstAt
	m.msgID = "m-0250" // after K0's cut-off, before e2
	if m.rk7FinPasses(p, aw, k0) {
		t.Fatal("an hs.fin passed although a later key was accepted under an epoch established after it")
	}
	m.msgID = "m-0350" // after e2
	if !m.rk7FinPasses(p, aw, k0) {
		t.Fatal("an hs.fin after the closing epoch did not pass")
	}
}

// RK7: the hs.fin that establishes an epoch counts as accepted under it
// (rk7Established), unless the record is suspended or it established
// nothing.
func TestRK7EstablishingHsFinRecorded(t *testing.T) {
	m, p, ids := rk7Fx(t)
	k1 := rkPub(rkKey(0x52))
	m.rk7Established(p, ids[2], k1) // not current: nothing established
	if len(p.RelayClosures) != 0 {
		t.Fatal("recorded for an epoch not established")
	}
	p.LastEpochID = ids[2]
	m.rk7Established(p, ids[2], k1)
	if len(p.RelayClosures) != 1 {
		t.Fatal("the establishing hs.fin was not recorded")
	}
}

// RK7's records go with the last earlier key, at the prune.
func TestRK7RecordsPrunedWithEarlierKeys(t *testing.T) {
	m, p, ids := rk7Fx(t)
	m.rk7Accepted(p, ids[0], rkPub(rkKey(0x52)))
	m.pruneEarlierRelays(testNow().Add(1000 * 24 * time.Hour))
	if len(p.EarlierRelays) != 0 || p.RelayClosures != nil {
		t.Fatal("the records outlived the earlier keys")
	}
}

// rk7ReconnectFin runs side 1's reconnect up to its hs.fin, taken with
// msg_id rkAfter, makes side 0 follow, and returns the hs.fin and side 0's
// answer awaiting it.
func (f *r29Fx) rk7ReconnectFin() (Message, *AwaitingHS) {
	f.t.Helper()
	f.do(1, func(m *Manager, p *Peer) { m.startReconnect(p, f.clk) })
	if f.deliver(1, 0, kHSInit) != 1 || f.deliver(0, 1, kHSResp) != 1 {
		f.t.Fatal("setup: no reconnect")
	}
	fin := f.rkTake(kHSFin, rkAfter)
	f.rkFollow()
	if len(f.m(0).st.Awaiting) != 1 {
		f.t.Fatal("setup: no answer")
	}
	for _, aw := range f.m(0).st.Awaiting {
		return fin, aw
	}
	return fin, nil
}

// RK7 with H5's "Exempt": an answer kept as fork evidence passes whatever
// its pinned ik, so its hs.fin from an earlier key after its cut-off is
// judged as fork evidence: the connection suspends, and no epoch is
// established.
func TestRK7ForkEvidenceAnswerSuspendsAfterCutoff(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	fin, aw := f.rk7ReconnectFin()
	aw.Reconnect.Fork = true
	aw.Signer = bytes.Repeat([]byte{9}, 32) // pinned to an ik no longer current
	cur := append([]byte(nil), f.cur(0)...)
	f.process(0, fin)
	if f.p(0).Fork == nil || f.superseded() != 0 {
		t.Fatal("the fork-evidence hs.fin did not suspend, or was refused")
	}
	if !bytes.Equal(f.cur(0), cur) {
		t.Fatal("an epoch was established from fork evidence")
	}
}

// A non-exempt answer whose pinned ik is not current is still refused
// superseded_relay after the cut-off, the answer kept.
func TestRK7NonExemptAnswerNotCurrentIKRefused(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	fin, aw := f.rk7ReconnectFin()
	aw.Signer = bytes.Repeat([]byte{9}, 32)
	f.process(0, fin)
	if f.superseded() != 1 || len(f.m(0).st.Awaiting) != 1 || f.p(0).suspended() {
		t.Fatal("not refused superseded_relay with the answer kept")
	}
}

// RK7, hs.fin: the answer expects its hs.fin from the key its hs.init was
// deposited with; once that key is no longer kept (pruned between the
// hs.init and the hs.fin), an hs.fin from a later earlier key after its
// cut-off is refused superseded_relay, the answer kept.
func TestRK7HsFinRefusedWhenInitKeyPruned(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	f.m(0).opt.RelayKeyRotation = true
	f.rekey(1)
	if f.deliver(1, 0, kHSInit) != 1 || f.deliver(0, 1, kHSResp) != 1 {
		t.Fatal("setup: no rekey")
	}
	fin := f.rkTake(kHSFin, rkAfter)
	k, k1, k2 := f.m(1).keys.relay, rkKey(rkK1), rkKey(rkK2)
	f.do(0, func(m *Manager, p *Peer) {
		m.relayAt, m.msgID = f.clk, rkCut
		if err := m.followRelayLinks(p, []*handshake.RelayLink{rkLink(t, k, k1), rkLink(t, k1, k2)}, rkAddr(k2)); err != nil {
			t.Fatal(err)
		}
		p.EarlierRelays = p.EarlierRelays[1:] // K pruned
		// K1 can still deposit (a token issued to it), so it stays earlier.
		m.st.Issued = append(m.st.Issued, IssuedToken{JTI: "k1-st", Kind: TokStanding, Sub: relayauth.EncodeKey(rkPub(k1)),
			PeerID: p.ID, Exp: f.clk.Add(30 * 24 * time.Hour)})
	})
	fin.Sender = relayauth.EncodeKey(rkPub(k1)) // deposited with K1, earlier, after its cut-off
	n := f.answerCount(0)
	f.process(0, fin)
	if f.superseded() != 1 || f.answerCount(0) != n || n == 0 {
		t.Fatalf("not refused with the answer kept: refused %d, answers %d -> %d", f.superseded(), n, f.answerCount(0))
	}
}

// RK7: a record whose position is not known counts as later (fail
// closed): it closes the pass of an epoch whatever that epoch's position.
func TestRK7UnknownPositionCloses(t *testing.T) {
	_, p, ids := rk7Fx(t)
	k0, k1 := rkPub(rkKey(0x51)), rkPub(rkKey(0x52))
	p.RelayClosures = []RelayClosure{{Epoch: bytes.Repeat([]byte{0xee}, 16), Key: k1}}
	if !p.rk7Closed(ids[2], p.Epochs[2].EstAt, "m-0400", k0, false) {
		t.Fatal("a record of unknown position did not close the pass")
	}
}

// RK7's records: a record under a later epoch from an earlier key does not
// cover one under an earlier epoch from a later key (each closes passes
// the other does not): both are kept.
func TestRK7RecordsKeyOrderKeepsBoth(t *testing.T) {
	m, p, ids := rk7Fx(t)
	k0, k1 := rkPub(rkKey(0x51)), rkPub(rkKey(0x52))
	m.rk7Accepted(p, ids[0], k1)
	m.rk7Accepted(p, ids[2], k0)
	if len(p.RelayClosures) != 2 {
		t.Fatalf("%d records, want 2", len(p.RelayClosures))
	}
	if !p.rk7Closed(ids[0], p.Epochs[0].EstAt, "m-0200", k0, false) {
		t.Fatal("the record from the later key was lost")
	}
}

// RK7 records only accepted messages: one from a later key under the
// epoch that its handler refuses (an update refused relay_unlinked) closes
// nothing, and the hs.confirm from K still passes.
func TestRK7RefusedMessageClosesNothing(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	f.rekey(0)
	if f.deliver(0, 1, kHSInit) != 1 || f.deliver(1, 0, kHSResp) != 1 || f.deliver(0, 1, kHSFin) != 1 {
		t.Fatal("setup: no rekey")
	}
	confirm := f.rkTake(kConfirm, rkAfter)
	k1 := rkKey(rkK1)
	u := &peerwire.AddressUpdate{Relay: rkAddr(k1), Token: f.rk8Tok(k1, "rf-st", 25*24*time.Hour),
		Links: []*handshake.RelayLink{rkLink(t, f.m(1).keys.relay, k1)}}
	f.do(1, func(m *Manager, p *Peer) {
		b, err := u.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		m.sendTo(p, peerwire.TypeRelayAddressUpdate, b, f.clk)
	})
	upd := f.rkTake(kOther, "rk-0700")
	f.rkFollow()
	upd.Sender = relayauth.EncodeKey(f.p(0).Relay.PK) // from K', the current key: its first old is not the sender
	f.process(0, upd)
	if f.activityCount(0, "drop.peer_key", "relay_unlinked") != 1 || len(f.p(0).RelayClosures) != 0 {
		t.Fatal("setup: the update was not refused, or a closure was recorded for it")
	}
	f.process(0, confirm)
	if f.superseded() != 0 {
		t.Fatal("a refused message closed the pass")
	}
}
