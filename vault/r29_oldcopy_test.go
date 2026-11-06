package vault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"
	"github.com/vettid/vettid-relay/relayclient"

	"github.com/vettid/vettid-vault/vault/store"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
)

// The old-copy actor (VAULT-MESSAGING §3.4.1 "Threat"): a snapshot of a
// vault's sealed state, taken at any write, run later as a second live
// copy. It holds what the vault held then (relay key, ik, kem, epochs,
// tokens) and deposits with those keys; the relay cannot tell its
// deposits from the original's, and it can collect from the shared
// mailbox (the test decides which copy a message reaches).

// snapshot takes side s's state as of its last write (its store holds
// exactly what the last write stored).
func (f *r29Fx) snapshot(s int) *store.Memory {
	f.t.Helper()
	m := f.m(s)
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.flushIfDirty(context.Background()); err != nil {
		f.t.Fatal(err)
	}
	return f.d[s].store.(*store.Memory).Clone()
}

// startCopy runs snap, an old copy of side s, as side 2: unlocked from its
// own store with its own relay stub, on the shared clock.
func (f *r29Fx) startCopy(s int, snap *store.Memory) {
	f.t.Helper()
	orig := f.d[s].fixture
	cf := &fixture{t: f.t, store: snap, vid: orig.vid}
	cf.opts = orig.opts
	cf.opts.Store = snap
	cf.opts.Relay = func(base string, key ed25519.PrivateKey) Relay {
		cf.relay = &stubRelay{base: base, key: key}
		return cf.relay
	}
	m, _, err := cf.unlock(testPIN, 0, 0)
	if err != nil {
		f.t.Fatalf("the old copy does not unlock: %v", err)
	}
	cf.m = m
	m.now = func() time.Time { return f.clk }
	m.register(TypeSpec{Type: "test.note", From: []string{KindConnection}, Connections: PeersBoth},
		HandlerFunc(func(_ context.Context, _ *Session, in *envelope.Inner) (json.RawMessage, error) {
			f.got[2] = append(f.got[2], string(in.Body))
			return nil, nil
		}))
	f.sink[2] = &recSink{}
	m.features = append(m.features, f.sink[2])
	f.d[2] = &devFixture{fixture: cf}
	f.id[2] = f.id[s]
}

// deliverAt is deliver with the relay's assertion of position: the
// deposits get msg_id id (and the same deposited_at), whatever the order
// in which the receiver processes them (§3.4.1: the relay asserts the
// order of msg_ids).
func (f *r29Fx) deliverAt(from, to, k int, id string) int {
	f.t.Helper()
	fm := f.m(from)
	fm.mu.Lock()
	_ = fm.flushThenDrain(context.Background())
	fm.mu.Unlock()
	d, tod := f.d[from], f.d[to]
	toPK := tod.m.keys.relay.Public().(ed25519.PublicKey)
	var msgs []Message
	d.relay.mu.Lock()
	kept := d.relay.deposits[:0]
	for i, dep := range d.relay.deposits {
		env, err := envelope.Parse(dep.payload)
		if err != nil || dep.mailbox != tod.m.st.Relay.Mailbox || !(k == kAny || f.kindOf(from, to, env) == k) {
			kept = append(kept, dep)
			continue
		}
		jti := ""
		if c, err := relayauth.ParseToken(dep.token, toPK); err == nil {
			jti = c.Jti
		}
		msgs = append(msgs, Message{MsgID: fmt.Sprintf("%s-%d", id, i), Sender: relayauth.EncodeKey(f.pk(from)), JTI: jti, Payload: dep.payload,
			DepositedAt: f.clk.UTC().Format(time.RFC3339Nano)})
	}
	d.relay.deposits = kept
	d.relay.mu.Unlock()
	if len(msgs) > 0 {
		if err := tod.m.ProcessBatch(context.Background(), &fakeCollector{}, msgs); err != nil {
			f.t.Fatal(err)
		}
	}
	return len(msgs)
}

// suspendedRef reports whether side s suspended its connection on fork
// evidence with the given ref (or on a rotation conflict, ref "conflict").
func (f *r29Fx) suspendedRef(s int, ref string) bool {
	p := f.p(s)
	if ref == "conflict" {
		return p.Conflict != nil
	}
	if p.Fork == nil {
		return false
	}
	for _, a := range f.sink[s].got {
		if a.Kind == "connection.fork_suspected" && a.Ref == ref {
			return true
		}
	}
	return false
}

func (f *r29Fx) activity(s int, kind, ref string) bool {
	for _, a := range f.sink[s].got {
		if a.Kind == kind && (ref == "" || a.Ref == ref) {
			return true
		}
	}
	return false
}

// A copy that holds what the original held is indistinguishable before
// any rotation: its message is accepted.
func TestR29OldCopyHarness(t *testing.T) {
	f := newR29Fx(t)
	snap := f.snapshot(0)
	f.startCopy(0, snap)
	f.note(2, "from-the-copy")
	if f.deliver(2, 1, kNote) != 1 || len(f.got[1]) != 1 {
		t.Fatal("the copy's message did not reach the peer as the original's")
	}
}

// Model: TestBlindF1CopyFinishesAnswer, with the shape of
// TestLeadMisattributedSeed. The copy of R, taken after R answered I's
// rekey, collects I's hs.fin, activates E1 and confirms it at I; the real
// R rotated and dropped its answer (S5), so it stays on E0. R's link under
// E0 makes I demote E1 (strict F1) and reconnect naming E0; R's restarted
// rekey from E0 names an epoch older than I's confirmed E1, signed by R's
// old ik: fork evidence, with no exception for an epoch I began (§3.4.1
// "Fork by ctx", 0.87.1): I suspends (ref epoch).
func TestR29OldCopyFinishesAnswerMisattributedShape(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	f.rekey(0)
	f.deliver(0, 1, kHSInit) // R answers
	snap := f.snapshot(1)    // the copy holds R's answer
	f.rotate(1)              // S5: R drops its answer
	f.deliver(0, 1, kAny)    // nothing pending from I yet
	// I takes R's hs.resp (deposited before R's rotation) and goes pending.
	f.deliver(1, 0, kHSResp)
	f.startCopy(1, snap)
	if f.deliver(0, 2, kHSFin) != 1 { // the copy collects the hs.fin
		t.Fatal("setup: no hs.fin for the copy")
	}
	f.deliver(2, 0, kConfirm) // and confirms E1 at I as R
	e1 := append([]byte(nil), f.cur(0)...)
	if f.p(0).Pending != nil {
		t.Fatal("setup: the copy did not confirm E1")
	}
	f.deliver(1, 0, kRotate) // R's link, under E0
	if e := f.p(0).epochMeta(e1); e == nil || !e.Demoted {
		f.dump()
		t.Fatal("F1 did not demote the copy's epoch")
	}
	f.settle()
	f.advance(time.Hour)
	f.tick(0)
	f.tick(1)
	f.settle()
	if !f.suspendedRef(0, "epoch") {
		f.dump()
		t.Fatal("the copy's confirmed epoch did not make a ctx naming E0 fork evidence")
	}
}

// Model: TestBlindF2aForcedSuspension (no copy). I's hs.fin, made before
// I's rotation, is processed first but asserted by the relay as deposited
// after I's link: R demotes the epoch it established (signed by the old
// ik, after the link), and I's restarted rekey naming E0 is ordinary (R's
// confirmed epoch): no forced suspension.
func TestR29BlindF2aNoForcedSuspension(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	f.rekey(0)
	f.deliver(0, 1, kHSInit)
	f.deliver(1, 0, kHSResp) // I pending E1, hs.fin out (signed ik0)
	f.rotate(0)              // S5: E1 abandoned; identity.rotate; a rekey again
	f.deliverAt(0, 1, kHSFin, "pump-z")
	f.deliverAt(0, 1, kRotate, "pump-a")
	f.settle()
	f.advance(time.Hour)
	f.tick(0)
	f.tick(1)
	f.settle()
	if f.p(0).suspended() || f.p(1).suspended() {
		f.dump()
		t.Fatal("F2a: a forced suspension")
	}
	if !f.sameEpoch() {
		f.dump()
		t.Fatal("did not converge")
	}
	f.talks()
}

// Model: TestBlindF2bHiddenFork. The copy of P (taken before P's rotation)
// rekeys with Q; its hs.fin is asserted before P's link, so position does
// not demote the copy's epoch; P's link under E0 does (strict F1), and the
// copy's epoch is not current at the end.
func TestR29BlindF2bCopyEpochNotKept(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	snap := f.snapshot(0)
	f.rotate(0)
	f.startCopy(0, snap)
	f.do(2, func(m *Manager, p *Peer) { m.startRekey(p, f.clk) })
	f.deliver(2, 1, kHSInit)
	f.deliver(1, 2, kHSResp)
	f.deliverAt(2, 1, kHSFin, "pump-a")
	ec := append([]byte(nil), f.cur(1)...)
	f.deliverAt(0, 1, kRotate, "pump-b")
	if e := f.p(1).epochMeta(ec); e == nil || !e.Demoted {
		f.dump()
		t.Fatal("F2b: the copy's epoch was not demoted by the original's link")
	}
	f.settle()
	f.advance(time.Hour)
	f.tick(0)
	f.tick(1)
	f.settle()
	if bytes.Equal(f.cur(1), ec) {
		f.dump()
		t.Fatal("the copy's epoch is still current")
	}
	t.Logf("F2b: Q suspended %v, stale %v, same epoch as P %v", f.p(1).suspended(), f.p(1).State == PeerStale, f.sameEpoch())
}

// Model: TestBlindF3RuleEHidesTwoCopies. P confirmed E1 but Q has received
// nothing under it; P's copy (holding E0) reconnects naming E0, Q's
// confirmed epoch: rule E destroys E1 at its hs.fin. P's next message
// under E1, with a later ts, is fork evidence: Q suspends (ref epoch).
func TestR29BlindF3RuleEEvidenceSuspends(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	snap := f.snapshot(0)
	f.rekey(0)
	f.deliver(0, 1, kHSInit)
	f.deliver(1, 0, kHSResp)
	f.deliver(0, 1, kHSFin)
	f.deliver(1, 0, kConfirm)
	if f.p(0).Pending != nil {
		t.Fatal("setup: P did not confirm")
	}
	f.startCopy(0, snap)
	f.do(2, func(m *Manager, p *Peer) { m.startReconnect(p, f.clk) })
	f.deliver(2, 1, kHSInit)
	f.deliver(1, 2, kHSResp)
	f.deliver(2, 1, kHSFin)
	f.advance(time.Minute)
	f.note(0, "under-E1")
	f.deliver(0, 1, kNote)
	if !f.suspendedRef(1, "epoch") {
		f.dump()
		t.Fatal("F3: rule E's evidence did not suspend")
	}
}

// Model: TestLeadFixAOwnCopyCannotHideFork. P sent a message under E1, an
// epoch Q began; P's copy (holding E0) rotates and reconnects naming E0:
// with no exception for an epoch Q began (§3.4.1 "Fork by ctx"), the
// copy's fork is caught at once (ref epoch).
func TestR29OwnCopyCannotHideFork(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	snap := f.snapshot(0)
	f.rekey(1) // Q begins E1 with P
	f.settle()
	f.note(0, "under-E1") // P sends under E1: Q's confirmed epoch
	f.settle()
	f.startCopy(0, snap)
	f.rotate(2) // the copy's second successor of ik0
	f.deliver(2, 1, kRotate)
	f.deliver(2, 1, kAny)
	if !f.suspendedRef(1, "epoch") {
		f.dump()
		t.Fatal("the copy's reconnect over an epoch P sent under did not suspend")
	}
}

// The I3 hole lead fix B had: Q rekeys; P's old copy answers it and
// confirms it, so Q makes current an epoch made with the copy (signed by
// P's old ik). P's real link under E0 must not let it be kept: strict F1
// demotes it, and P's rekey from E0 is then fork evidence (§3.4.1 "Fork
// by ctx": no exception for an epoch Q began): Q suspends.
func TestR29OldCopyAnswerToRekeyNotKept(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	snap := f.snapshot(0)
	f.startCopy(0, snap)
	f.rekey(1)
	f.deliver(1, 2, kHSInit) // the copy collects it
	f.deliver(2, 1, kHSResp) // and answers as P
	f.deliver(1, 2, kHSFin)
	f.deliver(2, 1, kConfirm) // and confirms it as P
	ec := append([]byte(nil), f.cur(1)...)
	if f.p(1).Pending != nil {
		t.Fatal("setup: the copy did not confirm Q's epoch")
	}
	f.rotate(0)
	f.deliver(0, 1, kRotate)
	if e := f.p(1).epochMeta(ec); e == nil || !e.Demoted {
		f.dump()
		t.Fatal("the copy's epoch was not demoted")
	}
	f.settle()
	f.advance(time.Hour)
	f.tick(0)
	f.tick(1)
	f.settle()
	if !f.suspendedRef(1, "epoch") {
		f.dump()
		t.Fatal("Q did not suspend on the copy's epoch")
	}
}

// The shape of TestLeadFixBSeed (seed 8756148401117559123, R1, the gate
// unseen both ways) under the strict F1 the lead chose. Neither side has
// seen the other's features: Q activates at hs.fin; P keeps its answer
// across its rotation (S5 toward an ungated peer), establishes it at
// Q's hs.fin, and its link travelled under E0 before that hs.fin
// arrived. Strict F1 demotes an epoch P did activate. The model at
// 641ef63 runs that seed clean under strict (F1 demoted 2, no
// violation), so the expected outcome here is no suspension and
// convergence; a suspension would be the "false suspension" the lead
// accepted as the cost of strict F1.
func TestR29FixBSeedShapeStrictExpected(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	for s := 0; s < 2; s++ {
		f.do(s, func(_ *Manager, p *Peer) { p.PeerFeatures = nil })
	}
	f.rekey(1)
	f.deliver(1, 0, kHSInit)
	f.do(0, func(_ *Manager, p *Peer) { p.PeerFeatures = nil })
	f.rotate(0) // P keeps its answer (Q ungated)
	f.deliver(0, 1, kHSResp)
	f.deliver(0, 1, kRotate) // P's link under E0, before Q's hs.fin reaches P
	f.deliver(1, 0, kHSFin)
	f.settle()
	f.advance(time.Hour)
	f.tick(0)
	f.tick(1)
	f.settle()
	sus := f.p(0).suspended() || f.p(1).suspended()
	t.Logf("strict F1, gate unseen: suspended %v, same epoch %v, stale %v/%v", sus, f.sameEpoch(), f.p(0).State, f.p(1).State)
	if sus {
		f.dump()
		t.Fatal("a false suspension (the model at 641ef63 runs this seed clean)")
	}
	if !f.sameEpoch() {
		f.dump()
		t.Fatal("did not converge")
	}
	f.talks()
}

// §3.4.1 "Epochs after an ik link": while the current epoch is demoted the
// vault sends nothing, but what it makes meanwhile is held, not lost:
// sealed under the new epoch once the reconnect establishes it, and
// delivered exactly once. (A test.note stands in for a member's
// message.send relayed to the peer: the same durable send path,
// SendToConnection -> sendTo -> sealAndQueue.)
func TestR29DemotedHoldsMessagesUntilNewEpoch(t *testing.T) {
	f := demoted(t, nil)
	f.note(0, "held-while-demoted")
	held := 0
	for _, e := range f.m(0).st.Outbox {
		if e.Held != nil && !e.Done {
			held++
		}
	}
	if held != 1 {
		t.Fatalf("held entries %d", held)
	}
	f.settle()
	f.advance(time.Hour)
	f.tick(0)
	f.tick(1)
	f.settle()
	f.settle()
	n := 0
	for _, b := range f.got[1] {
		if bytes.Contains([]byte(b), []byte("held-while-demoted")) {
			n++
		}
	}
	if n != 1 || !f.sameEpoch() {
		f.dump()
		t.Fatalf("the held message arrived %d times (same epoch %v)", n, f.sameEpoch())
	}
}

// demoted sets up side 0 with its current epoch E1 demoted by side 1's
// link (strict F1, its received flag clear): side 1 rekeyed E0 to E1,
// side 0 activated E1 at hs.fin as responder, and side 1 rotated before
// any hs.confirm reached it (S5 abandons its pending E1), so its
// identity.rotate travels under E0. before runs just before the link
// arrives.
func demoted(t *testing.T, before func(f *r29Fx)) *r29Fx {
	t.Helper()
	f := newR29Fx(t)
	f.longTokens()
	f.rekey(1)
	f.deliver(1, 0, kHSInit)
	f.deliver(0, 1, kHSResp)
	f.deliver(1, 0, kHSFin)
	e1 := append([]byte(nil), f.cur(0)...)
	if f.lose(0, 1, kConfirm) != 1 || f.p(1).Pending == nil {
		t.Fatal("setup: side 1's E1 is not pending")
	}
	f.rotate(1)
	if before != nil {
		before(f)
	}
	f.deliver(1, 0, kRotate)
	if e := f.p(0).epochMeta(e1); e == nil || !e.Demoted {
		f.dump()
		t.Fatal("setup: the current epoch is not demoted")
	}
	return f
}

func (f *r29Fx) arrived(s int, body string) int {
	n := 0
	for _, b := range f.got[s] {
		if bytes.Contains([]byte(b), []byte(body)) {
			n++
		}
	}
	return n
}

// Held longer than the 16-day durable ts window: sealed with a new ts, so
// it is still accepted after the reconnect.
func TestR29HeldLongerThanTSWindow(t *testing.T) {
	f := demoted(t, nil)
	f.note(0, "held-long")
	f.lose(0, 1, kAny) // the first reconnect is lost: the hold lasts
	f.advance(HandshakeTTL + 24*time.Hour)
	f.tick(0) // the reconnect expired: tried again
	f.tick(1)
	f.settle()
	f.advance(time.Hour)
	f.tick(0)
	f.tick(1)
	f.settle()
	if n := f.arrived(1, "held-long"); n != 1 || !f.sameEpoch() {
		f.dump()
		t.Fatalf("a message held %v arrived %d times", HandshakeTTL+24*time.Hour, n)
	}
}

// A held message whose exp passes is discarded: nothing is deposited.
func TestR29HeldExpiredDiscarded(t *testing.T) {
	f := demoted(t, nil)
	f.do(0, func(m *Manager, p *Peer) {
		m.sendWith(p, "test.note", json.RawMessage(`{"n":"expiring"}`), SendOptions{Exp: f.clk.Add(time.Hour)}, f.clk)
	})
	f.advance(2 * time.Hour)
	f.tick(0)
	for _, e := range f.m(0).st.Outbox {
		if e.Held != nil && !e.Done {
			t.Fatal("an expired held message is still held")
		}
	}
	f.settle()
	f.advance(time.Hour)
	f.tick(0)
	f.tick(1)
	f.settle()
	if n := f.arrived(1, "expiring"); n != 0 {
		t.Fatalf("an expired held message was delivered %d times", n)
	}
}

// A message sealed under the epoch before its demotion and not yet
// deposited goes back to held and arrives once, under the new epoch (the
// real peer never held the demoted one, so it could not have opened it).
func TestR29SealedUndepositedResealed(t *testing.T) {
	var r *stubRelay
	f := demoted(t, func(f *r29Fx) {
		r = f.d[0].relay
		r.mu.Lock()
		r.failMailbox = map[string]error{f.m(1).st.Relay.Mailbox: &relayclient.Error{Status: 503, Code: "unavailable"}}
		r.mu.Unlock()
		f.note(0, "sealed-before")
		r.mu.Lock()
		r.failMailbox = nil
		r.mu.Unlock()
	})
	held := 0
	for _, e := range f.m(0).st.Outbox {
		if e.Held != nil && !e.Done && bytes.Contains(e.Held, []byte("sealed-before")) {
			held++
		}
	}
	if held != 1 {
		t.Fatalf("the undeposited entry was not held again (%d)", held)
	}
	f.settle()
	f.advance(time.Hour)
	f.tick(0)
	f.tick(1)
	f.settle()
	if n := f.arrived(1, "sealed-before"); n != 1 || !f.sameEpoch() {
		f.dump()
		t.Fatalf("arrived %d times", n)
	}
}

// A rekey hs.init naming an older epoch that fails what AcceptRekey checks
// changes nothing (it is refused before the fork rule could move any
// state).
func TestR29MalformedRekeyOtherEpochChangesNothing(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	f.rekey(0)
	f.deliver(0, 1, kHSInit)
	snap := f.snapshot(1)
	f.rotate(1)
	f.lose(1, 0, kHSInit) // R's own restarted rekey: not delivered here
	f.deliver(1, 0, kHSResp)
	f.startCopy(1, snap)
	f.deliver(0, 2, kHSFin)
	f.deliver(2, 0, kConfirm)
	f.deliver(1, 0, kRotate)
	state := func() []byte {
		c := *f.p(0)
		c.Sessions = handshake.KeyringState{} // its receive count moves with any message opened
		j, _ := json.Marshal(&c)
		return j
	}
	before := state()
	nAct := len(f.sink[0].got)
	// A forged rekey under E0: an hs.init whose body does not parse.
	f.do(1, func(m *Manager, p *Peer) {
		in := &envelope.Inner{ID: m.newID(f.clk), Type: handshake.TypeInit, TS: f.clk, Body: json.RawMessage(`{"purpose":"rekey"}`)}
		raw, err := m.sealFor(p, m.sessions[p.ID].Current(), in)
		if err != nil {
			t.Fatal(err)
		}
		m.queueDeposit(&OutboxEntry{PeerID: p.ID, RelayURL: p.Relay.URL, Mailbox: p.Relay.Mailbox, Payload: raw}, f.clk)
	})
	f.deliver(1, 0, kHSInit)
	after := state()
	if !bytes.Equal(before, after) {
		t.Logf("before %s\nafter  %s", before, after)
	}
	if !bytes.Equal(before, after) || len(f.sink[0].got) != nNonRejected(f.sink[0].got, nAct) {
		f.dump()
		t.Fatal("a malformed rekey changed the connection's state")
	}
	if !f.audited(0, "rekey_rejected") {
		t.Fatal("not refused")
	}
}

// nNonRejected: the activity count expected after a refusal (one
// drop.rekey_rejected added to n).
func nNonRejected(got []Activity, n int) int {
	for _, a := range got[n:] {
		if a.Kind != "drop.rekey_rejected" {
			return -1
		}
	}
	return len(got)
}

// The lead's call: while the current epoch is demoted, reconnects that
// expire are counted; the third expiry makes the connection stale (with
// connection.stale), and no fourth starts. Each expired one's tokens are
// revoked.
func TestR29DemotedReconnectsBoundedThenStale(t *testing.T) {
	f := demoted(t, nil)
	for i := 1; i <= 3; i++ {
		var jtis []string
		for _, og := range f.m(0).st.Outgoing {
			if og.Purpose == handshake.PurposeReconnect {
				for _, it := range og.Issued {
					jtis = append(jtis, it.JTI)
				}
			}
		}
		if len(jtis) == 0 {
			f.dump()
			t.Fatalf("try %d: no reconnect open", i)
		}
		f.lose(0, 1, kAny)
		f.advance(HandshakeTTL + time.Hour)
		f.tick(0)
		for _, j := range jtis {
			denied := false
			for _, it := range f.m(0).st.Issued {
				denied = denied || it.JTI == j && it.Denied
			}
			if !denied {
				t.Fatalf("try %d: an expired reconnect's token was not revoked", i)
			}
		}
		if i < 3 && f.p(0).State == PeerStale {
			t.Fatalf("stale after %d expiries", i)
		}
	}
	if f.p(0).State != PeerStale || !f.sink[0].has("connection.stale") {
		t.Fatal("the third expiry did not make the connection stale")
	}
	f.advance(HandshakeTTL + time.Hour)
	f.tick(0)
	if f.m(0).hasOutgoing(f.id[0], handshake.PurposeReconnect) {
		t.Fatal("a fourth reconnect started")
	}
}

// openReconnect returns side s's open reconnect, or nil.
func (f *r29Fx) openReconnect(s int) *OutgoingHS {
	for _, og := range f.m(s).st.Outgoing {
		if og.New == nil && og.PeerID == f.id[s] && og.Purpose == handshake.PurposeReconnect {
			return og
		}
	}
	return nil
}

// 0.86.5 (a): while the reconnect after a demotion has its epoch pending
// (awaiting confirmation), no second reconnect starts, even past the
// handshake's own lifetime; and it names no demoted epoch.
func TestR29DemotedNoSecondReconnectWhilePending(t *testing.T) {
	f := demoted(t, nil)
	og := f.openReconnect(0)
	if og == nil {
		t.Fatal("setup: no reconnect")
	}
	if e := f.p(0).epochMeta(og.Named); e == nil || e.Demoted || e.Abandoned || e.Pending || e.Destroyed {
		t.Fatal("the reconnect names an epoch it must not")
	}
	f.deliver(0, 1, kHSInit)
	f.deliver(1, 0, kHSResp)
	if f.p(0).Pending == nil {
		t.Fatal("setup: no pending reconnect epoch")
	}
	f.lose(0, 1, kHSFin)
	f.advance(HandshakeTTL + 24*time.Hour) // within B
	f.tick(0)
	if f.openReconnect(0) != nil || f.p(0).Pending == nil {
		t.Fatal("a second reconnect started while the first's epoch was pending")
	}
}

// 0.86.5 (b): a try fails when its handshake expires or its pending
// epoch is abandoned; both count, and the third makes the connection
// stale, with no fourth try.
func TestR29DemotedExpiryAndAbandonCountAsTries(t *testing.T) {
	f := demoted(t, nil)
	// try 1: expires unanswered
	f.lose(0, 1, kAny)
	f.advance(HandshakeTTL + time.Hour)
	f.tick(0)
	if f.p(0).State == PeerStale || f.openReconnect(0) == nil {
		t.Fatal("after one expiry: stale, or no second try")
	}
	// tries 2 and 3: answered, pending, the hs.fin lost; B abandons them
	for try := 2; try <= 3; try++ {
		f.deliver(0, 1, kHSInit)
		f.deliver(1, 0, kHSResp)
		if f.p(0).Pending == nil {
			f.dump()
			t.Fatalf("try %d: not pending", try)
		}
		f.lose(0, 1, kAny)
		f.lose(1, 0, kAny)
		f.advance(PendingLife + time.Hour)
		f.tick(0)
		f.tick(0)
		if f.p(0).Pending != nil {
			t.Fatalf("try %d: B did not abandon", try)
		}
		if try < 3 && (f.p(0).State == PeerStale || f.openReconnect(0) == nil) {
			t.Fatalf("try %d: stale too early, or no next try", try)
		}
	}
	if f.p(0).State != PeerStale || !f.sink[0].has("connection.stale") {
		f.dump()
		t.Fatal("the third failed try (an abandon) did not make it stale")
	}
	if f.openReconnect(0) != nil {
		t.Fatal("a fourth try started")
	}
}
