package vault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
)

// VAULT-MESSAGING 0.86.0 (§6.3.1, §3.4.1) scenarios against the real code:
// two vaults in process, a shared clock, and a relay the test controls
// message by message (deliver, hold, lose). The scenarios are those of the
// executable model (vettid-vault trust-model, internal/trustmodel at
// 641ef63) that this release's rules fix. A release-28 peer is stood in for
// by a vault marked by setEmu28 (build tag vettid_emu28; skipped without): no features sent or counted, no hs.confirm,
// no rule E, no revert, identity.rotate read from `rotation` only, a rekey
// only under the current epoch and without rotations, no rules J and L.

type r29Fx struct {
	t    *testing.T
	d    [3]*devFixture // sides 0 and 1; 2: an old copy (startCopy)
	id   [3]string
	clk  time.Time
	got  [3][]string // test.note bodies each side received
	sink [3]*recSink // each side's activity
}

// newR29Fx connects two vaults (side 0 the inviter) on a shared clock.
// emu says which sides stand in for release 28.
func newR29Fx(t *testing.T, emu ...bool) *r29Fx {
	t.Helper()
	f := &r29Fx{t: t, clk: time.Now().UTC().Truncate(time.Millisecond)}
	a, b := newVaultPair(t)
	f.d = [3]*devFixture{a, b}
	for s, d := range f.d[:2] {
		s := s
		d.m.now = func() time.Time { return f.clk }
		d.m.register(TypeSpec{Type: "test.note", From: []string{KindConnection}, Connections: PeersBoth},
			HandlerFunc(func(_ context.Context, _ *Session, in *envelope.Inner) (json.RawMessage, error) {
				f.got[s] = append(f.got[s], string(in.Body))
				return nil, nil
			}))
		if s < len(emu) && emu[s] {
			setEmu28(t, d.m)
		}
		f.sink[s] = &recSink{}
		d.m.features = append(d.m.features, f.sink[s])
	}
	_, link := a.linkFor(t, time.Hour)
	r, _ := b.request(t, "connection.invite.accept", `{"link":"`+link+`"}`)
	cid := bodyStr(t, r, "connection_id")
	pump(t, b, a)
	pump(t, a, b)
	b.appInbox()
	pump(t, b, a)
	aPend := event(a.appInbox(), "connection.request.pending")
	a.request(t, "connection.approve", `{"pending_id":"`+bodyStr(t, aPend, "pending_id")+`"}`)
	pump(t, a, b)
	b.request(t, "connection.approve", `{"connection_id":"`+cid+`"}`)
	pump(t, b, a)
	for s, d := range f.d[:2] {
		for id, p := range d.m.st.Connections {
			f.id[s] = id
			if p.State != PeerActive {
				t.Fatal("not connected")
			}
		}
		d.appInbox()
	}
	f.settle()
	return f
}

func (f *r29Fx) p(s int) *Peer           { return f.d[s].m.st.Connections[f.id[s]] }
func (f *r29Fx) m(s int) *Manager        { return f.d[s].m }
func (f *r29Fx) advance(d time.Duration) { f.clk = f.clk.Add(d) }
func (f *r29Fx) pk(s int) ed25519.PublicKey {
	return f.d[s].m.keys.relay.Public().(ed25519.PublicKey)
}

// do runs fn on side s's vault under its lock, then flushes and drains.
func (f *r29Fx) do(s int, fn func(m *Manager, p *Peer)) {
	f.t.Helper()
	m := f.m(s)
	m.mu.Lock()
	fn(m, f.p(s))
	if err := m.flushThenDrain(context.Background()); err != nil {
		f.t.Fatal(err)
	}
	m.mu.Unlock()
}

// kinds of deposit, as the receiving side sees them.
const (
	kAny = iota
	kHSInit
	kHSResp
	kHSFin
	kConfirm
	kNote
	kRotate
	kOther
)

// kindOf classifies a deposit from side from to side to.
func (f *r29Fx) kindOf(from, to int, env *envelope.Envelope) int {
	m := f.m(to)
	if env.Mode() == envelope.ModeSealed {
		if m.lookupKEM(env.RecipientKid()) != nil {
			return kHSInit
		}
		return kHSResp
	}
	if m.awaitingByKids(env, f.pk(from)) != "" {
		return kHSFin
	}
	kr := m.sessions[f.id[to]]
	if kr == nil {
		return kOther
	}
	in, _, err := kr.Open(env, f.clk)
	if err != nil {
		return kOther
	}
	switch in.Type {
	case handshake.TypeInit:
		return kHSInit
	case handshake.TypeConfirm:
		return kConfirm
	case "test.note":
		return kNote
	case "identity.rotate":
		return kRotate
	}
	return kOther
}

// deliver moves from's deposits of kind k to to (kAny: all), in one batch.
func (f *r29Fx) deliver(from, to, k int) int {
	f.t.Helper()
	fm := f.m(from)
	fm.mu.Lock()
	_ = fm.flushThenDrain(context.Background())
	fm.mu.Unlock()
	return pumpOnly(f.t, f.d[from], f.d[to], func(env *envelope.Envelope) bool { return k == kAny || f.kindOf(from, to, env) == k })
}

// lose removes from's deposits of kind k to to without delivering them.
func (f *r29Fx) lose(from, to, k int) int {
	f.t.Helper()
	fm := f.m(from)
	fm.mu.Lock()
	_ = fm.flushThenDrain(context.Background())
	fm.mu.Unlock()
	d := f.d[from]
	d.relay.mu.Lock()
	defer d.relay.mu.Unlock()
	n := 0
	kept := d.relay.deposits[:0]
	for _, dep := range d.relay.deposits {
		env, err := envelope.Parse(dep.payload)
		if err == nil && dep.mailbox == f.m(to).st.Relay.Mailbox && (k == kAny || f.kindOf(from, to, env) == k) {
			n++
			continue
		}
		kept = append(kept, dep)
	}
	d.relay.deposits = kept
	return n
}

// settle delivers everything both ways until nothing moves (the apps'
// inboxes are emptied).
func (f *r29Fx) settle() {
	f.t.Helper()
	for i := 0; i < 12; i++ {
		n := f.deliver(0, 1, kAny) + f.deliver(1, 0, kAny)
		f.d[0].appInbox()
		f.d[1].appInbox()
		if n == 0 {
			return
		}
	}
}

// tick runs a batch with nothing in it on side s (housekeeping, timers)
// as the first short collect after an unlock.
func (f *r29Fx) tick(s int) {
	f.t.Helper()
	if err := f.m(s).ProcessBatch(context.Background(), &fakeCollector{}, nil); err != nil {
		f.t.Fatal(err)
	}
}

// note sends test.note from side s.
func (f *r29Fx) note(s int, body string) {
	f.do(s, func(m *Manager, p *Peer) { m.sendTo(p, "test.note", json.RawMessage(`{"n":"`+body+`"}`), f.clk) })
}

func (f *r29Fx) cur(s int) []byte { return f.p(s).LastEpochID }

// longTokens makes the tokens each side holds outlive the scenario (the
// model's longTokens): the standing tokens' 30 days are not under test, and
// a real vault renews them meanwhile (§7.2).
func (f *r29Fx) longTokens() {
	for s := 0; s < 2; s++ {
		p := f.p(s)
		p.Standing.Exp = f.clk.Add(365 * 24 * time.Hour)
		p.Reconnect.Exp = f.clk.Add(365 * 24 * time.Hour)
	}
}

func (f *r29Fx) dump() {
	for s := 0; s < 2; s++ {
		for _, a := range f.m(s).st.Audit {
			f.t.Logf("side %d: %s", s, a.Event)
		}
	}
}

func (f *r29Fx) sameEpoch() bool { return bytes.Equal(f.cur(0), f.cur(1)) }

// talks checks that a message goes each way and is handled.
func (f *r29Fx) talks() {
	f.t.Helper()
	n0, n1 := len(f.got[0]), len(f.got[1])
	f.note(0, "ping")
	f.note(1, "pong")
	f.settle()
	if len(f.got[1]) != n1+1 || len(f.got[0]) != n0+1 {
		f.t.Fatalf("messages not handled both ways: %d->%d, %d->%d", n1, len(f.got[1]), n0, len(f.got[0]))
	}
}

func (f *r29Fx) rekey(s int) {
	f.do(s, func(m *Manager, p *Peer) { m.startRekey(p, f.clk) })
}

func (f *r29Fx) audited(s int, ev string) bool {
	for _, a := range f.m(s).st.Audit {
		if a.Event == ev {
			return true
		}
	}
	return false
}

// --- features and the gate ---

// 0.86.0 (§10.8, §6.3.1 "Deployment"): each side counts the other's
// hs_confirm from the messages of the connection's first handshake, so the
// gate is open both ways from the start; a release-28 stand-in sends none
// and is counted as having none.
func TestR29FeaturesOpenTheGate(t *testing.T) {
	f := newR29Fx(t)
	for s := 0; s < 2; s++ {
		if !f.p(s).hasConfirm() {
			t.Fatalf("side %d did not count the peer's hs_confirm: %v", s, f.p(s).PeerFeatures)
		}
	}
	g := newR29Fx(t, false, true)
	if g.p(0).advertisedFeatures() || g.p(0).hasConfirm() {
		t.Fatalf("a release-28 peer counted with features %v", g.p(0).PeerFeatures)
	}
	if g.p(1).advertisedFeatures() {
		t.Fatal("the release-28 stand-in counted features")
	}
}

// --- the initiator's pending epoch and confirmation ---

// Model: TestScenarioA (lost confirm) and the plain case. A gated rekey's
// epoch is pending at the initiator after hs.fin; it keeps sending in the
// current epoch, which the responder still reads; the responder's
// hs.confirm makes it current.
func TestR29PendingThenConfirmed(t *testing.T) {
	f := newR29Fx(t)
	e0 := append([]byte(nil), f.cur(0)...)
	f.rekey(0)
	f.deliver(0, 1, kHSInit)
	f.deliver(1, 0, kHSResp)
	if f.p(0).Pending == nil || !bytes.Equal(f.cur(0), e0) {
		t.Fatal("the initiator's new epoch is not pending")
	}
	// Sent while pending: under the current epoch.
	f.note(0, "while-pending")
	f.deliver(0, 1, kHSFin)
	if bytes.Equal(f.cur(1), e0) {
		t.Fatal("the responder did not activate at hs.fin")
	}
	f.deliver(0, 1, kNote)
	if len(f.got[1]) != 1 {
		t.Fatal("a message the initiator sent while pending was lost")
	}
	// One at hs.fin, one again for the batch holding a message under the
	// confirmed (not current) epoch.
	if n := f.deliver(1, 0, kConfirm); n < 1 {
		t.Fatalf("hs.confirm deposits: %d", n)
	}
	if f.p(0).Pending != nil || !f.sameEpoch() {
		t.Fatal("hs.confirm did not make the pending epoch current")
	}
	f.talks()
}

// Model: TestScenarioALostConfirm: hs.confirm is lost; any later message
// from the responder under the new epoch confirms.
func TestR29LostConfirmAnyMessageConfirms(t *testing.T) {
	f := newR29Fx(t)
	f.rekey(0)
	f.deliver(0, 1, kHSInit)
	f.deliver(1, 0, kHSResp)
	f.deliver(0, 1, kHSFin)
	if f.lose(1, 0, kConfirm) != 1 {
		t.Fatal("no hs.confirm to lose")
	}
	f.note(1, "under-new")
	f.deliver(1, 0, kNote)
	if f.p(0).Pending != nil || !f.sameEpoch() || len(f.got[0]) != 1 {
		t.Fatal("a message under the pending epoch did not confirm it")
	}
}

// Finding C regression: the initiator's hs.fin is lost. Release 28 split
// the pair (the initiator active on the new epoch, the responder never).
// Now the initiator's epoch stays pending, both keep talking in the old
// one, and after B the initiator reconnects naming its current epoch,
// which the responder accepts: the pair ends on one epoch.
func TestR29FindingCLostFinNoSplit(t *testing.T) {
	f := newR29Fx(t)
	e0 := append([]byte(nil), f.cur(0)...)
	f.rekey(0)
	f.deliver(0, 1, kHSInit)
	f.deliver(1, 0, kHSResp)
	if f.lose(0, 1, kHSFin) != 1 {
		t.Fatal("no hs.fin to lose")
	}
	if !bytes.Equal(f.cur(0), e0) || !bytes.Equal(f.cur(1), e0) {
		t.Fatal("an epoch moved without its hs.fin")
	}
	f.talks() // still on the old epoch, both ways
	// B passes (judged after a short collect): abandon and reconnect.
	f.advance(PendingLife + time.Hour)
	f.tick(0)
	f.tick(1)
	if f.p(0).Pending != nil {
		t.Fatal("B passed and the epoch is still pending")
	}
	f.settle()
	if !f.sameEpoch() || bytes.Equal(f.cur(0), e0) {
		t.Fatalf("the pair did not end on one new epoch")
	}
	f.talks()
}

// Model: TestScenarioAUndepositableAnswer (rule J): a rekey from a peer
// whose standing token the vault holds has expired is not answered; the
// vault reconnects instead.
func TestR29UndepositableAnswerReconnects(t *testing.T) {
	f := newR29Fx(t)
	f.do(1, func(m *Manager, p *Peer) { p.Standing.Exp = f.clk.Add(-time.Minute) })
	f.rekey(0)
	f.deliver(0, 1, kHSInit)
	if f.answerCount(1) != 0 || !f.audited(1, "rekey_undepositable") {
		t.Fatal("an undepositable rekey was answered")
	}
	if !f.m(1).hasOutgoing(f.id[1], handshake.PurposeReconnect) {
		t.Fatal("no reconnect after an undepositable answer")
	}
}

func (f *r29Fx) answerCount(s int) int {
	n := 0
	for _, aw := range f.m(s).st.Awaiting {
		if aw.New == nil {
			n++
		}
	}
	return n
}

// §6.5 (0.86.0): no rekey while an own epoch is pending.
func TestR29NoRekeyWhilePending(t *testing.T) {
	f := newR29Fx(t)
	f.rekey(0)
	f.deliver(0, 1, kHSInit)
	f.deliver(1, 0, kHSResp)
	f.rekey(0)
	if f.m(0).hasOutgoing(f.id[0], handshake.PurposeRekey) {
		t.Fatal("a rekey started while the vault's epoch is pending")
	}
}

// §6.3.1 "Crossing": the initiator, holding a pending epoch, drops a rekey
// from the responder under the current epoch whose ts is not later than
// the hs.resp it processed.
func TestR29CrossingRekeyWhilePendingDropped(t *testing.T) {
	f := newR29Fx(t)
	f.rekey(0)
	f.deliver(0, 1, kHSInit)
	// Side 1's own rekey, made now (before its answer's ts would matter):
	// sealed with the same clock as its hs.resp.
	f.do(1, func(m *Manager, p *Peer) {
		// An answer awaits hs.fin, so the rekey block holds side 1 back;
		// force one past it to model a peer that crossed.
		kr := m.sessions[p.ID]
		ini, err := handshake.NewInitiator(handshake.InitiatorConfig{Purpose: handshake.PurposeRekey, Identity: m.keys.ik,
			StaticKEM: m.keys.kem.Public(), Relay: m.ownAddr(), ResponderIK: p.IK, ResponderRelayKey: p.Relay.PK,
			Current: kr.Current(), Policy: policyFor(p.Kind), Now: f.clk.Add(-time.Second)})
		if err != nil {
			t.Fatal(err)
		}
		m.queueDeposit(&OutboxEntry{PeerID: p.ID, RelayURL: p.Relay.URL, Mailbox: p.Relay.Mailbox, Payload: ini.Envelope()}, f.clk)
	})
	f.deliver(1, 0, kHSResp)
	if f.p(0).Pending == nil {
		t.Fatal("not pending")
	}
	f.deliver(1, 0, kHSInit)
	if !f.audited(0, "rekey_crossing_pending") || f.p(0).Pending == nil {
		t.Fatal("a crossing rekey with an earlier ts was not dropped")
	}
}

// --- rule E ---

// Model: TestFindingE_* / F7. The responder activated E1 at hs.fin but the
// initiator never confirmed it (its pending epoch passed B); the
// initiator's reconnect names E0, the responder's confirmed epoch, which
// is accepted; at its hs.fin rule E destroys E1, and both end on E2.
func TestR29RuleEReconnectNamingConfirmed(t *testing.T) {
	f := newR29Fx(t)
	e0 := append([]byte(nil), f.cur(0)...)
	f.rekey(0)
	f.deliver(0, 1, kHSInit)
	f.deliver(1, 0, kHSResp)
	f.deliver(0, 1, kHSFin)
	e1 := append([]byte(nil), f.cur(1)...)
	if f.lose(1, 0, kConfirm) != 1 {
		t.Fatal("no hs.confirm")
	}
	f.longTokens()
	if !bytes.Equal(f.p(1).confirmedID(), e0) {
		t.Fatal("the responder's confirmed epoch moved at hs.fin")
	}
	f.advance(PendingLife + time.Hour)
	f.tick(1) // no hs.confirm again: nothing arrived under E0
	f.lose(1, 0, kConfirm)
	f.tick(0)
	f.settle()
	if !f.sameEpoch() || bytes.Equal(f.cur(0), e0) || bytes.Equal(f.cur(0), e1) {
		t.Fatal("not on one new epoch")
	}
	if e := f.p(1).epochMeta(e1); e == nil || !e.Destroyed {
		f.dump()
		t.Fatal("rule E did not destroy the unconfirmed epoch")
	}
	f.talks()
}

// --- the ungated initiator: activation at hs.fin, the revert ---

// Model: TestLead5RevertReseals. Toward a release-28 peer the initiator
// activates at hs.fin; the hs.fin is lost, so the peer never activates;
// what the initiator sends under the new epoch is kept; a message from the
// peer under the old epoch more than T + 2 days after hs.fin reverts, and
// the kept messages are sealed again in the old epoch and arrive.
func TestR29RevertResealsTowardRelease28(t *testing.T) {
	f := newR29Fx(t, false, true)
	e0 := append([]byte(nil), f.cur(0)...)
	f.rekey(0)
	f.deliver(0, 1, kHSInit)
	f.deliver(1, 0, kHSResp)
	if f.p(0).Pending != nil || bytes.Equal(f.cur(0), e0) || f.p(0).Revert == nil {
		t.Fatal("toward a peer without the gate: active at hs.fin, keeping the old epoch")
	}
	f.lose(0, 1, kHSFin)
	f.note(0, "kept")
	f.lose(0, 1, kAny) // under an epoch the peer never activated: unreadable
	f.advance(RevertAfter + time.Hour)
	f.tick(1) // the peer's answer expires
	f.note(1, "old-epoch")
	f.deliver(1, 0, kNote)
	if !bytes.Equal(f.cur(0), e0) || f.p(0).Revert != nil {
		t.Fatal("no revert")
	}
	f.settle()
	found := false
	for _, b := range f.got[1] {
		found = found || bytes.Contains([]byte(b), []byte("kept"))
	}
	if !found {
		t.Fatalf("the kept message was not sealed again: %v", f.got[1])
	}
	f.talks()
}

// The revert's caps: per peer 256 copies; the oldest go first and count
// in connection.epoch_reverted's ref.
func TestR29RevertCopyCap(t *testing.T) {
	f := newR29Fx(t, false, true)
	f.rekey(0)
	f.deliver(0, 1, kHSInit)
	f.deliver(1, 0, kHSResp)
	f.do(0, func(m *Manager, p *Peer) {
		for i := 0; i < RevertMaxCopies+3; i++ {
			m.sendTo(p, "test.note", json.RawMessage(`{"n":"x"}`), f.clk)
		}
		if r := p.Revert; len(r.Copies) != RevertMaxCopies || r.Dropped != 3 {
			t.Fatalf("copies %d dropped %d", len(r.Copies), r.Dropped)
		}
	})
}

// --- §3.4.1: rotations ---

// rotate rotates side s's identity.
func (f *r29Fx) rotate(s int) {
	f.t.Helper()
	f.do(s, func(m *Manager, _ *Peer) {
		if err := m.rotateIdentity(f.clk); err != nil {
			f.t.Fatal(err)
		}
	})
}

// Model: TestRotateTwicePeerMissesFirst, 29<>29. Side 0 rotates twice;
// side 1 misses the first identity.rotate. The second carries the whole
// chain (S8), so side 1 follows both; the pair rekeys and talks.
func TestR29RotateTwicePeerMissesFirst(t *testing.T) {
	f := newR29Fx(t)
	f.rotate(0)
	if f.lose(0, 1, kRotate) != 1 {
		t.Fatal("no identity.rotate to lose")
	}
	f.lose(0, 1, kHSInit) // the rekey under the first new ik is lost too
	f.rotate(0)
	f.settle()
	f.advance(time.Hour)
	f.tick(0)
	f.tick(1)
	f.settle()
	if !bytes.Equal(f.p(1).IK, f.m(0).keys.ik.Public().(ed25519.PublicKey)) {
		t.Fatal("side 1 did not reach side 0's ik")
	}
	if !f.sameEpoch() {
		t.Fatal("not on one epoch")
	}
	// A rekey under the new ik happened (S8 parses at the peer, review H1):
	// the current epoch is signed by side 0's newest ik on both sides.
	if f.p(0).OwnChainAtEpoch != len(f.m(0).st.Rotations) {
		t.Fatalf("side 0's epoch signed by own chain %d of %d", f.p(0).OwnChainAtEpoch, len(f.m(0).st.Rotations))
	}
	if e := f.p(1).epochMeta(f.cur(1)); e == nil || !bytes.Equal(e.Signer, f.m(0).keys.ik.Public().(ed25519.PublicKey)) {
		t.Fatal("side 1's current epoch is not signed by side 0's new ik")
	}
	if f.audited(1, "rekey_rejected") {
		t.Fatal("a rekey with rotations was refused")
	}
	f.talks()
}

// The same with side 1 a release-28 stand-in: it reads `rotation` only and
// ignores a link from an ik it does not hold, and refuses side 0's rekey
// under the new ik. Rule L: side 0's rekey goes unanswered for its
// lifetime; it reconnects with the whole chain, which release 28 follows.
func TestR29RotateTwiceRelease28FollowerRecovers(t *testing.T) {
	f := newR29Fx(t, false, true)
	f.rotate(0)
	f.lose(0, 1, kRotate)
	f.lose(0, 1, kHSInit)
	f.rotate(0)
	f.settle()
	f.longTokens()
	if bytes.Equal(f.p(1).IK, f.m(0).keys.ik.Public().(ed25519.PublicKey)) {
		t.Fatal("the stand-in followed a link from an ik it did not hold")
	}
	f.advance(HandshakeTTL + time.Hour)
	f.tick(0)
	f.tick(1)
	if !f.audited(0, "reconnect_rule_l") {
		t.Fatal("rule L did not reconnect")
	}
	f.settle()
	if !bytes.Equal(f.p(1).IK, f.m(0).keys.ik.Public().(ed25519.PublicKey)) || !f.sameEpoch() {
		f.dump()
		t.Fatal("the release-28 follower did not recover")
	}
	f.talks()
}

// The baseline: two release-28 stand-ins stay stuck (bad_rotation, the
// rekey refused for good).
func TestR29RotateTwiceRelease28BothStuck(t *testing.T) {
	f := newR29Fx(t, true, true)
	f.rotate(0)
	f.lose(0, 1, kRotate)
	f.lose(0, 1, kHSInit)
	f.rotate(0)
	f.settle()
	f.advance(HandshakeTTL + time.Hour)
	f.tick(0)
	f.tick(1)
	f.settle()
	if bytes.Equal(f.p(1).IK, f.m(0).keys.ik.Public().(ed25519.PublicKey)) {
		t.Fatal("two release-28 vaults recovered: the stand-in is not release 28")
	}
}

// S5 (0.86.0): at the vault's own rotation, an answer awaiting hs.fin is
// dropped toward a peer with hs_confirm (the initiator then abandons its
// pending epoch when it follows the link) and the pair converges.
// Model: TestGateDisagreementS5Repaired's gated half.
func TestR29S5DropsAnswerTowardGatedPeer(t *testing.T) {
	f := newR29Fx(t)
	f.rekey(0)
	f.deliver(0, 1, kHSInit)
	f.deliver(1, 0, kHSResp)
	if f.answerCount(1) != 1 || f.p(0).Pending == nil {
		t.Fatal("setup")
	}
	f.rotate(1) // the responder rotates while its answer awaits hs.fin
	if f.answerCount(1) != 0 {
		t.Fatal("the answer to a gated peer was kept across the rotation")
	}
	f.settle()
	f.advance(time.Hour)
	f.tick(0)
	f.tick(1)
	f.settle()
	if f.p(0).Pending != nil || !f.sameEpoch() {
		t.Fatal("did not converge")
	}
	if !bytes.Equal(f.p(0).IK, f.m(1).keys.ik.Public().(ed25519.PublicKey)) {
		t.Fatal("the link was not followed")
	}
	f.talks()
}

// S5 toward a peer without the gate (a release-28 stand-in initiator): the
// answer is kept, established at its hs.fin, and a rekey under the new ik
// follows at once.
func TestR29S5KeepsAnswerTowardUngatedPeer(t *testing.T) {
	f := newR29Fx(t, true, false)
	f.rekey(0)
	f.deliver(0, 1, kHSInit)
	f.rotate(1)
	if f.answerCount(1) != 1 {
		t.Fatal("the answer to an ungated peer was dropped")
	}
	f.settle()
	f.advance(time.Hour)
	f.tick(0)
	f.tick(1)
	f.settle()
	if !f.sameEpoch() || !bytes.Equal(f.p(0).IK, f.m(1).keys.ik.Public().(ed25519.PublicKey)) {
		t.Fatal("did not converge under the new ik")
	}
	f.talks()
}

// The lower th1 decides crossing handshakes of different purposes (§6.5,
// 0.86.0): an own reconnect with the higher th1 is abandoned when the
// peer's rekey crosses it.
func TestR29LowerTh1AcrossPurposes(t *testing.T) {
	for try := 0; try < 50; try++ {
		f := newR29Fx(t)
		f.rekey(0)
		f.do(1, func(m *Manager, p *Peer) { m.startReconnect(p, f.clk) })
		var rc, rk []byte
		for _, og := range f.m(1).st.Outgoing {
			rc = og.Th1
		}
		for _, og := range f.m(0).st.Outgoing {
			rk = og.Th1
		}
		if bytes.Compare(rc, rk) <= 0 {
			continue // want the reconnect's th1 higher
		}
		f.deliver(0, 1, kHSInit)
		if f.m(1).hasOutgoing(f.id[1], handshake.PurposeReconnect) {
			t.Fatal("the higher-th1 reconnect was kept against a crossing rekey")
		}
		f.settle()
		f.advance(time.Minute)
		f.tick(0)
		f.tick(1)
		f.settle()
		if !f.sameEpoch() {
			t.Fatal("not on one epoch")
		}
		return
	}
	t.Skip("no th1 order found")
}

// Model: TestBlindF1 (strict F1, the lead's choice: no exception). Side 0
// rekeys toward a release-28 stand-in and activates at hs.fin, which is
// lost; the peer rotates and its identity.rotate travels under the old
// epoch. Side 0 follows the link, demotes the epoch it activated without
// confirmation (signed by the link's old_ik), makes the old one current
// again and reconnects naming it, which release 28 accepts.
func TestR29F1StrictDemotion(t *testing.T) {
	f := newR29Fx(t, false, true)
	f.longTokens()
	e0 := append([]byte(nil), f.cur(0)...)
	f.rekey(0)
	f.deliver(0, 1, kHSInit)
	f.deliver(1, 0, kHSResp)
	e1 := append([]byte(nil), f.cur(0)...)
	f.lose(0, 1, kHSFin)
	f.rotate(1)
	f.deliver(1, 0, kRotate)
	if e := f.p(0).epochMeta(e1); e == nil || !e.Demoted {
		f.dump()
		t.Fatal("F1 did not demote the epoch the peer never activated")
	}
	if !bytes.Equal(f.cur(0), e0) {
		t.Fatal("the epoch the link traveled under is not current again")
	}
	f.settle()
	f.advance(time.Hour)
	f.tick(0)
	f.tick(1)
	f.settle()
	if !f.sameEpoch() || !bytes.Equal(f.p(0).IK, f.m(1).keys.ik.Public().(ed25519.PublicKey)) {
		f.dump()
		t.Fatal("did not converge under the peer's new ik")
	}
	f.talks()
}

// §6.3.1 rule E's evidence: an authenticated message with a later ts under
// an epoch rule E destroyed suspends (ref epoch) toward a peer with
// hs_confirm (model: TestFindingE_ConfirmedEpochHidesForkEvidence) and,
// toward a peer without it, starts a reconnect naming that epoch instead
// (model: the lead's r8 point 1, F3 toward 28), refused as
// superseded_epoch.
func TestR29RuleEEvidence(t *testing.T) {
	for _, ungated := range []bool{false, true} {
		f := newR29Fx(t, ungated, false)
		f.longTokens()
		f.do(1, func(m *Manager, p *Peer) {
			e := p.epochMeta(p.LastEpochID)
			e.Destroyed, e.DestroyTS = true, f.clk.Add(-time.Hour)
		})
		f.note(0, "late")
		f.deliver(0, 1, kNote)
		p := f.p(1)
		switch {
		case !ungated && (p.Fork == nil || len(f.got[1]) != 0):
			t.Fatal("toward a gated peer: not suspended")
		case ungated && (p.Fork != nil || !f.audited(1, "reconnect_rule_e") || len(f.got[1]) != 0):
			f.dump()
			t.Fatal("toward an ungated peer: no reconnect naming the destroyed epoch")
		}
	}
}

// §6.3.1 "Deployment" (0.86.1): a revert re-seals with the same inner id
// and a new ts, skips expired copies, and audits the dropped count.
func TestR29RevertAuditsDropped(t *testing.T) {
	f := newR29Fx(t, false, true)
	f.longTokens()
	f.rekey(0)
	f.deliver(0, 1, kHSInit)
	f.deliver(1, 0, kHSResp)
	f.lose(0, 1, kHSFin)
	f.do(0, func(m *Manager, p *Peer) {
		for i := 0; i < RevertMaxCopies+2; i++ {
			m.sendTo(p, "test.note", json.RawMessage(`{"n":"x"}`), f.clk)
		}
		m.sendWith(p, "test.note", json.RawMessage(`{"n":"expiring"}`), SendOptions{Exp: f.clk.Add(time.Hour)}, f.clk)
	})
	f.lose(0, 1, kAny)
	f.advance(RevertAfter + 2*time.Hour)
	f.tick(0)
	f.tick(1)
	f.note(1, "old")
	f.deliver(1, 0, kNote)
	var ref string
	var seen bool
	for _, a := range f.sink[0].got {
		if a.Kind == "connection.epoch_reverted" {
			ref, seen = a.Ref, true
		}
	}
	if !seen || ref != "3" {
		t.Fatalf("connection.epoch_reverted ref %q (want the 3 dropped)", ref)
	}
	f.settle()
	for _, b := range f.got[1] {
		if bytes.Contains([]byte(b), []byte("expiring")) {
			t.Fatal("an expired copy was sealed again")
		}
	}
}

// Model: TestGateDisagreementS5Repaired. Side 0 has not yet seen side 1's
// features, so its rekey is ungated (active at hs.fin); side 1 has seen
// side 0's, so at its rotation it drops its answer (S5). The hs.fin finds
// no answer; side 1's identity.rotate (under the old epoch) makes side 0
// demote the epoch it activated (strict F1) and reconnect; the pair
// converges.
func TestR29GateDisagreementS5Repaired(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	f.do(0, func(m *Manager, p *Peer) { p.PeerFeatures = nil })
	e0 := append([]byte(nil), f.cur(0)...)
	f.rekey(0)
	f.deliver(0, 1, kHSInit)
	f.deliver(1, 0, kHSResp)
	if f.p(0).Pending != nil || bytes.Equal(f.cur(0), e0) {
		t.Fatal("setup: side 0 should have activated at hs.fin")
	}
	f.rotate(1)
	if f.answerCount(1) != 0 {
		t.Fatal("S5 kept the answer toward a gated peer")
	}
	f.settle()
	f.advance(time.Hour)
	f.tick(0)
	f.tick(1)
	f.settle()
	if !f.sameEpoch() || !bytes.Equal(f.p(0).IK, f.m(1).keys.ik.Public().(ed25519.PublicKey)) {
		f.dump()
		t.Fatal("did not converge")
	}
	f.talks()
}
