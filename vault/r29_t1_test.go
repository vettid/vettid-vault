package vault

import (
	"bytes"
	"context"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayclient"
	"github.com/vettid/vettid-vault/vms/handshake"
)

// R29-T1 (VAULT-MESSAGING 0.88.2 §6.3.1 "A handshake's tokens are adopted at
// confirmation"; owner decision a, GC 01M6SWPHVH6WFYJ8096KX0D5GC): seeds of
// the random pair that failed at 4a0d453 (before the rule, and before the
// harness's time jumps let an unlocked side collect, advanceLive), replayed
// from their seed (replays are exact, TestR29RandomPairReplay). Each must
// now converge, and no side may adopt a token its issuer had already
// revoked (the harness's R29-T1 assertion, watchAdoption). The scenario
// test of the class is TestR29TokenRevokedEndsTheTokenOnly.
//
//   - 16906628016574081987, 2547422016364076747, 8648490589795547312: the
//     adopt-before-confirm class (GC 01M6SWPHVH6WFYJ8096KX0D5GC): rotations
//     on both sides around crossing reconnects; at 4a0d453 deposits and
//     reconnect tries were refused token_revoked, then quota_exceeded, and
//     both sides ended stale.
//   - 3261938242456459520, 16401999147266222361: the "single 30-day lock"
//     class (lock>T:single), which ended stale the same way after one long
//     lock.
//   - 14735564589240170962: failed before and after the rule, with no lock:
//     a 30-day time jump while both sides were unlocked let handshake
//     messages expire at the relay unread, a vault that does not exist (an
//     unlocked vault collects continuously). The regression test of
//     advanceLive (the lead, GC #6449).
//
// The false suspensions of the 10,000-run searches at 3ce94c6 (GC #6493):
// a pending rekey's hs.fin, refused token_expired and waiting for a token,
// outlived the abandonment of its epoch; once the reconnect's hs.fin (on
// its carried token) and its confirmation had overtaken it, it reached the
// peer last, rule E destroyed the reconnect's epoch, and the prompt to
// adopt under it was taken as fork evidence. An abandoned pending epoch's
// hs.fin that was not deposited is now dropped (§6.3.1 Initiator).
func TestR29T1SuspendSeeds(t *testing.T) {
	for _, c := range []struct {
		seed  uint64
		burst bool
	}{{8453991582502839313, false}, {7170116888466898459, true}, {10899583487953230597, true}} {
		t.Run(strconv.FormatUint(c.seed, 10), func(t *testing.T) {
			if v, _ := rpRun(t, c.seed, 40, c.burst, false); v != "" {
				t.Fatalf("verdict %q, want converged", v)
			}
		})
	}
}

func TestR29T1Seeds(t *testing.T) {
	for _, seed := range []uint64{
		16906628016574081987, 2547422016364076747, 8648490589795547312,
		3261938242456459520, 16401999147266222361, 14735564589240170962,
	} {
		t.Run(strconv.FormatUint(seed, 10), func(t *testing.T) {
			if v, _ := rpRun(t, seed, 40, false, false); v != "" {
				t.Fatalf("verdict %q, want converged", v)
			}
		})
	}
}

// --- R29-T1 sub-rules (the lead's merged review of f24e4c0, GC #6453) ---

// t1Reconnect runs side i's reconnect with side r up to r's hs.fin: r has
// activated the epoch as responder, i's epoch is pending, and r's
// hs.confirm waits in the relay.
func (f *r29Fx) t1Reconnect(i, r int) {
	f.t.Helper()
	f.do(i, func(m *Manager, p *Peer) { m.startReconnect(p, f.clk) })
	if f.deliver(i, r, kHSInit) != 1 || f.deliver(r, i, kHSResp) != 1 || f.deliver(i, r, kHSFin) != 1 {
		f.dump()
		f.t.Fatal("setup: the reconnect did not reach hs.fin")
	}
}

// adoptions records the Adopt hook's calls on side s, with the number of
// test.note messages handled at that moment.
func (f *r29Fx) adoptions(s int) *[]string {
	var log []string
	f.m(s).opt.Hooks.Adopt = func(_, kind, tok, from string) {
		log = append(log, from+":"+kind+":"+strconv.Itoa(len(f.got[s])))
	}
	return &log
}

// The initiator adopts the tokens of the hs.resp in the write that confirms
// its pending epoch, not at hs.resp; hs.fin went on the carried token.
func TestR29T1InitiatorAdoptsAtConfirmation(t *testing.T) {
	f := newR29Fx(t)
	f.advance(10 * 24 * time.Hour) // carried tokens outlive the held ones
	before := f.p(1).Standing
	f.t1Reconnect(1, 0)
	pe := f.p(1).Pending
	if pe == nil || pe.Carried == nil || pe.Carried.Standing.Token == "" || pe.Carried.Standing.Token == before.Token {
		t.Fatal("the pending epoch does not keep the hs.resp's tokens")
	}
	carried := *pe.Carried
	if f.p(1).Standing.Token != before.Token {
		t.Fatal("the initiator adopted the hs.resp's standing token before confirmation")
	}
	if f.deliver(0, 1, kConfirm) != 1 {
		t.Fatal("no hs.confirm")
	}
	if f.p(1).Pending != nil || f.p(1).Standing.Token != carried.Standing.Token || f.p(1).Reconnect.Token != carried.Reconnect.Token {
		t.Fatal("the initiator did not adopt the hs.resp's tokens at confirmation")
	}
}

// The responder adopts the hs.init's tokens when its confirmed epoch
// reaches the epoch: on the initiator's prompt (relay.token.issued under the
// epoch), not at hs.fin; hs.confirm went on the carried token.
func TestR29T1ResponderAdoptsOnThePrompt(t *testing.T) {
	f := newR29Fx(t)
	f.advance(10 * 24 * time.Hour)
	before := f.p(0).Standing
	f.t1Reconnect(1, 0)
	c := f.p(0).carriedFor(f.cur(0))
	if c == nil || c.Standing.Token == "" || f.p(0).Standing.Token != before.Token {
		t.Fatal("the responder adopted at hs.fin, or keeps no carried tokens")
	}
	carried := *c
	log := f.adoptions(0)
	f.deliver(0, 1, kConfirm) // I confirms and re-mints under the epoch
	if f.deliver(1, 0, kOther) == 0 {
		t.Fatal("no prompt to adopt from the initiator")
	}
	if f.p(0).carriedFor(f.cur(0)) != nil {
		t.Fatal("the carried record is still waiting after the prompt")
	}
	if len(*log) == 0 || !strings.HasPrefix((*log)[0], "carried:") {
		t.Fatalf("no adoption of the carried tokens on the prompt: %v", *log)
	}
	if f.p(0).Standing.Exp.Before(carried.Standing.Exp) || f.p(0).Reconnect.Token != carried.Reconnect.Token && f.p(0).Reconnect.Exp.Before(carried.Reconnect.Exp) {
		t.Fatal("the responder holds tokens older than the carried ones")
	}
}

// Any message under the epoch moves the confirmed epoch, and the adoption
// is made before its handler runs.
func TestR29T1ResponderAdoptsBeforeTheHandler(t *testing.T) {
	f := newR29Fx(t)
	f.advance(10 * 24 * time.Hour)
	f.t1Reconnect(1, 0)
	log := f.adoptions(0)
	f.deliver(0, 1, kConfirm)
	f.lose(1, 0, kOther) // the prompt is lost; a note under the epoch follows
	f.note(1, "under-new")
	if f.deliver(1, 0, kNote) != 1 {
		t.Fatal("no note")
	}
	if len(*log) == 0 || (*log)[0] != "carried:standing:0" || len(f.got[0]) != 1 {
		t.Fatalf("not adopted before the handler: %v (handled %d)", *log, len(f.got[0]))
	}
}

// A carried token replaces a held one only if its exp is later.
func TestR29T1AdoptsOnlyALaterExp(t *testing.T) {
	f := newR29Fx(t)
	f.do(0, func(m *Manager, p *Peer) {
		held := p.Standing
		m.adoptHeld(p, TokStanding, &p.Standing, HeldToken{Token: "older", Exp: held.Exp.Add(-time.Hour)})
		if p.Standing != held {
			t.Fatal("a carried token with an earlier exp replaced the held one")
		}
		m.adoptHeld(p, TokStanding, &p.Standing, HeldToken{Token: "later", Exp: held.Exp.Add(time.Hour)})
		if p.Standing.Token != "later" {
			t.Fatal("a carried token with a later exp was not adopted")
		}
		p.Standing = held
	})
}

// token_revoked on a carried hs.confirm: the issuer abandoned the epoch (S5
// at its rotation). The entry is dropped, the handshake's carried tokens are
// discarded, and "hs.confirm again" stops for it.
func TestR29T1CarriedConfirmRevoked(t *testing.T) {
	f := newR29Fx(t)
	f.revocations(0)
	f.advance(10 * 24 * time.Hour)
	f.t1Reconnect(1, 0)
	f.lose(0, 1, kConfirm)
	f.rotate(1) // S5: I abandons its pending epoch and revokes what its hs.init carried
	f.lose(1, 0, kAny)
	f.advance(ConfirmResend + time.Hour)
	f.tick(0) // "hs.confirm again", on the carried token: refused
	if !f.audited(0, "carried_token_revoked") {
		f.dump()
		t.Fatal("token_revoked on the carried hs.confirm was not handled as a carried token's")
	}
	if c := f.p(0).carriedFor(f.cur(0)); c == nil || !c.Discarded {
		t.Fatal("the handshake's carried tokens were not discarded")
	}
	f.advance(ConfirmResend + time.Hour)
	f.tick(0)
	if f.m(0).confirmQueued(f.p(0)) {
		t.Fatal("hs.confirm again did not stop after the discard")
	}
}

// While carried tokens wait, the responder starts no reconnect for want of
// a valid standing token; at the wait's bound (the carried token's exp) it
// discards them and, holding no valid token, reconnects.
func TestR29T1WaitThenBoundReconnects(t *testing.T) {
	f := newR29Fx(t)
	f.advance(10 * 24 * time.Hour) // the held tokens end 10 days before the carried ones
	f.t1Reconnect(1, 0)
	f.lose(0, 1, kAny) // I hears nothing: no confirmation, no prompt
	f.advance(25 * 24 * time.Hour)
	f.tick(0)
	if !f.clk.After(f.p(0).Standing.Exp) {
		t.Fatal("setup: the held standing token has not expired")
	}
	if f.openReconnect(0) != nil || !f.m(0).carriedWait(f.p(0), f.clk) {
		f.dump()
		t.Fatal("the responder reconnected while carried tokens waited")
	}
	f.advance(10 * 24 * time.Hour) // past the carried token's exp
	f.tick(0)
	if c := f.p(0).carriedFor(f.cur(0)); c == nil || !c.Discarded {
		t.Fatal("the carried tokens were not discarded at their bound")
	}
	if f.openReconnect(0) == nil && f.p(0).Pending == nil {
		f.dump()
		t.Fatal("holding no valid standing token after the discard, the responder did not reconnect")
	}
}

// A quota refresh handled in the batch that confirms spares the re-mint of
// the confirmation (the prompt to adopt) and the newest handshake-carried
// standing token, and denies the rest (0.88.2 §7.2, §7.4).
func TestR29T1QuotaRefreshSparesThePrompt(t *testing.T) {
	f := newR29Fx(t)
	f.t1Reconnect(0, 1) // side 0 initiates: it is the issuer of the prompt
	f.deliver(1, 0, kConfirm)
	f.do(0, func(m *Manager, p *Peer) {
		s := &Session{m: m, peer: p, now: f.clk}
		if _, err := m.hTokenRefresh(context.Background(), s, nil); err != nil {
			t.Fatal(err)
		}
		var prompt, hs, denied int
		for _, it := range m.st.Issued {
			if it.PeerID != p.ID || it.Kind != TokStanding {
				continue
			}
			switch {
			case it.Prompt && !it.Denied:
				prompt++
			case it.Handshake && !it.Denied:
				hs++
			case it.Denied:
				denied++
			}
		}
		if prompt != 1 || hs != 1 || denied == 0 {
			t.Fatalf("prompt %d, handshake %d spared, %d denied", prompt, hs, denied)
		}
	})
}

// Carried tokens are part of the stored state: across a lock and unlock of
// both sides the reconnect still completes, and each side adopts.
func TestR29T1CarriedSurvivesRestart(t *testing.T) {
	f := newR29Fx(t)
	f.advance(10 * 24 * time.Hour)
	f.t1Reconnect(1, 0)
	r0 := *f.p(0).carriedFor(f.cur(0))
	i1 := *f.p(1).Pending.Carried
	f.restart(0)
	f.restart(1)
	if c := f.p(0).carriedFor(f.cur(0)); c == nil || c.Standing != r0.Standing {
		t.Fatal("the responder's carried tokens did not survive the restart")
	}
	if pe := f.p(1).Pending; pe == nil || pe.Carried == nil || pe.Carried.Standing != i1.Standing {
		t.Fatal("the initiator's carried tokens did not survive the restart")
	}
	f.settle()
	if f.p(1).Standing.Token != i1.Standing.Token && f.p(1).Standing.Exp.Before(i1.Standing.Exp) || f.p(0).carriedFor(f.cur(0)) != nil {
		f.dump()
		t.Fatal("after the restart the carried tokens were not adopted")
	}
}

// Review F1: X activates E2 as responder to Y's reconnect, then X's own
// reconnect E3 completes first (Y abandons its pending E2 at X's hs.fin and
// revokes what its hs.init carried). At E3's confirmation X must not adopt
// E2's carried tokens: E3 supersedes them.
func TestR29T1NoAdoptionOfAnEarlierEpoch(t *testing.T) {
	f := newR29Fx(t)
	f.advance(10 * 24 * time.Hour)
	f.t1Reconnect(1, 0) // E2: Y = 1 initiates, X = 0 activates
	e2 := *f.p(0).carriedFor(f.cur(0))
	var adopted []string // every token X starts to hold, even if replaced in the same write
	f.m(0).opt.Hooks.Adopt = func(_, _, tok, _ string) { adopted = append(adopted, tok) }
	f.lose(0, 1, kConfirm)
	f.advance(time.Minute)
	f.do(0, func(m *Manager, p *Peer) { m.startReconnect(p, f.clk) }) // E3, X's own
	f.settle()
	// The record of E2 is never adopted ("carried_adopted" is noted only by
	// a responder's adoption; E3's hs.resp tokens are adopted at its
	// confirmation without it): exp-later alone would mask it, since E3's
	// tokens are later.
	if slices.Contains(adopted, e2.Standing.Token) || slices.Contains(adopted, e2.Reconnect.Token) || f.audited(0, "carried_adopted") {
		f.dump()
		t.Fatal("X adopted the carried tokens of an earlier epoch")
	}
	if !f.sameEpoch() {
		f.dump()
		t.Fatal("the pair did not end on one epoch")
	}
}

// holdDeposits makes side s's relay refuse every deposit (503) until
// released, so that a deposit is made only after what follows.
func (f *r29Fx) holdDeposits(s int, on bool) {
	r := f.d[s].relay
	r.mu.Lock()
	if on {
		r.failWith = &relayclient.Error{Status: 503, Code: "unavailable"}
	} else {
		r.failWith = nil
	}
	r.mu.Unlock()
}

// token_revoked on R's hs.resp, deposited with the token I's hs.init
// carried: I abandoned its reconnect (S5) before the answer was deposited.
// The entry is dropped and the answer's carried tokens are discarded; the
// held tokens are untouched.
func TestR29T1CarriedRespRevoked(t *testing.T) {
	f := newR29Fx(t)
	f.revocations(0)
	held := f.p(0).Standing
	f.do(1, func(m *Manager, p *Peer) { m.startReconnect(p, f.clk) })
	f.holdDeposits(0, true)
	if f.deliver(1, 0, kHSInit) != 1 {
		t.Fatal("no hs.init")
	}
	f.rotate(1) // S5: I abandons its reconnect and revokes what its hs.init carried
	f.lose(1, 0, kAny)
	f.holdDeposits(0, false)
	f.advance(time.Minute)
	f.tick(0)
	if !f.audited(0, "carried_token_revoked") {
		f.dump()
		t.Fatal("token_revoked on the carried hs.resp was not handled as a carried token's")
	}
	for _, aw := range f.m(0).st.Awaiting {
		if aw.Reconnect != nil && aw.Reconnect.Standing.Token != "" {
			t.Fatal("the answer still keeps the hs.init's carried tokens")
		}
	}
	if f.p(0).Standing != held || f.p(0).State != PeerActive {
		t.Fatal("the refusal changed the held tokens or the connection")
	}
	// (owner decision a, GC 01M713PZNT77VVDSCY6DC00NWH, item 2) The answer ends now, not after L.
	for _, aw := range f.m(0).st.Awaiting {
		if aw.PeerID == f.p(0).ID && aw.Purpose == handshake.PurposeReconnect {
			t.Fatal("R kept its answer to a reconnect I dropped")
		}
	}
	if !f.audited(0, "answer_ended_carried_revoked") {
		t.Fatal("the answer's end was not audited")
	}
}

// token_revoked on I's hs.fin, deposited with the token R's hs.resp
// carried: R dropped its answer at its own rotation (S5) before the hs.fin
// was deposited. The entry is dropped and the pending epoch's carried
// tokens are discarded, never adopted.
func TestR29T1CarriedFinRevoked(t *testing.T) {
	f := newR29Fx(t)
	f.revocations(1)
	f.do(1, func(m *Manager, p *Peer) { m.startReconnect(p, f.clk) })
	f.deliver(1, 0, kHSInit)
	f.holdDeposits(1, true)
	if f.deliver(0, 1, kHSResp) != 1 {
		t.Fatal("no hs.resp")
	}
	f.rotate(0) // S5: R drops its answer and revokes what its hs.resp carried
	f.lose(0, 1, kAny)
	f.holdDeposits(1, false)
	f.advance(time.Minute)
	f.tick(1)
	if !f.audited(1, "carried_token_revoked") {
		f.dump()
		t.Fatal("token_revoked on the carried hs.fin was not handled as a carried token's")
	}
	if pe := f.p(1).Pending; pe != nil && pe.Carried != nil {
		t.Fatal("the pending epoch still keeps the hs.resp's carried tokens")
	}
	// (owner decision a, item 2) The pending epoch ends now, not at B, and the reconnect starts again.
	if !f.audited(1, "pending_abandoned_carried_revoked") {
		f.dump()
		t.Fatal("I's pending epoch did not end at the refusal")
	}
	if f.p(1).State != PeerActive {
		t.Fatal("the refusal made the connection stale")
	}
}

// (owner decision a, GC 01M713PZNT77VVDSCY6DC00NWH, item 3, option A) A quota
// refresh denies only the standing tokens no newer than the one it came
// under (its collect jti): a newer one, still on its way, is spared.
func TestR29QuotaRefreshSparesNewerThanItsOwnToken(t *testing.T) {
	f := newR29Fx(t)
	f.do(0, func(m *Manager, p *Peer) {
		under := m.latestIssued(p.ID, TokStanding)
		if under == nil {
			t.Fatal("setup: no standing token issued to the peer")
		}
		underJTI := under.JTI
		f.advance(time.Hour)
		m.issueTo(p, TokStanding, f.clk) // a near-end re-mint still on its way
		newer := m.latestIssued(p.ID, TokStanding)
		newerJTI := newer.JTI
		m.msgJTI = underJTI // the refresh was deposited under the older token
		s := &Session{m: m, peer: p, now: f.clk}
		if _, err := m.hTokenRefresh(context.Background(), s, nil); err != nil {
			t.Fatal(err)
		}
		m.msgJTI = ""
		for _, it := range m.st.Issued {
			switch it.JTI {
			case underJTI:
				if !it.Denied {
					t.Fatal("the token the refresh came under was not denied")
				}
			case newerJTI:
				if it.Denied {
					t.Fatal("a newer token, still on its way, was denied")
				}
			}
		}
	})
}

// t1Waiting brings side 0 (R) to "No reconnect while carried tokens wait":
// its held standing token has expired, the carried one is valid, and I has
// heard nothing since hs.fin.
func (f *r29Fx) t1Waiting() {
	f.t.Helper()
	f.advance(10 * 24 * time.Hour)
	f.t1Reconnect(1, 0)
	f.lose(0, 1, kAny)
	f.advance(25 * 24 * time.Hour)
	if f.clk.Before(f.p(0).Standing.Exp) || !f.m(0).carriedWait(f.p(0), f.clk) {
		f.t.Fatal("setup: not waiting with an expired held token")
	}
}

// Each trigger that would start a reconnect for want of a valid standing
// token, or judge "no reconnect token", does neither while carried tokens
// wait (0.88.2 §6.3.1).
func TestR29T1WaitGuardsEachTrigger(t *testing.T) {
	cases := []struct {
		name string
		run  func(f *r29Fx, m *Manager, p *Peer)
	}{
		{"refreshHeld", func(f *r29Fx, m *Manager, p *Peer) { m.refreshHeld(f.clk) }},
		{"reconnectExpired", func(f *r29Fx, m *Manager, p *Peer) { m.reconnectExpired(f.clk) }},
		{"noStandingToken via token_revoked on a held token", func(f *r29Fx, m *Manager, p *Peer) {
			e := &OutboxEntry{ID: m.newID(f.clk), PeerID: p.ID, Op: OpDeposit}
			m.tokenRevoked(p, e, p.Standing.Token, f.clk)
		}},
		{"deposit answered token_expired", func(f *r29Fx, m *Manager, p *Peer) {
			r := f.d[0].relay
			r.mu.Lock()
			r.failWith = &relayclient.Error{Status: 401, Code: CodeTokenExpired}
			r.mu.Unlock()
			e := &OutboxEntry{ID: m.newID(f.clk), PeerID: p.ID, Op: OpDeposit, RelayURL: p.Relay.URL, Mailbox: p.Relay.Mailbox, Payload: []byte("x")}
			_ = m.deposit(context.Background(), e, f.clk)
			r.mu.Lock()
			r.failWith = nil
			r.mu.Unlock()
		}},
		{"startReconnect with no reconnect token", func(f *r29Fx, m *Manager, p *Peer) {
			p.Reconnect = HeldToken{}
			m.startReconnect(p, f.clk)
		}},
		{"reconnectNaming with no reconnect token", func(f *r29Fx, m *Manager, p *Peer) {
			p.Reconnect = HeldToken{}
			m.reconnectNaming(p, p.LastEpochID, "test", f.clk)
		}},
		{"tickPending, a rekey with no valid token", func(f *r29Fx, m *Manager, p *Peer) {
			p.Pending = &PendingEpoch{ID: []byte("rekey-epoch"), Purpose: handshake.PurposeRekey, FinAt: f.clk}
			m.tickPending(p, f.clk)
			if p.Pending == nil {
				f.t.Error("tickPending abandoned the rekey for want of a token while carried tokens waited")
			}
			p.Pending = nil
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newR29Fx(t)
			f.t1Waiting()
			before := f.countOutgoingReconnects(0)
			f.do(0, func(m *Manager, p *Peer) { c.run(f, m, p) })
			if n := f.countOutgoingReconnects(0); n != before {
				t.Fatalf("a reconnect started while carried tokens waited (%d -> %d)", before, n)
			}
			if f.p(0).State == PeerStale {
				t.Fatal("judged stale while carried tokens waited")
			}
		})
	}
}

// "hs.confirm again" stays stopped for an epoch whose carried tokens were
// discarded, even after an own reconnect superseded the record and was
// then abandoned (review 3ce94c6, item 1).
func TestR29T1SupersedeKeepsTheStopMarker(t *testing.T) {
	f := newR29Fx(t)
	f.revocations(0)
	f.advance(10 * 24 * time.Hour)
	f.t1Reconnect(1, 0)
	f.lose(0, 1, kConfirm)
	f.do(0, func(m *Manager, p *Peer) {
		c := p.carriedFor(p.LastEpochID)
		c.Discarded, c.Standing, c.Reconnect = true, HeldToken{}, HeldToken{}
		m.supersedeCarried(p)
		if !p.confirmStopped() {
			t.Fatal("the supersede dropped the current epoch's stop marker")
		}
	})
}

// Two records collapse to one at the peer's reconnect's hs.fin, in a
// crossing that rule E does not cover (the reconnect names R's current
// epoch, not its confirmed one): I confirmed E1 but its prompt was lost, so
// E1's record still waits at R when I's next reconnect E2 is established.
// (Rule E usually destroys E1 first, which discards its record too.)
func TestR29T1FinSupersedesAnEarlierRecord(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	f.t1Reconnect(1, 0) // E1
	f.deliver(0, 1, kConfirm)
	f.lose(1, 0, kAny) // the prompt is lost: E1's record still waits at R
	if f.p(0).carriedFor(f.cur(0)) == nil {
		t.Fatal("setup: no waiting record for E1")
	}
	e1 := append([]byte(nil), f.cur(0)...)
	f.advance(time.Minute)
	f.t1Reconnect(1, 0) // E2, naming I's current epoch E1 (R's current): no rule E
	// E1 may stay as a Discarded marker (it was current at the supersede);
	// only E2's record may still be adopted.
	waiting := 0
	for _, c := range f.p(0).Carried {
		if !c.Discarded {
			waiting++
			if !bytes.Equal(c.Epoch, f.cur(0)) || bytes.Equal(c.Epoch, e1) {
				t.Fatal("a record other than E2's still waits")
			}
		}
	}
	if waiting != 1 {
		f.dump()
		t.Fatalf("at E2's hs.fin R has %d waiting records, not just E2's", waiting)
	}
}

// t1RekeyFinWaiting gives side 0 a pending rekey whose hs.fin the relay
// refused token_expired (side 0's deposits on its held standing token are
// refused from now on), so it waits in the outbox for a token. It returns
// the pending epoch's id.
func (f *r29Fx) t1RekeyFinWaiting() []byte {
	f.t.Helper()
	f.rekey(0)
	if f.deliver(0, 1, kHSInit) != 1 {
		f.t.Fatal("setup: no rekey hs.init")
	}
	// From the hs.fin on (not before: a refused hs.init would start a reconnect instead).
	held := f.p(0).Standing.Token
	r := f.d[0].relay
	r.mu.Lock()
	r.check = func(_, token string) error {
		if token == held {
			return &relayclient.Error{Status: 401, Code: CodeTokenExpired}
		}
		return nil
	}
	r.mu.Unlock()
	if f.deliver(1, 0, kHSResp) != 1 {
		f.t.Fatal("setup: the rekey did not reach hs.resp")
	}
	pe := f.p(0).Pending
	if pe == nil || f.finEntry(0, pe.ID) == nil {
		f.dump()
		f.t.Fatal("setup: no pending rekey with its hs.fin waiting")
	}
	return append([]byte(nil), pe.ID...)
}

// finEntry is side s's outbox entry, not done, holding the hs.fin of epoch id.
func (f *r29Fx) finEntry(s int, id []byte) *OutboxEntry {
	for _, e := range f.m(s).st.Outbox {
		if !e.Done && bytes.Equal(e.FinEpoch, id) {
			return e
		}
	}
	return nil
}

// An abandoned pending epoch's hs.fin that the relay has not accepted is
// dropped with it, whatever abandons it (VAULT-MESSAGING 0.88.2 §6.3.1
// Initiator; the false suspensions of GC #6493).
func TestR29AbandonedPendingDropsItsWaitingFin(t *testing.T) {
	cases := []struct {
		name    string
		abandon func(f *r29Fx)
	}{
		{"its own reconnect", func(f *r29Fx) {
			f.do(0, func(m *Manager, p *Peer) { m.startReconnect(p, f.clk) })
			// The reconnect's own hs.fin, on its carried token, still goes.
			if f.deliver(0, 1, kHSInit) != 1 || f.deliver(1, 0, kHSResp) != 1 || f.deliver(0, 1, kHSFin) != 1 {
				f.dump()
				f.t.Fatal("the newer epoch's hs.fin did not go")
			}
		}},
		{"the peer's reconnect activated (peer_activated)", func(f *r29Fx) {
			f.do(1, func(m *Manager, p *Peer) { m.startReconnect(p, f.clk) })
			f.deliver(1, 0, kHSInit)
			f.deliver(0, 1, kHSResp)
			f.deliver(1, 0, kHSFin)
		}},
		{"its own rotation (S5)", func(f *r29Fx) { f.rotate(0) }},
		{"no valid standing token (no_token)", func(f *r29Fx) {
			f.do(0, func(m *Manager, p *Peer) { p.Standing.Exp = f.clk.Add(-time.Minute) })
			f.tick(0)
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newR29Fx(t)
			f.longTokens()
			id := f.t1RekeyFinWaiting()
			c.abandon(f)
			if f.p(0).Pending != nil && bytes.Equal(f.p(0).Pending.ID, id) {
				f.dump()
				t.Fatal("setup: the pending rekey was not abandoned")
			}
			if f.finEntry(0, id) != nil {
				t.Fatal("the abandoned epoch's waiting hs.fin is still in the outbox")
			}
		})
	}
}

// R drops its open rekey answers to I when it establishes I's reconnect at
// its hs.fin (0.88.2): an hs.fin for one, redelivered after the reconnect's
// epoch is confirmed, would otherwise make rule E destroy that epoch.
func TestR29ReconnectDropsTheRekeyAnswers(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	f.rekey(0)
	if f.deliver(0, 1, kHSInit) != 1 {
		t.Fatal("no rekey hs.init")
	}
	f.lose(1, 0, kHSResp)
	rekeyAnswers := func() int {
		n := 0
		for _, aw := range f.m(1).st.Awaiting {
			if aw.PeerID == f.p(1).ID && aw.Purpose == handshake.PurposeRekey {
				n++
			}
		}
		return n
	}
	if rekeyAnswers() != 1 {
		t.Fatal("setup: R holds no rekey answer")
	}
	f.t1Reconnect(0, 1)
	if rekeyAnswers() != 0 {
		f.dump()
		t.Fatal("R kept its rekey answer after establishing I's reconnect")
	}
}

// I has its rekey K open and starts reconnect C; R answers both; I gets
// C's hs.resp first. I abandons K at C's hs.resp (0.88.2 §6.3.1 Initiator),
// so the late hs.resp of K makes no pending epoch that R, which dropped its
// answer to K at C's hs.fin, would never answer: the pair converges on C.
// (The lead's merged re-check of 5b4fd3c, Opus M1, Fable F1.)
func TestR29ReconnectRespAbandonsTheOwnRekeys(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	f.rekey(0)
	if f.deliver(0, 1, kHSInit) != 1 {
		t.Fatal("no rekey hs.init")
	}
	f.do(0, func(m *Manager, p *Peer) { m.startReconnect(p, f.clk) })
	if f.deliver(0, 1, kHSInit) != 1 {
		t.Fatal("no reconnect hs.init")
	}
	resps := f.takeKind(1, 0, kHSResp)
	if len(resps) != 2 {
		t.Fatalf("setup: %d answers, want the rekey's and the reconnect's", len(resps))
	}
	f.process(0, resps[1]) // the reconnect's first
	f.process(0, resps[0]) // then the rekey's
	f.settle()
	for i := 0; i < 3; i++ {
		f.advance(time.Hour)
		f.tick(0)
		f.tick(1)
		f.settle()
	}
	if !f.sameEpoch() || f.p(0).Pending != nil || f.p(1).Pending != nil {
		f.dump()
		t.Fatal("the pair did not end on one epoch")
	}
	for _, og := range f.m(0).st.Outgoing {
		if og.PeerID == f.p(0).ID && og.Purpose == handshake.PurposeRekey {
			t.Fatal("I kept its rekey open past its reconnect's hs.resp")
		}
	}
}

// A rekey answer marked replaced at a restore's reconnect is kept only as
// evidence: it holds no rekey of R's back (the lead's merged re-check of
// 5b4fd3c, Opus L1, Fable F2).
func TestR29ReplacedRekeyAnswerBlocksNoRekey(t *testing.T) {
	f := newR29Fx(t)
	f.do(1, func(m *Manager, p *Peer) {
		m.st.Awaiting["replaced"] = &AwaitingHS{ID: "replaced", PeerID: p.ID, Purpose: handshake.PurposeRekey, Created: f.clk, Replaced: true}
		if m.rekeyBlocked(p) {
			t.Fatal("a replaced rekey answer blocks R's rekeys")
		}
		m.st.Awaiting["replaced"].Replaced = false
		if !m.rekeyBlocked(p) {
			t.Fatal("setup: an open rekey answer does not block R's rekeys")
		}
		delete(m.st.Awaiting, "replaced")
	})
}
