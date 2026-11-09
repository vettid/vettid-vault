package vault

import (
	"context"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
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
