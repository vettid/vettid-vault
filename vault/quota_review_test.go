package vault

import (
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayclient"
	"github.com/vettid/vettid-vault/vms/peerwire"
)

// The lead's blind reviews of b020457 (GC #6783, #7027): Opus and Fable.

// spentRelay refuses every deposit under side s's current standing token
// for the token's quota (its msgs spent), the refresh included.
func (f *r29Fx) spentRelay(s int, q qNotes) (spent string, refusals *int) {
	spent = f.p(s).Standing.Token
	refusals = f.quotaRelayBy(s, q, func(tok, _ string) error {
		if tok == spent {
			return &relayclient.Error{Status: 429, Code: CodeQuotaExceeded, Quota: relayclient.QuotaToken}
		}
		return nil
	})
	return spent, refusals
}

// Must fix 1 (both): an own rekey's epoch pending, its hs.fin refused for
// the token's quota and then the refresh too: the vault reconnects at once
// (owner decision a, GC #6840), not after the token's exp (up to 30 days,
// past §8.4's 16: the waiting messages would be lost).
func TestQuotaReconnectsWhileARekeyIsPending(t *testing.T) {
	f := newR29Fx(t)
	q := qNotes{}
	f.rekey(0)
	if n := f.deliver(0, 1, kHSInit); n != 1 {
		t.Fatalf("%d hs.init delivered", n)
	}
	spent, refusals := f.spentRelay(0, q)
	if n := f.deliver(1, 0, kHSResp); n != 1 {
		t.Fatalf("%d hs.resp delivered", n)
	}
	if f.p(0).Pending == nil {
		t.Fatal("no own rekey epoch pending: the scenario is not set up")
	}
	q.send(f, 0, "after")
	f.advance(time.Minute)
	f.tick(0)
	if *refusals < 2 || !f.audited(0, "quota_refresh_refused") {
		t.Fatalf("%d refusals, refresh refused %v: want the hs.fin and the refresh refused", *refusals, f.audited(0, "quota_refresh_refused"))
	}
	if f.countOutgoingReconnects(0) == 0 {
		f.dump()
		t.Fatal("no reconnect while the own rekey is pending")
	}
	f.settle()
	f.advance(time.Minute)
	f.tick(0)
	f.settle()
	if f.p(0).Standing.Token == spent {
		t.Fatal("no fresh standing token")
	}
	if got := strings.Join(f.got[1], " "); got != `{"n":"after"}` {
		t.Fatalf("side 1 got %s", got)
	}
}

// Must fix 3 (Fable L1): the standing token revoked between the grant and
// its collect: the grant is still taken (else the connection could go
// stale).
func TestQuotaGrantTakenWhenTheStandingTokenIsGone(t *testing.T) {
	f := newR29Fx(t)
	q := qNotes{}
	f.quotaRelay(0, q, relayclient.QuotaToken, map[string]bool{"big": true})
	q.send(f, 0, "big")
	f.advance(time.Minute)
	if n := f.deliver(0, 1, kOther); n != 1 {
		t.Fatalf("%d refreshes delivered", n)
	}
	f.do(0, func(m *Manager, p *Peer) { p.Standing = HeldToken{} }) // revoked meanwhile (dropHeldToken)
	f.quotaRelay(0, q, relayclient.QuotaToken, nil)
	if n := f.deliver(1, 0, kAny); n == 0 {
		t.Fatal("no answer from side 1")
	}
	if f.p(0).Standing.Token == "" {
		t.Fatal("the grant was not taken")
	}
	if len(f.p(0).QuotaReqs) != 0 {
		t.Fatalf("open quota refreshes %v after the grant", f.p(0).QuotaReqs)
	}
	f.settle()
	if got := strings.Join(f.got[1], " "); got != `{"n":"big"}` {
		t.Fatalf("side 1 got %s", got)
	}
}

// A quota refresh entry held unsealed (§3.4.1) for testing sealHeld.
func heldRefresh(m *Manager, p *Peer, id string, held []byte, exp time.Time) *OutboxEntry {
	tag := tokenTag(p.Standing.Token)
	p.QuotaReqTok, p.QuotaReqs = tag, []string{id}
	e := &OutboxEntry{ID: "held-" + id, Op: OpDeposit, PeerID: p.ID, RelayURL: p.Relay.URL, Mailbox: p.Relay.Mailbox,
		Held: held, HeldExp: exp, QuotaRefresh: true, QuotaTok: tag, QuotaReq: id}
	m.st.Outbox = append(m.st.Outbox, e)
	return e
}

// Must fix 4 (Fable L2): a quota refresh dropped by sealHeld (past its
// exp, or unsealable) ends its request, so that a dead id does not take
// the kept first slot.
func TestQuotaHeldRefreshDroppedEndsItsRequest(t *testing.T) {
	for _, c := range []struct {
		name string
		held []byte
		exp  time.Duration
	}{
		{"expired", []byte("{}"), -time.Minute},
		{"unsealable", []byte("not an inner"), 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newR29Fx(t)
			f.do(0, func(m *Manager, p *Peer) {
				var exp time.Time
				if c.exp != 0 {
					exp = f.clk.Add(c.exp)
				}
				e := heldRefresh(m, p, "01J00000000000000000000000", c.held, exp)
				m.sealHeld(p)
				if !e.Done {
					t.Fatal("the held refresh was not dropped")
				}
				if len(p.QuotaReqs) != 0 {
					t.Fatalf("its request is still open: %v", p.QuotaReqs)
				}
			})
		})
	}
}

// Opus L1, Fable: the carried tokens of the current epoch still waiting
// (carriedWait) hold the quota reconnect back.
func TestQuotaReconnectWaitsForCarriedTokens(t *testing.T) {
	for _, carried := range []bool{false, true} {
		f := newR29Fx(t)
		f.do(0, func(m *Manager, p *Peer) {
			if carried {
				meta := p.epochMeta(p.LastEpochID)
				meta.Mine = false
				p.Confirmed = nil
				p.Carried = append(p.Carried, CarriedTokens{Epoch: append([]byte(nil), p.LastEpochID...), Since: f.clk})
				if !m.carriedWait(p, f.clk) {
					t.Fatal("the carried tokens do not wait: the scenario is not set up")
				}
			}
			m.quotaReconnect(p, f.clk)
		})
		if got, want := f.countOutgoingReconnects(0) > 0, !carried; got != want {
			t.Fatalf("carried %v: reconnect started %v, want %v", carried, got, want)
		}
	}
}

// Opus L1, Fable: a refresh refused with no `quota` may be the mailbox's:
// no reconnect, asked again an hour later.
func TestQuotaRefreshRefusedWithoutQuotaIsAskedAgain(t *testing.T) {
	f := newR29Fx(t)
	q := qNotes{}
	spent := f.p(0).Standing.Token
	f.quotaRelayBy(0, q, func(tok, _ string) error {
		if tok == spent {
			return &relayclient.Error{Status: 429, Code: CodeQuotaExceeded}
		}
		return nil
	})
	q.send(f, 0, "big")
	f.advance(time.Minute)
	f.tick(0)
	if !f.audited(0, "quota_refresh_refused") {
		t.Fatal("the refresh was not refused")
	}
	if f.countOutgoingReconnects(0) != 0 {
		t.Fatal("a reconnect on a refresh refused without quota")
	}
	n := f.auditCount(0, "quota_refresh_refused")
	f.advance(30 * time.Minute)
	f.tick(0)
	if f.auditCount(0, "quota_refresh_refused") != n {
		t.Fatal("asked again within the hour")
	}
	f.advance(31 * time.Minute)
	f.tick(0) // the note due: the refresh asked again
	f.tick(0) // and sent
	if f.auditCount(0, "quota_refresh_refused") != n+1 {
		t.Fatal("not asked again after the hour")
	}
	if f.countOutgoingReconnects(0) != 0 {
		t.Fatal("a reconnect on a refresh refused without quota")
	}
}

// Opus L1: a quota too_soon's allowed_after is taken up to the issuer's
// period plus a minute (§7.2), never further.
func TestQuotaTooSoonIsCapped(t *testing.T) {
	f := newR29Fx(t)
	f.do(0, func(m *Manager, p *Peer) {
		p.QuotaReqTok, p.QuotaReqs = tokenTag(p.Standing.Token), []string{"01J00000000000000000000000"}
		m.quotaTooSoon(p, "01J00000000000000000000000", peerwire.TooSoonBody(f.clk.Add(72*time.Hour)), f.clk)
		if got, want := m.quotaAsk[p.ID].after, f.clk.Add(peerwire.QuotaRefreshEvery+time.Minute); !got.Equal(want) {
			t.Fatalf("allowed_after %v, want %v", got, want)
		}
	})
}

// Opus L1: in the token's last minutes a waiting entry is due no later
// than the exp (then it reconnects, §6.6).
func TestQuotaNextIsClampedToTheExp(t *testing.T) {
	f := newR29Fx(t)
	f.do(0, func(m *Manager, p *Peer) {
		p.Standing.Exp = f.clk.Add(30 * time.Minute)
		if got := m.quotaNext(p, f.clk); !got.Equal(p.Standing.Exp) {
			t.Fatalf("next %v, want the exp %v", got, p.Standing.Exp)
		}
	})
}

// Opus L1: a deposit with a token of its own refused for the quota is not
// a standing token's quota wait (it is retried with the backoff).
func TestQuotaOwnTokenDepositDoesNotWait(t *testing.T) {
	f := newR29Fx(t)
	q := qNotes{}
	f.quotaRelayBy(0, q, func(tok, _ string) error {
		if tok == "own-token" {
			return &relayclient.Error{Status: 429, Code: CodeQuotaExceeded, Quota: relayclient.QuotaToken}
		}
		return nil
	})
	var e *OutboxEntry
	f.do(0, func(m *Manager, p *Peer) {
		e = &OutboxEntry{ID: "own", Op: OpDeposit, PeerID: p.ID, RelayURL: p.Relay.URL, Mailbox: p.Relay.Mailbox,
			Token: "own-token", Payload: []byte("x")}
		m.st.Outbox = append(m.st.Outbox, e)
	})
	f.tick(0)
	if e.QuotaWait || f.asking(0) {
		t.Fatalf("own-token deposit waits for a standing token: %+v", e)
	}
}

// Opus L1: a quota refresh answered with a token not adopted (no later
// exp) is forgotten all the same.
func TestQuotaNonAdoptingAnswerEndsTheRequest(t *testing.T) {
	f := newR29Fx(t)
	q := qNotes{}
	f.quotaRelay(0, q, relayclient.QuotaToken, map[string]bool{"big": true})
	q.send(f, 0, "big")
	if len(f.p(0).QuotaReqs) != 1 {
		t.Fatalf("open quota refreshes %v, want 1", f.p(0).QuotaReqs)
	}
	tok := f.p(0).Standing.Token
	f.settle() // no time passed: the fresh token's exp is not later
	if f.p(0).Standing.Token != tok {
		t.Fatal("the token was adopted: the scenario is not set up")
	}
	if len(f.p(0).QuotaReqs) != 0 {
		t.Fatalf("open quota refreshes %v after the answer", f.p(0).QuotaReqs)
	}
}

// Opus L1: the open refreshes of another standing token are dropped when
// one is asked under the current one.
func TestQuotaAskUnderANewTokenDropsTheOldRequests(t *testing.T) {
	f := newR29Fx(t)
	f.do(0, func(m *Manager, p *Peer) {
		p.QuotaReqTok, p.QuotaReqs = "0000000000000000", []string{"01J00000000000000000000000"}
		m.askQuotaRefresh(p, f.clk)
		if len(p.QuotaReqs) != 1 || p.QuotaReqs[0] == "01J00000000000000000000000" || p.QuotaReqTok != tokenTag(p.Standing.Token) {
			t.Fatalf("open %v under %s", p.QuotaReqs, p.QuotaReqTok)
		}
	})
}

// Fable N2: a refresh still queued under another token does not hold an
// ask under the current one.
func TestQuotaLeftoverRefreshDoesNotHoldAnAsk(t *testing.T) {
	f := newR29Fx(t)
	f.do(0, func(m *Manager, p *Peer) {
		m.st.Outbox = append(m.st.Outbox, &OutboxEntry{ID: "left", Op: OpDeposit, PeerID: p.ID, QuotaRefresh: true, QuotaTok: "0000000000000000"})
		m.askQuotaRefresh(p, f.clk)
		if len(p.QuotaReqs) != 1 {
			t.Fatalf("no refresh asked beside a leftover of another token: %v", p.QuotaReqs)
		}
	})
}

// Fable L1: with no standing token held (revoked), neither a new ask nor
// retryPeer drops the open refreshes: their grant is still to be taken.
func TestQuotaOpenRefreshesKeptWithNoStandingToken(t *testing.T) {
	f := newR29Fx(t)
	f.do(0, func(m *Manager, p *Peer) {
		id := "01J00000000000000000000000"
		p.QuotaReqTok, p.QuotaReqs = tokenTag(p.Standing.Token), []string{id}
		p.Standing = HeldToken{}
		m.askQuotaRefresh(p, f.clk)
		m.retryPeer(p.ID)
		if len(p.QuotaReqs) != 1 || p.QuotaReqs[0] != id || !quotaRequest(p, id) {
			t.Fatalf("open %v under %q: the grant would be lost", p.QuotaReqs, p.QuotaReqTok)
		}
	})
}

// L1 (the author's review): past the token's exp an entry refused under
// it is not sent again, also when no reconnect starts (carried tokens
// waiting, carriedWait): it waits.
func TestQuotaPastTheExpNotResentWhileCarriedTokensWait(t *testing.T) {
	f := newR29Fx(t)
	q := qNotes{}
	refusals := f.quotaRelay(0, q, relayclient.QuotaToken, map[string]bool{"big": true})
	f.d[0].relay.mu.Lock()
	f.d[0].relay.check = nil // the relay's clock behind: it takes the token past its exp
	f.d[0].relay.mu.Unlock()
	f.do(0, func(m *Manager, p *Peer) {
		p.Standing.Exp = f.clk.Add(10 * time.Minute)
		meta := p.epochMeta(p.LastEpochID)
		meta.Mine = false
		p.Confirmed = nil
		p.Carried = append(p.Carried, CarriedTokens{Epoch: append([]byte(nil), p.LastEpochID...), Since: f.clk})
	})
	q.send(f, 0, "big")
	f.lose(0, 1, kOther) // the refresh lost: no fresh token comes
	n := *refusals
	if e := q.entry(f, 0, "big"); e == nil || !e.NotBefore.Equal(f.p(0).Standing.Exp) {
		t.Fatalf("entry %+v: not due at the exp", e)
	}
	for i := 0; i < 4; i++ {
		f.advance(5 * time.Minute)
		f.tick(0)
	}
	if !f.m(0).carriedWait(f.p(0), f.clk) {
		t.Fatal("the carried tokens do not wait: the scenario is not set up")
	}
	if *refusals != n {
		t.Fatalf("%d refusals after %d: resent under the refused token past its exp", *refusals, n)
	}
	if e := q.entry(f, 0, "big"); e == nil || !e.QuotaWait {
		t.Fatalf("entry %+v: want it still waiting", e)
	}
}
