package vault

import (
	"bytes"
	"context"
	"testing"
	"time"
)

// The lead's final review of release 29 (GC #7773).

// Item 1: rule E's write discards the carried tokens of the epoch it
// destroys and, with no valid standing token held, reconnects in that write
// (§6.3.1 "Discarded, never adopted"), not at the next batch's housekeeping.
func TestR29FinalRuleEDiscardsCarriedInItsWrite(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	f.t1Reconnect(1, 0) // E1: R (0) activated it at hs.fin and holds its carried tokens
	f.lose(0, 1, kAny)  // I (1) hears nothing: no confirmation
	e1 := append([]byte(nil), f.cur(0)...)
	// I abandons E1 and rekeys under E0, R's confirmed epoch: at its hs.fin rule E destroys E1.
	f.do(1, func(m *Manager, p *Peer) { m.abandonPending(p, "test", false, f.clk) })
	f.rekey(1)
	if f.deliver(1, 0, kHSInit) != 1 || f.deliver(0, 1, kHSResp) != 1 {
		f.dump()
		t.Fatal("setup: the rekey did not reach hs.resp")
	}
	f.p(0).Standing.Exp = f.clk.Add(-time.Minute) // R now holds no valid standing token
	if f.deliver(1, 0, kHSFin) != 1 {
		f.dump()
		t.Fatal("setup: the rekey's hs.fin did not arrive")
	}
	if e := f.p(0).epochMeta(e1); e == nil || !e.Destroyed {
		f.dump()
		t.Fatal("setup: rule E did not destroy E1")
	}
	for _, c := range f.p(0).Carried {
		if bytes.Equal(c.Epoch, e1) && !c.Discarded {
			t.Fatal("E1's carried tokens wait after rule E's write")
		}
	}
	if !f.audited(0, "carried_discarded") {
		t.Fatal("the discard was not in rule E's write")
	}
	if f.openReconnect(0) == nil && f.p(0).Pending == nil {
		f.dump()
		t.Fatal("holding no valid standing token, R did not reconnect in rule E's write")
	}
}

// Item 1: a demotion's write discards the carried tokens of the epoch it
// demotes (§6.3.1 "Discarded, never adopted"), not the next housekeeping.
func TestR29FinalDemotionDiscardsCarriedInItsWrite(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	f.t1Reconnect(1, 0) // E1: R (0) activated it at hs.fin and holds its carried tokens
	e1 := append([]byte(nil), f.cur(0)...)
	if f.lose(0, 1, kConfirm) != 1 || f.p(1).Pending == nil {
		t.Fatal("setup: I's E1 is not pending")
	}
	if c := f.p(0).carriedFor(e1); c == nil || c.Discarded {
		t.Fatal("setup: R holds no waiting carried tokens for E1")
	}
	f.rotate(1)
	f.deliver(1, 0, kRotate) // E1, signed by I's old ik and established after the link: demoted
	if e := f.p(0).epochMeta(e1); e == nil || !e.Demoted {
		f.dump()
		t.Fatal("setup: E1 is not demoted")
	}
	if c := f.p(0).carriedFor(e1); c != nil && !c.Discarded {
		t.Fatal("E1's carried tokens wait after the demotion's write")
	}
	if !f.audited(0, "carried_discarded") {
		t.Fatal("the discard was not in the demotion's write")
	}
}

// Item 2: a reconnect whose links suspend the connection at its hs.fin
// leaves no carried record for its epoch, which was never established, so
// no later sweep audits a discard (carried_discarded) for it.
func TestR29FinalSuspendedFinLeavesNoCarriedRecord(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	f.rotate(1)
	f.lose(1, 0, kRotate) // R (0) learns the link from the reconnect
	f.lose(1, 0, kHSInit) // and the rekey under the new ik is lost too
	f.do(1, func(m *Manager, p *Peer) {
		m.abandonHandshakes(p, false, false, f.clk)
		m.startReconnect(p, f.clk)
	})
	if f.deliver(1, 0, kHSInit) != 1 || f.deliver(0, 1, kHSResp) != 1 {
		f.dump()
		t.Fatal("setup: the reconnect did not reach hs.resp")
	}
	// R's current epoch reads as one an old copy of I used after the link
	// ("Epochs after an ik link": established after it, its flag set), so
	// following the hs.fin's link suspends the connection.
	f.do(0, func(m *Manager, p *Peer) {
		e := p.epochMeta(p.LastEpochID)
		e.EstAt, e.EstMsg, e.GotFromPeer = f.clk.Add(time.Hour), "", true
	})
	carriedBefore := len(f.p(0).Carried)
	f.deliver(1, 0, kHSFin)
	if !f.p(0).suspended() {
		f.dump()
		t.Fatal("setup: following the links did not suspend")
	}
	if n := len(f.p(0).Carried); n != carriedBefore {
		t.Fatalf("a carried record was kept for an epoch never established (%d -> %d)", carriedBefore, n)
	}
	f.advance(time.Minute)
	f.tick(0)
	if f.audited(0, "carried_discarded") {
		t.Fatal("a discard was audited for a suspended connection's epoch never established")
	}
}

// Item 4: a token issued after the one a quota refresh came under is spared
// even when both expire in the same second ("newer" is issue order, not
// exp), and the one it came under is denied.
func TestR29FinalQuotaRefreshSparesALaterTokenOfTheSameExp(t *testing.T) {
	f := newR29Fx(t)
	f.do(0, func(m *Manager, p *Peer) {
		under := m.latestIssued(p.ID, TokStanding)
		if under == nil {
			t.Fatal("setup: no standing token issued to the peer")
		}
		underJTI, underExp := under.JTI, under.Exp
		m.issueTo(p, TokStanding, f.clk) // issued in the same second: the same exp
		var laterJTI string
		for _, it := range m.st.Issued {
			if it.PeerID == p.ID && it.Kind == TokStanding && it.JTI != underJTI && it.Exp.Equal(underExp) {
				laterJTI = it.JTI
			}
		}
		if laterJTI == "" {
			t.Fatal("setup: no later token of the same exp")
		}
		m.msgJTI = underJTI
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
			case laterJTI:
				if it.Denied {
					t.Fatal("a token issued after it, of the same exp, was denied")
				}
			}
		}
	})
}

// refreshUnder runs side m's hTokenRefresh for p as if deposited under jti.
func refreshUnder(t *testing.T, f *r29Fx, m *Manager, p *Peer, jti string) {
	t.Helper()
	m.msgJTI = jti
	if _, err := m.hTokenRefresh(context.Background(), &Session{m: m, peer: p, now: f.clk}, nil); err != nil {
		t.Fatal(err)
	}
	m.msgJTI = ""
}

func deniedJTI(m *Manager, jti string) bool {
	for _, it := range m.st.Issued {
		if it.JTI == jti {
			return it.Denied
		}
	}
	return false
}

// Item 4 (review of a28c54d, finding 2): a handshake's token enters the
// registry at activation, after a token minted later (a refresh answered
// meanwhile); a refresh under the handshake's token spares that later one.
func TestR29FinalQuotaRefreshSparesALaterTokenRegisteredBefore(t *testing.T) {
	f := newR29Fx(t)
	f.do(0, func(m *Manager, p *Peer) {
		h := m.latestIssued(p.ID, TokStanding)
		hJTI := h.JTI
		f.advance(time.Hour)
		m.issueTo(p, TokStanding, f.clk) // X: minted after H, its exp later
		x := m.latestIssued(p.ID, TokStanding)
		xJTI := x.JTI
		// H enters the registry after X, as a handshake's tokens do at activation.
		var hRec IssuedToken
		kept := m.st.Issued[:0]
		for _, it := range m.st.Issued {
			if it.JTI == hJTI {
				hRec = it
				continue
			}
			kept = append(kept, it)
		}
		m.st.Issued = append(kept, hRec)
		refreshUnder(t, f, m, p, hJTI)
		if !deniedJTI(m, hJTI) {
			t.Fatal("the token the refresh came under was not denied")
		}
		if deniedJTI(m, xJTI) {
			t.Fatal("a token minted after it, registered before it, was denied")
		}
	})
}

// Item 4 (review of a28c54d, M6): a second refresh under a token the first
// already denied spares the token the first one minted, still on its way.
func TestR29FinalSecondRefreshUnderADeniedTokenSparesTheFirstsToken(t *testing.T) {
	f := newR29Fx(t)
	f.do(0, func(m *Manager, p *Peer) {
		under := m.latestIssued(p.ID, TokStanding).JTI
		f.advance(time.Second)
		refreshUnder(t, f, m, p, under)
		first := m.latestIssued(p.ID, TokStanding).JTI
		if first == under || !deniedJTI(m, under) {
			t.Fatal("setup: the first refresh did not mint a fresh token and deny the old one")
		}
		f.advance(25 * time.Hour) // past the one-a-day bound
		refreshUnder(t, f, m, p, under)
		if deniedJTI(m, first) {
			t.Fatal("a refresh under an already denied token denied the token the first refresh minted")
		}
	})
}
