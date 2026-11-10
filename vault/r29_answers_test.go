package vault

import (
	"fmt"
	"sort"
	"testing"
	"time"
)

// §3.4.1 H5 (0.88.2 at c91810f, owner decision a): a new reconnect hs.init
// from P that Q answers does not end Q's earlier answer to P's reconnect
// pinned to the same ik; Q keeps at most MaxReconnectAnswers per peer
// (the oldest dropped beyond, its tokens revoked); the first hs.fin whose
// sig_I verifies is established and the others are dropped in that
// write, their tokens revoked.

// pReconnects has P (side 1) start n reconnects, each after abandoning
// the last; it returns their hs.init messages to Q, in order.
func (f *r29Fx) pReconnects(n int) []Message {
	f.t.Helper()
	var out []Message
	for i := 0; i < n; i++ {
		f.do(1, func(m *Manager, p *Peer) {
			for id, og := range m.st.Outgoing {
				if og.PeerID == p.ID {
					m.abandonOutgoing(id, f.clk)
				}
			}
			m.startReconnect(p, f.clk)
		})
		msgs := f.takeKind(1, 0, kHSInit)
		if len(msgs) != 1 {
			f.t.Fatalf("reconnect %d: %d hs.init", i, len(msgs))
		}
		msgs[0].MsgID = fmt.Sprintf("rc-%d", i) // distinct relay msg_ids
		out = append(out, msgs[0])
	}
	return out
}

// answerJTIs returns the tokens of Q's answers to P, by answer id.
func (f *r29Fx) answerJTIs(s int) map[string][]string {
	out := map[string][]string{}
	for id, aw := range f.m(s).st.Awaiting {
		if aw.PeerID == f.id[s] {
			out[id] = f.jtisOf(aw.Issued)
		}
	}
	return out
}

// The model's sequence (seeds 10393024044262541112, 471004796172726989):
// P sends R1, then R2; Q answers R2; R1, late, is answered too; P's
// hs.fin for R2 still finds its answer and the pair converges.
func TestR29LateReconnectKeepsLaterAnswer(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	rs := f.pReconnects(2)
	f.process(0, rs[1])
	f.process(0, rs[0])
	if n := f.answerCount(0); n != 2 {
		t.Fatalf("answers kept: %d", n)
	}
	f.settle()
	f.tick(0)
	f.tick(1)
	f.settle()
	if !f.sameEpoch() || f.p(0).State != PeerActive || f.p(1).State != PeerActive {
		f.dump()
		t.Fatal("did not converge")
	}
}

// At most MaxReconnectAnswers are kept; the oldest go, tokens revoked.
func TestR29ReconnectAnswersCapped(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	rs := f.pReconnects(MaxReconnectAnswers + 2)
	var first []string
	for i, r := range rs {
		f.advance(time.Second) // answers in order of their creation
		before := f.answerJTIs(0)
		f.process(0, r)
		if i < 2 {
			for id, j := range f.answerJTIs(0) {
				if _, ok := before[id]; !ok {
					first = append(first, j...)
				}
			}
		}
	}
	if n := f.answerCount(0); n != MaxReconnectAnswers {
		t.Fatalf("answers kept: %d (cap %d)", n, MaxReconnectAnswers)
	}
	if len(first) == 0 {
		t.Fatal("setup: no tokens in the first answers")
	}
	for _, j := range first {
		if !f.denied(0, j) {
			t.Fatal("a capped answer's token was not revoked")
		}
	}
}

// The first verified hs.fin is established; the other kept answers go in
// that write, their tokens revoked.
func TestR29FirstFinDropsOtherAnswers(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	rs := f.pReconnects(3)
	for _, r := range rs[:2] {
		f.process(0, r)
	}
	others := f.answerJTIs(0)
	f.process(0, rs[2]) // P's current reconnect, answered last
	f.deliver(0, 1, kHSResp)
	if f.deliver(1, 0, kHSFin) != 1 {
		t.Fatal("setup: no hs.fin")
	}
	if n := f.answerCount(0); n != 0 {
		t.Fatalf("%d answers kept after the verified hs.fin", n)
	}
	var ids []string
	for id := range others {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		for _, j := range others[id] {
			if !f.denied(0, j) {
				t.Fatal("a dropped answer's token was not revoked")
			}
		}
	}
}
