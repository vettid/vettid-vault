package vault

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"github.com/vettid/vettid-vault/vms/handshake"
)

// §3.4.1 "Epochs abandoned while pending, at P's identity.rotate"
// (R29-K9). Side 0 (Q) begins E1 with side 1 (P) and abandons it while
// pending; P's side never activated it, unless a copy did.

// k9Setup: Q's rekey E0 to E1 is answered by P, Q has E1 pending and its
// hs.fin out; then (withCopy) P is copied, P rotates (S5 drops its answer;
// its identity.rotate travels under E0 and is held back), and Q abandons
// E1 (a stand-in for any abandon but a link's).
func k9Setup(t *testing.T, withCopy bool) (*r29Fx, []byte) {
	t.Helper()
	f := newR29Fx(t)
	f.longTokens()
	f.rekey(0)
	f.deliver(0, 1, kHSInit)
	f.deliver(1, 0, kHSResp)
	if f.p(0).Pending == nil {
		t.Fatal("setup: no pending epoch")
	}
	e1 := append([]byte(nil), f.p(0).Pending.ID...)
	if withCopy {
		snap := f.snapshot(1)
		f.rotate(1)
		f.lose(1, 0, kHSInit) // P's restarted rekey: not under test
		f.startCopy(1, snap)
	}
	f.do(0, func(m *Manager, p *Peer) { m.abandonPending(p, "test", false, f.clk) })
	return f, e1
}

func (f *r29Fx) ended(s int, id []byte) bool {
	e := f.p(s).epochMeta(id)
	return e != nil && e.Ended
}

// A copy used E1 (its hs.confirm sets E1's flag without confirming it):
// at P's identity.rotate Q suspends (ref epoch, the neutral feed item).
func TestR29K9FlagSetSuspends(t *testing.T) {
	f, e1 := k9Setup(t, true)
	f.deliver(0, 2, kHSFin)
	f.deliver(2, 0, kConfirm)
	if !f.flag(0, e1) || f.p(0).suspended() || bytes.Equal(f.cur(0), e1) {
		t.Fatal("setup: E1's flag not set, or confirmed, or suspended early")
	}
	f.deliver(1, 0, kRotate)
	if !f.suspendedRef(0, "epoch") || !f.forkFeed(0) {
		f.dump()
		t.Fatal("K9 with the flag set did not suspend with the feed item")
	}
}

// Flag clear: E1 is ended (fork_suspected audited, no feed item, no
// suspension); the copy's later message under it suspends.
func TestR29K9FlagClearEndsThenSuspends(t *testing.T) {
	f, e1 := k9Setup(t, true)
	f.deliver(1, 0, kRotate)
	if !f.ended(0, e1) || f.p(0).suspended() || f.forkFeed(0) || !f.activity(0, "connection.fork_suspected", "epoch") {
		f.dump()
		t.Fatal("E1 not ended as K9 says")
	}
	f.deliver(0, 2, kHSFin)
	f.deliver(2, 0, kConfirm)
	if !f.suspendedRef(0, "epoch") {
		f.dump()
		t.Fatal("a message under an ended epoch did not suspend")
	}
}

// A reconnect ctx naming an ended epoch is refused, and is not fork
// evidence.
func TestR29K9EndedCtxRefused(t *testing.T) {
	f, e1 := k9Setup(t, true)
	f.deliver(1, 0, kRotate)
	if !f.ended(0, e1) {
		t.Fatal("setup: not ended")
	}
	f.do(0, func(m *Manager, p *Peer) {
		named, _, fork, refuse := m.classifyCtx086(p, handshake.EpochCtx(epochIDOf(e1)), nil)
		if !refuse || fork || named != nil {
			t.Fatalf("a ctx naming an ended epoch: named %x fork %v refuse %v", named, fork, refuse)
		}
	})
}

// A link first followed from an hs.resp judges nothing; the
// identity.rotate that carries it (now an ignore) does.
func TestR29K9NotJudgedAtHSResp(t *testing.T) {
	f, e1 := k9Setup(t, false)
	f.lose(0, 1, kAny) // E1's hs.fin is lost
	f.rotate(1)
	f.lose(1, 0, kHSInit) // P's restarted rekey: not under test (and not crossing Q's)
	f.do(1, func(m *Manager, p *Peer) {
		for id, og := range m.st.Outgoing {
			if og.PeerID == p.ID && og.Purpose == handshake.PurposeRekey {
				m.abandonOutgoing(id, f.clk)
			}
		}
	})
	f.rekey(0) // Q's new rekey, to P's old ik
	f.deliver(0, 1, kHSInit)
	f.deliver(1, 0, kHSResp) // carries P's link: followed at hs.resp
	if !bytes.Equal(f.p(0).IK, f.m(1).keys.ik.Public().(ed25519.PublicKey)) {
		f.dump()
		t.Fatal("setup: the hs.resp's link was not followed")
	}
	if f.ended(0, e1) || f.p(0).suspended() {
		f.dump()
		t.Fatal("an hs.resp's link judged the abandoned epoch")
	}
	f.deliver(1, 0, kRotate) // every link already followed: ignore, K9 judged
	if !f.ended(0, e1) {
		f.dump()
		t.Fatal("the identity.rotate (all links followed) did not judge the abandoned epoch")
	}
}

// An honest P that activated E1 (Q abandoned it meanwhile) rotates and
// sends identity.rotate under E1: E1 is not later than E, so it is not
// judged, although its flag is set.
func TestR29K9HonestRotateUnderEpochNotJudged(t *testing.T) {
	f, e1 := k9Setup(t, false)
	f.deliver(0, 1, kHSFin) // P activates E1
	f.deliver(1, 0, kConfirm)
	if !f.flag(0, e1) || !bytes.Equal(f.cur(1), e1) {
		t.Fatal("setup")
	}
	f.rotate(1)
	if f.deliver(1, 0, kRotate) != 1 {
		t.Fatal("setup: no identity.rotate")
	}
	if f.ended(0, e1) || f.p(0).suspended() {
		f.dump()
		t.Fatal("an identity.rotate under the epoch itself judged it")
	}
}
