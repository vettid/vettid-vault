package vault

import (
	"bytes"
	"testing"

	"github.com/vettid/vettid-vault/vms/suite"
)

// §3.4.1 "Strict F1, a link under an earlier epoch" (R29-K7): Q takes
// together every epoch of P after E whose P-side signer is the link's
// old_ik or an ancestor. Here side 0 holds, besides its current E1, a
// second such epoch X after E0 (recorded before the link arrives).

func strictF1(t *testing.T, flagX bool) (*r29Fx, []byte, []byte) {
	t.Helper()
	x := bytes.Repeat([]byte{0x5c}, suite.EpochIDSize)
	f := newR29Fx(t)
	f.longTokens()
	e0 := append([]byte(nil), f.cur(0)...)
	f.rekey(1)
	f.deliver(1, 0, kHSInit)
	f.deliver(0, 1, kHSResp)
	f.deliver(1, 0, kHSFin)
	f.lose(0, 1, kConfirm)
	f.rotate(1) // side 1 abandons its pending E1; identity.rotate under E0
	f.do(0, func(_ *Manager, p *Peer) {
		cur := p.epochMeta(p.LastEpochID)
		p.Epochs = append(p.Epochs, EpochMeta{ID: x, Signer: append([]byte(nil), cur.Signer...), Superseded: f.clk,
			EstAt: cur.EstAt, EstMsg: cur.EstMsg, GotFromPeer: flagX})
	})
	f.deliver(1, 0, kRotate)
	return f, e0, x
}

// No flag set: every such epoch is demoted, and the reconnect names E.
func TestR29StrictF1DemotesEveryLaterEpoch(t *testing.T) {
	f, e0, x := strictF1(t, false)
	if e := f.p(0).epochMeta(x); e == nil || !e.Demoted {
		f.dump()
		t.Fatal("a second later epoch signed by the old ik was not demoted")
	}
	if f.p(0).suspended() {
		t.Fatal("suspended with every flag clear")
	}
	og := f.openReconnect(0)
	if og == nil || !bytes.Equal(og.Named, e0) {
		f.dump()
		t.Fatal("the reconnect does not name E")
	}
}

// A flag set on any of them (here not the current one): Q suspends, ref
// epoch, with the (neutral) feed item.
func TestR29StrictF1AnyFlagSuspends(t *testing.T) {
	f, _, _ := strictF1(t, true)
	if !f.suspendedRef(0, "epoch") {
		f.dump()
		t.Fatal("a set flag on a later epoch did not suspend")
	}
	feed := false
	for _, a := range f.sink[0].got {
		feed = feed || a.Kind == "connection.fork_suspected" && a.Ref == "epoch" && a.Feed
	}
	if !feed {
		t.Fatal("no feed item")
	}
}
