package vault

import (
	"context"
	"testing"

	"github.com/vettid/vettid-relay/relayauth"

	"github.com/vettid/vettid-vault/vms/envelope"

	"github.com/vettid/vettid-vault/vms/handshake"
)

// §3.4.1 O3a (0.85.4, the lead's consistency check): side 0, a release-28
// stand-in, reconnects; side 1 answers; side 0 rotates while its reconnect
// is open (release 28 has no S5) and side 1 follows the link first, so H5
// drops its answer. Side 0's hs.fin, signed by the old (now ancestor) ik,
// then makes the connection stale from a peer without features, and is
// acked and dropped from one with features.
func TestR29O3aOlderPeersFin(t *testing.T) {
	for _, withFeatures := range []bool{false, true} {
		f := newR29Fx(t, true, false)
		f.longTokens()
		f.do(0, func(m *Manager, p *Peer) { m.startReconnect(p, f.clk) })
		f.deliver(0, 1, kHSInit)
		if f.answerCount(1) != 1 {
			t.Fatal("setup: no answer")
		}
		if withFeatures {
			f.do(1, func(_ *Manager, p *Peer) { p.PeerFeatures = []string{handshake.CapConfirm} })
		}
		f.rotate(0)
		if !f.m(0).hasOutgoing(f.id[0], handshake.PurposeReconnect) {
			t.Fatal("setup: the stand-in dropped its reconnect at its rotation")
		}
		f.deliver(0, 1, kRotate)
		if f.answerCount(1) != 0 || len(f.m(1).st.DroppedAnswers) != 1 {
			t.Fatal("H5 did not drop and record the answer")
		}
		f.deliver(1, 0, kHSResp)
		var fin []byte
		f.d[0].relay.mu.Lock()
		for _, dep := range f.d[0].relay.deposits {
			if env, err := envelope.Parse(dep.payload); err == nil && dep.mailbox == f.m(1).st.Relay.Mailbox && env.Mode() == envelope.ModeSession {
				fin = append([]byte(nil), dep.payload...)
			}
		}
		f.d[0].relay.mu.Unlock()
		if n := f.deliver(0, 1, kAny); n == 0 || fin == nil {
			t.Fatal("no hs.fin")
		}
		p := f.p(1)
		switch {
		case !withFeatures && p.State != PeerStale:
			f.dump()
			t.Fatal("O3a: not stale")
		case withFeatures && (p.State == PeerStale || !f.audited(1, "hs_fin_dropped")):
			t.Fatal("a peer with features: not acked and dropped")
		}
		if !withFeatures && !f.sink[1].has("connection.stale") {
			t.Fatal("no connection.stale")
		}
		if len(f.m(1).st.DroppedAnswers) != 0 {
			t.Fatal("the record outlived its hs.fin")
		}
		// The lead's call: erased at the first match; the same hs.fin again
		// finds nothing (no record, no outcome).
		before, acts, state := len(f.m(1).st.Audit), len(f.sink[1].got), p.State
		jti := ""
		for _, it := range f.m(1).st.Issued {
			if it.PeerID == f.id[1] && it.Kind == TokStanding && !it.Denied {
				jti = it.JTI
			}
		}
		msg := Message{MsgID: "replayed-fin", Sender: relayauth.EncodeKey(f.pk(0)), JTI: jti, Payload: fin}
		if err := f.m(1).ProcessBatch(context.Background(), &fakeCollector{}, []Message{msg}); err != nil {
			t.Fatal(err)
		}
		for _, a := range f.m(1).st.Audit[before:] {
			if a.Event == "hs_fin_dropped" {
				t.Fatal("a second identical hs.fin found the record")
			}
		}
		for _, a := range f.sink[1].got[acts:] {
			if a.Kind == "connection.stale" {
				t.Fatal("a second identical hs.fin had an outcome")
			}
		}
		if p.State != state || len(f.m(1).st.DroppedAnswers) != 0 {
			t.Fatal("a second identical hs.fin changed the connection")
		}
	}
}
