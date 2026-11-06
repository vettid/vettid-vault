package vault

import (
	"fmt"
	"testing"
)

// The lead's Opus review of r29-step5 (batch 4): one test per fix.

// H1, §3.4.1 "Fork by ctx": the ancestors are those of the ik the
// message reaches. Q (side 1) has E0 and E1 (signer a, confirmed by P's
// message under it). A copy line of P (holding E0) rotates a→b and
// reconnects naming E0 with the link a→b: Q suspends (ref epoch), with or
// without the copy's identity.rotate first, toward a person and a
// service.
func TestR29ForkByCtxReachedIK(t *testing.T) {
	for _, service := range []bool{false, true} {
		for _, rotateFirst := range []bool{false, true} {
			t.Run(fmt.Sprintf("service=%v,rotateFirst=%v", service, rotateFirst), func(t *testing.T) {
				f := newR29Fx(t)
				f.longTokens()
				if service {
					f.p(1).PeerKind = "service"
				}
				snap := f.snapshot(0) // P's copy line: E0
				f.rekey(1)            // Q begins E1 with P
				f.settle()
				f.note(0, "under-E1") // P sends under E1: Q's confirmed epoch
				f.settle()
				f.startCopy(0, snap)
				f.rotate(2) // the copy line rotates a→b
				if rotateFirst {
					f.deliver(2, 1, kRotate)
				}
				f.lose(2, 1, kAny)
				if !rotateFirst {
					if f.p(1).suspended() {
						t.Fatal("setup: suspended early")
					}
				}
				if !f.p(1).suspended() {
					f.do(2, func(m *Manager, p *Peer) {
						for id, og := range m.st.Outgoing {
							if og.PeerID == p.ID {
								m.abandonOutgoing(id, f.clk)
							}
						}
						m.startReconnect(p, f.clk)
					})
					f.deliver(2, 1, kHSInit)
					f.deliver(1, 2, kHSResp)
					f.deliver(2, 1, kHSFin)
				}
				if !f.suspendedRef(1, "epoch") {
					f.dump()
					t.Fatal("Q did not suspend")
				}
			})
		}
	}
}

// H1 for a rekey: the copy line's rekey from E0 after its rotation a→b
// carries the link (S8); E0 is neither current nor confirmed at Q, and E1
// (signer a) is after it: fork evidence.
func TestR29ForkByCtxReachedIKRekey(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	snap := f.snapshot(0)
	f.rekey(1)
	f.settle()
	f.note(0, "under-E1")
	f.settle()
	f.startCopy(0, snap)
	f.rotate(2) // the copy's rekey from E0, with a→b, is queued
	f.lose(2, 1, kRotate)
	if f.deliver(2, 1, kHSInit) != 1 {
		t.Fatal("setup: no rekey from the copy")
	}
	if !f.suspendedRef(1, "epoch") {
		f.dump()
		t.Fatal("a rekey whose links reach past E1's signer was not fork evidence")
	}
}
