package vault

import (
	"bytes"
	"testing"

	"github.com/vettid/vettid-vault/vms/handshake"
)

// peekResp tries an earlier key's hs.resp on a copy of the handshake: the
// state it exported is wiped and the copy is ended, whether the answer
// opens or not; the handshake itself is kept.
func TestPeekRespWipesItsCopy(t *testing.T) {
	for _, junk := range []bool{false, true} {
		f := newR29Fx(t)
		f.longTokens()
		f.rekey(0)
		if f.deliver(0, 1, kHSInit) != 1 {
			t.Fatal("setup: no rekey hs.init")
		}
		resp := f.rkTake(kHSResp, rkAfter)
		if junk {
			resp.Payload = append([]byte(nil), resp.Payload...)
			resp.Payload[len(resp.Payload)-1] ^= 1 // the tag: it no longer opens
		}
		f.rkFollow()
		var st handshake.InitiatorState
		var c *handshake.Initiator
		peeks := 0
		testPeekHook = func(s handshake.InitiatorState, i *handshake.Initiator) { st, c, peeks = s, i, peeks+1 }
		f.process(0, resp)
		testPeekHook = nil
		if peeks != 1 {
			t.Fatalf("junk=%v: %d peeks", junk, peeks)
		}
		for _, b := range [][]byte{st.EphSeed, st.Ks, st.Body} {
			if len(b) == 0 || bytes.Count(b, []byte{0}) != len(b) {
				t.Fatalf("junk=%v: the exported state kept a secret", junk)
			}
		}
		if !c.Done() {
			t.Fatalf("junk=%v: the copy was not ended", junk)
		}
		if f.superseded() != 1 || len(f.m(0).st.Outgoing) == 0 {
			t.Fatalf("junk=%v: not refused with the handshake kept", junk)
		}
	}
}
