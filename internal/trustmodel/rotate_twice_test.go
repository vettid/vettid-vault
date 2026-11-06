package trustmodel

import (
	"os"
	"strings"
	"testing"
)

// rotateTwiceMissFirst: Q rotates its ik twice; P misses the first
// identity.rotate. Release 29 (S8): the second statement, and every rekey
// under the old epoch, carry the chain since the epoch's signer, so P
// follows both links. Release 28 reads only `rotation` (core.go:573) and
// a rekey must carry the stored ik (responder.go:283): stuck.
func rotateTwiceMissFirst(t *testing.T, cfg Config) (ok bool, pIK, qIK Key, w *World) {
	cfg.Vaults = 2
	w = setup(cfg, 1)
	s := &scen{t, w}
	P, Q := s.p(0), s.p(1)
	s.rotate(Q, pathCred)
	if s.dropAt(P, KIdRot) == 0 {
		t.Fatalf("no identity.rotate to lose")
	}
	s.rotate(Q, pathCred)
	for d := 0; d < 60; d++ {
		s.drain(P, Q)
		s.tick(day)
		for _, x := range []*Party{P, Q} {
			x.tick()
		}
	}
	s.drain(P, Q)
	w.checkEnd(true)
	if os.Getenv("TRUSTMODEL_TRACE") != "" {
		t.Log("trace:\n  " + strings.Join(w.log, "\n  "))
	}
	r := P.st.peer(Q.ID)
	return r.IK == Q.st.IK && r.Status == stActive, r.IK, Q.st.IK, w
}

func TestRotateTwicePeerMissesFirst(t *testing.T) {
	for _, c := range []struct {
		name string
		cfg  Config
		must bool // must recover
	}{
		{"29<>29", Config{}, true},
		{"29<>29 no relay rotation", Config{NoRelayRot: true}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			ok, pik, qik, w := rotateTwiceMissFirst(t, c.cfg)
			var vs []string
			for _, v := range w.viol {
				vs = append(vs, v.Inv+": "+v.Detail)
			}
			t.Logf("%s: recovered %v (P holds %d for Q, Q at %d); violations %v", c.name, ok, pik, qik, vs)
			if c.must && (!ok || len(w.viol) > 0) {
				t.Errorf("did not recover")
			}
		})
	}
}
