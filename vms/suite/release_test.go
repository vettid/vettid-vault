//go:build !vmsvectors

package suite

import "testing"

// Deterministic randomness exists only in vmsvectors builds (compile-time
// exclusion, in the spirit of §13.6 "Dev mode"); a default build draws from
// crypto/rand and seals with crypto/hpke.
func TestReleaseBuildHasNoVectorHooks(t *testing.T) {
	if VectorBuild {
		t.Fatal("vector build in a default test run")
	}
	a, _ := RandomBytes(32)
	b, _ := RandomBytes(32)
	if Equal(a, b) {
		t.Fatal("randomness repeats")
	}
	k, _ := NewPrivateKey(seed(5))
	e1, _, _ := SetupSender(k.Public(), InfoSealed)
	e2, _, _ := SetupSender(k.Public(), InfoSealed)
	if Equal(e1, e2) {
		t.Fatal("encapsulation is deterministic")
	}
}
