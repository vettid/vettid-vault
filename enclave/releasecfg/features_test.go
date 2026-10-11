package releasecfg_test

import (
	"reflect"
	"testing"

	"github.com/vettid/vettid-vault/enclave/releasecfg"
	"github.com/vettid/vettid-vault/features/all"
)

// The names a channel file may list are exactly the optional features the
// code can register (0.26.0, §11.10.8): features/all cannot import this
// package (vault and feature code never link enclave packages), so each
// keeps the list and this test holds them together. A feature added to
// the code later must be added to both, and is then off in every channel
// until a channel file names it.
func TestOptionalFeaturesMatchTheCode(t *testing.T) {
	if got, want := releasecfg.OptionalFeatures(), all.Optional(); !reflect.DeepEqual(got, want) {
		t.Fatalf("releasecfg lists %v, features/all registers %v", got, want)
	}
	// Each name is the feature package's own Name(), and listing a name
	// registers exactly that feature beside the always-registered ones.
	base := all.NewSet(all.DevOptionsWith(nil)).Names()
	for _, n := range releasecfg.OptionalFeatures() {
		with := all.NewSet(all.DevOptionsWith([]string{n})).Names()
		if len(with) != len(base)+1 {
			t.Fatalf("%s: registered %v", n, with)
		}
		found := false
		for _, w := range with {
			found = found || w == n
		}
		if !found {
			t.Fatalf("listing %s registered %v", n, with)
		}
	}
}
