package peerwire

import "testing"

func TestValidContract(t *testing.T) {
	for _, s := range []string{"1.0", "0.0", "1.10", "9999.9999", "10.0", "0.1"} {
		if !ValidContract(s) {
			t.Errorf("%q refused", s)
		}
	}
	for _, s := range []string{"", "1", "1.", ".0", "01.0", "1.00", "1.01", "10000.0", "1.10000", "1.0.0", "1,0", "-1.0", "+1.0", " 1.0", "1.0 ", "1.a", "١.٠"} {
		if ValidContract(s) {
			t.Errorf("%q taken", s)
		}
	}
}
