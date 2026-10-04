package supervisor

import "testing"

// The self-test accepts RELAY-PROTOCOL 0.4.0 and every later 0.x (minor
// versions are additive), nothing older and nothing malformed.
func TestRelayProtocolOK(t *testing.T) {
	for v, want := range map[string]bool{
		"0.4.0": true, "0.5.0": true, "0.5.1": true, "0.12.0": true,
		"0.3.0": false, "1.0.0": false, "": false, "0.5": false, "0.05.0": false, "0.x.0": false, "0.5.0-rc1": false,
	} {
		if got := RelayProtocolOK(v); got != want {
			t.Errorf("%q: %v, want %v", v, got, want)
		}
	}
}
