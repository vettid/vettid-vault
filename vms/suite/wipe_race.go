//go:build race

package suite

// wipe zeroes b one byte at a time under the race detector, which does not
// see the builtin clear: a read of a secret while it is wiped is reported.
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
