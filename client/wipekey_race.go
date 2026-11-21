//go:build race

package client

// wipeKey zeroes b one byte at a time: under the race detector, so that a
// read of a key while Close wipes it is reported (the builtin clear is
// not instrumented).
func wipeKey(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
