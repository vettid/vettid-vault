//go:build !race

package suite

func wipe(b []byte) { clear(b) }
