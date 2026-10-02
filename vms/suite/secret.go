package suite

import (
	"crypto/subtle"
	"fmt"
	"runtime"
)

// Wipe overwrites b with zeros. Go cannot guarantee that no other copy of
// a secret exists (the garbage collector may have moved it, and the
// standard library keeps its own copies inside crypto/hpke and
// crypto/ed25519 values), so this is best-effort hygiene that shortens the
// lifetime of the copies this module controls.
func Wipe(b []byte) {
	clear(b)
	runtime.KeepAlive(b)
}

// Equal compares two byte strings in constant time (for equal lengths).
// Use it for every tag, key, hash commitment and kid comparison (§13.6).
func Equal(a, b []byte) bool { return subtle.ConstantTimeCompare(a, b) == 1 }

// Redacted is embedded in types that hold secrets so that fmt never prints
// their contents.
type Redacted struct{}

// Format implements fmt.Formatter.
func (Redacted) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte("[redacted]")) }
