//go:build !vmsvectors

package suite

import "crypto/rand"

// randRead fills b from the operating system CSPRNG. Release builds have
// no way to substitute another source: deterministic randomness exists
// only in builds with the `vmsvectors` tag (rand_vectors.go).
func randRead(b []byte) error {
	if _, err := rand.Read(b); err != nil {
		return ErrRandom
	}
	return nil
}

func newSender(pk *PublicKey, info []byte) ([]byte, hpkeSender, error) {
	return stdlibSender(pk, info)
}

// VectorBuild reports whether this is a `vmsvectors` build.
const VectorBuild = false
