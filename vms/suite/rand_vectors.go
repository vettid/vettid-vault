//go:build vmsvectors

package suite

import (
	"crypto/rand"
	"io"
	"sync"

	"github.com/vettid/vettid-vault/internal/hpkederand"
)

// This file exists only in builds with the `vmsvectors` tag, which are used
// to generate and check the §16 test vectors. It lets a test substitute a
// deterministic randomness source for every random value the library draws:
// key seeds, nonces, ULID entropy and HPKE encapsulation randomness.
// NEVER build a release with this tag.

// VectorBuild reports whether this is a `vmsvectors` build.
const VectorBuild = true

var (
	vecMu     sync.Mutex
	vecReader io.Reader
	vecLast   *hpkederand.Sender
)

// SetVectorRandomness makes every random draw come from r until the
// returned restore function is called. TEST VECTORS ONLY.
func SetVectorRandomness(r io.Reader) (restore func()) {
	vecMu.Lock()
	prev := vecReader
	vecReader = r
	vecMu.Unlock()
	return func() {
		vecMu.Lock()
		vecReader = prev
		vecMu.Unlock()
	}
}

// LastSenderValues returns the HPKE intermediate values of the most recent
// derandomized SetupSender. TEST VECTORS ONLY.
func LastSenderValues() (hpkederand.Values, bool) {
	vecMu.Lock()
	defer vecMu.Unlock()
	if vecLast == nil {
		return hpkederand.Values{}, false
	}
	return vecLast.Values(), true
}

func randRead(b []byte) error {
	vecMu.Lock()
	r := vecReader
	vecMu.Unlock()
	if r == nil {
		r = rand.Reader
	}
	if _, err := io.ReadFull(r, b); err != nil {
		return ErrRandom
	}
	return nil
}

func newSender(pk *PublicKey, info []byte) ([]byte, hpkeSender, error) {
	vecMu.Lock()
	r := vecReader
	vecMu.Unlock()
	if r == nil {
		return stdlibSender(pk, info)
	}
	rnd := make([]byte, hpkederand.RandomnessSize)
	if _, err := io.ReadFull(r, rnd); err != nil {
		return nil, nil, ErrRandom
	}
	s, err := hpkederand.NewSender(pk.raw, info, rnd)
	if err != nil {
		return nil, nil, err
	}
	vecMu.Lock()
	vecLast = s
	vecMu.Unlock()
	return s.Enc(), s, nil
}
