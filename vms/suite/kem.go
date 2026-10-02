package suite

import (
	"crypto/hpke"
	"sync"
)

var kem = hpke.MLKEM768X25519()

// PublicKey is an MLKEM768X25519 encapsulation key `ek` (§3.2).
type PublicKey struct {
	pk  hpke.PublicKey
	raw []byte
	kid Kid
}

// ParsePublicKey validates and parses a 1,216-byte encapsulation key.
func ParsePublicKey(ek []byte) (*PublicKey, error) {
	if len(ek) != EKSize {
		return nil, ErrKeySize
	}
	pk, err := kem.NewPublicKey(ek)
	if err != nil {
		return nil, ErrBadKey
	}
	raw := pk.Bytes()
	if !Equal(raw, ek) { // reject any non-canonical encoding
		return nil, ErrBadKey
	}
	return &PublicKey{pk: pk, raw: raw, kid: KidOf(raw)}, nil
}

// Bytes returns a copy of the encoded key.
func (p *PublicKey) Bytes() []byte { return append([]byte(nil), p.raw...) }

// Kid returns the key's kid (§4.4).
func (p *PublicKey) Kid() Kid { return p.kid }

// Equal compares two keys in constant time.
func (p *PublicKey) Equal(o *PublicKey) bool {
	if p == nil || o == nil {
		return false
	}
	return Equal(p.raw, o.raw)
}

// PrivateKey is an MLKEM768X25519 decapsulation key, stored as its 32-byte
// seed (§3.2).
type PrivateKey struct {
	Redacted
	mu   sync.RWMutex
	sk   hpke.PrivateKey
	seed []byte
	pub  *PublicKey
}

// NewPrivateKey expands a 32-byte seed into a key pair, as RFC 9180
// DeserializePrivateKey does for MLKEM768X25519 (SHAKE256 expansion).
// The seed is copied.
func NewPrivateKey(seed []byte) (*PrivateKey, error) {
	if len(seed) != SeedSize {
		return nil, ErrKeySize
	}
	sk, err := kem.NewPrivateKey(seed)
	if err != nil {
		return nil, ErrBadKey
	}
	pk, err := ParsePublicKey(sk.PublicKey().Bytes())
	if err != nil {
		return nil, ErrBadKey
	}
	return &PrivateKey{sk: sk, seed: append([]byte(nil), seed...), pub: pk}, nil
}

// GeneratePrivateKey creates a new key pair from a fresh random seed.
func GeneratePrivateKey() (*PrivateKey, error) {
	seed := make([]byte, SeedSize)
	defer Wipe(seed)
	if err := randRead(seed); err != nil {
		return nil, err
	}
	return NewPrivateKey(seed)
}

// Public returns the encapsulation key.
func (k *PrivateKey) Public() *PublicKey { return k.pub }

// Seed returns a copy of the seed, for storage in DEK-encrypted state.
func (k *PrivateKey) Seed() ([]byte, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.seed == nil {
		return nil, ErrDestroyed
	}
	return append([]byte(nil), k.seed...), nil
}

func (k *PrivateKey) hpkeKey() (hpke.PrivateKey, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.sk == nil {
		return nil, ErrDestroyed
	}
	return k.sk, nil
}

// Destroy wipes the seed and drops the expanded key. The expanded key held
// inside crypto/hpke cannot be wiped from here; dropping the reference
// leaves it to the garbage collector.
func (k *PrivateKey) Destroy() {
	k.mu.Lock()
	defer k.mu.Unlock()
	Wipe(k.seed)
	k.seed = nil
	k.sk = nil
}
