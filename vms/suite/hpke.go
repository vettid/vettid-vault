package suite

import (
	"crypto/hpke"
	"sync/atomic"
)

// hpkeSender is the subset of *hpke.Sender used here. The vector build
// substitutes a derandomized implementation (rand_vectors.go).
type hpkeSender interface {
	Seal(aad, plaintext []byte) ([]byte, error)
	Export(exporterContext string, length int) ([]byte, error)
}

// Exporter derives secrets from an HPKE context (RFC 9180 Export).
type Exporter interface {
	Export(label string, length int) ([]byte, error)
}

// Sender is a suite 2 HPKE sending context (SetupBaseS). It seals exactly
// one message (§4.3: a context MUST NOT be reused for a second message),
// and may Export any number of secrets.
type Sender struct {
	s    hpkeSender
	used atomic.Bool
}

// SetupSender runs SetupBaseS(pk_R = ek, info) and returns the
// encapsulated key (1,120 bytes) and the context.
func SetupSender(pk *PublicKey, info string) ([]byte, *Sender, error) {
	if pk == nil {
		return nil, nil, ErrBadKey
	}
	enc, s, err := newSender(pk, []byte(info))
	if err != nil {
		return nil, nil, ErrBadKey
	}
	if len(enc) != EncSize {
		return nil, nil, ErrKeySize
	}
	return enc, &Sender{s: s}, nil
}

// Seal encrypts the context's single message.
func (s *Sender) Seal(aad, plaintext []byte) ([]byte, error) {
	if !s.used.CompareAndSwap(false, true) {
		return nil, ErrContextUsed
	}
	return s.s.Seal(aad, plaintext)
}

// Export derives a secret (RFC 9180 §5.3).
func (s *Sender) Export(label string, length int) ([]byte, error) {
	return s.s.Export(label, length)
}

// Recipient is a suite 2 HPKE receiving context (SetupBaseR). It opens
// exactly one message.
type Recipient struct {
	r    *hpke.Recipient
	used atomic.Bool
}

// SetupRecipient runs SetupBaseR(enc, sk_R, info).
func SetupRecipient(enc []byte, sk *PrivateKey, info string) (*Recipient, error) {
	if len(enc) != EncSize {
		return nil, ErrKeySize
	}
	if sk == nil {
		return nil, ErrBadKey
	}
	k, err := sk.hpkeKey()
	if err != nil {
		return nil, err
	}
	r, err := hpke.NewRecipient(enc, k, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), []byte(info))
	if err != nil {
		return nil, ErrDecrypt
	}
	return &Recipient{r: r}, nil
}

// Open decrypts the context's single message.
func (r *Recipient) Open(aad, ciphertext []byte) ([]byte, error) {
	if !r.used.CompareAndSwap(false, true) {
		return nil, ErrContextUsed
	}
	pt, err := r.r.Open(aad, ciphertext)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

// Export derives a secret (RFC 9180 §5.3).
func (r *Recipient) Export(label string, length int) ([]byte, error) {
	return r.r.Export(label, length)
}

func stdlibSender(pk *PublicKey, info []byte) ([]byte, hpkeSender, error) {
	return hpke.NewSender(pk.pk, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), info)
}
