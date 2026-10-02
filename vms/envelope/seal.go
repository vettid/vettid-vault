package envelope

import (
	"github.com/vettid/vettid-vault/vms/suite"
)

// SealSession builds a session-mode envelope (§5.2): a fresh random 192-bit
// nonce, and XChaCha20-Poly1305 under the epoch's directional key with the
// 44-byte header as AAD. padded must be a padded inner plaintext.
func SealSession(key []byte, senderKid, recipientKid suite.Kid, padded []byte) ([]byte, error) {
	if !ValidPaddedLen(len(padded)) {
		return nil, ErrLength
	}
	nonce, err := suite.NewNonce()
	if err != nil {
		return nil, err
	}
	h := header(ModeSession, senderKid, recipientKid, nonce)
	ct, err := suite.SealX(key, nonce, h, padded)
	if err != nil {
		return nil, err
	}
	return append(h, ct...), nil
}

// OpenSession decrypts a session-mode envelope and returns the padded inner
// plaintext. Kid routing is the caller's job (see handshake.Epoch).
func OpenSession(e *Envelope, key []byte) ([]byte, error) {
	if e.mode != ModeSession {
		return nil, ErrWrongMode
	}
	pt, err := suite.OpenX(key, e.body(), e.raw[:HeaderSession], e.ciphertext())
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

// Sealer builds one sealed-mode envelope in two steps, so that a caller can
// see the header (and Export from the HPKE context) before sealing; the
// handshake needs th, which covers hs.resp's header, inside hs.resp's own
// plaintext (§6.3).
type Sealer struct {
	header []byte
	ctx    *suite.Sender
}

// NewSealer runs SetupBaseS(ek_R, info = "vettid/vms/2/sealed") (§4.3) and
// fixes the header: recipient_kid is the kid of ek_R.
func NewSealer(recipient *suite.PublicKey, senderKid suite.Kid) (*Sealer, error) {
	enc, ctx, err := suite.SetupSender(recipient, suite.InfoSealed)
	if err != nil {
		return nil, err
	}
	return &Sealer{header: header(ModeSealed, senderKid, recipient.Kid(), enc), ctx: ctx}, nil
}

// Header returns a copy of the 1,140-byte header (the AAD).
func (s *Sealer) Header() []byte { return append([]byte(nil), s.header...) }

// Export derives a secret from the HPKE context (§4.3, §6.3).
func (s *Sealer) Export(label string, n int) ([]byte, error) { return s.ctx.Export(label, n) }

// Seal encrypts the padded inner plaintext and returns the envelope. It may
// be called once.
func (s *Sealer) Seal(padded []byte) ([]byte, error) {
	if !ValidPaddedLen(len(padded)) {
		return nil, ErrLength
	}
	ct, err := s.ctx.Seal(s.header, padded)
	if err != nil {
		return nil, err
	}
	return append(append([]byte(nil), s.header...), ct...), nil
}

// SealSealed is NewSealer followed by Seal.
func SealSealed(recipient *suite.PublicKey, senderKid suite.Kid, padded []byte) ([]byte, suite.Exporter, error) {
	s, err := NewSealer(recipient, senderKid)
	if err != nil {
		return nil, nil, err
	}
	env, err := s.Seal(padded)
	if err != nil {
		return nil, nil, err
	}
	return env, s.ctx, nil
}

// OpenSealed decrypts a sealed-mode envelope with the recipient's private
// key. The envelope's recipient_kid must be the key's kid: the caller
// selects the key by kid, and no other key is ever tried (§4.4).
func OpenSealed(e *Envelope, sk *suite.PrivateKey) ([]byte, suite.Exporter, error) {
	if e.mode != ModeSealed {
		return nil, nil, ErrWrongMode
	}
	if sk == nil || !e.recipientKid.Equal(sk.Public().Kid()) {
		return nil, nil, ErrKid
	}
	r, err := suite.SetupRecipient(e.body(), sk, suite.InfoSealed)
	if err != nil {
		return nil, nil, ErrDecrypt
	}
	pt, err := r.Open(e.raw[:HeaderSealed], e.ciphertext())
	if err != nil {
		return nil, nil, ErrDecrypt
	}
	return pt, r, nil
}
