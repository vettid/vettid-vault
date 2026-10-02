// Package hpkederand is a derandomized HPKE (RFC 9180) base-mode sender for
// suite 2: KEM MLKEM768X25519 (0x647a), KDF HKDF-SHA256 (0x0001), AEAD
// ChaCha20-Poly1305 (0x0003).
//
// It exists ONLY to generate and check known-answer test vectors. The
// library's normal sealing path uses crypto/hpke with real randomness;
// this package is reachable from library code only in builds with the
// `vmsvectors` build tag. It is an independent implementation of the KEM
// combiner and key schedule, so every vector it produces is cross-checked
// by opening it with crypto/hpke.
//
// Encapsulation randomness is 64 bytes, split as in
// draft-connolly-cfrg-xwing-kem EncapsulateDerand: randomness[0:32] is the
// ML-KEM-768 message m, randomness[32:64] is the X25519 ephemeral secret.
package hpkederand

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/mlkem/mlkemtest"
	"crypto/sha256"
	"crypto/sha3"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	kemID  = 0x647a
	kdfID  = 0x0001
	aeadID = 0x0003

	// RandomnessSize is the encapsulation randomness length.
	RandomnessSize = 64

	pqEKSize = mlkem.EncapsulationKeySize768 // 1184
	xSize    = 32
)

// xwingLabel is the X-Wing combiner label, the ASCII art `\./` `/^\`.
var xwingLabel = []byte{0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c}

// Values are the intermediate values of one sender setup, for vectors.
type Values struct {
	Enc            []byte
	SharedSecret   []byte
	Key            []byte
	BaseNonce      []byte
	ExporterSecret []byte
}

// Sender is a derandomized HPKE sending context.
type Sender struct {
	v   Values
	seq uint64
}

// NewSender runs SetupBaseS(pk = ek, info) with the given encapsulation
// randomness.
func NewSender(ek, info, randomness []byte) (*Sender, error) {
	if len(ek) != pqEKSize+xSize {
		return nil, errors.New("hpkederand: bad encapsulation key size")
	}
	if len(randomness) != RandomnessSize {
		return nil, errors.New("hpkederand: randomness must be 64 bytes")
	}
	pq, err := mlkem.NewEncapsulationKey768(ek[:pqEKSize])
	if err != nil {
		return nil, errors.New("hpkederand: bad ML-KEM key")
	}
	pkT, err := ecdh.X25519().NewPublicKey(ek[pqEKSize:])
	if err != nil {
		return nil, errors.New("hpkederand: bad X25519 key")
	}
	ssPQ, ctPQ, err := mlkemtest.Encapsulate768(pq, randomness[:32])
	if err != nil {
		return nil, err
	}
	skE, err := ecdh.X25519().NewPrivateKey(randomness[32:64])
	if err != nil {
		return nil, err
	}
	ssT, err := skE.ECDH(pkT)
	if err != nil {
		return nil, err
	}
	ctT := skE.PublicKey().Bytes()

	h := sha3.New256()
	h.Write(ssPQ)
	h.Write(ssT)
	h.Write(ctT)
	h.Write(pkT.Bytes())
	h.Write(xwingLabel)
	ss := h.Sum(nil)

	enc := append(append([]byte{}, ctPQ...), ctT...)
	s := &Sender{v: Values{Enc: enc, SharedSecret: ss}}
	if err := s.keySchedule(info); err != nil {
		return nil, err
	}
	return s, nil
}

func suiteID() []byte {
	b := []byte("HPKE")
	b = binary.BigEndian.AppendUint16(b, kemID)
	b = binary.BigEndian.AppendUint16(b, kdfID)
	b = binary.BigEndian.AppendUint16(b, aeadID)
	return b
}

func labeledExtract(salt []byte, label string, ikm []byte) ([]byte, error) {
	in := append([]byte("HPKE-v1"), suiteID()...)
	in = append(in, label...)
	in = append(in, ikm...)
	return hkdf.Extract(sha256.New, in, salt)
}

func labeledExpand(prk []byte, label string, info []byte, l int) ([]byte, error) {
	in := binary.BigEndian.AppendUint16(nil, uint16(l))
	in = append(in, "HPKE-v1"...)
	in = append(in, suiteID()...)
	in = append(in, label...)
	in = append(in, info...)
	return hkdf.Expand(sha256.New, prk, string(in), l)
}

func (s *Sender) keySchedule(info []byte) error {
	pskIDHash, err := labeledExtract(nil, "psk_id_hash", nil)
	if err != nil {
		return err
	}
	infoHash, err := labeledExtract(nil, "info_hash", info)
	if err != nil {
		return err
	}
	ksc := append([]byte{0x00}, pskIDHash...) // mode_base
	ksc = append(ksc, infoHash...)
	secret, err := labeledExtract(s.v.SharedSecret, "secret", nil)
	if err != nil {
		return err
	}
	if s.v.Key, err = labeledExpand(secret, "key", ksc, chacha20poly1305.KeySize); err != nil {
		return err
	}
	if s.v.BaseNonce, err = labeledExpand(secret, "base_nonce", ksc, chacha20poly1305.NonceSize); err != nil {
		return err
	}
	s.v.ExporterSecret, err = labeledExpand(secret, "exp", ksc, sha256.Size)
	return err
}

// Values returns copies of the intermediate values.
func (s *Sender) Values() Values {
	c := func(b []byte) []byte { return append([]byte(nil), b...) }
	return Values{c(s.v.Enc), c(s.v.SharedSecret), c(s.v.Key), c(s.v.BaseNonce), c(s.v.ExporterSecret)}
}

// Enc returns the encapsulated key.
func (s *Sender) Enc() []byte { return append([]byte(nil), s.v.Enc...) }

// Seal encrypts the next message.
func (s *Sender) Seal(aad, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(s.v.Key)
	if err != nil {
		return nil, err
	}
	nonce := append([]byte(nil), s.v.BaseNonce...)
	var seq [8]byte
	binary.BigEndian.PutUint64(seq[:], s.seq)
	for i := range seq {
		nonce[len(nonce)-8+i] ^= seq[i]
	}
	s.seq++
	return aead.Seal(nil, nonce, plaintext, aad), nil
}

// Export derives an exporter secret.
func (s *Sender) Export(exporterContext string, length int) ([]byte, error) {
	if length < 0 || length > 0xffff {
		return nil, errors.New("hpkederand: bad export length")
	}
	return labeledExpand(s.v.ExporterSecret, "sec", []byte(exporterContext), length)
}
