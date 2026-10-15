package envelope

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/bits"

	"github.com/vettid/vettid-vault/vms/suite"
)

// Claim-check blobs (§5.5; 0.32.0, release A: versioned and padded):
//
//	blob   = ver (1: 0x01) || nonce (24) || XChaCha20-Poly1305(key, nonce, aad, framed)
//	aad    = "vettid/vms/2/blob" || 0x00 || ver
//	framed = uint32be(len(content)) || content || 0x00 * (Padme(4 + len(content)) - 4 - len(content))
//	sha256 = SHA-256(blob)    // checked in constant time before decryption
//	size   = len(content)     // checked against the framed length after
//
// The blob is BlobOverhead + Padme(4 + len(content)) bytes. The at-rest
// attachment objects of §10.5.1 use the same framing (vms/attwire).

// BlobDecision says how content of a given size must travel.
type BlobDecision int

const (
	// Inline: send in the envelope.
	Inline BlobDecision = iota
	// BlobRecommended: over 64 KiB; the blob flow SHOULD be used.
	BlobRecommended
	// BlobRequired: would not fit in an envelope; the blob flow MUST be used.
	BlobRequired
)

// DecideBlob classifies content of n bytes whose inner plaintext JSON (with
// the content embedded) would be jsonLen bytes.
func DecideBlob(n, jsonLen int) BlobDecision {
	if _, err := PaddedLen(jsonLen); err != nil {
		return BlobRequired
	}
	if n > BlobThreshold {
		return BlobRecommended
	}
	return Inline
}

// BlobVersion is the blob layout's version byte (§5.5).
const BlobVersion byte = 0x01

// BlobOverhead is what a blob adds to its framed plaintext: the version
// byte, the nonce and the tag.
const BlobOverhead = 1 + suite.XNonceSize + suite.TagSize

// FrameHeader is the length prefix of a framed plaintext.
const FrameHeader = 4

// Blob errors. A receiver learns only that a blob is unusable; the
// distinctions are for tests and audit.
var (
	ErrBlobHash    = errors.New("envelope: blob sha256 mismatch")
	ErrBlobVersion = errors.New("envelope: unknown blob version")
	ErrBlobFrame   = errors.New("envelope: malformed blob framing")
	ErrBlobSize    = errors.New("envelope: blob content size mismatch")
)

// Padme is Padmé padding (Nikitin et al., 2019) for a length L ≥ 2:
// E = floor(log2 L); S = floor(log2 E) + 1; z = E - S; L rounded up to a
// multiple of 2^z. It returns 0 for L < 2, where it is undefined.
func Padme(l int) int {
	if l < 2 {
		return 0
	}
	e := bits.Len(uint(l)) - 1
	s := bits.Len(uint(e))
	z := e - s
	mask := (1 << z) - 1
	return (l + mask) &^ mask
}

// FramedLen is the framed plaintext's length for content of n bytes.
func FramedLen(n int) int { return Padme(FrameHeader + n) }

// BlobLen is the length of the blob (or at-rest object) for content of n
// bytes: BlobOverhead + Padme(4 + n).
func BlobLen(n int) int { return BlobOverhead + FramedLen(n) }

// MaxBlobContent is the largest content whose blob fits maxBlob bytes (the
// relay's max_blob_bytes): attachment_max_bytes (§10.5.1), 8,257,532 for
// 8,388,608. 0 if none fits.
func MaxBlobContent(maxBlob int) int {
	if maxBlob < BlobLen(1) {
		return 0
	}
	// BlobLen is monotonic: binary search the largest n with BlobLen(n) ≤ max.
	lo, hi := 1, maxBlob
	for lo < hi {
		mid := lo + (hi-lo+1)/2
		if BlobLen(mid) <= maxBlob {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	return lo
}

// Frame returns content framed and padded (§5.5). content must be at least
// one byte.
func Frame(content []byte) ([]byte, error) {
	if len(content) == 0 || len(content) > 1<<31 {
		return nil, ErrBlobFrame
	}
	out := make([]byte, FramedLen(len(content)))
	binary.BigEndian.PutUint32(out, uint32(len(content)))
	copy(out[FrameHeader:], content)
	return out, nil
}

// Unframe checks a framed plaintext (its length exactly Padme(4 + len), len
// within it, the padding all zero) and returns the content, a sub-slice of
// framed.
func Unframe(framed []byte) ([]byte, error) {
	if len(framed) < FrameHeader+1 {
		return nil, ErrBlobFrame
	}
	n := binary.BigEndian.Uint32(framed)
	if n == 0 || uint64(n) > uint64(len(framed)-FrameHeader) {
		return nil, ErrBlobFrame
	}
	if FramedLen(int(n)) != len(framed) {
		return nil, ErrBlobFrame
	}
	var acc byte
	for _, b := range framed[FrameHeader+int(n):] {
		acc |= b
	}
	if acc != 0 {
		return nil, ErrBlobFrame
	}
	return framed[FrameHeader : FrameHeader+int(n)], nil
}

func blobAAD(ver byte) []byte { return append([]byte(suite.LabelBlob+"\x00"), ver) }

// SealFramed seals content as ver || nonce || XChaCha20-Poly1305(key, nonce,
// aad, framed), the layout shared by blobs and at-rest objects. The nonce
// is drawn from the library's randomness source.
func SealFramed(key, aad, content []byte) ([]byte, error) {
	framed, err := Frame(content)
	if err != nil {
		return nil, err
	}
	defer suite.Wipe(framed)
	nonce, err := suite.NewNonce()
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, BlobOverhead+len(framed))
	out = append(out, BlobVersion)
	out = append(out, nonce...)
	return suite.SealXTo(out, key, nonce, aad, framed)
}

// OpenFramed opens SealFramed's layout: the version byte must be known
// (the caller's aad ends with it), then the AEAD, then the framing. It
// returns the content (a fresh slice the caller may wipe).
func OpenFramed(key, aad, obj []byte) ([]byte, error) {
	if len(obj) < BlobOverhead+FrameHeader+1 {
		return nil, ErrBlobFrame
	}
	if obj[0] != BlobVersion {
		return nil, ErrBlobVersion
	}
	framed, err := suite.OpenX(key, obj[1:1+suite.XNonceSize], aad, obj[1+suite.XNonceSize:])
	if err != nil {
		return nil, ErrDecrypt
	}
	content, err := Unframe(framed)
	if err != nil {
		suite.Wipe(framed)
		return nil, err
	}
	return content, nil
}

// SealBlob encrypts content under a fresh key (§5.5). It returns the blob
// to upload, the key, and SHA-256(blob). A key is used for one blob only.
func SealBlob(content []byte) (blob, key []byte, sum [32]byte, err error) {
	key, err = suite.RandomBytes(suite.KeySize)
	if err != nil {
		return nil, nil, sum, err
	}
	blob, err = SealBlobWithKey(key, content)
	if err != nil {
		return nil, nil, sum, err
	}
	return blob, key, sha256.Sum256(blob), nil
}

// SealBlobWithKey seals content under key (vectors and tests; the key must
// be fresh, SealBlob draws one).
func SealBlobWithKey(key, content []byte) ([]byte, error) {
	return SealFramed(key, blobAAD(BlobVersion), content)
}

// OpenBlob checks SHA-256(blob) against sum in constant time, then the
// version byte, decrypts and checks the framing, and finally that the
// content is size bytes (size < 0: not checked). A receiver MUST reject a
// blob that fails any of these (§5.5).
func OpenBlob(blob, key []byte, sum [32]byte, size int) ([]byte, error) {
	got := sha256.Sum256(blob)
	if !suite.Equal(got[:], sum[:]) {
		return nil, ErrBlobHash
	}
	if len(blob) == 0 {
		return nil, ErrBlobFrame
	}
	content, err := OpenFramed(key, blobAAD(blob[0]), blob)
	if err != nil {
		return nil, err
	}
	if size >= 0 && len(content) != size {
		suite.Wipe(content)
		return nil, ErrBlobSize
	}
	return content, nil
}
