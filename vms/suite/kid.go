package suite

import (
	"crypto/subtle"
	"encoding/hex"
)

// Kid is an 8-byte key id (§4.4). Kids are lookup hints, not
// authenticators.
type Kid [KidSize]byte

// Anonymous is the all-zero kid of an anonymous sender.
var Anonymous Kid

// KidOf returns the kid of a static KEM key or ETK:
// SHA-256("vettid/vms/2/kid" || ek)[0:8].
func KidOf(ek []byte) Kid {
	h := LabeledHash(LabelKid, ek)
	var k Kid
	copy(k[:], h[:KidSize])
	return k
}

// Equal compares two kids in constant time.
func (k Kid) Equal(o Kid) bool { return subtle.ConstantTimeCompare(k[:], o[:]) == 1 }

// IsAnonymous reports whether k is the all-zero kid.
func (k Kid) IsAnonymous() bool { return k.Equal(Anonymous) }

// String returns the lowercase hex form.
func (k Kid) String() string { return hex.EncodeToString(k[:]) }

// ParseKidHex parses a 16-character lowercase hex kid.
func ParseKidHex(s string) (Kid, error) {
	var k Kid
	if len(s) != 2*KidSize {
		return k, ErrBadKey
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return k, ErrBadKey
		}
	}
	if _, err := hex.Decode(k[:], []byte(s)); err != nil {
		return k, ErrBadKey
	}
	return k, nil
}
