package envelope

import (
	"time"

	"github.com/vettid/vettid-vault/vms/suite"
)

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// ULIDLen is the length of a ULID string.
const ULIDLen = 26

// ValidULID reports whether s is a canonical ULID: 26 characters of
// upper-case Crockford base32, first character 0-7 (128 bits).
func ValidULID(s string) bool {
	if len(s) != ULIDLen || s[0] > '7' {
		return false
	}
	for i := 0; i < len(s); i++ {
		if crockfordValue(s[i]) < 0 {
			return false
		}
	}
	return true
}

func crockfordValue(c byte) int {
	for i := 0; i < len(crockford); i++ {
		if crockford[i] == c {
			return i
		}
	}
	return -1
}

// NewULID returns a ULID for time t: 48 bits of milliseconds and 80 bits
// from the library's randomness source.
func NewULID(t time.Time) (string, error) {
	var b [16]byte
	ms := uint64(t.UnixMilli())
	for i := 0; i < 6; i++ {
		b[i] = byte(ms >> (40 - 8*i))
	}
	r, err := suite.RandomBytes(10)
	if err != nil {
		return "", err
	}
	copy(b[6:], r)
	return encodeULID(b), nil
}

func encodeULID(b [16]byte) string {
	// 128 bits -> 26 base32 characters, 2 leading zero bits.
	out := make([]byte, ULIDLen)
	var acc uint64
	var hi uint64 = uint64(b[0])<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 | uint64(b[3])<<32 |
		uint64(b[4])<<24 | uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7])
	var lo uint64 = uint64(b[8])<<56 | uint64(b[9])<<48 | uint64(b[10])<<40 | uint64(b[11])<<32 |
		uint64(b[12])<<24 | uint64(b[13])<<16 | uint64(b[14])<<8 | uint64(b[15])
	for i := ULIDLen - 1; i >= 0; i-- {
		acc = lo & 31
		out[i] = crockford[acc]
		lo = lo>>5 | hi<<59
		hi >>= 5
	}
	return string(out)
}
