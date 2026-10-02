package envelope

import "crypto/subtle"

// PaddedLen returns the padded length for a JSON inner plaintext of n
// bytes (§5.4): json || 0x80 || 0x00*, padded to the next multiple of 512
// up to 16 KiB and above that to the next multiple of 16 KiB. It returns
// ErrTooLarge above MaxPadded (§5.5).
func PaddedLen(n int) (int, error) {
	if n < 0 {
		return 0, ErrLength
	}
	m := n + 1 // the 0x80 marker
	var p int
	if m <= SmallBucketLimit {
		p = (m + MinPadded - 1) / MinPadded * MinPadded
	} else {
		p = (m + SmallBucketLimit - 1) / SmallBucketLimit * SmallBucketLimit
	}
	if p > MaxPadded {
		return 0, ErrTooLarge
	}
	return p, nil
}

// ValidPaddedLen reports whether p is a padded size some JSON length maps
// to: a multiple of 512 in [512, 16384] or of 16384 in (16384, 245760].
func ValidPaddedLen(p int) bool {
	switch {
	case p < MinPadded || p > MaxPadded:
		return false
	case p <= SmallBucketLimit:
		return p%MinPadded == 0
	default:
		return p%SmallBucketLimit == 0
	}
}

// Pad pads a JSON inner plaintext to its bucket.
func Pad(json []byte) ([]byte, error) {
	p, err := PaddedLen(len(json))
	if err != nil {
		return nil, err
	}
	return padTo(json, p), nil
}

// PadFixed pads to exactly n bytes, which must be a valid padded size large
// enough for the JSON. The alternate channel uses n = AltChannelPadded.
func PadFixed(json []byte, n int) ([]byte, error) {
	if !ValidPaddedLen(n) {
		return nil, ErrLength
	}
	if len(json)+1 > n {
		return nil, ErrTooLarge
	}
	return padTo(json, n), nil
}

func padTo(json []byte, n int) []byte {
	out := make([]byte, n)
	copy(out, json)
	out[len(json)] = 0x80
	return out
}

// Unpad strictly removes bucket padding: the input must be a valid padded
// size, end in 0x80 followed only by zeros, and have exactly the length
// PaddedLen gives for the remaining JSON (no over-padding).
func Unpad(padded []byte) ([]byte, error) {
	json, err := unpad(padded)
	if err != nil {
		return nil, err
	}
	if p, err := PaddedLen(len(json)); err != nil || p != len(padded) {
		return nil, ErrPadding
	}
	return json, nil
}

// UnpadFixed strictly removes fixed-size padding of exactly n bytes.
func UnpadFixed(padded []byte, n int) ([]byte, error) {
	if len(padded) != n {
		return nil, ErrPadding
	}
	return unpad(padded)
}

// unpad finds the 0x80 marker scanning the whole buffer, without
// data-dependent early exit, so the time taken does not depend on where
// the plaintext ends.
func unpad(padded []byte) ([]byte, error) {
	if !ValidPaddedLen(len(padded)) {
		return nil, ErrPadding
	}
	marker := -1
	trailingZero := 1 // still inside the trailing run of zeros
	for i := len(padded) - 1; i >= 0; i-- {
		b := int(padded[i])
		isZero := subtle.ConstantTimeByteEq(byte(b), 0)
		isMarker := subtle.ConstantTimeByteEq(byte(b), 0x80)
		// The first non-zero byte from the end must be the marker.
		first := trailingZero & (1 ^ isZero)
		marker = subtle.ConstantTimeSelect(first&isMarker, i, marker)
		bad := first & (1 ^ isMarker)
		marker = subtle.ConstantTimeSelect(bad, -2, marker)
		trailingZero &= isZero
	}
	if marker < 0 {
		return nil, ErrPadding
	}
	return padded[:marker], nil
}
