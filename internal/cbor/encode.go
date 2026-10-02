package cbor

import "encoding/binary"

// Encoder appends canonical (minimal-length, definite-length) CBOR items.
// Map entries are written in call order; callers that need deterministic
// encoding order them as RFC 8949 §4.2.1 requires.
type Encoder struct {
	buf []byte
}

// Bytes returns the encoding.
func (e *Encoder) Bytes() []byte { return e.buf }

func (e *Encoder) head(major byte, n uint64) *Encoder {
	m := major << 5
	switch {
	case n < 24:
		e.buf = append(e.buf, m|byte(n))
	case n <= 0xff:
		e.buf = append(e.buf, m|24, byte(n))
	case n <= 0xffff:
		e.buf = binary.BigEndian.AppendUint16(append(e.buf, m|25), uint16(n))
	case n <= 0xffffffff:
		e.buf = binary.BigEndian.AppendUint32(append(e.buf, m|26), uint32(n))
	default:
		e.buf = binary.BigEndian.AppendUint64(append(e.buf, m|27), n)
	}
	return e
}

// Uint appends an unsigned integer.
func (e *Encoder) Uint(n uint64) *Encoder { return e.head(0, n) }

// Int appends a signed integer.
func (e *Encoder) Int(n int64) *Encoder {
	if n < 0 {
		return e.head(1, uint64(-1-n))
	}
	return e.head(0, uint64(n))
}

// ByteString appends a byte string.
func (e *Encoder) ByteString(b []byte) *Encoder {
	e.head(2, uint64(len(b)))
	e.buf = append(e.buf, b...)
	return e
}

// Text appends a text string.
func (e *Encoder) Text(s string) *Encoder {
	e.head(3, uint64(len(s)))
	e.buf = append(e.buf, s...)
	return e
}

// Array appends an array header for n items.
func (e *Encoder) Array(n int) *Encoder { return e.head(4, uint64(n)) }

// Map appends a map header for n entries.
func (e *Encoder) Map(n int) *Encoder { return e.head(5, uint64(n)) }

// Tag appends a tag number; the tagged item follows.
func (e *Encoder) Tag(t uint64) *Encoder { return e.head(6, t) }

// Null appends null.
func (e *Encoder) Null() *Encoder { e.buf = append(e.buf, 0xf6); return e }

// Bool appends a boolean.
func (e *Encoder) Bool(b bool) *Encoder {
	if b {
		e.buf = append(e.buf, 0xf5)
	} else {
		e.buf = append(e.buf, 0xf4)
	}
	return e
}

// Raw appends already-encoded CBOR.
func (e *Encoder) Raw(b []byte) *Encoder { e.buf = append(e.buf, b...); return e }
