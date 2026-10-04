package enclavetest

// PrimitiveConstructedVariants returns copies of the BER/DER encoding b
// in which one universal SEQUENCE (0x30) or SET (0x31) identifier octet
// has its constructed bit cleared (0x10, 0x11): the primitive-encoded
// constructed type that once made the hand-written parsers dereference a
// nil reader. It descends into constructed elements and into OCTET STRING
// contents that themselves parse as TLVs (such as the Android attestation
// application id).
func PrimitiveConstructedVariants(b []byte) [][]byte {
	pos, _, ok := tlvWalk(b, 0, false)
	if !ok {
		panic("enclavetest: PrimitiveConstructedVariants: input does not parse")
	}
	out := make([][]byte, 0, len(pos))
	for _, p := range pos {
		v := append([]byte(nil), b...)
		v[p] &^= 0x20
		out = append(out, v)
	}
	return out
}

// tlvWalk parses consecutive TLVs (up to an end-of-contents when indef)
// and returns the offsets of SEQUENCE/SET identifiers, the bytes consumed
// and whether the input parsed.
func tlvWalk(b []byte, base int, indef bool) ([]int, int, bool) {
	var pos []int
	i := 0
	for {
		if indef {
			if i+2 <= len(b) && b[i] == 0 && b[i+1] == 0 {
				return pos, i + 2, true
			}
		} else if i == len(b) {
			return pos, i, true
		}
		if i+2 > len(b) {
			return nil, 0, false
		}
		id := b[i]
		j := i + 1
		if id&0x1f == 0x1f {
			for j < len(b) && b[j]&0x80 != 0 {
				j++
			}
			j++
		}
		if j >= len(b) {
			return nil, 0, false
		}
		lb := b[j]
		j++
		cons := id&0x20 != 0
		if id == 0x30 || id == 0x31 {
			pos = append(pos, base+i)
		}
		if lb == 0x80 {
			if !cons {
				return nil, 0, false
			}
			sub, n, ok := tlvWalk(b[j:], base+j, true)
			if !ok {
				return nil, 0, false
			}
			pos = append(pos, sub...)
			i = j + n
			continue
		}
		l := int(lb)
		if lb > 0x80 {
			k := int(lb & 0x7f)
			if k > 4 || j+k > len(b) {
				return nil, 0, false
			}
			l = 0
			for _, c := range b[j : j+k] {
				l = l<<8 | int(c)
			}
			j += k
		}
		if l < 0 || l > len(b)-j {
			return nil, 0, false
		}
		c := b[j : j+l]
		if cons {
			sub, _, ok := tlvWalk(c, base+j, false)
			if !ok {
				return nil, 0, false
			}
			pos = append(pos, sub...)
		} else if id == 0x04 {
			if sub, _, ok := tlvWalk(c, base+j, false); ok {
				pos = append(pos, sub...)
			}
		}
		i = j + l
	}
}
