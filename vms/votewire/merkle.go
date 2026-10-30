package votewire

import "crypto/sha256"

// Merkle trees per RFC 6962 §2.1 with SHA-256 (BALLOT-PROTOCOL §8.2): leaf
// hash H(0x00 ‖ leaf), node hash H(0x01 ‖ left ‖ right), split at the
// largest power of two below n, the empty tree H(""). Proofs are audit
// paths, nearest sibling first, verified per RFC 9162 §2.1.3.2.

// LeafHash is H(0x00 ‖ leaf).
func LeafHash(leaf []byte) []byte { return H([]byte{0}, leaf) }

func nodeHash(l, r []byte) []byte { return H([]byte{1}, l, r) }

// split is the largest power of two below n (n ≥ 2).
func split(n int) int {
	k := 1
	for k<<1 < n {
		k <<= 1
	}
	return k
}

// Root is the tree head over the leaves, in order.
func Root(leaves [][]byte) []byte {
	if len(leaves) == 0 {
		s := sha256.Sum256(nil)
		return s[:]
	}
	hashes := make([][]byte, len(leaves))
	for i, l := range leaves {
		hashes[i] = LeafHash(l)
	}
	return rootOf(hashes)
}

func rootOf(h [][]byte) []byte {
	if len(h) == 1 {
		return h[0]
	}
	k := split(len(h))
	return nodeHash(rootOf(h[:k]), rootOf(h[k:]))
}

// Proof is the audit path of leaf index m in a tree of the leaves.
func Proof(leaves [][]byte, m int) ([][]byte, error) {
	if m < 0 || m >= len(leaves) {
		return nil, ErrProof
	}
	hashes := make([][]byte, len(leaves))
	for i, l := range leaves {
		hashes[i] = LeafHash(l)
	}
	return path(hashes, m), nil
}

func path(h [][]byte, m int) [][]byte {
	if len(h) == 1 {
		return nil
	}
	k := split(len(h))
	if m < k {
		return append(path(h[:k], m), rootOf(h[k:]))
	}
	return append(path(h[k:], m-k), rootOf(h[:k]))
}

// VerifyProof checks that leaf is at index m of a tree of n leaves with the
// given root. A proof entry that is not 32 bytes, or one too many or too
// few, fails.
func VerifyProof(root, leaf []byte, m, n uint64, proof [][]byte) bool {
	if m >= n || len(root) != HashLen {
		return false
	}
	fn, sn := m, n-1
	r := LeafHash(leaf)
	for _, p := range proof {
		if sn == 0 || len(p) != HashLen {
			return false
		}
		if fn&1 == 1 || fn == sn {
			r = nodeHash(p, r)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = nodeHash(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	return sn == 0 && eq(r, root)
}
