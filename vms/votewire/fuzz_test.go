package votewire

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

// A document that parses is exactly its own canonical form, and parsing
// never panics (BALLOT-PROTOCOL §2).
func FuzzDocuments(f *testing.F) {
	raw, _ := os.ReadFile(vectorsFile)
	var v vectors
	_ = json.Unmarshal(raw, &v)
	for _, d := range []string{v.Documents.Proposal, v.Documents.Extension, v.Documents.Results, v.Documents.Rows, `{}`, `[]`, `{"a":1,"a":2}`} {
		f.Add([]byte(d))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if c, err := Canonicalize(data); err == nil {
			c2, err := Canonicalize(c)
			if err != nil || !bytes.Equal(c, c2) {
				t.Fatalf("canonical form is not stable")
			}
		}
		if p, err := ParseProposal(data); err == nil {
			again, err := Canonicalize(data)
			if err != nil || !bytes.Equal(again, data) || p.Validate() != nil {
				t.Fatalf("a proposal parsed that is not canonical")
			}
		}
		_, _ = ParseExtension(data)
		_, _ = ParseResults(data)
		_, _ = ParseServiceList(data)
	})
}

// The message bodies never panic on any input.
func FuzzBodies(f *testing.F) {
	f.Add([]byte(`{"proposal":"AA==","proposal_sig":"","bundle":{},"record_secret":"","record_proof":{"index":0,"tree_size":1,"path":[]}}`))
	f.Add([]byte(`{"refusal_sig":null,"msg_ms":1,"connection":"","record_tag":""}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseProposalMsg(data)
		_, _ = ParseExtendedMsg(data)
		_, _ = ParseClosedMsg(data)
		_, _ = ParseCastAnswer(data)
		_, _ = ParseStatusAnswer(data)
		_, _ = ParseRefusal(data)
	})
}

// A proof never verifies a leaf that is not in the tree.
func FuzzVerifyProof(f *testing.F) {
	f.Add([]byte("a"), uint64(0), uint64(1), []byte{})
	f.Fuzz(func(t *testing.T, leaf []byte, m, n uint64, flat []byte) {
		var proof [][]byte
		for len(flat) >= 32 && len(proof) < 40 {
			proof = append(proof, flat[:32])
			flat = flat[32:]
		}
		leaves := [][]byte{[]byte("a"), []byte("b"), []byte("c")}
		root := Root(leaves)
		if VerifyProof(root, leaf, m, n, proof) {
			ok := false
			for _, l := range leaves {
				ok = ok || bytes.Equal(l, leaf)
			}
			if !ok && n == 3 {
				t.Fatalf("a leaf outside the tree verifies")
			}
		}
	})
}
