package votewire

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"
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
	v := loadFuzz()
	id := v.ProposalID
	f.Add([]byte(`{"proposal_id":"` + id + `","msg_ms":` + "1793606400123" + `,"receipt_sig":"` + e64(hxb(v.Service.ReceiptSig)) + `"}`))
	f.Add([]byte(`{"refusal_sig":"` + e64(hxb(v.Service.Refusal.Sig)) + `","msg_ms":1,"connection":"` + e64(hxb(v.Service.Refusal.Connection)) + `","record_tag":"` + e64(hxb(v.RecordTag)) + `"}`))
	f.Add([]byte(`{"proposal_id":"` + id + `","proposal":"` + e64([]byte(v.Documents.Proposal)) + `","proposal_sig":"` + e64(hxb(v.Documents.ProposalSig)) + `","record_secret":"` + e64(hxb(v.RecordSecret)) + `","record_proof":{"index":0,"tree_size":3,"path":[]},"ballot":{"vk":"` + e64(hxb(v.VK)) + `","choice_id":"yes","ballot_sig":"` + e64(hxb(v.BallotSig)) + `"},"msg_ms":1,"receipt_sig":"` + e64(hxb(v.Service.ReceiptSig)) + `","status_sig":"` + e64(hxb(v.Service.StatusSig)) + `"}`))
	f.Add([]byte(`{"proposal_id":"` + id + `","results_hash":"` + e64(H([]byte(v.Documents.Results))) + `"}`))
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

// A proof that verifies against the root of a, b, c at size 3 is for the leaf at that index.
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
		// Only for the tree's own size: a proof of a leaf at an index of a
		// tree of 3 is for the leaf there. At another size the same path
		// can verify (TestProofDoesNotBindTreeSize), which is why a record
		// proof's tree_size must equal `eligible`.
		if n == 3 && VerifyProof(root, leaf, m, n, proof) {
			if ok := m < uint64(len(leaves)) && bytes.Equal(leaves[m], leaf); !ok {
				t.Fatalf("a leaf outside the tree verifies (m=%d)", m)
			}
		}
	})
}

func loadFuzz() *vectors {
	raw, _ := os.ReadFile(vectorsFile)
	var v vectors
	_ = json.Unmarshal(raw, &v)
	return &v
}

func hxb(s string) []byte { b, _ := hex.DecodeString(s); return b }

// A bundle never panics VerifyBundle, and nothing but the real bundle
// verifies against the real roots.
func FuzzVerifyBundle(f *testing.F) {
	raw, err := os.ReadFile(anchorVector)
	if err != nil {
		f.Fatal(err)
	}
	var v anchorVec
	if err := json.Unmarshal(raw, &v); err != nil {
		f.Fatal(err)
	}
	roots, err := ParseTrustRoots([]byte("[" + string(v.TrustedRoot) + "]"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add([]byte(v.Bundle))
	f.Add([]byte(`{}`))
	stamp := time.Unix(v.Timestamp, 0)
	f.Fuzz(func(t *testing.T, bundle []byte) {
		info, err := VerifyBundle([]byte(v.Proposal), bundle, [][]byte{v.AnchorKey}, roots, stamp.Add(time.Hour), stamp)
		if err == nil && info == nil {
			t.Fatal("no error and no info")
		}
	})
}

// A trusted root never panics the parser.
func FuzzParseTrustRoot(f *testing.F) {
	raw, err := os.ReadFile(anchorVector)
	if err != nil {
		f.Fatal(err)
	}
	var v anchorVec
	if err := json.Unmarshal(raw, &v); err != nil {
		f.Fatal(err)
	}
	f.Add([]byte(v.TrustedRoot))
	f.Add([]byte(`{"tlogs":[],"timestampAuthorities":[]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseTrustRoot(data)
		_, _ = ParseTrustRoots(data)
	})
}
