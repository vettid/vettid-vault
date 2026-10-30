package votewire

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"
)

// The real bundles of the 2026-10-30 staging test vote (proposal
// 01M66MP0AYPF1QDDQFC8ABNPHF, Sigstore's staging Rekor and timestamp
// authority) and service-vault's anchor-vector.json (BALLOT-PROTOCOL
// 0.12.3), which carries the Sigstore staging TrustedRoot.
const (
	anchorVector = "../../testdata/vote/anchor-vector.json"
	stagingDir   = "../../testdata/vote/staging/"
)

type anchorVec struct {
	ServiceIK   []byte          `json:"service_ik"`
	AnchorKey   []byte          `json:"anchor_key"`
	AnchorCert  []byte          `json:"anchor_cert"`
	Proposal    string          `json:"proposal"`
	ProposalSig string          `json:"proposal_sig"` // hex
	Timestamp   int64           `json:"timestamp"`
	Bundle      json.RawMessage `json:"bundle"`
	TrustedRoot json.RawMessage `json:"trusted_root"`
}

func loadAnchor(t *testing.T) (*anchorVec, []*TrustRoot) {
	t.Helper()
	raw, err := os.ReadFile(anchorVector)
	if err != nil {
		t.Fatal(err)
	}
	var v anchorVec
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	roots, err := ParseTrustRoots([]byte("[" + string(v.TrustedRoot) + "]"))
	if err != nil {
		t.Fatal(err)
	}
	return &v, roots
}

func TestRealStagingBundle(t *testing.T) {
	v, roots := loadAnchor(t)
	doc := []byte(v.Proposal)
	stamp := time.Unix(v.Timestamp, 0)
	if err := VerifyProposal(v.ServiceIK, doc, hexb(v.ProposalSig)); err != nil {
		t.Fatalf("proposal_sig: %v", err)
	}
	if err := VerifyAnchorCert(v.ServiceIK, v.AnchorKey, v.AnchorCert); err != nil {
		t.Fatalf("anchor_cert: %v", err)
	}
	info, err := VerifyBundle(doc, v.Bundle, [][]byte{v.AnchorKey}, roots, stamp.Add(5*time.Minute), stamp.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if info.IntegratedTime != v.Timestamp || info.GenTime.Unix() != v.Timestamp || info.LogIndex != 56709899 {
		t.Errorf("%+v", info)
	}

	// The file a real publication writes (the bundle next to the document)
	// is the same bundle.
	b2, err := os.ReadFile(stagingDir + "proposal.json.sigstore.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyBundle(doc, b2, [][]byte{v.AnchorKey}, roots, stamp.Add(time.Hour), stamp); err != nil {
		t.Errorf("proposal.json.sigstore.json: %v", err)
	}
	// The results bundle, for the results document, with the same key.
	rd, _ := os.ReadFile(stagingDir + "results.json")
	rb, _ := os.ReadFile(stagingDir + "results.json.sigstore.json")
	if _, err := VerifyBundle(rd, rb, [][]byte{v.AnchorKey}, roots, time.Now().Add(24*time.Hour), time.Now()); err != nil {
		t.Errorf("results bundle: %v", err)
	}
}

func TestRealBundleFailures(t *testing.T) {
	v, roots := loadAnchor(t)
	doc := []byte(v.Proposal)
	stamp := time.Unix(v.Timestamp, 0)
	key := [][]byte{v.AnchorKey}
	check := func(name string, doc, bundle []byte, keys [][]byte, rs []*TrustRoot, notAfter, now time.Time, want error) {
		t.Helper()
		_, err := VerifyBundle(doc, bundle, keys, rs, notAfter, now)
		if !errors.Is(err, want) {
			t.Errorf("%s: %v, want %v", name, err, want)
		}
	}
	ok := stamp.Add(time.Minute)
	check("no accepted key", doc, v.Bundle, nil, roots, ok, ok, ErrAnchorKey)
	check("another key", doc, v.Bundle, [][]byte{make([]byte, 91)}, roots, ok, ok, ErrAnchorKey)
	other := append([]byte{}, doc...)
	other[10] ^= 1
	check("another document", other, v.Bundle, key, roots, ok, ok, ErrAnchor)
	check("late", doc, v.Bundle, key, roots, stamp.Add(-time.Second), ok, ErrAnchorLate)
	check("clock behind", doc, v.Bundle, key, roots, ok, stamp.Add(-StampAhead-time.Minute), ErrBundleClock)
	check("no roots", doc, v.Bundle, key, nil, ok, ok, ErrBundleRoot)
	check("empty", doc, nil, key, roots, ok, ok, ErrBundleRoot)
	check("not json", doc, []byte(`x`), key, roots, ok, ok, ErrBundleRoot)

	// Edits of the bundle itself: each is caught by the right check.
	edit := func(name string, want error, f func(m map[string]any)) {
		t.Helper()
		var m map[string]any
		if err := json.Unmarshal(v.Bundle, &m); err != nil {
			t.Fatal(err)
		}
		f(m)
		b, _ := json.Marshal(m)
		check(name, doc, b, key, roots, ok, ok, want)
	}
	entry := func(m map[string]any) map[string]any {
		return m["verificationMaterial"].(map[string]any)["tlogEntries"].([]any)[0].(map[string]any)
	}
	flip := func(m map[string]any, k string) {
		s, _ := base64.StdEncoding.DecodeString(m[k].(string))
		s[len(s)-1] ^= 1
		m[k] = base64.StdEncoding.EncodeToString(s)
	}
	edit("media type", ErrBundleRoot, func(m map[string]any) { m["mediaType"] = "x" })
	edit("two entries", ErrBundleRoot, func(m map[string]any) {
		vm := m["verificationMaterial"].(map[string]any)
		es := vm["tlogEntries"].([]any)
		vm["tlogEntries"] = append(es, es[0])
	})
	edit("kind and version", ErrBundleRoot, func(m map[string]any) { entry(m)["kindVersion"].(map[string]any)["version"] = "0.0.2" })
	edit("Rekor v2 entry", ErrBundleRoot, func(m map[string]any) {
		entry(m)["kindVersion"] = map[string]any{"kind": "hashedrekord", "version": "0.0.2"}
	})
	edit("digest algorithm", ErrBundleRoot, func(m map[string]any) {
		m["messageSignature"].(map[string]any)["messageDigest"].(map[string]any)["algorithm"] = "SHA2_512"
	})
	edit("digest", ErrAnchor, func(m map[string]any) {
		flip(m["messageSignature"].(map[string]any)["messageDigest"].(map[string]any), "digest")
	})
	edit("signature", ErrAnchor, func(m map[string]any) { flip(m["messageSignature"].(map[string]any), "signature") })
	edit("body", ErrBundleRoot, func(m map[string]any) { flip(entry(m), "canonicalizedBody") })
	edit("root hash", ErrBundleRoot, func(m map[string]any) { flip(entry(m)["inclusionProof"].(map[string]any), "rootHash") })
	edit("proof hash", ErrBundleRoot, func(m map[string]any) {
		h := entry(m)["inclusionProof"].(map[string]any)["hashes"].([]any)
		s, _ := base64.StdEncoding.DecodeString(h[0].(string))
		s[0] ^= 1
		h[0] = base64.StdEncoding.EncodeToString(s)
	})
	edit("tree size", ErrBundleRoot, func(m map[string]any) { entry(m)["inclusionProof"].(map[string]any)["treeSize"] = "25027489" })
	edit("checkpoint size", ErrBundleRoot, func(m map[string]any) {
		cp := entry(m)["inclusionProof"].(map[string]any)["checkpoint"].(map[string]any)
		cp["envelope"] = "rekor.sigstage.dev - 8202293616175992157\n25027489\n" + cp["envelope"].(string)[len("rekor.sigstage.dev - 8202293616175992157\n25027488\n"):]
	})
	edit("checkpoint signature", ErrBundleRoot, func(m map[string]any) {
		cp := entry(m)["inclusionProof"].(map[string]any)["checkpoint"].(map[string]any)
		s := cp["envelope"].(string)
		cp["envelope"] = s[:len(s)-6] + "AAAAA\n"
	})
	edit("signed entry timestamp", ErrBundleRoot, func(m map[string]any) { flip(entry(m)["inclusionPromise"].(map[string]any), "signedEntryTimestamp") })
	edit("integrated time", ErrBundleRoot, func(m map[string]any) { entry(m)["integratedTime"] = "1793371866" })
	edit("log id", ErrBundleRoot, func(m map[string]any) { flip(entry(m)["logId"].(map[string]any), "keyId") })
	edit("timestamp token", ErrBundleRoot, func(m map[string]any) {
		ts := m["verificationMaterial"].(map[string]any)["timestampVerificationData"].(map[string]any)["rfc3161Timestamps"].([]any)[0].(map[string]any)
		s, _ := base64.StdEncoding.DecodeString(ts["signedTimestamp"].(string))
		s[len(s)-1] ^= 1
		ts["signedTimestamp"] = base64.StdEncoding.EncodeToString(s)
	})
	edit("timestamp for another signature", ErrBundleRoot, func(m map[string]any) {
		// A different stamp from the same authority cannot be had here:
		// truncating the response is the next best thing.
		ts := m["verificationMaterial"].(map[string]any)["timestampVerificationData"].(map[string]any)["rfc3161Timestamps"].([]any)[0].(map[string]any)
		s, _ := base64.StdEncoding.DecodeString(ts["signedTimestamp"].(string))
		ts["signedTimestamp"] = base64.StdEncoding.EncodeToString(s[:len(s)-1])
	})

	// A root without the log's key, or without the authority, verifies
	// nothing; an older root listed first still lets the newer one verify.
	rl := &TrustRoot{Logs: roots[0].Logs[1:], TSAs: roots[0].TSAs}
	rt := &TrustRoot{Logs: roots[0].Logs, TSAs: roots[0].TSAs[:1]} // the 2026 authority signed this stamp
	check("root without the log", doc, v.Bundle, key, []*TrustRoot{rl}, ok, ok, ErrBundleRoot)
	check("root without the authority", doc, v.Bundle, key, []*TrustRoot{rt}, ok, ok, ErrBundleRoot)
	if _, err := VerifyBundle(doc, v.Bundle, key, []*TrustRoot{roots[0], rl}, ok, ok); err != nil {
		t.Errorf("an older root that fails must not hide a newer one: %v", err)
	}
	if _, err := VerifyBundle(doc, v.Bundle, key, []*TrustRoot{rl, roots[0]}, ok, ok); err != nil {
		t.Errorf("older root listed first: %v", err)
	}
}

func TestTrustRootFormat(t *testing.T) {
	v, _ := loadAnchor(t)
	if _, err := ParseTrustRoots([]byte("[" + string(v.TrustedRoot) + "]")); err != nil {
		t.Fatal(err)
	}
	for name, in := range map[string]string{
		"not an array": string(v.TrustedRoot),
		"empty":        `[]`,
		"no logs":      `[{"tlogs":[],"timestampAuthorities":[]}]`,
		"duplicate":    `[{"tlogs":[],"tlogs":[]}]`,
	} {
		if _, err := ParseTrustRoots([]byte(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A log id that is not the hash of the key is refused.
	var m map[string]any
	_ = json.Unmarshal(v.TrustedRoot, &m)
	m["tlogs"].([]any)[0].(map[string]any)["logId"] = map[string]any{"keyId": base64.StdEncoding.EncodeToString(make([]byte, 32))}
	b, _ := json.Marshal([]any{m})
	if _, err := ParseTrustRoots(b); err == nil {
		t.Error("a key under another key's id")
	}
}

func hexb(s string) []byte { b, _ := hex.DecodeString(s); return b }
