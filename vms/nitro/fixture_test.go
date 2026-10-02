package nitro

import (
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/vettid/vettid-vault/vms/pins"
)

func realDocument(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/aws-attestation-2025-09-16.b64")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

// A real NSM document (indefinite-length payload map, null nonce) verifies
// against the pinned AWS Nitro root at its own timestamp, with every check
// as strict as for test documents.
func TestRealDocument(t *testing.T) {
	doc := realDocument(t)
	if doc[10] != 0xbf {
		t.Fatal("fixture: expected an indefinite-length payload map")
	}
	d, err := Verify(doc, Pool(pins.NitroRoot()))
	if err != nil {
		t.Fatalf("real document: %v", err)
	}
	if !strings.HasPrefix(d.ModuleID, "i-02447a481344e9ec0-enc") || d.Timestamp.Year() != 2025 {
		t.Fatalf("module %s at %v", d.ModuleID, d.Timestamp)
	}
	if len(d.PCRs) != 16 || d.Measurements().IsDebug() || len(d.UserData) != 32 || d.Nonce != nil || len(d.PublicKey) == 0 {
		t.Fatalf("fields: %d PCRs, user_data %d, nonce %v, public key %d", len(d.PCRs), len(d.UserData), d.Nonce, len(d.PublicKey))
	}
	// Not fresh today: freshness stays the caller's check.
	if d.CheckFresh(d.Timestamp.AddDate(1, 0, 0), 5*60e9, 60e9) == nil {
		t.Fatal("a year-old document passed as fresh")
	}

	// Tampering anywhere fails.
	sig := append([]byte(nil), doc...)
	sig[len(sig)-1] ^= 1
	if _, err := Verify(sig, Pool(pins.NitroRoot())); !errors.Is(err, ErrSignature) {
		t.Fatalf("flipped signature: %v", err)
	}
	pay := append([]byte(nil), doc...)
	i := strings.Index(string(pay), "module_id") + 12
	pay[i] ^= 1
	if _, err := Verify(pay, Pool(pins.NitroRoot())); err == nil {
		t.Fatal("altered payload accepted")
	}
	// Another root does not anchor it.
	if _, err := Verify(doc, Pool(pins.AppleAppAttestRoot())); !errors.Is(err, ErrChain) {
		t.Fatalf("foreign root: %v", err)
	}
}
