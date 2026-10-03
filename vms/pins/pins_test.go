package pins

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"testing"
	"time"
)

func fp(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

// The pinned files are exactly the vendors' published certificates.
func TestFingerprints(t *testing.T) {
	if got := fp(NitroRoot().Raw); got != "641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b" {
		t.Errorf("nitro %s", got)
	}
	if got := fp(AppleAppAttestRoot().Raw); got != "1cb9823ba28ba6ad2d33a006941de2ae4f513ef1d4e831b9f7e0fa7b6242c932" {
		t.Errorf("apple %s", got)
	}
	want := map[string]bool{
		"1ef1a04b8ba58ab94589ac498c8982a783f24ea7307e0159a0c3a73b377d87cc": true,
		"ab6641178a36e179aa0c1cdddf9a16eb45fa20943e2b8cd7c7c05c26cf8b487a": true,
		"cedb1cb6dc896ae5ec797348bce9286753c2b38ee71ce0fbe34a9a1248800dfc": true,
		"6d9db4ce6c5c0b293166d08986e05774a8776ceb525d9e4329520de12ba4bcc0": true,
	}
	for _, c := range GoogleAttestationRoots() {
		if !want[fp(c.Raw)] {
			t.Errorf("google %s", fp(c.Raw))
		}
		delete(want, fp(c.Raw))
	}
	if len(want) != 0 {
		t.Errorf("missing google roots %v", want)
	}
}

// The TLS roots are the published Amazon Root CA 1-4 and GTS Root R1, R3
// and R4 (fingerprints from amazontrust.com and pki.goog).
func TestTLSFingerprints(t *testing.T) {
	check := func(name string, got []*x509.Certificate, want ...string) {
		t.Helper()
		if len(got) != len(want) {
			t.Fatalf("%s: %d roots", name, len(got))
		}
		for i, c := range got {
			if fp(c.Raw) != want[i] {
				t.Errorf("%s %d: %s", name, i, fp(c.Raw))
			}
		}
	}
	check("amazon", AmazonTLSRoots(),
		"8ecde6884f3d87b1125ba31ac3fcb13d7016de7f57cc904fe1cb97c6ae98196e",
		"1ba5b2aa8c65401a82960118f80bec4f62304d83cec4713a19c39c011ea46db4",
		"18ce6cfe7bf14e60b2e347b8dfe868cb31d02ebb3ada271569f50343b46db3a4",
		"e35d28419ed02025cfa69038cd623962458da5c695fbdea3c22b0bfb25897092")
	check("gts", GoogleTLSRoots(),
		"d947432abde7b7fa90fc2e6b59101b1280e0e1c7e4e40fa3c6887fff57a7f4cf",
		"34d8a73ee208d9bcdb0d956520934b4e40e69482596e8b6f73c8426b010a6f48",
		"349dfa4058c5e263123b398ae795573c4e1313c83fe68f93556cd5e8031b3c7d")
}

// Every pinned root is self-signed and valid now.
func TestRootsValid(t *testing.T) {
	now := time.Now()
	all := append(GoogleAttestationRoots(), NitroRoot(), AppleAppAttestRoot())
	all = append(all, AmazonTLSRoots()...)
	all = append(all, GoogleTLSRoots()...)
	for _, c := range all {
		if err := c.CheckSignatureFrom(c); err != nil {
			t.Errorf("%s: %v", c.Subject, err)
		}
		if now.Before(c.NotBefore) || now.After(c.NotAfter) {
			t.Errorf("%s: not valid now", c.Subject)
		}
	}
}

// The GrapheneOS allowlist: 21 device families from the GrapheneOS
// attestation compatibility guide, distinct, 32 bytes each.
func TestGrapheneOSBootKeys(t *testing.T) {
	keys := GrapheneOSVerifiedBootKeys()
	if len(keys) != 21 {
		t.Fatalf("%d keys", len(keys))
	}
	seen := map[string]bool{}
	for _, k := range keys {
		if len(k) != 32 || seen[string(k)] {
			t.Fatalf("bad or duplicate key %x", k)
		}
		seen[string(k)] = true
	}
	if hex.EncodeToString(keys[11]) != "896db2d09d84e1d6bb747002b8a114950b946e5825772a9d48ba7eb01d118c1c" { // Pixel 8 Pro
		t.Fatal("order or value changed")
	}
	keys[0][0] ^= 1 // a copy
	if GrapheneOSVerifiedBootKeys()[0][0] == keys[0][0] {
		t.Fatal("not a copy")
	}
}
