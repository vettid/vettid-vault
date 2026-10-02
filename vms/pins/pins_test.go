package pins

import (
	"crypto/sha256"
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

// Every pinned root is self-signed and valid now.
func TestRootsValid(t *testing.T) {
	now := time.Now()
	all := append(GoogleAttestationRoots(), NitroRoot(), AppleAppAttestRoot())
	for _, c := range all {
		if err := c.CheckSignatureFrom(c); err != nil {
			t.Errorf("%s: %v", c.Subject, err)
		}
		if now.Before(c.NotBefore) || now.After(c.NotAfter) {
			t.Errorf("%s: not valid now", c.Subject)
		}
	}
}
