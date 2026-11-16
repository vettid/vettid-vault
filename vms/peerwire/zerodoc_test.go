package peerwire_test

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/peerwire"
)

// A CheckedDocument made outside the checks (its zero value, d all zeros) is never signed, even for a challenge
// whose context ends in sixteen zeros.
func TestZeroCheckedDocumentIsNotSigned(t *testing.T) {
	_, cred, _ := ed25519.GenerateKey(nil)
	c := &peerwire.ConnAuthChallenge{RequestID: "01JB2Z6V9K3M4N5P6Q7R8S9T30", Nonce: make([]byte, peerwire.ConnAuthNonceSize),
		Context: "Approve — ref 0000000000000000", Purpose: peerwire.PurposeApproval}
	ik := make([]byte, 32)
	var zero peerwire.CheckedDocument
	for _, d := range []*peerwire.CheckedDocument{&zero, new(peerwire.CheckedDocument)} {
		if _, err := peerwire.SignConnAuthDocument(cred, ik, ik, c, d, time.Now(), nil); err == nil {
			t.Fatal("signed a zero-value checked document")
		}
	}
}
