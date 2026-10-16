package enclave_test

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/client"
	"github.com/vettid/vettid-vault/enclave"
	"github.com/vettid/vettid-vault/internal/enclavetest"
	"github.com/vettid/vettid-vault/vms/altchan"
	"github.com/vettid/vettid-vault/vms/manifest"
)

// 0.34.0, release R (§11.2, §11.10.9): every descriptor the instance
// publishes names the image's capabilities, and the attestation over the
// descriptor still verifies, so the list is bound with the rest; a
// descriptor with the list changed no longer matches its attestation.
func TestDescriptorCapabilities(t *testing.T) {
	for _, offered := range []bool{true, false} {
		descriptorCapabilities(t, offered)
	}
}

// offered is the measured release constant recovery_offered: listed as
// recovery_offered only when true (owner decision of 2026-10-16).
func descriptorCapabilities(t *testing.T, offered bool) {
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	clk := func() time.Time { return now }
	w := enclavetest.NewWorld(clk, relayURL)
	w.AddRelease(r3)
	in, err := w.StartWith(3, func(c *enclave.Config) { c.Recovery.Offered = offered })
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	tr := w.Trust()
	s, err := manifest.ParseServed(w.Served())
	if err != nil {
		t.Fatal(err)
	}
	m, err := manifest.Verify(s, tr.ManifestKeys)
	if err != nil {
		t.Fatal(err)
	}
	for round := 0; round < 2; round++ {
		desc, att := in.Descriptor()
		e, err := client.VerifyEnclave(desc, att, m, true, tr, now)
		if err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		got := e.Descriptor.Capabilities
		want := []string{altchan.CapAttachments, altchan.CapRecoveryR}
		if offered {
			want = []string{altchan.CapAttachments, altchan.CapRecoveryOffered, altchan.CapRecoveryR}
		}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("round %d: capabilities %q", round, got)
		}
		// A host that removes recovery_r breaks the attestation's user_data.
		forged := bytes.Replace(desc, []byte(`,"recovery_r"`), nil, 1)
		if bytes.Equal(forged, desc) {
			t.Fatal("forgery did not change the descriptor")
		}
		if _, err := client.VerifyEnclave(forged, att, m, true, tr, now); err == nil {
			t.Fatalf("round %d: a descriptor without recovery_r verified under the original attestation", round)
		}
		// The rotated ETK's descriptor carries the same list.
		if err := in.RotateETK(); err != nil {
			t.Fatal(err)
		}
	}
}
