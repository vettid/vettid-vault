package devattest_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/enclave/releasecfg"
	"github.com/vettid/vettid-vault/vms/altchan"
	"github.com/vettid/vettid-vault/vms/devattest"
	"github.com/vettid/vettid-vault/vms/nitro"
	"github.com/vettid/vettid-vault/vms/pins"
)

// realIOSAppIDs are the App IDs a real attestation file may name: the
// dev-stack and debug builds only (testdata/real/README.md: never export
// from a Release or Staging build). They attest in the production
// environment when signed with the production App Attest entitlement.
var realIOSAppIDs = map[string]bool{
	"3X25CJ86MV.com.vettid.app.dev":      true,
	"3X25CJ86MV.com.vettid.app.devstack": true,
}

// realIOS is one testdata/real/*.ios.json file (testdata/real/README.md).
type realIOS struct {
	AppID       string `json:"app_id"`
	AttestedAt  string `json:"attested_at"`
	KeyID       string `json:"key_id"`
	Attestation string `json:"attestation"`
	Challenge   string `json:"challenge"`
	Assertions  []struct {
		ClientDataHash string `json:"client_data_hash"`
		Assertion      string `json:"assertion"`
	} `json:"assertions"`
}

func b64(t *testing.T, what, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || len(b) == 0 {
		t.Fatalf("%s: not standard base64", what)
	}
	return b
}

func hash32(t *testing.T, what, s string) [32]byte {
	t.Helper()
	b := b64(t, what, s)
	if len(b) != 32 {
		t.Fatalf("%s: %d bytes, want 32", what, len(b))
	}
	return [32]byte(b)
}

// verifyIOS and verifyIOSAssertion against App Attest objects of real
// iPhones (testdata/real/*.ios.json, see the README there): the
// attestation must chain to the Apple App Attestation root the release
// pins (pins.AppleAppAttestRoot), in the production environment, for the
// App ID the file names, with the file's challenge as clientDataHash; each
// assertion must verify with the attested key over its clientDataHash,
// with counters that increase in file order. The test PKI of the other
// tests is made to satisfy the verifier; these files show that real
// hardware does. Run it with the test iPhone's files before a release
// that accepts an iOS app.
func TestRealIOSAttestations(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("testdata", "real", "*.ios.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Skip("no real App Attest objects in vms/devattest/testdata/real (*.ios.json; see the README there): the iOS verifier is not checked against real hardware in this run")
	}
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			raw, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			var r realIOS
			dec := json.NewDecoder(bytes.NewReader(raw))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&r); err != nil || dec.More() {
				t.Fatalf("not a real-attestation file: %v", err)
			}
			if !realIOSAppIDs[r.AppID] {
				t.Fatalf("app_id %q is not a VettID App ID", r.AppID)
			}
			at, err := time.Parse(time.RFC3339, r.AttestedAt)
			if err != nil {
				t.Fatalf("attested_at: %v", err)
			}
			if len(r.Assertions) == 0 {
				t.Fatal("no assertions")
			}
			p := &devattest.Policy{IOSRoots: nitro.Pool(pins.AppleAppAttestRoot()), IOSAppID: r.AppID}
			d := &altchan.DeviceAttest{Platform: altchan.PlatformIOS, KeyID: b64(t, "key_id", r.KeyID), Attestation: b64(t, "attestation", r.Attestation)}
			// The certificates' validity is checked at the time the
			// attestation was made; the credential certificate is short-lived.
			b, err := devattest.VerifyAttest(p, d, hash32(t, "challenge", r.Challenge), at, nil)
			if err != nil {
				t.Fatalf("a real attestation is refused: %v", err)
			}
			for i, a := range r.Assertions {
				s := devattest.Signed{ClientDataHash: hash32(t, "client_data_hash", a.ClientDataHash)}
				nb, err := devattest.VerifyAssertion(p, b, &altchan.DeviceAssertion{Platform: altchan.PlatformIOS, Assertion: b64(t, "assertion", a.Assertion)}, s, b.Counter, at, nil)
				if err != nil {
					t.Fatalf("assertion %d is refused: %v", i, err)
				}
				t.Logf("assertion %d: counter %d", i, nb.Counter)
				b = nb
			}
			// The refusals, on real data: each release channel's App ID
			// refuses the attestation and its first assertion; a replayed
			// assertion and a changed challenge are refused.
			first := r.Assertions[0]
			attested, err := devattest.VerifyAttest(p, d, hash32(t, "challenge", r.Challenge), at, nil)
			if err != nil {
				t.Fatal(err)
			}
			for ch, id := range releasecfg.IOSAppIDs {
				other := *p
				other.IOSAppID = id
				if _, err := devattest.VerifyAttest(&other, d, hash32(t, "challenge", r.Challenge), at, nil); !errors.Is(err, devattest.ErrApplication) {
					t.Fatalf("the %s App ID: the attestation gives %v", ch, err)
				}
				s := devattest.Signed{ClientDataHash: hash32(t, "client_data_hash", first.ClientDataHash)}
				da := &altchan.DeviceAssertion{Platform: altchan.PlatformIOS, Assertion: b64(t, "assertion", first.Assertion)}
				if _, err := devattest.VerifyAssertion(&other, attested, da, s, attested.Counter, at, nil); !errors.Is(err, devattest.ErrApplication) {
					t.Fatalf("the %s App ID: the assertion gives %v", ch, err)
				}
			}
			last := r.Assertions[len(r.Assertions)-1]
			s := devattest.Signed{ClientDataHash: hash32(t, "client_data_hash", last.ClientDataHash)}
			da := &altchan.DeviceAssertion{Platform: altchan.PlatformIOS, Assertion: b64(t, "assertion", last.Assertion)}
			if _, err := devattest.VerifyAssertion(p, b, da, s, b.Counter, at, nil); !errors.Is(err, devattest.ErrCounter) {
				t.Fatalf("a replayed assertion gives %v", err)
			}
			flipped := hash32(t, "challenge", r.Challenge)
			flipped[0] ^= 1
			if _, err := devattest.VerifyAttest(p, d, flipped, at, nil); !errors.Is(err, devattest.ErrChallenge) {
				t.Fatalf("a changed challenge gives %v", err)
			}
		})
	}
}
