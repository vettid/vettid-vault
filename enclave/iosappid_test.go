package enclave_test

import (
	"crypto/sha256"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/enclave"
	"github.com/vettid/vettid-vault/enclave/releasecfg"
	"github.com/vettid/vettid-vault/internal/enclavetest"
	"github.com/vettid/vettid-vault/vms/devattest"
	"github.com/vettid/vettid-vault/vms/nitro"
)

// VAULT-MESSAGING 0.35.0 §11.10.8, "iOS App ID": each channel's images
// accept exactly that channel's App ID. With the TEST Apple CA in place of
// Apple's root (only the App ID is under test), a staging configuration
// accepts an attestation and an assertion of the staging App ID and
// refuses production's, a production configuration the reverse, and a
// configuration without channel constants refuses both.
func TestIOSAppIDPerChannel(t *testing.T) {
	const prodApp, stagingApp = "3X25CJ86MV.com.vettid.app", "3X25CJ86MV.com.vettid.app.staging"
	b, err := os.ReadFile("releasecfg/staging.json")
	if err != nil {
		t.Fatal(err)
	}
	st, err := releasecfg.Check(releasecfg.ChannelStaging, b)
	if err != nil {
		t.Fatal(err)
	}
	b, err = os.ReadFile("releasecfg/prod.json")
	if err != nil {
		t.Fatal(err)
	}
	pf, err := releasecfg.Parse(b) // production's file still has placeholders; its App ID is final
	if err != nil {
		t.Fatal(err)
	}
	prod := pf.Config
	now := time.Now()
	ch := sha256.Sum256([]byte("enroll"))
	for _, tc := range []struct {
		name   string
		c      *releasecfg.Config
		accept string
	}{
		{"staging", st, stagingApp},
		{"production", &prod, prodApp},
		{"no channel", nil, ""},
	} {
		pol := *enclave.ReleaseConfigFor(tc.c, "i-1", enclave.DefaultRelayURL).DeviceAttest
		if pol.IOSAppID != tc.accept {
			t.Fatalf("%s: iOS App ID %q, want %q", tc.name, pol.IOSAppID, tc.accept)
		}
		pol.IOSRoots = nitro.Pool(enclavetest.TestAppleCA().Root.Cert)
		for i, app := range []string{stagingApp, prodApp, "3X25CJ86MV.com.vettid.app.dev"} {
			a := enclavetest.NewIOSAttester(byte(0x60+i), enclavetest.IOSOptions{AppID: app})
			d, _ := a.Attest(ch)
			bd, err := devattest.VerifyAttest(&pol, d, ch, now, nil)
			if app != tc.accept {
				want := devattest.ErrApplication
				if tc.accept == "" {
					want = devattest.ErrPlatform
				}
				if !errors.Is(err, want) {
					t.Errorf("%s: attestation of %s: %v", tc.name, app, err)
				}
				continue
			}
			if err != nil {
				t.Fatalf("%s: attestation of %s: %v", tc.name, app, err)
			}
			s := devattest.ForChallenge(sha256.Sum256([]byte("unlock")))
			as, _ := a.Assert(s)
			if _, err := devattest.VerifyAssertion(&pol, bd, as, s, bd.Counter, now, nil); err != nil {
				t.Fatalf("%s: assertion of %s: %v", tc.name, app, err)
			}
			// The same key asserting under the other channel's App ID.
			other := prodApp
			if app == prodApp {
				other = stagingApp
			}
			x := enclavetest.NewIOSAttester(byte(0x60+i), enclavetest.IOSOptions{AppID: other})
			as, _ = x.Assert(s)
			if _, err := devattest.VerifyAssertion(&pol, bd, as, s, bd.Counter, now, nil); !errors.Is(err, devattest.ErrApplication) {
				t.Errorf("%s: assertion under %s: %v", tc.name, other, err)
			}
		}
	}
}
