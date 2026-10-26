package enclave_test

import (
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/enclave"
	"github.com/vettid/vettid-vault/enclave/releasecfg"
	"github.com/vettid/vettid-vault/internal/enclavetest"
	"github.com/vettid/vettid-vault/vms/altchan"
	"github.com/vettid/vettid-vault/vms/devattest"
	"github.com/vettid/vettid-vault/vms/pins"
)

// VAULT-RELEASES §3.1 (owner decision 2026-10-27): a staging image
// accepts its automation attestation CA beside the vendor roots, and only
// a staging image does. The CA here is the TEST Android CA standing in
// for it; every other check of §11.7 still applies (package, signer,
// security level, root of trust).
func TestReleaseConfigAutomationRoots(t *testing.T) {
	ca := enclavetest.TestAndroidCA()
	dev := enclavetest.AndroidSignerDev
	conf := func(channel string) *releasecfg.Config {
		return &releasecfg.Config{Channel: channel, AndroidPackage: releasecfg.AndroidPackages[releasecfg.ChannelStaging],
			AndroidSigners: []releasecfg.Signer{{Digest: dev[:], Class: devattest.ClassDevelopment}},
			Automation:     &releasecfg.Automation{AndroidRoots: []*x509.Certificate{ca.Root.Cert}, Until: time.Now().AddDate(0, 1, 0)}}
	}
	now := time.Now()
	var ch [32]byte
	ch[0] = 7
	chain := ca.Attest(enclavetest.TestKey(elliptic.P256(), 0x31), enclavetest.AndroidOptions{Challenge: ch, Package: "com.vettid.app.staging", Signers: [][]byte{dev[:]}})
	att := &altchan.DeviceAttest{Platform: altchan.PlatformAndroid, Chain: chain}
	list := enclavetest.EmptyStatusList(now)

	st := enclave.ReleaseConfigFor(conf(releasecfg.ChannelStaging), "i-1", enclave.DefaultRelayURL).DeviceAttest
	if len(st.AndroidRoots) != len(pins.GoogleAttestationRoots())+1 {
		t.Fatalf("staging roots: %d", len(st.AndroidRoots))
	}
	b, err := devattest.VerifyAttest(st, att, ch, now, list)
	if err != nil {
		t.Fatalf("staging refused the automation chain: %v", err)
	}
	if b.SignerClass != devattest.ClassDevelopment {
		t.Fatalf("signer class %q", b.SignerClass)
	}
	// The vendor roots are untouched by the append.
	if again := enclave.ReleaseConfigFor(nil, "i-1", enclave.DefaultRelayURL).DeviceAttest; len(again.AndroidRoots) != len(pins.GoogleAttestationRoots()) {
		t.Fatalf("vendor roots changed: %d", len(again.AndroidRoots))
	}
	// Only the root differs: a wrong package, an unpinned signer, a
	// software key or an unlocked device is still refused on staging.
	for name, o := range map[string]enclavetest.AndroidOptions{
		"package":  {Challenge: ch, Package: "com.vettid.app", Signers: [][]byte{dev[:]}},
		"signer":   {Challenge: ch, Package: "com.vettid.app.staging"},
		"software": {Challenge: ch, Package: "com.vettid.app.staging", Signers: [][]byte{dev[:]}, SoftwareLevel: true},
		"unlocked": {Challenge: ch, Package: "com.vettid.app.staging", Signers: [][]byte{dev[:]}, Unlocked: true},
	} {
		a := &altchan.DeviceAttest{Platform: altchan.PlatformAndroid, Chain: ca.Attest(enclavetest.TestKey(elliptic.P256(), 0x31), o)}
		if _, err := devattest.VerifyAttest(st, a, ch, now, list); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A configuration of any other channel ignores the roots, however it
	// was built: the chain does not end at a pinned root.
	for _, c := range []*releasecfg.Config{conf(releasecfg.ChannelProd), conf("")} {
		pol := enclave.ReleaseConfigFor(c, "i-1", enclave.DefaultRelayURL).DeviceAttest
		if len(pol.AndroidRoots) != len(pins.GoogleAttestationRoots()) {
			t.Fatalf("%q: roots %d", c.Channel, len(pol.AndroidRoots))
		}
		if _, err := devattest.VerifyAttest(pol, att, ch, now, list); !errors.Is(err, devattest.ErrRoot) {
			t.Fatalf("%q accepted the automation chain: %v", c.Channel, err)
		}
	}
}

// The embedded configuration: a production image never accepts more than
// the vendor roots. Run with -tags vettid_channel_prod /
// vettid_channel_staging by `make channels`.
func TestReleaseConfigAutomationEmbedded(t *testing.T) {
	cfg := enclave.ReleaseConfig("i-1", enclave.DefaultRelayURL)
	ch, c := releasecfg.Embedded()
	want := len(pins.GoogleAttestationRoots())
	if ch == releasecfg.ChannelStaging {
		want += len(c.AutomationRoots())
	}
	if got := len(cfg.DeviceAttest.AndroidRoots); got != want {
		t.Fatalf("channel %q: %d Android roots, want %d", ch, got, want)
	}
}
