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

// VAULT-RELEASES §3.1, VAULT-MESSAGING 0.66.0 §11.10.8 (owner decision
// 2026-10-26): a staging image accepts its automation attestation CA
// beside the vendor roots, and only a staging image does. The CA here is
// the TEST Android CA standing in for it. Such a chain must report the
// automation signer, a vendor chain must not, and every other check of
// §11.7 still applies (package, security level, root of trust).
func TestReleaseConfigAutomationRoots(t *testing.T) {
	ca := enclavetest.TestAndroidCA()
	dev := enclavetest.AndroidSignerDev
	auto := releasecfg.AutomationSignerDigest
	conf := func(channel string) *releasecfg.Config {
		return &releasecfg.Config{Channel: channel, AndroidPackage: releasecfg.AndroidPackages[releasecfg.ChannelStaging],
			AndroidSigners: []releasecfg.Signer{{Digest: dev[:], Class: devattest.ClassDevelopment}, {Digest: auto[:], Class: devattest.ClassAutomation}},
			Automation:     &releasecfg.Automation{AndroidRoots: []*x509.Certificate{ca.Root.Cert}, Until: time.Now().AddDate(0, 1, 0)}}
	}
	now := time.Now()
	var ch [32]byte
	ch[0] = 7
	opts := func(edit func(*enclavetest.AndroidOptions)) enclavetest.AndroidOptions {
		o := enclavetest.AndroidOptions{Challenge: ch, Package: "com.vettid.app.staging", Signers: [][]byte{auto[:]}}
		if edit != nil {
			edit(&o)
		}
		return o
	}
	attest := func(o enclavetest.AndroidOptions) *altchan.DeviceAttest {
		return &altchan.DeviceAttest{Platform: altchan.PlatformAndroid, Chain: ca.Attest(enclavetest.TestKey(elliptic.P256(), 0x31), o)}
	}
	att := attest(opts(nil))
	list := enclavetest.EmptyStatusList(now)

	st := enclave.ReleaseConfigFor(conf(releasecfg.ChannelStaging), "i-1", enclave.DefaultRelayURL).DeviceAttest
	if len(st.AndroidRoots) != len(pins.GoogleAttestationRoots()) || len(st.AndroidAutomationRoots) != 1 || len(st.AndroidSigners) != 2 {
		t.Fatalf("staging: %d vendor roots, %d automation roots, %d signers", len(st.AndroidRoots), len(st.AndroidAutomationRoots), len(st.AndroidSigners))
	}
	b, err := devattest.VerifyAttest(st, att, ch, now, list)
	if err != nil {
		t.Fatalf("staging refused the automation chain: %v", err)
	}
	if b.SignerClass != devattest.ClassAutomation {
		t.Fatalf("signer class %q", b.SignerClass)
	}
	// Only the root differs: a wrong package, another pinned signer (the
	// development one: an automation chain is always labelled as one), an
	// unpinned signer, a software key or an unlocked device is refused.
	for name, o := range map[string]enclavetest.AndroidOptions{
		"package":           opts(func(o *enclavetest.AndroidOptions) { o.Package = "com.vettid.app" }),
		"development class": opts(func(o *enclavetest.AndroidOptions) { o.Signers = [][]byte{dev[:]} }),
		"unpinned signer":   opts(func(o *enclavetest.AndroidOptions) { o.Signers = nil }),
		"software":          opts(func(o *enclavetest.AndroidOptions) { o.SoftwareLevel = true }),
		"unlocked":          opts(func(o *enclavetest.AndroidOptions) { o.Unlocked = true }),
	} {
		if _, err := devattest.VerifyAttest(st, attest(o), ch, now, list); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// The reverse: a chain ending at a vendor root (here the TEST CA as
	// one) cannot claim the automation signer.
	vendor := *st
	vendor.AndroidRoots = []*x509.Certificate{ca.Root.Cert}
	vendor.AndroidAutomationRoots = nil
	if _, err := devattest.VerifyAttest(&vendor, att, ch, now, list); !errors.Is(err, devattest.ErrApplication) {
		t.Fatalf("a vendor chain with the automation signer: %v", err)
	}
	if b, err := devattest.VerifyAttest(&vendor, attest(opts(func(o *enclavetest.AndroidOptions) { o.Signers = [][]byte{dev[:]} })), ch, now, list); err != nil || b.SignerClass != devattest.ClassDevelopment {
		t.Fatalf("a vendor chain with the development signer: %v", err)
	}
	// A configuration of any other channel ignores the roots and the
	// automation signer, however it was built.
	for _, c := range []*releasecfg.Config{conf(releasecfg.ChannelProd), conf("")} {
		pol := enclave.ReleaseConfigFor(c, "i-1", enclave.DefaultRelayURL).DeviceAttest
		if len(pol.AndroidAutomationRoots) != 0 || len(pol.AndroidRoots) != len(pins.GoogleAttestationRoots()) {
			t.Fatalf("%q: roots %d, automation roots %d", c.Channel, len(pol.AndroidRoots), len(pol.AndroidAutomationRoots))
		}
		for _, sg := range pol.AndroidSigners {
			if sg.Class == devattest.ClassAutomation {
				t.Fatalf("%q pins the automation signer", c.Channel)
			}
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
	want := 0
	if ch == releasecfg.ChannelStaging {
		want = len(c.AutomationRoots())
	}
	if got := len(cfg.DeviceAttest.AndroidAutomationRoots); got != want || len(cfg.DeviceAttest.AndroidRoots) != len(pins.GoogleAttestationRoots()) {
		t.Fatalf("channel %q: %d automation roots (want %d), %d vendor roots", ch, got, want, len(cfg.DeviceAttest.AndroidRoots))
	}
	if ch == releasecfg.ChannelProd {
		for _, sg := range cfg.DeviceAttest.AndroidSigners {
			if sg.Class == devattest.ClassAutomation || sg.Class == devattest.ClassDevelopment {
				t.Fatalf("a %s signer in a production image", sg.Class)
			}
		}
	}
}
