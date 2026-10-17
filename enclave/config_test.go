package enclave_test

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/vettid/vettid-vault/enclave"
	"github.com/vettid/vettid-vault/enclave/releasecfg"
	"github.com/vettid/vettid-vault/vms/devattest"
)

// The release device policy never carries development packages (the dev
// enclave's device policy file is the only setter), and its Android
// package is the embedded channel file's (0.26.0, §11.10.8): the
// channel's own, never a constant shared by the channels. A build without
// complete channel constants has no package, so Android attestation fails
// closed. Run with -tags vettid_channel_prod / vettid_channel_staging by
// `make channels`.
func TestReleaseConfigAndroidPackage(t *testing.T) {
	cfg := enclave.ReleaseConfig("i-1", enclave.DefaultRelayURL)
	if cfg.DeviceAttest == nil {
		t.Fatal("no device policy")
	}
	if len(cfg.DeviceAttest.AndroidDevPackages) != 0 {
		t.Fatalf("release policy has development packages: %v", cfg.DeviceAttest.AndroidDevPackages)
	}
	ch, c := releasecfg.Embedded()
	want, features := "", []string{}
	if c != nil {
		want, features = releasecfg.AndroidPackages[ch], c.Features
		if want == "" || c.AndroidPackage != want {
			t.Fatalf("%s: channel file package %q", ch, c.AndroidPackage)
		}
	}
	if got := cfg.DeviceAttest.AndroidPackage; got != want {
		t.Fatalf("channel %q: Android package %q, want %q", ch, got, want)
	}
	if got := enclave.ReleaseFeatures(); got == nil || !reflect.DeepEqual(got, features) {
		t.Fatalf("channel %q: features %v, want %v", ch, got, features)
	}
	if ch == releasecfg.ChannelStaging && c != nil {
		if want != "com.vettid.app.staging" || len(features) != 7 {
			t.Fatalf("staging: %q %v", want, features)
		}
	} // 0.27.0 (§11.7.1): the pinned signers reach the device policy with
	// their classes; unbound keys are accepted only by a staging image up
	// to S10, never by a production one; and no release configuration
	// behaves as a release from before the rule.
	if cfg.Before027 {
		t.Fatal("a release configuration with Before027")
	}
	pol := cfg.DeviceAttest
	if c == nil {
		if len(pol.AndroidSigners) != 0 || pol.AndroidAcceptUnbound {
			t.Fatalf("without complete constants: %d signers, unbound accepted %v", len(pol.AndroidSigners), pol.AndroidAcceptUnbound)
		}
		return
	}
	if len(pol.AndroidSigners) != len(c.AndroidSigners) {
		t.Fatalf("signers %d, the channel file pins %d", len(pol.AndroidSigners), len(c.AndroidSigners))
	}
	for i, sg := range c.AndroidSigners {
		if !bytes.Equal(pol.AndroidSigners[i].Digest, sg.Digest) || pol.AndroidSigners[i].Class != sg.Class || !devattest.ValidClass(sg.Class) {
			t.Fatalf("signer %d: %+v, the channel file says %+v", i, pol.AndroidSigners[i], sg)
		}
		if ch == releasecfg.ChannelProd && sg.Class == devattest.ClassDevelopment {
			t.Fatal("a development signer in a production image")
		}
	}
	wantUnbound := ch == releasecfg.ChannelStaging && c.Release <= 10
	if pol.AndroidAcceptUnbound != wantUnbound || ch == releasecfg.ChannelProd && pol.AndroidAcceptUnbound {
		t.Fatalf("channel %q release %d: unbound keys accepted %v, want %v", ch, c.Release, pol.AndroidAcceptUnbound, wantUnbound)
	}
}

// VAULT-MESSAGING 0.33.2 §11.14.4: the counter's record lock period comes
// from the embedded (measured) channel: a day in a staging image, 100
// years in a production one. Without complete channel constants it is
// zero, which the counter treats as 100 years. Run with -tags
// vettid_channel_prod / vettid_channel_staging by `make channels`.
func TestReleaseConfigCounterLock(t *testing.T) {
	cfg := enclave.ReleaseConfig("i-1", enclave.DefaultRelayURL)
	ch, c := releasecfg.Embedded()
	if c == nil {
		if cfg.Recovery.CounterLock != 0 {
			t.Fatalf("no channel constants, counter lock %v", cfg.Recovery.CounterLock)
		}
		return
	}
	want := releasecfg.ProdCounterLock
	if ch == releasecfg.ChannelStaging {
		want = releasecfg.StagingCounterLock
	}
	if cfg.Recovery.CounterLock != want {
		t.Fatalf("channel %q: counter lock %v, want %v", ch, cfg.Recovery.CounterLock, want)
	}
}

// 0.35.0 (§11.10.8, "iOS App ID"): the release device policy's iOS App ID
// is the embedded channel file's, never a constant shared by the
// channels, and it carries no development App ID and no development
// environment (the dev enclave's device policy file is their only
// setter). A build without complete channel constants has no App ID, so
// App Attest fails closed. Run with -tags vettid_channel_prod /
// vettid_channel_staging by `make channels`.
func TestReleaseConfigIOSAppID(t *testing.T) {
	cfg := enclave.ReleaseConfig("i-1", enclave.DefaultRelayURL)
	pol := cfg.DeviceAttest
	if pol == nil {
		t.Fatal("no device policy")
	}
	if len(pol.IOSDevAppIDs) != 0 || pol.IOSDevelopmentEnvironment {
		t.Fatalf("release policy has development iOS members: %v %v", pol.IOSDevAppIDs, pol.IOSDevelopmentEnvironment)
	}
	if pol.IOSRoots == nil {
		t.Fatal("no Apple root")
	}
	ch, c := releasecfg.Embedded()
	want := ""
	if c != nil {
		want = releasecfg.IOSAppIDs[ch]
		if want == "" || c.IOSAppID != want {
			t.Fatalf("%s: channel file iOS App ID %q", ch, c.IOSAppID)
		}
	}
	if pol.IOSAppID != want {
		t.Fatalf("channel %q: iOS App ID %q, want %q", ch, pol.IOSAppID, want)
	}
	if ch == releasecfg.ChannelStaging && c != nil && want != "3X25CJ86MV.com.vettid.app.staging" {
		t.Fatalf("staging: %q", want)
	}
}
