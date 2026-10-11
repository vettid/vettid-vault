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
