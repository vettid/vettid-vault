package enclave_test

import (
	"reflect"
	"testing"

	"github.com/vettid/vettid-vault/enclave"
	"github.com/vettid/vettid-vault/enclave/releasecfg"
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
	}
}
