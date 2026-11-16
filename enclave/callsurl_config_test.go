package enclave

import (
	"testing"

	"github.com/vettid/vettid-vault/enclave/releasecfg"
)

// The channel file's calls_url reaches the enclave's Config (and from there the vault processes' client).
func TestReleaseConfigCarriesCallsURL(t *testing.T) {
	rc := &releasecfg.Config{Channel: releasecfg.ChannelStaging, CallsURL: "https://calls.staging.vettid.org"}
	if cfg := releaseConfigFor(rc, "i-1", DefaultRelayURL); cfg.CallsURL != rc.CallsURL {
		t.Fatalf("CallsURL = %q", cfg.CallsURL)
	}
	if cfg := releaseConfigFor(&releasecfg.Config{Channel: releasecfg.ChannelStaging}, "i-1", DefaultRelayURL); cfg.CallsURL != "" {
		t.Fatalf("CallsURL without one = %q", cfg.CallsURL)
	}
}
