package parent

import (
	"net/url"
	"slices"
	"testing"

	"github.com/vettid/vettid-vault/enclave/releasecfg"
)

// Every channel's calling-service issuer is on the parent's allowlist, and nothing else is: the allowlist names
// exactly the issuers some channel may pin (production has none yet).
func TestCallsHostsMatchChannels(t *testing.T) {
	var want []string
	for _, ch := range []string{releasecfg.ChannelProd, releasecfg.ChannelStaging} {
		u := releasecfg.CallsURLs[ch]
		if u == "" {
			continue
		}
		p, err := url.Parse(u)
		if err != nil || p.Scheme != "https" || p.Port() != "" || p.Path != "" {
			t.Fatalf("%s calls URL %q", ch, u)
		}
		want = append(want, p.Hostname())
	}
	slices.Sort(want)
	got := slices.Clone(CallsHosts)
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("CallsHosts = %v, the channels' issuers are %v", got, want)
	}
	allow := DefaultAllow("relay.example.org", "us-east-1")
	for _, h := range want {
		if !slices.Contains(allow, h) {
			t.Errorf("%s not in DefaultAllow", h)
		}
	}
	if slices.Contains(allow, "calls.vettid.org") {
		t.Error("calls.vettid.org allowed before production has a calling service")
	}
}
