package releasecfg

import (
	"errors"
	"strings"
	"testing"
)

// withCallsURL adds a calls_url member (raw JSON value) to a test file.
func withCallsURL(s, raw string) string {
	return strings.Replace(s, `"features":`, `"calls_url":`+raw+`,"features":`, 1)
}

// VAULT-MESSAGING §10.10, §11.10.8: calls_url is optional; a file that names one must name its own channel's
// issuer, and production has none until it has a calling service.
func TestCallsURL(t *testing.T) {
	if f, err := Check(ChannelStaging, []byte(staging(complete(t)))); err != nil || f.CallsURL != "" {
		t.Fatalf("absent: %q %v", f.CallsURL, err)
	}
	f, err := Check(ChannelStaging, []byte(withCallsURL(staging(complete(t)), `"https://calls.staging.vettid.org"`)))
	if err != nil || f.CallsURL != "https://calls.staging.vettid.org" {
		t.Fatalf("staging: %v", err)
	}
	for name, s := range map[string]string{
		"staging names production's": withCallsURL(staging(complete(t)), `"https://calls.vettid.org"`),
		"staging names another host": withCallsURL(staging(complete(t)), `"https://calls.example.org"`),
		"staging, a path":            withCallsURL(staging(complete(t)), `"https://calls.staging.vettid.org/"`),
		"staging, not a string":      withCallsURL(staging(complete(t)), `1`),
		"staging, empty":             withCallsURL(staging(complete(t)), `""`),
		"production names staging's": withCallsURL(complete(t), `"https://calls.staging.vettid.org"`),
		"production names its own":   withCallsURL(complete(t), `"https://calls.vettid.org"`),
	} {
		if _, err := Parse([]byte(s)); !errors.Is(err, ErrFormat) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
