package grants

import (
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/features/itemspec"
)

// VAULT-MESSAGING 0.23.1: errata to 0.23.0 from its implementation
// (vettid-vault #52), §10.12.

// retry_after is at most 86,400 seconds: the vault never sends more (a
// wait is clamped) and a received data.value with more is malformed.
func TestRetryAfterMax(t *testing.T) {
	if retryAfter(48*time.Hour) != MaxRetryAfter || retryAfter(24*time.Hour) != MaxRetryAfter || MaxRetryAfter != 86400 {
		t.Fatal("retry_after not clamped to 86,400")
	}
	base := `{"fetch_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0A","grant_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0B","error":"rate_limited","retry_after":`
	if v, err := ParseValue([]byte(base + `86400}`)); err != nil || v.RetryAfter != 86400 {
		t.Fatalf("86400: %+v %v", v, err)
	}
	if _, err := ParseValue([]byte(base + `86401}`)); err == nil {
		t.Fatal("retry_after 86401 accepted")
	}
}

// A received `limits: {}` means no limits: the grant carries none.
func TestEmptyLimitsMeanNone(t *testing.T) {
	g, err := ParseDescriptor([]byte(`{"grant_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0A","kind":"item","ref":"01JB2Z6V9K3M4N5P6Q7R8S9T0B",` +
		`"name":"N","category":"login","labels":[],"limits":{}}`))
	if err != nil || g.Limits.Set() || g.Limits != (itemspec.RateLimits{}) {
		t.Fatalf("limits {}: %+v %v", g.Limits, err)
	}
}

// The rule windows count only fetches through the rule grants of the
// item: a fetch through a one-off grant of the same item is neither
// refused by them nor counted in them.
func TestOneOffFetchNotInRuleWindows(t *testing.T) {
	a, b := pair()
	share(t, a, b, `{"request_id":"RID","approve":true}`)
	relay(t, a, b, t0, "data.decided")
	gid := ""
	for _, x := range a.f.Given() {
		if x.Ref == s3 && x.RuleID == "" {
			gid = x.ID
		}
	}
	a.it.retry = map[string]time.Duration{s3: time.Hour} // the rule windows of s3 are full
	if _, e := fetch(t, a, b, t0, gid); e != "" {
		t.Fatalf("one-off fetch refused by the rule windows: %q", e)
	}
	if a.it.fetched[s3] != 0 {
		t.Fatalf("one-off fetch counted in the rule windows (%d)", a.it.fetched[s3])
	}
	if strings.Contains(string(last(t, a.h, "data.value").Body), "retry_after") {
		t.Fatal("retry_after on a one-off fetch")
	}
}
