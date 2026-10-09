package grants

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/features/itemspec"
	"github.com/vettid/vettid-vault/vault"
)

// VAULT-MESSAGING 0.23.0 §10.12: limits on rule grants and descriptors,
// rate_limited with retry_after (checked last, no use counted, audited,
// passed on to the device that fetched), uses across the rule grants of
// an item.

func TestRateLimitedWire(t *testing.T) {
	for body, ok := range map[string]bool{
		`{"fetch_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0A","grant_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0B","error":"rate_limited","retry_after":12}`: true,
		`{"fetch_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0A","grant_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0B","error":"rate_limited"}`:                  false, // retry_after required
		`{"fetch_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0A","grant_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0B","error":"rate_limited","retry_after":0}`:  false,
		`{"fetch_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0A","grant_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0B","error":"exhausted","retry_after":5}`:     false, // only with rate_limited
		`{"fetch_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0A","grant_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0B","error":"expired"}`:                       true,
	} {
		v, err := ParseValue([]byte(body))
		if (err == nil) != ok {
			t.Errorf("%s: %v", body, err)
		}
		if ok && v.Error == ErrRateLimited && v.RetryAfter != 12 {
			t.Errorf("retry_after %d", v.RetryAfter)
		}
	}
	d := `{"grant_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0A","kind":"item","ref":"01JB2Z6V9K3M4N5P6Q7R8S9T0B","name":"N","category":"login","labels":[]`
	for lim, ok := range map[string]bool{`{"per_hour":5,"per_day":20}`: true, `{"per_day":1}`: true, `{}`: true, `{"per_hour":0}`: false,
		`{"per_hour":3601}`: false, `{"per_day":86401}`: false, `5`: false} {
		g, err := ParseDescriptor([]byte(d + `,"limits":` + lim + `}`))
		if (err == nil) != ok {
			t.Errorf("limits %s: %v", lim, err)
		}
		if ok && lim == `{"per_hour":5,"per_day":20}` && g.Limits != (itemspec.RateLimits{PerHour: 5, PerDay: 20}) {
			t.Errorf("parsed %+v", g.Limits)
		}
	}
	if retryAfter(1500*time.Millisecond) != 2 || retryAfter(0) != 1 || retryAfter(time.Hour) != 3600 {
		t.Fatal("retry_after rounding")
	}
}

// A rule grant carries its rule's limits (given: current, received: as
// its descriptor said); past a limit the member's vault refuses after the
// other checks with rate_limited and retry_after, audited, no use
// counted; the asking vault passes both on in grant.value.
func TestRateLimitedFetch(t *testing.T) {
	a, b := pair()
	s := vault.NewSession(context.TODO(), a.h, vault.PeerInfo{}, t0, nil)
	m, _ := a.it.Readable(s1, nil)
	rule := "01JB2Z6V9K3M4N5P6Q7R8S9T09"
	lim := itemspec.RateLimits{PerHour: 5}
	ids, err := a.f.IssueRuleGrants(s, "cB", rule, []itemspec.Meta{m}, 3, lim, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if sh := string(last(t, a.h, "data.shared").Body); !strings.Contains(sh, `"uses":3,"limits":{"per_hour":5}}`) {
		t.Fatalf("descriptor %s", sh)
	}
	relay(t, a, b, t0, "data.shared")
	if l := string(ok(t, call(t, b, t0, "app", "grant.list", `{}`))["received"]); !strings.Contains(l, `"limits":{"per_hour":5}`) {
		t.Fatalf("received %s", l)
	}
	if _, e := fetch(t, a, b, t0, ids[0]); e != "" {
		t.Fatal(e)
	}
	if a.it.fetched[s1] != 1 {
		t.Fatalf("counted in the rule windows %d times", a.it.fetched[s1])
	}
	// The windows are full: refused, retry_after passed on.
	a.it.retry = map[string]time.Duration{s1: 90 * time.Second}
	if _, e := fetch(t, a, b, t0, ids[0]); e != ErrRateLimited {
		t.Fatalf("error %q", e)
	}
	if v := string(last(t, b.h, "grant.value").Body); !strings.Contains(v, `"error":"rate_limited","retry_after":90`) {
		t.Fatalf("grant.value %s", v)
	}
	if !a.h.HasActivity("drop.grant_rate_limited") {
		t.Fatal("not audited")
	}
	g := a.f.Given()[0]
	if g.Used != 1 || g.State != StateActive || a.it.fetched[s1] != 1 {
		t.Fatalf("a refusal counted: %+v", g)
	}
	// The other refusals come first: an unavailable item is unavailable.
	delete(a.it.items, s1)
	if _, e := fetch(t, a, b, t0, ids[0]); e != ErrUnavailable {
		t.Fatalf("checked last: %q", e)
	}
	// SetRuleLimits: the given grant carries the rule's current limits.
	a.f.SetRuleLimits(s, rule, itemspec.RateLimits{PerDay: 9})
	if l := string(ok(t, call(t, a, t0, "app", "grant.list", `{}`))["given"]); !strings.Contains(l, `"limits":{"per_day":9}`) {
		t.Fatalf("given %s", l)
	}
	// A one-off grant has no rate limit.
	a.it = newItems()
	a.f.items = a.it
	share(t, a, b, `{"request_id":"RID","approve":true}`)
	relay(t, a, b, t0, "data.decided")
	a.it.retry = map[string]time.Duration{s3: time.Hour}
	ev := string(last(t, b.h, "grant.event").Body)
	if strings.Contains(ev, "limits") {
		t.Fatalf("one-off grant with limits: %s", ev)
	}
	gid := ""
	for _, x := range a.f.Given() {
		if x.Ref == s3 && x.RuleID == "" {
			gid = x.ID
		}
	}
	if _, e := fetch(t, a, b, t0, gid); e != "" {
		t.Fatalf("one-off grant rate limited: %q", e)
	}
}

// uses across the rule grants of an item (owner's review of #181): one
// use on each that has uses, exhausted if any is spent, all spent
// together, uses_left the least; a one-off grant of the item is not among
// them.
func TestRuleGrantsUsesTogether(t *testing.T) {
	a, b := pair()
	s := vault.NewSession(context.TODO(), a.h, vault.PeerInfo{}, t0, nil)
	m, _ := a.it.Readable(s1, nil)
	g1, _ := a.f.IssueRuleGrants(s, "cB", "01JB2Z6V9K3M4N5P6Q7R8S9T07", []itemspec.Meta{m}, 2, itemspec.RateLimits{}, time.Time{})
	relay(t, a, b, t0, "data.shared")
	g2, _ := a.f.IssueRuleGrants(s, "cB", "01JB2Z6V9K3M4N5P6Q7R8S9T08", []itemspec.Meta{m}, 0, itemspec.RateLimits{}, time.Time{})
	relay(t, a, b, t0, "data.shared")
	if _, e := fetch(t, a, b, t0, g2[0]); e != "" {
		t.Fatal(e)
	}
	if v := string(last(t, a.h, "data.value").Body); !strings.Contains(v, `"uses_left":1`) {
		t.Fatalf("the least uses_left through a grant without uses: %s", v)
	}
	a.h.Reset()
	if _, e := fetch(t, a, b, t0, g2[0]); e != "" {
		t.Fatal(e)
	}
	for _, x := range a.f.Given() {
		if x.State != StateUsed {
			t.Fatalf("not all spent together: %+v", x)
		}
	}
	if n := len(a.h.SentOfType("sync.event")); n < 2 {
		t.Fatalf("%d grant.changed", n)
	}
	for _, id := range []string{g1[0], g2[0]} {
		if _, e := fetch(t, a, b, t0, id); e != ErrExhausted {
			t.Fatalf("%s: %q", id, e)
		}
	}
}
