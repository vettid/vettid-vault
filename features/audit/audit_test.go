package audit

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/featuretest"
	"github.com/vettid/vettid-vault/vault"
)

var t0 = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

func rec(f *Feature, h *featuretest.Host, at time.Time, a vault.Activity) {
	f.RecordActivity(vault.NewSession(context.Background(), h, vault.PeerInfo{}, at, nil), a)
}

func TestChainAndList(t *testing.T) {
	f, h := New(), featuretest.NewHost()
	rec(f, h, t0, vault.Activity{Kind: "connection.added", ConnectionID: "c1", Audit: true})
	rec(f, h, t0.Add(time.Second), vault.Activity{Kind: "message.sent", ConnectionID: "c1", Ref: "m1", Direction: "out", Audit: true})
	rec(f, h, t0.Add(2*time.Second), vault.Activity{Kind: "feed.only", Feed: true}) // not an audit activity
	rec(f, h, t0.Add(3*time.Second), vault.Activity{Kind: "drop.rate_limited", ConnectionID: "c2", Audit: true})
	es := f.Entries()
	if len(es) != 3 {
		t.Fatalf("%d entries", len(es))
	}
	prev := make([]byte, 32)
	for i, e := range es {
		if e.Seq != uint64(i+1) || !bytes.Equal(e.Prev, prev) || !bytes.Equal(e.Hash, Hash(prev, &e)) {
			t.Fatalf("entry %d does not chain", i)
		}
		prev = e.Hash
	}
	r := featuretest.Call(f, h, t0, "app", "connection.audit.list", `{"connection_id":"c1"}`)
	var out struct {
		Entries []struct {
			Kind string `json:"kind"`
			Seq  uint64 `json:"seq"`
		} `json:"entries"`
		Head string `json:"head"`
	}
	if err := json.Unmarshal(r.Body, &out); err != nil || len(out.Entries) != 2 || out.Entries[0].Kind != "message.sent" {
		t.Fatalf("per-connection list: %s", r.Body)
	}
	if out.Head != base64.StdEncoding.EncodeToString(prev) {
		t.Fatal("head")
	}
	r = featuretest.Call(f, h, t0, "desktop", "audit.list", `{"kinds":["drop"]}`)
	if !strings.Contains(string(r.Body), "drop.rate_limited") || strings.Contains(string(r.Body), "message.sent") {
		t.Fatalf("kinds filter: %s", r.Body)
	}
	// Paging.
	r = featuretest.Call(f, h, t0, "app", "audit.list", `{"limit":2}`)
	if !strings.Contains(string(r.Body), `"next_before_seq":2`) {
		t.Fatalf("paging: %s", r.Body)
	}
	r = featuretest.Call(f, h, t0, "app", "audit.list", `{"limit":2,"before_seq":2}`)
	if !strings.Contains(string(r.Body), `"connection.added"`) || strings.Contains(string(r.Body), "next_before_seq") {
		t.Fatalf("page 2: %s", r.Body)
	}
}

func TestAuthorizationAndBadBodies(t *testing.T) {
	f, h := New(), featuretest.NewHost()
	for _, k := range []string{"agent", "connection:c1"} {
		if r := featuretest.Call(f, h, t0, k, "audit.list", `{}`); r.Code != "forbidden" {
			t.Fatalf("%s read the audit log", k)
		}
	}
	for _, b := range []string{`{"limit":0}`, `{"limit":501}`, `{"kinds":[]}`, `{"kinds":[1]}`, `{"connection_id":""}`, `{"before_seq":0}`} {
		if r := featuretest.Call(f, h, t0, "app", "audit.list", b); r.Code != "bad_request" {
			t.Errorf("%s: %q", b, r.Code)
		}
	}
	if r := featuretest.Call(f, h, t0, "app", "connection.audit.list", `{}`); r.Code != "bad_request" {
		t.Error("connection.audit.list without connection_id")
	}
}

func TestRetention(t *testing.T) {
	f, h := New(), featuretest.NewHost()
	rec(f, h, t0, vault.Activity{Kind: "a", Audit: true})
	rec(f, h, t0.Add(Retention+time.Hour), vault.Activity{Kind: "b", Audit: true})
	es := f.Entries()
	if len(es) != 1 || es[0].Kind != "b" || es[0].Seq != 2 {
		t.Fatalf("retention: %+v", es)
	}
	// The oldest kept entry still names the pruned entry's hash.
	if bytes.Equal(es[0].Prev, make([]byte, 32)) {
		t.Fatal("chain restarted after pruning")
	}
	for i := 0; i < MaxEntries+5; i++ {
		rec(f, h, t0.Add(Retention+time.Hour), vault.Activity{Kind: "c", Audit: true})
	}
	if n := len(f.Entries()); n != MaxEntries {
		t.Fatalf("cap: %d", n)
	}
	g := New()
	featuretest.RoundTrip(t, f, g)
	if len(g.Entries()) != MaxEntries {
		t.Fatal("round trip")
	}
}

// §10.9: drop.* entries are bounded per principal and kind; the rest of
// the log is not displaced.
func TestDropThrottle(t *testing.T) {
	f, h := New(), featuretest.NewHost()
	rec(f, h, t0, vault.Activity{Kind: "connection.added", ConnectionID: "c1", Audit: true})
	for i := 0; i < 500; i++ {
		rec(f, h, t0.Add(time.Duration(i)*time.Second), vault.Activity{Kind: "drop.rate_limited", ConnectionID: "c1", Audit: true})
	}
	var drops, suppressed int
	for _, e := range f.Entries() {
		switch e.Kind {
		case "drop.rate_limited":
			drops++
		case "drop.suppressed":
			suppressed++
		}
	}
	if drops != DropsPerHour || suppressed != 1 {
		t.Fatalf("drops %d suppressed %d", drops, suppressed)
	}
	rec(f, h, t0.Add(2*time.Hour), vault.Activity{Kind: "drop.rate_limited", ConnectionID: "c1", Audit: true})
	if es := f.Entries(); es[len(es)-1].Kind != "drop.rate_limited" {
		t.Fatal("window did not reset")
	}
}

// §10.9: an app that holds (seq, hash) checks that the log extends it.
func TestAfterSeqExtendsAnchor(t *testing.T) {
	f, h := New(), featuretest.NewHost()
	for i := 0; i < 5; i++ {
		rec(f, h, t0.Add(time.Duration(i)*time.Second), vault.Activity{Kind: "k", Audit: true})
	}
	anchor := f.Entries()[1] // seq 2
	r := featuretest.Call(f, h, t0, "app", "audit.list", `{"after_seq":2,"limit":2}`)
	var out struct {
		Entries []struct {
			Seq  uint64 `json:"seq"`
			Prev string `json:"prev"`
			Hash string `json:"hash"`
		} `json:"entries"`
		Next uint64 `json:"next_after_seq"`
	}
	if err := json.Unmarshal(r.Body, &out); err != nil || len(out.Entries) != 2 || out.Entries[0].Seq != 3 || out.Next != 4 {
		t.Fatalf("after_seq: %s", r.Body)
	}
	if out.Entries[0].Prev != base64.StdEncoding.EncodeToString(anchor.Hash) {
		t.Fatal("does not extend the anchor")
	}
	if r := featuretest.Call(f, h, t0, "app", "audit.list", `{"after_seq":1,"before_seq":3}`); r.Code != "bad_request" {
		t.Fatal("after_seq with before_seq accepted")
	}
}

func FuzzParseQuery(f *testing.F) {
	f.Add([]byte(`{"connection_id":"c","kinds":["drop","message.sent"],"before_seq":9,"limit":10}`), false)
	f.Fuzz(func(t *testing.T, b []byte, needConn bool) {
		q, err := ParseQuery(b, needConn)
		if err != nil {
			return
		}
		if q.Limit < 1 || q.Limit > MaxLimit || len(q.Kinds) > MaxKinds || (needConn && q.ConnectionID == "") {
			t.Fatal("invalid query accepted")
		}
	})
}
