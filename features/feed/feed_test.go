package feed

import (
	"context"
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

type listed struct {
	Items []struct {
		ID     string `json:"item_id"`
		Seq    uint64 `json:"seq"`
		Kind   string `json:"kind"`
		Status string `json:"status"`
		Title  string `json:"title"`
	} `json:"items"`
	Seq uint64 `json:"seq"`
}

func list(t *testing.T, f *Feature, h *featuretest.Host, body string) listed {
	t.Helper()
	r := featuretest.Call(f, h, t0, "app", "feed.list", body)
	var l listed
	if !r.OK() || json.Unmarshal(r.Body, &l) != nil {
		t.Fatalf("feed.list %s: %q", body, r.Code)
	}
	return l
}

func TestItemsAndSync(t *testing.T) {
	f, h := New(), featuretest.NewHost()
	rec(f, h, t0, vault.Activity{Kind: "connection.request", Ref: "p1", Feed: true})
	rec(f, h, t0, vault.Activity{Kind: "audit.only", Audit: true})
	rec(f, h, t0.Add(time.Second), vault.Activity{Kind: "credential.password_failed", Feed: true, Priority: "high"})
	if ev := h.SentOfType("feed.event"); len(ev) != 2 || ev[0].To != "devices" {
		t.Fatalf("feed.event: %+v", ev)
	}
	l := list(t, f, h, `{}`)
	if len(l.Items) != 2 || l.Items[0].Kind != "credential.password_failed" || l.Seq != 2 {
		t.Fatalf("list: %+v", l)
	}
	first := l.Items[1].ID
	h.Reset()
	r := featuretest.Call(f, h, t0, "desktop", "feed.update", `{"item_id":"`+first+`","status":"read"}`)
	if !r.OK() || !strings.Contains(string(r.Body), `"read"`) {
		t.Fatalf("update: %q %s", r.Code, r.Body)
	}
	if ev := h.SentOfType("sync.event"); len(ev) != 1 || ev[0].To != "devices-except:dev-desktop" || !strings.Contains(string(ev[0].Body), "feed.updated") {
		t.Fatal("sync.event feed.updated")
	}
	if l := list(t, f, h, `{"status":"read"}`); len(l.Items) != 1 || l.Items[0].ID != first {
		t.Fatal("status filter")
	}
	if r := featuretest.Call(f, h, t0, "app", "feed.delete", `{"item_id":"`+first+`"}`); !r.OK() {
		t.Fatal(r.Code)
	}
	if r := featuretest.Call(f, h, t0, "app", "feed.get", `{"item_id":"`+first+`"}`); r.Code != "not_found" {
		t.Fatal("deleted item readable")
	}
	// Catch-up after seq 2 sees the update and the tombstone.
	l = list(t, f, h, `{"after_seq":2}`)
	if len(l.Items) != 1 || l.Items[0].Status != "deleted" || l.Seq != 4 {
		t.Fatalf("catch-up: %+v", l)
	}
	g := New()
	featuretest.RoundTrip(t, f, g)
	if len(g.Items()) != 2 {
		t.Fatal("round trip")
	}
}

func TestGuides(t *testing.T) {
	f, h := New(), featuretest.NewHost()
	body := `{"guides":[{"guide_id":"welcome","version":1,"title":"Welcome","message":"Hi"},{"guide_id":"pin","version":2,"title":"PIN","message":"..","priority":"high"}]}`
	r := featuretest.Call(f, h, t0, "app", "guide.sync", body)
	if !r.OK() || string(r.Body) != `{"created":2,"updated":0}` {
		t.Fatalf("sync: %s", r.Body)
	}
	// Idempotent.
	if r := featuretest.Call(f, h, t0, "desktop", "guide.sync", body); string(r.Body) != `{"created":0,"updated":0}` {
		t.Fatalf("repeat: %s", r.Body)
	}
	r = featuretest.Call(f, h, t0, "app", "guide.sync", `{"guides":[{"guide_id":"welcome","version":2,"title":"Welcome!","message":"Hi"}]}`)
	if string(r.Body) != `{"created":0,"updated":1}` {
		t.Fatalf("update: %s", r.Body)
	}
	if l := list(t, f, h, `{}`); len(l.Items) != 3 || l.Items[0].Title != "Welcome!" {
		t.Fatalf("items: %+v", l)
	}
}

func TestAuthorizationAndBadBodies(t *testing.T) {
	f, h := New(), featuretest.NewHost()
	for _, typ := range []string{"feed.list", "feed.update", "guide.sync"} {
		if r := featuretest.Call(f, h, t0, "agent", typ, `{}`); r.Code != "forbidden" {
			t.Fatalf("agent may send %s", typ)
		}
	}
	for _, c := range []struct{ typ, body string }{
		{"feed.list", `{"status":"deleted"}`},
		{"feed.list", `{"limit":0}`},
		{"feed.update", `{"item_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V"}`},
		{"feed.update", `{"item_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V","status":"deleted"}`},
		{"feed.update", `{"item_id":"x","status":"read"}`},
		{"guide.sync", `{"guides":[{"guide_id":"A","version":1,"title":"t","message":""}]}`},
		{"guide.sync", `{"guides":[{"guide_id":"a","version":0,"title":"t","message":""}]}`},
		{"guide.sync", `{"guides":[{"guide_id":"a","version":1,"title":"","message":""}]}`},
		{"guide.sync", `{"guides":[{"guide_id":"a","version":1,"title":"t","message":""},{"guide_id":"a","version":2,"title":"t","message":""}]}`},
	} {
		if r := featuretest.Call(f, h, t0, "app", c.typ, c.body); r.Code != "bad_request" {
			t.Errorf("%s %s: %q", c.typ, c.body, r.Code)
		}
	}
	if r := featuretest.Call(f, h, t0, "app", "feed.update", `{"item_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V","status":"read"}`); r.Code != "not_found" {
		t.Error("unknown item")
	}
}

func TestRetention(t *testing.T) {
	f, h := New(), featuretest.NewHost()
	rec(f, h, t0, vault.Activity{Kind: "a", Feed: true})
	rec(f, h, t0.Add(31*24*time.Hour), vault.Activity{Kind: "b", Feed: true})
	if it := f.Items(); len(it) != 1 || it[0].Kind != "b" {
		t.Fatal("default 30-day retention")
	}
	for i := 0; i < MaxItems+3; i++ {
		rec(f, h, t0.Add(31*24*time.Hour), vault.Activity{Kind: "c", Feed: true})
	}
	if n := len(f.Items()); n != MaxItems {
		t.Fatalf("cap: %d", n)
	}
}

func FuzzParseList(f *testing.F) {
	f.Add([]byte(`{"status":"active","after_seq":3,"limit":5}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if q, err := ParseList(b); err == nil && (q.Limit < 1 || q.Limit > MaxLimit) {
			t.Fatal("bad limit accepted")
		}
	})
}

func FuzzParseUpdate(f *testing.F) {
	f.Add([]byte(`{"item_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V","status":"archived","priority":"low"}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if u, err := ParseUpdate(b); err == nil && u.Status == StatusDeleted {
			t.Fatal("delete through update")
		}
	})
}

func FuzzParseGuides(f *testing.F) {
	f.Add([]byte(`{"guides":[{"guide_id":"a","version":1,"title":"t","message":"m","priority":"urgent"}]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		gs, err := ParseGuides(b)
		if err != nil {
			return
		}
		if len(gs) > MaxGuides {
			t.Fatal("too many guides")
		}
		for _, g := range gs {
			if g.Version < 1 || g.Title == "" || !priorities[g.Priority] {
				t.Fatal("invalid guide accepted")
			}
		}
	})
}
