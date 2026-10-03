package profile

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/featuretest"
	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
)

func call(f *Feature, h *featuretest.Host, kind, typ, body string) featuretest.Result {
	return featuretest.Call(f, h, time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC), kind, typ, body)
}

func TestAuthorization(t *testing.T) {
	f, h := New(), featuretest.NewHost()
	if r := call(f, h, "agent", "profile.get", `{}`); r.Code != "forbidden" {
		t.Fatal("agent read the profile")
	}
	if r := call(f, h, "connection:c1", "profile.set", `{"version":0}`); r.Code != "forbidden" {
		t.Fatal("peer set the profile")
	}
	h.AddConnection("c1")
	if r := call(f, h, "app", "profile.update", `{"version":1,"name":"x","fields":{}}`); r.Code != "forbidden" {
		t.Fatal("a device sent profile.update")
	}
}

func TestSetSharesOnlySharedFields(t *testing.T) {
	f, h := New(), featuretest.NewHost()
	h.AddConnection("c1")
	h.AddConnection("c2")
	h.DownConns["c2"] = true // one peer unreachable: the others still get it
	r := call(f, h, "app", "profile.set", `{"version":0,"name":"Ada","set":{"contact.email":{"value":"ada@example.org","label":"work"},"id.passport":{"value":"X123"}},"shared":["contact.email"],"order":["id.passport","contact.email"]}`)
	if !r.OK() {
		t.Fatal(r.Code)
	}
	if f.DisplayName() != "Ada" {
		t.Fatal("display name")
	}
	ups := h.SentOfType("profile.update")
	if len(ups) != 1 || ups[0].To != "c1" {
		t.Fatalf("profile.update: %+v", ups)
	}
	if strings.Contains(string(ups[0].Body), "X123") || !strings.Contains(string(ups[0].Body), "ada@example.org") {
		t.Fatalf("shared view: %s", ups[0].Body)
	}
	if ev := h.SentOfType("sync.event"); len(ev) != 1 || ev[0].To != "devices-except:dev-app" {
		t.Fatal("sync.event")
	}
	// A private-only change does not go to connections.
	h.Reset()
	if r := call(f, h, "desktop", "profile.set", `{"version":1,"set":{"id.passport":{"value":"Y456"}}}`); !r.OK() {
		t.Fatal(r.Code)
	}
	if len(h.SentOfType("profile.update")) != 0 {
		t.Fatal("private change broadcast")
	}
	// Stale version.
	if r := call(f, h, "app", "profile.set", `{"version":1,"name":"B"}`); r.Code != "conflict" {
		t.Fatalf("stale version: %q", r.Code)
	}
	// Deleting a shared field removes it from the lists and broadcasts.
	h.Reset()
	if r := call(f, h, "app", "profile.set", `{"version":2,"delete":["contact.email"]}`); !r.OK() {
		t.Fatal(r.Code)
	}
	g := call(f, h, "app", "profile.get", `{}`).Obj(t)
	if string(g["shared"]) != "[]" || string(g["order"]) != `["id.passport"]` {
		t.Fatalf("lists after delete: %s %s", g["shared"], g["order"])
	}
	if len(h.SentOfType("profile.update")) != 1 {
		t.Fatal("removal of a shared field not broadcast")
	}
	// The new connection gets the profile on activation (§9.3).
	h.Reset()
	h.AddConnection("c3")
	f.ConnectionAdded(vault.NewSession(context.Background(), h, vault.PeerInfo{}, time.Now(), nil), "c3")
	if ups := h.SentOfType("profile.update"); len(ups) != 1 || ups[0].To != "c3" {
		t.Fatal("no profile.update on activation")
	}
	g2 := New()
	featuretest.RoundTrip(t, f, g2)
	if g2.DisplayName() != "Ada" {
		t.Fatal("round trip")
	}
}

func TestSetBad(t *testing.T) {
	f, h := New(), featuretest.NewHost()
	for _, b := range []string{
		`{}`,
		`{"version":0,"set":{"Bad Key":{"value":"x"}}}`,
		`{"version":0,"set":{"k":{"value":""}}}`,
		`{"version":0,"set":{"k":{"value":"x","label":"` + strings.Repeat("l", MaxLabel+1) + `"}}}`,
		`{"version":0,"shared":["missing"]}`,
		`{"version":0,"shared":["k","k"]}`,
		`{"version":0,"photo":"` + base64.StdEncoding.EncodeToString([]byte("GIF89a")) + `"}`,
		`{"version":0,"name":"` + strings.Repeat("n", MaxName+1) + `"}`,
	} {
		if r := call(f, h, "app", "profile.set", b); r.Code != "bad_request" {
			t.Errorf("%.80s: %q", b, r.Code)
		}
	}
	png := base64.StdEncoding.EncodeToString([]byte("\x89PNG\r\n\x1a\nrest"))
	if r := call(f, h, "app", "profile.set", `{"version":0,"photo":"`+png+`"}`); !r.OK() {
		t.Fatal("png refused")
	}
	if r := call(f, h, "app", "profile.set", `{"version":1,"photo":""}`); !r.OK() {
		t.Fatal("photo removal refused")
	}
}

func TestUpdateFromPeer(t *testing.T) {
	f, h := New(), featuretest.NewHost()
	h.AddConnection("c1")
	r := call(f, h, "connection:c1", "profile.update", `{"version":3,"name":"Bob","fields":{"contact.email":{"value":"bob@example.org"}}}`)
	if !r.OK() {
		t.Fatal(r.Code)
	}
	o, err := strictjson.ParseObject(h.Profiles["c1"])
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := o.String("name"); n != "Bob" {
		t.Fatal("stored profile")
	}
	if ev := h.SentOfType("connection.event"); len(ev) != 1 || !strings.Contains(string(ev[0].Body), `"profile"`) {
		t.Fatal("connection.event profile")
	}
	// Older or repeated versions are ignored (§8.4).
	call(f, h, "connection:c1", "profile.update", `{"version":2,"name":"Old","fields":{}}`)
	call(f, h, "connection:c1", "profile.update", `{"version":3,"name":"Same","fields":{}}`)
	o, _ = strictjson.ParseObject(h.Profiles["c1"])
	if n, _ := o.String("name"); n != "Bob" {
		t.Fatal("older profile applied")
	}
}

func FuzzParseSet(f *testing.F) {
	f.Add([]byte(`{"version":0,"name":"A","set":{"a.b":{"value":"v","label":"l"}},"delete":["c"],"shared":["a.b"],"order":["a.b"],"photo":""}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := ParseSet(b)
		if err != nil {
			return
		}
		for k, v := range p.SetF {
			if !keyRE.MatchString(k) || v.Value == "" || len(v.Value) > MaxValue {
				t.Fatal("invalid field accepted")
			}
		}
	})
}

func FuzzParseUpdate(f *testing.F) {
	f.Add([]byte(`{"version":1,"name":"A","fields":{"a":{"value":"v"}}}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		u, err := ParseUpdate(b)
		if err != nil {
			return
		}
		if u.Version == 0 || len(u.Fields) > MaxFields || len(u.Photo) > MaxPhoto {
			t.Fatal("invalid update accepted")
		}
		if _, err := ParseUpdate(u.Marshal()); err != nil {
			t.Fatal("canonical form does not parse")
		}
	})
}
