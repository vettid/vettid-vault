package items_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/vettid/vettid-vault/vault"
)

// §6.4, §10.8 (0.69.0): a service connection is sent the core and the
// display name only (no photo, items []), and nothing when only the photo or
// the @profile items change; its own update is kept without its items.
func TestProfileToAndFromService(t *testing.T) {
	e := newEnv(t)
	c := e.h.Conns["cB"]
	c.PeerKind = "service"
	e.h.Conns["cB"] = c
	png := base64.StdEncoding.EncodeToString([]byte("\x89PNG\r\n\x1a\nimg"))

	// The first change counts the core: both are sent it.
	e.ok(e.call("app", "profile.set", `{"version":0,"name":"Al"}`))
	if len(e.sentTo("cB", "profile.update")) != 1 {
		t.Fatalf("first: %v", e.h.Sent)
	}
	// Photo only: the person gets it, the service nothing.
	e.h.Reset()
	e.ok(e.call("app", "profile.set", `{"version":1,"photo":"`+png+`"}`))
	if len(e.sentTo("cA", "profile.update")) != 1 || len(e.sentTo("cB", "profile.update")) != 0 {
		t.Fatalf("photo: %v", e.h.Sent)
	}
	// An @profile item: likewise.
	e.h.Reset()
	e.put("data", "Contact", []string{"@profile"}, field{Label: "Email", Kind: "email", Value: "al@example.org"})
	if len(e.sentTo("cA", "profile.update")) != 1 || len(e.sentTo("cB", "profile.update")) != 0 {
		t.Fatalf("item: %v", e.h.Sent)
	}
	// The display name: both, the service's reduced.
	e.h.Reset()
	e.ok(e.call("app", "profile.set", `{"version":2,"name":"Alice"}`))
	ups := e.sentTo("cB", "profile.update")
	if len(ups) != 1 {
		t.Fatalf("name: %v", e.h.Sent)
	}
	b := string(ups[0].Body)
	if !strings.Contains(b, `"name":"Alice"`) || !strings.HasSuffix(b, `"items":[]}`) || strings.Contains(b, "photo") || strings.Contains(b, "example.org") {
		t.Fatalf("service update: %s", b)
	}
	if a := e.sentTo("cA", "profile.update"); len(a) != 1 || !bytes.Contains(a[0].Body, []byte("example.org")) || !bytes.Contains(a[0].Body, []byte("photo")) {
		t.Fatalf("person update: %v", a)
	}
	// The activation update (ConnectionAdded) is reduced too.
	e.h.Reset()
	e.set.Items.ConnectionAdded(vault.NewSession(context.Background(), e.h, vault.PeerInfo{}, e.clk.T, nil), "cB")
	if ups := e.sentTo("cB", "profile.update"); len(ups) != 1 || !strings.HasSuffix(string(ups[0].Body), `"items":[]}`) || strings.Contains(string(ups[0].Body), "photo") {
		t.Fatalf("activation: %v", ups)
	}
	// A service's update is kept without items, its photo (a logo) kept.
	core := `"first_name":"Svc","last_name":"Co","ik":"` + base64.StdEncoding.EncodeToString(e.h.Conns["cB"].IK) + `"`
	e.ok(e.call("connection:cB", "profile.update", `{"version":1,`+core+`,"photo":"`+png+`","items":[{"item_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V","name":"x","category":"c","fields":[{"field_id":"f","label":"l","kind":"text","value":"v"}]}]}`))
	var kept string
	for _, p := range e.h.Profiles {
		kept = string(p)
	}
	if kept == "" || strings.Contains(kept, "item_id") || !strings.Contains(kept, "photo") {
		t.Fatalf("kept: %q", kept)
	}
}
