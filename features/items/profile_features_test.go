package items_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/features/all"
	"github.com/vettid/vettid-vault/features/credential"
	"github.com/vettid/vettid-vault/internal/featuretest"
	"github.com/vettid/vettid-vault/vault"
)

func unlocked(e *env) {
	e.set.Items.Unlocked(vault.NewSession(context.Background(), e.h, vault.PeerInfo{}, e.clk.T, nil))
}

// §10.8 (0.81.0): the profile.update to a service carries `features`
// ["vote"] when the image registers the vote feature, a person gets none,
// and a vault that gains the feature sends it once, with the next version.
func TestProfileFeaturesToService(t *testing.T) {
	e := newEnv(t)
	c := e.h.Conns["cB"]
	c.PeerKind = "service"
	e.h.Conns["cB"] = c
	e.ok(e.call("app", "profile.set", `{"version":0,"name":"Al"}`))
	svc, per := e.sentTo("cB", "profile.update"), e.sentTo("cA", "profile.update")
	if len(svc) != 1 || len(per) != 1 {
		t.Fatalf("%v", e.h.Sent)
	}
	if !strings.Contains(string(svc[0].Body), `"features":["vote"]`) || !strings.HasSuffix(string(svc[0].Body), `"items":[]}`) {
		t.Errorf("service: %s", svc[0].Body)
	}
	if strings.Contains(string(per[0].Body), "features") {
		t.Errorf("person: %s", per[0].Body)
	}
	// Already advertised: an unlock sends nothing.
	e.h.Reset()
	unlocked(e)
	if len(e.h.Sent) != 0 {
		t.Errorf("unlock after advertising: %v", e.h.Sent)
	}
}

func TestProfileFeaturesAddedByARelease(t *testing.T) {
	// Before the feature: the vault advertised nothing to the service.
	old := all.NewSet(all.Options{CredentialKDF: credential.MinKDF, Optional: []string{"presence"}})
	h := featuretest.NewHost()
	h.AddConnection("cA")
	h.AddConnection("cB")
	c := h.Conns["cB"]
	c.PeerKind = "service"
	h.Conns["cB"] = c
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	s := vault.NewSession(context.Background(), h, vault.PeerInfo{}, now, nil)
	old.Items.ConnectionAdded(s, "cB") // counts the core and sends the first update
	first := toConn(h, "cB")
	if len(first) != 1 || strings.Contains(string(first[0].Body), "features") {
		t.Fatalf("without the feature: %v", first)
	}
	raw, err := old.Items.Save()
	if err != nil {
		t.Fatal(err)
	}
	// The release that adds it: same state, the new image.
	now2 := all.NewSet(all.Options{CredentialKDF: credential.MinKDF, Optional: []string{"presence", "vote"}})
	if err := now2.Items.Load(raw); err != nil {
		t.Fatal(err)
	}
	h.Reset()
	s = vault.NewSession(context.Background(), h, vault.PeerInfo{}, now, nil)
	now2.Items.Unlocked(s)
	ups := toConn(h, "cB")
	if len(ups) != 1 || ups[0].To != "cB" || !strings.Contains(string(ups[0].Body), `"features":["vote"]`) {
		t.Fatalf("after the release: %v", h.Sent)
	}
	if !strings.Contains(string(first[0].Body), `"version":1`) || !strings.Contains(string(ups[0].Body), `"version":2`) {
		t.Errorf("versions: %s -> %s", first[0].Body, ups[0].Body)
	}
	// Once only.
	h.Reset()
	now2.Items.Unlocked(s)
	if len(h.Sent) != 0 {
		t.Errorf("second unlock: %v", h.Sent)
	}
	// Persisted: a reload does not send it again.
	raw2, _ := now2.Items.Save()
	again := all.NewSet(all.Options{CredentialKDF: credential.MinKDF, Optional: []string{"vote"}})
	if err := again.Items.Load(raw2); err != nil {
		t.Fatal(err)
	}
	again.Items.Unlocked(s)
	if len(h.Sent) != 0 {
		t.Errorf("after reload: %v", h.Sent)
	}
	// A person connection is never sent one.
	for _, x := range h.Sent {
		if x.To == "cA" {
			t.Error("person sent an update")
		}
	}
}

func toConn(h *featuretest.Host, id string) []featuretest.Sent {
	var out []featuretest.Sent
	for _, x := range h.SentOfType("profile.update") {
		if x.To == id {
			out = append(out, x)
		}
	}
	return out
}
