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
	// 0.86.0: hs_confirm goes to every connection, after items (§10.8).
	if !strings.HasSuffix(string(svc[0].Body), `"items":[],"features":["hs_confirm","vote"],"contract":"1.0"}`) {
		t.Errorf("service: %s", svc[0].Body)
	}
	if !strings.HasSuffix(string(per[0].Body), `,"features":["hs_confirm"]}`) {
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
	if len(first) != 1 || !strings.Contains(string(first[0].Body), `"features":["hs_confirm"]`) {
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
	if len(ups) != 1 || ups[0].To != "cB" || !strings.Contains(string(ups[0].Body), `"features":["hs_confirm","vote"]`) {
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

// §10.4 "Approval documents" (0.89.0): approval_document goes to a service in profile.update's features only while
// the member's app lists it in its last device.features, and is not sticky: it comes and goes with the app's
// list, each change sent once with the next version.
func TestApprovalDocumentAdvertisedWhileTheAppListsIt(t *testing.T) {
	e := newEnv(t)
	c := e.h.Conns["cB"]
	c.PeerKind = "service"
	e.h.Conns["cB"] = c
	e.ok(e.call("app", "profile.set", `{"version":0,"name":"Al"}`))
	if svc := e.sentTo("cB", "profile.update"); len(svc) != 1 || strings.Contains(string(svc[0].Body), "approval_document") {
		t.Fatalf("before the app lists it: %v", svc)
	}
	changed := func() []featuretest.Sent {
		e.h.Reset()
		e.set.Items.AppFeaturesChanged(vault.NewSession(context.Background(), e.h, vault.PeerInfo{}, e.clk.T, nil))
		return e.sentTo("cB", "profile.update")
	}
	e.h.AppFeatures = []string{"approval_document", "hs_confirm"}
	if svc := changed(); len(svc) != 1 || !strings.Contains(string(svc[0].Body), `"features":["approval_document","hs_confirm","vote"]`) ||
		!strings.Contains(string(svc[0].Body), `"version":2`) {
		t.Fatalf("listed: %v", svc)
	}
	// A person is never told.
	if per := e.sentTo("cA", "profile.update"); len(per) != 0 {
		t.Fatalf("a person was told: %v", per)
	}
	// Once only.
	if svc := changed(); len(svc) != 0 {
		t.Fatalf("again: %v", svc)
	}
	// Not sticky: the app's list no longer carries it.
	e.h.AppFeatures = []string{"hs_confirm"}
	if svc := changed(); len(svc) != 1 || strings.Contains(string(svc[0].Body), "approval_document") || !strings.Contains(string(svc[0].Body), `"version":3`) {
		t.Fatalf("dropped: %v", svc)
	}
}

// A service that could not be told keeps the change pending: AppFeaturesChanged reports it, and tells it when it
// can.
func TestApprovalDocumentToldAgainAfterAFailedSend(t *testing.T) {
	e := newEnv(t)
	c := e.h.Conns["cB"]
	c.PeerKind = "service"
	e.h.Conns["cB"] = c
	e.ok(e.call("app", "profile.set", `{"version":0,"name":"Al"}`))
	e.h.AppFeatures = []string{"approval_document"}
	s := vault.NewSession(context.Background(), e.h, vault.PeerInfo{}, e.clk.T, nil)
	e.h.DownConns["cB"] = true
	if e.set.Items.AppFeaturesChanged(s) {
		t.Fatal("reported told after a failed send")
	}
	e.h.DownConns["cB"] = false
	e.h.Reset()
	if !e.set.Items.AppFeaturesChanged(s) || len(e.sentTo("cB", "profile.update")) != 1 {
		t.Fatalf("not told when it could be: %v", e.h.Sent)
	}
}

// Retries against a service that cannot be reached change nothing: no version taken, no state changed. A service
// whose rotation is pending is not one to retry: the rotation sends it the update.
func TestApprovalDocumentRetriesChangeNothing(t *testing.T) {
	e := newEnv(t)
	c := e.h.Conns["cB"]
	c.PeerKind = "service"
	e.h.Conns["cB"] = c
	e.ok(e.call("app", "profile.set", `{"version":0,"name":"Al"}`))
	shared := func() string {
		raw, _ := e.set.Items.Save()
		i := strings.Index(string(raw), `"shared":`)
		return string(raw)[i : i+12]
	}
	before, changed := shared(), e.h.Changed
	e.h.AppFeatures = []string{"approval_document"}
	e.h.DownConns["cB"] = true
	s := vault.NewSession(context.Background(), e.h, vault.PeerInfo{}, e.clk.T, nil)
	for range 5 {
		if e.set.Items.AppFeaturesChanged(s) {
			t.Fatal("reported told")
		}
	}
	if shared() != before || e.h.Changed != changed {
		t.Fatalf("retries changed the state: %s -> %s, changed %d", before, shared(), e.h.Changed-changed)
	}
	// Rotation pending: not counted as not told, and nothing is sent to it now.
	e.h.DownConns["cB"] = false
	c = e.h.Conns["cB"]
	c.RotationPending = true
	e.h.Conns["cB"] = c
	e.h.Reset()
	if !e.set.Items.AppFeaturesChanged(s) || len(e.sentTo("cB", "profile.update")) != 0 {
		t.Fatalf("rotation pending: %v", e.h.Sent)
	}
}
