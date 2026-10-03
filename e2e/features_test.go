//go:build devenclave && e2e

package e2e

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/client"
	"github.com/vettid/vettid-vault/internal/relaytest"
	"github.com/vettid/vettid-vault/vault"
)

// pairDesktop pairs a desktop to tv from its app (§6.7).
func pairDesktop(t *testing.T, tv *testVault, relayURL string) *client.Device {
	t.Helper()
	ctx := ctxT(t, 60*time.Second)
	desk, err := client.New(ctx, client.Config{Role: vault.KindDesktop, Name: tv.name + "-desk", RelayURL: relayURL, PollWait: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	pc := mustOK(t, tv.request(tv.app, "device.pair.create", `{"role":"desktop"}`))
	link, _ := pc.String("link")
	pid, _ := pc.String("pairing_id")
	if _, err := desk.Pair(ctx, link); err != nil {
		t.Fatal(err)
	}
	waitEvent(t, tv.app, "device.pair.pending", has("pairing_id", pid))
	mustOK(t, tv.request(tv.app, "device.pair.approve", `{"pairing_id":"`+pid+`"}`))
	if err := desk.AwaitPaired(ctx); err != nil {
		t.Fatal(err)
	}
	return desk
}

func syncKind(kind string) func(json.RawMessage) bool { return has("kind", kind) }

// V4 batch 1, credential (§3.5, §10.6) through the real relay: the app holds
// the credential; every use carries it and the password; the desktop sees
// only metadata and change notices; the credential survives a vault restart;
// rotation rotates the vault's identity.
func TestCredentialFlow(t *testing.T) {
	r := relaytest.Start(t, nil)
	a := newTestVault(t, r.URL, "a", nil)
	desk := pairDesktop(t, a, r.URL)
	ctx := ctxT(t, 120*time.Second)

	// Every use rotates the CEK: a new blob and version; the previous blob
	// is refused (and undecryptable, §3.5.3).
	b1 := a.app.CredentialBlob()
	if _, err := a.app.CredentialUnlock(ctx, credPW); err != nil {
		t.Fatal(err)
	}
	spent := a.app.LastUTK()
	waitEvent(t, desk, "sync.event", syncKind("credential.changed"))
	b2 := a.app.CredentialBlob()
	if string(b1) == string(b2) {
		t.Fatal("the CEK did not rotate")
	}
	if _, err := a.app.CredentialRaw(ctx, "credential.unlock", spent, b2, map[string]any{"password": credPW}); client.Code(err) != "utk_invalid" {
		t.Fatalf("UTK reuse: %v", err)
	}
	if _, err := a.app.CredentialUnlock(ctx, credPW); err != nil {
		t.Fatal(err)
	}
	if _, err := a.app.CredentialRaw(ctx, "credential.unlock", takeUTK(t, a.app), b1, map[string]any{"password": credPW}); client.Code(err) != "stale_credential" {
		t.Fatalf("previous blob: %v", err)
	}
	id, err := a.app.CriticalSecretAdd(ctx, credPW, "btc seed", "seed_phrase", "", []byte("zoo zoo zoo wrong"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.app.CriticalSecretGet(ctx, "not the password", id); client.Code(err) != "bad_password" {
		t.Fatalf("wrong password: %v", err)
	}
	// The desktop may list metadata but never read a value.
	l, err := desk.CriticalSecretList(ctx)
	if err != nil || !strings.Contains(string(l["secrets"]), "btc seed") {
		t.Fatalf("desktop list: %v", err)
	}
	if rr := a.request(desk, "credential.secret.get", `{}`); rr.ErrorCode() != "forbidden" {
		t.Fatalf("desktop read a critical secret: %q", rr.ErrorCode())
	}
	// Restart the vault: the credential record, the CEK and the UTK pool persist.
	a.restart()
	v, err := a.app.CriticalSecretGet(ctx, credPW, id)
	if err != nil || string(v) != "zoo zoo zoo wrong" {
		t.Fatalf("after restart: %v", err)
	}
	// Pool replenishment: spend until refills arrive with responses.
	for i := 0; i < 12; i++ {
		if _, err := a.app.CredentialUnlock(ctx, credPW); err != nil {
			t.Fatal(err)
		}
	}
	if n := a.app.UTKCount(); n < 5 {
		t.Fatalf("pool not replenished: %d", n)
	}
	// Rotation: a new credential key, and the vault's ik rotates with it (§3.4).
	if err := a.app.CredentialRotate(ctx, credPW); err != nil {
		t.Fatal(err)
	}
	if _, err := a.app.CredentialUnlock(ctx, credPW); err != nil {
		t.Fatal(err)
	}
	// Audit and feed (§10.9).
	au, err := a.app.AuditList(ctx, map[string]any{"kinds": []string{"credential", "identity"}}, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"credential.created", "credential.secret.read", "credential.password_failed", "credential.rotated", "identity.rotated"} {
		if !strings.Contains(string(au["entries"]), `"`+k+`"`) {
			t.Errorf("audit lacks %s", k)
		}
	}
	waitEvent(t, desk, "feed.event", has("kind", "credential.secret.read"))
}

// V4 batch 1, profile, secrets, settings, audit and feed through the real
// relay between two connected vaults.
func TestProfileSecretsAuditFeed(t *testing.T) {
	r := relaytest.Start(t, nil)
	a := newTestVault(t, r.URL, "a", nil)
	b := newTestVault(t, r.URL, "b", nil)
	ctx := ctxT(t, 120*time.Second)
	// A's display name goes into its invite hint and hs.init; the shared
	// profile follows on activation (§6.2, §9.3).
	if _, err := a.app.ProfileSet(ctx, map[string]any{"version": 0, "name": "Ada",
		"set":    map[string]any{"contact.email": map[string]any{"value": "ada@example.org"}, "id.passport": map[string]any{"value": "P123"}},
		"shared": []string{"contact.email"}}); err != nil {
		t.Fatal(err)
	}
	aConn, bConn := connect(t, a, b, 600)
	waitEvent(t, b.app, "connection.event", has("event", "profile"))
	g := mustOK(t, b.request(b.app, "connection.get", `{"connection_id":"`+bConn+`"}`))
	if n, _ := g.String("name"); n != "Ada" || !strings.Contains(string(g["profile"]), "ada@example.org") || strings.Contains(string(g["profile"]), "P123") {
		t.Fatalf("B's view of A: %s", g["profile"])
	}
	// A changes a shared field: B gets profile.update again.
	b.app.Events() // drain
	if _, err := a.app.ProfileSet(ctx, map[string]any{"version": 1, "set": map[string]any{"contact.email": map[string]any{"value": "ada@new.example.org"}}}); err != nil {
		t.Fatal(err)
	}
	waitEvent(t, b.app, "connection.event", has("event", "profile"))
	g = mustOK(t, b.request(b.app, "connection.get", `{"connection_id":"`+bConn+`"}`))
	if !strings.Contains(string(g["profile"]), "ada@new.example.org") {
		t.Fatalf("update not applied: %s", g["profile"])
	}

	// Secrets: put, versioned replace, list without values.
	sid, v, err := b.app.SecretPut(ctx, "", 0, "wifi", "hunter22", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.app.SecretPut(ctx, sid, v+1, "wifi", "x", nil); client.Code(err) != "conflict" {
		t.Fatalf("stale version: %v", err)
	}
	if _, _, err := b.app.SecretPut(ctx, sid, v, "wifi", "hunter23", nil); err != nil {
		t.Fatal(err)
	}
	s, err := b.app.SecretGet(ctx, sid)
	if err != nil || !strings.Contains(string(s["value"]), "hunter23") {
		t.Fatalf("get: %v", err)
	}

	// Settings.
	if _, err := a.app.SettingsSet(ctx, 0, map[string]any{"app.theme": "dark"}); err != nil {
		t.Fatal(err)
	}

	// Audit per connection, and the feed with a guide.
	sendText(t, a, a.app, aConn, "hello")
	waitEvent(t, b.app, "message.new", nil)
	ca, err := b.app.AuditList(ctx, map[string]any{"connection_id": bConn}, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"connection.added", "message.received"} {
		if !strings.Contains(string(ca["entries"]), `"`+k+`"`) {
			t.Errorf("connection audit lacks %s: %s", k, ca["entries"])
		}
	}
	if strings.Contains(string(ca["entries"]), "hello") {
		t.Fatal("message content in the audit log")
	}
	waitEvent(t, b.app, "feed.event", has("kind", "message.received"))
	if _, err := a.app.GuideSync(ctx, []map[string]any{{"guide_id": "welcome", "version": 1, "title": "Welcome", "message": "Hi"}}); err != nil {
		t.Fatal(err)
	}
	fl, err := a.app.FeedList(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"connection.request", "connection.added", "guide"} {
		if !strings.Contains(string(fl["items"]), `"kind":"`+k+`"`) {
			t.Errorf("feed lacks %s", k)
		}
	}
}

// takeUTK takes a fresh UTK from the app's pool (fetching one if needed).
func takeUTK(t *testing.T, d *client.Device) client.UTK {
	t.Helper()
	if _, err := d.CredentialVersion(ctxT(t, 10*time.Second)); err != nil {
		t.Fatal(err)
	}
	u, err := d.TakeUTK(ctxT(t, 30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	return u
}
