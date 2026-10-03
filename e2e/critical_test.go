//go:build devenclave && e2e

package e2e

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/relaytest"
	"github.com/vettid/vettid-vault/internal/strictjson"
)

// V4 batch 3, critical-secret use (§10.13) through the real relay: A's
// member holds an Ed25519 signing key in the Protean Credential and lists
// it in the catalog; B asks A's member to sign a payload; A's app sees the
// request and approves with the password (bound to the request and the
// payload); B receives only the signature, which verifies; A's credential
// rotated (a new version). A second request is denied.
func TestCriticalSecretUse(t *testing.T) {
	r := relaytest.Start(t, nil)
	a := newTestVault(t, r.URL, "a", nil)
	b := newTestVault(t, r.URL, "b", nil)
	ctx := ctxT(t, 120*time.Second)
	_, bConn := connect(t, a, b, 600)

	seed := bytes.Repeat([]byte{0x7a}, 32)
	sid, err := a.app.CriticalSecretAdd(ctx, credPW, "Signing key", "signing_key", "", seed)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.app.CriticalSecretCatalog(ctx, sid, true); err != nil {
		t.Fatal(err)
	}
	v0, err := a.app.CredentialVersion(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ver0, _ := v0.Uint("version", 1, 1<<40)

	payload := []byte("pay 5 EUR to invoice 7")
	reqID, err := b.app.CriticalUseRequest(ctx, bConn, sid, "sign", payload, "invoice 7")
	if err != nil {
		t.Fatal(err)
	}
	pend := waitEvent(t, a.app, "critical-secret-use.pending", has("request_id", reqID))
	po, _ := strictjson.ParseObject(pend.Body)
	shown, _ := po.Base64("payload", -1)
	if !bytes.Equal(shown, payload) || field(t, pend.Body, "context") != "invoice 7" || field(t, pend.Body, "name") != "Signing key" {
		t.Fatalf("pending: %s", pend.Body)
	}
	st, err := a.app.CriticalUseApprove(ctx, credPW, reqID, shown)
	if err != nil || st != "ok" {
		t.Fatalf("approve: %q %v", st, err)
	}
	res := waitEvent(t, b.app, "critical-secret-use.result", has("request_id", reqID))
	ro, _ := strictjson.ParseObject(res.Body)
	if s, _ := ro.String("status"); s != "ok" {
		t.Fatalf("result: %s", res.Body)
	}
	sig, _ := ro.Base64("signature", ed25519.SignatureSize)
	pub, _ := ro.Base64("public_key", ed25519.PublicKeySize)
	if !bytes.Equal(pub, ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)) || !ed25519.Verify(pub, payload, sig) {
		t.Fatal("signature does not verify")
	}
	v1, err := a.app.CredentialVersion(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if ver1, _ := v1.Uint("version", 1, 1<<40); ver1 <= ver0 {
		t.Fatalf("credential did not rotate: %d -> %d", ver0, ver1)
	}

	// A second request, denied by the member.
	reqID2, err := b.app.CriticalUseRequest(ctx, bConn, sid, "auth", []byte("challenge"), "")
	if err != nil {
		t.Fatal(err)
	}
	waitEvent(t, a.app, "critical-secret-use.pending", has("request_id", reqID2))
	if err := a.app.CriticalUseDeny(ctx, reqID2); err != nil {
		t.Fatal(err)
	}
	waitEvent(t, b.app, "critical-secret-use.result", func(raw json.RawMessage) bool {
		return has("request_id", reqID2)(raw) && has("status", "denied")(raw)
	})

	// Neither side's audit log holds the payload or the signature; both
	// record the use.
	au, err := a.app.AuditList(ctx, map[string]any{"kinds": []string{"critical-secret"}}, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"critical-secret.use.requested", "critical-secret.used", "critical-secret.use.denied"} {
		if !bytes.Contains(au["entries"], []byte(`"`+k+`"`)) {
			t.Errorf("A's audit lacks %s", k)
		}
	}
	if bytes.Contains(au["entries"], []byte(base64.StdEncoding.EncodeToString(sig))) {
		t.Fatal("signature in the audit log")
	}
	bu, err := b.app.AuditList(ctx, map[string]any{"kinds": []string{"critical-secret"}}, false)
	if err != nil || !bytes.Contains(bu["entries"], []byte(`"critical-secret.use.result"`)) {
		t.Fatalf("B's audit: %v", err)
	}
}
