//go:build devenclave && e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/relaytest"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/paircode"
)

// The relay's https name for the code derivations: a code cannot name the
// test relay's plain-http address (VAULT-MESSAGING §6.7.2), so the relay
// computes its salts under this name, as a deployed relay does under its
// own.
const pcRelayName = "https://relay.vettid.test"

// ClientRelay's code claim calls against the real relay (RELAY-PROTOCOL
// 0.14.1 §6.9.1): the salts as the relay lists them pass the vault's
// checks; a claim PUT with the vault's tag and blob is redeemed once by
// whoever has the code and opens with it; a deleted claim is gone. A relay
// without a code key offers none.
func TestPairCodeRealRelay(t *testing.T) {
	ctx := ctxT(t, 60*time.Second)
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	r := relaytest.Start(t, relaytest.Options{"RELAY_PAIR_CODE_KEY": base64.StdEncoding.EncodeToString(key), "RELAY_BASE_URL": pcRelayName})
	_, sk, _ := ed25519.GenerateKey(rand.Reader)
	cr := vault.NewClientRelay(r.URL, sk, http.DefaultClient, nil)
	lim, err := cr.Register(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !lim.OffersPairCodes() {
		t.Fatal("a relay with a code key does not advertise pair_codes")
	}

	listed, err := cr.PairCodeSalts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	salts, err := paircode.CheckSalts(pcRelayName, listed, time.Now(), nil)
	if err != nil {
		t.Fatalf("the relay's salts fail the vault's checks: %v", err)
	}
	// The salt a PUT goes under, as the vault picks it: in an hour's first
	// minutes the relay also lists the previous hour's, which it refuses
	// for a PUT (the list's first entry is not the one).
	putSalt := paircode.ForPut(salts, time.Now())[0]
	put := func(code []byte, bundle string) (claimID string) {
		t.Helper()
		claimID, _ = paircode.NewClaimID()
		sc := make([]byte, paircode.SaltSize)
		_, _ = rand.Read(sc)
		tag, err := paircode.Tag(paircode.PurposeDesktop, pcRelayName, code, putSalt.SR)
		if err != nil {
			t.Fatal(err)
		}
		x, _ := paircode.X(paircode.PurposeDesktop, pcRelayName, code, sc)
		kw, _ := paircode.KW(x)
		blob, err := paircode.Seal(kw, paircode.PurposeDesktop, pcRelayName, claimID, sc, []byte(bundle))
		if err != nil {
			t.Fatal(err)
		}
		if exp, err := cr.PutPairCode(ctx, claimID, putSalt.SaltID, tag, sc, blob); err != nil || time.Until(exp) <= 0 {
			t.Fatalf("PUT: %v, expires %v", err, exp)
		}
		return claimID
	}
	code, _ := paircode.NewCode()
	claimID := put(code, `{"probe":1}`)

	// Whoever has the code: a tag per listed salt, one redeem.
	redeem := func(code []byte) (int, []byte) {
		t.Helper()
		var tags []map[string]any
		for _, s := range salts {
			tag, _ := paircode.Tag(paircode.PurposeDesktop, pcRelayName, code, s.SR)
			tags = append(tags, map[string]any{"salt_id": s.SaltID, "tag": tag})
		}
		body, _ := json.Marshal(map[string]any{"tags": tags})
		resp, err := http.Post(r.URL+"/v1/pair-code/redeem", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(resp.Body)
		return resp.StatusCode, buf.Bytes()
	}
	status, raw := redeem(code)
	if status != http.StatusOK {
		t.Fatalf("redeem: %d %s", status, raw)
	}
	var claim struct {
		ClaimID string `json:"claim_id"`
		Salt    []byte `json:"salt"`
		Blob    []byte `json:"blob"`
	}
	if err := json.Unmarshal(raw, &claim); err != nil || claim.ClaimID != claimID {
		t.Fatalf("redeemed %q (%v), put %q", claim.ClaimID, err, claimID)
	}
	x, _ := paircode.X(paircode.PurposeDesktop, pcRelayName, code, claim.Salt)
	kw, _ := paircode.KW(x)
	if bj, err := paircode.Open(kw, paircode.PurposeDesktop, pcRelayName, claim.ClaimID, claim.Salt, claim.Blob); err != nil || string(bj) != `{"probe":1}` {
		t.Fatalf("the redeemed blob: %q, %v", bj, err)
	}
	if status, raw := redeem(code); status != http.StatusNotFound {
		t.Fatalf("a second redeem: %d %s", status, raw)
	}

	// A deleted claim cannot be redeemed; the delete is idempotent.
	code2, _ := paircode.NewCode()
	id2 := put(code2, `{"probe":2}`)
	for range 2 {
		if err := cr.DeletePairCode(ctx, id2); err != nil {
			t.Fatalf("DELETE: %v", err)
		}
	}
	if status, raw := redeem(code2); status != http.StatusNotFound {
		t.Fatalf("redeem after the delete: %d %s", status, raw)
	}

	// The relay deletes a claim by its signing mailbox: a DELETE signed by
	// another mailbox's key (the vault's next key, after a relay key
	// rotation) answers as done and leaves the claim, so the vault deletes
	// with the key that put it (§3.4.1 S7's rule; vault
	// TestRelayRotClaimsAreDeletedAtTheCreatingMailbox).
	_, skNext, _ := ed25519.GenerateKey(rand.Reader)
	next := vault.NewClientRelay(r.URL, skNext, http.DefaultClient, nil)
	if _, err := next.Register(ctx); err != nil {
		t.Fatal(err)
	}
	code5, _ := paircode.NewCode()
	id5 := put(code5, `{"probe":5}`)
	if err := next.DeletePairCode(ctx, id5); err != nil {
		t.Fatalf("another mailbox's DELETE: %v", err)
	}
	if status, raw := redeem(code5); status != http.StatusOK {
		t.Fatalf("a claim another mailbox deleted is gone: %d %s", status, raw)
	}
	code6, _ := paircode.NewCode()
	id6 := put(code6, `{"probe":6}`)
	if err := next.DeletePairCode(ctx, id6); err != nil {
		t.Fatal(err)
	}
	if err := cr.DeletePairCode(ctx, id6); err != nil {
		t.Fatal(err)
	}
	if status, raw := redeem(code6); status != http.StatusNotFound {
		t.Fatalf("the creating mailbox's DELETE left the claim: %d %s", status, raw)
	}

	// A link claim the same way: another mailbox's DELETE leaves it, the
	// creating mailbox's removes it.
	linkID, _, err := cr.PutClaim(ctx, []byte("link-claim"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := next.DeleteClaim(ctx, linkID); err != nil && vault.RelayCode(err) != vault.CodeClaimUnknown {
		t.Fatalf("another mailbox's link DELETE: %v", err)
	}
	if got, err := cr.GetClaim(ctx, r.URL, linkID); err != nil || string(got) != "link-claim" {
		t.Fatalf("a link claim another mailbox deleted is gone: %q %v", got, err)
	}
	if err := cr.DeleteClaim(ctx, linkID); err != nil {
		t.Fatal(err)
	}
	if _, err := cr.GetClaim(ctx, r.URL, linkID); err == nil {
		t.Fatal("the creating mailbox's link DELETE left the claim")
	}

	// The relay's refusals as the vault reads them (§6.7.2's retry rule):
	// a salt it does not list is bad_request; another mailbox's claim
	// with the same tag is code_taken, and both claims are gone.
	tag3, _ := paircode.Tag(paircode.PurposeDesktop, pcRelayName, code2, putSalt.SR)
	id3, _ := paircode.NewClaimID()
	if _, err := cr.PutPairCode(ctx, id3, "00000000", tag3, make([]byte, paircode.SaltSize), []byte("x")); vault.RelayCode(err) != "bad_request" {
		t.Fatalf("an unlisted salt: %v (%q)", err, vault.RelayCode(err))
	}
	code4, _ := paircode.NewCode()
	put(code4, `{"probe":4}`)
	_, sk3, _ := ed25519.GenerateKey(rand.Reader)
	other := vault.NewClientRelay(r.URL, sk3, http.DefaultClient, nil)
	if _, err := other.Register(ctx); err != nil {
		t.Fatal(err)
	}
	tag4, _ := paircode.Tag(paircode.PurposeDesktop, pcRelayName, code4, putSalt.SR)
	id4, _ := paircode.NewClaimID()
	if _, err := other.PutPairCode(ctx, id4, putSalt.SaltID, tag4, make([]byte, paircode.SaltSize), []byte("x")); vault.RelayCode(err) != "code_taken" {
		t.Fatalf("the same tag from another mailbox: %v (%q)", err, vault.RelayCode(err))
	}
	if status, raw := redeem(code4); status != http.StatusNotFound {
		t.Fatalf("redeem after code_taken: %d %s", status, raw)
	}

	// No code key: no code claims.
	off := relaytest.Start(t, nil)
	_, sk2, _ := ed25519.GenerateKey(rand.Reader)
	lim2, err := vault.NewClientRelay(off.URL, sk2, http.DefaultClient, nil).Register(context.Background())
	if err != nil || lim2.OffersPairCodes() {
		t.Fatalf("a relay without a code key: offers %v (%v)", lim2.OffersPairCodes(), err)
	}
}
