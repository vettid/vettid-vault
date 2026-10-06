package vectors

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/leashwire"
)

// leashSpec is VAULT-MESSAGING 0.12.0 §16 (leash.json) as the spec prints
// it: leash.json must reproduce these values byte for byte (§15 item 21).
var leashSpec = map[string]struct {
	delegation, sha, sig, status, statusSig string
	from, to                                int64
}{
	"a": {
		delegation: `{"approval":"auto","exp":1798632000,"grant_id":"01JB2Z6V9K3M4N5P6Q7R8S9T41",` +
			`"iat":1790856000,"iss":"G6QHW3fJ4/s+zeFc2vUiHzwQNz5iP3sOHvdjZrCvcTc=",` +
			`"limits":{"per_day":1000,"per_hour":60},"nonce":"MjIyMjIyMjIyMjIyMjIyMg==",` +
			`"scope":{"access":"read","match":"any","op":"items.read","tags":["api-keys","work"],` +
			`"uses":10},"status_issuer":"ypOsFwUYcHHWe4PH/w7+gQjo7EUwV113JoeTM9vavnw=",` +
			`"status_ttl":900,"sub":"SAdaWX5yGhVuLgeZ3lzAxTJNxufq8c3UYlCGjsUyFd0=","v":1,"version":1}`,
		sha: "82403562f0a1b62c520c468d46f58a473eefc0cae0ac6a0d8d8bdaef225ea436",
		sig: "xGYxdD9lhE27/4NjTmDl1L+9/UJRv3cdRdWp3yOVxCOPgicdwrL+lv9A7lP4RNkE47XVEpAjAvh7Dc0z9dBKCw==",
		status: `{"delegation":"gkA1YvChtixSDEaNRvWKRz7vwMrgrGoNjYva7yJepDY=",` +
			`"grant_id":"01JB2Z6V9K3M4N5P6Q7R8S9T41","issued_at":1790856060,"not_after":1790856960,` +
			`"status":"valid","v":1}`,
		statusSig: "aSkNJrcIZmkYLzpX5Z7jb/1tHXkwrcNHBZURMycInB9vWdwEpGJB3RDzPmzUscKL6H3tRaOSyZID653kpcgACg==",
		from:      1790856000, to: 1790857020,
	},
	"b": {
		delegation: `{"approval":"ask","grant_id":"01JB2Z6V9K3M4N5P6Q7R8S9T42","iat":1790856000,` +
			`"iss":"G6QHW3fJ4/s+zeFc2vUiHzwQNz5iP3sOHvdjZrCvcTc=","nonce":"MzMzMzMzMzMzMzMzMzMzMw==",` +
			`"scope":{"connections":["01JB2Z6V9K3M4N5P6Q7R8S9T43"],"op":"message.send"},` +
			`"status_issuer":"ypOsFwUYcHHWe4PH/w7+gQjo7EUwV113JoeTM9vavnw=","status_ttl":300,` +
			`"sub":"SAdaWX5yGhVuLgeZ3lzAxTJNxufq8c3UYlCGjsUyFd0=","v":1,"version":2}`,
		sha: "36ce9294e797cf1eecff1c61b8a21647e45a20eedd6acdb2abe2a591e322bacc",
		sig: "PS1c/aT/OAMyYaPhSudMMJX7TjCaXVrkjk6zOmjoFfZR9ZxjkzjTgfMg6smbq6KCDRoqh4AmXwUAtnJivESDBw==",
		status: `{"delegation":"Ns6SlOeXzx7s/xxhuKIWR+RaIO7das2yq+KlkeMiusw=",` +
			`"grant_id":"01JB2Z6V9K3M4N5P6Q7R8S9T42","issued_at":1790856060,"not_after":1790856360,` +
			`"status":"valid","v":1}`,
		statusSig: "AcQTmAdY8UpkeDssy4iHgHo8hKPZxwq1FJI8YHOwSUOgHRlCEc+SV4VVZr7fTn/jzKrFo9EilExC3XwKJKW1Bw==",
		from:      1790856000, to: 1790856420,
	},
}

// §10.11 LEASH vectors (leash.json): the file matches the spec's §16
// values byte for byte, and every value is re-derived from the file's
// inputs with crypto/ed25519 and the context strings directly; the
// reference verifier accepts each pair exactly within its window.
func TestLeashVectors(t *testing.T) { checkLeashVectors(t, Dir) }

func checkLeashVectors(t *testing.T, dir string) {
	d := load(t, dir, "leash.json")
	if d.str("context_delegation") != "leash/v1/delegation" || d.str("context_status") != "leash/v1/status" ||
		leashwire.Label != "leash/v1/delegation" || leashwire.LabelStatus != "leash/v1/status" {
		t.Fatal("context strings")
	}
	cred := ed25519.NewKeyFromSeed(d.hex("credential_key_seed_hex"))
	agent := ed25519.NewKeyFromSeed(d.hex("agent_ik_seed_hex"))
	vault := ed25519.NewKeyFromSeed(d.hex("vault_ik_seed_hex"))
	eq(t, "credential key", cred.Public().(ed25519.PublicKey), d.b64("credential_key_pk_b64"))
	eq(t, "agent ik", agent.Public().(ed25519.PublicKey), d.b64("agent_ik_pk_b64"))
	eq(t, "vault ik", vault.Public().(ed25519.PublicKey), d.b64("vault_ik_pk_b64"))
	if d.str("credential_key_pk_b64") != "G6QHW3fJ4/s+zeFc2vUiHzwQNz5iP3sOHvdjZrCvcTc=" ||
		d.str("agent_ik_pk_b64") != "SAdaWX5yGhVuLgeZ3lzAxTJNxufq8c3UYlCGjsUyFd0=" ||
		d.str("vault_ik_pk_b64") != "ypOsFwUYcHHWe4PH/w7+gQjo7EUwV113JoeTM9vavnw=" {
		t.Error("keys differ from §16")
	}
	if d.num("skew_seconds") != 60 {
		t.Error("skew")
	}
	for name, spec := range leashSpec {
		v := d.sub(name)
		del, st := []byte(v.str("delegation_json")), []byte(v.str("status_json"))
		// The spec's bytes.
		if string(del) != spec.delegation || string(st) != spec.status || v.str("sig_b64") != spec.sig ||
			v.str("status_sig_b64") != spec.statusSig || v.str("delegation_sha256_hex") != spec.sha {
			t.Errorf("%s: differs from VAULT-MESSAGING §16", name)
		}
		if int64(v.num("accept_from")) != spec.from || int64(v.num("accept_to")) != spec.to {
			t.Errorf("%s: acceptance window", name)
		}
		eq(t, name+" delegation_b64", v.b64("delegation_b64"), del)
		eq(t, name+" status_b64", v.b64("status_b64"), st)
		if v.num("delegation_len") != len(del) {
			t.Errorf("%s: delegation_len", name)
		}
		// Re-derived independently of leashwire.
		h := sha256.Sum256(del)
		if hex.EncodeToString(h[:]) != v.str("delegation_sha256_hex") {
			t.Errorf("%s: sha-256", name)
		}
		var m map[string]json.RawMessage
		if err := json.Unmarshal(del, &m); err != nil {
			t.Fatal(err)
		}
		var nonce string
		_ = json.Unmarshal(m["nonce"], &nonce)
		if nonce != base64.StdEncoding.EncodeToString(v.hex("nonce_hex")) {
			t.Errorf("%s: nonce", name)
		}
		sig := ed25519.Sign(cred, append([]byte("leash/v1/delegation"), del...))
		if base64.StdEncoding.EncodeToString(sig) != v.str("sig_b64") {
			t.Errorf("%s: sig", name)
		}
		ssig := ed25519.Sign(vault, append([]byte("leash/v1/status"), st...))
		if base64.StdEncoding.EncodeToString(ssig) != v.str("status_sig_b64") {
			t.Errorf("%s: status_sig", name)
		}
		var sm map[string]json.RawMessage
		if err := json.Unmarshal(st, &sm); err != nil {
			t.Fatal(err)
		}
		var sh string
		_ = json.Unmarshal(sm["delegation"], &sh)
		if sh != base64.StdEncoding.EncodeToString(h[:]) {
			t.Errorf("%s: status names another delegation", name)
		}
		// The library: JCS round trip and the reference verifier.
		pd, err := leashwire.ParseCanonical(del)
		if err != nil || string(pd.Marshal()) != string(del) {
			t.Fatalf("%s: parse: %v", name, err)
		}
		if _, err := leashwire.ParseStatusCanonical(st); err != nil {
			t.Fatalf("%s: status: %v", name, err)
		}
		p := &leashwire.Presented{Delegation: del, Sig: sig, Status: st, StatusSig: ssig}
		member := cred.Public().(ed25519.PublicKey)
		for _, now := range []int64{spec.from, spec.to} {
			if _, err := leashwire.VerifyPresented(member, p, time.Unix(now, 0)); err != nil {
				t.Errorf("%s: rejected at %d: %v", name, now, err)
			}
		}
		for _, now := range []int64{spec.from - 1, spec.to + 1} {
			if _, err := leashwire.VerifyPresented(member, p, time.Unix(now, 0)); err == nil {
				t.Errorf("%s: accepted at %d", name, now)
			}
		}
	}
}
