package items_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"testing"

	"github.com/vettid/vettid-vault/features/credential"
	"github.com/vettid/vettid-vault/features/items"
	"github.com/vettid/vettid-vault/features/itemspec"
	"github.com/vettid/vettid-vault/vms/credwire"
	"github.com/vettid/vettid-vault/vms/suite"
)

// keysOf opens the current blob as an attacker holding the decrypted vault
// state (the CEK) and the password would, and returns the item keys.
func (e *env) keysOf(cekSeed []byte, blob string) map[string]credential.Item {
	e.t.Helper()
	cek, err := suite.NewPrivateKey(cekSeed)
	if err != nil {
		e.t.Fatal(err)
	}
	b, _ := suiteDecode(blob)
	_, pt, err := credential.Open(cek, e.h.VaultID(), b, []byte(pw))
	if err != nil {
		e.t.Fatal(err)
	}
	in, err := credential.ParseInner(pt)
	if err != nil {
		e.t.Fatal(err)
	}
	out := map[string]credential.Item{}
	for _, it := range in.Items {
		out[it.ID] = it
	}
	return out
}

func (e *env) cekSeed() []byte {
	e.t.Helper()
	raw, _ := e.set.Credential.Save()
	var st struct {
		CEK []byte `json:"cek_seed"`
	}
	if err := json.Unmarshal(raw, &st); err != nil {
		e.t.Fatal(err)
	}
	return st.CEK
}

func (e *env) stored(id string) *itemspec.Item {
	for _, it := range e.set.Items.Items() {
		if it.ID == id {
			return &it
		}
	}
	e.t.Fatalf("item %s not stored", id)
	return nil
}

// §3.5.2, §10.7: a critical item's values are encrypted under a per-item
// key kept only in the credential; DEK state holds ciphertext only; every
// use of the item re-keys it, so a key obtained once (from an old blob or
// a compromised release) no longer opens it; credential.rotate re-keys
// every item.
func TestEnvelopeEncryption(t *testing.T) {
	e := newEnv(t)
	e.createCredential()
	a := e.putCritical("Seed", nil, field{Label: "Words", Kind: "multiline", Value: "abandon ability able"})
	b := e.putCritical("Other", nil, field{Label: "Key", Kind: "password", Value: "other-secret"})
	raw, _ := e.set.Items.Save()
	if bytes.Contains(raw, []byte("abandon")) || bytes.Contains(raw, []byte("other-secret")) || !bytes.Contains(raw, []byte(`"sealed"`)) {
		t.Fatal("DEK state: plaintext, or no ciphertext")
	}
	// The DEK state alone (ciphertext, CEK, latest blob) needs the password.
	seed0, blob0 := e.cekSeed(), e.blob
	k0 := e.keysOf(seed0, blob0)
	pt, err := items.OpenSealed(e.h.VaultID(), e.stored(a), ptrItem(k0[a]))
	if err != nil || !bytes.Contains(pt, []byte("abandon")) {
		t.Fatalf("current key: %v", err)
	}
	if _, err := items.OpenSealed(e.h.VaultID(), e.stored(a), &credential.Item{ID: a, Gen: k0[a].Gen, Key: make([]byte, 32)}); err == nil {
		t.Fatal("opened without the item key")
	}
	cs, _ := e.set.Credential.Save()
	if bytes.Contains(cs, []byte(base64.StdEncoding.EncodeToString(k0[a].Key))) || bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString(k0[a].Key))) {
		t.Fatal("an item key outside the credential")
	}
	// A use of a rotates its key; b is untouched.
	e.ok(e.sealed("app", "item.reveal", map[string]any{"item_id": a}, map[string]any{"password": pw, "item_id": a}, true, true))
	if _, err := items.OpenSealed(e.h.VaultID(), e.stored(a), ptrItem(k0[a])); err == nil {
		t.Fatal("the old key still opens the item after a use")
	}
	k1 := e.keysOf(e.cekSeed(), e.blob)
	if k1[a].Gen != k0[a].Gen+1 || bytes.Equal(k1[a].Key, k0[a].Key) || !bytes.Equal(k1[b].Key, k0[b].Key) {
		t.Fatal("re-key on use")
	}
	// The old blob is dead: its CEK was destroyed.
	cek, _ := suite.NewPrivateKey(e.cekSeed())
	ob, _ := suiteDecode(blob0)
	if _, _, err := credential.Open(cek, e.h.VaultID(), ob, []byte(pw)); err == nil {
		t.Fatal("the old blob opens under the current CEK")
	}
	// credential.rotate re-keys every item.
	e.ok(e.sealed("app", "credential.rotate", nil, map[string]any{"password": pw}, true, false))
	k2 := e.keysOf(e.cekSeed(), e.blob)
	for _, id := range []string{a, b} {
		if _, err := items.OpenSealed(e.h.VaultID(), e.stored(id), ptrItem(k1[id])); err == nil {
			t.Fatalf("%s opens with its pre-rotation key", id)
		}
		if pt, err := items.OpenSealed(e.h.VaultID(), e.stored(id), ptrItem(k2[id])); err != nil || len(pt) == 0 {
			t.Fatalf("%s after rotation: %v", id, err)
		}
	}
	// Still revealed, used and moved correctly.
	o := e.ok(e.sealed("app", "item.reveal", map[string]any{"item_id": b}, map[string]any{"password": pw, "item_id": b}, true, true))
	if !o.Has("values_sealed") {
		t.Fatal("reveal after rotation")
	}
	e.ok(e.sealed("app", "item.sensitivity", map[string]any{"item_id": a, "version": e.version(a), "sensitivity": "secret"},
		map[string]any{"password": pw, "item_id": a}, true, false))
	if r := e.ok(e.call("app", "item.reveal", `{"item_id":"`+a+`"}`)); !bytes.Contains(r["fields"], []byte("abandon ability able")) {
		t.Fatal("values lost moving out of critical")
	}
	if e.stored(a).Sealed != nil {
		t.Fatal("ciphertext kept for a secret item")
	}
}

func ptrItem(i credential.Item) *credential.Item { return &i }

// §10.7: capacity is no longer bound by the credential's size: 200
// critical items (the limit is 1,000) and each still opens.
func TestCriticalCapacity(t *testing.T) {
	e := newEnv(t)
	e.createCredential()
	var ids []string
	for i := 0; i < 200; i++ {
		ids = append(ids, e.putCritical("Key "+strconv.Itoa(i), nil, field{Label: "Value", Kind: "password", Value: "v" + strconv.Itoa(i) + "-" + string(bytes.Repeat([]byte{'x'}, 2000))}))
	}
	for _, i := range []int{0, 99, 199} {
		o := e.ok(e.sealed("app", "item.reveal", map[string]any{"item_id": ids[i]}, map[string]any{"password": pw, "item_id": ids[i]}, true, true))
		sv, _ := o.Base64("values_sealed", -1)
		pt, err := openReply(e, sv)
		if err != nil || !bytes.Contains(pt, []byte(`"v`+strconv.Itoa(i)+`-`)) {
			t.Fatalf("item %d: %v", i, err)
		}
	}
	if n := len(e.keysOf(e.cekSeed(), e.blob)); n != 200 {
		t.Fatalf("%d keys in the credential", n)
	}
}

func FuzzParseValues(f *testing.F) {
	f.Add([]byte(`{"fields":[{"field_id":"f1","value":"x"},{"field_id":"f2","value":{"city":"Oslo"}}],"notes":"n"}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		v, err := items.ParseValues(b)
		if err == nil && len(v.Fields) > itemspec.MaxFields {
			t.Fatal("too many fields")
		}
	})
}

func suiteDecode(b64 string) ([]byte, error) { return base64.StdEncoding.DecodeString(b64) }

func openReply(e *env, sealed []byte) ([]byte, error) {
	return credwire.OpenValue(e.reply, e.h.VaultID(), e.lastI, sealed)
}
