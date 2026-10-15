package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"github.com/vettid/vettid-vault/vault/store"
)

// Compatibility with vaults sealed by staging release S9 (the release
// before VAULT-MESSAGING 0.26.0 and 0.27.0; vettid-vault f6614b9). S10
// changes no state member and adds two members to the device binding
// inside the sealed header (signer, signer_class). A vault sealed by S9
// must load on S10, keep working, move to a later release and bind.
//
// The JSON members below are S9's own, read from its sources at f6614b9
// (vault/crypto.go Header and UnlockKey, vms/devattest Binding,
// vault/state.go State and Peer). The test builds a vault whose stored
// header and state use only those members, so what S10 loads here is
// shaped exactly as S9 wrote it. (The compat workflow also runs the real
// S9 binaries against this tree: scripts/compat-matrix.sh.)
var (
	s9Header = strings.Fields(`v vault_id user_guid provisional created_at kdf pepper unlock_keys backoff state_seq header_seq
		sealed_release manifest_serial seal_key_verified recovery has_credential deleting recovery_log app_key app_key_seq credential_backup`)
	s9UnlockKey = strings.Fields(`device_id ik kem attestation`)
	s9Binding   = strings.Fields(`platform pk serials key_id counter`)
	s9State     = strings.Fields(`v vault_id user_guid state_seq relay ik_seed kem_seed retired_kems rotations wake_seed devices connections
		issued denied_subs invites awaiting outgoing requests seen_msg_ids seen_inner responses outbox audit settings features blocks
		access_requests held transfer deleting sealed_release release_move announced_release account name_request name_seq owner_check
		push push_regs`)
	s9Peer = strings.Fields(`id kind name state ik kem relay chain profile suite created_at sessions last_epoch_id own_chain_at_epoch
		standing reconnect attestation recovering api_key last_active_at meta access pair_grants asks`)
	// S1 to S9 registered every feature, so their vaults may hold an
	// entry for each optional one.
	s9OptionalFeatures = []string{"actions", "calls", "intro", "leash", "location", "presence", "wallet"}
)

func onlyMembers(t *testing.T, what string, raw json.RawMessage, allowed []string) map[string]json.RawMessage {
	t.Helper()
	var o map[string]json.RawMessage
	if err := json.Unmarshal(raw, &o); err != nil {
		t.Fatalf("%s: %v", what, err)
	}
	ok := map[string]bool{}
	for _, a := range allowed {
		ok[a] = true
	}
	for k := range o {
		if !ok[k] {
			t.Fatalf("%s has member %q, which S9 did not write", what, k)
		}
	}
	return o
}

// storedPlain returns the stored header's and state's plaintext JSON.
func storedPlain(t *testing.T, st store.Store, sealer testSealer, vid, release string, dek []byte) (header, state []byte) {
	t.Helper()
	ctx := context.Background()
	hb, _, err := st.Get(ctx, store.HeaderKey(vid, release))
	if err != nil {
		t.Fatal(err)
	}
	if header, err = sealer.Unseal(ctx, hb, headerAAD(vid)); err != nil {
		t.Fatal(err)
	}
	sb, _, err := st.Get(ctx, store.StateKey(vid))
	if err != nil {
		t.Fatal(err)
	}
	if state, _, err = decryptState(dek, vid, sb); err != nil {
		t.Fatal(err)
	}
	return header, state
}

func TestVaultSealedByS9(t *testing.T) {
	ctx := context.Background()
	d := newDevFixture(t)
	sealer := d.opts.Sealer.(testSealer)
	// The app's binding as S9 recorded it: no signer. A feature entry for
	// each optional feature, as S9's vaults have, and one item of state
	// the member made (a setting).
	d.devPeer.Attestation = json.RawMessage(`{"platform":"android","pk":"AQ==","serials":["3e9","2","1"],"counter":0}`)
	entries := map[string]string{}
	d.m.mu.Lock()
	for i, n := range s9OptionalFeatures {
		entries[n] = `{"v":1,"n":` + string(rune('0'+i)) + `,"data":{"k":"` + n + `"}}`
		d.m.st.Features[n] = json.RawMessage(entries[n])
	}
	d.m.st.Settings.App = map[string]string{"app.theme": "dark"}
	d.m.st.Settings.Version = 1
	d.m.st.DeviceTokensMarked = false // an S9 vault's device tokens carry no owner_device (0.32.0, §7.1)
	dek := append([]byte(nil), d.m.dek...)
	d.m.mu.Unlock()
	if err := d.m.Lock(ctx); err != nil {
		t.Fatal(err)
	}
	// What is stored now is shaped as S9 wrote it: only S9's members.
	hraw, sraw := storedPlain(t, d.store, sealer, d.vid, testRelease.PCR0, dek)
	ho := onlyMembers(t, "header", hraw, s9Header)
	var keys []json.RawMessage
	if err := json.Unmarshal(ho["unlock_keys"], &keys); err != nil || len(keys) != 1 {
		t.Fatalf("unlock keys %s", ho["unlock_keys"])
	}
	ko := onlyMembers(t, "unlock key", keys[0], s9UnlockKey)
	onlyMembers(t, "binding", ko["attestation"], s9Binding)
	so := onlyMembers(t, "state", sraw, s9State)
	var devs map[string]json.RawMessage
	if err := json.Unmarshal(so["devices"], &devs); err != nil || len(devs) != 1 {
		t.Fatalf("devices %s", so["devices"])
	}
	for id, p := range devs {
		po := onlyMembers(t, "device "+id, p, s9Peer)
		onlyMembers(t, "device binding", po["attestation"], s9Binding)
	}

	own := ReleaseEntry{PCR0: testRelease.PCR0, Number: testRelease.Number, Status: "active"}
	next := Release{PCR0: "s10plus1", Number: testRelease.Number + 1}
	target := ReleaseEntry{PCR0: next.PCR0, Number: next.Number, Status: "active"}
	sealer2 := testSealer{key: bytes.Repeat([]byte{9}, 32)}
	params := func(o Options, running ReleaseEntry, verify func(k *UnlockKey) (json.RawMessage, error)) AltUnlockParams {
		return AltUnlockParams{Options: o, VaultID: d.vid, UserGUID: "u1", DeviceIK: d.devPeer.IK, PIN: testPIN,
			VerifyDevice: verify,
			Manifest: func(seen uint64) (*ManifestView, error) {
				return &ManifestView{Serial: seen + 1, Own: running, Lookup: func(pcr0 string) (ReleaseEntry, bool) {
					switch pcr0 {
					case own.PCR0:
						return own, true
					case target.PCR0:
						return target, true
					}
					return ReleaseEntry{}, false
				}}, nil
			},
			OwnKeyCheck: func(_ context.Context, e ReleaseEntry) (*SealKeyRecord, error) {
				return &SealKeyRecord{VerifiedBy: e.PCR0}, nil
			},
			SealerFor: func(context.Context, ReleaseEntry) (Sealer, *SealKeyRecord, error) {
				return sealer2, &SealKeyRecord{VerifiedBy: testRelease.PCR0}, nil
			}}
	}
	unbound := func(k *UnlockKey) (json.RawMessage, error) { return k.Attestation, nil } // staging S10: accepted unbound
	rec := &recSink{}
	opts := d.opts
	opts.AndroidSigners = testPins
	// Every optional feature registered, as on staging: each is given
	// exactly its S9 entry.
	loaded := map[string]*namedFeature{}
	opts.Features = []Feature{rec}
	for _, n := range s9OptionalFeatures {
		loaded[n] = &namedFeature{name: n}
		opts.Features = append(opts.Features, loaded[n])
	}

	// 1. S10 loads the S9 vault and it keeps working, still unbound.
	m, out := UnlockAlt(ctx, params(opts, own, unbound))
	if m == nil || !out.OK {
		t.Fatalf("S10 unlock of an S9 vault: %+v", out)
	}
	for _, n := range s9OptionalFeatures {
		if len(loaded[n].loads) != 1 || loaded[n].loads[0] != entries[n] {
			t.Fatalf("feature %s was given %v, S9 stored %s", n, loaded[n].loads, entries[n])
		}
	}
	if m.st.Settings.App["app.theme"] != "dark" || m.st.Devices["dev1"] == nil {
		t.Fatal("state lost")
	}
	if sg := m.signerJSON(m.st.Devices["dev1"]); sg != nil {
		t.Fatalf("an unbound vault reports a signer: %s", sg)
	}
	if _, bound := rec.find(kindSignerBound); bound {
		t.Fatal("bound without a chain")
	}
	if err := m.Lock(ctx); err != nil {
		t.Fatal(err)
	}

	// 2. The same vault on an image that registers no optional feature
	// (production's list): the seven entries are carried unchanged.
	bare := d.opts
	bare.AndroidSigners = testPins
	m, out = UnlockAlt(ctx, params(bare, own, unbound))
	if m == nil || !out.OK {
		t.Fatalf("unlock without optional features: %+v", out)
	}
	if err := m.Lock(ctx); err != nil {
		t.Fatal(err)
	}
	_, sraw = storedPlain(t, d.store, sealer, d.vid, testRelease.PCR0, dek)
	var st struct {
		Features map[string]json.RawMessage `json:"features"`
	}
	if err := json.Unmarshal(sraw, &st); err != nil {
		t.Fatal(err)
	}
	for _, n := range s9OptionalFeatures {
		if string(st.Features[n]) != entries[n] {
			t.Fatalf("entry of %s after a flush by an image without it: %s, was %s", n, st.Features[n], entries[n])
		}
	}

	// 3. It moves to the next release (approved on this one), unbound.
	mv := params(bare, own, unbound)
	mv.Update = &UpdateRequest{To: target.PCR0, ToRelease: target.Number, VerifyApproval: func(k *UnlockKey) (json.RawMessage, error) { return k.Attestation, nil }}
	m, out = UnlockAlt(ctx, mv)
	if m != nil || !out.OK || out.Update == nil || out.Update.Result != UpdateMoved {
		t.Fatalf("move: %+v %+v", out, out.Update)
	}
	// 4. The next release binds it from its chain at the confirming
	// unlock (the enclave returns the binding with the signer), audits
	// device.signer_bound, and every S9 entry is still there.
	at := opts
	at.Sealer, at.Release = sealer2, next
	rec2 := &recSink{}
	at.Features = []Feature{rec2}
	conf := params(at, target, func(*UnlockKey) (json.RawMessage, error) { return androidBinding(sigVettID, "vettid"), nil })
	m, out = UnlockAlt(ctx, conf)
	if m == nil || !out.OK {
		t.Fatalf("unlock on the next release: %+v", out)
	}
	if a, ok := rec2.find(kindSignerBound); !ok || a.Ref != "vettid" {
		t.Fatalf("device.signer_bound: %+v %v", a, ok)
	}
	if sg := string(m.signerJSON(m.st.Devices["dev1"])); sg != `{"class":"vettid","digest":"`+sigVettID+`"}` {
		t.Fatalf("signer after the binding: %s", sg)
	}
	if m.st.SealedRelease != next.PCR0 || m.st.ReleaseMove != nil {
		t.Fatalf("release state %q %+v", m.st.SealedRelease, m.st.ReleaseMove)
	}
	names := m.FeatureEntries()
	sort.Strings(names)
	for _, n := range s9OptionalFeatures {
		if raw, ok := featureEntryOf(m, n); !ok || string(raw) != entries[n] {
			t.Fatalf("entry of %s after the move: %s %v (entries %v)", n, raw, ok, names)
		}
	}
	if err := m.Lock(ctx); err != nil {
		t.Fatal(err)
	}
	// 5. And unlocks there again, bound, with the old header gone.
	m, out = UnlockAlt(ctx, params(at, target, func(k *UnlockKey) (json.RawMessage, error) { return k.Attestation, nil }))
	if m == nil || !out.OK {
		t.Fatalf("second unlock on the next release: %+v", out)
	}
	if s, _ := m.vaultSigner(""); s != sigVettID {
		t.Fatalf("binding %q", s)
	}
	if _, _, err := d.store.Get(ctx, store.HeaderKey(d.vid, testRelease.PCR0)); err == nil {
		t.Fatal("the old release's header is still there after the confirmation")
	}
	_ = m.Lock(ctx)
}

func featureEntryOf(m *Manager, name string) (json.RawMessage, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	raw, ok := m.st.Features[name]
	return raw, ok
}
