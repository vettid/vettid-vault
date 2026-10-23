package vault

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// IOS-PLAN VA4, VAULT-MESSAGING §11.7.1 "Across an iOS app" (decided
// 2026-10-11): the vault keeps the last recorded Android signer across an
// app without one (an iOS app), so that a later transfer or recovery to an
// Android app of another signer is signer_changed, confirmed and audited
// as between two Android apps. The whole chains through the enclave are in
// e2e (TestSignerAcrossIOS*).

var iosBinding = json.RawMessage(`{"platform":"ios","pk":"AQ==","key_id":"AQ==","counter":0}`)

// iosHolder is a vault whose app is an iOS app, keeping kept (digest,
// class), or nothing (an iOS-first vault).
func iosHolder(t *testing.T, kept ...string) *devFixture {
	t.Helper()
	d := boundFixture(t, "", "")
	d.devPeer.Attestation = iosBinding
	d.m.mu.Lock()
	d.m.syncUnlockKeys()
	if len(kept) == 2 {
		d.m.st.KeptSigner = kept
	}
	d.m.mu.Unlock()
	return d
}

// Android → iOS: the pending carries neither member, no confirmation, no
// audit; the vault keeps the Android signer (in the state), and the iOS
// app's device.list entry shows none.
func TestKeptSignerAtMoveToIOS(t *testing.T) {
	d := boundFixture(t, sigVettID, "vettid")
	p, id, _ := transferTo(t, d, iosBinding, 0x50)
	if _, _, ok := pendingSigner(t, p); ok {
		t.Fatalf("pending for an iOS app: %s", p.Body)
	}
	newID := d.m.st.Requests[d.m.st.Transfer.Inbound].Peer.ID
	completeTransferNow(t, d, id)
	if d.hasActivity(kindSignerChanged) || d.hasActivity(kindSignerBound) {
		t.Fatal("a move to an app without a signer was audited")
	}
	if k := d.m.st.KeptSigner; len(k) != 2 || k[0] != sigVettID || k[1] != "vettid" {
		t.Fatalf("kept %v", k)
	}
	if s, c := d.m.vaultSigner(""); s != sigVettID || c != "vettid" {
		t.Fatalf("binding %q %q", s, c)
	}
	if sg := d.m.signerJSON(d.m.st.Devices[newID]); sg != nil {
		t.Fatalf("device.list shows a signer on the iOS app: %s", sg)
	}
}

// iOS (keeping vettid) → Android of another signer: signer_changed; an
// approval without `signer` or with the wrong class is signer_unconfirmed
// and the transfer stays open; confirmed, it completes with
// device.signer_changed vettid:google_play in the audit log and the feed;
// nothing is kept any more.
func TestKeptSignerChangedOnReturn(t *testing.T) {
	d := iosHolder(t, sigVettID, "vettid")
	p, id, _ := transferTo(t, d, androidBinding(sigPlay, "google_play"), 0x50)
	if s, changed, ok := pendingSigner(t, p); !ok || s != "google_play" || !changed {
		t.Fatalf("pending %s", p.Body)
	}
	for name, tc := range map[string]struct {
		signer  string
		present bool
	}{"no signer": {"", false}, "the kept class": {"vettid", true}, "another class": {"development", true}} {
		if err := d.confirm(id, tc.signer, tc.present); !isUnconfirmed(err) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if d.m.st.Transfer == nil || d.m.st.Transfer.State != TransferOpen {
		t.Fatal("the transfer did not stay open")
	}
	if err := d.confirm(id, "google_play", true); err != nil {
		t.Fatalf("confirmed: %v", err)
	}
	newID := d.m.st.Requests[d.m.st.Transfer.Inbound].Peer.ID
	completeTransferNow(t, d, id)
	a, ok := sinkOf(d).find(kindSignerChanged)
	if !ok || a.DeviceID != newID || a.Ref != "vettid:google_play" || !a.Audit || !a.Feed || a.Priority != "high" {
		t.Fatalf("device.signer_changed: %+v %v", a, ok)
	}
	if d.hasActivity(kindSignerBound) {
		t.Fatal("audited as a binding")
	}
	if d.m.st.KeptSigner != nil {
		t.Fatalf("still kept: %v", d.m.st.KeptSigner)
	}
	if s, _ := d.m.vaultSigner(""); s != sigPlay {
		t.Fatalf("binding %q", s)
	}
}

// iOS (keeping vettid) → Android of the kept signer: signer_changed
// false, no confirmation; the transfer binds again, audited
// device.signer_bound (§11.7.1 "Across platforms"), not as a change.
func TestKeptSignerSameOnReturn(t *testing.T) {
	d := iosHolder(t, sigVettID, "vettid")
	p, id, _ := transferTo(t, d, androidBinding(sigVettID, "vettid"), 0x50)
	if s, changed, ok := pendingSigner(t, p); !ok || s != "vettid" || changed {
		t.Fatalf("pending %s", p.Body)
	}
	if err := d.confirm(id, "", false); err != nil {
		t.Fatalf("no signer needed: %v", err)
	}
	if err := d.confirm(id, "google_play", true); !isUnconfirmed(err) {
		t.Fatalf("the wrong class: %v", err)
	}
	newID := d.m.st.Requests[d.m.st.Transfer.Inbound].Peer.ID
	completeTransferNow(t, d, id)
	if d.hasActivity(kindSignerChanged) {
		t.Fatal("a return to the kept signer was audited as a change")
	}
	if a, ok := sinkOf(d).find(kindSignerBound); !ok || a.Ref != "vettid" || a.DeviceID != newID || a.Feed {
		t.Fatalf("device.signer_bound: %+v %v", a, ok)
	}
	if d.m.st.KeptSigner != nil {
		t.Fatalf("still kept: %v", d.m.st.KeptSigner)
	}
}

// iOS → iOS keeps the kept signer, unaudited.
func TestKeptSignerAcrossTwoIOSApps(t *testing.T) {
	d := iosHolder(t, sigVettID, "vettid")
	p, id, _ := transferTo(t, d, iosBinding, 0x50)
	if _, _, ok := pendingSigner(t, p); ok {
		t.Fatalf("pending %s", p.Body)
	}
	completeTransferNow(t, d, id)
	if d.hasActivity(kindSignerChanged) || d.hasActivity(kindSignerBound) {
		t.Fatal("audited")
	}
	if k := d.m.st.KeptSigner; len(k) != 2 || k[0] != sigVettID || k[1] != "vettid" {
		t.Fatalf("kept %v", k)
	}
}

// An iOS-first vault (no Android signer ever recorded): the first Android
// app is signer_bound, as before VA4.
func TestIOSFirstVaultBindsAndroid(t *testing.T) {
	d := iosHolder(t)
	p, id, _ := transferTo(t, d, androidBinding(sigPlay, "google_play"), 0x50)
	if s, changed, ok := pendingSigner(t, p); !ok || s != "google_play" || changed {
		t.Fatalf("pending %s", p.Body)
	}
	if err := d.confirm(id, "", false); err != nil {
		t.Fatalf("no signer needed: %v", err)
	}
	completeTransferNow(t, d, id)
	if a, ok := sinkOf(d).find(kindSignerBound); !ok || a.Ref != "google_play" {
		t.Fatalf("device.signer_bound: %+v %v", a, ok)
	}
	if d.hasActivity(kindSignerChanged) || d.m.st.KeptSigner != nil {
		t.Fatal("changed, or kept")
	}
}

// A kept signer the running release no longer pins is named by the class
// kept with it.
func TestKeptSignerUnpinnedClass(t *testing.T) {
	d := iosHolder(t, sigOther, "development")
	_, id, _ := transferTo(t, d, androidBinding(sigVettID, "vettid"), 0x50)
	if err := d.confirm(id, "vettid", true); err != nil {
		t.Fatal(err)
	}
	completeTransferNow(t, d, id)
	if a, ok := sinkOf(d).find(kindSignerChanged); !ok || a.Ref != "development:vettid" {
		t.Fatalf("device.signer_changed: %+v", a)
	}
}

// Recovery (credential.recover, §11.11.5) from an iOS app keeping vettid:
// to another signer, signer_changed; to the kept one, signer_bound; from
// an iOS-first vault, signer_bound. Recovery to an iOS app keeps the
// Android signer.
func TestKeptSignerAtRecovery(t *testing.T) {
	for _, tc := range []struct {
		name      string
		kept      []string
		to        json.RawMessage
		kind, ref string
		keptAfter string
	}{
		{"another signer", []string{sigVettID, "vettid"}, androidBinding(sigPlay, "google_play"), kindSignerChanged, "vettid:google_play", ""},
		{"the kept signer", []string{sigVettID, "vettid"}, androidBinding(sigVettID, "vettid"), kindSignerBound, "vettid", ""},
		{"iOS first", nil, androidBinding(sigPlay, "google_play"), kindSignerBound, "google_play", ""},
		{"to iOS", []string{sigVettID, "vettid"}, iosBinding, "", "", sigVettID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := iosHolder(t, tc.kept...)
			rec := &Peer{ID: "rec1", Kind: KindApp, State: PeerActive, Recovering: true, Attestation: tc.to}
			d.m.st.Devices[rec.ID] = rec
			d.m.hdr.Recovery = &RecoveryRecord{ID: "01JB2Z6V9K3M4N5P6Q7R8S9T30", State: RecoveryRegistered, App: &RecoveryApp{IK: make([]byte, 32)}}
			d.m.mu.Lock()
			// The registered app does not count before credential.recover.
			before, _ := d.m.vaultSigner("")
			err := d.m.completeRecovery(rec.ID, time.Now())
			d.m.mu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			if len(tc.kept) == 2 && before != tc.kept[0] {
				t.Fatalf("binding before credential.recover %q", before)
			}
			checkSignerMove(t, d, rec.ID, tc.kind, tc.ref, tc.keptAfter)
		})
	}
}

// Release R (§11.14.6): the recovery open records the vault's binding
// (the kept signer, when the app is an iOS app) in RecoveredSigner, and
// the recovered phone's first handshake moves it.
func TestKeptSignerAtRecoveredPhone(t *testing.T) {
	for _, tc := range []struct {
		name      string
		kept      []string
		to        json.RawMessage
		kind, ref string
		keptAfter string
	}{
		{"another signer", []string{sigVettID, "vettid"}, androidBinding(sigPlay, "google_play"), kindSignerChanged, "vettid:google_play", ""},
		{"the kept signer", []string{sigVettID, "vettid"}, androidBinding(sigVettID, "vettid"), kindSignerBound, "vettid", ""},
		{"iOS first", nil, androidBinding(sigPlay, "google_play"), kindSignerBound, "google_play", ""},
		{"to iOS", []string{sigVettID, "vettid"}, iosBinding, "", "", sigVettID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := iosHolder(t, tc.kept...)
			phone := d.addDevice(t, "phone", KindApp, 0x68)
			phone.peer.Recovering, phone.peer.Attestation = true, tc.to
			d.m.mu.Lock()
			// As recovery_open does before it removes the apps.
			if s, c := d.m.vaultSigner(""); s != "" {
				d.m.st.RecoveredSigner = []string{s, c}
			}
			if len(tc.kept) == 2 && (len(d.m.st.RecoveredSigner) != 2 || d.m.st.RecoveredSigner[0] != tc.kept[0]) {
				d.m.mu.Unlock()
				t.Fatalf("recovered signer %v", d.m.st.RecoveredSigner)
			}
			d.m.replaceApps("", time.Now())
			d.m.recoveredPhonePaired(phone.peer, time.Now())
			d.m.mu.Unlock()
			checkSignerMove(t, d, phone.peer.ID, tc.kind, tc.ref, tc.keptAfter)
		})
	}
}

func checkSignerMove(t *testing.T, d *devFixture, newID, kind, ref, keptAfter string) {
	t.Helper()
	got := 0
	for _, a := range sinkOf(d).got {
		if a.Kind != kindSignerBound && a.Kind != kindSignerChanged {
			continue
		}
		got++
		if a.Kind != kind || a.Ref != ref || a.DeviceID != newID || a.Feed != (kind == kindSignerChanged) {
			t.Fatalf("recorded %+v, want %s %s", a, kind, ref)
		}
	}
	if want := map[bool]int{true: 1, false: 0}[kind != ""]; got != want {
		t.Fatalf("%d signer entries, want %d", got, want)
	}
	k, _ := d.m.keptSigner()
	if k != keptAfter {
		t.Fatalf("kept %q after, want %q", k, keptAfter)
	}
}

// The state format: kept_signer is an optional member; a state written
// before VA4 (without it) loads with nothing kept, and it survives a
// round trip.
func TestKeptSignerState(t *testing.T) {
	var old State
	if err := json.Unmarshal([]byte(`{"v":1,"vault_id":"v","user_guid":"u","state_seq":3,"devices":{}}`), &old); err != nil {
		t.Fatal(err)
	}
	if old.KeptSigner != nil {
		t.Fatal("kept from nothing")
	}
	b, _ := json.Marshal(&old)
	if strings.Contains(string(b), "kept_signer") {
		t.Fatalf("an empty kept_signer is written: %s", b)
	}
	old.KeptSigner = []string{sigVettID, "vettid"}
	b, _ = json.Marshal(&old)
	var back State
	if err := json.Unmarshal(b, &back); err != nil || len(back.KeptSigner) != 2 || back.KeptSigner[0] != sigVettID || back.KeptSigner[1] != "vettid" {
		t.Fatalf("round trip %v %v", back.KeptSigner, err)
	}
	// A malformed member keeps nothing (validDigest).
	m := &Manager{st: &State{KeptSigner: []string{"a1a1", "vettid"}}}
	if d, _ := m.keptSigner(); d != "" {
		t.Fatal("a short digest kept")
	}
}

// The real recovery open (release R, §11.14.6), first run and resumed
// after its step-2 state write failed: RecoveredSigner is the vault's
// binding (an Android app's signer, or the signer kept across an iOS
// app), and the recovered phone's first handshake compares with it.
func TestRecoveryOpenRecordsSigner(t *testing.T) {
	for _, tc := range []struct {
		name      string
		app       json.RawMessage
		kept      []string
		to        json.RawMessage
		kind, ref string
		keptAfter string
	}{
		{"android to another signer", androidBinding(sigVettID, "vettid"), nil, androidBinding(sigPlay, "google_play"), kindSignerChanged, "vettid:google_play", ""},
		{"android to iOS", androidBinding(sigVettID, "vettid"), nil, iosBinding, "", "", sigVettID},
		{"iOS keeping a signer to another", iosBinding, []string{sigVettID, "vettid"}, androidBinding(sigPlay, "google_play"), kindSignerChanged, "vettid:google_play", ""},
	} {
		for _, resumed := range []bool{false, true} {
			name := tc.name
			if resumed {
				name += ", resumed"
			}
			t.Run(name, func(t *testing.T) {
				sink := &recSink{}
				f := newOpenFixtureWith(t, func(f *openFixture) {
					f.m.mu.Lock()
					f.m.st.Devices["app1"] = &Peer{ID: "app1", Kind: KindApp, State: PeerActive, Attestation: tc.app}
					f.m.st.KeptSigner = tc.kept
					f.m.dirty = true
					f.m.mu.Unlock()
					f.flush()
				})
				f.opts.AndroidSigners = testPins
				f.opts.Features = append(append([]Feature(nil), f.opts.Features...), sink)
				if resumed {
					f.st.failState = 1
					if m, out := f.open(testPIN, rPW); m != nil || out.Code != OpenRetry {
						t.Fatalf("failed completion: %+v", out)
					}
				}
				m, out := f.open(testPIN, rPW)
				if m == nil || !out.OK {
					t.Fatalf("open: %+v", out)
				}
				m.mu.Lock()
				defer m.mu.Unlock()
				if rs := m.st.RecoveredSigner; len(rs) != 2 || rs[0] != sigVettID || rs[1] != "vettid" {
					t.Fatalf("recovered signer %v", rs)
				}
				if m.st.Devices["app1"] != nil {
					t.Fatal("the old app was not removed")
				}
				phone := &Peer{ID: "phone", Kind: KindApp, State: PeerActive, Recovering: true, Attestation: tc.to}
				m.st.Devices[phone.ID] = phone
				m.recoveredPhonePaired(phone, m.now())
				got := 0
				for _, a := range sink.got {
					if a.Kind != kindSignerBound && a.Kind != kindSignerChanged {
						continue
					}
					got++
					if a.Kind != tc.kind || a.Ref != tc.ref || a.DeviceID != phone.ID || a.Feed != (tc.kind == kindSignerChanged) {
						t.Fatalf("recorded %+v, want %s %s", a, tc.kind, tc.ref)
					}
				}
				if want := map[bool]int{true: 1, false: 0}[tc.kind != ""]; got != want {
					t.Fatalf("%d signer entries, want %d", got, want)
				}
				if k, _ := m.keptSigner(); k != tc.keptAfter {
					t.Fatalf("kept %q, want %q", k, tc.keptAfter)
				}
			})
		}
	}
}
