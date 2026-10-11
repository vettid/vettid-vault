package vault

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vault/store"
	"github.com/vettid/vettid-vault/vms/altchan"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
)

// VAULT-MESSAGING 0.27.0 §11.7.1: the runtime's side of the signer
// binding. Attestation itself (one pinned digest, the chain of an
// unbound key) is devattest's; the whole flows through the enclave are in
// enclave and e2e.

// Test signer digests (64 hex digits) and the pins of a release that
// pins the first two.
var (
	sigVettID = strings.Repeat("a1", 32)
	sigPlay   = strings.Repeat("b2", 32)
	sigOther  = strings.Repeat("c3", 32)
	testPins  = []SignerPin{{Digest: sigVettID, Class: "vettid"}, {Digest: sigPlay, Class: "google_play"}}
)

// androidBinding is a device binding as the enclave stores it: with a
// signer, or (signer "") as releases before 0.27.0 wrote it.
func androidBinding(signer, class string) json.RawMessage {
	b := map[string]any{"platform": "android", "pk": "AQ==", "serials": []string{"3e9", "2", "1"}, "counter": 0}
	if signer != "" {
		b["signer"], b["signer_class"] = signer, class
	}
	raw, _ := json.Marshal(b)
	return raw
}

func TestSignerOfBinding(t *testing.T) {
	if d, c := signerOf(androidBinding(sigVettID, "vettid")); d != sigVettID || c != "vettid" {
		t.Fatalf("%q %q", d, c)
	}
	for name, raw := range map[string]json.RawMessage{
		"before 0.27.0":    androidBinding("", ""),
		"none":             nil,
		"ios":              json.RawMessage(`{"platform":"ios","pk":"AQ==","key_id":"AQ==","counter":3}`),
		"ios with signer":  json.RawMessage(`{"platform":"ios","pk":"AQ==","signer":"` + sigVettID + `"}`),
		"short digest":     json.RawMessage(`{"platform":"android","pk":"AQ==","signer":"a1a1"}`),
		"upper-case digit": json.RawMessage(`{"platform":"android","pk":"AQ==","signer":"` + strings.ToUpper(sigVettID) + `"}`),
		"not json":         json.RawMessage(`{`),
	} {
		if d, c := signerOf(raw); d != "" || c != "" {
			t.Errorf("%s: %q %q", name, d, c)
		}
	}
	o := &Options{AndroidSigners: testPins}
	for _, tc := range []struct {
		digest, recorded, class string
		pinned                  bool
	}{
		{sigVettID, "", "vettid", true},
		{sigPlay, "vettid", "google_play", true},        // the running release's class wins
		{sigOther, "development", "development", false}, // a signer no longer pinned: the recorded class
		{sigOther, "", "unknown", false},
		{sigOther, "free text", "unknown", false},
	} {
		if c, p := o.signerClass(tc.digest, tc.recorded); c != tc.class || p != tc.pinned {
			t.Errorf("%s/%s: %q %v", tc.digest[:4], tc.recorded, c, p)
		}
	}
}

// altUnlock locks nothing: it runs an alternate-channel unlock of d's
// vault as d's app with the given device check.
func altUnlock(d *devFixture, opts Options, pin string, verify func(k *UnlockKey) (json.RawMessage, error)) (*Manager, *AltUnlockOutcome) {
	own := ReleaseEntry{PCR0: testRelease.PCR0, Number: testRelease.Number, Status: "active"}
	return UnlockAlt(context.Background(), AltUnlockParams{Options: opts, VaultID: d.vid, UserGUID: "u1", DeviceIK: d.devPeer.IK, PIN: pin,
		VerifyDevice: verify,
		Manifest: func(seen uint64) (*ManifestView, error) {
			return &ManifestView{Serial: seen + 1, Own: own, Lookup: func(string) (ReleaseEntry, bool) { return own, true }}, nil
		},
		OwnKeyCheck: func(context.Context, ReleaseEntry) (*SealKeyRecord, error) {
			return &SealKeyRecord{VerifiedBy: testRelease.PCR0}, nil
		}})
}

func storedHeader(t *testing.T, d *devFixture) *Header {
	t.Helper()
	blob, _, err := d.store.Get(context.Background(), store.HeaderKey(d.vid, testRelease.PCR0))
	if err != nil {
		t.Fatal(err)
	}
	h, err := unsealHeader(context.Background(), d.opts.Sealer, blob, d.vid, testRelease.PCR0)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func logged(h *Header, kind string) (n int, ref string) {
	for _, e := range h.RecoveryLog {
		if e.Kind == kind {
			n++
			ref = e.Ref
		}
	}
	return n, ref
}

// §11.7.1 "The refusal": signer_refused is answered inside the uniform
// sealed result (not dropped) to a request whose signature and assertion
// verified; it is decided before the PIN (a wrong PIN and a running
// backoff do not change the answer) and neither counts toward nor resets
// the backoff; it raises no alarm and reports nothing to the host; it is
// recorded in the sealed header's log at most once per 24 hours and
// written to the audit log, without a device, at the next unlock that
// succeeds. A wrong signature or assertion never yields it.
func TestSignerRefusedAtUnlock(t *testing.T) {
	d := newDevFixture(t)
	d.devPeer.Attestation = androidBinding(sigOther, "development") // bound to a signer this release does not pin
	// Two earlier PIN failures: the backoff state that must not move.
	d.m.hdr.Backoff = Backoff{Failures: 2, NotBefore: time.Now().Add(-time.Minute)}
	if err := d.m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	clock := time.Now()
	var events []LifecycleEvent
	opts := d.opts
	opts.AndroidSigners = testPins
	opts.Now = func() time.Time { return clock }
	opts.Lifecycle = func(ev LifecycleEvent) { events = append(events, ev) }
	refuse := func(k *UnlockKey) (json.RawMessage, error) { return nil, &SignerRefused{Reason: SignerUnpinned} }
	before := storedHeader(t, d)
	for i, pin := range []string{testPIN, "000000", testPIN} {
		m, out := altUnlock(d, opts, pin, refuse)
		if m != nil || out.OK || out.Code != CodeSignerRefused || out.Drop || len(out.DeviceKEM) == 0 {
			t.Fatalf("attempt %d (pin %s): %+v", i, pin, out)
		}
		if out.RetryAfter != 0 || out.Token != "" || len(out.Events) != 0 {
			t.Fatalf("attempt %d: the refusal carries %+v", i, out)
		}
	}
	h := storedHeader(t, d)
	if h.Backoff.Failures != 2 || !h.Backoff.NotBefore.Equal(before.Backoff.NotBefore) {
		t.Fatalf("the backoff moved: %+v, was %+v", h.Backoff, before.Backoff)
	}
	if n, ref := logged(h, kindSignerRefused); n != 1 || ref != SignerUnpinned {
		t.Fatalf("header log after three refusals: %d entries, ref %q", n, ref)
	}
	if h.HeaderSeq != before.HeaderSeq+1 {
		t.Fatalf("header_seq %d, was %d: one write for one log entry", h.HeaderSeq, before.HeaderSeq)
	}
	if len(events) != 0 {
		t.Fatalf("a refusal reported to the host: %+v", events)
	}
	// During a running backoff the answer is still signer_refused.
	if err := rewriteHeader(d, func(h *Header) { h.Backoff.NotBefore = clock.Add(time.Hour) }); err != nil {
		t.Fatal(err)
	}
	if _, out := altUnlock(d, opts, testPIN, refuse); out.Code != CodeSignerRefused || out.RetryAfter != 0 {
		t.Fatalf("during a backoff: %+v", out)
	}
	if err := rewriteHeader(d, func(h *Header) { h.Backoff.NotBefore = clock.Add(-time.Minute) }); err != nil {
		t.Fatal(err)
	}
	// 24 hours later: one more entry (this time the unbound case).
	clock = clock.Add(24*time.Hour + time.Minute)
	for i := 0; i < 2; i++ {
		if _, out := altUnlock(d, opts, testPIN, func(*UnlockKey) (json.RawMessage, error) { return nil, &SignerRefused{Reason: SignerUnbound} }); out.Code != CodeSignerRefused {
			t.Fatalf("a day later: %+v", out)
		}
	}
	if n, ref := logged(storedHeader(t, d), kindSignerRefused); n != 2 || ref != SignerUnbound {
		t.Fatalf("header log a day later: %d entries, ref %q", n, ref)
	}
	// A wrong signature is dropped and a wrong assertion is `attestation`:
	// neither is signer_refused, and neither is logged.
	if m, out := altUnlock(d, opts, testPIN, func(*UnlockKey) (json.RawMessage, error) { return nil, ErrDeviceSig }); m != nil || !out.Drop || out.Code == CodeSignerRefused {
		t.Fatalf("wrong signature: %+v", out)
	}
	if m, out := altUnlock(d, opts, testPIN, func(*UnlockKey) (json.RawMessage, error) { return nil, ErrDeviceAttestation }); m != nil || out.Drop || out.Code != CodeAttestation {
		t.Fatalf("wrong assertion: %+v", out)
	}
	if n, _ := logged(storedHeader(t, d), kindSignerRefused); n != 2 {
		t.Fatalf("a failed signature or assertion was logged as a refusal: %d", n)
	}
	// The next unlock that succeeds (a release that pins the signer
	// again, or after a recovery) writes them to the audit log.
	rec := &recSink{}
	ok := opts
	ok.Features = []Feature{rec}
	m, out := altUnlock(d, ok, testPIN, func(k *UnlockKey) (json.RawMessage, error) { return k.Attestation, nil })
	if m == nil || !out.OK {
		t.Fatalf("unlock: %+v", out)
	}
	var refs []string
	for _, a := range rec.got {
		if a.Kind == kindSignerRefused {
			if a.DeviceID != "" || a.ConnectionID != "" || !a.Audit || a.Feed {
				t.Fatalf("device.signer_refused entry %+v", a)
			}
			refs = append(refs, a.Ref)
		}
	}
	sort.Strings(refs)
	if strings.Join(refs, ",") != "unbound,unpinned" {
		t.Fatalf("audited refusals %v", refs)
	}
	if len(m.hdr.RecoveryLog) != 0 || m.hdr.Backoff.Failures != 0 {
		t.Fatalf("after the unlock: log %v, backoff %+v", m.hdr.RecoveryLog, m.hdr.Backoff)
	}
	for _, ev := range events {
		if strings.HasPrefix(ev.Event, "alarm") {
			t.Fatalf("an alarm was reported: %+v", ev)
		}
	}
	_ = m.Lock(context.Background())
}

// rewriteHeader edits d's stored header in place (test setup).
func rewriteHeader(d *devFixture, edit func(*Header)) error {
	ctx := context.Background()
	key := store.HeaderKey(d.vid, testRelease.PCR0)
	blob, ver, err := d.store.Get(ctx, key)
	if err != nil {
		return err
	}
	h, err := unsealHeader(ctx, d.opts.Sealer, blob, d.vid, testRelease.PCR0)
	if err != nil {
		return err
	}
	edit(h)
	b, err := sealHeader(ctx, d.opts.Sealer, h)
	if err != nil {
		return err
	}
	_, err = d.store.Put(ctx, key, b, ver)
	return err
}

// §11.7.1 "Vaults enrolled before 0.27.0": when the enclave bound the key
// from its chain at an unlock, the new binding is written with the header
// and the binding is audited (device.signer_bound, ref = the class) at
// that unlock; later unlocks record nothing; device.list then shows the
// signer on the app's entry.
func TestSignerBoundAtUnlock(t *testing.T) {
	d := newDevFixture(t)
	d.devPeer.Attestation = androidBinding("", "") // a binding from before 0.27.0
	if err := d.m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s, _ := signerOf(storedHeader(t, d).UnlockKeys[0].Attestation); s != "" {
		t.Fatal("the fixture's header is bound")
	}
	rec := &recSink{}
	opts := d.opts
	opts.AndroidSigners = testPins
	opts.Features = []Feature{rec}
	bind := func(*UnlockKey) (json.RawMessage, error) { return androidBinding(sigVettID, "vettid"), nil }
	m, out := altUnlock(d, opts, testPIN, bind)
	if m == nil || !out.OK {
		t.Fatalf("unlock: %+v", out)
	}
	a, ok := rec.find(kindSignerBound)
	if !ok || a.Ref != "vettid" || !a.Audit || a.Feed {
		t.Fatalf("device.signer_bound: %+v %v", a, ok)
	}
	if s, c := signerOf(storedHeader(t, d).UnlockKeys[0].Attestation); s != sigVettID || c != "vettid" {
		t.Fatalf("stored binding %q %q", s, c)
	}
	if sg := string(m.signerJSON(m.st.Devices["dev1"])); sg != `{"class":"vettid","digest":"`+sigVettID+`"}` {
		t.Fatalf("device.list signer %s", sg)
	}
	if err := m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Bound now: the enclave returns the stored binding and nothing more
	// is audited.
	rec2 := &recSink{}
	opts.Features = []Feature{rec2}
	m, out = altUnlock(d, opts, testPIN, func(k *UnlockKey) (json.RawMessage, error) { return k.Attestation, nil })
	if m == nil || !out.OK {
		t.Fatalf("second unlock: %+v", out)
	}
	if _, again := rec2.find(kindSignerBound); again {
		t.Fatal("bound twice")
	}
	_ = m.Lock(context.Background())
}

// §10.3, §11.7.1 "What the member sees": device.list carries
// signer{class, digest} on the app's entry only, for an Android app with
// a recorded signer; nothing for a vault that is not bound, for iOS, for
// a desktop or an agent, or for a recovering app.
func TestDeviceListSigner(t *testing.T) {
	d := newDevFixture(t)
	d.m.opt.AndroidSigners = testPins
	desk := d.addDevice(t, "desk1", KindDesktop, 0x60)
	desk.peer.Attestation = androidBinding(sigVettID, "vettid") // never an app's binding
	list := func() []strictObj {
		t.Helper()
		r, _ := d.request(t, "device.list", `{}`)
		var body struct {
			Devices []strictObj `json:"devices"`
		}
		if err := json.Unmarshal(r.Body, &body); err != nil {
			t.Fatal(err)
		}
		return body.Devices
	}
	signers := func() map[string]string {
		out := map[string]string{}
		for _, e := range list() {
			if s, ok := e["signer"]; ok {
				out[string(e["id"])] = string(s)
			}
		}
		return out
	}
	// setBinding replaces the app's binding where it is authoritative:
	// the sealed header's unlock key (and the device record's copy).
	setBinding := func(raw json.RawMessage) {
		d.m.mu.Lock()
		defer d.m.mu.Unlock()
		d.devPeer.Attestation = raw
		d.m.syncUnlockKeys()
		for i := range d.m.hdr.UnlockKeys {
			d.m.hdr.UnlockKeys[i].Attestation = raw
		}
	}
	if s := signers(); len(s) != 0 {
		t.Fatalf("an unbound vault reports a signer: %v", s)
	}
	setBinding(androidBinding(sigPlay, "vettid"))
	want := `{"class":"google_play","digest":"` + sigPlay + `"}` // the running release's class
	if s := signers(); len(s) != 1 || s[`"dev1"`] != want {
		t.Fatalf("signers %v", s)
	}
	setBinding(json.RawMessage(`{"platform":"ios","pk":"AQ==","key_id":"AQ==","counter":1}`))
	if s := signers(); len(s) != 0 {
		t.Fatalf("an iOS app reports a signer: %v", s)
	}
	setBinding(androidBinding(sigVettID, "vettid"))
	d.devPeer.Recovering = true
	if s := d.m.signerJSON(d.devPeer); s != nil {
		t.Fatalf("a recovering app reports a signer: %s", s)
	}
	d.devPeer.Recovering = false
	// The sealed header's copy is authoritative once written: the device
	// record's own copy is not what is reported.
	d.devPeer.Attestation = androidBinding(sigPlay, "google_play")
	if s := signers(); s[`"dev1"`] != `{"class":"vettid","digest":"`+sigVettID+`"}` {
		t.Fatalf("the header's binding is not the one reported: %v", s)
	}
}

type strictObj map[string]json.RawMessage

// attestAs makes the fixture's device attestation return a binding with
// the given signer for every app pairing (a transfer's new app).
func attestAs(d *devFixture, binding json.RawMessage) {
	d.m.opt.DeviceAttest = func(*altchan.DeviceAttest, [32]byte, time.Time) (json.RawMessage, error) {
		return binding, nil
	}
}

// transferTo runs a transfer of d's vault up to the holder's
// device.transfer.pending and returns it with the transfer id and the
// new app.
func transferTo(t *testing.T, d *devFixture, newBinding json.RawMessage, seed byte) (pending *envelope.Inner, id string, n *newcomer) {
	t.Helper()
	attestAs(d, newBinding)
	inv := d.transferInvite(t)
	n = newNewcomer(t, seed)
	n.hsInitAttest(t, d.m, handshake.PurposeApp, inv.ID, "t"+string(rune('0'+seed%10)), testAttest)
	n.finish(t, d)
	for _, r := range d.responses(t) {
		if r.Type == "device.transfer.pending" {
			pending = r
		}
	}
	if pending == nil {
		t.Fatal("the holder was not asked")
	}
	return pending, inv.ID, n
}

func completeTransferNow(t *testing.T, d *devFixture, id string) {
	t.Helper()
	d.m.mu.Lock()
	err := d.m.approveTransfer(context.Background(), id, d.m.now())
	if err == nil {
		d.m.afterRespond(d.m.now())
		d.m.syncUnlockKeys()
	}
	d.m.mu.Unlock()
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
}

func pendingSigner(t *testing.T, p *envelope.Inner) (signer string, changed, present bool) {
	t.Helper()
	var o strictObj
	if err := json.Unmarshal(p.Body, &o); err != nil {
		t.Fatal(err)
	}
	_, hasS := o["signer"]
	_, hasC := o["signer_changed"]
	if hasS != hasC {
		t.Fatalf("signer and signer_changed do not come together: %s", p.Body)
	}
	if !hasS {
		return "", false, false
	}
	if json.Unmarshal(o["signer"], &signer) != nil || json.Unmarshal(o["signer_changed"], &changed) != nil {
		t.Fatalf("pending %s", p.Body)
	}
	if strings.Contains(string(p.Body), sigVettID) || strings.Contains(string(p.Body), sigPlay) {
		t.Fatalf("the pending carries a digest: %s", p.Body)
	}
	return signer, changed, true
}

func isUnconfirmed(err error) bool {
	var he *HandlerError
	return errors.As(err, &he) && he.Code == "signer_unconfirmed"
}

// boundFixture is a vault whose app is bound to signer.
func boundFixture(t *testing.T, signer, class string) *devFixture {
	d := newDevFixture(t)
	sinkOf(d)
	d.m.opt.AndroidSigners = testPins
	d.devPeer.Attestation = androidBinding(signer, class)
	d.m.mu.Lock()
	d.m.syncUnlockKeys()
	d.m.mu.Unlock()
	return d
}

func (d *devFixture) confirm(id, signer string, present bool) error {
	d.m.mu.Lock()
	defer d.m.mu.Unlock()
	return d.m.confirmTransferSigner(id, signer, present)
}

// §6.7.1, §11.7.1: a transfer to the same signer needs no `signer` in
// the approval and audits no device.signer_changed.
func TestTransferSameSigner(t *testing.T) {
	d := boundFixture(t, sigVettID, "vettid")
	p, id, n := transferTo(t, d, androidBinding(sigVettID, "vettid"), 0x50)
	if s, changed, ok := pendingSigner(t, p); !ok || s != "vettid" || changed {
		t.Fatalf("pending %s", p.Body)
	}
	if err := d.confirm(id, "", false); err != nil {
		t.Fatalf("no signer needed: %v", err)
	}
	if err := d.confirm(id, "vettid", true); err != nil {
		t.Fatalf("naming the same class: %v", err)
	}
	if err := d.confirm(id, "google_play", true); !isUnconfirmed(err) {
		t.Fatalf("naming another class: %v", err)
	}
	completeTransferNow(t, d, id)
	if d.hasActivity(kindSignerChanged) || d.hasActivity(kindSignerBound) {
		t.Fatal("a transfer to the same signer was audited as a change")
	}
	if s, _ := d.m.vaultSigner(""); s != sigVettID {
		t.Fatalf("binding %q", s)
	}
	_ = n
}

// To another pinned signer: the pending says signer_changed; an approval
// without `signer`, or with the wrong class, is signer_unconfirmed and
// the transfer stays open; with it the transfer completes, the binding is
// the new signer, and device.signer_changed is audited and put in the
// feed (priority high) with both classes and no digest.
func TestTransferChangesSigner(t *testing.T) {
	d := boundFixture(t, sigVettID, "vettid")
	p, id, n := transferTo(t, d, androidBinding(sigPlay, "google_play"), 0x50)
	if s, changed, ok := pendingSigner(t, p); !ok || s != "google_play" || !changed {
		t.Fatalf("pending %s", p.Body)
	}
	for name, tc := range map[string]struct {
		signer  string
		present bool
	}{"no signer": {"", false}, "the old class": {"vettid", true}, "another class": {"development", true}, "empty": {"", true}, "a digest": {sigPlay, true}} {
		if err := d.confirm(id, tc.signer, tc.present); !isUnconfirmed(err) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if d.m.st.Transfer == nil || d.m.st.Transfer.State != TransferOpen || d.m.st.Requests[d.m.st.Transfer.Inbound] == nil {
		t.Fatal("the transfer did not stay open")
	}
	if s, _ := d.m.vaultSigner(""); s != sigVettID {
		t.Fatal("the binding moved before the approval")
	}
	if err := d.confirm(id, "google_play", true); err != nil {
		t.Fatalf("confirmed: %v", err)
	}
	// Another transfer id is left to the approval (not_found there).
	if err := d.confirm("01JB2Z6V9K3M4N5P6Q7R8S9T0V", "", false); err != nil {
		t.Fatalf("unknown transfer: %v", err)
	}
	newID := d.m.st.Requests[d.m.st.Transfer.Inbound].Peer.ID
	completeTransferNow(t, d, id)
	a, ok := sinkOf(d).find(kindSignerChanged)
	if !ok || a.DeviceID != newID || a.Ref != "vettid:google_play" || !a.Audit || !a.Feed || a.Priority != "high" {
		t.Fatalf("device.signer_changed: %+v %v", a, ok)
	}
	if strings.Contains(a.Ref, sigPlay) || strings.Contains(a.Ref, sigVettID) {
		t.Fatal("a digest in the audit entry")
	}
	if s, c := d.m.vaultSigner(""); s != sigPlay || c != "google_play" {
		t.Fatalf("binding %q %q", s, c)
	}
	keys := d.m.hdr.UnlockKeys
	if len(keys) != 1 {
		t.Fatalf("unlock keys %d", len(keys))
	}
	if s, _ := signerOf(keys[0].Attestation); s != sigPlay {
		t.Fatalf("the header's binding %q", s)
	}
	if sg := string(d.m.signerJSON(d.m.st.Devices[newID])); sg != `{"class":"google_play","digest":"`+sigPlay+`"}` {
		t.Fatalf("device.list signer %s", sg)
	}
	_ = n
}

// From a vault with no recorded signer (staging at S10): signer_changed
// is false, no `signer` is needed, and the transfer binds and audits
// device.signer_bound.
func TestTransferFromUnboundVault(t *testing.T) {
	d := boundFixture(t, "", "")
	p, id, _ := transferTo(t, d, androidBinding(sigVettID, "vettid"), 0x50)
	if s, changed, ok := pendingSigner(t, p); !ok || s != "vettid" || changed {
		t.Fatalf("pending %s", p.Body)
	}
	if err := d.confirm(id, "", false); err != nil {
		t.Fatalf("no signer needed: %v", err)
	}
	newID := d.m.st.Requests[d.m.st.Transfer.Inbound].Peer.ID
	completeTransferNow(t, d, id)
	a, ok := sinkOf(d).find(kindSignerBound)
	if !ok || a.Ref != "vettid" || a.DeviceID != newID || a.Feed {
		t.Fatalf("device.signer_bound: %+v %v", a, ok)
	}
	if d.hasActivity(kindSignerChanged) {
		t.Fatal("binding an unbound vault was audited as a change")
	}
	if s, _ := d.m.vaultSigner(""); s != sigVettID {
		t.Fatalf("binding %q", s)
	}
}

// A new app without a signer (iOS): the pending carries neither member,
// and a `signer` in the approval names nothing the vault will do.
func TestTransferToAppWithoutSigner(t *testing.T) {
	d := boundFixture(t, sigVettID, "vettid")
	p, id, _ := transferTo(t, d, json.RawMessage(`{"platform":"ios","pk":"AQ==","key_id":"AQ==","counter":0}`), 0x50)
	if _, _, ok := pendingSigner(t, p); ok {
		t.Fatalf("pending for an iOS app: %s", p.Body)
	}
	if err := d.confirm(id, "", false); err != nil {
		t.Fatal(err)
	}
	if err := d.confirm(id, "vettid", true); !isUnconfirmed(err) {
		t.Fatalf("a class named for an app without a signer: %v", err)
	}
	completeTransferNow(t, d, id)
	if d.hasActivity(kindSignerChanged) || d.hasActivity(kindSignerBound) {
		t.Fatal("audited")
	}
	if s, _ := d.m.vaultSigner(""); s != "" {
		t.Fatalf("binding %q after a move to an app without one", s)
	}
}

// The class of a signer the running release no longer pins comes from
// the binding (recorded when it was made), so a change away from it is
// still named.
func TestSignerChangedFromUnpinned(t *testing.T) {
	d := boundFixture(t, sigOther, "development")
	p, id, _ := transferTo(t, d, androidBinding(sigVettID, "vettid"), 0x50)
	if s, changed, ok := pendingSigner(t, p); !ok || s != "vettid" || !changed {
		t.Fatalf("pending %s", p.Body)
	}
	completeTransferNow(t, d, id)
	if a, ok := sinkOf(d).find(kindSignerChanged); !ok || a.Ref != "development:vettid" {
		t.Fatalf("device.signer_changed: %+v", a)
	}
}
