package vault

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/vettid/vettid-vault/vault/store"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// counterFeature changes its own state in a queued request, as LEASH does
// when an agent's leash.grant.list takes a grant_seq (§10.11): each
// test.count takes the next number and answers it.
type counterFeature struct{ n uint64 }

func (c *counterFeature) Name() string { return "counter" }
func (c *counterFeature) Types() []TypeSpec {
	return []TypeSpec{
		{Type: "test.count", Request: true, From: []string{KindApp}},
		{Type: "test.ring", Request: true, From: []string{KindConnection}}, // as a call.offer
	}
}
func (c *counterFeature) Handle(context.Context, *Session, *envelope.Inner) (json.RawMessage, error) {
	c.n++
	return json.RawMessage(`{"n":` + strconv.FormatUint(c.n, 10) + `}`), nil
}
func (c *counterFeature) Load(raw json.RawMessage) error {
	if len(raw) == 0 {
		return nil
	}
	return json.Unmarshal(raw, &c.n)
}
func (c *counterFeature) Save() (json.RawMessage, error) { return json.Marshal(c.n) }

// A feature's state changed by a queued request is stored before the
// answer naming it goes out (§8.2, §8.3): a failed write sends nothing; the
// next write that succeeds stores the feature's state and only then sends
// the answer; and a vault reopened after a crash (no write of its own) has
// the number the answer carried, so it is never given out again.
//
// The first half follows TestFailedWriteThenLaterWriteSendsStored, which
// does this for core state; what is new here is a feature's state in the
// same write, and the reopen.
func TestFeatureStateStoredBeforeAnswer(t *testing.T) {
	d := newDevFixture(t)
	c := &counterFeature{}
	d.m.addFeature(c)
	_ = d.responses(t)
	failWrites(d, 1)
	if err := d.send("test.count", []byte(`{}`)); err == nil {
		t.Fatal("the batch's write did not fail")
	}
	d.m.mu.Lock()
	d.m.drainOutbox(context.Background()) // any drain in between (the attachment runner's)
	d.m.mu.Unlock()
	if got := d.responses(t); len(got) != 0 {
		t.Fatalf("sent before a write stored it: %v", typesOf(got))
	}
	if err := d.send("device.list", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	got := d.responses(t)
	if types := typesOf(got); len(types) != 2 || types[0] != "test.count" || types[1] != "device.list" {
		t.Fatalf("after the later write: %v", types)
	}
	if string(got[0].Body) != `{"n":1}` {
		t.Fatalf("test.count answered %s", got[0].Body)
	}
	d.m.mu.Lock()
	_ = d.m.flushThenDrain(context.Background())
	d.m.mu.Unlock()
	if again := d.responses(t); len(again) != 0 {
		t.Fatalf("sent again: %v", typesOf(again))
	}

	// Reopen from the store without a write of the vault's own.
	d.m.Crash()
	c2 := &counterFeature{}
	opts := d.opts
	opts.Store = d.store
	opts.Features = append(append([]Feature(nil), d.opts.Features...), c2)
	m, _, err := Unlock(context.Background(), UnlockParams{Options: opts, VaultID: d.vid, PIN: testPIN, UnlockSecret: testSecret})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Crash()
	if c2.n != 1 {
		t.Fatalf("the stored state has %d, the answer said 1", c2.n)
	}
}

// failingCounter is counterFeature as a release that cannot read the stored
// state (a later release's, or a damaged one).
type failingCounter struct{ counterFeature }

func (f *failingCounter) Load(json.RawMessage) error {
	return errors.New("a state from a later release")
}

// §3.3 (0.88.17, owner decision 2026-11-11): a feature whose part of the
// state does not read fails closed. It is audited feature.load_failed, does
// not run (its device type is answered unsupported_type), and its part is
// carried unchanged through flushes, so a release that can read it finds it
// whole; it is never run, or saved, as an empty state.
func TestFeatureThatDoesNotLoadFailsClosed(t *testing.T) {
	d := newDevFixture(t)
	d.m.addFeature(&counterFeature{})
	_ = d.responses(t)
	if r, _ := d.request(t, "test.count", `{}`); r.Error != nil {
		t.Fatal(r.Error.Code)
	}
	d.m.mu.Lock()
	_ = d.m.flushThenDrain(context.Background())
	stored := append(json.RawMessage(nil), d.m.st.Features["counter"]...)
	d.m.mu.Unlock()
	if string(stored) != "1" {
		t.Fatalf("stored %s", stored)
	}
	reopen := func(fs ...Feature) *Manager {
		d.m.Crash()
		opts := d.opts
		opts.Store = d.store
		opts.Features = append(append([]Feature(nil), d.opts.Features...), fs...)
		m, _, err := Unlock(context.Background(), UnlockParams{Options: opts, VaultID: d.vid, PIN: testPIN, UnlockSecret: testSecret})
		if err != nil {
			t.Fatal(err)
		}
		d.m = m
		return m
	}

	sink := &recSink{}
	m := reopen(&failingCounter{}, sink)
	var refs []string
	for _, a := range sink.got {
		if a.Kind == "feature.load_failed" {
			refs = append(refs, a.Ref)
		}
	}
	if len(refs) != 1 || refs[0] != "counter" {
		t.Fatalf("audited %v", refs)
	}
	if r, _ := d.request(t, "test.count", `{}`); r.Error == nil || r.Error.Code != "unsupported_type" {
		t.Fatalf("a feature that did not load ran: %+v", r)
	}
	m.mu.Lock()
	_ = m.flushThenDrain(context.Background())
	kept := append(json.RawMessage(nil), m.st.Features["counter"]...)
	m.mu.Unlock()
	if string(kept) != string(stored) {
		t.Fatalf("the stored part was changed: %s, was %s", kept, stored)
	}

	// A release that reads it finds it whole, and goes on from it.
	c3 := &counterFeature{}
	reopen(c3)
	defer d.m.Crash()
	if c3.n != 1 {
		t.Fatalf("the state found later: %d", c3.n)
	}
	if r, _ := d.request(t, "test.count", `{}`); r.Error != nil || string(r.Body) != `{"n":2}` {
		t.Fatalf("after: %+v", r)
	}
}

// requiredCounter is counterFeature as a feature other features call
// directly (vault.Required), in a release that cannot read its state.
type requiredCounter struct{ failingCounter }

func (r *requiredCounter) RequiredAtUnlock() bool { return true }

// §3.3 (0.88.17, owner decision 2026-11-11): when a feature others call
// directly cannot read its part, it is not run half: the unlock is refused
// with no write,
// no unlocked, answered state_unreadable (not state_unsupported, which tells
// the member to set the vault up again); a release that reads it opens the
// vault, its part whole.
func TestRequiredFeatureThatDoesNotLoadRefusesTheUnlock(t *testing.T) {
	f := newRFixture(t)
	f.m.mu.Lock()
	f.m.st.Features["counter"] = json.RawMessage("7")
	f.m.dirty = true
	f.m.mu.Unlock()
	f.flush()
	if err := f.m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	base := f.opts.Features
	f.opts.Features = append(append([]Feature(nil), base...), &requiredCounter{})
	wc := &writeCounter{Store: f.opts.Store}
	store := f.opts.Store
	f.opts.Store = wc
	gauge := Unlocked()
	m, out := f.unlock(testPIN, testSecret)
	if m != nil || out.OK || out.Code != CodeStateUnreadable {
		t.Fatalf("%+v", out)
	}
	if Unlocked() != gauge {
		t.Fatalf("unlocked gauge %d, was %d: the manager was not zeroized", Unlocked(), gauge)
	}
	if wc.count() != 0 {
		t.Fatalf("%d writes on refusal", wc.count())
	}
	for _, ev := range out.Events {
		if ev.Event == "unlocked" {
			t.Fatal("unlocked reported")
		}
	}

	// A feature that is not Required is not run, and the unlock goes on.
	f.opts.Store = store
	f.opts.Features = append(append([]Feature(nil), base...), &failingCounter{})
	m, out = f.unlock(testPIN, testSecret)
	if m == nil || !out.OK {
		t.Fatalf("not required: %+v", out)
	}
	_ = m.Lock(context.Background())

	// A release that reads it opens the vault, the part whole.
	c := &counterFeature{}
	f.opts.Features = append(append([]Feature(nil), base...), c)
	m, out = f.unlock(testPIN, testSecret)
	if m == nil || !out.OK || c.n != 7 {
		t.Fatalf("reader: %+v, n %d", out, c.n)
	}
	_ = m.Lock(context.Background())
}

// §3.3 (0.88.17): a recovery open refuses the same way, state_unreadable,
// with no write of the state (the attempt was spent before it opened).
func TestRequiredFeatureThatDoesNotLoadRefusesTheRecoveryOpen(t *testing.T) {
	f := newOpenFixtureWith(t, func(f *openFixture) {
		f.m.mu.Lock()
		f.m.st.Features["counter"] = json.RawMessage("7")
		f.m.dirty = true
		f.m.mu.Unlock()
		f.flush()
	})
	before, _, err := f.st.Get(context.Background(), store.StateKey(f.vid))
	if err != nil {
		t.Fatal(err)
	}
	f.opts.Features = append(append([]Feature(nil), f.opts.Features...), &requiredCounter{})
	wc := &writeCounter{Store: f.opts.Store}
	f.opts.Store = wc
	gauge := Unlocked()
	m, out := f.open(testPIN, rPW)
	if m != nil || out.OK || out.Code != CodeStateUnreadable || !out.AttemptUsed() {
		t.Fatalf("recovery open: %+v (the attempt is spent before the state opens)", out)
	}
	if Unlocked() != gauge {
		t.Fatalf("unlocked gauge %d, was %d", Unlocked(), gauge)
	}
	if wc.count() != 0 {
		t.Fatalf("%d store writes on refusal", wc.count())
	}
	after, _, err := f.st.Get(context.Background(), store.StateKey(f.vid))
	if err != nil || string(before) != string(after) {
		t.Fatal("the state was written after it opened")
	}
}

// The recovery's resume path (the stored `next`, no new attempt) refuses
// state_unreadable too, before restoreLive or any write. The stored state
// is replaced, after step 1, by the same state carrying a part the
// Required feature cannot read.
func TestRequiredFeatureThatDoesNotLoadRefusesTheRecoveryResume(t *testing.T) {
	var dek []byte
	f := newOpenFixtureWith(t, func(f *openFixture) {
		f.m.mu.Lock()
		dek = append([]byte(nil), f.m.dek...)
		f.m.mu.Unlock()
	})
	f.st.failState = 1
	if m, out := f.open(testPIN, rPW); m != nil || out.Code != OpenRetry {
		t.Fatalf("setup: failed completion: %+v", out)
	}
	if h := f.storedHeader(); h.Next == nil || h.Next.Reason != ReplaceRecovery {
		t.Fatal("setup: step 1 not stored")
	}
	ctx := context.Background()
	blob, ver, err := f.st.Get(ctx, store.StateKey(f.vid))
	if err != nil {
		t.Fatal(err)
	}
	dv, _ := StateDEKVersion(blob)
	pt, seq, err := decryptState(dek, f.vid, blob)
	if err != nil {
		t.Fatal(err)
	}
	var st map[string]any
	if err := json.Unmarshal(pt, &st); err != nil {
		t.Fatal(err)
	}
	feats, _ := st["features"].(map[string]any)
	if feats == nil {
		feats = map[string]any{}
	}
	feats["counter"] = 7
	st["features"] = feats
	pt, _ = json.Marshal(st)
	nb, err := encryptState(dek, dv, f.vid, seq, pt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.Store.Put(ctx, store.StateKey(f.vid), nb, ver); err != nil {
		t.Fatal(err)
	}
	f.opts.Features = append(append([]Feature(nil), f.opts.Features...), &requiredCounter{})
	wc := &writeCounter{Store: f.opts.Store}
	f.opts.Store = wc
	gauge := Unlocked()
	m, out := f.open(testPIN, rPW)
	if m != nil || out.OK || out.Code != CodeStateUnreadable || out.AttemptUsed() {
		t.Fatalf("resume: %+v (no attempt is spent on the resume path)", out)
	}
	if Unlocked() != gauge {
		t.Fatalf("unlocked gauge %d, was %d", Unlocked(), gauge)
	}
	if wc.count() != 0 {
		t.Fatalf("%d store writes on refusal", wc.count())
	}
}

// §11.10.4 before §3.3: a stale header (a release the vault has left) is
// still answered wrong_release when a Required feature's part does not read
// either: the release decisions come first.
func TestUnreadableRequiredPartStillAnswersWrongRelease(t *testing.T) {
	f := newRFixture(t)
	f.m.mu.Lock()
	f.m.st.Features["counter"] = json.RawMessage("7")
	f.m.st.SealedRelease = "a release this vault has left"
	f.m.dirty = true
	f.m.mu.Unlock()
	f.flush()
	if err := f.m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.opts.Features = append(append([]Feature(nil), f.opts.Features...), &requiredCounter{})
	gauge := Unlocked()
	m, out := f.unlock(testPIN, testSecret)
	if m != nil || out.OK || out.Code != CodeWrongRelease {
		t.Fatalf("stale header: %+v", out)
	}
	if Unlocked() != gauge {
		t.Fatalf("unlocked gauge %d, was %d", Unlocked(), gauge)
	}
}

// storedPart is feature name's part of the state as stored, decrypted.
func storedPart(t *testing.T, d *devFixture, name string) string {
	t.Helper()
	d.m.mu.Lock()
	defer d.m.mu.Unlock()
	blob, _, err := d.store.Get(context.Background(), store.StateKey(d.vid))
	if err != nil {
		t.Fatal(err)
	}
	pt, _, err := decryptState(d.m.dek, d.vid, blob)
	if err != nil {
		t.Fatal(err)
	}
	var st struct {
		Features map[string]json.RawMessage `json:"features"`
	}
	if err := json.Unmarshal(pt, &st); err != nil {
		t.Fatal(err)
	}
	return string(st.Features[name])
}

// The part of a feature that does not run is carried byte for byte, as
// stored: also a value a re-encoding would change (key order, a number
// past float64, 1.0, characters JSON may escape, a duplicate key). It is
// compared in the decrypted stored state, not in memory.
func TestAnUnrunPartIsCarriedByteForByte(t *testing.T) {
	d := newDevFixture(t)
	const nasty = `{"z":1,"a":18446744073709551615,"f":1.0,"s":"<&>é","d":{"k":1,"k":2}}`
	d.m.mu.Lock()
	d.m.st.Features["counter"] = json.RawMessage(nasty)
	d.m.dirty = true
	_ = d.m.flushThenDrain(context.Background())
	d.m.mu.Unlock()
	// The state's encoding escapes <, & and > once (the same JSON); what is
	// stored then is never re-encoded differently.
	before := storedPart(t, d, "counter")
	if want := `{"z":1,"a":18446744073709551615,"f":1.0,"s":"\u003c\u0026\u003eé","d":{"k":1,"k":2}}`; before != want {
		t.Fatalf("stored as %s", before)
	}
	d.m.Crash()
	opts := d.opts
	opts.Store = d.store
	opts.Features = append(append([]Feature(nil), d.opts.Features...), &failingCounter{})
	m, _, err := Unlock(context.Background(), UnlockParams{Options: opts, VaultID: d.vid, PIN: testPIN, UnlockSecret: testSecret})
	if err != nil {
		t.Fatal(err)
	}
	d.m = m
	defer m.Crash()
	m.mu.Lock()
	m.dirty = true
	_ = m.flushThenDrain(context.Background())
	m.mu.Unlock()
	if after := storedPart(t, d, "counter"); after != before {
		t.Fatalf("carried as %s, stored as %s", after, before)
	}
}

// A connection's message without re to a feature that does not run (as a
// call.offer to calls) is answered unsupported_type, not dropped: the
// caller's vault learns at once that the call cannot be made.
func TestAnUnrunFeaturesConnectionTypeIsUnsupported(t *testing.T) {
	d := newDevFixture(t)
	conn := d.asConnection(t, "c1", 0x71)
	d.m.addFeature(&counterFeature{})
	d.m.mu.Lock()
	d.m.dirty = true
	_ = d.m.flushThenDrain(context.Background())
	d.m.mu.Unlock()
	d.m.Crash()
	opts := d.opts
	opts.Store = d.store
	opts.Features = append(append([]Feature(nil), d.opts.Features...), &failingCounter{})
	m, _, err := Unlock(context.Background(), UnlockParams{Options: opts, VaultID: d.vid, PIN: testPIN, UnlockSecret: testSecret})
	if err != nil {
		t.Fatal(err)
	}
	d.m = m
	defer m.Crash()
	id := d.sendRaw(t, conn, "test.ring", "")
	in := d.inbox(conn)[conn.peer.ID]
	if r := find(in, reply(id)); r == nil || r.Status != envelope.StatusError || errCode(r) != "unsupported_type" {
		t.Fatalf("test.ring to an unrun feature: %+v", in)
	}
}

// altUnlockWith unlocks d's vault as d's app through §11.10.4's release rules
// (not pinOnly), with the device, manifest and key checks stubbed; opts
// are d's options with the features under test.
func altUnlockWith(d *devFixture, opts Options, tweak func(*AltUnlockParams)) (*Manager, *AltUnlockOutcome) {
	own := ReleaseEntry{PCR0: testRelease.PCR0, Number: testRelease.Number, Status: "active"}
	p := AltUnlockParams{Options: opts, VaultID: d.vid, UserGUID: "u1", DeviceIK: d.devPeer.IK, PIN: testPIN, UnlockSecret: testSecret,
		VerifyDevice: func(k *UnlockKey) (json.RawMessage, error) { return k.Attestation, nil },
		Manifest: func(seen uint64) (*ManifestView, error) {
			return &ManifestView{Serial: seen + 1, Own: own, Lookup: func(string) (ReleaseEntry, bool) { return own, true }}, nil
		},
		OwnKeyCheck: func(context.Context, ReleaseEntry) (*SealKeyRecord, error) {
			return &SealKeyRecord{VerifiedBy: testRelease.PCR0}, nil
		}}
	if tweak != nil {
		tweak(&p)
	}
	return UnlockAlt(context.Background(), p)
}

// withRequired is d's options with requiredCounter, which cannot read
// its part.
func withRequired(d *devFixture) Options {
	opts := d.opts
	opts.Store = d.store
	opts.Features = append(append([]Feature(nil), d.opts.Features...), &requiredCounter{})
	return opts
}

// The confirming unlock at a move's new release (§11.10.4) with a Required
// part that does not read: refused state_unreadable, the move not
// confirmed (the state not written), and the old release's header kept.
func TestUnreadablePartAtAMovesConfirmationKeepsTheOldHeader(t *testing.T) {
	d := newDevFixture(t)
	old := strings.Repeat("ef", 48)
	ctx := context.Background()
	if _, err := d.store.Put(ctx, store.HeaderKey(d.vid, old), []byte("the old release's header"), ""); err != nil {
		t.Fatal(err)
	}
	d.m.mu.Lock()
	d.m.st.Features["counter"] = json.RawMessage("7")
	d.m.st.ReleaseMove = &ReleaseMove{To: testRelease.PCR0, ToRelease: testRelease.Number, From: old, ApprovedBy: d.devPeer.ID}
	d.m.dirty = true
	_ = d.m.flushThenDrain(ctx)
	d.m.mu.Unlock()
	if err := d.m.Lock(ctx); err != nil {
		t.Fatal(err)
	}
	stateBefore, _, _ := d.store.Get(ctx, store.StateKey(d.vid))
	gauge := Unlocked()
	m, out := altUnlockWith(d, withRequired(d), nil)
	if m != nil || out.OK || out.Code != CodeStateUnreadable {
		t.Fatalf("confirmation: %+v", out)
	}
	if Unlocked() != gauge {
		t.Fatalf("unlocked gauge %d, was %d", Unlocked(), gauge)
	}
	if b, _, err := d.store.Get(ctx, store.HeaderKey(d.vid, old)); err != nil || string(b) != "the old release's header" {
		t.Fatalf("the old header went: %q %v", b, err)
	}
	if stateAfter, _, _ := d.store.Get(ctx, store.StateKey(d.vid)); string(stateAfter) != string(stateBefore) {
		t.Fatal("the state was written: the move was confirmed")
	}
}

// An unlock that would cancel a recovery, with a Required part that does
// not read: refused state_unreadable, and no cancellation is reported or
// stored: no marker, no event, the stored header unchanged.
func TestUnreadablePartCancelsNoRecovery(t *testing.T) {
	d := cancelFixture(t, func(m *Manager) {
		m.mu.Lock()
		m.st.Features["counter"] = json.RawMessage("7")
		m.dirty = true
		_ = m.flushThenDrain(context.Background())
		m.mu.Unlock()
	})
	ctx := context.Background()
	hdrBefore, _, _ := d.store.Get(ctx, store.HeaderKey(d.vid, testRelease.PCR0))
	m, out := cancelUnlock(d, withRequired(d), nil)
	if m != nil || out.OK || out.Code != CodeStateUnreadable {
		t.Fatalf("unlock: %+v", out)
	}
	if out.RecoveryCancelled || out.CancelledRecoveryID != "" || out.CancelledMarker() != "" || len(out.Events) != 0 {
		t.Fatalf("a cancellation was reported: %+v", out)
	}
	if hdrAfter, _, _ := d.store.Get(ctx, store.HeaderKey(d.vid, testRelease.PCR0)); string(hdrAfter) != string(hdrBefore) {
		t.Fatal("the stored header changed")
	}
	if r := storedRecovery(t, d); r == nil || r.ID != cancelledRecID {
		t.Fatalf("the recovery went: %+v", r)
	}
}

// auditSink keeps the kinds of the audited activity in its own part of
// the state, as the audit log does.
type auditSink struct{ kinds []string }

func (a *auditSink) Name() string      { return "auditsink" }
func (a *auditSink) Types() []TypeSpec { return nil }
func (a *auditSink) Load(raw json.RawMessage) error {
	if len(raw) == 0 {
		return nil
	}
	return json.Unmarshal(raw, &a.kinds)
}
func (a *auditSink) Save() (json.RawMessage, error) { return json.Marshal(a.kinds) }
func (a *auditSink) RecordActivity(_ *Session, x Activity) {
	if x.Audit {
		a.kinds = append(a.kinds, x.Kind)
	}
}
func (a *auditSink) Handle(context.Context, *Session, *envelope.Inner) (json.RawMessage, error) {
	return nil, nil
}

// feature.load_failed is durable: after an unlock and a flush with nothing
// else to store, the audit's stored part has it.
func TestLoadFailedIsStored(t *testing.T) {
	d := newDevFixture(t)
	ctx := context.Background()
	d.m.mu.Lock()
	d.m.st.Features["counter"] = json.RawMessage("7")
	d.m.dirty = true
	_ = d.m.flushThenDrain(ctx)
	d.m.mu.Unlock()
	d.m.Crash()
	opts := d.opts
	opts.Store = d.store
	opts.Features = append(append([]Feature(nil), d.opts.Features...), &failingCounter{}, &auditSink{})
	m, _, err := Unlock(ctx, UnlockParams{Options: opts, VaultID: d.vid, PIN: testPIN, UnlockSecret: testSecret})
	if err != nil {
		t.Fatal(err)
	}
	d.m = m
	defer m.Crash()
	m.mu.Lock()
	_ = m.flushThenDrain(ctx)
	m.mu.Unlock()
	if part := storedPart(t, d, "auditsink"); !strings.Contains(part, "feature.load_failed") {
		t.Fatalf("the stored audit: %s", part)
	}
}

// moveParams makes p an unlock that may move to target (release N+1):
// the manifest lists it, and its sealer is the test's.
func moveParams(d *devFixture, p *AltUnlockParams, target string) {
	own := ReleaseEntry{PCR0: testRelease.PCR0, Number: testRelease.Number, Status: "active"}
	next := ReleaseEntry{PCR0: target, Number: testRelease.Number + 1, Status: "active"}
	p.Manifest = func(seen uint64) (*ManifestView, error) {
		return &ManifestView{Serial: seen + 1, Own: own, Lookup: func(pcr0 string) (ReleaseEntry, bool) {
			if pcr0 == target {
				return next, true
			}
			return own, true
		}}, nil
	}
	p.SealerFor = func(context.Context, ReleaseEntry) (Sealer, *SealKeyRecord, error) {
		return d.opts.Sealer, &SealKeyRecord{VerifiedBy: testRelease.PCR0}, nil
	}
}

// storedPartWith is name's part of the stored state, opened with dek.
func storedPartWith(t *testing.T, d *devFixture, dek []byte, name string) string {
	t.Helper()
	blob, _, err := d.store.Get(context.Background(), store.StateKey(d.vid))
	if err != nil {
		t.Fatal(err)
	}
	pt, _, err := decryptState(dek, d.vid, blob)
	if err != nil {
		t.Fatal(err)
	}
	var st struct {
		Features map[string]json.RawMessage `json:"features"`
	}
	if err := json.Unmarshal(pt, &st); err != nil {
		t.Fatal(err)
	}
	return string(st.Features[name])
}

// unreadableFixture is a locked vault whose counter part a Required
// feature cannot read, and the DEK to open its stored state with.
func unreadableFixture(t *testing.T, before func(*Manager)) (*devFixture, []byte, string) {
	d := newDevFixture(t)
	ctx := context.Background()
	d.m.mu.Lock()
	d.m.st.Features["counter"] = json.RawMessage(`{"later":true,"n":7}`)
	if before != nil {
		before(d.m)
	}
	d.m.dirty = true
	_ = d.m.flushThenDrain(ctx)
	dek := append([]byte(nil), d.m.dek...)
	d.m.mu.Unlock()
	part := storedPartWith(t, d, dek, "counter")
	if err := d.m.Lock(ctx); err != nil {
		t.Fatal(err)
	}
	return d, dek, part
}

// (Owner decision 2026-11-11, GC #8621 a) An approved update with a part
// a Required feature cannot read: the move is recorded and sealed for the
// next release, the part carried byte for byte, no feature run, no
// unlocked. A plain unlock of the same state still answers
// state_unreadable.
func TestAnApprovedMoveCarriesAnUnreadablePart(t *testing.T) {
	const target = "c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3"
	d, dek, part := unreadableFixture(t, nil)
	opts := withRequired(d)
	if m, out := altUnlockWith(d, opts, nil); m != nil || out.Code != CodeStateUnreadable {
		t.Fatalf("plain unlock: %+v", out)
	}
	gauge := Unlocked()
	registers := 0
	inner := opts.Relay
	opts.Relay = func(base string, key ed25519.PrivateKey) Relay {
		return &registerCount{Relay: inner(base, key), n: &registers}
	}
	d.relay.mu.Lock()
	deposits := len(d.relay.deposits)
	d.relay.mu.Unlock()
	m, out := altUnlockWith(d, opts, func(p *AltUnlockParams) {
		moveParams(d, p, target)
		p.Update = &UpdateRequest{To: target, ToRelease: testRelease.Number + 1,
			VerifyApproval: func(k *UnlockKey) (json.RawMessage, error) { return k.Attestation, nil }}
	})
	if m != nil || !out.OK || out.Update == nil || out.Update.Result != UpdateMoved {
		t.Fatalf("move: %+v %+v", out, out.Update)
	}
	for _, e := range out.Events {
		if e.Event == "unlocked" {
			t.Fatal("unlocked reported")
		}
	}
	if Unlocked() != gauge {
		t.Fatalf("unlocked gauge %d, was %d", Unlocked(), gauge)
	}
	if got := storedPartWith(t, d, dek, "counter"); got != part {
		t.Fatalf("the part in N+1's state: %s, was %s", got, part)
	}
	if registers != 0 {
		t.Fatalf("registered at the relay %d times", registers)
	}
	d.relay.mu.Lock()
	sent := len(d.relay.deposits) - deposits
	d.relay.mu.Unlock()
	if sent != 0 {
		t.Fatalf("%d messages sent", sent)
	}
	if mv := storedState(t, d, dek).ReleaseMove; mv == nil || mv.To != target {
		t.Fatalf("the move is not in the stored state: %+v", mv)
	}
	if _, _, err := d.store.Get(context.Background(), store.HeaderKey(d.vid, target)); err != nil {
		t.Fatalf("not sealed for the next release: %v", err)
	}
}

// (L1, GC #8621 a) A pending move with a part a Required feature cannot
// read completes as any pending move does, the part carried unchanged.
func TestAPendingMoveCompletesWithAnUnreadablePart(t *testing.T) {
	const target = "c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4"
	d, dek, part := unreadableFixture(t, func(m *Manager) {
		m.st.ReleaseMove = &ReleaseMove{To: target, ToRelease: testRelease.Number + 1, From: testRelease.PCR0, ApprovedBy: d0(m)}
	})
	opts := withRequired(d)
	registers := 0
	inner := opts.Relay
	opts.Relay = func(base string, key ed25519.PrivateKey) Relay {
		return &registerCount{Relay: inner(base, key), n: &registers}
	}
	d.relay.mu.Lock()
	deposits := len(d.relay.deposits)
	d.relay.mu.Unlock()
	m, out := altUnlockWith(d, opts, func(p *AltUnlockParams) { moveParams(d, p, target) })
	if m != nil || !out.OK || out.Update == nil || out.Update.Result != UpdateMoved {
		t.Fatalf("pending move: %+v %+v", out, out.Update)
	}
	d.relay.mu.Lock()
	sent := len(d.relay.deposits) - deposits
	d.relay.mu.Unlock()
	if registers != 0 || sent != 0 {
		t.Fatalf("registered %d times, %d messages sent", registers, sent)
	}
	if got := storedPartWith(t, d, dek, "counter"); got != part {
		t.Fatalf("the part: %s, was %s", got, part)
	}
	if _, _, err := d.store.Get(context.Background(), store.HeaderKey(d.vid, target)); err != nil {
		t.Fatalf("not sealed for the next release: %v", err)
	}
}

// d0 is the vault's first app device, the move's approver.
func d0(m *Manager) string {
	for id, p := range m.st.Devices {
		if p.Kind == KindApp {
			return id
		}
	}
	return ""
}

// gatePart is a credential feature (a CredentialGate) as far as the header
// bits go: it holds a credential.
type gatePart struct{ counterFeature }

func (g *gatePart) Name() string           { return "gate" }
func (g *gatePart) Types() []TypeSpec      { return nil }
func (g *gatePart) CredentialReady() bool  { return true }
func (g *gatePart) CredentialExists() bool { return true }

// HasBackupCopy: it keeps the credential's backup copy (§3.5.6), so the
// header's credential_backup bit is true.
func (g *gatePart) HasBackupCopy() bool { return true }

// unreadGate is the credential feature of a release that cannot read its
// part: Required, and its Load fails.
type unreadGate struct{ gatePart }

func (g *unreadGate) RequiredAtUnlock() bool { return true }
func (g *unreadGate) Load(json.RawMessage) error {
	return errors.New("a state from a later release")
}

// credGateFixture is a locked vault whose header says it holds a credential,
// with the credential's part stored.
func credGateFixture(t *testing.T, before func(*Manager)) *devFixture {
	d := newDevFixture(t)
	ctx := context.Background()
	d.m.addFeature(&gatePart{})
	d.m.mu.Lock()
	if before != nil {
		before(d.m)
	}
	d.m.dirty = true
	_ = d.m.flushThenDrain(ctx)
	if err := d.m.writeHeader(ctx); err != nil {
		t.Fatal(err)
	}
	d.m.mu.Unlock()
	if err := d.m.Lock(ctx); err != nil {
		t.Fatal(err)
	}
	if h := storedHeader(t, d); !h.HasCredential || h.CredentialBackup == nil || !*h.CredentialBackup || h.RecoveryRefusal() != "" {
		t.Fatalf("setup: header %v %v %q", h.HasCredential, h.CredentialBackup, h.RecoveryRefusal())
	}
	return d
}

// headerAt is the sealed header stored for release.
func headerAt(t *testing.T, d *devFixture, release string) *Header {
	t.Helper()
	blob, _, err := d.store.Get(context.Background(), store.HeaderKey(d.vid, release))
	if err != nil {
		t.Fatal(err)
	}
	h, err := unsealHeader(context.Background(), d.opts.Sealer, blob, d.vid, release)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// (GC #8621 a) A move with the credential's part unread keeps the header's
// credential bits as stored, on both paths: the next release's header still
// says the vault holds a credential, so a recovery is neither refused
// no_credential nor cancelled before a release that reads it opens.
func TestAMoveWithTheCredentialUnreadKeepsTheHeaderBits(t *testing.T) {
	for _, pending := range []bool{false, true} {
		target := strings.Repeat("d5", 48)
		if pending {
			target = strings.Repeat("d6", 48)
		}
		d := credGateFixture(t, func(m *Manager) {
			if pending {
				m.st.ReleaseMove = &ReleaseMove{To: target, ToRelease: testRelease.Number + 1, From: testRelease.PCR0, ApprovedBy: d0(m)}
			}
		})
		before := storedHeader(t, d)
		opts := d.opts
		opts.Store = d.store
		opts.Features = append(append([]Feature(nil), d.opts.Features...), &unreadGate{})
		m, out := altUnlockWith(d, opts, func(p *AltUnlockParams) {
			moveParams(d, p, target)
			if !pending {
				p.Update = &UpdateRequest{To: target, ToRelease: testRelease.Number + 1,
					VerifyApproval: func(k *UnlockKey) (json.RawMessage, error) { return k.Attestation, nil }}
			}
		})
		if m != nil || !out.OK || out.Update == nil || out.Update.Result != UpdateMoved {
			t.Fatalf("pending %v: %+v %+v", pending, out, out.Update)
		}
		for name, h := range map[string]*Header{"N": storedHeader(t, d), "N+1": headerAt(t, d, target)} {
			if h.HasCredential != before.HasCredential || !sameBool(h.CredentialBackup, before.CredentialBackup) {
				t.Fatalf("pending %v, %s: has_credential %v backup %v, was %v %v", pending, name,
					h.HasCredential, h.CredentialBackup, before.HasCredential, before.CredentialBackup)
			}
			if r := h.RecoveryRefusal(); r != "" {
				t.Fatalf("pending %v, %s: recovery refused %q", pending, name, r)
			}
			if h.CredentialBackup == nil || !*h.CredentialBackup {
				t.Fatalf("pending %v, %s: the backup bit went", pending, name)
			}
		}
	}
}

func sameBool(a, b *bool) bool { return (a == nil) == (b == nil) && (a == nil || *a == *b) }

// registerCount counts the relay registrations of a vault.
type registerCount struct {
	Relay
	n *int
}

func (r *registerCount) Register(ctx context.Context) (Limits, error) {
	*r.n++
	return r.Relay.Register(ctx)
}

// storedState is the stored state, opened with dek.
func storedState(t *testing.T, d *devFixture, dek []byte) *State {
	t.Helper()
	blob, _, err := d.store.Get(context.Background(), store.StateKey(d.vid))
	if err != nil {
		t.Fatal(err)
	}
	pt, _, err := decryptState(dek, d.vid, blob)
	if err != nil {
		t.Fatal(err)
	}
	var st State
	if err := json.Unmarshal(pt, &st); err != nil {
		t.Fatal(err)
	}
	return &st
}

// (Owner decision 2026-11-12, GC #8689 a) The release a move went to cannot
// read a Required part either: it does not confirm the move, but an approved
// update to a later active release still goes on from it, from the release
// the vault is still sealed at, with the part carried unchanged and the
// header's credential bits as stored. Without such an update it refuses
// state_unreadable and writes nothing.
func TestAnUnconfirmedReleaseThatCannotReadMovesOnWithAnApprovedUpdate(t *testing.T) {
	old, target := strings.Repeat("e7", 48), strings.Repeat("e8", 48)
	var dek []byte
	d := credGateFixture(t, func(m *Manager) {
		m.st.ReleaseMove = &ReleaseMove{To: testRelease.PCR0, ToRelease: testRelease.Number, From: old, ApprovedBy: d0(m)}
		m.st.SealedRelease = old
		dek = append([]byte(nil), m.dek...)
	})
	part := storedPartWith(t, d, dek, "gate")
	before := storedHeader(t, d)
	opts := d.opts
	opts.Store = d.store
	opts.Features = append(append([]Feature(nil), d.opts.Features...), &unreadGate{})
	approved := func(k *UnlockKey) (json.RawMessage, error) { return k.Attestation, nil }
	refused := map[string]func(*AltUnlockParams){
		"no update": func(p *AltUnlockParams) { moveParams(d, p, target) },
		"approval does not verify": func(p *AltUnlockParams) {
			moveParams(d, p, target)
			p.Update = &UpdateRequest{To: target, ToRelease: testRelease.Number + 1,
				VerifyApproval: func(*UnlockKey) (json.RawMessage, error) { return nil, errors.New("no") }}
		},
		"not a later release": func(p *AltUnlockParams) {
			moveParams(d, p, target)
			look := p.Manifest
			p.Manifest = func(seen uint64) (*ManifestView, error) {
				v, err := look(seen)
				if err != nil {
					return nil, err
				}
				inner := v.Lookup
				v.Lookup = func(pcr0 string) (ReleaseEntry, bool) {
					e, ok := inner(pcr0)
					if pcr0 == target {
						e.Number = testRelease.Number
					}
					return e, ok
				}
				return v, nil
			}
			p.Update = &UpdateRequest{To: target, ToRelease: testRelease.Number, VerifyApproval: approved}
		},
		"not active": func(p *AltUnlockParams) {
			moveParams(d, p, target)
			look := p.Manifest
			p.Manifest = func(seen uint64) (*ManifestView, error) {
				v, err := look(seen)
				if err != nil {
					return nil, err
				}
				inner := v.Lookup
				v.Lookup = func(pcr0 string) (ReleaseEntry, bool) {
					e, ok := inner(pcr0)
					if pcr0 == target {
						e.Status = "deprecated"
					}
					return e, ok
				}
				return v, nil
			}
			p.Update = &UpdateRequest{To: target, ToRelease: testRelease.Number + 1, VerifyApproval: approved}
		},
	}
	for name, set := range refused {
		gauge := Unlocked()
		if m, out := altUnlockWith(d, opts, set); m != nil || out.OK || out.Code != CodeStateUnreadable {
			t.Fatalf("%s: %+v", name, out)
		}
		if Unlocked() != gauge {
			t.Fatalf("%s: unlocked gauge %d, was %d", name, Unlocked(), gauge)
		}
		if mv := storedState(t, d, dek).ReleaseMove; mv == nil || mv.To != testRelease.PCR0 || mv.From != old {
			t.Fatalf("%s: the stored move changed: %+v", name, mv)
		}
		if _, _, err := d.store.Get(context.Background(), store.HeaderKey(d.vid, target)); err == nil {
			t.Fatalf("%s: sealed for %s", name, target)
		}
	}
	gauge := Unlocked()
	registers := 0
	inner := opts.Relay
	opts.Relay = func(base string, key ed25519.PrivateKey) Relay {
		return &registerCount{Relay: inner(base, key), n: &registers}
	}
	d.relay.mu.Lock()
	deposits := len(d.relay.deposits)
	d.relay.mu.Unlock()
	m, out := altUnlockWith(d, opts, func(p *AltUnlockParams) {
		moveParams(d, p, target)
		p.Update = &UpdateRequest{To: target, ToRelease: testRelease.Number + 1, VerifyApproval: approved}
	})
	if m != nil || !out.OK || out.Update == nil || out.Update.Result != UpdateMoved {
		t.Fatalf("move on: %+v %+v", out, out.Update)
	}
	for _, e := range out.Events {
		if e.Event == "unlocked" {
			t.Fatal("unlocked reported")
		}
	}
	if Unlocked() != gauge {
		t.Fatalf("unlocked gauge %d, was %d", Unlocked(), gauge)
	}
	d.relay.mu.Lock()
	sent := len(d.relay.deposits) - deposits
	d.relay.mu.Unlock()
	if registers != 0 || sent != 0 {
		t.Fatalf("registered %d times, %d messages sent", registers, sent)
	}
	st := storedState(t, d, dek)
	if mv := st.ReleaseMove; mv == nil || mv.To != target || mv.ToRelease != testRelease.Number+1 || mv.From != old {
		t.Fatalf("the stored move: %+v", mv)
	}
	if st.SealedRelease != old {
		t.Fatalf("the move was confirmed: sealed release %s", st.SealedRelease)
	}
	if got := storedPartWith(t, d, dek, "gate"); got != part {
		t.Fatalf("the part: %s, was %s", got, part)
	}
	for name, h := range map[string]*Header{"N+1": storedHeader(t, d), "N+2": headerAt(t, d, target)} {
		if h.HasCredential != before.HasCredential || !sameBool(h.CredentialBackup, before.CredentialBackup) || h.RecoveryRefusal() != "" {
			t.Fatalf("%s: has_credential %v backup %v refusal %q, was %v %v", name,
				h.HasCredential, h.CredentialBackup, h.RecoveryRefusal(), before.HasCredential, before.CredentialBackup)
		}
	}
}
