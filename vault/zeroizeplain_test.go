package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vault/store"
)

// plaintexts puts one of each stored plaintext in m's state (a held request,
// a cached answer, a held outbox entry) and returns their bytes.
func plaintexts(m *Manager) (held, cached, outbox []byte) {
	held, cached, outbox = []byte("held request inner"), []byte("cached answer inner"), []byte("held outbox plaintext")
	exp := time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC) // past every test clock: never pruned
	m.st.Held["h1"] = &HeldRequest{ID: "h1", DeviceID: "d1", Key: "p|i1", Inner: held, Created: time.Now(), Expires: exp}
	m.st.Responses["p|i2"] = CachedResponse{Inner: cached, Expires: exp}
	m.st.Outbox = append(m.st.Outbox, &OutboxEntry{ID: "o1", Op: OpDeposit, PeerID: "c1", Held: outbox, HeldExp: exp})
	return held, cached, outbox
}

// zeroize (a lock, a split brain) wipes the plaintexts the state keeps as it
// drops it: the held requests, the cached answers and the held outbox entries.
func TestZeroizeWipesStoredPlaintexts(t *testing.T) {
	for _, c := range []struct {
		name string
		drop func(m *Manager)
	}{
		{"a lock", func(m *Manager) {
			if err := m.Lock(context.Background()); err != nil {
				t.Fatal(err)
			}
		}},
		{"a crash", func(m *Manager) { m.Crash() }},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := newDevFixture(t)
			var held, cached, outbox []byte
			locked(d, func(m *Manager) {
				if m.st.Held == nil {
					m.st.Held = map[string]*HeldRequest{}
				}
				held, cached, outbox = plaintexts(m)
			})
			c.drop(d.m)
			checkWiped(t, "the held request", held)
			checkWiped(t, "the cached answer", cached)
			checkWiped(t, "the held outbox entry", outbox)
		})
	}
}

// A state an unlock decodes and then refuses (here a rollback: below the
// smallest state seq allowed) never runs: its stored plaintexts are wiped.
func TestARefusedUnlockWipesTheDecodedPlaintexts(t *testing.T) {
	f := newFixture(t)
	f.m.mu.Lock()
	if f.m.st.Held == nil {
		f.m.st.Held = map[string]*HeldRequest{}
	}
	plaintexts(f.m)
	if err := f.m.persist(context.Background(), false); err != nil {
		f.m.mu.Unlock()
		t.Fatal(err)
	}
	f.m.mu.Unlock()
	f.m.Crash()
	var dropped *State
	testDroppedStateHook = func(st *State) { dropped = st }
	defer func() { testDroppedStateHook = nil }()
	if _, _, err := f.unlock(testPIN, 1<<40, 0); !errors.Is(err, ErrRollback) {
		t.Fatalf("unlock: %v", err)
	}
	if dropped == nil {
		t.Fatal("no decoded state was dropped")
	}
	if len(dropped.Held) != 1 || len(dropped.Responses) == 0 || len(dropped.Outbox) == 0 {
		t.Fatalf("the stored plaintexts were not in the decoded state: %d %d %d", len(dropped.Held), len(dropped.Responses), len(dropped.Outbox))
	}
	for _, h := range dropped.Held {
		checkWiped(t, "the decoded held request", h.Inner)
	}
	for _, r := range dropped.Responses {
		checkWiped(t, "the decoded cached answer", r.Inner)
	}
	for _, e := range dropped.Outbox {
		checkWiped(t, "the decoded outbox entry", e.Held)
	}
}

// The same for a state of an earlier release, which an unlock reads and
// refuses (R29-U1, §6.3.1).
func TestAnUnsupportedStateWipesTheDecodedPlaintexts(t *testing.T) {
	f := newFixture(t)
	f.m.mu.Lock()
	if f.m.st.Held == nil {
		f.m.st.Held = map[string]*HeldRequest{}
	}
	plaintexts(f.m)
	f.m.st.MessagingRelease = 28
	if err := f.m.persist(context.Background(), false); err != nil {
		f.m.mu.Unlock()
		t.Fatal(err)
	}
	f.m.mu.Unlock()
	f.m.Crash()
	var dropped *State
	testDroppedStateHook = func(st *State) { dropped = st }
	defer func() { testDroppedStateHook = nil }()
	if _, _, err := f.unlock(testPIN, 0, 0); !errors.Is(err, ErrStateUnsupported) {
		t.Fatalf("unlock: %v", err)
	}
	checkDropped(t, dropped)
}

// checkDropped checks that the decoded state a refusal dropped held the
// stored plaintexts, and that each was wiped.
func checkDropped(t *testing.T, dropped *State) {
	t.Helper()
	if dropped == nil || len(dropped.Held) != 1 || len(dropped.Responses) == 0 || len(dropped.Outbox) == 0 {
		t.Fatal("the decoded state with its plaintexts was not dropped")
	}
	for _, h := range dropped.Held {
		checkWiped(t, "the decoded held request", h.Inner)
	}
	for _, r := range dropped.Responses {
		checkWiped(t, "the decoded cached answer", r.Inner)
	}
	for _, e := range dropped.Outbox {
		checkWiped(t, "the decoded outbox entry", e.Held)
	}
}

// The same for a state that opens but is not this vault's own at its seq
// (here its state_seq differs from the blob's): refused as missing.
func TestAMismatchedStateWipesTheDecodedPlaintexts(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.m.mu.Lock()
	if f.m.st.Held == nil {
		f.m.st.Held = map[string]*HeldRequest{}
	}
	plaintexts(f.m)
	if err := f.m.persist(ctx, false); err != nil {
		f.m.mu.Unlock()
		t.Fatal(err)
	}
	c := *f.m.st
	c.StateSeq += 7
	pt, err := json.Marshal(&c)
	if err != nil {
		f.m.mu.Unlock()
		t.Fatal(err)
	}
	blob, err := encryptState(f.m.dek, f.m.hdr.DEKVersion, f.m.st.VaultID, f.m.st.StateSeq, pt)
	if err == nil {
		_, err = f.store.Put(ctx, store.StateKey(f.m.st.VaultID), blob, f.m.stateVer)
	}
	f.m.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	f.m.Crash()
	var dropped *State
	testDroppedStateHook = func(st *State) { dropped = st }
	defer func() { testDroppedStateHook = nil }()
	if _, _, err := f.unlock(testPIN, 0, 0); !errors.Is(err, ErrState) {
		t.Fatalf("unlock: %v", err)
	}
	checkDropped(t, dropped)
}

// A recovery open decodes the stored state too: one that does not belong
// with the header (here its state_seq differs from the blob's) is refused
// as a stored mismatch, and its plaintexts are wiped.
func TestARecoveryOpenOfAMismatchedStateWipesTheDecodedPlaintexts(t *testing.T) {
	var dek []byte
	var ver uint64
	f := newOpenFixtureWith(t, func(f *openFixture) {
		f.m.mu.Lock()
		if f.m.st.Held == nil {
			f.m.st.Held = map[string]*HeldRequest{}
		}
		plaintexts(f.m)
		f.m.dirty = true
		dek, ver = bytes.Clone(f.m.dek), f.m.hdr.DEKVersion
		f.m.mu.Unlock()
		f.flush()
	})
	ctx := context.Background()
	sk := store.StateKey(f.vid)
	sb, sv, err := f.st.Get(ctx, sk)
	if err != nil {
		t.Fatal(err)
	}
	pt, seq, err := decryptState(dek, f.vid, sb)
	if err != nil {
		t.Fatal(err)
	}
	var c State
	if err := json.Unmarshal(pt, &c); err != nil {
		t.Fatal(err)
	}
	c.StateSeq += 7
	pt, err = json.Marshal(&c)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := encryptState(dek, ver, f.vid, seq, pt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.Put(ctx, sk, blob, sv); err != nil {
		t.Fatal(err)
	}
	var dropped *State
	testDroppedStateHook = func(st *State) { dropped = st }
	defer func() { testDroppedStateHook = nil }()
	if m, out := f.open(testPIN, rPW); m != nil || out.Code != OpenStoredMismatch {
		t.Fatalf("%+v", out)
	}
	checkDropped(t, dropped)
}
