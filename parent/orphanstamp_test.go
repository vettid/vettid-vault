package parent_test

import (
	"errors"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/hostproto"
	"github.com/vettid/vettid-vault/internal/parenttest"
	"github.com/vettid/vettid-vault/parent"
)

// The orphan clear removes only the entry this parent's own confirmation
// made (the stamp, app_key_next.att).

func seedRow(h *harness) {
	h.tables.PutVault(parenttest.VaultRow{VaultID: vaultID, UserGUID: "u1", State: "locked", AppKey: []byte("k1"), AppKeyID: parent.AppKeyID([]byte("k1")), AppKeySeq: 1})
}

func (e *fakeEnclave) orphanClear(key, seq, hseq string) {
	e.appKeyEvent(parent.EventAppKeyNextClear, key, seq, "", hseq)
}

func secondParent(t *testing.T, first *harness) (*harness, *fakeEnclave) {
	h := newHarness(t, func(c *parent.Config) { c.Tables = first.tables })
	e := h.connect("boot-2", nil)
	e.descriptor()
	waitFor(t, "ready", func() bool { return h.p.Health().Release == pcr })
	return h, e
}

// A split brain: two instances confirm the same key at the same header_seq.
// The loser's confirmation came first, the winner's replaced it (larger
// stamp); the loser's header write then failed and it clears. The winner's
// entry stays.
func TestOrphanClearLeavesTheWinnersEntry(t *testing.T) {
	hW, eW := appKeyHarness(t)
	seedRow(hW)
	hL, eL := secondParent(t, hW)
	if got := eL.confirmAppKey(t, vaultID, "next", "K6", "6", "9"); got != hostproto.StatusOK {
		t.Fatalf("loser: %s", got)
	}
	if got := eW.confirmAppKey(t, vaultID, "next", "K6", "6", "9"); got != hostproto.StatusOK {
		t.Fatalf("winner: %s", got)
	}
	winner, _ := hW.tables.Vault(vaultID)
	if string(winner.AppKeyNext) != "K6" || winner.AppKeyNextAtt == 0 {
		t.Fatalf("row %+v", winner)
	}
	eL.orphanClear("K6", "6", "9")
	waitFor(t, "clear received", func() bool { return hL.hasLog(`"event":"app_key_next_clear"`) })
	time.Sleep(150 * time.Millisecond)
	if r, _ := hW.tables.Vault(vaultID); string(r.AppKeyNext) != "K6" || r.AppKeyNextAtt != winner.AppKeyNextAtt {
		t.Fatalf("the loser's clear removed the winner's entry: %+v", r)
	}
}

// One instance: its confirmation, then its clear, removes the entry; the
// clear sent again at the next flush finds nothing and does nothing.
func TestOrphanClearOwnEntry(t *testing.T) {
	h, e := appKeyHarness(t)
	seedRow(h)
	if got := e.confirmAppKey(t, vaultID, "next", "K6", "6", "9"); got != hostproto.StatusOK {
		t.Fatalf("confirm: %s", got)
	}
	e.orphanClear("K6", "6", "9")
	waitFor(t, "cleared", func() bool { r, _ := h.tables.Vault(vaultID); return r.AppKeyNext == nil })
	e.orphanClear("K6", "6", "9") // the flush's second send
	time.Sleep(50 * time.Millisecond)
	if r, _ := h.tables.Vault(vaultID); r.AppKeyNext != nil || r.AppKey == nil {
		t.Fatalf("row %+v", r)
	}
}

// A parent that does not know the stamp (it restarted, or never confirmed
// the key) clears nothing, even an entry that matches by key and header_seq.
func TestOrphanClearUnknownStampDoesNothing(t *testing.T) {
	h, e := appKeyHarness(t)
	seedRow(h)
	h.tables.PutVault(parenttest.VaultRow{VaultID: vaultID, UserGUID: "u1", State: "locked", AppKey: []byte("k1"), AppKeyID: parent.AppKeyID([]byte("k1")), AppKeySeq: 1,
		AppKeyNext: []byte("K6"), AppKeyNextSeq: 6, AppKeyNextHSeq: 9, AppKeyNextAtt: 12345})
	e.orphanClear("K6", "6", "9")
	time.Sleep(200 * time.Millisecond)
	if r, _ := h.tables.Vault(vaultID); string(r.AppKeyNext) != "K6" {
		t.Fatalf("cleared without a stamp: %+v", r)
	}
	// And the table itself refuses a clear without one.
	_ = h.tables.Lifecycle(t.Context(), parent.Lifecycle{Event: parent.EventAppKeyNextClear, VaultID: vaultID, AppKey: []byte("K6"), AppKeySeq: 6, HeaderSeq: 9}, "me", time.Now())
	if r, _ := h.tables.Vault(vaultID); string(r.AppKeyNext) != "K6" {
		t.Fatalf("table cleared an unstamped event: %+v", r)
	}
}

// The retry of a failed clear keeps the stamp: it applies when the entry is
// still ours, and does nothing when another instance's confirmation replaced
// it in the meantime.
func TestOrphanClearRetryKeepsStamp(t *testing.T) {
	defer parent.SetAppKeyRetryForTest(5*time.Millisecond, 20*time.Millisecond)()
	for _, replaced := range []bool{false, true} {
		h, e := appKeyHarness(t)
		seedRow(h)
		if got := e.confirmAppKey(t, vaultID, "next", "K6", "6", "9"); got != hostproto.StatusOK {
			t.Fatalf("confirm: %s", got)
		}
		h.tables.SetAppKeyErr(errors.New("throttled"))
		e.orphanClear("K6", "6", "9")
		waitFor(t, "write failed", func() bool { return h.hasLog("app key write failed; trying again") })
		var other int64
		if replaced {
			other = time.Now().Add(time.Hour).UnixNano()
			if err := h.tables.ConfirmAppKey(t.Context(), vaultID, "next", []byte("K6"), 6, 9, other, time.Now()); err != nil {
				t.Fatal(err)
			}
		}
		h.tables.SetAppKeyErr(nil)
		if !replaced {
			waitFor(t, "cleared by the retry", func() bool { r, _ := h.tables.Vault(vaultID); return r.AppKeyNext == nil })
			continue
		}
		time.Sleep(150 * time.Millisecond)
		if r, _ := h.tables.Vault(vaultID); string(r.AppKeyNext) != "K6" || r.AppKeyNextAtt != other {
			t.Fatalf("the retry removed another instance's entry: %+v", r)
		}
	}
}
