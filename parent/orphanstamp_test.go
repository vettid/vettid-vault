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
	h.tables.PutVault(parenttest.VaultRow{VaultID: vaultID, UserGUID: "u1", State: "locked", LeaseInstance: "i-test", LeaseExpires: leaseFar, AppKey: []byte("k1"), AppKeyID: parent.AppKeyID([]byte("k1")), AppKeySeq: 1})
}

func (e *fakeEnclave) orphanClear(key, seq, hseq string) {
	e.appKeyEvent(parent.EventAppKeyNextClear, key, seq, "", hseq)
}

func secondParent(t *testing.T, first *harness) (*harness, *fakeEnclave) {
	h := newHarness(t, func(c *parent.Config) { c.Tables = first.tables; c.InstanceID = "i-b" })
	e := h.connect("boot-2", nil)
	e.descriptor()
	waitFor(t, "ready", func() bool { return h.p.Health().Release == pcr })
	return h, e
}

// Split brain across two instances, A the lease holder (the winner) and B a
// stale instance that does not hold the lease. The lease bounds every live
// confirmation and every orphan clear, so B's never touches the row.
//
//	(a) B confirms the same key after A's re-confirmation;
//	(b) B confirms another key at the same header_seq;
//	(c) B confirms first (a larger stamp: clock skew), A afterwards.
//
// Each leaves A's entry, with A's stamp, after B's clear.
func TestSplitBrainLeaseKeepsTheWinnersEntry(t *testing.T) {
	for _, c := range []struct {
		name        string
		bKey        string
		bFirst      bool
		clearBefore bool
	}{{"a same key later", "K6", false, false}, {"b another key", "K7", false, false}, {"c skew, B first", "K6", true, false}, {"a clear between", "K6", false, true}} {
		t.Run(c.name, func(t *testing.T) {
			hA, eA := appKeyHarness(t)
			seedRow(hA)
			hB, eB := secondParent(t, hA)
			if c.bFirst {
				if got := eB.confirmAppKey(t, vaultID, "next", c.bKey, "6", "9"); got != hostproto.StatusConflict {
					t.Fatalf("B first: %s", got)
				}
			}
			for i := 0; i < 2; i++ { // the confirmation, and the re-confirmation after step 1
				if got := eA.confirmAppKey(t, vaultID, "next", "K6", "6", "9"); got != hostproto.StatusOK {
					t.Fatalf("A: %s", got)
				}
				if i == 0 && c.clearBefore {
					eB.orphanClear(c.bKey, "6", "9")
				}
				if i == 0 && !c.bFirst {
					if got := eB.confirmAppKey(t, vaultID, "next", c.bKey, "6", "9"); got != hostproto.StatusConflict {
						t.Fatalf("B later: %s", got)
					}
				}
			}
			winner, _ := hA.tables.Vault(vaultID)
			eB.orphanClear(c.bKey, "6", "9")
			waitFor(t, "clear received", func() bool { return hB.hasLog(`"event":"app_key_next_clear"`) })
			time.Sleep(150 * time.Millisecond)
			if r, _ := hA.tables.Vault(vaultID); string(r.AppKeyNext) != "K6" || r.AppKeyNextAtt != winner.AppKeyNextAtt || winner.AppKeyNextAtt == 0 {
				t.Fatalf("the winner's entry changed: %+v (was %+v)", r, winner)
			}
		})
	}
}

// A confirmation by an instance that does not hold the lease (none, another's,
// or an expired one) is a conflict and writes nothing, in both modes.
func TestConfirmWithoutLeaseIsConflict(t *testing.T) {
	for _, lease := range []struct {
		inst string
		exp  int64
	}{{"", 0}, {"i-other", leaseFar}, {"i-test", time.Now().Add(-time.Minute).Unix()}} {
		h, e := appKeyHarness(t)
		h.tables.PutVault(parenttest.VaultRow{VaultID: vaultID, UserGUID: "u1", State: "enrolling", LeaseInstance: lease.inst, LeaseExpires: lease.exp,
			AppKey: []byte("k1"), AppKeyID: parent.AppKeyID([]byte("k1")), AppKeySeq: 1})
		for _, f := range [][]string{{vaultID, "next", "K6", "6", "9"}, {vaultID, "enroll", "k9", "9", "1"}} {
			if got := e.confirmAppKey(t, f...); got != hostproto.StatusConflict {
				t.Fatalf("lease %+v %s: %s", lease, f[1], got)
			}
		}
		if r, _ := h.tables.Vault(vaultID); r.AppKeyNext != nil || string(r.AppKey) != "k1" {
			t.Fatalf("written without the lease: %+v", r)
		}
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
	h.tables.PutVault(parenttest.VaultRow{VaultID: vaultID, UserGUID: "u1", State: "locked", LeaseInstance: "i-test", LeaseExpires: leaseFar, AppKey: []byte("k1"), AppKeyID: parent.AppKeyID([]byte("k1")), AppKeySeq: 1,
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
			if err := h.tables.ConfirmAppKey(t.Context(), vaultID, "i-test", "next", []byte("K6"), 6, 9, other, time.Now()); err != nil {
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

var leaseFar = time.Now().Add(24 * time.Hour).Unix()
