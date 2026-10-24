package parent_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/hostproto"
	"github.com/vettid/vettid-vault/internal/parenttest"
	"github.com/vettid/vettid-vault/parent"
)

// The vault row's app_key and app_key_next are written durably: the
// enclave's request for app_key_next is answered after the table write,
// a failed write is tried again until it is written, and the enclave's
// assertions after a connect write what a restarted parent lost.

func (e *fakeEnclave) appKeyEvent(ev, key, seq, next, hseq string) {
	_ = e.conn.Notify(hostproto.KindLifecycle, hostproto.Strings(ev, vaultID, pcr, pcr, "1", key, seq, "", "0", "", "", next, hseq, "")...)
}

func (e *fakeEnclave) confirmAppKey(t *testing.T, fields ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r, err := e.conn.Call(ctx, hostproto.KindAppKeyNext, hostproto.Strings(fields...)...)
	if err != nil || len(r) != 1 {
		t.Fatalf("AppKeyNext: %v %q", err, r)
	}
	return string(r[0])
}

func appKeyHarness(t *testing.T) (*harness, *fakeEnclave) {
	h := newHarness(t, nil)
	e := h.connect("boot-1", nil)
	e.descriptor()
	waitFor(t, "ready", func() bool { return h.p.Health().Release == pcr })
	return h, e
}

func TestConfirmAppKeyNext(t *testing.T) {
	h, e := appKeyHarness(t)
	h.tables.PutVault(parenttest.VaultRow{VaultID: vaultID, UserGUID: "u1", State: "locked", LeaseInstance: "i-other", LeaseExpires: time.Now().Add(time.Hour).Unix(),
		AppKey: []byte("k1"), AppKeyID: parent.AppKeyID([]byte("k1")), AppKeySeq: 1})
	// ok only once the table names the key as app_key_next, whatever the lease.
	if got := e.confirmAppKey(t, vaultID, "next", "k2", "2", "7"); got != hostproto.StatusOK {
		t.Fatalf("next: %s", got)
	}
	r, _ := h.tables.Vault(vaultID)
	if string(r.AppKeyNext) != "k2" || r.AppKeyNextSeq != 2 || r.AppKeyNextHSeq != 7 || string(r.AppKey) != "k1" {
		t.Fatalf("row %+v", r)
	}
	// Again (the enclave retries a lost ok): ok.
	if got := e.confirmAppKey(t, vaultID, "next", "k2", "2", "7"); got != hostproto.StatusOK {
		t.Fatalf("again: %s", got)
	}
	// The row's app_key already is the key: ok, no next written.
	if got := e.confirmAppKey(t, vaultID, "next", "k1", "1", "3"); got != hostproto.StatusOK {
		t.Fatalf("app_key already: %s", got)
	}
	// Another key at a seq the row's app_key has: conflict, not retried.
	if got := e.confirmAppKey(t, vaultID, "next", "kX", "1", "3"); got != hostproto.StatusConflict {
		t.Fatalf("other key: %s", got)
	}
	// A failed write is error, and nothing is claimed.
	h.tables.ConfirmErr = errors.New("throttled")
	if got := e.confirmAppKey(t, vaultID, "next", "k3", "3", "8"); got != hostproto.StatusError {
		t.Fatalf("failed write: %s", got)
	}
	h.tables.ConfirmErr = nil
	if r, _ := h.tables.Vault(vaultID); string(r.AppKeyNext) != "k2" {
		t.Fatalf("row %+v", r)
	}
	// No row: conflict.
	if got := e.confirmAppKey(t, "fedcba9876543210fedcba9876543210", "next", "k2", "2", "7"); got != hostproto.StatusConflict {
		t.Fatalf("no row: %s", got)
	}
	// Enrollment: the row gets app_key.
	h.tables.PutVault(parenttest.VaultRow{VaultID: vaultID, UserGUID: "u1", State: "enrolling", AppKey: []byte("old"), AppKeySeq: 5, AppKeyNext: []byte("n"), AppKeyNextSeq: 6})
	if got := e.confirmAppKey(t, vaultID, "enroll", "k1", "1", "1"); got != hostproto.StatusOK {
		t.Fatalf("enroll: %s", got)
	}
	if r, _ := h.tables.Vault(vaultID); string(r.AppKey) != "k1" || r.AppKeySeq != 1 || r.AppKeyNext != nil {
		t.Fatalf("row %+v", r)
	}
	// Malformed: invalid.
	for _, f := range [][]string{{}, {vaultID}, {vaultID, "bogus", "k", "1", "1"}, {vaultID, "next", "", "1", "1"}, {vaultID, "next", "k", "0", "1"},
		{vaultID, "next", "k", "01", "1"}, {vaultID, "next", "k", "1", "x"}, {"NOT/AN/ID", "next", "k", "1", "1"}} {
		if got := e.confirmAppKey(t, f...); got != hostproto.StatusInvalid {
			t.Fatalf("%q: %s", f, got)
		}
	}
}

// A failed app_key write is not dropped: it is written again until it
// succeeds, and the rest of the event is not held back by it.
func TestAppKeyWriteRetried(t *testing.T) {
	defer parent.SetAppKeyRetryForTest(5*time.Millisecond, 20*time.Millisecond)()
	h, e := appKeyHarness(t)
	h.tables.PutVault(parenttest.VaultRow{VaultID: vaultID, UserGUID: "u1", State: "locked", AppKey: []byte("k1"), AppKeyID: parent.AppKeyID([]byte("k1")), AppKeySeq: 1,
		AppKeyNext: []byte("k2"), AppKeyNextSeq: 2})
	h.tables.SetAppKeyErr(errors.New("throttled"))
	e.appKeyEvent("unlocked", "k2", "2", "0", "9")
	waitFor(t, "rest of the event", func() bool { r, _ := h.tables.Vault(vaultID); return r.State == "unlocked" })
	time.Sleep(50 * time.Millisecond) // several failed tries
	if r, _ := h.tables.Vault(vaultID); string(r.AppKey) != "k1" {
		t.Fatalf("written while failing: %+v", r)
	}
	h.logMu.Lock()
	logged := strings.Contains(h.logs.String(), "app key write failed; trying again")
	h.logMu.Unlock()
	if !logged {
		t.Fatal("failure not logged")
	}
	h.tables.SetAppKeyErr(nil)
	waitFor(t, "app_key written", func() bool {
		r, _ := h.tables.Vault(vaultID)
		return string(r.AppKey) == "k2" && r.AppKeySeq == 2 && r.AppKeyNext == nil
	})
}

// The enclave's assertion is written as app_key. app_key_next_assert no
// longer exists: a frame with that event is refused, and a stale one could
// never bring back a next key (R1).
func TestAppKeyAssertionsWritten(t *testing.T) {
	h, e := appKeyHarness(t)
	h.tables.PutVault(parenttest.VaultRow{VaultID: vaultID, UserGUID: "u1", State: "locked"})
	e.appKeyEvent(parent.EventAppKeyAssert, "k1", "1", "", "0")
	waitFor(t, "app_key", func() bool { r, _ := h.tables.Vault(vaultID); return string(r.AppKey) == "k1" && r.AppKeySeq == 1 })
	e.appKeyEvent("app_key_next_assert", "k2", "2", "", "6")
	// Older assertions change nothing, and an assertion never touches the state.
	e.appKeyEvent(parent.EventAppKeyAssert, "k0", "1", "", "0")
	e.appKeyEvent(parent.EventAppKeyAssert, "k2", "2", "", "0")
	waitFor(t, "app_key moved on", func() bool { r, _ := h.tables.Vault(vaultID); return string(r.AppKey) == "k2" })
	if r, _ := h.tables.Vault(vaultID); r.State != "locked" || r.AppKeyNext != nil {
		t.Fatalf("row %+v", r)
	}
}

// The app_key_next report is not written to the table at all (the
// acknowledged request wrote it): no failure, no retry, the row untouched.
func TestAppKeyNextReportNotWritten(t *testing.T) {
	defer parent.SetAppKeyRetryForTest(5*time.Millisecond, 20*time.Millisecond)()
	h, e := appKeyHarness(t)
	h.tables.PutVault(parenttest.VaultRow{VaultID: vaultID, UserGUID: "u1", State: "locked", AppKey: []byte("k1"), AppKeyID: parent.AppKeyID([]byte("k1")), AppKeySeq: 1})
	h.tables.SetAppKeyErr(errors.New("throttled"))
	e.appKeyEvent(parent.EventAppKeyNext, "k2", "2", "", "5")
	waitFor(t, "logged as a lifecycle event", func() bool { return h.hasLog(`"msg":"lifecycle","event":"app_key_next"`) })
	h.tables.SetAppKeyErr(nil)
	time.Sleep(80 * time.Millisecond)
	if r, _ := h.tables.Vault(vaultID); r.AppKeyNext != nil || h.hasLog("app key write failed") || h.hasLog("lifecycle write failed") {
		t.Fatalf("written or retried: %+v", r)
	}
}

// A report at the header_seq of a live entry does not replace it (it would
// drop the attempt stamp, and a late older attempt would then pass).
func TestReportKeepsTheLiveEntryStamp(t *testing.T) {
	tb := parenttest.NewTables()
	ctx, now := context.Background(), time.Now()
	tb.PutVault(parenttest.VaultRow{VaultID: "v1", UserGUID: "u1", State: "locked", AppKey: []byte("k5"), AppKeyID: parent.AppKeyID([]byte("k5")), AppKeySeq: 5})
	older, newer := att(), att()
	if err := tb.ConfirmAppKey(ctx, "v1", "next", []byte("K8"), 6, 9, newer, now); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"K8", "K6"} { // the same key and another, at the same header_seq
		_ = tb.AppKeys(ctx, parent.Lifecycle{Event: parent.EventAppKeyNext, VaultID: "v1", AppKey: []byte(k), AppKeySeq: 6, HeaderSeq: 9}, now)
	}
	if r, _ := tb.Vault("v1"); string(r.AppKeyNext) != "K8" || r.AppKeyNextAtt != newer {
		t.Fatalf("report replaced the live entry: %+v", r)
	}
	if err := tb.ConfirmAppKey(ctx, "v1", "next", []byte("K6"), 6, 9, older, now); !errors.Is(err, parent.ErrConflict) {
		t.Fatalf("a late older attempt: %v", err)
	}
}

// R2: an earlier attempt's confirmation landed on the row but its header
// was never stored; the next attempt reuses the header_seq with another
// key, and its live confirm is not refused. R3: a stale next key of an
// earlier vault (a higher seq and header_seq) does not refuse every later
// confirm. Reports and retries stay strict.
func TestLiveConfirmReplacesOwnEarlierAttempt(t *testing.T) {
	tb := parenttest.NewTables()
	ctx, now := context.Background(), time.Now()
	row := func() parenttest.VaultRow { r, _ := tb.Vault("v1"); return r }
	tb.PutVault(parenttest.VaultRow{VaultID: "v1", UserGUID: "u1", State: "locked", AppKey: []byte("k5"), AppKeyID: parent.AppKeyID([]byte("k5")), AppKeySeq: 5})
	if err := tb.ConfirmAppKey(ctx, "v1", "next", []byte("K6"), 6, 4, att(), now); err != nil {
		t.Fatal(err)
	}
	// R2: another key, the same header_seq.
	_ = tb.AppKeys(ctx, parent.Lifecycle{Event: parent.EventAppKeyNext, VaultID: "v1", AppKey: []byte("K8"), AppKeySeq: 6, HeaderSeq: 4}, now)
	if string(row().AppKeyNext) != "K6" {
		t.Fatal("a report replaced the next key at an equal header_seq")
	}
	if err := tb.ConfirmAppKey(ctx, "v1", "next", []byte("K8"), 6, 4, att(), now); err != nil || string(row().AppKeyNext) != "K8" {
		t.Fatalf("R2: %v %+v", err, row())
	}
	// A next key of a higher seq or header_seq is never replaced by a live
	// confirm (R3 is not granted: a stale next of an earlier vault is an
	// availability-only residual).
	tb.PutVault(parenttest.VaultRow{VaultID: "v1", UserGUID: "u1", State: "enrolling", AppKey: []byte("k1"), AppKeyID: parent.AppKeyID([]byte("k1")), AppKeySeq: 1,
		AppKeyNext: []byte("old"), AppKeyNextSeq: 9, AppKeyNextHSeq: 40})
	if err := tb.ConfirmAppKey(ctx, "v1", "next", []byte("K2"), 2, 3, att(), now); !errors.Is(err, parent.ErrConflict) || string(row().AppKeyNext) != "old" {
		t.Fatalf("a higher next was replaced: %v %+v", err, row())
	}
	// An enrollment's own confirmation clears it.
	if err := tb.ConfirmAppKey(ctx, "v1", "enroll", []byte("k1"), 1, 1, att(), now); err != nil || row().AppKeyNext != nil {
		t.Fatalf("enroll: %v %+v", err, row())
	}
}

// 4a: two live confirmations of one vault through the parent, the first
// slow. They are serialized, so the older attempt cannot land after the
// newer one: the newer key stays.
func TestConfirmsAreSerializedPerVault(t *testing.T) {
	h, e := appKeyHarness(t)
	h.tables.PutVault(parenttest.VaultRow{VaultID: vaultID, UserGUID: "u1", State: "locked", AppKey: []byte("k5"), AppKeyID: parent.AppKeyID([]byte("k5")), AppKeySeq: 5})
	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	h.tables.SetConfirmHook(func(key []byte) {
		if string(key) == "K6" {
			entered <- struct{}{}
			<-release // the older attempt is slow
		}
	})
	a := make(chan string, 1)
	go func() { a <- e.confirmAppKey(t, vaultID, "next", "K6", "6", "9") }()
	<-entered
	b := make(chan string, 1)
	go func() { b <- e.confirmAppKey(t, vaultID, "next", "K8", "6", "9") }()
	select {
	case got := <-b:
		t.Fatalf("the newer attempt was answered (%s) while the older was in flight", got)
	case <-time.After(150 * time.Millisecond):
	}
	close(release)
	if got := <-a; got != hostproto.StatusOK {
		t.Fatalf("older: %s", got)
	}
	if got := <-b; got != hostproto.StatusOK {
		t.Fatalf("newer: %s", got)
	}
	if r, _ := h.tables.Vault(vaultID); string(r.AppKeyNext) != "K8" {
		t.Fatalf("the older attempt landed last: %+v", r)
	}
}

// A handler past its deadline writes nothing and gives the lock back.
func TestLateConfirmWritesNothing(t *testing.T) {
	defer parent.SetConfirmDeadlineForTest(300 * time.Millisecond)()
	h, e := appKeyHarness(t)
	h.tables.PutVault(parenttest.VaultRow{VaultID: vaultID, UserGUID: "u1", State: "locked", AppKey: []byte("k5"), AppKeyID: parent.AppKeyID([]byte("k5")), AppKeySeq: 5})
	h.tables.SetAppKeyErr(errors.New("throttled"))
	e.appKeyEvent(parent.EventAppKey, "k6", "6", "", "0") // queued: waitKeyQ cannot finish
	waitFor(t, "queued", func() bool { return h.hasLog("app key write failed; trying again") })
	if got := e.confirmAppKey(t, vaultID, "next", "K9", "9", "9"); got != hostproto.StatusError {
		t.Fatalf("past its deadline: %s", got)
	}
	h.tables.SetAppKeyErr(nil)
	waitFor(t, "queue drained", func() bool { r, _ := h.tables.Vault(vaultID); return string(r.AppKey) == "k6" })
	if r, _ := h.tables.Vault(vaultID); r.AppKeyNext != nil {
		t.Fatalf("a late handler wrote: %+v", r)
	}
	if got := e.confirmAppKey(t, vaultID, "next", "K7", "7", "10"); got != hostproto.StatusOK {
		t.Fatalf("the lock was not given back: %s", got)
	}
}

// 4b: the row's app_key lags (K5), K7 is confirmed at seq 7 / header_seq 15;
// a late live K6 (seq 6, header_seq 9) must not replace it.
func TestLateOlderConfirmDoesNotReplaceNewer(t *testing.T) {
	h, e := appKeyHarness(t)
	h.tables.PutVault(parenttest.VaultRow{VaultID: vaultID, UserGUID: "u1", State: "locked", AppKey: []byte("K5"), AppKeyID: parent.AppKeyID([]byte("K5")), AppKeySeq: 5})
	if got := e.confirmAppKey(t, vaultID, "next", "K7", "7", "15"); got != hostproto.StatusOK {
		t.Fatalf("K7: %s", got)
	}
	if got := e.confirmAppKey(t, vaultID, "next", "K6", "6", "9"); got != hostproto.StatusConflict {
		t.Fatalf("late K6: %s", got)
	}
	if r, _ := h.tables.Vault(vaultID); string(r.AppKeyNext) != "K7" || r.AppKeyNextSeq != 7 {
		t.Fatalf("the newer next key was replaced: %+v", r)
	}
}

// The enrolled event never rolls app_key back: through the parent, as the
// enclave's event arrives (also a retried or repeated one).
func TestEnrolledEventNeverRollsBack(t *testing.T) {
	h, e := appKeyHarness(t)
	h.tables.PutVault(parenttest.VaultRow{VaultID: vaultID, UserGUID: "u1", State: "unlocked", AppKey: []byte("k2"), AppKeyID: parent.AppKeyID([]byte("k2")), AppKeySeq: 2})
	e.appKeyEvent("enrolled", "k1", "1", "", "0")
	waitFor(t, "written", func() bool { return len(h.tables.LifecycleEvents(vaultID)) == 1 })
	if r, _ := h.tables.Vault(vaultID); string(r.AppKey) != "k2" || r.AppKeySeq != 2 {
		t.Fatalf("enrolled rolled app_key back: %+v", r)
	}
	// A row still enrolling takes it (a replaced provisional vault).
	h.tables.PutVault(parenttest.VaultRow{VaultID: vaultID, UserGUID: "u1", State: "enrolling", AppKey: []byte("k2"), AppKeyID: parent.AppKeyID([]byte("k2")), AppKeySeq: 2})
	e.appKeyEvent("enrolled", "k1", "1", "", "0")
	waitFor(t, "replaced", func() bool { r, _ := h.tables.Vault(vaultID); return string(r.AppKey) == "k1" })
}

func (h *harness) hasLog(s string) bool {
	h.logMu.Lock()
	defer h.logMu.Unlock()
	return strings.Contains(h.logs.String(), s)
}

// D1: the three regressions the review reproduced. A stale write that
// arrives after a confirmation does not undo it.
func TestStaleAppKeyWritesDoNotRegress(t *testing.T) {
	tb := parenttest.NewTables()
	ctx, now := context.Background(), time.Now()
	row := func() parenttest.VaultRow { r, _ := tb.Vault("v1"); return r }
	// 1. A stale next key at the same seq (an older attempt's retry or
	// assertion) does not replace the confirmed one; the same key again
	// and a later header_seq do.
	tb.PutVault(parenttest.VaultRow{VaultID: "v1", UserGUID: "u1", State: "locked", AppKey: []byte("k5"), AppKeyID: parent.AppKeyID([]byte("k5")), AppKeySeq: 5})
	if err := tb.ConfirmAppKey(ctx, "v1", "next", []byte("K7"), 6, 7, att(), now); err != nil {
		t.Fatal(err)
	}
	_ = tb.AppKeys(ctx, parent.Lifecycle{Event: parent.EventAppKeyNext, VaultID: "v1", AppKey: []byte("K6"), AppKeySeq: 6, HeaderSeq: 5}, now)
	_ = tb.Lifecycle(ctx, parent.Lifecycle{Event: parent.EventAppKeyNext, VaultID: "v1", AppKey: []byte("K6"), AppKeySeq: 6, HeaderSeq: 5}, "me", now)
	if r := row(); string(r.AppKeyNext) != "K7" || r.AppKeyNextHSeq != 7 {
		t.Fatalf("a stale next replaced the confirmed one: %+v", r)
	}
	if err := tb.ConfirmAppKey(ctx, "v1", "next", []byte("K6"), 6, 5, att(), now); !errors.Is(err, parent.ErrConflict) {
		t.Fatalf("a late confirm of the older attempt: %v", err)
	}
	_ = tb.AppKeys(ctx, parent.Lifecycle{Event: parent.EventAppKeyNext, VaultID: "v1", AppKey: []byte("K9"), AppKeySeq: 6, HeaderSeq: 7}, now)
	if r := row(); string(r.AppKeyNext) != "K7" {
		t.Fatalf("a report at an equal header_seq replaced: %+v", r)
	}
	_ = tb.AppKeys(ctx, parent.Lifecycle{Event: parent.EventAppKeyNext, VaultID: "v1", AppKey: []byte("K8"), AppKeySeq: 6, HeaderSeq: 9}, now)
	if r := row(); string(r.AppKeyNext) != "K8" {
		t.Fatalf("a later attempt did not replace: %+v", r)
	}
	// 2. A late next_cleared of an older header_seq does not remove a newer
	// replacement's key.
	_ = tb.AppKeys(ctx, parent.Lifecycle{Event: parent.EventAppKey, VaultID: "v1", AppKey: []byte("k5"), AppKeySeq: 5, NextCleared: true, HeaderSeq: 6}, now)
	if r := row(); string(r.AppKeyNext) != "K8" {
		t.Fatalf("a late clear removed the next key: %+v", r)
	}
	_ = tb.AppKeys(ctx, parent.Lifecycle{Event: parent.EventAppKey, VaultID: "v1", AppKey: []byte("k5"), AppKeySeq: 5, NextCleared: true, HeaderSeq: 9}, now)
	if r := row(); r.AppKeyNext != nil {
		t.Fatalf("the clear of its own header_seq did not apply: %+v", r)
	}
	// 3. A retried enrolled does not roll app_key back to the seq-1 key,
	// and still serves a replaced provisional vault (row enrolling).
	tb.PutVault(parenttest.VaultRow{VaultID: "v1", UserGUID: "u1", State: "unlocked", AppKey: []byte("k2"), AppKeyID: parent.AppKeyID([]byte("k2")), AppKeySeq: 2})
	_ = tb.AppKeys(ctx, parent.Lifecycle{Event: "enrolled", VaultID: "v1", AppKey: []byte("k1"), AppKeySeq: 1}, now)
	_ = tb.Lifecycle(ctx, parent.Lifecycle{Event: "enrolled", VaultID: "v1", AppKey: []byte("k1"), AppKeySeq: 1}, "me", now)
	if r := row(); string(r.AppKey) != "k2" || r.AppKeySeq != 2 {
		t.Fatalf("enrolled rolled app_key back: %+v", r)
	}
	tb.PutVault(parenttest.VaultRow{VaultID: "v1", UserGUID: "u1", State: "enrolling", AppKey: []byte("k2"), AppKeyID: parent.AppKeyID([]byte("k2")), AppKeySeq: 2})
	_ = tb.AppKeys(ctx, parent.Lifecycle{Event: "enrolled", VaultID: "v1", AppKey: []byte("k1"), AppKeySeq: 1}, now)
	if r := row(); string(r.AppKey) != "k1" {
		t.Fatalf("a replaced provisional vault's first key: %+v", r)
	}
}

// The confirm waits for the vault's failed app key writes, so a retry
// cannot land after it.
func TestConfirmDrainsRetryQueue(t *testing.T) {
	defer parent.SetAppKeyRetryForTest(5*time.Millisecond, 20*time.Millisecond)()
	h, e := appKeyHarness(t)
	h.tables.PutVault(parenttest.VaultRow{VaultID: vaultID, UserGUID: "u1", State: "locked", AppKey: []byte("k1"), AppKeyID: parent.AppKeyID([]byte("k1")), AppKeySeq: 1})
	h.tables.SetAppKeyErr(errors.New("throttled"))
	e.appKeyEvent(parent.EventAppKey, "k2", "2", "", "0")
	waitFor(t, "queued", func() bool { return h.hasLog("app key write failed; trying again") })
	done := make(chan string, 1)
	go func() { done <- e.confirmAppKey(t, vaultID, "next", "k3", "3", "9") }()
	select {
	case got := <-done:
		t.Fatalf("answered before the earlier write: %s", got)
	case <-time.After(100 * time.Millisecond):
	}
	h.tables.SetAppKeyErr(nil)
	if got := <-done; got != hostproto.StatusOK {
		t.Fatalf("confirm: %s", got)
	}
	// The retry was written first, then the confirmation: not the other way.
	if r, _ := h.tables.Vault(vaultID); string(r.AppKey) != "k2" || string(r.AppKeyNext) != "k3" {
		t.Fatalf("row %+v", r)
	}
}

// A permanent failure is logged and given up, not retried for ever; an
// app-key-only failure still logs the line it always did.
func TestPermanentAppKeyFailureGivenUp(t *testing.T) {
	defer parent.SetAppKeyRetryForTest(5*time.Millisecond, 20*time.Millisecond)()
	h, e := appKeyHarness(t)
	h.tables.PutVault(parenttest.VaultRow{VaultID: vaultID, UserGUID: "u1", State: "locked"})
	h.tables.SetAppKeyErr(fmt.Errorf("%w: refused", parent.ErrPermanent))
	e.appKeyEvent(parent.EventAppKey, "k2", "2", "", "0")
	waitFor(t, "the line an unwritten event always had", func() bool { return h.hasLog(`"msg":"lifecycle write failed","event":"app_key"`) })
	waitFor(t, "given up", func() bool { return h.hasLog("app key write refused; not tried again") })
	h.tables.SetAppKeyErr(nil)
	time.Sleep(60 * time.Millisecond)
	if r, _ := h.tables.Vault(vaultID); r.AppKey != nil {
		t.Fatalf("written after it was given up: %+v", r)
	}
}

// A burst of assertions never holds up a confirmation, and logs no
// lifecycle line at info.
func TestAssertionBurstDoesNotBlock(t *testing.T) {
	defer parent.SetAssertPaceForTest(time.Millisecond)()
	h, e := appKeyHarness(t)
	h.tables.SetAppKeyDelay(10 * time.Millisecond)
	h.tables.PutVault(parenttest.VaultRow{VaultID: vaultID, UserGUID: "u1", State: "locked", AppKey: []byte("k1"), AppKeyID: parent.AppKeyID([]byte("k1")), AppKeySeq: 1})
	for i := 0; i < 300; i++ {
		id := fmt.Sprintf("%032x", i+1)
		_ = e.conn.Notify(hostproto.KindLifecycle, hostproto.Strings(parent.EventAppKeyAssert, id, pcr, pcr, "1", "kk", "1", "", "0", "", "", "", "0", "")...)
	}
	start := time.Now()
	if got := e.confirmAppKey(t, vaultID, "next", "k2", "2", "4"); got != hostproto.StatusOK {
		t.Fatalf("confirm: %s", got)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("confirm waited %v behind the assertions", d)
	}
	if h.hasLog(`"level":"INFO","msg":"lifecycle","event":"app_key_assert"`) {
		t.Fatal("assertions logged at info")
	}
}

var attCounter atomic.Int64

// att is an increasing attempt stamp for calls that go to the tables direct.
func att() int64 { return attCounter.Add(1) }

// The attempt stamp: at an equal header_seq a live confirmation of an older
// attempt that lands late (after a newer one) is refused, whatever the key.
func TestOlderAttemptStampRefused(t *testing.T) {
	tb := parenttest.NewTables()
	ctx, now := context.Background(), time.Now()
	tb.PutVault(parenttest.VaultRow{VaultID: "v1", UserGUID: "u1", State: "locked", AppKey: []byte("k5"), AppKeyID: parent.AppKeyID([]byte("k5")), AppKeySeq: 5})
	older, newer := att(), att()
	if err := tb.ConfirmAppKey(ctx, "v1", "next", []byte("K8"), 6, 9, newer, now); err != nil {
		t.Fatal(err)
	}
	if err := tb.ConfirmAppKey(ctx, "v1", "next", []byte("K6"), 6, 9, older, now); !errors.Is(err, parent.ErrConflict) {
		t.Fatalf("a late older attempt: %v", err)
	}
	if r, _ := tb.Vault("v1"); string(r.AppKeyNext) != "K8" {
		t.Fatalf("row %+v", r)
	}
	// The same attempt again (a repeated request) and a later one are not older.
	if err := tb.ConfirmAppKey(ctx, "v1", "next", []byte("K9"), 6, 9, att(), now); err != nil {
		t.Fatal(err)
	}
}

// A write sent before the deadline is not cancelled by it and keeps the
// vault's lock until it has an outcome: the vault's next attempt waits for
// it, so the older attempt cannot land after the newer one.
func TestInFlightWriteHoldsTheLockPastTheDeadline(t *testing.T) {
	defer parent.SetConfirmDeadlineForTest(300 * time.Millisecond)()
	h, e := appKeyHarness(t)
	h.tables.PutVault(parenttest.VaultRow{VaultID: vaultID, UserGUID: "u1", State: "locked", AppKey: []byte("k5"), AppKeyID: parent.AppKeyID([]byte("k5")), AppKeySeq: 5})
	release := make(chan struct{})
	h.tables.SetConfirmHook(func(key []byte) {
		if string(key) == "K6" {
			<-release // the write is in flight past the deadline
		}
	})
	start := time.Now()
	if got := e.confirmAppKey(t, vaultID, "next", "K6", "6", "9"); got != hostproto.StatusError {
		t.Fatalf("past the deadline: %s", got)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("the vault waited for the write")
	}
	k8 := make(chan string, 1)
	go func() { k8 <- e.confirmAppKey(t, vaultID, "next", "K8", "6", "9") }()
	time.Sleep(100 * time.Millisecond)
	close(release)
	if got := <-k8; got != hostproto.StatusOK {
		t.Fatalf("K8: %s", got)
	}
	if keys := h.tables.ConfirmedKeys(); len(keys) != 2 || keys[0] != "K6" || keys[1] != "K8" {
		t.Fatalf("writes reached the table as %v (K6 must land, and before K8)", keys)
	}
	if r, _ := h.tables.Vault(vaultID); string(r.AppKeyNext) != "K8" {
		t.Fatalf("row %+v", r)
	}
}
