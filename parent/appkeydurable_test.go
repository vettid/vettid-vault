package parent_test

import (
	"context"
	"errors"
	"strings"
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
	h.tables.AppKeyErr = errors.New("throttled")
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
	h.tables.AppKeyErr = nil
	waitFor(t, "app_key written", func() bool {
		r, _ := h.tables.Vault(vaultID)
		return string(r.AppKey) == "k2" && r.AppKeySeq == 2 && r.AppKeyNext == nil
	})
}

// The enclave's assertions are written as app_key and app_key_next.
func TestAppKeyAssertionsWritten(t *testing.T) {
	h, e := appKeyHarness(t)
	h.tables.PutVault(parenttest.VaultRow{VaultID: vaultID, UserGUID: "u1", State: "locked"})
	e.appKeyEvent(parent.EventAppKeyAssert, "k1", "1", "", "0")
	waitFor(t, "app_key", func() bool { r, _ := h.tables.Vault(vaultID); return string(r.AppKey) == "k1" && r.AppKeySeq == 1 })
	e.appKeyEvent(parent.EventAppKeyNextAssert, "k2", "2", "", "6")
	waitFor(t, "app_key_next", func() bool {
		r, _ := h.tables.Vault(vaultID)
		return string(r.AppKeyNext) == "k2" && r.AppKeyNextSeq == 2 && r.AppKeyNextHSeq == 6
	})
	// Older assertions change nothing, and an assertion never touches the state.
	e.appKeyEvent(parent.EventAppKeyAssert, "k0", "1", "", "0")
	e.appKeyEvent(parent.EventAppKeyAssert, "k2", "2", "", "0")
	waitFor(t, "app_key moved on, next gone", func() bool { r, _ := h.tables.Vault(vaultID); return string(r.AppKey) == "k2" && r.AppKeyNext == nil })
	if r, _ := h.tables.Vault(vaultID); r.State != "locked" {
		t.Fatalf("state %q", r.State)
	}
}
