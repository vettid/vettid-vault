package vault

import (
	"context"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/countertest"
	"github.com/vettid/vettid-vault/vms/strictjson"
)

// An answer reports only a header_seq known to be stored (§11.4, §13.2):
// a header put that fails may still have stored, so its seq is not used
// again, but the phone's floor never passes the stored header.

// A wrong PIN whose count's header put fails: the PIN is not tested (§11.8,
// counted before it is tested), retry reports the header_seq as read, and
// the next unlock with that floor is not refused as a rollback.
func TestBadPINWithAFailedHeaderPutReportsTheStoredSeq(t *testing.T) {
	f := newRFixture(t)
	f.flush()
	if err := f.m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	stored := f.storedHeader().HeaderSeq
	f.st.mu.Lock()
	f.st.failHeader = 1
	f.st.mu.Unlock()
	_, out := UnlockAlt(context.Background(), AltUnlockParams{Options: f.opts, VaultID: f.vid, PIN: "000000", UnlockSecret: testSecret, pinOnly: true})
	if out.Code != CodeRetry || out.HeaderSeq != stored {
		t.Fatalf("retry reports header_seq %d, stored %d (%s)", out.HeaderSeq, stored, out.Code)
	}
	f.st.mu.Lock()
	f.st.failHeader = 0
	f.st.mu.Unlock()
	m, out := UnlockAlt(context.Background(), AltUnlockParams{Options: f.opts, VaultID: f.vid, PIN: testPIN, UnlockSecret: testSecret, pinOnly: true,
		MinHeaderSeq: out.HeaderSeq})
	if m == nil || !out.OK {
		t.Fatalf("the next unlock with the reported floor: %+v", out)
	}
	m.Crash()
}

// The recovery-open outcomes that write the header (wrong, wrong_again,
// attempt_lost) keep the header_seq last stored when that write fails
// (their answers carry none; the outcome is kept consistent).
func TestRecoveryOpenAnswersReportTheStoredSeq(t *testing.T) {
	for _, c := range []struct {
		code  string
		setup func(t *testing.T, f *openFixture)
		pw    string
	}{
		{OpenWrong, nil, "a wrong password here"},
		{OpenWrongAgain, func(t *testing.T, f *openFixture) {
			if _, out := f.open(testPIN, "a wrong password here"); out.Code != OpenWrong {
				t.Fatalf("setup: %+v", out)
			}
		}, "a wrong password here"},
		{OpenAttemptLost, func(_ *testing.T, f *openFixture) {
			f.bucket.StoreThenFail(countertest.OpPutCreate, 1)
			f.bucket.FailNext(countertest.OpGetVersion, 1)
		}, rPW},
	} {
		t.Run(c.code, func(t *testing.T) {
			f := newOpenFixture(t)
			if c.setup != nil {
				c.setup(t, f)
			}
			stored := f.storedHeader().HeaderSeq
			f.st.mu.Lock()
			f.st.failHeader = 1
			f.st.mu.Unlock()
			m, out := f.open(testPIN, c.pw)
			if m != nil || out.Code != c.code {
				t.Fatalf("%+v", out)
			}
			if out.HeaderSeq != stored || f.storedHeader().HeaderSeq != stored {
				t.Fatalf("reports header_seq %d, stored %d", out.HeaderSeq, f.storedHeader().HeaderSeq)
			}
		})
	}
}

// §11.11.5 step 1: an owner app registered as a recovery's phone unlocks
// a vault without a backup copy and is refused no_backup, the recovery
// cancelled. The answer carries the header_seq last stored: that of the
// cancel's header write when it is stored, and the one before it when its
// put fails (not the seq of the write that failed), so the app's floor
// never passes the stored header.
func TestNoBackupRefusalReportsTheStoredHeaderSeq(t *testing.T) {
	for _, fails := range []bool{false, true} {
		d := newDevFixture(t)
		if err := d.m.Lock(context.Background()); err != nil {
			t.Fatal(err)
		}
		p := HeaderParams{Options: d.opts, VaultID: d.vid, UserGUID: "u1"}
		if err := headerTx(context.Background(), p, func(h *Header, now time.Time) (bool, error) {
			h.Recovery = &RecoveryRecord{ID: cancelledRecID, State: RecoveryRegistered, RequestedAt: now, NotBefore: now,
				Expires: now.Add(48 * time.Hour), App: &RecoveryApp{IK: d.devPeer.IK}}
			return false, nil
		}); err != nil {
			t.Fatal(err)
		}
		before := storedHeader(t, d).HeaderSeq
		opts := d.opts
		if fails {
			// The count's write passes (§11.8); no_backup's own write fails.
			opts.Store = &faultStore{Store: d.store, passHeader: 1, failHeader: 1}
		}
		m, uo := cancelUnlock(d, opts, func(p *AltUnlockParams) { p.CancelRecovery = false })
		if m != nil || uo.OK || uo.Code != CodeNoBackup {
			t.Fatalf("put fails %v: unlock %+v", fails, uo)
		}
		h := storedHeader(t, d)
		// The count's write (+1), then no_backup's (+1, the count reset with
		// it) or, when that fails, the count given back (+1).
		if fails && (h.HeaderSeq != before+2 || h.Recovery == nil) || !fails && (h.HeaderSeq != before+2 || h.Recovery != nil) {
			t.Fatalf("put fails %v: stored header_seq %d (before %d), recovery %v", fails, h.HeaderSeq, before, h.Recovery)
		}
		if uo.HeaderSeq != h.HeaderSeq {
			t.Fatalf("put fails %v: header_seq %d, stored %d", fails, uo.HeaderSeq, h.HeaderSeq)
		}
	}
}

// vault.status reports the header_seq last stored, not one a failed header
// write counted.
func TestStatusReportsTheStoredHeaderSeq(t *testing.T) {
	d := newDevFixture(t)
	hs := &headerFailStore{Store: d.store}
	var stored uint64
	d.withLock(func(m *Manager) {
		stored = m.hdr.HeaderSeq
		m.opt.Store = hs
		hs.fail.Store(true)
		if err := m.writeHeader(context.Background()); err == nil {
			t.Fatal("the header write did not fail")
		}
		hs.fail.Store(false)
		if m.hdr.HeaderSeq == stored {
			t.Fatal("the failed write counted no header_seq")
		}
	})
	app := d.self()
	id := d.sendAs(app, "vault.status", `{}`)
	r := find(d.inbox(app)["dev1"], reply(id))
	o, err := strictjson.ParseObject(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := o.Uint("header_seq", 0, 1<<53); n != stored {
		t.Fatalf("vault.status header_seq %d, stored %d", n, stored)
	}
}

// §11.8 (VAULT-MESSAGING 0.90.8): an unlock's PIN attempt is counted before
// it is tested. A host that fails the count's header write gets no PIN
// result, right PIN or wrong: retry, the stored count unchanged.
func TestUnlockCountWriteFailedTestsNoPIN(t *testing.T) {
	for _, pin := range []string{"000000", testPIN} {
		f := newRFixture(t)
		f.flush()
		if err := f.m.Lock(context.Background()); err != nil {
			t.Fatal(err)
		}
		h0 := f.storedHeader()
		f.st.mu.Lock()
		f.st.failHeader = 1
		f.st.mu.Unlock()
		m, out := UnlockAlt(context.Background(), AltUnlockParams{Options: f.opts, VaultID: f.vid, PIN: pin, UnlockSecret: testSecret, pinOnly: true})
		if m != nil || out.Code != CodeRetry || out.HeaderSeq != h0.HeaderSeq {
			t.Fatalf("pin %s: %+v", pin, out)
		}
		if h := f.storedHeader(); h.Backoff.Failures != h0.Backoff.Failures || h.HeaderSeq != h0.HeaderSeq {
			t.Fatalf("pin %s: stored failures %d seq %d, before %d %d", pin, h.Backoff.Failures, h.HeaderSeq, h0.Backoff.Failures, h0.HeaderSeq)
		}
	}
}

// Each wrong PIN is stored counted before its bad_pin; a right PIN after
// them resets the stored count.
func TestUnlockWrongPINsCountedThenReset(t *testing.T) {
	f := newRFixture(t)
	f.flush()
	if err := f.m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 2; i++ {
		_, out := UnlockAlt(context.Background(), AltUnlockParams{Options: f.opts, VaultID: f.vid, PIN: "000000", UnlockSecret: testSecret, pinOnly: true})
		h := f.storedHeader()
		if out.Code != CodeBadPIN || h.Backoff.Failures != i || out.HeaderSeq != h.HeaderSeq {
			t.Fatalf("wrong PIN %d: %s, stored failures %d, reported seq %d stored %d", i, out.Code, h.Backoff.Failures, out.HeaderSeq, h.HeaderSeq)
		}
	}
	m, out := UnlockAlt(context.Background(), AltUnlockParams{Options: f.opts, VaultID: f.vid, PIN: testPIN, UnlockSecret: testSecret, pinOnly: true})
	if m == nil || !out.OK {
		t.Fatalf("right PIN: %+v", out)
	}
	defer m.Crash()
	if h := f.storedHeader(); h.Backoff.Failures != 0 {
		t.Fatalf("not reset: %d", h.Backoff.Failures)
	}
}

// A right PIN with no earlier failures leaves no count behind: the count
// its attempt stored is reset by the unlock's own header write.
func TestUnlockRightPINLeavesNoCount(t *testing.T) {
	f := newRFixture(t)
	f.flush()
	if err := f.m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	m, out := UnlockAlt(context.Background(), AltUnlockParams{Options: f.opts, VaultID: f.vid, PIN: testPIN, UnlockSecret: testSecret, pinOnly: true})
	if m == nil || !out.OK {
		t.Fatalf("right PIN: %+v", out)
	}
	defer m.Crash()
	if h := f.storedHeader(); h.Backoff.Failures != 0 {
		t.Fatalf("a count left behind: %d", h.Backoff.Failures)
	}
}

// What is decided before the PIN (a phone secret that matches nothing) is
// not counted: nothing is written.
func TestUnlockWrongSecretIsNotCounted(t *testing.T) {
	f := newRFixture(t)
	f.flush()
	if err := f.m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	h0 := f.storedHeader()
	_, out := UnlockAlt(context.Background(), AltUnlockParams{Options: f.opts, VaultID: f.vid, PIN: "000000", UnlockSecret: testSecret2, pinOnly: true})
	if out.Code != CodeDeviceSecret {
		t.Fatalf("%+v", out)
	}
	if h := f.storedHeader(); h.Backoff.Failures != h0.Backoff.Failures || h.HeaderSeq != h0.HeaderSeq {
		t.Fatalf("counted: failures %d seq %d", h.Backoff.Failures, h.HeaderSeq)
	}
}
