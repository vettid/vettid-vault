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

// A wrong PIN whose header put fails: bad_pin reports the header_seq as
// read, and the next unlock with that floor is not refused as a rollback.
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
	if out.Code != CodeBadPIN || out.HeaderSeq != stored {
		t.Fatalf("bad_pin reports header_seq %d, stored %d (%s)", out.HeaderSeq, stored, out.Code)
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
			opts.Store = &faultStore{Store: d.store, failHeader: 1}
		}
		m, uo := cancelUnlock(d, opts, func(p *AltUnlockParams) { p.CancelRecovery = false })
		if m != nil || uo.OK || uo.Code != CodeNoBackup {
			t.Fatalf("put fails %v: unlock %+v", fails, uo)
		}
		h := storedHeader(t, d)
		if fails && (h.HeaderSeq != before || h.Recovery == nil) || !fails && (h.HeaderSeq != before+1 || h.Recovery != nil) {
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
