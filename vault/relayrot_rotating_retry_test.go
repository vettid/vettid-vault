package vault

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayclient"
)

// §3.4 "Retrying with the same key", "A definite refusal", "After the
// grace", "The refused state" and "What is audited"; §3.4.2 RK14 step 1
// "When it is cleared".

// No definite answer (a 5xx, 429, timestamp_stale, replay_detected): the
// key stays pending and not refused, and is retried with the same key once
// the jittered wait has run (at most 1 min for the first retry).
func TestRelayRotNoAnswerRetriedWithTheSameKey(t *testing.T) {
	for _, err := range []error{relayErr(503, "unavailable"), relayErr(429, "rate_limited"), relayErr(401, CodeTimestampStale),
		relayErr(401, CodeReplayDetected)} {
		fx := newRotFx(t)
		fx.w.rotate = []error{err}
		if e := fx.credRotate(); e != nil {
			t.Fatal(e)
		}
		pr := fx.pending()
		if pr == nil || pr.Refused != "" {
			t.Fatalf("%v: pending %+v", err, pr)
		}
		pmb := fx.pendingMailbox()
		fx.clk = fx.clk.Add(time.Minute + time.Second)
		fx.batch()
		rot, _ := fx.w.log()
		if len(rot) != 2 || rot[0] != rot[1] || fx.mailbox() != pmb {
			t.Fatalf("%v: rotates %v", err, rot)
		}
	}
}

// The sooner retries back off: none before the wait, and the n-th wait is
// at most min(1 h, 1 min × 2^(n−1)).
func TestRelayRotSoonerRetriesBackOff(t *testing.T) {
	for n := 1; n <= 9; n++ {
		limit := min(time.Hour, time.Minute<<(n-1))
		for range 50 {
			if w := relayRetryWait(n); w < 0 || w > limit {
				t.Fatalf("wait %d: %v over %v", n, w, limit)
			}
		}
	}
	fx := newRotFx(t)
	fx.w.rotate = []error{relayErr(503, ""), relayErr(503, "")}
	if err := fx.credRotate(); err != nil {
		t.Fatal(err)
	}
	var next time.Time
	fx.do(func(m *Manager) { next = m.rk.next })
	if next.Before(fx.clk) || next.After(fx.clk.Add(time.Minute)) {
		t.Fatalf("first wait to %v", next)
	}
	fx.clk = next.Add(-time.Millisecond)
	if next.After(fx.clk) {
		fx.batch()
		if rot, _ := fx.w.log(); len(rot) != 1 {
			t.Fatalf("retried before the wait: %v", rot)
		}
	}
}

// A 429's retry_after is stored with the pending key: a lock and an unlock
// do not reset it; the unlock makes no attempt while it runs and audits
// identity.rotation_failed (with its feed item), and the next attempt is
// made when it has run out.
func TestRelayRotRetryAfterKeptAcrossTheUnlock(t *testing.T) {
	fx := newRotFx(t)
	e := &relayclient.Error{Status: 429, Code: "rate_limited", RetryAfter: 7200}
	fx.w.rotate = []error{e}
	if err := fx.credRotate(); err != nil {
		t.Fatal(err)
	}
	if pr := fx.pending(); pr == nil || !pr.RetryAfter.Equal(fx.clk.Add(2*time.Hour)) {
		t.Fatalf("retry_after %+v", pr)
	}
	fx.clk = fx.clk.Add(time.Hour)
	fx.restart()
	if rot, _ := fx.w.log(); len(rot) != 1 {
		t.Fatalf("attempted while retry_after runs: %v", rot)
	}
	if a := fx.acts("identity.rotation_failed"); len(a) != 1 || a[0].Priority != "high" || !a[0].Feed {
		t.Fatalf("rotation_failed %+v", a)
	}
	fx.clk = fx.clk.Add(time.Hour + time.Second)
	fx.batch()
	if rot, _ := fx.w.log(); len(rot) != 2 || fx.pending() != nil {
		t.Fatalf("not completed after retry_after: %v", rot)
	}
}

// identity.rotation_failed for a key left pending: at an unlock whose own
// attempt does not complete it, at most once per unlock; none at an unlock
// that completes it.
func TestRelayRotLeftPendingAuditedOncePerUnlock(t *testing.T) {
	fx := newRotFx(t)
	fx.w.rotate = []error{relayErr(503, ""), relayErr(503, ""), relayErr(503, "")}
	if err := fx.credRotate(); err != nil {
		t.Fatal(err)
	}
	if len(fx.acts("identity.rotation_failed")) != 0 {
		t.Fatal("audited at the rotation's own attempt")
	}
	fx.restart()
	fx.clk = fx.clk.Add(2 * time.Minute)
	fx.batch()
	if rot, _ := fx.w.log(); len(rot) != 3 || len(fx.acts("identity.rotation_failed")) != 1 {
		t.Fatalf("rotates %v, audits %d", rot, len(fx.acts("identity.rotation_failed")))
	}
	fx.restart()
	if fx.pending() != nil || len(fx.acts("identity.rotation_failed")) != 1 {
		t.Fatal("an unlock that completes the key audited rotation_failed")
	}
}

// A definite refusal (a 4xx other than those above) is not retried: the
// refused state is stored with its code and audited at once; no sooner
// retry; one attempt at each unlock; vault.status carries relay "refused"
// to the app.
func TestRelayRotRefusedState(t *testing.T) {
	fx := newRotFx(t)
	fx.w.rotate = []error{relayErr(403, "forbidden"), relayErr(403, "forbidden")}
	if err := fx.credRotate(); err != nil {
		t.Fatal(err)
	}
	if pr := fx.pending(); pr == nil || pr.Refused != "forbidden" || len(fx.acts("identity.rotation_failed")) != 1 {
		t.Fatalf("pending %+v, audits %d", pr, len(fx.acts("identity.rotation_failed")))
	}
	fx.clk = fx.clk.Add(2 * time.Hour)
	fx.batch()
	if err := fx.m.relayMailboxUnknown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if rot, _ := fx.w.log(); len(rot) != 1 {
		t.Fatalf("retried in the refused state: %v", rot)
	}
	if !fx.statusRefused() {
		t.Fatal("vault.status has no relay refused")
	}
	fx.crash()
	if pr := fx.pending(); pr == nil || pr.Refused == "" {
		t.Fatal("the refused state was not stored")
	}
	fx.batch()
	if rot, _ := fx.w.log(); len(rot) != 2 {
		t.Fatalf("not one attempt at the unlock: %v", rot)
	}
	fx.restart() // its attempt succeeds and leaves the state at the second write
	if fx.pending() != nil || fx.statusRefused() {
		t.Fatal("still refused after a successful attempt")
	}
}

// statusRefused reports whether vault.status to the app carries relay
// "refused".
func (fx *rotFx) statusRefused() bool {
	fx.t.Helper()
	_ = fx.responses(fx.t)
	if err := fx.send("vault.status", []byte(`{}`)); err != nil {
		fx.t.Fatal(err)
	}
	for _, in := range fx.responses(fx.t) {
		if in.Type == "vault.status" {
			var b struct {
				Relay string `json:"relay"`
			}
			_ = json.Unmarshal(in.Body, &b)
			return b.Relay == "refused"
		}
	}
	fx.t.Fatal("no vault.status answer")
	return false
}

// RK14 step 1 "When it is cleared": the anchor stored for an attempt that
// the relay refused with its own 400 bad_request or 401 signature_invalid
// is cleared in the refused state's write; any other refusal keeps it,
// and so does a later 400 once kept.
func TestRelayRotAnchorClearedOnlyByTheRelaysOwnRefusal(t *testing.T) {
	cases := []struct {
		err   error
		clear bool
	}{
		{relayErr(400, "bad_request"), true},
		{relayErr(401, "signature_invalid"), true},
		{relayErr(400, "http_400"), false}, // no error body: a proxy
		{relayErr(403, "forbidden"), false},
		{relayErr(401, "bad_request"), false},
	}
	for _, c := range cases {
		fx := newRotFx(t)
		fx.w.rotate = []error{c.err}
		if err := fx.credRotate(); err != nil {
			t.Fatal(err)
		}
		if pr := fx.pending(); pr == nil || pr.Refused == "" {
			t.Fatalf("%v: not refused", c.err)
		}
		if a := fx.m.RelayKeyStatus().Anchor; a.IsZero() != c.clear {
			t.Fatalf("%v: anchor %v", c.err, a)
		}
		fx.m.Crash() // stored with the refused state: read without a start
		m, _, err := fx.unlock(testPIN, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		fx.m = m
		if a := fx.m.RelayKeyStatus().Anchor; c.clear && !a.IsZero() || !c.clear && a.IsZero() {
			t.Fatalf("%v: stored anchor %v", c.err, a)
		}
	}
	// Once kept, a later 400 does not clear it.
	fx := newRotFx(t)
	fx.w.rotate = []error{relayErr(503, ""), relayErr(400, "bad_request")}
	if err := fx.credRotate(); err != nil {
		t.Fatal(err)
	}
	a0 := fx.m.RelayKeyStatus().Anchor
	fx.clk = fx.clk.Add(2 * time.Minute)
	fx.batch()
	if pr := fx.pending(); pr == nil || pr.Refused == "" || !fx.m.RelayKeyStatus().Anchor.Equal(a0) {
		t.Fatalf("a later 400 cleared the kept anchor: %+v", fx.m.RelayKeyStatus())
	}
}

// After the grace the rotate is answered mailbox_unknown and the stored
// pending key is registered: a 200 continues with step 3; a 201 (a fresh
// mailbox) re-mints every held token with iat at that time, not
// backdated.
func TestRelayRotAfterTheGraceRegisters(t *testing.T) {
	for _, fresh := range []bool{false, true} {
		fx := newRotFx(t)
		fx.w.rotate = []error{relayErr(503, "")}
		if err := fx.credRotate(); err != nil {
			t.Fatal(err)
		}
		pmb := fx.pendingMailbox()
		held := fx.pending().Held["c1"].Standing
		fx.w.mu.Lock()
		delete(fx.w.live, fx.mailbox()) // the grace ended
		if !fresh {
			fx.w.live[pmb] = true // an earlier rotate made it
		}
		fx.w.mu.Unlock()
		fx.clk = fx.clk.Add(2 * time.Minute)
		fx.batch()
		_, regs := fx.w.log()
		if fx.mailbox() != pmb || regs[len(regs)-1] != pmb {
			t.Fatalf("fresh %v: mailbox %s, registers %v", fresh, fx.mailbox(), regs)
		}
		fx.do(func(m *Manager) {
			tok := m.st.Relay.Recipients["c1"].Standing
			if (tok != held) != fresh {
				t.Fatalf("fresh %v: held token re-minted %v", fresh, tok != held)
			}
			if fresh {
				c, err := parseOwnToken(m, tok)
				if err != nil || !c.Iat.Equal(fx.clk.Truncate(time.Second)) {
					t.Fatalf("fresh token iat %v (now %v) %v", c.Iat, fx.clk, err)
				}
			}
		})
	}
}

// A definite refusal of the registration puts the key in the refused
// state; the anchor stays (it was not the rotate that was refused).
func TestRelayRotRegistrationRefused(t *testing.T) {
	fx := newRotFx(t)
	fx.w.mu.Lock()
	delete(fx.w.live, fx.mailbox())
	fx.w.register = []error{relayErr(400, "bad_request")}
	fx.w.mu.Unlock()
	if err := fx.credRotate(); err != nil {
		t.Fatal(err)
	}
	if pr := fx.pending(); pr == nil || pr.Refused != "bad_request" || fx.m.RelayKeyStatus().Anchor.IsZero() {
		t.Fatalf("pending %+v, anchor %v", pr, fx.m.RelayKeyStatus().Anchor)
	}
}

// The collect loop's mailbox_unknown on the current mailbox starts the
// rotate, then the registration, while a key is pending and not refused.
func TestRelayRotMailboxUnknownStartsTheRotate(t *testing.T) {
	fx := newRotFx(t)
	fx.w.rotate = []error{relayErr(503, "")}
	if err := fx.credRotate(); err != nil {
		t.Fatal(err)
	}
	pmb := fx.pendingMailbox()
	fx.w.mu.Lock()
	delete(fx.w.live, fx.mailbox())
	fx.w.mu.Unlock()
	fx.clk = fx.clk.Add(2 * time.Minute)
	if err := fx.m.relayMailboxUnknown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fx.mailbox() != pmb {
		t.Fatal("mailbox_unknown did not complete the pending key")
	}
}

// The refused state's attempt is one per unlock, and its refusal is
// audited once in that unlock (not again as a key left pending).
func TestRelayRotRefusedOneAttemptAndOneAuditPerUnlock(t *testing.T) {
	fx := newRotFx(t)
	fx.w.rotate = []error{relayErr(403, "forbidden"), relayErr(403, "forbidden")}
	if err := fx.credRotate(); err != nil {
		t.Fatal(err)
	}
	fx.restart()
	if rot, _ := fx.w.log(); len(rot) != 2 || len(fx.acts("identity.rotation_failed")) != 2 {
		t.Fatalf("rotates %v, audits %d", rot, len(fx.acts("identity.rotation_failed")))
	}
	fx.do(func(m *Manager) { m.relayKeyStep(context.Background(), true) })
	if rot, _ := fx.w.log(); len(rot) != 2 {
		t.Fatalf("a second attempt in one unlock: %v", rot)
	}
}

// Only the key left pending is audited: when the unlock completes it and
// the next key it stored gets no answer, nothing is audited.
func TestRelayRotNextKeyNotAuditedAsLeftPending(t *testing.T) {
	fx := newRotFx(t)
	fx.w.rotate = []error{relayErr(503, "")}
	if err := fx.credRotate(); err != nil {
		t.Fatal(err)
	}
	if err := fx.m.RotateIdentity(context.Background()); err != nil {
		t.Fatal(err)
	}
	fx.w.rotate = []error{nil, relayErr(503, "")}
	fx.restart()
	if fx.pending() == nil || len(fx.m.RelayKeyStatus().OldMailboxes) != 1 || len(fx.acts("identity.rotation_failed")) != 0 {
		t.Fatalf("status %+v, audits %d", fx.m.RelayKeyStatus(), len(fx.acts("identity.rotation_failed")))
	}
}
