package vault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/countertest"
	"github.com/vettid/vettid-vault/vault/counter"
)

// The counter's record at a completed recovery (VAULT-MESSAGING §11.14.11,
// "The record a host cannot drop"): the completion reads the counter's
// status after its state is stored and writes recovery.attempt for each
// attempt, and recovery.attempts_used, once; the next owner check adds
// nothing it already wrote; a completion that fails writes nothing.

// attemptRefs is the refs of the sink's recovery.attempt and
// recovery.attempts_used activities, in order.
func attemptRefs(s *recSink) (attempts, used []string) {
	for _, a := range s.got {
		switch a.Kind {
		case "recovery.attempt":
			attempts = append(attempts, a.Ref)
		case "recovery.attempts_used":
			used = append(used, a.Ref)
		}
	}
	return attempts, used
}

func sameRefs(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// ownerCheckAttempts runs the recovery part of a passed owner check on m.
func ownerCheckAttempts(m *Manager) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ownerCheckRecovery(context.Background(), testPIN, []byte(rPW), 0, true, m.now())
}

func flushManager(t *testing.T, m *Manager) {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.flushIfDirty(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestRecoveryOpenWritesTheCounterRecord(t *testing.T) {
	f := newOpenFixture(t)
	sink := &recSink{}
	f.opts.Features = append(f.opts.Features, sink)
	if m, out := f.open(testPIN, "wrong password one"); m != nil || out.Code != OpenWrong || out.Used != 1 {
		t.Fatalf("wrong: %+v", out)
	}
	if a, u := attemptRefs(sink); len(a)+len(u) != 0 {
		t.Fatalf("a wrong pair wrote the record: %v %v", a, u)
	}
	m, out := f.open(testPIN, rPW)
	if m == nil || !out.OK || out.Used != 2 {
		t.Fatalf("right pair: %+v", out)
	}
	want := []string{"1/1/not_success/counter", "1/2/success/counter"}
	a, u := attemptRefs(sink)
	if !sameRefs(a, want) || !sameRefs(u, []string{"1/2"}) {
		t.Fatalf("at the completion: attempts %v, used %v", a, u)
	}
	for _, x := range sink.got {
		if x.Kind == "recovery.attempt" && (x.Priority != "" || !x.Audit || !x.Feed) {
			t.Fatalf("attempt in the recovered generation: %+v", x)
		}
	}
	// Stored with the next flush: the recovered phone's next owner check
	// adds nothing.
	flushManager(t, m)
	if err := m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.clock = f.clock.Add(time.Hour)
	m2 := f.mustUnlock(testPIN, f.phoneUS)
	defer m2.Crash()
	ownerCheckAttempts(m2)
	if a, u := attemptRefs(sink); !sameRefs(a, want) || !sameRefs(u, []string{"1/2"}) {
		t.Fatalf("after the owner check: attempts %v, used %v", a, u)
	}
}

// A completion that fails at its state write writes no record; the resume
// through the `next` wrap (no new attempt) writes it once, with the success.
func TestRecoveryOpenFailedCompletionWritesNoRecord(t *testing.T) {
	f := newOpenFixture(t)
	sink := &recSink{}
	f.opts.Features = append(f.opts.Features, sink)
	f.st.failState = 1
	if m, out := f.open(testPIN, rPW); m != nil || out.OK || out.Code != OpenRetry || !out.Counted {
		t.Fatalf("failed completion: %+v", out)
	}
	if a, u := attemptRefs(sink); len(a)+len(u) != 0 {
		t.Fatalf("a failed completion wrote the record: %v %v", a, u)
	}
	m, out := f.open(testPIN, rPW)
	if m == nil || !out.OK || out.Counted {
		t.Fatalf("resume: %+v", out)
	}
	want := []string{"1/1/success/counter"}
	a, u := attemptRefs(sink)
	if !sameRefs(a, want) || !sameRefs(u, []string{"1/1"}) {
		t.Fatalf("at the resume: attempts %v, used %v", a, u)
	}
	for _, x := range sink.got {
		if x.Kind == "recovery.attempt" && x.Priority != "" {
			t.Fatalf("attempt in the recovered generation: %+v", x)
		}
	}
	flushManager(t, m)
	ownerCheckAttempts(m)
	if a, u := attemptRefs(sink); !sameRefs(a, want) || !sameRefs(u, []string{"1/1"}) {
		t.Fatalf("after the owner check: attempts %v, used %v", a, u)
	}
	m.Crash()
}

// A completion whose step-3 header write fails: its state (step 2) is
// stored but the run answers retry and writes no record; the repeat after
// step 2 writes it once.
func TestRecoveryOpenPartialCompletionWritesNoRecord(t *testing.T) {
	f := newOpenFixture(t)
	sink := &recSink{}
	f.opts.Features = append(f.opts.Features, sink)
	f.st.passHeader, f.st.failHeader = 1, 1
	if m, out := f.open(testPIN, rPW); m != nil || out.Code != OpenRetry || !out.Counted {
		t.Fatalf("failed step 3: %+v", out)
	}
	if a, u := attemptRefs(sink); len(a)+len(u) != 0 {
		t.Fatalf("a partial completion wrote the record: %v %v", a, u)
	}
	m, out := f.open(testPIN, rPW)
	if m == nil || !out.OK || out.Counted {
		t.Fatalf("repeat: %+v", out)
	}
	defer m.Crash()
	if a, u := attemptRefs(sink); !sameRefs(a, []string{"1/1/success/counter"}) || !sameRefs(u, []string{"1/1"}) {
		t.Fatalf("at the repeat: attempts %v, used %v", a, u)
	}
}

// openAs runs a recovery open from another phone under recovery id id.
func (f *openFixture) openAs(id string, phone ed25519.PrivateKey, us []byte, pin, pw string) (*Manager, *RecoveryOpenOutcome) {
	return RecoveryOpen(context.Background(), RecoveryOpenParams{Options: f.opts, VaultID: f.vid, UserGUID: "u1", RecoveryID: id,
		DeviceIK: phone.Public().(ed25519.PublicKey), PIN: pin, Password: []byte(pw), UnlockSecret: us,
		VerifyDevice: func(*RecoveryApp) (json.RawMessage, error) { return json.RawMessage(`{}`), nil },
		Manifest: func(uint64) (*ManifestView, error) {
			return &ManifestView{Serial: 1, Own: ReleaseEntry{PCR0: testRelease.PCR0, Number: testRelease.Number}}, nil
		}})
}

// attemptPriorities maps each recovery.attempt ref to its priority.
func attemptPriorities(s *recSink) map[string]string {
	p := map[string]string{}
	for _, a := range s.got {
		if a.Kind == "recovery.attempt" {
			p[a.Ref] = a.Priority
		}
	}
	return p
}

// "urgent unless the member completed a recovery in that generation since"
// (§11.14.11): after the member's recovery with attempt 1 the vault stays
// armed in generation 1; a later recovery by someone else spends attempt 2
// in it, and the member's next owner check audits that one as urgent.
func TestLaterAttemptInTheRecoveredGenerationIsUrgent(t *testing.T) {
	f := newOpenFixture(t)
	sink := &recSink{}
	f.opts.Features = append(f.opts.Features, sink)
	m, out := f.open(testPIN, rPW)
	if m == nil || !out.OK || out.Used != 1 {
		t.Fatalf("member's recovery: %+v", out)
	}
	flushManager(t, m)
	if err := m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	if p := attemptPriorities(sink); len(p) != 1 || p["1/1/success/counter"] != "" {
		t.Fatalf("member's attempt: %v", p)
	}
	if h := f.storedHeader(); h.Rec.Wrap == nil || h.Rec.Generation != 1 {
		t.Fatalf("not armed in generation 1: %+v", h.Rec)
	}
	// Someone else, after the quiet period, from another phone.
	f.clock = f.clock.Add(73 * time.Hour)
	f.bucket.Advance(73 * time.Hour)
	p := HeaderParams{Options: f.opts, VaultID: f.vid, UserGUID: "u1"}
	if err := headerTx(context.Background(), p, func(h *Header, _ time.Time) (bool, error) {
		h.HasCredential = true
		yes := true
		h.CredentialBackup = &yes
		return false, nil
	}); err != nil {
		t.Fatal(err)
	}
	const id2 = "rec-other"
	code, _, _, err := RecoveryRequest(context.Background(), p, id2, RecoveryDelay)
	if err != nil {
		t.Fatal(err)
	}
	f.clock = f.clock.Add(25 * time.Hour)
	f.bucket.Advance(25 * time.Hour)
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x62}, 32))
	app := RecoveryApp{IK: other.Public().(ed25519.PublicKey), KEM: bytes.Repeat([]byte{3}, 32), RelayPK: bytes.Repeat([]byte{4}, 32)}
	if err := RecoveryRegister(context.Background(), p, id2, code, app, ok); err != nil {
		t.Fatal(err)
	}
	if m, out := f.openAs(id2, other, bytes.Repeat([]byte{0x78}, 32), "000000", rPW); m != nil || out.Code != OpenWrong || out.Used != 2 {
		t.Fatalf("other's attempt: %+v", out)
	}
	// The member's next owner check.
	m2 := f.mustUnlock(testPIN, f.phoneUS)
	defer m2.Crash()
	ownerCheckAttempts(m2)
	pr := attemptPriorities(sink)
	if pri, seen := pr["1/2/not_success/counter"]; !seen || pri != "urgent" {
		t.Fatalf("the later attempt: %v", pr)
	}
	if len(pr) != 2 || pr["1/1/success/counter"] != "" {
		t.Fatalf("attempts: %v", pr)
	}
}

// The urgency rule on its own: attempts of the recovered generation up to
// the recovered attempt are not urgent, every other one is; a state with
// only the old recovered_generation (no attempt) fails toward urgent.
func TestRecordAttemptsUrgency(t *testing.T) {
	f := newRFixture(t)
	sink := &recSink{}
	f.m.features = append(f.m.features, sink)
	view := func(g uint64, n int) *counter.View {
		v := &counter.View{Generation: g, Used: n}
		for i := 1; i <= n; i++ {
			v.Attempts = append(v.Attempts, counter.Attempt{N: i, Success: i == 2})
		}
		return v
	}
	f.m.mu.Lock()
	defer f.m.mu.Unlock()
	now := f.m.now()
	// Old state: recovered_generation alone.
	f.m.st.RecoveredGeneration = 5
	f.m.recordAttempts(view(5, 1), now)
	if p := attemptPriorities(sink); p["5/1/not_success/counter"] != "urgent" {
		t.Fatalf("old state: %v", p)
	}
	f.m.st.RecoveredAttempt = []uint64{7, 2}
	f.m.recordAttempts(view(7, 3), now)
	f.m.recordAttempts(view(8, 1), now)
	want := map[string]string{"5/1/not_success/counter": "urgent", "7/1/not_success/counter": "", "7/2/success/counter": "",
		"7/3/not_success/counter": "urgent", "8/1/not_success/counter": "urgent"}
	if p := attemptPriorities(sink); len(p) != len(want) {
		t.Fatalf("got %v", p)
	} else {
		for k, v := range want {
			if pri, seen := p[k]; !seen || pri != v {
				t.Fatalf("%s: got %q (%v)", k, pri, p)
			}
		}
	}
}

// failSucceed makes the counter's next n Succeed writes for (g, k) fail.
func (f *openFixture) failSucceed(g uint64, k, n int) {
	name := f.m.counter().Names().Success(g, k)
	left := n
	f.bucket.SetHook(func(op, key string) {
		if op == countertest.OpPutCreate && key == name && left > 0 {
			left--
			f.bucket.FailNext(op, 1)
		}
	})
}

// The first run's Succeed fails three times and its state write fails, so
// its PendingSucceed is lost; the repeat through the `next` wrap sends the
// success again from the header's `next` part, and the record shows it.
func TestResumeSendsTheLostSucceed(t *testing.T) {
	f := newOpenFixture(t)
	sink := &recSink{}
	f.opts.Features = append(f.opts.Features, sink)
	f.failSucceed(1, 1, 3)
	f.st.failState = 1
	if m, out := f.open(testPIN, rPW); m != nil || out.Code != OpenRetry || !out.Counted {
		t.Fatalf("failed completion: %+v", out)
	}
	if v, _ := f.m.counter().Status(context.Background(), 1); v.Used != 1 || v.Attempts[0].Success {
		t.Fatalf("Succeed was not meant to land: %+v", v)
	}
	m, out := f.open(testPIN, rPW)
	if m == nil || !out.OK || out.Counted {
		t.Fatalf("resume: %+v", out)
	}
	defer m.Crash()
	if v, _ := f.m.counter().Status(context.Background(), 1); !v.Attempts[0].Success {
		t.Fatalf("the success was not sent again: %+v", v)
	}
	if len(m.st.PendingSucceed) != 0 {
		t.Fatalf("still pending: %v", m.st.PendingSucceed)
	}
	if p := attemptPriorities(sink); len(p) != 1 || p["1/1/success/counter"] != "" {
		t.Fatalf("record: %v", p)
	}
}

// A counter error at the completion's status read: the open still answers
// ok, writes no record, and the next owner check writes it.
func TestCompletionStatusErrorStillOK(t *testing.T) {
	f := newOpenFixture(t)
	sink := &recSink{}
	f.opts.Features = append(f.opts.Features, sink)
	present := f.m.counter().Names().Present()
	after := false
	f.bucket.SetHook(func(op, key string) {
		if after {
			f.bucket.SetDown(true)
		}
		if op == countertest.OpPut && key == present {
			after = true // the presence is the completion's last write before the read
		}
	})
	m, out := f.open(testPIN, rPW)
	if m == nil || !out.OK {
		t.Fatalf("open: %+v", out)
	}
	defer m.Crash()
	if a, u := attemptRefs(sink); len(a)+len(u) != 0 {
		t.Fatalf("a failed status read wrote the record: %v %v", a, u)
	}
	f.bucket.SetHook(nil)
	f.bucket.SetDown(false)
	ownerCheckAttempts(m)
	if a, u := attemptRefs(sink); !sameRefs(a, []string{"1/1/success/counter"}) || !sameRefs(u, []string{"1/1"}) {
		t.Fatalf("after the owner check: %v %v", a, u)
	}
}

// A recovery whose tenth attempt is the right one: the completion's record
// sees all ten used and disarms (change_required).
func TestTenthAttemptCompletionDisarms(t *testing.T) {
	f := newOpenFixture(t)
	sink := &recSink{}
	f.opts.Features = append(f.opts.Features, sink)
	used := 0
	for i := 1; used < 9; i++ {
		m, out := f.open(testPIN, fmt.Sprintf("wrong password %d", used+1))
		if m != nil {
			t.Fatal("opened with a wrong pair")
		}
		switch {
		case out.Code == OpenWrong:
			used = out.Used
		case out.Code == OpenWait:
			f.bucket.Advance(out.RetryAt.Sub(f.bucket.Now()) + time.Second)
		default:
			t.Fatalf("attempt %d: %+v", used+1, out)
		}
		if i > 40 {
			t.Fatal("too many tries")
		}
	}
	var m *Manager
	var out *RecoveryOpenOutcome
	for i := 0; ; i++ {
		m, out = f.open(testPIN, rPW)
		if out.Code != OpenWait || i > 2 {
			break
		}
		f.bucket.Advance(out.RetryAt.Sub(f.bucket.Now()) + time.Second)
	}
	if m == nil || !out.OK || out.Used != 10 {
		t.Fatalf("tenth: %+v", out)
	}
	defer m.Crash()
	if !m.hdr.Rec.ChangeRequired || m.hdr.Rec.Wrap != nil {
		t.Fatalf("not disarmed: %+v", m.hdr.Rec)
	}
	a, u := attemptRefs(sink)
	if len(a) != 10 || a[9] != "1/10/success/counter" || !sameRefs(u, []string{"1/10"}) {
		t.Fatalf("record: %v %v", a, u)
	}
}
