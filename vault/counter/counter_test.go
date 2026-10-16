package counter_test

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/countertest"
	"github.com/vettid/vettid-vault/vault/counter"
	"github.com/vettid/vettid-vault/vms/recovery"
)

const (
	unit  = 10 * time.Minute // staging's unit
	quiet = 72 * time.Hour
)

var t0 = time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)

func setup(t *testing.T) (*countertest.Bucket, *counter.Counter) {
	t.Helper()
	b := countertest.New(t0)
	n, err := recovery.NewNames(bytes.Repeat([]byte{0x51}, 32), "test-vault-0001")
	if err != nil {
		t.Fatal(err)
	}
	return b, counter.New(b, n, unit)
}

func present(t *testing.T, b *countertest.Bucket, c *counter.Counter) {
	t.Helper()
	if _, err := c.MarkPresent(context.Background()); err != nil {
		t.Fatal(err)
	}
	b.Advance(quiet + time.Minute)
}

// spendAndJudge is steps 3 to 4b of an open, from one counter.
func spendAndJudge(t *testing.T, c *counter.Counter, g uint64) (counter.SpendResult, string) {
	t.Helper()
	ctx := context.Background()
	v, err := c.Status(ctx, g)
	if err != nil {
		t.Fatal(err)
	}
	if vd, _ := counter.FirstLook(v, quiet); vd != counter.VerdictTest {
		return counter.SpendResult{Outcome: vd}, vd
	}
	r := c.Spend(ctx, g, v.Next())
	if r.Outcome != counter.Spent {
		return r, r.Outcome
	}
	cv, err := c.Confirm(ctx, g)
	if err != nil {
		t.Fatal(err)
	}
	vd, _ := counter.AfterSpend(cv, v.Next(), r.At, v.Now, quiet, unit)
	return r, vd
}

func TestScheduleOfWaits(t *testing.T) {
	b, c := setup(t)
	present(t, b, c)
	ctx := context.Background()
	for k := 1; k <= 10; k++ {
		r, vd := spendAndJudge(t, c, 1)
		if vd != counter.VerdictTest {
			t.Fatalf("attempt %d: %s", k, vd)
		}
		if r.Used != k {
			t.Fatalf("attempt %d used %d", k, r.Used)
		}
		w := time.Duration(recovery.WaitUnits(k)) * unit
		if !r.WaitUntil.Equal(r.At.Add(w)) {
			t.Fatalf("attempt %d wait until %v", k, r.WaitUntil)
		}
		if k == 10 {
			break
		}
		if w > 0 {
			// Before the wait ends: wait, nothing used.
			b.Advance(w - time.Second)
			v, _ := c.Status(ctx, 1)
			if vd, at := counter.FirstLook(v, quiet); vd != counter.VerdictWait || !at.Equal(r.WaitUntil) {
				t.Fatalf("after attempt %d: %s %v", k, vd, at)
			}
			if got := c.Spend(ctx, 1, k+1); got.Outcome != counter.Wait {
				t.Fatalf("spend during the wait: %s", got.Outcome)
			}
			b.Advance(time.Second)
		}
	}
	v, _ := c.Status(ctx, 1)
	if !v.Exhausted() || len(v.Attempts) != 10 {
		t.Fatalf("not exhausted: %+v", v)
	}
	if vd, _ := counter.FirstLook(v, quiet); vd != counter.VerdictExhaus {
		t.Fatal(vd)
	}
	if r := c.Spend(ctx, 1, 11); r.Outcome != counter.Exhausted {
		t.Fatal(r.Outcome)
	}
}

func TestManyEnclavesOneAttempt(t *testing.T) {
	b, c := setup(t)
	present(t, b, c)
	ctx := context.Background()
	v, _ := c.Status(ctx, 1)
	var wg sync.WaitGroup
	out := make([]string, 8)
	for i := range out {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			out[i] = counter.New(b, c.Names(), unit).Spend(ctx, 1, v.Next()).Outcome
		}(i)
	}
	wg.Wait()
	spent := 0
	for _, o := range out {
		if o == counter.Spent {
			spent++
		} else if o != counter.Wait && o != counter.Lost {
			t.Fatalf("outcome %s", o)
		}
	}
	if spent != 1 {
		t.Fatalf("%d callers were answered spent for one attempt", spent)
	}
}

func TestDeleteMarkerNeverYieldsATest(t *testing.T) {
	b, c := setup(t)
	present(t, b, c)
	ctx := context.Background()
	if _, vd := spendAndJudge(t, c, 1); vd != counter.VerdictTest {
		t.Fatal(vd)
	}
	// The host puts a delete marker on token 1; a conditional create then
	// succeeds over it, but the listing after the write shows three
	// entries: lost, never spent.
	b.AddDeleteMarker(c.Names().Token(1, 1))
	if r := c.Spend(ctx, 1, 1); r.Outcome == counter.Spent {
		t.Fatal("a re-created token was answered spent")
	}
	v, _ := c.Status(ctx, 1)
	if v.Next() != 2 {
		t.Fatalf("next %d", v.Next())
	}
}

func TestStoredWriteAnsweredWithAnError(t *testing.T) {
	b, c := setup(t)
	present(t, b, c)
	b.StoreThenFail(countertest.OpPutCreate, 1)
	r, vd := spendAndJudge(t, c, 1)
	if r.Outcome != counter.Spent || vd != counter.VerdictTest {
		t.Fatalf("%s %s: the body read back proves the token mine", r.Outcome, vd)
	}
	if b.Calls(countertest.OpGetVersion) != 1 {
		t.Fatal("no read of the body")
	}
}

func TestFailuresFallOnTheSafeSide(t *testing.T) {
	ctx := context.Background()
	b, c := setup(t)
	present(t, b, c)
	b.FailNext(countertest.OpList, 1)
	if r := c.Spend(ctx, 1, 1); r.Outcome != counter.Unavailable {
		t.Fatal(r.Outcome)
	}
	if v, _ := c.Status(ctx, 1); v.Used != 0 {
		t.Fatal("an unavailable spend used an attempt")
	}
	b.FailNext(countertest.OpGetRetention, 1)
	if r := c.Spend(ctx, 1, 1); r.Outcome != counter.Lost {
		t.Fatal(r.Outcome)
	}
	if v, _ := c.Status(ctx, 1); v.Used != 1 {
		t.Fatal("a lost attempt not counted")
	}
	b.FailNext(countertest.OpPutCreate, 1) // unknown outcome, nothing stored
	if r := c.Spend(ctx, 1, 2); r.Outcome != counter.Lost {
		t.Fatal(r.Outcome)
	}
	b.SetDown(true)
	if _, err := c.Status(ctx, 1); err == nil {
		t.Fatal("status while down")
	}
	if _, err := c.MarkPresent(ctx); err == nil {
		t.Fatal("present while down")
	}
	if err := c.Close(ctx, 1); err == nil {
		t.Fatal("close while down")
	}
}

func TestCloseIsFinal(t *testing.T) {
	ctx := context.Background()
	b, c := setup(t)
	present(t, b, c)
	v, _ := c.Status(ctx, 1)
	// A caller looked before the close and spends after it: Confirm sees
	// the close and nothing is tested (G4).
	if err := c.Close(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(ctx, 1); err != nil {
		t.Fatal("close repeated", err)
	}
	if r := c.Spend(ctx, 1, v.Next()); r.Outcome != counter.Closed {
		t.Fatal(r.Outcome)
	}
	cv, _ := c.Confirm(ctx, 1)
	if vd, _ := counter.AfterSpend(cv, 1, b.Now(), v.Now, quiet, unit); vd != counter.VerdictClosed {
		t.Fatal(vd)
	}
}

func TestQuietPeriodAndPresence(t *testing.T) {
	ctx := context.Background()
	b, c := setup(t)
	v, _ := c.Status(ctx, 1)
	if vd, _ := counter.FirstLook(v, quiet); vd != counter.VerdictQuiet {
		t.Fatal("no present record must be refused")
	}
	at, err := c.MarkPresent(ctx)
	if err != nil || !at.Equal(t0) {
		t.Fatal(at, err)
	}
	// An older version inserted later does not make the member look
	// absent: the newest time is taken.
	b.InsertVersion(c.Names().Present(), t0.Add(-100*time.Hour), t0.Add(time.Hour))
	b.Advance(quiet - time.Minute)
	v, _ = c.Status(ctx, 1)
	if vd, r := counter.FirstLook(v, quiet); vd != counter.VerdictQuiet || !r.Equal(t0.Add(quiet)) {
		t.Fatal(vd, r)
	}
	// Presence written between a spend and its confirming read: the
	// attempt is used and not tested.
	b.Advance(2 * time.Minute)
	v, _ = c.Status(ctx, 1)
	r := c.Spend(ctx, 1, 1)
	if r.Outcome != counter.Spent {
		t.Fatal(r.Outcome)
	}
	if _, err := c.MarkPresent(ctx); err != nil {
		t.Fatal(err)
	}
	cv, _ := c.Confirm(ctx, 1)
	if vd, _ := counter.AfterSpend(cv, 1, r.At, v.Now, quiet, unit); vd != counter.VerdictQuiet {
		t.Fatal(vd)
	}
	// After 96 hours the present records' locks end and the host can
	// delete them: a vault with none is refused, never "never present".
	b.Advance(97 * time.Hour)
	b.DeleteUnlocked(c.Names().Present())
	v, _ = c.Status(ctx, 1)
	if !v.PresentAt.IsZero() {
		t.Fatal("unlocked present records survived")
	}
	if vd, _ := counter.FirstLook(v, quiet); vd != counter.VerdictQuiet {
		t.Fatal(vd)
	}
}

func TestHeldAnswers(t *testing.T) {
	ctx := context.Background()
	b, c := setup(t)
	present(t, b, c)
	// A spend answer held for more than 10 minutes: not tested.
	v, _ := c.Status(ctx, 1)
	r := c.Spend(ctx, 1, 1)
	b.Advance(11 * time.Minute)
	cv, _ := c.Confirm(ctx, 1)
	if vd, _ := counter.AfterSpend(cv, 1, r.At, v.Now, quiet, unit); vd == counter.VerdictTest {
		t.Fatal("tested after a held answer")
	}
	// A status held back for more than 10 minutes before the spend.
	v, _ = c.Status(ctx, 1)
	b.Advance(11 * time.Minute)
	r = c.Spend(ctx, 1, 2)
	cv, _ = c.Confirm(ctx, 1)
	if vd, _ := counter.AfterSpend(cv, 2, r.At, v.Now, quiet, unit); vd == counter.VerdictTest {
		t.Fatal("tested after a held status")
	}
	// A late confirming read within 10 minutes tests the attempt, and a
	// second attempt is never tested without its wait.
	b.Advance(time.Hour)
	v, _ = c.Status(ctx, 1)
	r = c.Spend(ctx, 1, 3)
	if r.Outcome != counter.Spent {
		t.Fatal(r.Outcome)
	}
	b.Advance(9 * time.Minute)
	cv, _ = c.Confirm(ctx, 1)
	if vd, _ := counter.AfterSpend(cv, 3, r.At, v.Now, quiet, unit); vd != counter.VerdictTest {
		t.Fatal(vd)
	}
	if r4 := c.Spend(ctx, 1, 4); r4.Outcome != counter.Wait {
		t.Fatal(r4.Outcome)
	}
}

func TestSuccessEndsItsWait(t *testing.T) {
	ctx := context.Background()
	b, c := setup(t)
	present(t, b, c)
	for k := 1; k <= 2; k++ {
		spendAndJudge(t, c, 1)
	}
	v, _ := c.Status(ctx, 1)
	if v.WaitUntil.IsZero() {
		t.Fatal("no wait after attempt 2")
	}
	if err := c.Succeed(ctx, 1, 2); err != nil {
		t.Fatal(err)
	}
	v, _ = c.Status(ctx, 1)
	if !v.WaitUntil.IsZero() || !v.Attempts[1].Success {
		t.Fatalf("success did not end its wait: %+v", v)
	}
	// The ten are for the life of the pair: a success gives none back.
	if v.Used != 2 || v.Next() != 3 {
		t.Fatal(v.Used)
	}
}

func TestNotBefore(t *testing.T) {
	ctx := context.Background()
	b, c := setup(t)
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC) // the enclave's clock, never compared with S3's
	nb, est := counter.NotBefore(now, nil, quiet, 24*time.Hour)
	if !est || !nb.Equal(now.Add(quiet)) {
		t.Fatal(nb, est)
	}
	if _, err := c.MarkPresent(ctx); err != nil {
		t.Fatal(err)
	}
	b.Advance(10 * time.Hour)
	v, _ := c.Status(ctx, 1)
	if nb, est := counter.NotBefore(now, v, quiet, 24*time.Hour); est || !nb.Equal(now.Add(62*time.Hour)) {
		t.Fatal(nb)
	}
	b.Advance(100 * time.Hour)
	v, _ = c.Status(ctx, 1)
	if nb, _ := counter.NotBefore(now, v, quiet, 24*time.Hour); !nb.Equal(now.Add(24 * time.Hour)) {
		t.Fatal(nb)
	}
}

// G5 (§11.14.4): the present lock exceeds the quiet period plus the
// 10-minute window, also for a longer quiet period.
func TestPresentLockCoversQuiet(t *testing.T) {
	b, c := setup(t)
	c.WithQuiet(90 * time.Hour)
	if _, err := c.MarkPresent(context.Background()); err != nil {
		t.Fatal(err)
	}
	b.Advance(90*time.Hour + counter.ConfirmWindow + time.Minute)
	b.DeleteUnlocked(c.Names().Present())
	v, _ := c.Status(context.Background(), 1)
	if v.PresentAt.IsZero() {
		t.Fatal("a present record younger than quiet + 10 min was deletable")
	}
}
