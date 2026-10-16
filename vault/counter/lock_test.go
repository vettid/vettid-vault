package counter_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/countertest"
	"github.com/vettid/vettid-vault/vault/counter"
	"github.com/vettid/vettid-vault/vms/recovery"
)

// The channels' lock periods of token, success and close records
// (VAULT-MESSAGING 0.33.2 §11.14.4): production 100 years, staging a day.
var channels = []struct {
	name   string
	period time.Duration
}{
	{"production", 100 * 365 * 24 * time.Hour},
	{"staging", 24 * time.Hour},
}

func channelCounter(t *testing.T, period, u time.Duration) (*countertest.Bucket, *counter.Counter) {
	t.Helper()
	b := countertest.New(t0)
	n, err := recovery.NewNames(bytes.Repeat([]byte{0x52}, 32), "test-vault-0002")
	if err != nil {
		t.Fatal(err)
	}
	c := counter.New(b, n, u)
	if period > 0 {
		c.WithRecordLock(period)
	}
	return b, c
}

// lockOf reads back the lock of the only version of name.
func lockOf(t *testing.T, b *countertest.Bucket, name string) (time.Time, time.Time) {
	t.Helper()
	ctx := context.Background()
	l, err := b.List(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Entries) != 1 {
		t.Fatalf("%s: %d entries", name, len(l.Entries))
	}
	r, err := b.GetRetention(ctx, name, l.Entries[0].VersionID)
	if err != nil || r.Mode != counter.ModeCompliance {
		t.Fatalf("%s: %+v %v", name, r, err)
	}
	return l.Entries[0].LastModified, r.Until
}

// A counter given no period locks for production's 100 years.
func TestRecordLockDefaultsToProduction(t *testing.T) {
	_, c := channelCounter(t, 0, unit)
	if c.RecordLock() != counter.LongLock || counter.LongLock != channels[0].period {
		t.Fatalf("default record lock %v", c.RecordLock())
	}
	c.WithRecordLock(-time.Hour)
	if c.RecordLock() != counter.LongLock {
		t.Fatal("a negative period changed the lock")
	}
}

// Every record kind, on each channel: tokens the period or their wait
// plus a day if longer, success and close records the period, wait
// records until the wait's end, present records 96 hours.
func TestRecordLocksPerChannel(t *testing.T) {
	for _, ch := range channels {
		for _, u := range []time.Duration{10 * time.Minute, 24 * time.Hour} {
			t.Run(ch.name+"/"+u.String(), func(t *testing.T) {
				ctx := context.Background()
				b, c := channelCounter(t, ch.period, u)
				nm := c.Names()
				at, until := func() (time.Time, time.Time) {
					if _, err := c.MarkPresent(ctx); err != nil {
						t.Fatal(err)
					}
					return lockOf(t, b, nm.Present())
				}()
				if !until.Equal(at.Add(counter.PresentLock)) {
					t.Fatalf("present lock %v after %v", until, at)
				}
				b.Advance(quiet + time.Minute)
				for k := 1; k <= 3; k++ {
					v, err := c.Status(ctx, 1)
					if err != nil {
						t.Fatal(err)
					}
					if !v.WaitUntil.IsZero() {
						b.Advance(v.WaitUntil.Sub(v.Now))
						v, _ = c.Status(ctx, 1)
					}
					r := c.Spend(ctx, 1, k)
					if r.Outcome != counter.Spent {
						t.Fatalf("attempt %d: %s", k, r.Outcome)
					}
					w := time.Duration(recovery.WaitUnits(k)) * u
					tat, tuntil := lockOf(t, b, nm.Token(1, k))
					if want := v.Now.Add(max(ch.period, w+counter.TokenWaitMargin)); !tuntil.Equal(want) {
						t.Fatalf("token %d locked until %v, want %v", k, tuntil, want)
					}
					if tuntil.Before(tat.Add(w)) {
						t.Fatalf("token %d unlocks before its wait ends", k)
					}
					if w > 0 {
						wat, wuntil := lockOf(t, b, nm.Wait(1, k))
						if !wuntil.Equal(tat.Add(w)) || !wuntil.Equal(r.WaitUntil) {
							t.Fatalf("wait %d locked until %v (written %v)", k, wuntil, wat)
						}
					}
				}
				if err := c.Succeed(ctx, 1, 3); err != nil {
					t.Fatal(err)
				}
				sat, suntil := lockOf(t, b, nm.Success(1, 3))
				if !suntil.Equal(sat.Add(ch.period)) {
					t.Fatalf("success locked until %v, written %v", suntil, sat)
				}
				if err := c.Close(ctx, 1); err != nil {
					t.Fatal(err)
				}
				cat, cuntil := lockOf(t, b, nm.Close(1))
				if !cuntil.Equal(cat.Add(ch.period)) {
					t.Fatalf("close locked until %v, written %v", cuntil, cat)
				}
			})
		}
	}
}

// On staging, success and close records can be removed a day after they
// were written and not before; in production they cannot be removed for
// a century. Tokens outlive their waits on both.
func TestRecordsDeletableAfterThePeriod(t *testing.T) {
	for _, ch := range channels {
		t.Run(ch.name, func(t *testing.T) {
			ctx := context.Background()
			b, c := channelCounter(t, ch.period, unit)
			present(t, b, c)
			spendAndJudge(t, c, 1)
			if err := c.Succeed(ctx, 1, 1); err != nil {
				t.Fatal(err)
			}
			if err := c.Close(ctx, 1); err != nil {
				t.Fatal(err)
			}
			pre := c.Names().Prefix()
			b.Advance(24*time.Hour - time.Second)
			b.DeleteUnlocked(pre)
			if v, _ := c.Status(ctx, 1); !v.Closed || v.Used != 1 || !v.Attempts[0].Success {
				t.Fatalf("records removed within the day: %+v", v)
			}
			b.Advance(2 * time.Second)
			b.DeleteUnlocked(pre)
			v, _ := c.Status(ctx, 1)
			gone := !v.Closed && v.Used == 0
			if gone != (ch.name == "staging") {
				t.Fatalf("%s after a day: %+v", ch.name, v)
			}
		})
	}
}

// With a wait longer than the staging period (production's unit on a
// staging lock), the token cannot be removed while its wait runs, so the
// wait cannot be dropped by removing the attempt.
func TestTokenOutlivesItsWaitOnStaging(t *testing.T) {
	ctx := context.Background()
	day := 24 * time.Hour
	b, c := channelCounter(t, channels[1].period, day)
	present(t, b, c)
	for k := 1; k <= 3; k++ {
		v, _ := c.Status(ctx, 1)
		if !v.WaitUntil.IsZero() {
			b.Advance(v.WaitUntil.Sub(v.Now))
		}
		if r := c.Spend(ctx, 1, k); r.Outcome != counter.Spent {
			t.Fatalf("attempt %d: %s", k, r.Outcome)
		}
	}
	// Attempt 3's wait is two days: just before it ends, delete everything
	// unlocked. The older tokens' periods have passed (staging gives
	// those attempts back), but attempt 3 and its wait stay.
	b.Advance(2*day - time.Second)
	b.DeleteUnlocked(c.Names().Prefix())
	v, _ := c.Status(ctx, 1)
	if _, ok := v.Attempt(3); !ok || v.Next() != 4 || v.WaitUntil.IsZero() {
		t.Fatalf("the running wait was removed: %+v", v)
	}
	if r := c.Spend(ctx, 1, 4); r.Outcome != counter.Wait {
		t.Fatal(r.Outcome)
	}
}

// A token whose own time is more than TokenWaitMargin after Spend's
// listing would unlock before its wait ends: the attempt is lost.
func TestTokenLockShortOfItsWaitIsLost(t *testing.T) {
	ctx := context.Background()
	b, c := channelCounter(t, channels[1].period, unit)
	present(t, b, c)
	spendAndJudge(t, c, 1)
	tok := c.Names().Token(1, 2)
	b.SetHook(func(op, key string) {
		if op == countertest.OpPutCreate && key == tok {
			b.Advance(counter.TokenWaitMargin + time.Minute)
		}
	})
	if r := c.Spend(ctx, 1, 2); r.Outcome != counter.Lost || r.Used != 2 {
		t.Fatalf("%+v", r)
	}
}
