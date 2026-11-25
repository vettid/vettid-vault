package vault

import (
	"context"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/handshake"
)

// A refused heavy permit is asked again every 250 ms within the wait, and
// taken when given (chosen waits: 3 s, 2 s for a recovery open); with no
// wait it is asked once.
func TestPollPermitWaits(t *testing.T) {
	asked := 0
	take := func(context.Context) (func(), bool) {
		asked++
		if asked < 3 {
			return nil, false
		}
		return func() {}, true
	}
	start := time.Now()
	if _, ok := pollPermit(context.Background(), take, HeavyPermitWait); !ok || asked != 3 {
		t.Fatalf("given on the third ask: %v after %d", ok, asked)
	}
	if d := time.Since(start); d < 2*permitPoll || d > time.Second {
		t.Fatalf("waited %v for two polls", d)
	}
	asked = 0
	if _, ok := pollPermit(context.Background(), func(context.Context) (func(), bool) { asked++; return nil, false }, 0); ok || asked != 1 {
		t.Fatal("no wait: asked once")
	}
	asked = 0
	start = time.Now()
	if _, ok := pollPermit(context.Background(), func(context.Context) (func(), bool) { asked++; return nil, false }, 600*time.Millisecond); ok {
		t.Fatal("given")
	}
	if d := time.Since(start); d < 600*time.Millisecond || asked < 3 {
		t.Fatalf("gave up after %v, %d asks", d, asked)
	}
	if HeavyPermitWait != 3*time.Second || RecoveryOpenPermitWait != 2*time.Second || permitPoll != 250*time.Millisecond {
		t.Fatal("the chosen waits changed")
	}
}

// refusedTwice is a heavy permit refused on its first two asks, then given
// (a code pairing's derivation ending meanwhile).
func refusedTwice(asked *int) func(context.Context) (func(), bool) {
	return func(context.Context) (func(), bool) {
		*asked++
		if *asked < 3 {
			return nil, false // held by another: worth waiting for
		}
		return func() {}, true
	}
}

// A transfer approval waits for the permit rather than answering busy
// (which would spend the UTK).
func TestTransferApprovalWaitsForThePermit(t *testing.T) {
	d := newDevFixture(t)
	attestOK(d)
	inv := d.transferInvite(t)
	n := newNewcomer(t, 0x50)
	n.hsInitAttest(t, d.m, handshake.PurposeApp, inv.ID, "t1", testAttest)
	n.finish(t, d)
	asked := 0
	d.m.opt.HeavyPermit = refusedTwice(&asked)
	d.m.mu.Lock()
	err := d.m.approveTransfer(context.Background(), inv.ID, testPIN, []byte(rPW), false, d.m.now())
	d.m.mu.Unlock()
	if err != nil || asked != 3 {
		t.Fatalf("%v after %d asks", err, asked)
	}
}

// A PIN or password change waits for the permit too.
func TestChangeWaitsForThePermit(t *testing.T) {
	f := newRFixture(t)
	f.arm()
	f.flush()
	asked := 0
	f.m.opt.HeavyPermit = refusedTwice(&asked)
	if err := f.change(SecretChange{Reason: ReplacePassword, PIN: testPIN, Password: []byte(rPW), NewPassword: []byte(rNewPW)}); err != nil || asked != 3 {
		t.Fatalf("%v after %d asks", err, asked)
	}
}

// A refusal for lack of memory (NoRoom) is busy at once: no wait.
func TestPollPermitNoRoomDoesNotWait(t *testing.T) {
	asked := 0
	start := time.Now()
	if _, ok := pollPermit(context.Background(), func(context.Context) (func(), bool) { asked++; return NoRoom, false }, HeavyPermitWait); ok || asked != 1 {
		t.Fatalf("no room: %v after %d asks", ok, asked)
	}
	if time.Since(start) > permitPoll {
		t.Fatal("waited on no room")
	}
}

// A recovery open waits up to 2 s for a held permit, then is busy; a
// refusal for lack of memory is busy at once.
func TestRecoveryOpenPermitWait(t *testing.T) {
	t.Run("given within the wait", func(t *testing.T) {
		f := newOpenFixture(t)
		asked := 0
		f.opts.HeavyPermit = refusedTwice(&asked)
		if m, out := f.open(testPIN, rPW); m == nil || !out.OK || asked != 3 {
			t.Fatalf("%+v after %d asks", out, asked)
		}
	})
	t.Run("held past the wait", func(t *testing.T) {
		f := newOpenFixture(t)
		f.opts.HeavyPermit = func(context.Context) (func(), bool) { return nil, false }
		start := time.Now()
		if m, out := f.open(testPIN, rPW); m != nil || out.Code != OpenBusy {
			t.Fatalf("%+v", out)
		}
		if d := time.Since(start); d < 2*time.Second || d > 3*time.Second {
			t.Fatalf("busy after %v (the wait under the request lock is 2 s)", d)
		}
	})
	t.Run("no room", func(t *testing.T) {
		f := newOpenFixture(t)
		asked := 0
		f.opts.HeavyPermit = func(context.Context) (func(), bool) { asked++; return NoRoom, false }
		start := time.Now()
		if m, out := f.open(testPIN, rPW); m != nil || out.Code != OpenBusy || asked != 1 || time.Since(start) > time.Second {
			t.Fatalf("%+v, %d asks", out, asked)
		}
	})
}

// The arming of the recovery wrap keeps waiting through a refusal for lack
// of memory, within its wait; every other caller is busy at once on it.
func TestArmingWaitsThroughNoRoom(t *testing.T) {
	asked := 0
	take := func(context.Context) (func(), bool) {
		asked++
		if asked < 3 {
			return NoRoom, false
		}
		return func() {}, true
	}
	if _, ok := pollPermitFor(context.Background(), take, HeavyPermitWait, true); !ok || asked != 3 {
		t.Fatalf("arming: %v after %d asks", ok, asked)
	}
	asked = 0
	if _, ok := pollPermitFor(context.Background(), take, HeavyPermitWait, false); ok || asked != 1 {
		t.Fatalf("another caller: %v after %d asks", ok, asked)
	}
}

// The recovery wrap's arming waits through no room for the permit.
func TestArmWaitsThroughNoRoom(t *testing.T) {
	f := newRFixture(t)
	asked := 0
	f.m.opt.HeavyPermit = func(context.Context) (func(), bool) {
		asked++
		if asked < 3 {
			return NoRoom, false
		}
		return func() {}, true
	}
	f.m.mu.Lock()
	st := f.m.arm(context.Background(), testPIN, []byte(rPW), 3*time.Second, f.backup.on, f.m.now()) // credential.create's wait
	f.m.mu.Unlock()
	if st != RecoveryArmed || asked != 3 {
		t.Fatalf("%s after %d asks", st, asked)
	}
}
