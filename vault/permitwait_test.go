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
		return func() {}, asked >= 3
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
		return func() {}, *asked >= 3
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
