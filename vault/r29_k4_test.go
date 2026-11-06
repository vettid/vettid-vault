package vault

import "testing"

// §3.4.1 "Epochs after an ik link" (R29-K4), the flag-set case: an epoch
// Q would demote by position (signed by the link's old_ik, established by
// a message deposited after the link) whose received flag is set makes Q
// suspend (ref epoch, the neutral feed item) instead.
func TestR29PositionDemotionFlagSetSuspends(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	f.rekey(0)
	f.deliver(0, 1, kHSInit)
	f.deliver(1, 0, kHSResp)
	snap := f.snapshot(0) // a copy of P with E1 pending
	f.rotate(0)
	f.deliverAt(0, 1, kHSFin, "pump-z") // Q activates E1 (deposited after the link)
	e1 := append([]byte(nil), f.cur(1)...)
	f.startCopy(0, snap)
	f.deliver(1, 2, kConfirm) // the copy confirms E1
	f.note(2, "copy-under-E1")
	f.deliverAt(2, 1, kNote, "pump-zz")
	if !f.flag(1, e1) || f.p(1).suspended() {
		t.Fatal("setup: E1's flag not set, or suspended early")
	}
	f.deliverAt(0, 1, kRotate, "pump-a") // the link, deposited before the hs.fin
	if !f.suspendedRef(1, "epoch") || !f.forkFeed(1) {
		f.dump()
		t.Fatal("an epoch demotable by position with its flag set did not suspend")
	}
	if e := f.p(1).epochMeta(e1); e != nil && e.Demoted {
		t.Fatal("demoted instead of suspending")
	}
}
