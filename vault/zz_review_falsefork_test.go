package vault

import (
	"testing"
	"time"
)

// Reviewer's probe (not part of the release): I has a rekey K open and
// starts a reconnect naming E0 while K awaits hs.resp. The reconnect
// hs.init is delayed at the relay (R collected it and crashed before the
// ack, so it is redelivered later, §8.4). K completes: R establishes E_K,
// I confirms E_K at R's hs.confirm and sends under E_K. Then the delayed
// reconnect hs.init reaches R: ctx E0 is R's confirmed epoch while E_K is
// current, so R answers it as "named confirmed". I accepts the hs.resp
// (nothing checks that the reconnect's ctx is still I's current epoch),
// sends hs.fin, and R's rule E destroys E_K with the hs.init's ts t2.
// I's traffic under E_K (ts > t2), redelivered after that hs.fin, is then
// fork evidence at R: an honest pair is suspended.
func TestReviewStaleReconnectRuleEFalseFork(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()

	// 1. I's rekey K; R answers it.
	f.rekey(0)
	if f.deliver(0, 1, kHSInit) != 1 {
		t.Fatal("setup: rekey hs.init not delivered")
	}
	f.advance(time.Minute)

	// 2. I starts a reconnect (naming E0) while K is open; the hs.init is
	//    held back (R's crash before its ack delays it).
	f.do(0, func(m *Manager, p *Peer) { m.startReconnect(p, f.clk) })
	rc := f.takeKind(0, 1, kHSInit)
	if len(rc) != 1 {
		t.Fatalf("setup: expected the reconnect hs.init, got %d", len(rc))
	}
	f.advance(time.Minute)

	// 3. K completes and is confirmed at I.
	if f.deliver(1, 0, kHSResp) != 1 || f.deliver(0, 1, kHSFin) != 1 || f.deliver(1, 0, kConfirm) < 1 {
		f.dump()
		t.Fatal("setup: the rekey did not complete")
	}
	if f.p(0).Pending != nil || !f.sameEpoch() {
		t.Fatal("setup: K not confirmed at I")
	}
	eK := append([]byte(nil), f.cur(0)...)
	f.advance(time.Minute)

	// 4. The delayed reconnect hs.init reaches R: answered as named-confirmed.
	f.process(1, rc[0])
	if n := f.answerCount(1); n != 1 {
		f.dump()
		t.Fatalf("R did not answer the delayed reconnect (answers=%d)", n)
	}
	f.advance(time.Minute)

	// 5. I sends under E_K; that message is held back (redelivered later).
	f.note(0, "under-EK")
	notes := f.takeKind(0, 1, kNote)
	if len(notes) != 1 {
		t.Fatalf("setup: expected one note, got %d", len(notes))
	}
	f.advance(time.Minute)

	// 6. I accepts the stale reconnect's hs.resp and sends hs.fin; R
	//    establishes it and rule E destroys E_K.
	if f.deliver(1, 0, kHSResp) != 1 {
		t.Fatal("hs.resp not delivered")
	}
	if pe := f.p(0).Pending; pe == nil {
		t.Fatal("I did not make the reconnect's epoch pending (the probe's premise fails: good)")
	}
	if f.deliver(0, 1, kHSFin) != 1 {
		t.Fatal("hs.fin not delivered")
	}
	if e := f.p(1).epochMeta(eK); e == nil || !e.Destroyed {
		t.Fatalf("E_K not destroyed by rule E at R (meta=%+v)", e)
	}

	// 7. I's message under E_K arrives after that: fork evidence?
	f.process(1, notes[0])
	if f.suspendedRef(1, "epoch") {
		f.dump()
		t.Fatal("FALSE FORK: R suspended an honest peer (ref epoch) after a stale reconnect's hs.fin")
	}
}
