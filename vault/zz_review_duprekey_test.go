package vault

import (
	"testing"
	"time"
)

// Reviewer's probe (not part of the release): a rekey hs.init deposited
// twice by I (a crash between the relay's 201 and the flush that marks the
// outbox entry done re-deposits the same bytes under a new msg_id) reaches
// R as two messages with the same inner id. dispatch hands hs.init to
// handleRekeyInit before the inner-id dedupe, so R answers twice; I
// completes one answer, and the other waits L (16 days) and holds R's
// rekeys back (rekeyBlocked).
func TestReviewDuplicateRekeyInitAnsweredTwice(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	f.rekey(0)
	msgs := f.takeKind(0, 1, kHSInit)
	if len(msgs) != 1 {
		t.Fatalf("setup: expected one rekey hs.init, got %d", len(msgs))
	}
	dup := msgs[0]
	dup.MsgID = "redeposit-after-crash"
	f.process(1, msgs[0])
	f.advance(time.Second)
	f.process(1, dup)
	if n := f.answerCount(1); n != 1 {
		t.Fatalf("R holds %d answers to one rekey hs.init (duplicate not deduped before handleRekeyInit)", n)
	}
}
