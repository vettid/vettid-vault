package vault

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// §12.5 step 2 after a relay key rotation: the deletion also deletes each
// old mailbox whose key it holds, with that key, so the revocations and
// claim deletions queued for it are moot as the current one's are. One
// whose deletion fails keeps its entries for the drain that follows.

// deletionAfterRotation is a vault with an invitation made before a
// rotation (its claim put, and its open token issued, by the old mailbox)
// and one made after it (by the current one), each still open, so the
// deletion's step 1 queues a claim deletion and a jti revocation for both
// mailboxes, and a sub revocation for every peer.
func deletionAfterRotation(t *testing.T) (fx *rotFx, old, cur string, before, after *Invite) {
	fx = newRotFx(t)
	old = fx.mailbox()
	invite := func() *Invite {
		var inv *Invite
		fx.do(func(m *Manager) {
			var err error
			if inv, _, err = m.createInvite(context.Background(), KindConnection, time.Hour, "dev1", m.now()); err != nil {
				t.Fatal(err)
			}
		})
		return inv
	}
	before = invite()
	if err := fx.credRotate(); err != nil {
		t.Fatal(err)
	}
	if cur = fx.mailbox(); cur == old {
		t.Fatal("no rotation")
	}
	after = invite()
	if before.Mailbox != old || after.Mailbox != cur {
		t.Fatalf("invite mailboxes %q, %q", before.Mailbox, after.Mailbox)
	}
	return fx, old, cur, before, after
}

// sentSince is what the relay was asked to revoke or delete since
// sentMark's lengths: each "mailbox:kind:value".
func (fx *rotFx) sentSince(revokes, claims int) []string {
	fx.w.mu.Lock()
	defer fx.w.mu.Unlock()
	return append(append([]string(nil), fx.w.revokes[revokes:]...), fx.w.claimDels[claims:]...)
}

func (fx *rotFx) sentMark() (int, int) {
	fx.w.mu.Lock()
	defer fx.w.mu.Unlock()
	return len(fx.w.revokes), len(fx.w.claimDels)
}

func (fx *rotFx) deletedMailboxes() string {
	fx.w.mu.Lock()
	defer fx.w.mu.Unlock()
	return strings.Join(fx.w.deleted, ",")
}

func (fx *rotFx) deposits() int {
	fx.w.mu.Lock()
	defer fx.w.mu.Unlock()
	return len(fx.w.signers)
}

func (fx *rotFx) deleteBudget(d time.Duration) {
	fx.do(func(m *Manager) { m.opt.DeleteRetry = &DeleteRetry{Others: d} })
}

func (fx *rotFx) deleteVault() {
	fx.t.Helper()
	if err := fx.m.Delete(context.Background()); err != nil {
		fx.t.Fatal(err)
	}
}

// Both mailboxes deleted: nothing queued for either is sent.
func TestRelayRotDeleteDeletesTheOldMailbox(t *testing.T) {
	fx, old, cur, _, _ := deletionAfterRotation(t)
	r, c := fx.sentMark()
	fx.deleteVault()
	if got, want := fx.deletedMailboxes(), cur+","+old; got != want {
		t.Fatalf("deleted %q, want %q", got, want)
	}
	if got := fx.sentSince(r, c); len(got) != 0 {
		t.Fatalf("sent after both mailboxes were deleted: %v", got)
	}
	// The old one with one attempt, the current one with the client's
	// retries.
	fx.w.mu.Lock()
	defer fx.w.mu.Unlock()
	if got := strings.Join(fx.w.deletedOnce, ","); got != old {
		t.Fatalf("deleted with one attempt %q, want %q", got, old)
	}
}

// An old mailbox already gone (the relay's cascade from the current one,
// or its grace ended) took its tokens and claims with it: our relay
// answers its DELETE 204 (RELAY-PROTOCOL §6.10), and mailbox_unknown, from
// a relay that answers so, is taken the same way.
func TestRelayRotDeleteOldMailboxAlreadyGone(t *testing.T) {
	for _, answer := range []error{nil, relayErr(404, CodeMailboxUnknown)} {
		fx, old, _, _, _ := deletionAfterRotation(t)
		fx.w.mu.Lock()
		fx.w.deleteErr = map[string]error{old: answer}
		fx.w.mu.Unlock()
		r, c := fx.sentMark()
		fx.deleteVault()
		if got := fx.sentSince(r, c); len(got) != 0 {
			t.Fatalf("answer %v: sent for a mailbox that is gone: %v", answer, got)
		}
	}
}

// The old mailbox's deletion fails: its claim deletion and its token's
// revocation stay queued and go out in the drain, through its key; the
// current mailbox's, deleted, do not.
func TestRelayRotDeleteOldMailboxDeletionFails(t *testing.T) {
	fx, old, cur, before, _ := deletionAfterRotation(t)
	fx.w.mu.Lock()
	fx.w.deleteErr = map[string]error{old: relayErr(503, "")}
	fx.w.mu.Unlock()
	r, c := fx.sentMark()
	fx.deleteVault()
	if got := fx.deletedMailboxes(); got != cur {
		t.Fatalf("deleted %q, want %q", got, cur)
	}
	sent := fx.sentSince(r, c)
	has := func(s string) bool {
		for _, x := range sent {
			if x == s {
				return true
			}
		}
		return false
	}
	for _, want := range []string{old + ":claim:" + before.ClaimID, old + ":jti:" + before.OpenJTI} {
		if !has(want) {
			t.Fatalf("%s not sent: %v", want, sent)
		}
	}
	// A sender key's revocation goes to every mailbox it went to, the
	// deleted current one too (which answers mailbox_unknown).
	sub, curSub := false, false
	for _, x := range sent {
		sub = sub || strings.HasPrefix(x, old+":sub:")
		curSub = curSub || strings.HasPrefix(x, cur+":sub:")
		if strings.HasPrefix(x, cur+":claim:") || strings.HasPrefix(x, cur+":jti:") {
			t.Fatalf("an entry only for the deleted current mailbox was sent: %s", x)
		}
	}
	if !sub || !curSub {
		t.Fatalf("a sender key's revocation not sent to both mailboxes: %v", sent)
	}
}

// An old mailbox past its stop, whose collects ended, may still be at the
// relay until its grace ends: it is deleted too. Nothing queued for it is
// sent, even when its deletion fails (the vault no longer acts for it,
// oldInGrace).
func TestRelayRotDeleteDeletesAStoppedOldMailbox(t *testing.T) {
	for _, fails := range []bool{false, true} {
		fx, old, cur, _, _ := deletionAfterRotation(t)
		fx.setClk(fx.old(0).Anchor.Add(OldMailboxStop))
		fx.batch() // the stop
		want := cur + "," + old
		if fails {
			fx.w.mu.Lock()
			fx.w.deleteErr = map[string]error{old: relayErr(503, "")}
			fx.w.mu.Unlock()
			want = cur
		}
		r, c := fx.sentMark()
		fx.deleteVault()
		if got := fx.deletedMailboxes(); got != want {
			t.Fatalf("fails %v: deleted %q, want %q", fails, got, want)
		}
		if got := fx.sentSince(r, c); len(got) != 0 {
			t.Fatalf("fails %v: sent for a stopped mailbox: %v", fails, got)
		}
	}
}

// The old mailboxes' deletions make one attempt each, so a relay that
// answers 5xx for one does not take step 2's time from the drain's
// notices; any other deletion (the current and the pending mailbox) keeps
// the client's retries.
func TestDeleteMailboxOneAttempt(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(503)
		_, _ = w.Write([]byte(`{"code":"unavailable","message":"later"}`))
	}))
	defer srv.Close()
	r := NewClientRelay(srv.URL, ed25519.NewKeyFromSeed(make([]byte, 32)), srv.Client(), nil)
	if err := r.DeleteMailbox(withOneAttempt(context.Background())); err == nil {
		t.Fatal("a 503 answered as deleted")
	}
	if got := n.Load(); got != 1 {
		t.Fatalf("%d attempts, want 1", got)
	}
	n.Store(0)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := r.DeleteMailbox(ctx); err == nil {
		t.Fatal("a 503 answered as deleted")
	}
	if got := n.Load(); got < 2 {
		t.Fatalf("%d attempts with the client's retries", got)
	}
}

// Two rotations, two old mailboxes: each is deleted, and one whose
// deletion fails does not stop the next.
func TestRelayRotDeleteTwoOldMailboxes(t *testing.T) {
	for _, fail := range []bool{false, true} {
		fx, old1, _, before, _ := deletionAfterRotation(t)
		if err := fx.credRotate(); err != nil {
			t.Fatal(err)
		}
		old2, cur := fx.old(1).Mailbox, fx.mailbox()
		want := cur + "," + old1 + "," + old2
		if fail {
			fx.w.mu.Lock()
			fx.w.deleteErr = map[string]error{old1: relayErr(503, "")}
			fx.w.mu.Unlock()
			want = cur + "," + old2
		}
		fx.claimEntries(old2, "o2")
		r, c := fx.sentMark()
		fx.deleteVault()
		if got := fx.deletedMailboxes(); got != want {
			t.Fatalf("fail %v: deleted %q, want %q", fail, got, want)
		}
		// Only the failed mailbox's claim deletion goes out in the drain;
		// the deleted old2's do not. (A sender key's revocation, routed to
		// both, goes to both while old1's keeps it queued.)
		sent := strings.Join(fx.sentSince(r, c), ",")
		if got := strings.Contains(sent, old1+":claim:"+before.ClaimID); got != fail {
			t.Fatalf("fail %v: old1's claim deletion sent %v: %s", fail, got, sent)
		}
		if strings.Contains(sent, ":o2-") {
			t.Fatalf("fail %v: the deleted old2's claim deletions were sent: %s", fail, sent)
		}
	}
}

// A stalled best-effort deletion is cut off at the bound: the deletion
// ends, the drain's notices still go out, and the stalled mailbox's
// entries (and any old mailbox not reached) stay queued for that drain.
func TestRelayRotDeleteStalledDeletionIsCutOff(t *testing.T) {
	t.Run("old", func(t *testing.T) {
		fx, old, _, before, _ := deletionAfterRotation(t)
		fx.deleteBudget(200 * time.Millisecond)
		fx.w.mu.Lock()
		fx.w.deleteStall = map[string]bool{old: true}
		fx.w.mu.Unlock()
		r, c := fx.sentMark()
		n := fx.deposits()
		start := time.Now()
		fx.deleteVault()
		if el := time.Since(start); el > 5*time.Second {
			t.Fatalf("the deletion took %v", el)
		}
		if fx.deposits() == n {
			t.Fatal("no notice was deposited after the cut-off")
		}
		sent := strings.Join(fx.sentSince(r, c), ",")
		if !strings.Contains(sent, old+":claim:"+before.ClaimID) {
			t.Fatalf("the stalled mailbox's claim deletion not sent: %s", sent)
		}
	})
	t.Run("pending", func(t *testing.T) {
		fx, old, _, before, _ := deletionAfterRotation(t)
		fx.w.rotate = []error{relayErr(503, "")}
		if err := fx.credRotate(); err != nil {
			t.Fatal(err)
		}
		pmb := fx.pendingMailbox()
		if pmb == "" {
			t.Fatal("no key pending")
		}
		fx.deleteBudget(200 * time.Millisecond)
		fx.w.mu.Lock()
		fx.w.deleteStall = map[string]bool{pmb: true}
		fx.w.mu.Unlock()
		r, c := fx.sentMark()
		fx.deleteVault()
		if got := fx.deletedMailboxes(); strings.Contains(got, old) {
			t.Fatalf("an old mailbox was asked after the bound: %q", got)
		}
		sent := strings.Join(fx.sentSince(r, c), ",")
		if !strings.Contains(sent, old+":claim:"+before.ClaimID) {
			t.Fatalf("the unreached old mailbox's claim deletion not sent: %s", sent)
		}
	})
}
