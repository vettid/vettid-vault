package vault

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/paircode"
)

// The rotation world's claim deletions, by the mailbox whose key signed
// each: "mailbox:claim:id" or "mailbox:code:id".
var _ PairCodeRelay = (*rotRelay)(nil)

func (r *rotRelay) DeleteClaim(_ context.Context, claimID string) error {
	r.w.mu.Lock()
	defer r.w.mu.Unlock()
	r.w.claimDels = append(r.w.claimDels, mailboxOf(r.key)+":claim:"+claimID)
	return r.w.claimErr[mailboxOf(r.key)]
}

func (r *rotRelay) DeletePairCode(_ context.Context, claimID string) error {
	r.w.mu.Lock()
	defer r.w.mu.Unlock()
	r.w.claimDels = append(r.w.claimDels, mailboxOf(r.key)+":code:"+claimID)
	return r.w.claimErr[mailboxOf(r.key)]
}

func (r *rotRelay) PairCodeSalts(context.Context) ([]paircode.Salt, error) { return nil, nil }

func (r *rotRelay) PutPairCode(context.Context, string, string, []byte, []byte, []byte) (time.Time, error) {
	return time.Time{}, nil
}

func (fx *rotFx) claimDels() string {
	fx.w.mu.Lock()
	defer fx.w.mu.Unlock()
	return strings.Join(fx.w.claimDels, ",")
}

func (fx *rotFx) drain() {
	fx.t.Helper()
	fx.do(func(m *Manager) { m.flushThenDrain(context.Background()) })
}

// §3.4.1 S7, §6.7.2: an invitation made before a relay key rotation and
// ended after it has its claim deleted, and its open token revoked, with
// the key of the mailbox that made them (the relay deletes a claim by its
// signing mailbox: the current key's DELETE would be a no-op); one made
// after it, with the current key. A code claim's deletion goes the same
// way. Once the old mailbox is stopped, nothing is sent for it.
func TestRelayRotClaimsAreDeletedAtTheCreatingMailbox(t *testing.T) {
	fx := newRotFx(t)
	old := fx.mailbox()
	var before *Invite
	fx.do(func(m *Manager) {
		inv, _, err := m.createInvite(context.Background(), KindConnection, time.Hour, "dev1", m.now())
		if err != nil {
			t.Fatal(err)
		}
		if inv.Mailbox != old {
			t.Fatalf("invite mailbox %q, want %q", inv.Mailbox, old)
		}
		before = inv
		// A code pairing's, recorded as its claim was put then.
		m.recordCodeInvite("code1", KindApp, "dev1", "j-code1", "pc1", m.now().Add(paircode.TTL))
		if inv := m.st.Invites["code1"]; inv.Mailbox != old {
			t.Fatalf("code invite mailbox %q", inv.Mailbox)
		}
	})
	if err := fx.credRotate(); err != nil {
		t.Fatal(err)
	}
	cur := fx.mailbox()
	if cur == old {
		t.Fatal("no rotation")
	}
	fx.do(func(m *Manager) {
		for _, t0 := range m.st.Issued {
			if t0.JTI == before.OpenJTI && t0.Iss != old {
				t.Fatalf("the open token's issuer %q", t0.Iss)
			}
		}
		after, _, err := m.createInvite(context.Background(), KindConnection, time.Hour, "dev1", m.now())
		if err != nil {
			t.Fatal(err)
		}
		if after.Mailbox != cur {
			t.Fatalf("a new invite's mailbox %q", after.Mailbox)
		}
		m.endInvite(m.st.Invites[before.ID], m.now())
		m.endInvite(m.st.Invites["code1"], m.now())
		m.endInvite(after, m.now())
	})
	fx.drain()
	want := old + ":claim:" + before.ClaimID + "," + old + ":code:pc1," + cur + ":claim:"
	if got := fx.claimDels(); !strings.HasPrefix(got, want) {
		t.Fatalf("claim deletions %q, want %q…", got, want)
	}
	fx.w.mu.Lock()
	revokes := strings.Join(fx.w.revokes, ",")
	fx.w.mu.Unlock()
	if !strings.Contains(revokes, old+":jti:"+before.OpenJTI) || !strings.Contains(revokes, old+":jti:j-code1") {
		t.Fatalf("the old invites' tokens not revoked at their mailbox: %v", revokes)
	}

	// Once the old mailbox is stopped its claims went with it: nothing is
	// sent, and the entry is done.
	fx.setClk(fx.old(0).Anchor.Add(OldMailboxStop))
	fx.batch() // the stop
	n := len(fx.claimDels())
	fx.do(func(m *Manager) {
		m.queue(&OutboxEntry{ID: m.newID(m.now()), Op: OpDeleteClaim, Value: "late", ByMailbox: old, Created: m.now()})
	})
	fx.drain()
	if len(fx.claimDels()) != n {
		t.Fatalf("a stopped mailbox's claim deletion was sent: %v", fx.claimDels())
	}
	fx.do(func(m *Manager) {
		for _, e := range m.st.Outbox {
			if e.Value == "late" && !e.Done {
				t.Fatal("the entry for a stopped mailbox is left to retry")
			}
		}
	})
}

// A code claim whose PUT failed, and the open token minted for it that was
// never handed out, made before a rotation: deleted and revoked after it
// with the key of the mailbox that made them.
func TestRelayRotFailedCodeClaimAtTheCreatingMailbox(t *testing.T) {
	fx := newRotFx(t)
	old := fx.mailbox()
	fx.do(func(m *Manager) {
		m.queueDeleteCodeClaim("pc-failed", m.now().Add(paircode.TTL), m.now())
		m.denyUnusedToken("j-unused", m.now().Add(paircode.TTL), m.now())
	})
	// Not drained before the rotation: the entries wait in the outbox.
	if err := fx.credRotate(); err != nil {
		t.Fatal(err)
	}
	fx.drain()
	if got := fx.claimDels(); !strings.Contains(got, old+":code:pc-failed") {
		t.Fatalf("claim deletions %q", got)
	}
	fx.w.mu.Lock()
	revokes := strings.Join(fx.w.revokes, ",")
	fx.w.mu.Unlock()
	if !strings.Contains(revokes, old+":jti:j-unused") {
		t.Fatalf("revokes %v", revokes)
	}
}

// An old mailbox's mailbox_unknown to a claim's deletion: the mailbox and
// its claims are gone, so the deletion is done; the current mailbox's is
// a failure as before.
func TestRelayRotOldMailboxGoneEndsTheDeletion(t *testing.T) {
	fx, old, cur := rotated(t)
	gone := relayErr(404, CodeMailboxUnknown)
	fx.do(func(m *Manager) {
		if !m.oldMailboxGone(old, gone) || m.oldMailboxGone(cur, gone) || m.oldMailboxGone("", gone) ||
			m.oldMailboxGone(old, relayErr(500, "internal")) {
			t.Fatal("oldMailboxGone")
		}
	})
}

// claimEntries queues one deletion of each kind through mailbox mb, values
// v+"-claim" and v+"-code".
func (fx *rotFx) claimEntries(mb, v string) {
	fx.t.Helper()
	fx.do(func(m *Manager) {
		m.queue(&OutboxEntry{ID: m.newID(m.now()), Op: OpDeleteClaim, Value: v + "-claim", ByMailbox: mb, Created: m.now()})
		m.queue(&OutboxEntry{ID: m.newID(m.now()), Op: OpDeletePairCode, Value: v + "-code", ByMailbox: mb, Created: m.now()})
	})
}

// claimEntriesDone reports whether neither of v's entries is left to
// retry (a done entry leaves the outbox).
func (fx *rotFx) claimEntriesDone(v string) bool {
	fx.t.Helper()
	pending := 0
	fx.do(func(m *Manager) {
		for _, e := range m.st.Outbox {
			if (e.Value == v+"-claim" || e.Value == v+"-code") && !e.Done {
				pending++
			}
		}
	})
	return pending == 0
}

// An old mailbox answering a claim's deletion mailbox_unknown during its
// grace: its claims went with it, so both kinds of deletion are done and
// not tried again. The current mailbox's mailbox_unknown is a failure,
// left to retry.
func TestRelayRotOldMailboxUnknownToADeletionIsDone(t *testing.T) {
	fx, old, cur := rotated(t)
	fx.w.mu.Lock()
	fx.w.claimErr = map[string]error{old: relayErr(404, CodeMailboxUnknown), cur: relayErr(404, CodeMailboxUnknown)}
	fx.w.mu.Unlock()
	fx.claimEntries(old, "o")
	fx.claimEntries(cur, "c")
	fx.drain()
	if !fx.claimEntriesDone("o") {
		t.Fatal("an old mailbox's mailbox_unknown left its deletions to retry")
	}
	if fx.claimEntriesDone("c") {
		t.Fatal("the current mailbox's mailbox_unknown counted as deleted")
	}
	n := strings.Count(fx.claimDels(), old+":")
	fx.drain()
	if got := strings.Count(fx.claimDels(), old+":"); got != n {
		t.Fatalf("the old mailbox's deletions were tried again: %v", fx.claimDels())
	}
}

// A mailbox stopped early (its collect answered mailbox_unknown), before
// its grace would end: nothing is signed with its key for a claim, and
// the entries are done.
func TestRelayRotDeletionForAMailboxStoppedEarly(t *testing.T) {
	fx, old, _ := rotated(t)
	fx.do(func(m *Manager) {
		if oldStopDue(&m.st.Relay.Old[0], m.now()) {
			t.Fatal("the stop is due already")
		}
		if !m.mailboxGone(old, m.now()) {
			t.Fatal("not stopped")
		}
	})
	n := len(fx.claimDels())
	fx.claimEntries(old, "s")
	fx.drain()
	if len(fx.claimDels()) != n {
		t.Fatalf("a stopped mailbox's key signed a deletion: %v", fx.claimDels())
	}
	if !fx.claimEntriesDone("s") {
		t.Fatal("the entries for a stopped mailbox are left to retry")
	}
}

// With relay key rotation off, an invite and its open token still record
// the mailbox that made them, so one made before the switch is turned on
// is deleted there after the first rotation.
func TestIssuingMailboxIsRecordedWithRotationOff(t *testing.T) {
	fx := newRotFx(t)
	mb := fx.mailbox()
	fx.do(func(m *Manager) {
		m.opt.RelayKeyRotation = false
		inv, _, err := m.createInvite(context.Background(), KindConnection, time.Hour, "dev1", m.now())
		if err != nil {
			t.Fatal(err)
		}
		if inv.Mailbox != mb {
			t.Fatalf("invite mailbox %q, want %q", inv.Mailbox, mb)
		}
		for _, it := range m.st.Issued {
			if it.JTI == inv.OpenJTI && it.Iss != mb {
				t.Fatalf("open token's issuer %q", it.Iss)
			}
		}
		for _, p := range m.st.Devices {
			if _, toks, err := m.mint(p, TokStanding, time.Hour, nil, m.now(), nil); err != nil || toks[0].Iss != mb {
				t.Fatalf("a peer token's issuer %v %v", toks, err)
			}
			break
		}
		m.opt.RelayKeyRotation = true
	})
}
