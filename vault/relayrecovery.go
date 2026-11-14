package vault

import (
	"context"
	"crypto/ed25519"
	"time"

	"github.com/vettid/vettid-vault/vms/suite"
)

// A recovery's inherited key (VAULT-MESSAGING §3.4 "A recovery's inherited
// key", 0.85.4; owner decisions of 2026-11-05, O5b and "rule 2"; §3.4.2
// RK14 step 1 "At a recovery's open"). Only with Options.RelayKeyRotation.
//
// A recovery's open makes one attempt at a relay key left pending by an
// earlier run, before the phone gets the vault's address and before its
// step-2 write, and writes nothing before that write:
//   - the rotate (or registration) succeeds: the key stays pending, with
//     the time of a 201 (Created) or marked Unconfirmed (an answer that its
//     mailbox exists: a lost run of the open may have had it made afresh),
//     and is completed by the next attempt once freshMailboxWait has run;
//     the recovery's rotation owes a relay-key rotation, as with no answer;
//   - no definite answer: the key stays pending, and the recovery's
//     rotation owes a relay-key rotation, as any rotation made while a key
//     is pending. Its attempts never wait for the recovered phone (it is
//     not the recovery's own key, recoveryWaits): they go on at once, at
//     the sooner retries and at mailbox_unknown. When the open met
//     mailbox_unknown, the open's vault_bundle names a mailbox that is
//     gone; the phone's own unlock before its first handshake carries the
//     vault's address again (resumeLostOK), the new one once the key is
//     current. A reading of this release (the spec should confirm); the
//     open is not answered "retry" instead, because an open repeated
//     before its step 1 is stored spends another of the pair's attempts;
//   - a refused rotate (the old mailbox lives): the refused key, its tokens
//     and its refused mark are discarded, and the recovery's rotation
//     stores its own new key as pending, meeting any relay-key rotation
//     owed;
//   - a refused registration (past the grace, no live mailbox): a fresh key
//     is registered before any state holds it, and the step-2 write stores
//     it as current, its tokens minted again; if that registration fails
//     too, the inherited key stays in the refused state and no further key
//     is generated.
// The start of the attempt becomes the current key's anchor in the step-2
// write when it has none, unless the rotate was refused with the relay's
// own 400 or 401.
//
// An open cannot tell whether a lost run of it (a failed step-1 or step-2
// write, a crash after the attempt) learnt anything of the relay: a key
// still pending after the attempt, and not refused, is marked Unconfirmed
// and waits freshMailboxWait from the mark; an open never completes it.
// Residual: a fresh key registered at an open whose step-2 write then
// fails leaves an empty mailbox at the relay, since nothing is written
// before step 2.

// inheritedKeyAtOpen is that attempt; the step-2 write stores what it
// changed. Called in the open, with the lock held, before the recovery's
// rotation.
func (m *Manager) inheritedKeyAtOpen(ctx context.Context, p RecoveryOpenParams, now time.Time) {
	pr := m.st.Relay.Pending
	if !m.relayRotation() || pr == nil || m.keys.pendingRelay == nil {
		return
	}
	// Inherited: it is not this recovery's own key, and never waits for
	// a recovered phone (recoveryWaits), whichever recovery stored it.
	pr.Recovery = ""
	if m.relay == nil {
		m.relay = p.Relay(m.st.Relay.URL, m.keys.relay)
	}
	if now.Before(pr.RetryAfter) {
		// A retry_after still running is honoured here too (§3.4
		// "Retrying with the same key"): no attempt, as if unanswered.
		m.relayKeyFailedAt(now)
		return
	}
	if m.freshWaitRuns(pr) {
		// The wait after a mailbox that may have been created afresh runs:
		// no attempt, and nothing audited (nothing failed).
		return
	}
	// Any recovery open: a lost run of it (its step-1 or step-2 write
	// failed, or it crashed after the attempt) may have had this key's
	// mailbox made afresh, that answer's time lost with it, and nothing
	// stored tells this open from a first one, nor a 201 of that run from
	// an older stored Created. Whatever this attempt's outcome, a key still
	// pending after it, not refused and not just answered 201 by this
	// attempt, is marked Unconfirmed now (a lost answer came before),
	// stored by the step-2 write: it is not completed before
	// freshMailboxWait has run from the mark, so no later attempt (a sooner
	// retry, the recovered phone's unlock) completes it inside the
	// tombstone's window. The mark is not Created: a real 201 after it
	// still starts the wait. It costs a recovery that inherits a pending
	// key a wait (and a second when a later registration makes the mailbox
	// afresh). Not a key left in the refused state: relayKeyAttempt tries
	// that one at the next unlock; a 201 then starts the wait, and an
	// answer that the mailbox exists completes it, its held tokens minted
	// again only if a wait was stored with it (Created or Unconfirmed,
	// mayBeFresh). A refused key with neither, or with an old Created, is
	// completed without minting again: a lost run of the open that made its
	// mailbox afresh before it was refused is not ruled out there, a
	// residual (availability only: the tokens the relay refuses are minted
	// again at the next rotation).
	answered201 := false
	defer func() {
		if cur := m.st.Relay.Pending; cur == pr && pr.Refused == "" && !answered201 {
			at := m.now()
			pr.Unconfirmed = at.UTC()
			m.rk.next = at.Add(freshMailboxWait)
			m.dirty = true
		}
		// The mark or this answer's wait comes after any answer of an
		// attempt stored by an earlier run (relayKeyAttempt): that attempt
		// is accounted for, and a later run does not wait again for it. A
		// refused key keeps it: its next attempt waits from then.
		if cur := m.st.Relay.Pending; cur == pr && (answered201 || pr.Refused == "") {
			pr.Attempt = time.Time{}
		}
	}()
	hadAnchor := !m.st.Relay.Anchor.IsZero()
	out, created, byRotate, err := m.relayKeyCall(ctx)
	if !hadAnchor && !(out == relayRefused && byRotate && relaysOwnRefusal(err)) {
		m.st.Relay.Anchor = now.UTC()
	}
	m.dirty = true
	switch {
	case out == relayDone && created && (pr.Created.IsZero() || byRotate):
		// A mailbox created afresh: the key stays pending until
		// freshMailboxWait has run (relayKeyAttempt), the answer's time
		// stored with it by the step-2 write; the recovery's rotation owes
		// a relay-key rotation, as with no answer.
		// The time the answer came, not the open's (the deletion may have
		// come during the call).
		at := m.now()
		pr.Created, pr.Refused, pr.RetryAfter = at.UTC(), "", time.Time{}
		pr.Unconfirmed = time.Time{} // a real answer's wait replaces a mark
		m.rk.next = at.Add(freshMailboxWait)
		answered201 = true
		return
	case out == relayDone:
		// The relay answers that the key's mailbox exists: it may have been
		// made afresh by a lost run of this open (whatever Created holds,
		// that run's 201 may be newer), so an open never completes it; the
		// mark is stored above, and the next attempt after its wait
		// completes it. A mailbox made long before only waits once,
		// needlessly.
		pr.Refused, pr.RetryAfter = "", time.Time{}
		return
	case out == relayRefused && byRotate:
		m.relayKeyFailedAt(now)
		named := pr.Named
		m.dropPendingRelay()
		m.rk.carryNamed = named // the recovery's own key names no mark twice
		return
	case out == relayRefused:
		if m.freshKeyAtOpen(ctx, pr, now) {
			return
		}
		// Nothing changed: the inherited key, whose registration was
		// refused, stays in the refused state.
		pr.Refused, pr.RetryAfter = RelayCode(err), time.Time{}
		if pr.Refused == "" {
			pr.Refused = "refused"
		}
	}
	m.relayKeyFailedAt(now)
}

// relayKeyFailedAt audits identity.rotation_failed once for this run.
func (m *Manager) relayKeyFailedAt(now time.Time) {
	m.rk.failAudited = false
	m.relayKeyFailed(now)
}

// freshKeyAtOpen registers a fresh key in place of an inherited key whose
// registration was refused, and makes it current in memory (the step-2
// write stores it): the only relay key not stored first, since a write
// before step 2 would be under the DEK the old copy holds.
//
// The order: the seed and the registration first, which change nothing;
// only once the relay has the fresh mailbox is the inherited key dropped
// and the fresh key made current, which cannot fail there (the relay-key
// rotation owed is met and cleared first, so makePendingCurrent draws no
// next key). false: no key was registered, and nothing changed.
func (m *Manager) freshKeyAtOpen(ctx context.Context, pr *PendingRelay, now time.Time) bool {
	draw := suite.RandomBytes
	if m.opt.KeyRand != nil {
		draw = m.opt.KeyRand
	}
	seed, err := draw(32)
	if err != nil {
		return false
	}
	key := ed25519.NewKeyFromSeed(seed)
	rr, ok := m.withKey(key).(RelayRotator)
	if !ok {
		suite.Wipe(seed)
		suite.Wipe(key)
		return false
	}
	lim, _, err := rr.RegisterCreated(ctx)
	if err != nil {
		suite.Wipe(seed)
		suite.Wipe(key)
		return false
	}
	// Registered: from here on nothing fails. The fresh key takes the
	// inherited key's place, with every mark owed: it meets the relay-key
	// rotation owed and is the recovery's own relay key, so the
	// recovery's rotation generates none.
	m.limits = lim
	marks := unionMarks(unionMarks(pr.Marks, pr.Next), m.st.RotationOwed)
	named := pr.Named
	if o := m.st.RotationOwed; o != nil {
		o.RelayKey = time.Time{}
	}
	m.dropPendingRelay()
	m.st.Relay.Pending = &PendingRelay{Seed: seed, Held: map[string]*HeldTokens{}, Marks: marks, Named: named}
	m.keys.pendingRelay = key
	m.rk.pending = m.withKey(key)
	m.makePendingCurrent(true, now) // every held token minted, iat now; no next key drawn (above)
	m.rk.relayMet = true
	return true
}

// relayMetAtOpen reports, and clears, that the open's fresh key is the
// recovery's relay key: its rotation stores no other.
func (m *Manager) relayMetAtOpen() bool {
	met := m.rk.relayMet
	m.rk.relayMet = false
	return met
}

// openRegisters reports whether a recovery's open registers its current
// key: not while the key inherited pending is still pending (its attempt
// was the open's; after the grace a registration would make the old
// mailbox again), nor once that mailbox answered mailbox_unknown.
func (m *Manager) openRegisters() bool {
	if !m.relayRotation() {
		return true
	}
	if !m.st.Relay.Collect.Stopped.IsZero() {
		return false
	}
	return m.st.Relay.Pending == nil || m.rk.left == "" || m.pendingMailbox() != m.rk.left
}
