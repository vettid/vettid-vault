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
// A recovery's open completes a relay key left pending by an earlier run in
// one attempt, before the phone gets the vault's address and before its
// step-2 write, and writes nothing before that write:
//   - the rotate (or registration) succeeds: the step-2 write is that key's
//     second write, and the recovery's own rotation then stores its new key
//     as pending;
//   - no definite answer: the key stays pending, and the recovery's
//     rotation owes a relay-key rotation, as any rotation made while a key
//     is pending;
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

// inheritedKeyAtOpen is that attempt; the step-2 write stores what it
// changed. Called in the open, with the lock held, before the recovery's
// rotation.
func (m *Manager) inheritedKeyAtOpen(ctx context.Context, p RecoveryOpenParams, now time.Time) {
	pr := m.st.Relay.Pending
	if !m.relayRotation() || pr == nil || m.keys.pendingRelay == nil {
		return
	}
	if m.relay == nil {
		m.relay = p.Relay(m.st.Relay.URL, m.keys.relay)
	}
	hadAnchor := !m.st.Relay.Anchor.IsZero()
	out, created, byRotate, err := m.relayKeyCall(ctx)
	if !hadAnchor && !(out == relayRefused && byRotate && relaysOwnRefusal(err)) {
		m.st.Relay.Anchor = now.UTC()
	}
	m.dirty = true
	switch {
	case out == relayDone:
		if m.makePendingCurrent(created, now) {
			return
		}
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
// before step 2 would be under the DEK the old copy holds. false: none
// was registered; nothing changed.
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
	m.limits = lim
	// The fresh key takes the inherited key's place, with every mark owed:
	// it meets the relay-key rotation owed and is the recovery's own relay
	// key, so the recovery's rotation generates none.
	marks := unionMarks(unionMarks(pr.Marks, pr.Next), m.st.RotationOwed)
	named := pr.Named
	m.dropPendingRelay()
	if o := m.st.RotationOwed; o != nil {
		o.RelayKey = time.Time{}
	}
	m.st.Relay.Pending = &PendingRelay{Seed: seed, Held: map[string]*HeldTokens{}, Marks: marks, Named: named}
	m.keys.pendingRelay = key
	m.rk.pending = m.withKey(key)
	if !m.makePendingCurrent(true, now) { // every held token minted, iat now
		return false
	}
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
