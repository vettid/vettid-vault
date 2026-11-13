package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/strictjson"
	"github.com/vettid/vettid-vault/vms/suite"
)

// The identity-key parts of VAULT-MESSAGING §3.4.1 that 0.86.0 changed
// (and that apply without relay-key rotation, which this release does not
// build): Table B for identity.rotate with the whole chain (S8), "Epochs
// after an ik link" (strict F1 demotion, F2 fork evidence by the confirmed
// epoch), H5 with pending epochs, S5 at the vault's own rotation and the
// identity.rotate resend.

// ancestor reports whether ik is an ancestor of p's current ik: the old_ik
// of a followed link (§3.4.1 "Terms").
func (p *Peer) ancestor(ik []byte) bool {
	if len(ik) == 0 || bytes.Equal(ik, p.IK) {
		return false
	}
	for _, r := range parseRotations(p.Chain) {
		if bytes.Equal(r.OldIK, ik) {
			return true
		}
	}
	return false
}

// signedAtOrBefore reports whether signer is the link's oldIK or an
// ancestor of it: the old_ik of a followed link before the one from oldIK
// (§3.4.1 "that link's old_ik or an ancestor").
func (p *Peer) signedAtOrBefore(signer, oldIK []byte) bool {
	if len(signer) == 0 {
		return false
	}
	if bytes.Equal(signer, oldIK) {
		return true
	}
	for _, r := range parseRotations(p.Chain) {
		if bytes.Equal(r.OldIK, oldIK) {
			return false
		}
		if bytes.Equal(r.OldIK, signer) {
			return true
		}
	}
	return false
}

// signedByLinks reports whether signer is the old_ik of one of links, or
// an ancestor of one.
func (p *Peer) signedByLinks(signer []byte, links []*handshake.Rotation) bool {
	for _, r := range links {
		if p.signedAtOrBefore(signer, r.OldIK) {
			return true
		}
	}
	return false
}

// rejected reports whether ik was dropped at connection.rotation.resolve.
func (p *Peer) rejected(ik []byte) bool {
	for _, x := range p.Rejected {
		if bytes.Equal(x.NewIK, ik) {
			return true
		}
	}
	return false
}

// rotateLinks reads an identity.rotate body: `rotations` (S8, 0.86.0: the
// whole chain since the epoch's signer) when present, else `rotation`
// alone (rotateIdentity's fallback when identityRotateBody has no chain).
func rotateLinks(body []byte) ([]*handshake.Rotation, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBadRequest
	}
	raw, ok := o["rotation"]
	if !ok {
		return nil, errBadRequest
	}
	last, err := handshake.ParseRotation(raw)
	if err != nil {
		return nil, errBadRequest
	}
	arr, present, err := o.OptArray("rotations")
	if err != nil || len(arr) > handshake.MaxRotations {
		return nil, errBadRequest
	}
	if !present || len(arr) == 0 {
		return []*handshake.Rotation{last}, nil
	}
	var links []*handshake.Rotation
	for _, x := range arr {
		r, err := handshake.ParseRotation(x)
		if err != nil {
			return nil, errBadRequest
		}
		links = append(links, r)
	}
	if !bytes.Equal(links[len(links)-1].Marshal(), last.Marshal()) {
		return nil, errBadRequest // `rotation` is the chain's last link
	}
	return links, nil
}

// hIdentityRotate is Table B's identity.rotate column (§3.4.1): the links
// already followed are skipped (all followed: ignore); the first one not
// followed must start at the current ik (an ancestor ik: unexpected; a
// rejected ik: rejected_ik; any other: unknown_ik); the chain must verify and no new
// ik may be an ancestor or rejected (ik_rollback). Following applies
// "Epochs after an ik link" and H5.
func (m *Manager) hIdentityRotate(_ context.Context, s *Session, in *envelope.Inner) (json.RawMessage, error) {
	links, err := rotateLinks(in.Body)
	if err != nil {
		return nil, err
	}
	p := s.peer
	for _, r := range links {
		if m.rotationConflict(p, r, s.now) {
			return nil, nil
		}
	}
	if p.suspended() {
		return nil, nil
	}
	var ep []byte
	if s.epoch != nil {
		id := s.epoch.ID()
		ep = id[:]
	}
	known := parseRotations(p.Chain)
	i := handshake.KnownPrefix(known, links)
	if i == len(links) {
		m.k9(p, links, ep, s.now) // every link already followed: ignore, R29-K9 still judged
		return nil, nil
	}
	switch first := links[i].OldIK; {
	case bytes.Equal(first, p.IK):
	case p.rejected(first):
		m.refusePeerKey(p, "rejected_ik", s.now)
		return nil, nil
	case p.ancestor(first):
		// Table B: an ancestor ik in identity.rotate is only "every link
		// already followed: ignore"; any other case cannot occur ("—"),
		// so refuse (unexpected).
		m.refusePeerKey(p, "unexpected", s.now)
		return nil, nil
	default:
		m.refusePeerKey(p, "unknown_ik", s.now)
		return nil, nil
	}
	app := links[i:]
	if _, _, err := handshake.ResolveChain(p.IK, app); err != nil {
		m.audit(s.now, "bad_rotation", p.ID)
		return nil, nil
	}
	for _, r := range app {
		if p.ancestor(r.NewIK) || p.rejected(r.NewIK) {
			m.refusePeerKey(p, "ik_rollback", s.now)
			return nil, nil
		}
	}
	m.followLinks(p, app, ep, s.now)
	m.k9(p, links, ep, s.now)
	return nil, nil
}

// k9 is §3.4.1 "Epochs abandoned while pending, at P's identity.rotate"
// (R29-K9), in the write that follows or ignores an identity.rotate from
// P under epoch msgEpoch (E): for each of its links, every epoch of P that
// the vault began and abandoned while pending (never confirmed), later
// than E in establishing order, whose sig_R was made by the link's old_ik
// or an ancestor, was never activated by P. With its received flag set a
// copy used it: suspended (ref epoch, the neutral feed item). Otherwise it
// is ended (connection.fork_suspected, ref epoch, no feed item): a later
// message under it is fork evidence, and a reconnect ctx naming it is
// refused. One this message's link just abandoned is ended, not demoted.
// It is not judged at an hs.resp or hs.fin.
func (m *Manager) k9(p *Peer, links []*handshake.Rotation, msgEpoch []byte, now time.Time) {
	ie := p.epochIndex(msgEpoch)
	if p.Kind != KindConnection || ie < 0 || p.suspended() {
		return
	}
	var judged []*EpochMeta
	for i := ie + 1; i < len(p.Epochs); i++ {
		e := &p.Epochs[i]
		if !e.Mine || !e.Abandoned || e.Ended {
			continue
		}
		for _, r := range links {
			if p.signedAtOrBefore(e.Signer, r.OldIK) {
				judged = append(judged, e)
				break
			}
		}
	}
	for _, e := range judged {
		if e.GotFromPeer {
			m.suspendForkRef(p, "epoch", now)
			return
		}
	}
	for _, e := range judged {
		e.Ended = true
		e.Demoted, e.DemotedAt, e.DemotedMsg = false, time.Time{}, ""
		m.record(Activity{Kind: "connection.fork_suspected", ConnectionID: connID(p), DeviceID: devID(p), Ref: "epoch", Audit: true}, now)
		m.dirty = true
	}
}

// evidenceFirst is acceptFrom step 3 (§3.4.1): every identity link a
// message carries is checked by rule C before anything refuses it (a
// demoted or destroyed epoch, Table B), so that a second successor is
// recorded whatever epoch it travels under. It reports whether the
// connection is (now) suspended by a conflict.
func (m *Manager) evidenceFirst(p *Peer, in *envelope.Inner, now time.Time) bool {
	if p.Kind != KindConnection {
		return false
	}
	var links []*handshake.Rotation
	switch in.Type {
	case "identity.rotate":
		links, _ = rotateLinks(in.Body)
	case handshake.TypeInit:
		// A rekey's links are checked here and recorded as seen only once
		// it has passed rekeyPrecheck (handleRekeyInit, review 5).
		if b, err := handshake.ParseInit(in.Body); err == nil {
			for _, r := range b.Rotations {
				if m.rotationConflictRec(p, r, false, now) {
					return p.Conflict != nil
				}
			}
		}
		return false
	}
	for _, r := range links {
		if m.rotationConflict(p, r, now) {
			return p.Conflict != nil
		}
	}
	return false
}

// followLinks follows identity links at the position of the message being
// handled, which traveled under epoch msgEpoch (nil: a handshake), with
// "Epochs after an ik link" and H5.
func (m *Manager) followLinks(p *Peer, app []*handshake.Rotation, msgEpoch []byte, now time.Time) {
	if len(app) == 0 {
		return
	}
	for _, r := range app {
		p.IK, p.KEM = append([]byte(nil), r.NewIK...), r.NewKEM.Bytes()
		p.Chain = append(p.Chain, r.Marshal())
	}
	pruneSeen(p) // a followed link is no longer only seen; irrelevant ones go
	m.dirty = true
	// Following a link abandons the pending epoch whose sig_R the link's
	// old_ik made (the peer dropped that answer at its rotation, S5),
	// unless the message traveled under it (it has just confirmed it).
	restart := ""
	if pe := p.Pending; pe != nil && !bytes.Equal(pe.ID, msgEpoch) {
		if e := p.epochMeta(pe.ID); e != nil && p.signedByLinks(e.Signer, app) {
			m.abandonPending(p, "link", false, now)
			restart = string(pe.Purpose) // started again under the current ik, as H5 says
		}
	}
	if m.noLinkRestart {
		restart = ""
	}
	defer func() {
		switch handshake.Purpose(restart) {
		case handshake.PurposeReconnect:
			m.startReconnect(p, now)
		case handshake.PurposeRekey:
			m.startRekey(p, now)
		}
	}()
	byPosition := func(e *EpochMeta) bool {
		return !e.Demoted && !e.Pending && p.signedByLinks(e.Signer, app) && !e.EstAt.IsZero() && posAfter(e.EstAt, e.EstMsg, m.relayAt, m.msgID)
	}
	for i := range p.Epochs {
		if e := &p.Epochs[i]; byPosition(e) && e.GotFromPeer {
			// §3.4.1 "Epochs after an ik link" (R29-K4): its received flag
			// is set, so P's side used it after the rotation: a copy did.
			m.suspendForkRef(p, "epoch", now)
			return
		}
	}
	demotedCurrent := false
	for i := range p.Epochs {
		e := &p.Epochs[i]
		// An epoch signed by an old ik, established by a message deposited
		// after the link: an old copy's. It stops being current.
		if byPosition(e) {
			e.Demoted, e.DemotedAt, e.DemotedMsg = true, m.relayAt, m.msgID
			// S8 (0.86.6): a demotion by position is audited as a fork
			// sign (ref epoch), without a feed item or a suspension.
			m.record(Activity{Kind: "connection.fork_suspected", ConnectionID: connID(p), DeviceID: devID(p), Ref: "epoch", Audit: true}, now)
			if bytes.Equal(e.ID, p.LastEpochID) {
				demotedCurrent = true
				if kr := m.sessions[p.ID]; kr != nil {
					m.rehold(p, kr.Current(), now)
				}
			}
			m.note(now, "epoch_demoted", p.ID)
		}
	}
	m.f1Demote(p, app, msgEpoch, now)
	if demotedCurrent && !m.noLinkRestart {
		m.restartAfterDemotion(p, now) // not beside the caller's own handshake
	}
	m.h5(p, now)
}

// f1Demote is §3.4.1 "Strict F1, a link under an earlier epoch": a link
// carried under an epoch E of P, while Q's current epoch is later than E
// and signed by the link's old_ik, shows that P never activated the epochs
// after E signed by that key, or that a copy did. Q takes together every
// epoch of P after E whose P-side signer is the link's old_ik or an
// ancestor: if any has its received flag set, Q suspends (ref epoch);
// otherwise it demotes them all and reconnects naming E (a device:
// rekeys), which P accepts as its last.
func (m *Manager) f1Demote(p *Peer, app []*handshake.Rotation, msgEpoch []byte, now time.Time) {
	if msgEpoch == nil || bytes.Equal(msgEpoch, p.LastEpochID) || !p.newer(p.LastEpochID, msgEpoch) {
		return
	}
	cur := p.epochMeta(p.LastEpochID)
	ie := p.epochIndex(msgEpoch)
	if cur == nil || ie < 0 {
		return
	}
	for _, r := range app {
		if !bytes.Equal(cur.Signer, r.OldIK) {
			continue
		}
		var later []*EpochMeta
		for i := ie + 1; i < len(p.Epochs); i++ {
			e := &p.Epochs[i]
			if e.Pending || e.Abandoned || e.Destroyed {
				continue // pending and abandoned ones: "Pending epochs at a link", K9
			}
			if p.signedAtOrBefore(e.Signer, r.OldIK) {
				later = append(later, e)
			}
		}
		for _, e := range later {
			if e.GotFromPeer {
				// P's side used it after the rotation: a copy did.
				m.suspendForkRef(p, "epoch", now)
				return
			}
		}
		for _, e := range later {
			if !e.Demoted {
				// Demoted at the link's position x: messages under it
				// deposited after x are refused (ancestor_ik); one deposited
				// before x is accepted, and one that would set its flag
				// suspends ("The flag is judged whenever it is set").
				e.Demoted, e.DemotedAt, e.DemotedMsg = true, m.relayAt, m.msgID
			}
		}
		// Audited as a fork sign (ref epoch), without a feed item or a
		// suspension, as a demotion by position is.
		m.record(Activity{Kind: "connection.fork_suspected", ConnectionID: connID(p), DeviceID: devID(p), Ref: "epoch", Audit: true}, now)
		m.note(now, "epoch_demoted_f1", p.ID)
		kr := m.sessions[p.ID]
		if kr != nil {
			m.rehold(p, kr.Current(), now)
		}
		for _, id := range sortedKeys(m.st.Outgoing) {
			og, sortedOK := m.st.Outgoing[id]
			if !sortedOK {
				continue // removed earlier in this loop
			}
			if og.New == nil && og.PeerID == p.ID && og.Purpose == handshake.PurposeRekey {
				m.abandonOutgoing(id, now)
			}
		}
		switch {
		case m.noLinkRestart:
			// Not beside the caller's own handshake, which establishes
			// the next epoch.
		case p.Kind == KindConnection:
			m.reconnectNaming(p, msgEpoch, "f1", now)
		default:
			m.startRekey(p, now)
		}
		return
	}
}

// Held messages (§3.4.1 "Epochs after an ik link", 0.86.2/0.86.3 draft):
// while p's current epoch is demoted, a durable message to p waits
// unsealed in its place in the outbox and is sealed, with a new ts and the
// same inner id (receivers dedupe by it), under the next current epoch;
// one whose exp passes first is discarded; an ephemeral one is not sent.

// holdDemoted queues a message made while p's current epoch is demoted.
func (m *Manager) holdDemoted(p *Peer, in *envelope.Inner, wake string) {
	if te := m.registry[in.Type]; te != nil && te.spec.Ephemeral {
		return // ephemeral: not sent
	}
	m.holdInner(p, in, wake)
}

// holdInner queues in, unsealed, as a held entry for p.
func (m *Manager) holdInner(p *Peer, in *envelope.Inner, wake string) {
	c := *in
	c.Seq, c.Features = 0, nil
	j, err := c.Marshal(envelope.ModeSealed)
	if err != nil {
		return
	}
	m.queueDeposit(&OutboxEntry{PeerID: p.ID, RelayURL: p.Relay.URL, Mailbox: p.Relay.Mailbox, Held: j, HeldExp: in.Exp, Wake: wake, InnerID: in.ID,
		Type: in.Type}, m.now())
}

// rehold turns p's outbox entries sealed under the epoch ep (the current
// epoch, just demoted) and not yet deposited back into held ones: the
// vault reads each back with ep's send key. Handshake messages and
// entries already deposited are left as they are.
func (m *Manager) rehold(p *Peer, ep *handshake.Epoch, now time.Time) { m.reholdAt(p, ep, false, now) }

// resealAtKeyChange is 0.88.7 §8.3 "Re-sealed at a key change" (owner
// decision b, GC #7213 Q2): just before connection p's current epoch is
// replaced (activate, confirmPending), every durable entry to p still
// waiting in the outbox goes back to held, and sealHeld seals it under the
// new epoch, in its place, with the same inner id and (unless an earlier
// copy may have reached the relay) a fresh ts. Before 0.88.7 such an entry
// kept the bytes sealed at queue time and, deposited after a long wait,
// was refused by the peer (unknown_kid, stale_or_future) after the relay
// accepted it: lost silently (GC #7160 cause 2). A device's entries are
// left as they are.
func (m *Manager) resealAtKeyChange(p *Peer, kr *handshake.Keyring) {
	if p.Kind != KindConnection || kr == nil {
		return
	}
	m.reholdAt(p, kr.Current(), true, m.now())
}

// reholdAt is rehold; at a key change (keyChange) an entry sealed in
// session mode that ep cannot read back (sealed under an epoch whose send
// key is gone: an entry from before 0.88.7 that already waited across a key
// change) cannot be re-sealed and is not delivered (notDelivered), an
// hs.confirm excepted (as it is); an ephemeral entry stays as it is, and an
// hs.confirm under ep is superseded (done).
func (m *Manager) reholdAt(p *Peer, ep *handshake.Epoch, keyChange bool, now time.Time) {
	if ep == nil {
		return
	}
	for _, e := range m.st.Outbox {
		if e.Done || e.PeerID != p.ID || e.Op != OpDeposit || e.Held != nil || e.Handshake || len(e.Payload) == 0 {
			continue
		}
		if keyChange && e.Ephemeral {
			// 0.88.7: an ephemeral entry (§8.5) ends silently at a key change:
			// it is never told, and the peer may not open it later.
			e.Done, m.dirty = true, true
			continue
		}
		env, err := envelope.Parse(e.Payload)
		if err != nil {
			continue
		}
		in, err := ep.OpenSent(env)
		if err != nil {
			if keyChange && memberDeposit(e) && env.Mode() == envelope.ModeSession {
				m.notDelivered(e, "undelivered_unreadable", now) // 0.88.7 §8.3: not safe to re-seal
			}
			continue // sealed under another epoch: as it is
		}
		if te := m.registry[in.Type]; te != nil && te.spec.Ephemeral {
			e.Done, m.dirty = true, true // ephemeral: not sent (one queued before 0.88.7 recorded Ephemeral)
			continue
		}
		if keyChange && e.Confirm {
			// An hs.confirm for the epoch being replaced is superseded: the
			// new epoch's own follows (queueConfirm) or is not needed.
			e.Done, m.dirty = true, true
			continue
		}
		in.Seq, in.Features = 0, nil
		j, err := marshalHeld(in)
		if err != nil {
			if memberDeposit(e) {
				m.notDelivered(e, "undelivered_unreadable", now) // 0.88.7: it cannot be held to be sealed again
			}
			continue
		}
		e.Payload, e.Held, e.HeldExp = nil, j, in.Exp
		if e.InnerID == "" {
			e.InnerID = in.ID
		}
		m.markUnstored(e) // changed in place: not sent before a write stores it
		m.dirty = true
	}
}

// sealHeld seals p's held messages under its current epoch, once that is
// not demoted, each in its place in the outbox: the same inner id, a new
// ts (the durable ts window is 16 days; a hold can last up to B); one
// whose exp has passed is discarded.
//
// 0.88.7 §8.3 "Re-sealed at a key change": an entry an earlier deposit of
// which may have reached the relay (Tried: a lost answer) keeps its ts, so
// that the peer's ts window (16 days) refuses it no later than the peer's
// inner-id dedupe (also 16 days) forgets the first copy: a fresh ts could
// make the peer run it twice. Kept, and already past the window, it is not
// delivered (notDelivered).
func (m *Manager) sealHeld(p *Peer) {
	kr := m.sessions[p.ID]
	if kr == nil || kr.Current() == nil {
		return
	}
	now := m.now()
	for _, e := range m.st.Outbox {
		if e.Done || e.PeerID != p.ID || e.Held == nil {
			continue
		}
		if !e.HeldExp.IsZero() && !now.Before(e.HeldExp) {
			if e.InnerID == "" {
				e.InnerID = heldID(e.Held)
			}
			e.Done, e.Held = true, nil
			m.quotaRefreshEnded(e)                           // a quota refresh's: no answer can come
			m.auditRef(now, "held_expired", p.ID, e.InnerID) // S12 (0.88.7: ref = its inner id)
			m.dirty = true
			continue
		}
		in, err := envelope.ParseInner(e.Held, envelope.ModeSealed)
		if err != nil {
			// Unreadable: dropped and audited (§3.4.1 "After a demotion":
			// no held message goes silently).
			m.notDelivered(e, "held_unsealable", now)
			continue
		}
		if !e.Tried {
			in.TS = now
		} else if now.Sub(in.TS) > envelope.MaxDurableAge {
			m.notDelivered(e, "undelivered_window", now) // 0.88.7 §8.3: kept ts, past §8.4's window
			continue
		}
		raw, err := m.sealFor(p, kr.Current(), in)
		if errors.Is(err, errDemoted) {
			return // still demoted: the rest wait too, in order
		}
		if err != nil {
			// It cannot be sealed at all (review M1): dropped, audited, so
			// that it does not hold the mailbox's queue for good.
			m.notDelivered(e, "held_unsealable", now) // drop.held_unsealable
			continue
		}
		e.Payload, e.Held, e.HeldExp = raw, nil, time.Time{}
		e.RelayURL, e.Mailbox = p.Relay.URL, p.Relay.Mailbox
		m.markUnstored(e) // sealed in place: not sent before a write stores it (0.88.7)
		m.dirty = true
	}
}

// marshalHeld writes an inner read back for holding (sealed-mode JSON);
// a variable so that a test can make it fail.
var marshalHeld = func(in *envelope.Inner) ([]byte, error) { return in.Marshal(envelope.ModeSealed) }

// heldID is a held entry's inner id ("" if none or unreadable).
func heldID(held []byte) string {
	if held == nil {
		return ""
	}
	if in, err := envelope.ParseInner(held, envelope.ModeSealed); err == nil {
		return in.ID
	}
	return ""
}

// The member's notice of 0.88.7 §8.3 "Not delivered" (card GC #6875,
// owner decision a, GC #7711): one feed item per connection per hour, with
// a count. NoticeNotDelivered for every case but undelivered_window, whose
// message may already have reached the peer (NoticeUnconfirmed: "may not
// have been delivered").
const (
	NoticeNotDelivered = "message.not_delivered"
	NoticeUnconfirmed  = "message.delivery_unconfirmed"
	NoticeWindow       = time.Hour
)

// NoticeOwnRemoval is whether the member is told of messages to a
// connection that they removed themselves: not (the owner's a, GC #7806:
// they chose to end it; the drop is still audited). Removals by the peer,
// a replacement and a gone mailbox are told.
const NoticeOwnRemoval = false

// upkeepTypes are the vault's own messages to a connection, which recover
// by themselves and are not the member's to be told about: profile and
// identity upkeep, the held notice; with upkeepPrefixes, the relay's
// tokens (relay.token.refresh, relay.token.issued, and the answers to the
// peer's own, which carry the request's type) and attachment transfers.
var (
	upkeepTypes    = map[string]bool{"profile.update": true, "identity.rotate": true, "vault.held": true}
	upkeepPrefixes = []string{"relay.", "att."}
)

// memberMessage reports whether an entry is the member's own message
// (sent or answered): not a quota refresh or upkeep. One whose type can't
// be read is taken as the member's (told rather than silent).
func memberMessage(e *OutboxEntry, typ string) bool {
	if e.QuotaRefresh || upkeepTypes[typ] {
		return false
	}
	for _, p := range upkeepPrefixes {
		if strings.HasPrefix(typ, p) {
			return false
		}
	}
	return true
}

// entryType is e's inner type: recorded at queue time, or read back from
// a held entry or from its payload under the current epoch ("" if none).
func (m *Manager) entryType(e *OutboxEntry) string {
	if e.Type != "" {
		return e.Type
	}
	if e.Held != nil {
		if in, err := envelope.ParseInner(e.Held, envelope.ModeSealed); err == nil {
			return in.Type
		}
		return ""
	}
	if kr := m.sessions[e.PeerID]; kr != nil && kr.Current() != nil && len(e.Payload) > 0 {
		if env, err := envelope.Parse(e.Payload); err == nil {
			if in, err := kr.Current().OpenSent(env); err == nil {
				return in.Type
			}
		}
	}
	return ""
}

// notDelivered is the seam of 0.88.7 §8.3 "Not delivered": a durable
// entry to a connection that the vault will not deposit (it cannot be
// re-sealed safely, or its connection ended: removed, replaced, its
// mailbox unknown, suspended, refused) ends here, never silently: it
// audits drop.<reason>, and for the member's own messages (card GC #6875)
// records the member's notice.
func (m *Manager) notDelivered(e *OutboxEntry, reason string, now time.Time) {
	ref := e.InnerID
	if ref == "" {
		ref = heldID(e.Held)
	}
	typ := m.entryType(e)
	e.Done, e.Held, e.Payload = true, nil, nil
	m.quotaRefreshEnded(e)                 // a quota refresh's (#216): no answer can come
	m.auditRef(now, reason, e.PeerID, ref) // ref: the message's inner id
	m.dirty = true
	if reason == "undelivered_removed" && m.removingOwn && !NoticeOwnRemoval {
		return // the member's own removal: audited, not told (#7806)
	}
	if e.Unconfirmed {
		// Told at its late deposit that it may not have been delivered: any
		// end since is audited, not told again; "couldn't be delivered"
		// would overstate it, as it may have arrived (lead, #7906).
		return
	}
	kind := NoticeNotDelivered
	if reason == "undelivered_window" {
		kind = NoticeUnconfirmed
	}
	m.notice(e, typ, kind, ref, now)
}

// unconfirmedLate tells the member, once, that e may not have been
// delivered: it goes as it is with a ts older than RestampAfter, and the
// relay's hold may take it past the peer's 16 days (the late window, lead
// a #7901). It is audited (unconfirmed_late) and still deposited. Only the
// member's own messages are told or audited (not upkeep).
//
// Once per stored state: Unconfirmed is stored by the drain's write after
// the deposit; a crash before it can tell the member again after the
// restart (told twice, never not at all).
func (m *Manager) unconfirmedLate(e *OutboxEntry, now time.Time) {
	if e.Unconfirmed {
		return
	}
	e.Unconfirmed, m.dirty = true, true
	typ := m.entryType(e)
	if !memberMessage(e, typ) {
		return
	}
	m.auditRef(now, "unconfirmed_late", e.PeerID, e.InnerID)
	m.notice(e, typ, NoticeUnconfirmed, e.InnerID, now)
}

// notice records the member's feed item for e, if it is the member's own
// message to a connection (or one gone).
func (m *Manager) notice(e *OutboxEntry, typ, kind, ref string, now time.Time) {
	p := m.peer(e.PeerID)
	if (p != nil && p.Kind != KindConnection) || !memberMessage(e, typ) {
		return
	}
	// The connection's name as the vault has it now (its display name, else
	// its first and last name: noticeName), so that the app can name a
	// connection that is gone (vault-local: the feed only).
	name := noticeName(p)
	m.record(Activity{Kind: kind, ConnectionID: e.PeerID, Name: name, Ref: ref, Feed: true, Batch: NoticeWindow}, now)
}

// reconnectFailed counts a failed try of a reconnect to p naming epoch
// named (§3.4.1 "The reconnect bound": a try fails only when its handshake
// expires unanswered; a refusal is silent and not counted): at the third
// for the same named epoch the connection goes stale (with
// connection.stale and its feed item). Every reconnect counts, whatever
// started it. Each expired one's tokens were revoked already.
func (m *Manager) reconnectFailed(p *Peer, named []byte, now time.Time) {
	if p.Kind != KindConnection {
		return
	}
	if p.RC == nil || !bytes.Equal(p.RC.Epoch, named) {
		p.RC = &ReconnectCount{Epoch: append([]byte(nil), named...)}
	}
	p.RC.Tries++
	m.dirty = true
	if p.RC.Tries >= ReconnectTries {
		m.markStale(p, now)
	}
}

// tickDemoted: while the current epoch is demoted and no handshake that
// would replace it is open (the last one expired, its tokens revoked), a
// new one is started (§3.4.1: Q sends nothing until a new epoch is
// established, so it keeps trying to establish one; one at a time, each
// bounded by the handshake lifetime).
func (m *Manager) tickDemoted(p *Peer, now time.Time) {
	if p.Kind != KindConnection || p.State != PeerActive || p.suspended() || p.Pending != nil ||
		m.hasOutgoing(p.ID, handshake.PurposeReconnect) || !m.currentDemoted(p) {
		return
	}
	if !m.canReconnect(p, now) {
		if noReconnectToken(p, now) {
			m.markStale(p, now) // no reconnect token left: no way back (review RR2-3)
		}
		return // until something changes (an answer settles): no-op
	}
	m.restartAfterDemotion(p, now)
}

// restartAfterDemotion: the current epoch was demoted (an old copy's):
// nothing more is sent in it, and a new epoch is made (a reconnect naming
// the newest epoch not demoted; a device: none can be made from it, so the
// device pairs again, as §6.7).
//
// 0.86.5 (vettid.org #548): the epoch named is the newest of P's that has
// been current here and is neither demoted nor destroyed (an abandoned
// pending epoch never was current); with none, the connection goes stale.
func (m *Manager) restartAfterDemotion(p *Peer, now time.Time) {
	if p.Kind != KindConnection {
		return
	}
	for i := len(p.Epochs) - 1; i >= 0; i-- {
		e := p.Epochs[i]
		if !e.Demoted && !e.Pending && !e.Abandoned && !e.Destroyed {
			m.reconnectNaming(p, e.ID, "demoted", now)
			return
		}
	}
	m.markStale(p, now)
}

// demotedMeta is the record of the epoch current in p's keyring if it is
// demoted, or nil (the keyring's current epoch, review RR2-1).
func (m *Manager) demotedMeta(p *Peer) *EpochMeta {
	kr := m.sessions[p.ID]
	if kr == nil || kr.Current() == nil {
		return nil
	}
	id := kr.Current().ID()
	if e := p.epochMeta(id[:]); e != nil && e.Demoted {
		return e
	}
	return nil
}

func (m *Manager) currentDemoted(p *Peer) bool { return m.demotedMeta(p) != nil }

// canReconnect reports whether a reconnect to p could start now: a valid
// reconnect token, no answer of ours to its reconnect awaiting hs.fin
// (between persons), its kem readable.
func (m *Manager) canReconnect(p *Peer, now time.Time) bool {
	if p.Kind != KindConnection || noReconnectToken(p, now) {
		return false
	}
	if !p.isService() && len(m.answeredReconnects(p)) > 0 {
		return false
	}
	_, err := suite.ParsePublicKey(p.KEM)
	return err == nil
}

// h5 (§3.4.1 H5, 0.86.0): whenever the current ik for p changes, the
// vault's open handshakes with p pinned to an ik no longer current are
// abandoned and started again (a pending epoch included), and its
// answers awaiting hs.fin whose pinned ik is no longer current are
// dropped.
func (m *Manager) h5(p *Peer, now time.Time) {
	rekey, reconnect := false, false
	for _, id := range sortedKeys(m.st.Outgoing) {
		og, sortedOK := m.st.Outgoing[id]
		if !sortedOK {
			continue // removed earlier in this loop
		}
		if og.New != nil || og.PeerID != p.ID || og.Replaced || bytes.Equal(og.Init.ResponderIK, p.IK) {
			continue
		}
		rekey = rekey || og.Purpose == handshake.PurposeRekey
		reconnect = reconnect || og.Purpose == handshake.PurposeReconnect
		m.abandonOutgoing(id, now)
	}
	if pe := p.Pending; pe != nil {
		if e := p.epochMeta(pe.ID); e != nil && !bytes.Equal(e.Signer, p.IK) {
			m.abandonPending(p, "h5", false, now)
			if pe.Purpose == handshake.PurposeReconnect {
				reconnect = true // its tokens were revoked: a reconnect brings fresh ones
			} else {
				rekey = true
			}
		}
	}
	for _, id := range sortedKeys(m.st.Awaiting) {
		aw, sortedOK := m.st.Awaiting[id]
		if !sortedOK {
			continue // removed earlier in this loop
		}
		if aw.New == nil && aw.PeerID == p.ID && aw.Signer != nil && !bytes.Equal(aw.Signer, p.IK) &&
			(aw.Reconnect == nil || !aw.Reconnect.Fork) {
			m.abandonAwaiting(id, now)
		}
	}
	if m.noLinkRestart {
		return // the caller's own handshake establishes the next epoch
	}
	switch {
	case reconnect:
		m.startReconnect(p, now)
	case rekey:
		m.startRekey(p, now)
	}
}

// forkEpoch is §3.4.1 "Fork by ctx" for a rekey or reconnect from P whose
// ctx names epoch ctx: the current or confirmed epoch is ordinary; one
// older than the confirmed epoch, where an epoch after it up to the
// confirmed one has an ancestor of P's ik as its signer, is fork
// evidence. There is no exception for an epoch the vault began that
// became current; one it began and abandoned while pending, and one
// demoted with its received flag clear, are skipped (0.88.2, owner
// decisions a).
//
// The ancestors are those of the ik the message reaches (Table B,
// reached included): the stored chain's and the old_ik of every link the
// message carries that Q has not yet followed (reached, from reachedLinks).
func (p *Peer) forkEpoch(ctx []byte, reached []*handshake.Rotation) bool {
	if bytes.Equal(ctx, p.LastEpochID) || bytes.Equal(ctx, p.confirmedID()) {
		return false
	}
	ic, ik := p.epochIndex(ctx), p.epochIndex(p.confirmedID())
	if ic < 0 || ik <= ic {
		return false
	}
	for _, e := range p.Epochs[ic+1 : ik+1] {
		if e.Mine && e.Abandoned {
			// (0.88.2, owner decision a) an epoch the vault began and
			// abandoned while pending never became current: P may never
			// have activated it, so it is no evidence.
			continue
		}
		if e.Demoted && !e.GotFromPeer {
			// (0.88.2 at c91810f, owner decision a) an epoch demoted (K4,
			// K7) with its received flag clear is no evidence either; one
			// with its flag set suspended at its demotion.
			continue
		}
		if p.ancestor(e.Signer) {
			return true
		}
		for _, r := range reached {
			if bytes.Equal(r.OldIK, e.Signer) {
				return true
			}
		}
	}
	return false
}

// reachedLinks returns the links of rots (a handshake's rotations) that
// the vault has not yet followed, when the chain resolves from p's stored
// ik (Table B "reached"); nil otherwise.
func (p *Peer) reachedLinks(rots []*handshake.Rotation) []*handshake.Rotation {
	if len(rots) == 0 {
		return nil
	}
	_, _, n, err := handshake.ResolveChainKnown(p.IK, parseRotations(p.Chain), rots)
	if err != nil {
		return nil
	}
	return rots[n:]
}

// rekeyOtherEpoch judges a rekey hs.init under an epoch that is neither
// current nor the confirmed one, once the hs.init has passed
// rekeyPrecheck: fork evidence (§3.4.1 "Fork by ctx") suspends. The
// hs.init is not answered either way.
func (m *Manager) rekeyOtherEpoch(p *Peer, ep *handshake.Epoch, rots []*handshake.Rotation, now time.Time) {
	if p.Kind != KindConnection {
		return
	}
	id := ep.ID()
	if p.forkEpoch(id[:], p.reachedLinks(rots)) {
		m.suspendForkRef(p, "epoch", now)
	}
}

// rekeyPrecheck applies, before anything is changed, every check of a
// rekey hs.init that does not depend on the outcome (what AcceptRekey and
// the responder's initiator check would refuse): it parses, is a rekey,
// names the epoch it travels under, is within the durable ts window,
// comes from the relay key on record (= from.relay.pk), and its from.ik
// is the stored ik or reached through the links it carries.
func (m *Manager) rekeyPrecheck(p *Peer, in *envelope.Inner, ep *handshake.Epoch, sender []byte, now time.Time) error {
	body, err := handshake.ParseInit(in.Body)
	if err != nil {
		return err
	}
	if body.Purpose != handshake.PurposeRekey || body.Ctx != handshake.EpochCtx(ep.ID()) {
		return handshake.ErrCtx
	}
	if err := in.CheckTime(now, true); err != nil {
		return err
	}
	if !bytes.Equal(sender, m.recordRelayKey(p, sender)) || !bytes.Equal(sender, body.From.Relay.PK) {
		return handshake.ErrSender
	}
	if len(body.Rotations) == 0 {
		if !bytes.Equal(body.From.IK, p.IK) {
			return handshake.ErrIdentity
		}
		return nil
	}
	final, _, _, err := handshake.ResolveChainKnown(p.IK, parseRotations(p.Chain), body.Rotations)
	if err != nil || !bytes.Equal(final, body.From.IK) {
		return handshake.ErrIdentity
	}
	return nil
}

// --- the rotating side ---

// identityRotateBody is identity.rotate to p (S8, 0.86.0): `rotation`, the
// newest link, and `rotations`, the whole chain since the signer of the
// epoch it travels in.
func (m *Manager) identityRotateBody(p *Peer) []byte {
	links := m.ownRotationsSince(p.OwnChainAtEpoch)
	if len(links) == 0 { // 0ee0078 core.go:744: `rotation` only
		return nil
	}
	last := links[len(links)-1]
	arr := []byte{'['}
	for i, r := range links {
		if i > 0 {
			arr = append(arr, ',')
		}
		arr = append(arr, r.Marshal()...)
	}
	return strictjson.NewBuilder().Raw("rotation", last.Marshal()).Raw("rotations", append(arr, ']')).Bytes()
}

// s5 is the vault's own rotation's step for p (S5, 0.86.0): its own open
// rekeys and reconnects and its pending epoch are abandoned (started again
// after identity.rotate); its answers awaiting hs.fin are dropped (their
// epochs would be signed by the superseded ik).
func (m *Manager) s5(p *Peer, now time.Time) (reconnect bool) {
	for _, id := range sortedKeys(m.st.Outgoing) {
		og, sortedOK := m.st.Outgoing[id]
		if !sortedOK {
			continue // removed earlier in this loop
		}
		if og.New != nil || og.PeerID != p.ID || og.Replaced {
			continue
		}
		reconnect = reconnect || og.Purpose == handshake.PurposeReconnect
		m.abandonOutgoing(id, now)
	}
	if pe := p.Pending; pe != nil {
		reconnect = reconnect || pe.Purpose == handshake.PurposeReconnect
		m.abandonPending(p, "s5", false, now)
	}
	for _, id := range sortedKeys(m.st.Awaiting) {
		aw, sortedOK := m.st.Awaiting[id]
		if !sortedOK {
			continue // removed earlier in this loop
		}
		if aw.New == nil && aw.PeerID == p.ID {
			m.abandonAwaiting(id, now)
		}
	}
	return reconnect
}

// idResend is S5's resend (0.86.0): a session message from p under an
// epoch whose own-side signer is an ancestor of the vault's ik, with an
// inner ts more than 1 hour after the vault's rotation, means p missed
// it: identity.rotate goes again with the whole chain, at most 3 times
// per peer per rotation and once an hour.
func (m *Manager) idResend(p *Peer, ep *handshake.Epoch, in *envelope.Inner, now time.Time) {
	if p.Kind != KindConnection || ep == nil || len(m.st.Rotations) == 0 || m.st.RotatedAt.IsZero() {
		return
	}
	id := ep.ID()
	e := p.epochMeta(id[:])
	if e == nil || e.OwnChain >= len(m.st.Rotations) || !in.TS.After(m.st.RotatedAt.Add(time.Hour)) {
		return
	}
	r := p.IDResend
	if r == nil || r.Rotation != len(m.st.Rotations) {
		r = &IDResend{Rotation: len(m.st.Rotations)}
		p.IDResend = r
	}
	if r.N >= 3 || now.Sub(r.At) < time.Hour {
		return
	}
	links := m.ownRotationsSince(e.OwnChain)
	if len(links) == 0 {
		return
	}
	arr := []byte{'['}
	for i, l := range links {
		if i > 0 {
			arr = append(arr, ',')
		}
		arr = append(arr, l.Marshal()...)
	}
	body := strictjson.NewBuilder().Raw("rotation", links[len(links)-1].Marshal()).Raw("rotations", append(arr, ']')).Bytes()
	if m.sendTo(p, "identity.rotate", body, now) != "" {
		r.N++
		r.At = now
		m.dirty = true
	}
}

// noticeName is the name a "not delivered" notice carries (owner a, GC
// #7862): the connection's display name, or else the first and last name
// its profile always shares (§6.2); "" when neither can be read. A display
// name of only spaces counts as none.
func noticeName(p *Peer) string {
	if p == nil {
		return ""
	}
	if n := strings.TrimSpace(p.Name); n != "" {
		return n
	}
	if len(p.Profile) == 0 {
		return ""
	}
	o, err := strictjson.ParseObject(p.Profile)
	if err != nil {
		return ""
	}
	var parts []string
	for _, k := range []string{"first_name", "last_name"} {
		if v, _, _ := o.OptString(k); strings.TrimSpace(v) != "" {
			parts = append(parts, strings.TrimSpace(v))
		}
	}
	// Trimmed again after the cut, which may end on a space.
	return strings.TrimSpace(truncateUTF8(strings.Join(parts, " "), 128))
}
