package vault

import (
	"bytes"
	"strconv"
	"time"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
)

// Toward a peer without the gate (VAULT-MESSAGING 0.86.0, §6.3.1
// "Deployment"): the initiator activates at hs.fin as before, but keeps
// the old epoch (send keys, rk and receive keys) and a copy of each durable
// message it sends under the new one until it receives anything under the
// new epoch, at most 48 days; if the peer meanwhile shows that it never
// activated, the initiator reverts. And rule E's and rule L's reconnects,
// tried again up to 3 times; refused or the last failing, the connection
// goes stale.

// The revert's cap on kept copies (§6.3.1 "Deployment"; owner decision
// of 2026-11-05, replacing 10,000 copies / 64 MiB): at most 256 copies and
// 1 MiB per connection, and 8 MiB per vault in all. Past a connection's
// cap its oldest copy is dropped; past the vault's, the vault's oldest
// copy (whichever connection holds it). A copy's size is its inner
// plaintext, which for content sent by claim-check holds only the
// reference. The figures live here only.
const (
	RevertMaxCopies     = 256
	RevertMaxBytes      = 1 << 20
	RevertMaxVaultBytes = 8 << 20
	// RevertClaimCheck: while copies are kept toward a peer, content over
	// 64 KiB goes to it by claim-check (0.86.1, §5.5's SHOULD a MUST), so
	// a copy holds the reference. This release has no vault-side
	// claim-check upload for its own messages: such a message is sent
	// inline as before and its copy is not kept (counted as dropped).
	RevertClaimCheck = 64 << 10
)

// revertStore keeps the copies (§6.3.1 "Deployment"). The one
// implementation keeps them in the peers' records in the sealed state; the
// interface is the seam for moving them out of it without touching the
// revert itself. peers are every peer of the vault (for the vault-wide
// cap).
type revertStore interface {
	// add keeps c for p, applying the caps.
	add(p *Peer, c RevertCopy, peers []*Peer)
	// take returns p's copies, oldest first, and how many the caps dropped,
	// and forgets them.
	take(p *Peer) ([]RevertCopy, int)
	// drop forgets p's copies.
	drop(p *Peer)
	// expire forgets p's copies whose exp has passed (not counted as
	// dropped).
	expire(p *Peer, now time.Time)
}

// stateRevertStore keeps copies in Peer.Revert.
type stateRevertStore struct{}

func dropOldest(r *RevertKeep) {
	r.Bytes -= len(r.Copies[0].Inner)
	r.Copies[0] = RevertCopy{}
	r.Copies = r.Copies[1:]
	r.Dropped++
}

func (stateRevertStore) add(p *Peer, c RevertCopy, peers []*Peer) {
	r := p.Revert
	r.Copies = append(r.Copies, c)
	r.Bytes += len(c.Inner)
	for len(r.Copies) > RevertMaxCopies || r.Bytes > RevertMaxBytes {
		dropOldest(r)
	}
	for {
		total := 0
		var oldest *RevertKeep
		for _, q := range peers {
			if q.Revert == nil {
				continue
			}
			total += q.Revert.Bytes
			if len(q.Revert.Copies) > 0 && (oldest == nil || q.Revert.Copies[0].Seq < oldest.Copies[0].Seq) {
				oldest = q.Revert
			}
		}
		if total <= RevertMaxVaultBytes || oldest == nil {
			return
		}
		dropOldest(oldest)
	}
}

func (stateRevertStore) take(p *Peer) ([]RevertCopy, int) {
	r := p.Revert
	c, d := r.Copies, r.Dropped
	r.Copies, r.Bytes, r.Dropped = nil, 0, 0
	return c, d
}

func (stateRevertStore) expire(p *Peer, now time.Time) {
	r := p.Revert
	if r == nil {
		return
	}
	kept := r.Copies[:0]
	for _, c := range r.Copies {
		if !c.Exp.IsZero() && !now.Before(c.Exp) {
			r.Bytes -= len(c.Inner)
			continue
		}
		kept = append(kept, c)
	}
	for i := len(kept); i < len(r.Copies); i++ {
		r.Copies[i] = RevertCopy{}
	}
	r.Copies = kept
}

func (stateRevertStore) drop(p *Peer) {
	if r := p.Revert; r != nil {
		r.Copies, r.Bytes = nil, 0
	}
}

// copies is the store in use.
var copies revertStore = stateRevertStore{}

// startRevertKeep begins the keep after an ungated activation of newID
// that superseded oldID.
func (m *Manager) startRevertKeep(p *Peer, oldID, newID []byte, oldChain int, now time.Time) {
	p.Revert = &RevertKeep{Old: append([]byte(nil), oldID...), New: append([]byte(nil), newID...), FinAt: now,
		Until: now.Add(ConfirmedKeysFor), OldOwnChain: oldChain}
	m.dirty = true
}

// keepCopy keeps a copy of a durable message sent to p under the new
// epoch while a revert is possible. The caps drop the oldest copy.
func (m *Manager) keepCopy(p *Peer, in *envelope.Inner, wake string) {
	r := p.Revert
	if r == nil || !bytes.Equal(p.LastEpochID, r.New) {
		return
	}
	if te := m.registry[in.Type]; te != nil && te.spec.Ephemeral {
		return // ephemeral: never re-sealed
	}
	c := *in
	c.Seq = 0
	j, err := c.Marshal(envelope.ModeSealed) // without seq; the inner id is kept
	if err != nil {
		return
	}
	if len(j) > RevertClaimCheck {
		// Over 64 KiB, whoever's content it is: not copied (review 8; this
		// release cannot send it by claim-check), counted as dropped.
		r.Dropped++
		m.note(m.now(), "revert_copy_too_large", p.ID)
		m.dirty = true
		return
	}
	m.st.RevertSeq++
	copies.add(p, RevertCopy{Inner: j, Wake: wake, Seq: m.st.RevertSeq, Exp: in.Exp}, m.allPeers())
	m.dirty = true
}

// keepToHeld ends a revert keep other than by an accepted message under
// the new epoch (0.86.6 S1: rule E destroying it, a demotion, own_copy, a
// later activation): the kept messages go into the held queue, sealed with
// a new ts and their inner ids under the next current epoch (expired ones
// skipped), connection.epoch_reverted is audited (ref: the copies the caps
// dropped), and the copies are dropped. keepOld: the old epoch is being
// made current again (its keys are not released).
func (m *Manager) keepToHeld(p *Peer, keepOld bool, now time.Time) {
	r := p.Revert
	if r == nil {
		return
	}
	kept, dropped := copies.take(p)
	held := 0
	for _, c := range kept {
		in, err := envelope.ParseInner(c.Inner, envelope.ModeSealed)
		if err != nil {
			continue
		}
		if !in.Exp.IsZero() && !now.Before(in.Exp) {
			m.audit(now, "held_expired", p.ID) // as a held entry that expires (0.86.6)
			continue
		}
		m.holdInner(p, in, c.Wake)
		held++
	}
	ref := ""
	if dropped > 0 {
		ref = strconv.Itoa(dropped)
	}
	switch {
	case held > 0:
		// The revert's History line ("<connection name>: some messages were
		// resent."), only when a copy was held (0.86.6).
		m.record(Activity{Kind: "connection.epoch_reverted", ConnectionID: connID(p), DeviceID: devID(p), Ref: ref, Audit: true}, now)
	case dropped > 0:
		m.note(now, "epoch_reverted_dropped_"+ref, p.ID) // copies lost to the caps, none held: no History line
	}
	if kr := m.sessions[p.ID]; kr != nil && !keepOld {
		kr.Release(epochIDOf(r.Old), now.Add(handshake.ReceiveKeyRetention))
	}
	p.Revert = nil
	m.dirty = true
}

// endRevertKeep ends the keep: the old epoch goes as any previous epoch
// (its receive keys 16 days from now), and the copies are dropped.
func (m *Manager) endRevertKeep(p *Peer, now time.Time) {
	r := p.Revert
	if r == nil {
		return
	}
	if kr := m.sessions[p.ID]; kr != nil {
		kr.Release(epochIDOf(r.Old), now.Add(handshake.ReceiveKeyRetention))
	}
	copies.drop(p)
	p.Revert = nil
	m.dirty = true
}

// revert: the peer sent a message under the old epoch more than T + 2
// days after hs.fin, so it never activated the new one. In one write,
// before that message is processed: the new epoch is destroyed and the
// old one is current again; every kept message is sealed again in the old
// epoch with the same inner id and a new ts, skipping any whose exp has
// passed; connection.epoch_reverted is audited (ref: the copies the cap
// dropped, if any); then the peer's rekey is answered (rekeyIn), or the
// vault starts one from the old epoch.
//
// The new epoch is destroyed as rule E destroys (§6.3.1): it records the
// inner ts of the message that caused the revert, and keeps its receive
// key 16 days, so that a later message under it is authenticated: with a
// later ts it is fork evidence (or, toward a peer without hs_confirm, a
// reconnect naming it), with an earlier one it is refused
// (superseded_epoch).
func (m *Manager) revert(p *Peer, rekeyIn bool, ts, now time.Time) {
	r := p.Revert
	kr := m.sessions[p.ID]
	if r == nil || kr == nil {
		return
	}
	if !kr.Reinstate(epochIDOf(r.Old), now) {
		// The old epoch cannot be current again: the keep ends, its copies
		// held for the next epoch (S1).
		m.keepToHeld(p, false, now)
		return
	}
	kept, dropped := copies.take(p)
	p.Revert = nil
	for _, o := range m.st.Outbox {
		if !o.Done && o.PeerID == p.ID && bytes.Equal(o.FinEpoch, r.New) {
			o.Done = true // its hs.fin, if not yet sent, goes with it (review)
		}
	}
	if e := p.epochMeta(r.New); e != nil {
		e.Destroyed, e.DestroyTS, e.Superseded = true, ts, now
	}
	if e := p.epochMeta(r.Old); e != nil {
		e.Superseded = time.Time{}
	}
	p.LastEpochID = append([]byte(nil), r.Old...)
	p.OwnChainAtEpoch = r.OldOwnChain
	if bytes.Equal(p.Confirmed, r.New) {
		p.Confirmed = append([]byte(nil), r.Old...)
	}
	if p.isService() {
		// A reverted epoch never enters the history (§6.6, 0.86.0).
		kept := p.History[:0]
		for _, h := range p.History {
			if !bytes.Equal(h.ID, r.New) {
				kept = append(kept, h)
			}
		}
		p.History = kept
		if n := len(p.History); n > 0 && bytes.Equal(p.History[n-1].ID, r.Old) {
			p.History[n-1].Superseded = time.Time{}
		}
	}
	for _, c := range kept {
		in, err := envelope.ParseInner(c.Inner, envelope.ModeSealed)
		if err != nil || !in.Exp.IsZero() && !now.Before(in.Exp) {
			continue
		}
		in.TS = now // same inner id (receivers dedupe by it, §8.2), a new ts
		raw, err := m.sealFor(p, kr.Current(), in)
		if err != nil {
			continue
		}
		m.queueDeposit(&OutboxEntry{PeerID: p.ID, RelayURL: p.Relay.URL, Mailbox: p.Relay.Mailbox, Payload: raw, Wake: c.Wake}, now)
	}
	ref := ""
	if dropped > 0 {
		ref = strconv.Itoa(dropped)
	}
	// History (app): "<connection name>: some messages were resent." (NEW).
	m.record(Activity{Kind: "connection.epoch_reverted", ConnectionID: connID(p), DeviceID: devID(p), Ref: ref, Audit: true}, now)
	for id, og := range m.st.Outgoing {
		if og.New == nil && og.PeerID == p.ID && og.Purpose == handshake.PurposeRekey {
			m.abandonOutgoing(id, now)
		}
	}
	m.dirty = true
	if !rekeyIn {
		m.startRekey(p, now)
	}
}

// tickRevert ends a keep past its 48 days.
func (m *Manager) tickRevert(p *Peer, now time.Time) {
	if r := p.Revert; r != nil && now.After(r.Until) {
		m.endRevertKeep(p, now)
	} else if r != nil {
		copies.expire(p, now)
	}
}

// reconnectNaming starts a reconnect to connection p naming epoch ctx, for
// rule E or rule L: the vault's own rekey and its unfinished rekey answers
// to p are dropped (the peer did not finish them, and they would block
// it), and its pending epoch is abandoned.
func (m *Manager) reconnectNaming(p *Peer, ctx []byte, why string, now time.Time) bool {
	if p.Kind != KindConnection || p.State != PeerActive || p.suspended() || m.hasOutgoing(p.ID, handshake.PurposeReconnect) ||
		!m.canReconnect(p, now) {
		return false // nothing is abandoned for a reconnect that cannot start
	}
	for id, og := range m.st.Outgoing {
		if og.New == nil && og.PeerID == p.ID && og.Purpose == handshake.PurposeRekey {
			m.abandonOutgoing(id, now)
		}
	}
	for id, aw := range m.st.Awaiting {
		if aw.New == nil && aw.PeerID == p.ID && aw.Purpose == handshake.PurposeRekey {
			m.abandonAwaiting(id, now)
		}
	}
	if p.Pending != nil {
		m.abandonPending(p, why, false, now)
	}
	og := m.startReconnectCtx(p, ctx, now)
	if og == nil {
		m.note(now, "reconnect_not_started", p.ID)
		return false
	}
	og.Named = append([]byte(nil), ctx...)
	if why == ruleRCE || why == ruleRCL {
		og.RuleRC = why // tried again up to 3 times; refused or the last: stale
	} else {
		og.Why = why
	}
	m.note(now, "reconnect_"+why, p.ID)
	return true
}

// ruleRCExpired handles a rule-E or rule-L reconnect that expired
// unanswered: it is tried again with the same ctx, up to 3 tries per
// epoch within the reconnect token's quota; after the last, the
// connection goes stale.
func (m *Manager) ruleRCExpired(p *Peer, og *OutgoingHS, now time.Time) {
	tries := 0
	switch og.RuleRC {
	case ruleRCE:
		if e := p.epochMeta(og.Named); e != nil {
			e.RCTries++
			tries = e.RCTries
		} else {
			tries = RuleRCTries
		}
	case ruleRCL:
		if p.RuleL == nil {
			p.RuleL = &RuleLState{}
		}
		p.RuleL.Tries++
		tries = p.RuleL.Tries
	}
	if tries <= RuleRCTries && m.reconnectNaming(p, og.Named, og.RuleRC, now) {
		return
	}
	m.markStale(p, now)
}

// markStale makes connection p stale (one path for every cause of
// 0.85.4: O3a, the gate's deadline, rule E's and rule L's reconnects):
// audited connection.stale with its feed item ("Your connection with
// <name> stopped working. Send them a new invitation.", app text), so a
// new invitation from that peer is accepted (§6.4).
func (m *Manager) markStale(p *Peer, now time.Time) {
	if p.State == PeerStale {
		return
	}
	p.State = PeerStale
	for _, e := range m.st.Outbox {
		if !e.Done && e.PeerID == p.ID && e.Held != nil {
			e.Done, e.Held = true, nil // held for an epoch that will not come (review 2)
		}
	}
	m.abandonHandshakes(p, true, true, now)
	if p.Pending != nil {
		m.abandonPending(p, "stale", false, now)
	}
	m.notifyDevices("connection.event", connEvent(p.ID, "stale"), "", now)
	m.record(Activity{Kind: "connection.stale", ConnectionID: p.ID, Ref: p.ID, Audit: true, Feed: true}, now)
	m.dirty = true
}
