package vault

import (
	"bytes"
	"crypto/ed25519"
	"time"

	"github.com/vettid/vettid-vault/vms/suite"
)

// §3.4.2 RK7 (VAULT-MESSAGING 0.90.4), between two vaults: in Table A's
// row "Earlier, after its cut-off", two messages pass to Table B instead
// of being refused:
//   - an hs.confirm under an epoch that a handshake signed by the vault's
//     current ik for the peer established;
//   - an hs.fin for an answer the vault has open, when its sig_I verifies
//     under the ik the answer pinned and that ik is the vault's current ik
//     for the peer; its epoch is the one the hs.fin establishes.
//
// Each pass closes per epoch: once the vault has accepted, under that
// epoch or a later one, a message from a relay key of the peer's later
// than the message's sender. "Later" is establishment order at the vault,
// by the position of the message that established each epoch (EpochMeta
// EstAt, EstMsg; for an epoch the vault began, its hs.resp's), compared as
// in "Cut-off"; a tie is not later. Pending epochs and epochs abandoned
// while pending are not counted, except the pass's own. For an hs.fin, only
// epochs established at a later position than the hs.fin's own count, and
// it is judged when the hs.fin is processed. A closure is recorded when it
// happens and never undone, even if its epoch is later destroyed, demoted
// or ended; the records are kept while the peer has an earlier relay key.
// Only with Options.RelayKeyRotation; a device's relay key is not covered.
//
// What is recorded: a message accepted under an epoch (dispatch, once its
// handler is done and only if nothing refused it), and the hs.fin that
// establishes one (rk7Established). An hs.resp records nothing: the epoch
// it establishes is pending, and the message that confirms it is recorded
// when it is accepted.

// RelayClosure is one of RK7's records: a message from relay key Key was
// accepted under Epoch, which was established at position (EstAt, EstMsg).
type RelayClosure struct {
	Epoch  []byte    `json:"epoch"`
	EstAt  time.Time `json:"est_at,omitzero"`
	EstMsg string    `json:"est_msg,omitempty"`
	Key    []byte    `json:"key"`
}

// relayIndex is pk's place in p's chain of relay keys: an earlier key's
// index (oldest first), the current key after them, or -1 for a key the
// vault does not keep for p.
func (p *Peer) relayIndex(pk []byte) int {
	for i := range p.EarlierRelays {
		if suite.EqualPublic(p.EarlierRelays[i].Relay.PK, pk) {
			return i
		}
	}
	if suite.EqualPublic(p.Relay.PK, pk) {
		return len(p.EarlierRelays)
	}
	return -1
}

// laterThan reports whether position (at, msg) is later than (at2, msg2)
// for RK7: a position not known (no msg_id) counts as later, so that an
// unknown position closes rather than passes (fail closed).
func laterThan(at time.Time, msg string, at2 time.Time, msg2 string) bool {
	if msg == "" || msg2 == "" {
		return true
	}
	return posAfter(at, msg, at2, msg2)
}

// rk7Accepted records that a message from p deposited with sender was
// accepted under epoch id (it passed acceptFrom and the epoch's checks, or
// established it at an hs.fin). Only while p has an earlier relay key: a
// record of the current key is of use only once a key older than it is
// kept, and the oldest kept key is never later than anything.
func (m *Manager) rk7Accepted(p *Peer, id []byte, sender ed25519.PublicKey) {
	if !m.opt.RelayKeyRotation || p == nil || p.Kind != KindConnection || len(p.EarlierRelays) == 0 || len(id) == 0 {
		return
	}
	meta := p.epochMeta(id)
	si := p.relayIndex(sender)
	if meta == nil || si < 0 {
		return
	}
	r := RelayClosure{Epoch: append([]byte(nil), id...), EstAt: meta.EstAt, EstMsg: meta.EstMsg, Key: append([]byte(nil), sender...)}
	for _, x := range p.RelayClosures {
		if p.closureCovers(x, r) {
			return // nothing new
		}
	}
	out := []RelayClosure{r}
	for _, x := range p.RelayClosures {
		if !p.closureCovers(r, x) {
			out = append(out, x)
		}
	}
	p.RelayClosures = out
	m.dirty = true
}

// closureCovers reports whether record a closes every pass that record b
// closes: a's epoch is b's or established later, and a's key is not
// earlier than b's. b is then redundant (records are only made under
// epochs that are neither pending nor abandoned while pending: a message
// accepted under the vault's pending epoch confirms it first).
func (p *Peer) closureCovers(a, b RelayClosure) bool {
	ia, ib := p.relayIndex(a.Key), p.relayIndex(b.Key)
	if ia < 0 || ia < ib {
		return false
	}
	if bytes.Equal(a.Epoch, b.Epoch) || a.EstMsg == "" {
		return true
	}
	return b.EstMsg != "" && posAfter(a.EstAt, a.EstMsg, b.EstAt, b.EstMsg)
}

// rk7Closed reports whether the pass of a message from p deposited with
// sender is closed. For an hs.confirm, epoch is the epoch it travels under
// and (at, msg) that epoch's position; for an hs.fin (fin), epoch is nil
// and (at, msg) the hs.fin's own position, and only records of epochs
// established later than it count.
func (p *Peer) rk7Closed(epoch []byte, at time.Time, msg string, sender []byte, fin bool) bool {
	si := p.relayIndex(sender)
	for _, r := range p.RelayClosures {
		ri := p.relayIndex(r.Key)
		if ri < 0 || si >= 0 && ri <= si {
			continue // not a later key
		}
		own := !fin && bytes.Equal(r.Epoch, epoch)
		if e := p.epochMeta(r.Epoch); e != nil && !own && (e.Pending || e.Abandoned) {
			continue // not counted (a record is never made under one; kept for safety)
		}
		if own || laterThan(r.EstAt, r.EstMsg, at, msg) {
			return true
		}
	}
	return false
}

// rk7ConfirmPasses is RK7's first pass: an hs.confirm from connection p,
// under epoch id, deposited with an earlier relay key after its cut-off.
func (m *Manager) rk7ConfirmPasses(p *Peer, id []byte, sender ed25519.PublicKey) bool {
	if p.Kind != KindConnection || len(id) == 0 {
		return false
	}
	e := p.epochMeta(id)
	if e == nil || len(e.Signer) == 0 || !bytes.Equal(e.Signer, p.IK) {
		return false // not established by a handshake signed by the current ik
	}
	return !p.rk7Closed(id, e.EstAt, e.EstMsg, sender, false)
}

// rk7FinPasses is RK7's second pass, before sig_I is checked: an hs.fin
// for aw, an answer the vault has open to connection p, deposited with an
// earlier relay key after its cut-off, whose pinned ik is p's current ik,
// and whose pass is not closed at the hs.fin's own position. The caller
// then requires sig_I to verify under that ik (HandleFin).
func (m *Manager) rk7FinPasses(p *Peer, aw *AwaitingHS, sender ed25519.PublicKey) bool {
	if !m.opt.RelayKeyRotation || p == nil || aw == nil || aw.New != nil || p.Kind != KindConnection {
		return false
	}
	if m.relayStateOf(p, sender) != relayEarlierAfter {
		return false
	}
	if aw.Reconnect != nil && aw.Reconnect.Fork {
		// An answer kept as fork evidence (H5's "Exempt"; §6.6 "Fork
		// detection") passes whatever its pinned ik and its closure, so
		// that its hs.fin, if sig_I verifies under the pinned key, is
		// judged as fork evidence and suspends (finishReconnect); it never
		// establishes an epoch. Evidence first: a reading of this release;
		// the spec should confirm it.
		return true
	}
	if len(aw.Signer) != ed25519.PublicKeySize || !bytes.Equal(aw.Signer, p.IK) {
		return false
	}
	return !p.rk7Closed(nil, m.relayAt, m.msgID, sender, true)
}

// pruneRelayClosures drops RK7's records once p keeps no earlier relay
// key, and those of a key it no longer keeps (older than every kept one,
// so later than no sender).
func pruneRelayClosures(p *Peer) {
	if len(p.EarlierRelays) == 0 {
		p.RelayClosures = nil
		return
	}
	out := p.RelayClosures[:0]
	for _, r := range p.RelayClosures {
		if p.relayIndex(r.Key) >= 0 {
			out = append(out, r)
		}
	}
	if len(out) == 0 {
		out = nil
	}
	p.RelayClosures = out
}

// rk7Established records, for RK7, that an hs.fin from p deposited with
// sender established epoch id (if it did, and p is not suspended): the
// message that establishes an epoch counts as accepted under it (a reading
// of this release, the one that closes passes sooner; the spec should
// confirm).
func (m *Manager) rk7Established(p *Peer, id []byte, sender ed25519.PublicKey) {
	if p != nil && !p.suspended() && bytes.Equal(p.LastEpochID, id) {
		m.rk7Accepted(p, id, sender)
	}
}
