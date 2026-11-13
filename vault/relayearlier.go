package vault

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"time"

	"github.com/vettid/vettid-relay/relayauth"

	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Relay-key rotation, the receiving side's state (VAULT-MESSAGING 0.90.3
// §3.4.1 "Terms": relay-key states and cut-offs). Everything here acts only
// with Options.RelayKeyRotation; without it a peer has no earlier relay
// key and every sender other than the relay key on record is foreign.

// EarlierRelay is a relay key of the peer's that the vault followed it away
// from (§3.4.1 "Relay-key states": earlier), kept with its followed relay
// link and its cut-off until no token the vault issued to it can still
// deposit.
type EarlierRelay struct {
	// Relay is the key and its mailbox. URL is the peer's relay as the
	// vault had it on record, or empty for a key the vault never had on
	// record (one passed in a chain of several links).
	Relay PeerRelay `json:"relay"`
	// Link is the followed relay link from this key (its old is Relay.PK).
	Link json.RawMessage `json:"link"`
	// The cut-off: the position of the message with which the vault
	// followed the link, its deposited_at and msg_id, and the vault's own
	// mailbox it was collected from (§3.4.1 "Cut-off").
	CutAt      time.Time `json:"cut_at,omitzero"`
	CutMsg     string    `json:"cut_msg,omitempty"`
	CutMailbox string    `json:"cut_mailbox,omitempty"`
}

// RelayConflict is Peer.RelayConflict: two successors of one relay key of
// an owner device or agent (§3.4.1 rule C, "Between a vault and its own
// device or agent"). Kept is the first successor, which stays; Refused the
// other.
type RelayConflict struct {
	At      time.Time `json:"at"`
	Old     []byte    `json:"old"`
	Kept    []byte    `json:"kept"`
	Refused []byte    `json:"refused"`
}

// MaxRelaySeen bounds Peer.RelaySeen (§3.4.1 rule C: at most 32 seen links
// per peer; RK12 "within its cap of 32 per peer"). A link past it is not
// recorded. The identity links' Seen has its own cap of 32 (MaxSeen).
const MaxRelaySeen = 32

// relayKeyState is a message sender's relay-key state (§3.4.1 "Terms").
type relayKeyState int

const (
	relayForeign relayKeyState = iota
	relayCurrent
	relayEarlierBefore // an earlier key, deposited before its cut-off
	relayEarlierAfter  // an earlier key, deposited after its cut-off
)

// earlierRelay returns p's earlier relay key pk, or nil.
func (p *Peer) earlierRelay(pk []byte) *EarlierRelay {
	for i := range p.EarlierRelays {
		if suite.EqualPublic(p.EarlierRelays[i].Relay.PK, pk) {
			return &p.EarlierRelays[i]
		}
	}
	return nil
}

// relayStateOf is the relay-key state of sender for the message being
// handled (its position is m.relayAt, m.msgID, collected from the vault's
// own mailbox). Without Options.RelayKeyRotation it is current or foreign.
func (m *Manager) relayStateOf(p *Peer, sender []byte) relayKeyState {
	if p == nil {
		return relayForeign
	}
	if suite.EqualPublic(sender, p.Relay.PK) {
		return relayCurrent
	}
	if !m.opt.RelayKeyRotation {
		return relayForeign
	}
	e := p.earlierRelay(sender)
	if e == nil {
		return relayForeign
	}
	// ASSUMPTION: the vault collects one mailbox, its current one, so the
	// message being handled was collected from m.st.Relay.Mailbox (here
	// and as the cut-off's mailbox in followRelayLinks). Once the vault
	// rotates its own relay key and collects its old mailbox too (§3.4
	// step 1, §3.4.1 "Order of processing"), the mailbox a message was
	// collected from must travel in Message and be used here and there;
	// that comes before the rotating side is built.
	if e.beforeCutoff(m.relayAt, m.msgID, m.st.Relay.Mailbox) {
		return relayEarlierBefore
	}
	return relayEarlierAfter
}

// beforeCutoff reports whether a message at (at, msgID), collected from the
// vault's mailbox mailbox, was deposited before e's cut-off (§3.4.1
// "Cut-off"): in the mailbox the cut-off was collected from, its msg_id
// is smaller than the cut-off's; in another mailbox, its deposited_at is
// not later than the cut-off's (the residual "same deposited_at" counts
// as before). A position that is not known (no msg_id) is after: fail
// closed.
func (e *EarlierRelay) beforeCutoff(at time.Time, msgID, mailbox string) bool {
	if mailbox == e.CutMailbox {
		if msgID == "" || e.CutMsg == "" {
			return false
		}
		return msgIDBefore(msgID, e.CutMsg)
	}
	if at.IsZero() || e.CutAt.IsZero() {
		return false
	}
	return !at.After(e.CutAt)
}

// msgIDBefore orders msg_ids within one mailbox (ULIDs; a shorter id sorts
// first, as posAfter does, so that counters compare as numbers).
func msgIDBefore(a, b string) bool {
	if len(a) != len(b) {
		return len(a) < len(b)
	}
	return a < b
}

// keepsRelayKey reports whether pk is p's current relay key or an earlier
// one the vault keeps.
func (p *Peer) keepsRelayKey(pk []byte) bool {
	return suite.EqualPublic(pk, p.Relay.PK) || p.earlierRelay(pk) != nil
}

// errRelayFollow is a follow the vault refuses to record.
var errRelayFollow = errors.New("vault: relay links cannot be followed")

// followRelayLinks records that the vault follows p's relay links, which
// lead from p's current relay key to the address to: in the state write
// of the message being handled, each passed key becomes earlier, with its
// link and this message's position as its cut-off, and to becomes p's
// current key (§3.4.1 rule U: "In one state write Q records the links,
// each passed key with this update's position as its cut-off, makes
// relay.pk current"; §3.4.2 RK8 "When Q follows", where the position is
// the hs.fin's or the hs.resp's).
//
// It is the entry point rule U (a relay.address.update) and RK8 (a
// reconnect) call once their own checks have passed: skipping the leading
// links already followed, RK5's ik requirement, rule T's tokens, the
// revocations of the tokens issued to the passed keys and RK6 are theirs.
// It records the keys only, and fails closed: a chain that does not verify
// from p's current key to to, or a new key the vault keeps for p (rule U,
// relay_rollback; I3: never a key it followed away from), changes nothing.
func (m *Manager) followRelayLinks(p *Peer, links []*handshake.RelayLink, to handshake.RelayAddr) error {
	if handshake.ValidateRelayAddr(to) != nil || handshake.VerifyRelayChain(p.Relay.PK, to.PK, links) != nil {
		return errRelayFollow
	}
	for _, l := range links {
		if p.keepsRelayKey(l.New) {
			return errRelayFollow
		}
	}
	for i, l := range links {
		r := PeerRelay{PK: append([]byte(nil), l.Old...), Mailbox: relayauth.MailboxID(ed25519.PublicKey(l.Old))}
		if i == 0 {
			r.URL, r.Mailbox = p.Relay.URL, p.Relay.Mailbox
		}
		// CutMailbox: the vault's current mailbox (see relayStateOf's
		// one-mailbox assumption).
		p.EarlierRelays = append(p.EarlierRelays, EarlierRelay{Relay: r, Link: l.Marshal(),
			CutAt: m.relayAt, CutMsg: m.msgID, CutMailbox: m.st.Relay.Mailbox})
	}
	p.Relay = PeerRelay{URL: to.URL, Mailbox: to.Mailbox, PK: append([]byte(nil), to.PK...)}
	pruneRelaySeen(p) // a followed link is no longer only seen
	m.dirty = true
	return nil
}

// pruneEarlierRelays drops the earlier relay keys no token the vault issued
// to them can still deposit with (§3.4.1 "Relay-key states"), and the seen
// relay links that no longer start at a key the vault keeps. It drops from
// the oldest end only: an entry goes when it and every older one can no
// longer deposit. A key kept for deposits keeps every later earlier key
// with its followed link, so that rule C still finds a second successor of
// any key a kept key's chain passed (an intermediate key the vault never
// issued a token to, for example). A token counts until its exp, unless
// the vault revoked it: rule U revokes the reconnect tokens of the keys it
// follows away from, and counting them would keep each earlier key for a
// reconnect token's 365 days, so the per-peer cap would allow only about
// 32 rotations a year. A deposit under a revoked token that the relay
// still took before its denylist request went through is then refused as
// foreign rather than judged by its cut-off: fail closed.
func (m *Manager) pruneEarlierRelays(now time.Time) {
	if !m.opt.RelayKeyRotation {
		return
	}
	for _, p := range m.allPeers() {
		if len(p.EarlierRelays) == 0 {
			continue
		}
		n := 0
		for n < len(p.EarlierRelays) && !m.issuedCanDeposit(p, p.EarlierRelays[n].Relay.PK, now) {
			n++
		}
		if n > 0 {
			p.EarlierRelays = append([]EarlierRelay(nil), p.EarlierRelays[n:]...)
			if len(p.EarlierRelays) == 0 {
				p.EarlierRelays = nil
			}
			pruneRelaySeen(p)
			m.dirty = true
		}
	}
}

// issuedCanDeposit reports whether a token the vault issued with sub pk is
// unexpired and not revoked: one it recorded as issued, or one minted in a
// handshake with p not yet recorded (a pending epoch's, an open hs.init's
// or hs.resp's; one revoked before that is recorded as denied). Only a
// denied reconnect token stops counting: rule U revokes those at a follow,
// and their year-long exp would keep the key. A denied standing token (a
// refresh denies the older ones) counts until its exp, since it can still
// deposit until the relay has taken the denylist request.
func (m *Manager) issuedCanDeposit(p *Peer, pk []byte, now time.Time) bool {
	sub := relayauth.EncodeKey(ed25519.PublicKey(pk))
	denied := map[string]bool{}
	for _, t := range m.st.Issued {
		if t.Denied && t.Kind == TokReconnect {
			denied[t.JTI] = true
		}
	}
	live := func(ts []IssuedToken) bool {
		for _, t := range ts {
			if t.Sub == sub && now.Before(t.Exp) && !(t.Denied && t.Kind == TokReconnect) && !denied[t.JTI] {
				return true
			}
		}
		return false
	}
	if live(m.st.Issued) || p.Pending != nil && live(p.Pending.Issued) {
		return true
	}
	for _, og := range m.st.Outgoing {
		if og.PeerID == p.ID && live(og.Issued) {
			return true
		}
	}
	for _, aw := range m.st.Awaiting {
		if aw.PeerID == p.ID && live(aw.Issued) {
			return true
		}
	}
	return false
}

// pruneRelaySeen keeps the seen relay links that are not followed and that
// start at a key the vault keeps for p or one a kept seen link reaches.
func pruneRelaySeen(p *Peer) {
	var links []*handshake.RelayLink
	for _, raw := range p.RelaySeen {
		if l, err := handshake.ParseRelayLink(raw); err == nil && !p.followedRelayLink(l) {
			links = append(links, l)
		}
	}
	reach := map[string]bool{string(p.Relay.PK): true}
	for _, e := range p.EarlierRelays {
		reach[string(e.Relay.PK)] = true
	}
	keep := make([]bool, len(links))
	for changed := true; changed; {
		changed = false
		for i, l := range links {
			if !keep[i] && reach[string(l.Old)] {
				keep[i], reach[string(l.New)], changed = true, true, true
			}
		}
	}
	var out []json.RawMessage
	for i, l := range links {
		if keep[i] {
			out = append(out, l.Marshal())
		}
	}
	p.RelaySeen = out
}

// followedRelayLink reports whether l is one of p's followed relay links.
func (p *Peer) followedRelayLink(l *handshake.RelayLink) bool {
	for _, e := range p.EarlierRelays {
		if f, err := handshake.ParseRelayLink(e.Link); err == nil && suite.EqualPublic(f.Old, l.Old) && suite.EqualPublic(f.New, l.New) {
			return true
		}
	}
	return false
}
