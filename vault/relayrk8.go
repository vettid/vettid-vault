package vault

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"time"

	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/suite"
)

// §3.4.2 RK8 (VAULT-MESSAGING 0.90.4), links in reconnects: the receiving
// side. A reconnect hs.init, or an hs.resp to the vault's own reconnect,
// deposited with a relay key of the peer's earlier than the one it
// announces (from.relay.pk, or the hs.resp's relay.pk) carries relay_links
// from the deposit key up to the announced key. Only with
// Options.RelayKeyRotation, between two vaults (a reconnect is a
// connection's).
//
// The order, for such a message from p deposited with sender:
//  1. Parse, before acceptFrom step 1: a fault in a link's form, the
//     count, or the chain's end (the first old not the deposit key, the
//     last new not the announced key) is refused relay_unlinked, and no
//     link of the message, identity or relay, is checked or kept by rule C
//     (§3.4.1 rule U, "Precedence", "When it is refused").
//  2. acceptFrom step 1: a suspended record keeps the relay links that
//     pass rule C as seen (RK12), and refuses.
//  3. Step 3: rule C on the identity links and the relay links; a chain
//     refused by rule U's checks (v, suite, old equal to new, a repeated
//     key, a bad signature, a break) is refused relay_unlinked, the
//     earlier valid links kept as seen by rule U's two lists.
//  4. Table A: with such links the message passes the rows "Current" and
//     "Earlier", before or after the cut-off ("When Q accepts it").
//  5. Rule U's checks that do not depend on the ik, each refusing with no
//     link followed (RK10): the announced key one the vault followed away
//     from (superseded_relay), the followed prefix, relay_rollback, the
//     cap of earlier keys, rule T on the message's `token` against the
//     announced key's mailbox (token_unusable). For an hs.init they run at
//     the hs.init (fail closed: none can heal) and again at its hs.fin.
//  6. RK5's ik requirement, before any identity link is applied.
//  7. In the write that processes the hs.resp after sig_R verifies, or
//     that establishes the reconnect at its verified hs.fin: the identity
//     links, then the relay links (followRelayLinks, with that message's
//     position as the cut-off, the message itself counting as before it),
//     then the tokens by rule T. After the write, as rule U: the reconnect
//     tokens issued to the passed keys are revoked, relay.token.issued goes
//     for the new key, the queued deposits move, and RK6 runs after the
//     establishment.
//
// An earlier key past its cut-off cannot move the ik here: unlike an
// update's, a reconnect's identity links are authenticated by sig_I or
// sig_R under the ik they lead to, which an old copy of the peer does not
// hold, so the exception rule U makes for an update's identity links
// (earlierAfterRotations) has no counterpart.

// rk8Applies reports whether a reconnect message from p carries relay
// links RK8 judges.
func (m *Manager) rk8Applies(p *Peer, links []*handshake.RelayLink) bool {
	return m.opt.RelayKeyRotation && p != nil && p.Kind == KindConnection && len(links) > 0
}

// rk8EndRefused is the parse-time end check that the library cannot make:
// the first old must be the deposit key (§3.4.1 rule U, "Precedence").
func rk8EndRefused(sender ed25519.PublicKey, links []*handshake.RelayLink) bool {
	return len(links) == 0 || links[0] == nil || !suite.EqualPublic(links[0].Old, sender)
}

// rk8Checks is step 5 above without the token: it returns the links still
// to follow (none when every one is already followed and the announced key
// is p's current one) and the refusal's reason, "" when they pass.
func (m *Manager) rk8Checks(p *Peer, links []*handshake.RelayLink, announced []byte) ([]*handshake.RelayLink, string) {
	if p.earlierRelay(announced) != nil {
		return nil, "superseded_relay" // the vault already followed p away from it
	}
	k := m.followedRelayPrefix(p, links)
	if k == len(links) {
		if !suite.EqualPublic(announced, p.Relay.PK) {
			return nil, "unexpected" // cannot occur: the last new followed is current or earlier
		}
		return nil, "" // the follow changes nothing
	}
	rest := links[k:]
	if !suite.EqualPublic(rest[0].Old, p.Relay.PK) {
		return nil, "relay_rollback"
	}
	for _, l := range rest {
		if p.keepsRelayKey(l.New) {
			return nil, "relay_rollback"
		}
	}
	if len(p.EarlierRelays)+len(rest) > MaxEarlierRelays {
		return nil, "unexpected" // the cap (MaxEarlierRelays), as rule U
	}
	return rest, ""
}

// rk8IKOK is RK5's ik requirement for a reconnect message whose ik (from.ik
// or the key sig_R verifies under) is ik and whose identity links are
// rots, judged before the links are applied: ik is p's current ik, or the
// links lead from it (after those already followed) to ik.
func rk8IKOK(p *Peer, ik []byte, rots []*handshake.Rotation) bool {
	if len(ik) != ed25519.PublicKeySize {
		return false
	}
	if bytes.Equal(ik, p.IK) {
		return true
	}
	final, _, _, err := handshake.ResolveChainKnown(p.IK, parseRotations(p.Chain), rots)
	return err == nil && bytes.Equal(final, ik)
}

// rk8Follow follows rest to the announced address in the state write of
// the message being handled (its position is the cut-off). The held
// tokens for the passed mailbox no longer count: the carried tokens for
// the new one are adopted at the epoch's confirmation, and until then the
// deposits on held tokens wait ("No reconnect while carried tokens wait"
// holds); a reading of this release, the spec should confirm. It returns
// the passed keys and p's previous address, for rk8After.
func (m *Manager) rk8Follow(p *Peer, rest []*handshake.RelayLink, to handshake.RelayAddr, now time.Time) ([]ed25519.PublicKey, PeerRelay, bool) {
	old := p.Relay
	if len(rest) == 0 {
		return nil, old, true
	}
	passed := make([]ed25519.PublicKey, 0, len(rest))
	for _, l := range rest {
		passed = append(passed, l.Old)
	}
	if m.followRelayLinks(p, rest, to) != nil {
		return nil, old, false
	}
	p.Standing = HeldToken{}
	p.Reconnect = HeldToken{}
	p.RelayAwaitRC = now.UTC()
	return passed, old, true
}

// rk8After is what rule U does after its write, at an RK8 follow, once
// the handshake's establishment in the same write is done (RK6's order):
// the queued deposits move, the reconnect tokens issued to the passed keys
// are revoked, relay.token.issued goes for the new key (on one of the
// tokens for its mailbox, once held: RK8 "How Q gets a token"), and RK6
// runs. The reconnect whose own message made the follow is not restarted:
// at an hs.resp it is no longer open; at an hs.init's hs.fin the vault's
// own open reconnect was dropped when the peer's was established.
func (m *Manager) rk8After(p *Peer, passed []ed25519.PublicKey, old PeerRelay, now time.Time) {
	if len(passed) == 0 || p.suspended() {
		return
	}
	m.readdressQueued(p, old, now)
	m.revokePassedReconnect(p, passed, now)
	m.answerUpdate(p, now)
	m.rk6(p, passed, now)
	m.retryPeer(p.ID)
}

// marshalRelayLinks is links as stored with a pending reconnect.
func marshalRelayLinks(links []*handshake.RelayLink) []json.RawMessage {
	out := make([]json.RawMessage, 0, len(links))
	for _, l := range links {
		out = append(out, l.Marshal())
	}
	return out
}

// parseRelayLinksStored reads them back; ok is false if any does not parse.
func parseRelayLinksStored(raw []json.RawMessage) ([]*handshake.RelayLink, bool) {
	out := make([]*handshake.RelayLink, 0, len(raw))
	for _, r := range raw {
		l, err := handshake.ParseRelayLink(r)
		if err != nil {
			return nil, false
		}
		out = append(out, l)
	}
	return out, true
}

// addrOf is a PeerRelay as a relay address.
func addrOf(r PeerRelay) handshake.RelayAddr {
	return handshake.RelayAddr{URL: r.URL, Mailbox: r.Mailbox, PK: append([]byte(nil), r.PK...)}
}

// ikReason is Table B's refusal for a message whose ik is ik: the reason
// RK5's ik requirement fails with (the spec names none; a reading of this
// release, as rule U's rk5).
func ikReason(p *Peer, ik []byte) string {
	switch {
	case p.ancestor(ik):
		return "ancestor_ik"
	case p.rejected(ik):
		return "rejected_ik"
	}
	return "unknown_ik"
}

// rk8RespEvidence is RK8's parse-time end check and acceptFrom step 3 for
// the relay links of res, an hs.resp to the vault's own reconnect from p
// deposited with sender (identity links already checked by rule C). It
// returns "" when the chain is valid, "-" when rule C suspended the
// connection (a relay fork; nothing more is audited), or the refusal's
// reason (relay_unlinked).
func (m *Manager) rk8RespEvidence(p *Peer, res *handshake.Result, sender ed25519.PublicKey, now time.Time) string {
	if rk8EndRefused(sender, res.Resp.RelayLinks) {
		return "relay_unlinked" // parse time: no link checked or kept
	}
	ok, ev := m.relayLinksEvidence(p, sender, res.Resp.Relay.PK, res.Resp.RelayLinks, now)
	if ev != relayEvNone {
		return "-"
	}
	if !ok {
		return "relay_unlinked"
	}
	return ""
}
