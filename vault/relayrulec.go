package vault

import (
	"crypto/ed25519"
	"time"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/peerwire"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Rule C for relay links (VAULT-MESSAGING 0.90.3 §3.4.1 rule C, "Relay
// links"; acceptFrom steps 1 and 3; §3.4.2 RK12). Only with
// Options.RelayKeyRotation.

// relayEv is what rule C found in a message's relay links.
type relayEv int

const (
	relayEvNone     relayEv = iota // no second successor
	relayEvFork                    // a connection: suspended as a relay fork
	relayEvConflict                // a device or agent: the message is refused (conflict)
)

// relayLinksKept sorts a relay chain into rule U's two lists (0.90.3: in an
// update and in a reconnect alike, every refusal of a chain falls in
// exactly one of them). sender is the key the message was deposited with,
// announced the key it announces (an update's relay.pk, an hs.init's
// from.relay.pk, an hs.resp's relay.pk). It returns the links that go
// through rule C, and whether the chain is valid as a whole.
//   - No link is kept when the chain is refused for its count, a link's
//     form, a v or suite (both refused when the links are parsed), a link
//     whose old equals its new, a repeated key in the sequence of the first
//     old and each new, or an end mismatch (the first old is not sender, or
//     the last new is not announced).
//   - Earlier valid links are still kept when the chain is refused only for
//     a bad signature or a break in the chain: the links before the first
//     link whose signatures do not verify or whose old is not the previous
//     link's new (each of them valid, and connected to sender).
func relayLinksKept(sender, announced ed25519.PublicKey, links []*handshake.RelayLink) ([]*handshake.RelayLink, bool) {
	if len(links) == 0 || len(links) > handshake.MaxRelayLinks {
		return nil, false
	}
	seq := []ed25519.PublicKey{links[0].Old}
	for _, l := range links {
		if l == nil || len(l.Old) != ed25519.PublicKeySize || len(l.New) != ed25519.PublicKeySize || suite.EqualPublic(l.Old, l.New) {
			return nil, false
		}
		for _, k := range seq {
			if suite.EqualPublic(k, l.New) {
				return nil, false // a repeated key
			}
		}
		seq = append(seq, l.New)
	}
	if !suite.EqualPublic(links[0].Old, sender) || !suite.EqualPublic(links[len(links)-1].New, announced) {
		return nil, false // an end mismatch
	}
	prev := sender
	for i, l := range links {
		if !suite.EqualPublic(l.Old, prev) || l.Verify() != nil {
			return links[:i], false // a break or a bad signature: the earlier links are still seen
		}
		prev = l.New
	}
	return links, true
}

// relayLinksEvidence checks a message's relay links by rule C: acceptFrom
// step 3 ("evidence first", whatever the sender's position, before Table
// A), and, for a suspended record, step 1 (§3.4.2 RK12: the links that
// pass rule C are kept as seen, as step 3 keeps them, so that a relay fork
// is still recorded and a later different successor is one). p's sender
// is not foreign (the caller found p by it). It reports whether the chain
// is valid as a whole (rule U's form, end and signature checks; rule C's
// outcome aside) and what rule C found; at the first second successor it
// stops.
func (m *Manager) relayLinksEvidence(p *Peer, sender, announced ed25519.PublicKey, links []*handshake.RelayLink, now time.Time) (bool, relayEv) {
	kept, ok := relayLinksKept(sender, announced, links)
	for _, l := range kept {
		if ev := m.relayRuleC(p, l, now); ev != relayEvNone {
			return false, ev
		}
	}
	return ok, relayEvNone
}

// relayRuleC is rule C for one valid relay link l of p's: a link whose old
// key already has a followed or seen successor other than its new key is a
// second successor; otherwise l is kept as seen (at most one per old key,
// at most MaxRelaySeen), unless it is already followed or seen.
func (m *Manager) relayRuleC(p *Peer, l *handshake.RelayLink, now time.Time) relayEv {
	known := false
	check := func(raw []byte) (relayEv, bool) {
		prev, err := handshake.ParseRelayLink(raw)
		if err != nil || !suite.EqualPublic(prev.Old, l.Old) {
			return relayEvNone, false
		}
		if suite.EqualPublic(prev.New, l.New) {
			known = true // the same link again, followed or seen
			return relayEvNone, false
		}
		return m.relaySecondSuccessor(p, prev, l, now), true
	}
	for _, e := range p.EarlierRelays {
		if ev, done := check(e.Link); done {
			return ev
		}
	}
	for _, raw := range p.RelaySeen {
		if ev, done := check(raw); done {
			return ev
		}
	}
	if !known && len(p.RelaySeen) < MaxRelaySeen {
		p.RelaySeen = append(p.RelaySeen, l.Marshal())
		m.dirty = true
	}
	return relayEvNone
}

// relaySecondSuccessor acts on two successors of one relay key of p's:
// first, followed or seen before, and second (§3.4.1 rule C, "Relay
// links").
//   - Between vaults (a connection, a service included) the connection is
//     suspended as a fork: connection.fork_suspected with ref relay, and
//     its feed item; connection.rotation.resolve then answers not_found;
//     the only exit is a new invitation. A record already suspended (an
//     identity conflict, an epoch fork) still records the relay fork
//     (acceptFrom step 1).
//   - With the vault's own device or agent nothing suspends: the first
//     successor stays and the message with the other is refused
//     (conflict); the vault sends that device nothing more and tells the
//     member with a high feed item.
func (m *Manager) relaySecondSuccessor(p *Peer, first, second *handshake.RelayLink, now time.Time) relayEv {
	if p.Kind == KindConnection {
		m.suspendRelayFork(p, now)
		return relayEvFork
	}
	if p.RelayConflict == nil {
		p.RelayConflict = &RelayConflict{At: now.UTC(), Old: append([]byte(nil), first.Old...),
			Kept: append([]byte(nil), first.New...), Refused: append([]byte(nil), second.New...)}
		for _, e := range m.st.Outbox {
			if e.PeerID == p.ID && !e.Done && e.Op == OpDeposit {
				e.Done = true // nothing more is sent to this device
			}
		}
		// The spec names no audit kind for this item (NEW text, for
		// wording approval with the app PRs): it uses
		// connection.fork_suspected with the device's id and ref relay, as
		// a device's epoch fork does (iklinks.go).
		m.record(Activity{Kind: "connection.fork_suspected", DeviceID: p.ID, Ref: "relay", Audit: true, Feed: true, Priority: "high"}, now)
		m.dirty = true
	}
	return relayEvConflict
}

// suspendRelayFork records a relay fork of connection p and suspends it
// (suspendForkRef, ref relay). A record already suspended on fork evidence
// keeps its suspension and gets the relay fork's audit entry and feed item
// too, so that the member is told the way out (a new invitation after the
// peer replaced its keys).
func (m *Manager) suspendRelayFork(p *Peer, now time.Time) {
	if p.RelayFork != nil {
		return
	}
	p.RelayFork = &ForkSuspension{At: now.UTC()}
	m.dirty = true
	if p.Fork == nil {
		m.suspendForkRef(p, "relay", now)
		return
	}
	m.record(Activity{Kind: "connection.fork_suspected", ConnectionID: p.ID, Ref: "relay", Audit: true, Feed: true, Priority: "high"}, now)
}

// relayBlocked reports whether nothing may be sent to the peer with id:
// an owner device or agent with two successors of one relay key (rule C).
func (m *Manager) relayBlocked(id string) bool {
	if id == "" {
		return false
	}
	p := m.st.Devices[id]
	return p != nil && p.RelayConflict != nil
}

// updateRelayEvidence checks the relay links of a relay.address.update from
// p, deposited with sender, by rule C (acceptFrom step 3, or step 1 with
// RK12 while p is suspended). A body that does not parse (malformed, or a
// link's form or the chain's count refused when it is parsed) keeps no
// link. It reports whether the message is to be refused now (conflict,
// audited here) rather than passed on.
//
// Rule U itself (following the links, the tokens) and the update's identity
// links (§3.4.2 RK5: applied first) are not built: the handler still
// refuses the update (relay_unlinked).
func (m *Manager) updateRelayEvidence(p *Peer, in *envelope.Inner, sender ed25519.PublicKey, now time.Time) bool {
	u, err := peerwire.ParseAddressUpdate(in.Body)
	if err != nil {
		return false
	}
	_, ev := m.relayLinksEvidence(p, sender, u.Relay.PK, u.Links, now)
	if ev == relayEvConflict {
		m.refusePeerKey(p, "conflict", now)
		return true
	}
	return false
}
