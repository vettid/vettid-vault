package vault

import (
	"crypto/ed25519"
	"time"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/peerwire"
)

// Table A, relay key (VAULT-MESSAGING 0.90.4 §3.4.1, acceptFrom step 4):
// the rows for a message deposited with an earlier relay key of the
// peer's. The rows "Record suspended" (step 1), "Foreign" (step 2: no peer
// is found for the sender) and "Current" are as before. Only with
// Options.RelayKeyRotation: without it no sender is earlier.
//
//   - Earlier, before its cut-off: as Current. Session messages are
//     accepted, relay.token.issued is accepted, and identity.rotate, hs.init,
//     hs.resp and hs.fin go to Table B.
//   - Earlier, after its cut-off: refused (superseded_relay), except
//     relay.address.update (rule U, ruleU), relay.token.issued (its tokens
//     only, by rule T), and an identity.rotate whose every link is already followed
//     (ignored; R29-K9 is still judged). A refused hs.resp or hs.fin keeps
//     its handshake (S2).
//
// Between two vaults the row "Earlier, after its cut-off" has §3.4.2's
// exceptions: RK7 (an hs.confirm here, an hs.fin to an open answer in
// handleFin; relayrk7.go) and RK8 (a reconnect hs.init or hs.resp whose
// relay links connect its sender to the key it announces; relayrk8.go).

// tableARefuses applies Table A to a session-mode message from p deposited
// with sender (dispatch), after step 3. It reports whether the message was
// refused (acked, dropped, audited drop.peer_key superseded_relay).
func (m *Manager) tableARefuses(p *Peer, in *envelope.Inner, ep *handshake.Epoch, sender ed25519.PublicKey, now time.Time) bool {
	if m.relayStateOf(p, sender) != relayEarlierAfter {
		return false
	}
	switch in.Type {
	case handshake.TypeConfirm:
		if ep != nil {
			id := ep.ID()
			if m.rk7ConfirmPasses(p, id[:], sender) {
				return false // RK7: passed on (beforeAccept confirms the epoch)
			}
		}
	case peerwire.TypeRelayAddressUpdate, tokenIssuedType:
		return false // relay.token.issued: its tokens only (dispatch, after beforeAccept)
	case "identity.rotate":
		if links, err := rotateLinks(in.Body); err == nil {
			if ok, _ := m.idLinksAllowed(p, sender, links); ok {
				return false // every link already followed: ignored by the handler, K9 judged
			}
		}
	}
	m.refusePeerKey(p, "superseded_relay", now)
	return true
}

// tableAHandshake applies Table A to an hs.resp or hs.fin from p deposited
// with sender: after an earlier key's cut-off it is refused
// (superseded_relay) and its handshake kept (S2). It reports whether it
// refused the message.
func (m *Manager) tableAHandshake(p *Peer, sender ed25519.PublicKey, now time.Time) bool {
	if p == nil || m.relayStateOf(p, sender) != relayEarlierAfter {
		return false
	}
	m.refusePeerKey(p, "superseded_relay", now)
	return true
}

// respLinksEvidence is acceptFrom step 3 for an hs.resp that Table A then
// refuses with its handshake kept: the answer is opened on a copy of the
// handshake (the handshake itself stays as it is), and its identity links
// are checked by rule C and kept as seen, as the accepted path checks
// them. An answer that does not open or verify carries no evidence. It
// returns the opened answer (its epoch destroyed), or nil.
func (m *Manager) respLinksEvidence(p *Peer, ini *handshake.Initiator, raw []byte, sender ed25519.PublicKey, now time.Time) *handshake.Result {
	res := m.peekResp(p, ini, raw, sender, now)
	if res == nil {
		return nil
	}
	for _, r := range res.Resp.Rotations {
		if m.rotationConflict(p, r, now) {
			return nil
		}
	}
	return res
}

// peekResp opens an hs.resp on a copy of the handshake ini, which stays as
// it is, and returns the result with its epoch destroyed, or nil if it
// does not open or verify. The handshake pins the relay key on record
// when it began; the sender is an earlier key of p's (acceptFrom judged
// it), so the library is given the pinned key when both are keys the
// vault keeps for p, as unpinnedSender does for an accepted answer.
func (m *Manager) peekResp(p *Peer, ini *handshake.Initiator, raw []byte, sender ed25519.PublicKey, now time.Time) *handshake.Result {
	if p == nil || ini == nil {
		return nil
	}
	st, err := ini.Export()
	if err != nil {
		return nil
	}
	c, err := handshake.RestoreInitiator(st, m.keys.ik)
	if err != nil {
		return nil
	}
	from := sender
	if pinned := c.ResponderRelayKey(); p.keepsRelayKey(pinned) && p.keepsRelayKey(sender) {
		from = pinned
	}
	res, err := c.HandleResp(raw, from, now)
	if err != nil {
		return nil
	}
	res.Epoch.Destroy()
	return res
}

// recordRelayKey is the key a rekey or reconnect hs.init of p's deposited
// with sender is checked against as "the relay key on record" (§6.3):
// sender itself when Table A passes it to Table B as an earlier key before
// its cut-off, otherwise the relay key on record.
func (m *Manager) recordRelayKey(p *Peer, sender ed25519.PublicKey) ed25519.PublicKey {
	if m.relayStateOf(p, sender) == relayEarlierBefore {
		return sender
	}
	return p.Relay.PK
}
