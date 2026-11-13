package vault

import (
	"crypto/ed25519"

	"github.com/vettid/vettid-vault/vms/handshake"
)

// idLinksAllowed is the one gate every message passes before the vault
// applies identity links it carries (VAULT-MESSAGING 0.90.4 §3.4.1 Table A,
// the row "Earlier, after its cut-off", identity.rotate column): from an
// earlier relay key of p's after its cut-off, identity links are judged as
// that row judges an identity.rotate. If every link is already followed,
// nothing is applied and the message goes on (R29-K9 is still judged by
// the caller); otherwise it is refused superseded_relay and nothing is
// applied. A relay link from that key is the same for every recipient, so
// an old copy holding it could otherwise replay a followed relay link and
// move the ik. From any other row the links go on to the caller's Table B.
//
// Every entry point that applies identity links calls it first: an
// identity.rotate (Table A, tableARefuses), a relay.address.update
// (earlierAfterRotations, before RK5), a reconnect hs.init (respondReconnect,
// before the ctx is classified, so §6.6 "The links of a refused reconnect"
// never runs for such a sender), an hs.fin (handleFin, before sig_I, for the
// links its hs.init or rekey brought) and an hs.resp (handleResp, before any
// link is applied). It reports whether the links may go on, and the
// refusal's reason otherwise.
func (m *Manager) idLinksAllowed(p *Peer, sender ed25519.PublicKey, rots []*handshake.Rotation) (bool, string) {
	if !m.opt.RelayKeyRotation || p == nil || len(rots) == 0 || m.relayStateOf(p, sender) != relayEarlierAfter {
		return true, ""
	}
	if handshake.KnownPrefix(parseRotations(p.Chain), rots) == len(rots) {
		return true, "" // every link already followed: nothing applied
	}
	return false, "superseded_relay"
}
