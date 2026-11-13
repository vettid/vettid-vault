package vault

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/vettid/vettid-relay/relayauth"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/peerwire"
)

// Rule T, tokens (VAULT-MESSAGING 0.90.4 §3.4.1, with §7.1 "The holder's checks"). A token in a message the
// vault accepts, or takes tokens from, is kept only if it verifies, has not
// expired, names as sub the vault's relay key (the vault rotates no relay
// key of its own yet, so it keeps no earlier one for deposits), and names
// as iss the mailbox of the peer's current relay key: for an update being
// followed, relay.pk's; for a reconnect hs.init, the one its from.relay
// names, used only to deposit that handshake's answer. Any other token is
// ignored and is no reason to refuse the message, except an update's `token`
// (rule U: token_unusable), and except a relay.token.issued whose iss is a
// mailbox the vault does not yet know for the peer, which is deferred.
// Every rule T check goes through heldTokenFrom, which makes the holder's
// checks of §7.1 (0.90.4: signature and claims, the lifetime bounds per
// kind, exp after iat, iat not ahead of the clock, a revoked jti) and, with
// Options.RelayKeyRotation, rule T's "has not expired".

// errExpiredHeld is a token rule T does not keep: it has expired.
var errExpiredHeld = errors.New("vault: an expired token")

// heldTokenFrom is heldToken for a token of the given kind minted by the
// mailbox of relay r (the peer's relay key on record for heldToken): every
// holder's check of §7.1 (0.90.4) and, with relay-key rotation, rule T's
// "has not expired".
func (m *Manager) heldTokenFrom(tok string, p *Peer, r PeerRelay, kind string) (HeldToken, error) {
	c, err := peerwire.VerifyHeldToken(tok, r.PK, r.Mailbox, r.URL, m.keys.relay.Public().(ed25519.PublicKey))
	if err != nil {
		return HeldToken{}, err
	}
	life := StandingMax
	if kind == TokReconnect {
		life = handshake.ReconnectTokenMaxLifetime
	}
	// The own relay's limit is the one read when the vault registered with
	// it, so a raise of the relay's policy is seen only from the next unlock.
	if lim := time.Duration(m.limits.MaxTokenLifetimeSeconds) * time.Second; lim > 0 && lim < life && r.URL == m.st.Relay.URL {
		// The issuer's relay is this vault's own: its advertised
		// max_token_lifetime_seconds is known, and the relay refuses a
		// token over it (token_invalid).
		life = lim
	}
	if c.Exp.Sub(c.Iat) > life || !c.Exp.After(c.Iat) || c.Iat.After(m.now().Add(envelope.MaxClockSkewFuture)) {
		return HeldToken{}, errHeldLifetime
	}
	for _, rv := range p.RevokedHeld {
		if rv.JTI == c.Jti {
			return HeldToken{}, errRevokedHeld // 0.88.2 §8.6: never used again
		}
	}
	if m.opt.RelayKeyRotation && !m.now().Before(c.Exp) {
		return HeldToken{}, errExpiredHeld
	}
	return HeldToken{Token: tok, Exp: c.Exp}, nil
}

// relayOf is a relay address as a PeerRelay.
func relayOf(a handshake.RelayAddr) PeerRelay {
	return PeerRelay{URL: a.URL, Mailbox: a.Mailbox, PK: append([]byte(nil), a.PK...)}
}

// RuleTVisibility is the relay visibility timeout rule T's deferral is
// measured in (§3.4.1 "defer": at most two of the relay's visibility
// timeouts, RELAY-PROTOCOL §6.3, after the vault first saw the message).
// The vault does not read the relay's visibility_timeout_seconds; 60 s is
// the value §11.14.10 takes when it is absent. A relay with a longer one
// redelivers less often than this assumes, and the message is then
// refused sooner: fail closed (a reading of this release; the spec should
// confirm).
const RuleTVisibility = 60 * time.Second

// RuleTDeferMax bounds the messages deferred at once per peer and reason
// (§3.4.1 "defer": at most 8).
const RuleTDeferMax = 8

// deferUnknownIss is the reason a message is deferred under rule T: a
// relay.token.issued whose iss is a mailbox the vault does not yet know for
// the peer (internal: never audited).
const deferUnknownIss = "unknown_iss"

// DeferredMsg is a message rule T left unacked: its peer, the reason, and
// when the vault first saw it.
type DeferredMsg struct {
	PeerID string    `json:"peer_id"`
	Reason string    `json:"reason"`
	Since  time.Time `json:"since"`
}

// ruleTDefers is rule T's deferral for a relay.token.issued from p whose
// iss is a mailbox the vault does not know for p (it may be p's next
// mailbox, from an update not processed yet): the message is left unacked
// and unprocessed, so that the relay delivers it again, for at most two
// visibility timeouts after it was first seen and for at most 8 such
// messages of p's at once. Past either bound it is processed, and rule T
// ignores its token (bad_issued_token). The vault collects one mailbox,
// so "while another mailbox has not been collected past it" does not
// arise. It reports whether the message is deferred now.
func (m *Manager) ruleTDefers(p *Peer, in *envelope.Inner, now time.Time) bool {
	if !m.opt.RelayKeyRotation || in.Type != tokenIssuedType || m.msgID == "" {
		return false
	}
	_, tok, err := peerwire.ParseTokenIssued(in.Body)
	if err != nil {
		return false
	}
	iss := unverifiedIss(tok)
	d := m.st.Deferred[m.msgID]
	if iss == "" || m.knowsMailbox(p, iss) {
		if d != nil {
			delete(m.st.Deferred, m.msgID)
			m.dirty = true
		}
		return false
	}
	if d == nil {
		// Every deferral of p's kept counts, whatever its age, so that
		// replays under fresh msg_ids cannot grow the state: past the cap
		// a message is processed at once. An entry stays until
		// DedupeRetention, so 8 deferrals that never come back stop further
		// deferral for this peer until then: a later relay.token.issued for
		// a mailbox not yet known is processed at once and its token ignored
		// (liveness only: P's resend recovers).
		n := 0
		for _, x := range m.st.Deferred {
			if x.PeerID == p.ID && x.Reason == deferUnknownIss {
				n++
			}
		}
		if n >= RuleTDeferMax {
			return false
		}
		if m.st.Deferred == nil {
			m.st.Deferred = map[string]*DeferredMsg{}
		}
		m.st.Deferred[m.msgID] = &DeferredMsg{PeerID: p.ID, Reason: deferUnknownIss, Since: now.UTC()}
		m.dirty = true
		return true
	}
	if now.Sub(d.Since) < 2*RuleTVisibility {
		return true
	}
	delete(m.st.Deferred, m.msgID)
	m.dirty = true
	return false
}

// pruneDeferred forgets deferrals whose message has not come back within
// the relay's message retention (it is gone).
func (m *Manager) pruneDeferred(now time.Time) {
	for id, d := range m.st.Deferred {
		if now.Sub(d.Since) > DedupeRetention {
			delete(m.st.Deferred, id)
			m.dirty = true
		}
	}
	if len(m.st.Deferred) == 0 && m.st.Deferred != nil {
		m.st.Deferred = nil
	}
}

// knowsMailbox reports whether mb is p's current mailbox or the mailbox of
// an earlier relay key the vault keeps for p.
func (m *Manager) knowsMailbox(p *Peer, mb string) bool {
	if mb == p.Relay.Mailbox {
		return true
	}
	for _, e := range p.EarlierRelays {
		if e.Relay.Mailbox == mb {
			return true
		}
	}
	return false
}

// unverifiedIss reads a token's iss without checking its signature (only
// to tell whether its mailbox is known; rule T then verifies it). "" when
// it does not parse.
func unverifiedIss(tok string) string {
	const header = "v4.public."
	if len(tok) > relayauth.MaxTokenLen || !strings.HasPrefix(tok, header) {
		return ""
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(tok[len(header):])
	if err != nil || len(raw) < ed25519.SignatureSize {
		return ""
	}
	c, err := relayauth.ParseClaims(raw[:len(raw)-ed25519.SignatureSize])
	if err != nil {
		return ""
	}
	return c.Iss
}
