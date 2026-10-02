package vault

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/vettid/vettid-relay/relayauth"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/handshake"
)

// Token lifetimes and thresholds (§7).
const (
	StandingMax         = 30 * 24 * time.Hour
	StandingRemintBelow = 10 * 24 * time.Hour // issuer re-mints (§7.2)
	HolderRefreshBelow  = 3 * 24 * time.Hour  // holder asks (§7.2)
	PeerQuotaMsgs       = 20000
	PeerQuotaBytes      = 512 << 20
	tokenRefreshType    = "relay.token.refresh"
	tokenIssuedType     = "relay.token.issued"
)

var errToken = errors.New("vault: token invalid")

func mailboxOf(k ed25519.PrivateKey) string {
	return relayauth.MailboxID(k.Public().(ed25519.PublicKey))
}

func (m *Manager) standingTTL(kind string) time.Duration {
	ttl := StandingMax
	if max := time.Duration(m.limits.MaxTokenLifetimeSeconds) * time.Second; max > 0 && max < ttl {
		ttl = max
	}
	if kind == KindConnection && m.opt.ConnectionStandingTTL > 0 && m.opt.ConnectionStandingTTL < ttl {
		ttl = m.opt.ConnectionStandingTTL
	}
	return ttl
}

func i64(v int64) *int64 { return &v }

// mintStanding issues a standing token for p (sub = p's relay key), with
// the peer quota for connections and none for owner devices (§7.1).
func (m *Manager) mintStanding(p *Peer, now time.Time, acc []IssuedToken) (string, []IssuedToken, error) {
	var quota *relayauth.Quota
	if p.Kind == KindConnection {
		quota = &relayauth.Quota{Msgs: i64(PeerQuotaMsgs), Bytes: i64(PeerQuotaBytes)}
	}
	return m.mint(p, TokStanding, m.standingTTL(p.Kind), quota, now, acc)
}

// mintReconnect issues a reconnect token (§6.6): ≤ 365 days and the relay
// cap, quota 4 messages / 64 KiB.
func (m *Manager) mintReconnect(p *Peer, now time.Time, acc []IssuedToken) (string, []IssuedToken, error) {
	ttl := handshake.ReconnectTokenLifetime(time.Duration(m.limits.MaxTokenLifetimeSeconds) * time.Second)
	quota := &relayauth.Quota{Msgs: i64(handshake.ReconnectTokenQuotaMsgs), Bytes: i64(handshake.ReconnectTokenQuotaBytes)}
	return m.mint(p, TokReconnect, ttl, quota, now, acc)
}

func (m *Manager) mint(p *Peer, kind string, ttl time.Duration, quota *relayauth.Quota, now time.Time, acc []IssuedToken) (string, []IssuedToken, error) {
	jti := m.newID(now)
	tok, err := m.relay.MintToken(p.Relay.PK, ttl, jti, quota)
	if err != nil {
		return "", acc, err
	}
	// relayclient backdates iat by 30 s; exp = iat + ttl.
	exp := now.UTC().Truncate(time.Second).Add(-30 * time.Second).Add(ttl)
	return tok, append(acc, IssuedToken{JTI: jti, Kind: kind, Sub: relayauth.EncodeKey(p.Relay.PK), PeerID: p.ID, Exp: exp}), nil
}

// heldToken validates a token another principal issued to the vault: its
// signature by the principal's relay key, iss = its mailbox, sub = the
// vault's relay key, and a deposit scope.
func (m *Manager) heldToken(tok string, p *Peer) (HeldToken, error) {
	msg, err := relayauth.VerifyToken(tok, p.Relay.PK)
	if err != nil {
		return HeldToken{}, errToken
	}
	c, err := relayauth.ParseClaims(msg)
	if err != nil || c.Iss != p.Relay.Mailbox || c.Scope != relayauth.ScopeDeposit ||
		c.Sub != relayauth.EncodeKey(m.keys.relay.Public().(ed25519.PublicKey)) ||
		strings.TrimRight(c.Aud, "/") != strings.TrimRight(p.Relay.URL, "/") {
		return HeldToken{}, errToken
	}
	return HeldToken{Token: tok, Exp: c.Exp}, nil
}

// hasLiveIssued reports whether the vault has an unexpired, undenied token
// of this kind issued to peer.
func (m *Manager) hasLiveIssued(peer, kind string, now time.Time) bool {
	for _, t := range m.st.Issued {
		if t.PeerID == peer && t.Kind == kind && !t.Denied && now.Before(t.Exp) {
			return true
		}
	}
	return false
}

func (m *Manager) latestIssued(peer, kind string) *IssuedToken {
	var best *IssuedToken
	for i := range m.st.Issued {
		t := &m.st.Issued[i]
		if t.PeerID == peer && t.Kind == kind && !t.Denied && (best == nil || t.Exp.After(best.Exp)) {
			best = t
		}
	}
	return best
}

// remintIssued re-mints standing tokens with < 10 days left and reconnect
// tokens with < 60 days left, and delivers them as relay.token.issued
// (§7.2 "On unlock" steps 1-2; also run periodically).
func (m *Manager) remintIssued(now time.Time) {
	for _, p := range m.allPeers() {
		if p.State != PeerActive {
			continue
		}
		if t := m.latestIssued(p.ID, TokStanding); t == nil || t.Exp.Sub(now) < StandingRemintBelow && m.standingTTL(p.Kind) > StandingRemintBelow {
			m.issueTo(p, TokStanding, now)
		}
		if p.Kind == KindConnection {
			if t := m.latestIssued(p.ID, TokReconnect); t == nil || handshake.ReconnectRemintDue(t.Exp, now) {
				m.issueTo(p, TokReconnect, now)
			}
		}
	}
}

func (m *Manager) issueTo(p *Peer, kind string, now time.Time) {
	var tok string
	var issued []IssuedToken
	var err error
	if kind == TokReconnect {
		tok, issued, err = m.mintReconnect(p, now, nil)
	} else {
		tok, issued, err = m.mintStanding(p, now, nil)
	}
	if err != nil {
		return
	}
	m.st.Issued = append(m.st.Issued, issued...)
	m.sendTo(p, tokenIssuedType, strictjson.NewBuilder().String("kind", kind).String("token", tok).Bytes(), now)
}

// refreshHeld asks peers for fresh standing tokens when ours have < 3 days
// left (§7.2), and starts reconnects for connections whose token expired.
func (m *Manager) refreshHeld(now time.Time) {
	for _, p := range m.allPeers() {
		if p.State != PeerActive || p.Standing.Token == "" {
			continue
		}
		if !now.Before(p.Standing.Exp) {
			if p.Kind == KindConnection {
				m.startReconnect(p, now)
			}
			continue
		}
		if p.Standing.Exp.Sub(now) < HolderRefreshBelow && !m.requestPending(p.ID, tokenRefreshType) {
			if id := m.sendTo(p, tokenRefreshType, json.RawMessage(`{}`), now); id != "" {
				m.requests[id] = p.ID
				m.requestTypes[id] = tokenRefreshType
			}
		}
	}
}

func (m *Manager) requestPending(peer, typ string) bool {
	for id, p := range m.requests {
		if p == peer && m.requestTypes[id] == typ {
			return true
		}
	}
	return false
}

// storeIssuedTo stores a token a peer issued to us ({kind, token}).
func (m *Manager) storeIssuedTo(p *Peer, body json.RawMessage, now time.Time) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return
	}
	tok, err := o.String("token")
	if err != nil {
		return
	}
	kind, _, _ := o.OptString("kind")
	ht, err := m.heldToken(tok, p)
	if err != nil {
		m.audit(now, "bad_issued_token", p.ID)
		return
	}
	if kind == TokReconnect {
		if p.Kind == KindConnection {
			p.Reconnect = ht
		}
		return
	}
	if ht.Exp.After(p.Standing.Exp) {
		p.Standing = ht
		m.retryPeer(p.ID)
	}
}

// denySub revokes every token issued to p's relay key (§7.4).
func (m *Manager) denySub(p *Peer, now time.Time) {
	sub := relayauth.EncodeKey(p.Relay.PK)
	for i := range m.st.Issued {
		if m.st.Issued[i].Sub == sub {
			m.st.Issued[i].Denied = true
		}
	}
	if !slices.Contains(m.st.DeniedSubs, sub) {
		m.st.DeniedSubs = append(m.st.DeniedSubs, sub)
	}
	m.queueRevoke("sub", sub, now)
}

// subDenied reports whether tokens to this relay key were revoked.
func (m *Manager) subDenied(pk ed25519.PublicKey) bool {
	sub := relayauth.EncodeKey(pk)
	for _, t := range m.st.Issued {
		if t.Sub == sub && t.Denied {
			return true
		}
	}
	return slices.Contains(m.st.DeniedSubs, sub)
}

// denyJTI revokes one token (§7.4: invites and pairings).
func (m *Manager) denyJTI(jti string, now time.Time) {
	for i := range m.st.Issued {
		if m.st.Issued[i].JTI == jti {
			m.st.Issued[i].Denied = true
		}
	}
	m.queueRevoke("jti", jti, now)
}

// pruneIssued drops registry entries long past expiry.
func (m *Manager) pruneIssued(now time.Time) {
	kept := m.st.Issued[:0]
	for _, t := range m.st.Issued {
		if now.Sub(t.Exp) < 30*24*time.Hour {
			kept = append(kept, t)
		}
	}
	m.st.Issued = kept
}
