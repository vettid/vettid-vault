package peerwire

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"time"

	"github.com/vettid/vettid-relay/relayauth"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// Token kinds (§7.1). The reconnect token's lifetime, quota and re-mint
// rule are vms/handshake's (ReconnectTokenLifetime,
// ReconnectTokenQuotaMsgs, ReconnectTokenQuotaBytes, ReconnectRemintDue).
const (
	TokenStanding  = "standing"
	TokenReconnect = "reconnect"
	TokenOpen      = "open"
	// TokenRequest covers only the rest of a handshake that awaits
	// approval and connection.approved (§7.1, 0.10.3).
	TokenRequest = "request"
)

// Standing-token lifetimes, quotas and thresholds (§7.1, §7.2).
const (
	StandingMax         = 30 * 24 * time.Hour
	StandingRemintBelow = 10 * 24 * time.Hour // the issuer re-mints (§7.2)
	HolderRefreshBelow  = 3 * 24 * time.Hour  // the holder asks (§7.2)
	// The quota of a standing token issued to a peer vault (§7.1).
	PeerQuotaMsgs  = 20000
	PeerQuotaBytes = 512 << 20
	// QuotaRefreshEvery bounds the refreshes of a connection whose standing
	// token still has HolderRefreshBelow or more left (a refresh after
	// quota_exceeded, §7.2, 0.32.0): one in this period.
	QuotaRefreshEvery = 24 * time.Hour
	// RenewEvery bounds a connection's refreshes near its token's end
	// (§7.2): one in this period.
	RenewEvery = time.Hour
	// TokenBackdate is how far relayclient backdates a token's iat
	// (RELAY-PROTOCOL §5.2, VAULT-MESSAGING §7.1): exp = iat + lifetime.
	TokenBackdate = 60 * time.Second
)

// Request tokens (§7.1).
const (
	RequestTokenQuotaMsgs  = 8
	RequestTokenQuotaBytes = 65536
	RequestTokenConnection = 16 * 24 * time.Hour // ≤ 16 d for a peer vault
	RequestTokenDevice     = 10 * time.Minute    // ≤ 10 min for a new device
)

// Message types (§7.2).
const (
	TypeTokenIssued  = "relay.token.issued"
	TypeTokenRefresh = "relay.token.refresh"
	// CodeTooSoon is the error code of a relay.token.refresh refused
	// until allowed_after (TooSoonBody).
	CodeTooSoon = "too_soon"
)

// ErrToken is a token that is not a deposit token the peer issued to us.
var ErrToken = errors.New("peerwire: token invalid")

// VerifyHeldToken checks a token a peer issued to us (§7.1): its signature
// by the peer's relay key issuerPK, iss = the peer's mailbox, sub = our
// own relay key, aud = the peer's relay URL (trailing slashes ignored) and
// a deposit scope. It returns the token's claims.
func VerifyHeldToken(tok string, issuerPK ed25519.PublicKey, issuerMailbox, issuerRelayURL string, own ed25519.PublicKey) (relayauth.Claims, error) {
	msg, err := relayauth.VerifyToken(tok, issuerPK)
	if err != nil {
		return relayauth.Claims{}, ErrToken
	}
	c, err := relayauth.ParseClaims(msg)
	if err != nil || c.Iss != issuerMailbox || c.Scope != relayauth.ScopeDeposit ||
		c.Sub != relayauth.EncodeKey(own) ||
		strings.TrimRight(c.Aud, "/") != strings.TrimRight(issuerRelayURL, "/") {
		return relayauth.Claims{}, ErrToken
	}
	return c, nil
}

// TokenIssuedBody is a relay.token.issued body, and the answer to
// relay.token.refresh (kind standing): {kind, token}.
func TokenIssuedBody(kind, token string) []byte {
	return strictjson.NewBuilder().String("kind", kind).String("token", token).Bytes()
}

// ParseTokenIssued parses a relay.token.issued body, or a
// relay.token.refresh answer: token is required; kind is "" when absent or
// not a string, which the vault treats as a standing token. Check the
// token with VerifyHeldToken.
func ParseTokenIssued(body []byte) (kind, token string, err error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return "", "", ErrBody
	}
	if token, err = o.String("token"); err != nil {
		return "", "", ErrBody
	}
	kind, _, _ = o.OptString("kind")
	return kind, token, nil
}

// TokenRefreshBody is the relay.token.refresh request body: {}.
func TokenRefreshBody() []byte { return []byte(`{}`) }

// TooSoonBody is the body of a too_soon error answer: {allowed_after}.
func TooSoonBody(allowedAfter time.Time) []byte {
	return strictjson.NewBuilder().String("allowed_after", envelope.FormatTS(allowedAfter)).Bytes()
}

// ParseTooSoon parses the body of a too_soon error answer strictly.
func ParseTooSoon(body []byte) (time.Time, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return time.Time{}, ErrBody
	}
	s, err := o.String("allowed_after")
	if err != nil {
		return time.Time{}, ErrBody
	}
	t, err := envelope.ParseTS(s)
	if err != nil {
		return time.Time{}, ErrBody
	}
	return t, nil
}
