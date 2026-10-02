package handshake

import (
	"bytes"
	"crypto/ed25519"
	"time"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/suite"
)

// CheckSender applies the collect-sender rule for every message after
// hs.init (§6.3): the relay `sender` MUST equal the relay key on record for
// the principal whose session decrypted the message. A mismatch is acked,
// dropped and audited by the runtime.
func CheckSender(collectSender, recordRelayKey ed25519.PublicKey) error {
	if !suite.EqualPublic(collectSender, recordRelayKey) {
		return ErrSender
	}
	return nil
}

// CheckReconnectTokenUse applies §6.6 "Permitted use": a deposit made on a
// reconnect token may only be a sealed-mode hs.init with purpose
// reconnect. pending is the decrypted hs.init (nil if the message was not
// one). Anything else MUST be dropped and audited.
func CheckReconnectTokenUse(mode envelope.Mode, pending *PendingInit) error {
	if mode != envelope.ModeSealed || pending == nil || pending.inner == nil ||
		pending.inner.Type != TypeInit || pending.body == nil || pending.body.Purpose != PurposeReconnect {
		return ErrTokenUse
	}
	return nil
}

// SimultaneousRekeyWinner decides between two crossing rekey hs.inits
// (§6.5): the one with the lower th1 (compared as big-endian byte strings)
// wins. It reports whether ours wins. th1 values are public.
func SimultaneousRekeyWinner(ourTh1, theirTh1 [32]byte) bool {
	return bytes.Compare(ourTh1[:], theirTh1[:]) < 0
}

// Reconnect token parameters (§6.6).
const (
	ReconnectTokenMaxLifetime = 365 * 24 * time.Hour
	ReconnectTokenQuotaMsgs   = 4
	ReconnectTokenQuotaBytes  = 65536
	ReconnectRemintBelow      = 60 * 24 * time.Hour
	RetiredKEMRetention       = 400 * 24 * time.Hour
)

// ReconnectTokenLifetime returns the lifetime to mint a reconnect token
// with: 365 days, capped by the relay's max_token_lifetime_seconds.
func ReconnectTokenLifetime(relayMax time.Duration) time.Duration {
	if relayMax > 0 && relayMax < ReconnectTokenMaxLifetime {
		return relayMax
	}
	return ReconnectTokenMaxLifetime
}

// ShouldUseReconnect reports whether a vault uses its reconnect token
// (§6.6): after a deposit fails with token_expired, or on unlock when the
// standing token it holds for the peer has already expired.
func ShouldUseReconnect(depositFailedTokenExpired bool, standingExpiry, now time.Time) bool {
	return depositFailedTokenExpired || !now.Before(standingExpiry)
}

// ReconnectRemintDue reports whether an issued reconnect token should be
// re-minted because less than 60 days remain (§6.6, §7.2).
func ReconnectRemintDue(expiry, now time.Time) bool {
	return expiry.Sub(now) < ReconnectRemintBelow
}
