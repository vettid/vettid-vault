package invite

import "time"

// Invite TTLs (§6.4). The default is 10 minutes (in person); the others are
// for remote invites. Pairing QRs always use 10 minutes (§6.7).
var (
	TTLInPerson = 10 * time.Minute
	TTLRemote   = []time.Duration{time.Hour, 24 * time.Hour, 7 * 24 * time.Hour}
)

// PairingTTL is the TTL of a device or agent pairing QR (§6.7).
const PairingTTL = 10 * time.Minute

// RelayLimits are the relay policy values advertised at registration
// (§1.2), as durations.
type RelayLimits struct {
	OpenTokenMaxLifetime time.Duration // open_token_max_lifetime_seconds
	ClaimTTL             time.Duration // claim_ttl_seconds
}

// AllTTLs returns the defined invite TTLs, shortest first.
func AllTTLs() []time.Duration { return append([]time.Duration{TTLInPerson}, TTLRemote...) }

// IsRemote reports whether an invite with this TTL is a remote invite.
func IsRemote(ttl time.Duration) bool { return ttl > TTLInPerson }

// CheckTTL accepts ttl only if it is one of the defined TTLs and at or
// below both relay limits (§6.4: "MUST be at or below both").
func CheckTTL(ttl time.Duration, l RelayLimits) error {
	defined := false
	for _, t := range AllTTLs() {
		if t == ttl {
			defined = true
		}
	}
	if !defined || ttl > l.OpenTokenMaxLifetime || ttl > l.ClaimTTL {
		return ErrTTL
	}
	return nil
}

// OfferableTTLs returns the TTLs an app may offer: never one above the
// relay's limits (§6.4: "The app MUST NOT offer options above them").
func OfferableTTLs(l RelayLimits) []time.Duration {
	var out []time.Duration
	for _, t := range AllTTLs() {
		if CheckTTL(t, l) == nil {
			out = append(out, t)
		}
	}
	return out
}

// AutoApproveAllowed reports whether a connection request may be approved
// without the owner: only in-person invites, and only when the owner
// enabled auto-approval. Remote invites never (§6.4: "Auto-approval MUST NOT
// apply"); pairing never (§6.7: approval first).
func AutoApproveAllowed(remote, pairing, ownerEnabled bool) bool {
	return ownerEnabled && !remote && !pairing
}
