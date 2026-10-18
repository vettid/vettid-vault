package altchan

import (
	"encoding/json"
	"sort"

	"github.com/vettid/vettid-vault/internal/strictjson"
)

// Release capabilities (VAULT-MESSAGING 0.34.0 §11.10.9): the protocol
// capabilities a release implements, a constant of the image (so PCR0
// covers it), named in the ETK descriptor (§11.2), which the attestation
// binds, and in a transfer's bundle (§6.4). Apps choose the enroll,
// unlock, transfer and recovery path from it; a descriptor or bundle
// without it is a release before R. Nothing the host, the member API or
// the relay sends changes it. These are not the channel file's optional
// features (§11.10.8).
const (
	// CapRecoveryR: §11.14, the phone-held unlock secret, the recovery
	// open, and none of the recovery of §11.11.5. Listed whatever
	// recovery_offered says.
	CapRecoveryR = "recovery_r"
	// CapAttachments: message attachments (§7.3, §10.5.1).
	CapAttachments = "attachments"
	// CapRecoveryOffered: the release offers recovery (its measured
	// channel file's recovery_offered is true, §11.14.13); absent beside
	// recovery_r, every recovery request is refused not_offered and the
	// app hides recovery (owner decision of 2026-10-16).
	CapRecoveryOffered = "recovery_offered"
)

// Bounds on a capability list (§11.10.9).
const (
	MaxCapabilities   = 32
	MaxCapabilityName = 32
)

// ReleaseCapabilities returns this image's capability list, sorted: the
// code's capabilities, and recovery_offered when the measured release
// configuration offers recovery (offered is releasecfg's
// recovery_offered, compiled into the image like every release constant).
func ReleaseCapabilities(offered bool) []string {
	if offered {
		return []string{CapAttachments, CapRecoveryOffered, CapRecoveryR}
	}
	return []string{CapAttachments, CapRecoveryR}
}

// HasCapability reports whether caps names c.
func HasCapability(caps []string, c string) bool {
	for _, x := range caps {
		if x == c {
			return true
		}
	}
	return false
}

// ValidCapabilities checks a list: at most MaxCapabilities names, each
// 1 to MaxCapabilityName characters of [a-z0-9_], unique and sorted.
func ValidCapabilities(caps []string) bool {
	if len(caps) > MaxCapabilities || !sort.StringsAreSorted(caps) {
		return false
	}
	for i, c := range caps {
		if !validCapName(c) || (i > 0 && caps[i-1] == c) {
			return false
		}
	}
	return true
}

func validCapName(s string) bool {
	if len(s) == 0 || len(s) > MaxCapabilityName {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

// MarshalCapabilities encodes a valid list as a JSON array.
func MarshalCapabilities(caps []string) []byte {
	if caps == nil {
		caps = []string{}
	}
	b, _ := json.Marshal(caps) // names are [a-z0-9_]: no escaping
	return b
}

// ParseCapabilities reads the optional member name of o. An absent member
// is (nil, nil): a release before R. A present member that is not a valid
// list is an error.
func ParseCapabilities(o strictjson.Object, name string) ([]string, error) {
	arr, ok, err := o.OptArray(name)
	if err != nil {
		return nil, ErrMalformed
	}
	if !ok {
		return nil, nil
	}
	caps := make([]string, 0, len(arr))
	for _, raw := range arr {
		s, err := strictjson.AsString(raw)
		if err != nil {
			return nil, ErrMalformed
		}
		caps = append(caps, s)
	}
	if !ValidCapabilities(caps) {
		return nil, ErrMalformed
	}
	return caps, nil
}

// MaxTimeScale bounds a descriptor's or bundle's time_scale (0.43.0,
// §11.10.8: production 1, staging 1 or 24, development up to 86,400).
const MaxTimeScale = 86400

// ParseTimeScale reads the optional member name of o (0.43.0,
// §11.10.9): absent is 0 (a release before the scale, meaning 1); present,
// an integer 1..MaxTimeScale, anything else an error.
func ParseTimeScale(o strictjson.Object, name string) (uint64, error) {
	if !o.Has(name) {
		return 0, nil
	}
	n, err := o.Uint(name, 1, MaxTimeScale)
	if err != nil {
		return 0, ErrMalformed
	}
	return n, nil
}
