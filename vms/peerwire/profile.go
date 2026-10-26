package peerwire

import (
	"crypto/ed25519"
	"encoding/json"
	"unicode/utf8"

	"github.com/vettid/vettid-vault/internal/strictjson"
)

// The shared profile (§10.8): every active connection receives
// profile.update, whose read-only core (0.18.0) is the member's account
// names and the vault's identity key; the rest ({name?, photo?, items})
// are the member's optional extras.
const (
	TypeProfileUpdate = "profile.update"
	// MaxAccountName bounds an account name in the snapshot and the
	// profile's core (§10.8, §11.13: 1–160 bytes).
	MaxAccountName = 160
	// MaxProfileItems bounds a profile.update's items (§10.8).
	MaxProfileItems = 32
	// MaxProfileUpdate bounds a profile.update body, in bytes (§10.8,
	// 0.19.0).
	MaxProfileUpdate = 196608
)

// ValidAccountName reports whether s is a name as the snapshot and the
// shared profile's core carry it (§10.8, §11.13): a UTF-8 string of 1–160
// bytes without control characters (C0, DEL, C1, U+2028, U+2029; DEL
// since 0.21.0).
func ValidAccountName(s string) bool {
	if s == "" || len(s) > MaxAccountName || !utf8.ValidString(s) {
		return false
	}
	return !HasNameControl(s)
}

// HasNameControl reports whether s holds a character of the set the
// account's names and email exclude (§10.8, §11.13, 0.21.0): C0
// (U+0000–U+001F), DEL (U+007F), C1 (U+0080–U+009F), U+2028 and U+2029.
func HasNameControl(s string) bool {
	for _, r := range s {
		if r < 0x20 || r >= 0x7f && r <= 0x9f || r == 0x2028 || r == 0x2029 {
			return true
		}
	}
	return false
}

// ValidHandshakeProfile reports whether a connection hs.init profile from
// a vault carries both core names (§6.2, 0.18.0): {first_name, last_name,
// name?}.
func ValidHandshakeProfile(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	o, err := strictjson.ParseObject(raw)
	if err != nil {
		return false
	}
	for _, k := range []string{"first_name", "last_name"} {
		if s, err := o.String(k); err != nil || !ValidAccountName(s) {
			return false
		}
	}
	return true
}

// ProfileUpdateBody returns a profile.update body (§10.8): {version,
// first_name, last_name, ik, name?, photo?, items}. extras is the JSON
// object of the members after the core, at least {"items": [...]}, in
// their order; nil is {"items":[]}, a profile with no extras.
func ProfileUpdateBody(version uint64, firstName, lastName string, ik []byte, extras []byte) []byte {
	if extras == nil {
		extras = []byte(`{"items":[]}`)
	}
	b := strictjson.NewBuilder().Uint("version", version).String("first_name", firstName).String("last_name", lastName).
		Base64("ik", ik).Bytes()
	return append(append(b[:len(b)-1], ','), extras[1:]...)
}

// ProfileUpdate is a parsed profile.update body (from a peer, which may be
// malicious): its version, its core and every member as parsed.
type ProfileUpdate struct {
	Version uint64
	// The core (§10.8, 0.18.0); Malformed when a core member is missing
	// or breaks its rules (the receiver drops it after the version check).
	FirstName string
	LastName  string
	IK        ed25519.PublicKey
	Malformed bool
	// Items are the raw items (at most MaxProfileItems, unchecked).
	Items []json.RawMessage
	// Members are all the body's members, raw (for the extras).
	Members map[string]json.RawMessage
}

// ParseProfileUpdate parses a profile.update body strictly as far as a
// peer needs it (§10.8): at most MaxProfileUpdate bytes, an object,
// version 1–2^53−1, the core and an items array of at most
// MaxProfileItems. The core's members are checked too, but reported in
// Malformed rather than as an error, since §10.8 drops such an update only
// after the version check. The extras (name, photo, the items' contents)
// are left to the caller.
func ParseProfileUpdate(body []byte) (*ProfileUpdate, error) {
	if len(body) > MaxProfileUpdate {
		return nil, ErrBody
	}
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, ErrBody
	}
	u := &ProfileUpdate{Members: o}
	if u.Version, err = o.Uint("version", 1, strictjson.MaxSafeInteger); err != nil {
		return nil, ErrBody
	}
	u.FirstName, err = o.String("first_name")
	u.Malformed = err != nil || !ValidAccountName(u.FirstName)
	u.LastName, err = o.String("last_name")
	u.Malformed = u.Malformed || err != nil || !ValidAccountName(u.LastName)
	u.IK, err = o.Base64("ik", ed25519.PublicKeySize)
	u.Malformed = u.Malformed || err != nil
	if u.Items, err = o.Array("items"); err != nil || len(u.Items) > MaxProfileItems {
		return nil, ErrBody
	}
	return u, nil
}
