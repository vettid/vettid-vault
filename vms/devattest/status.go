package devattest

import (
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
)

// MaxStatusList bounds the Google attestation status list (about 180 KB
// in 2026).
const MaxStatusList = 8 << 20

// StatusList is a parsed Google attestation status list
// (https://android.googleapis.com/attestation/status), with the time the
// enclave fetched it over TLS it terminates (§11.7; transport in V3b).
type StatusList struct {
	FetchedAt time.Time
	revoked   map[string]bool
}

// ParseStatusList parses the list strictly: {"entries": {"<serial hex>":
// {"status": ..., "reason": ...}}}. Every listed serial counts as revoked
// whatever its status (fail closed); serials are lowercase hex.
func ParseStatusList(b []byte, fetchedAt time.Time) (*StatusList, error) {
	if len(b) == 0 || len(b) > MaxStatusList {
		return nil, ErrRevocationList
	}
	o, err := strictjson.ParseObject(b)
	if err != nil {
		return nil, ErrRevocationList
	}
	ents, err := o.Object("entries")
	if err != nil {
		return nil, ErrRevocationList
	}
	l := &StatusList{FetchedAt: fetchedAt, revoked: make(map[string]bool, len(ents))}
	for serial, raw := range ents {
		if !validSerial(serial) {
			return nil, ErrRevocationList
		}
		e, err := strictjson.AsObject(raw)
		if err != nil {
			return nil, ErrRevocationList
		}
		if s, err := e.String("status"); err != nil || s == "" {
			return nil, ErrRevocationList
		}
		l.revoked[serial] = true
	}
	return l, nil
}

func validSerial(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// Check fails if the list is missing, older than maxAge, or lists any of
// the serials.
func (l *StatusList) Check(serials []string, now time.Time, maxAge time.Duration) error {
	if l == nil || l.FetchedAt.IsZero() || now.Sub(l.FetchedAt) > maxAge || l.FetchedAt.After(now.Add(5*time.Minute)) {
		return ErrRevocationList
	}
	for _, s := range serials {
		if l.revoked[s] {
			return ErrRevoked
		}
	}
	return nil
}

// Len returns the number of listed serials.
func (l *StatusList) Len() int { return len(l.revoked) }
