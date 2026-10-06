package vault

import (
	"context"
	"encoding/json"
	"regexp"
	"sort"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// Settings defaults and bounds (§10.8).
const (
	DefaultCredentialUnlockTTL = 300 * time.Second
	DefaultFeedRetentionDays   = 30
	MaxAppSettings             = 64
	MaxAppSettingBytes         = 4096
	// The location log (§10.16).
	DefaultLocationHistoryDays     = 30
	DefaultLocationHistoryInterval = 300
)

var appKeyRE = regexp.MustCompile(`^app\.[a-z0-9_.-]{1,48}$`)

func (s Settings) clone() Settings {
	c := s
	if s.HoldOffUntil != nil {
		u := *s.HoldOffUntil
		c.HoldOffUntil = &u
	}
	if s.App != nil {
		c.App = make(map[string]string, len(s.App))
		for k, v := range s.App {
			c.App[k] = v
		}
	}
	return c
}

// UnlockTTL is the credential unlock window (§3.5.3).
func (s Settings) UnlockTTL() time.Duration {
	if s.CredentialUnlockTTL == 0 {
		return DefaultCredentialUnlockTTL
	}
	return time.Duration(s.CredentialUnlockTTL) * time.Second
}

// FeedRetention is how long feed items are kept.
func (s Settings) FeedRetention() time.Duration {
	d := s.FeedRetentionDays
	if d == 0 {
		d = DefaultFeedRetentionDays
	}
	return time.Duration(d) * 24 * time.Hour
}

// LocationHistoryEnabled reports whether the vault keeps the member's own
// location log (location.history.enabled, off by default, §10.16).
func (s Settings) LocationHistoryEnabled() bool { return s.LocationHistory }

// LocationHistoryRetention is how long the log keeps a position.
func (s Settings) LocationHistoryRetention() time.Duration {
	d := s.LocationHistoryDays
	if d == 0 {
		d = DefaultLocationHistoryDays
	}
	return time.Duration(d) * 24 * time.Hour
}

// LocationHistoryInterval is the log's recording cadence.
func (s Settings) LocationHistoryInterval() time.Duration {
	v := s.LocationHistorySeconds
	if v == 0 {
		v = DefaultLocationHistoryInterval
	}
	return time.Duration(v) * time.Second
}

// Backup reports whether the vault keeps the credential's copy (§3.5.6,
// credential.backup, on by default).
func (s Settings) Backup() bool { return !s.NoBackup }

func (s Settings) json() []byte {
	ttl := uint64(s.UnlockTTL() / time.Second)
	feed := s.FeedRetentionDays
	if feed == 0 {
		feed = DefaultFeedRetentionDays
	}
	b := strictjson.NewBuilder().Bool("connections.auto_approve_in_person", s.AutoApproveInPerson).
		Bool("credential.backup", s.Backup()).Uint("credential.unlock_ttl_seconds", ttl).Uint("feed.retention_days", feed).
		Bool("location.history.enabled", s.LocationHistory).
		Uint("location.history.interval_seconds", uint64(s.LocationHistoryInterval()/time.Second)).
		Uint("location.history.retention_days", uint64(s.LocationHistoryRetention()/(24*time.Hour))).
		Bool("owner_check.hold", !s.HoldOff)
	if s.HoldOff && s.HoldOffUntil != nil {
		b.String("owner_check.hold_off_until", envelope.FormatTS(*s.HoldOffUntil))
	}
	b.Uint("owner_check.interval_seconds", uint64(s.OwnerCheckInterval()/time.Second))
	keys := make([]string, 0, len(s.App))
	for k := range s.App {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		b.String(k, s.App[k])
	}
	return b.Bytes()
}

func (m *Manager) hSettingsGet(_ context.Context, s *Session, _ *envelope.Inner) (json.RawMessage, error) {
	st := s.Settings()
	return strictjson.NewBuilder().Uint("version", st.Version).Raw("settings", st.json()).Bytes(), nil
}

// ApplySettings applies a settings.set body to cur and returns the result
// with the version incremented. It is exported for fuzzing.
func ApplySettings(cur Settings, body []byte) (Settings, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return cur, errBadRequest
	}
	v, err := o.Uint("version", 0, strictjson.MaxSafeInteger)
	if err != nil {
		return cur, errBadRequest
	}
	set, err := o.Object("set")
	if err != nil || len(set) == 0 {
		return cur, errBadRequest
	}
	next := cur.clone()
	for k, raw := range set {
		switch k {
		case "connections.auto_approve_in_person":
			if next.AutoApproveInPerson, err = set.Bool(k); err != nil {
				return cur, errBadRequest
			}
		case "credential.unlock_ttl_seconds":
			if next.CredentialUnlockTTL, err = set.Uint(k, 30, 3600); err != nil {
				return cur, errBadRequest
			}
		case "feed.retention_days":
			if next.FeedRetentionDays, err = set.Uint(k, 1, 365); err != nil {
				return cur, errBadRequest
			}
		case "location.history.enabled":
			if next.LocationHistory, err = set.Bool(k); err != nil {
				return cur, errBadRequest
			}
		case "location.history.retention_days":
			if next.LocationHistoryDays, err = set.Uint(k, 1, 365); err != nil {
				return cur, errBadRequest
			}
		case "location.history.interval_seconds":
			if next.LocationHistorySeconds, err = set.Uint(k, 60, 3600); err != nil {
				return cur, errBadRequest
			}
		case "credential.backup":
			on, err := set.Bool(k)
			if err != nil {
				return cur, errBadRequest
			}
			next.NoBackup = !on
		case "owner_check.interval_seconds":
			// §3.6.2: 1 h to 24 h; the check cannot be turned off.
			if next.OwnerCheckSeconds, err = set.Uint(k, uint64(MinOwnerCheckInterval/time.Second),
				uint64(DefaultOwnerCheckInterval/time.Second)); err != nil {
				return cur, errBadRequest
			}
		case "owner_check.hold":
			on, err := set.Bool(k)
			if err != nil {
				return cur, errBadRequest
			}
			if !on {
				return cur, errOwnerCheckRequired // off only within a check (§3.6.7)
			}
			next.HoldOff, next.HoldOffUntil = false, nil
		case "owner_check.hold_off_until":
			return cur, errOwnerCheckRequired
		default:
			if !appKeyRE.MatchString(k) {
				return cur, errBadRequest
			}
			if string(raw) == "null" {
				delete(next.App, k)
				continue
			}
			sv, err := set.String(k)
			if err != nil || len(sv) > MaxAppSettingBytes {
				return cur, errBadRequest
			}
			if next.App == nil {
				next.App = map[string]string{}
			}
			next.App[k] = sv
		}
	}
	if len(next.App) > MaxAppSettings {
		return cur, NewError("limit", "")
	}
	if v != cur.Version {
		return cur, NewError("conflict", "")
	}
	next.Version = cur.Version + 1
	return next, nil
}

func (m *Manager) hSettingsSet(_ context.Context, s *Session, in *envelope.Inner) (json.RawMessage, error) {
	if s.from.Kind != KindApp && namesOwnerCheck(in.Body) {
		return nil, errForbiddenH // holder only (§3.6.2, §3.6.7), never held for approval
	}
	prev := s.Settings()
	next, err := ApplySettings(prev, in.Body)
	if err != nil {
		return nil, err
	}
	s.host.SetSettings(next)
	s.Record(Activity{Kind: "settings.changed", DeviceID: s.from.ID, Ref: uitoa(next.Version), Audit: true})
	if m := s.m; m != nil {
		for _, f := range m.features {
			if o, ok := f.(SettingsObserver); ok {
				o.SettingsChanged(s, next)
			}
		}
	}
	s.SyncEvent("settings.changed", strictjson.NewBuilder().Uint("version", next.Version).Bytes())
	if s.m != nil {
		m.settingsOwnerCheck(prev, next, s.now)
	}
	return strictjson.NewBuilder().Uint("version", next.Version).Bytes(), nil
}

var errOwnerCheckRequired = &HandlerError{Code: "owner_check_required"}

// namesOwnerCheck reports whether a settings.set body names an owner-check
// setting.
func namesOwnerCheck(body []byte) bool {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return false
	}
	set, err := o.Object("set")
	if err != nil {
		return false
	}
	for _, k := range ownerCheckKeys {
		if set.Has(k) {
			return true
		}
	}
	return false
}
