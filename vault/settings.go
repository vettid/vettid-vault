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
	DefaultAuditRetentionDays  = 365
	MaxAppSettings             = 64
	MaxAppSettingBytes         = 4096
)

var appKeyRE = regexp.MustCompile(`^app\.[a-z0-9_.-]{1,48}$`)

func (s Settings) clone() Settings {
	c := s
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

// AuditRetention is how long audit entries are kept.
func (s Settings) AuditRetention() time.Duration {
	d := s.AuditRetentionDays
	if d == 0 {
		d = DefaultAuditRetentionDays
	}
	return time.Duration(d) * 24 * time.Hour
}

func (s Settings) json() []byte {
	ttl := uint64(s.UnlockTTL() / time.Second)
	feed, audit := s.FeedRetentionDays, s.AuditRetentionDays
	if feed == 0 {
		feed = DefaultFeedRetentionDays
	}
	if audit == 0 {
		audit = DefaultAuditRetentionDays
	}
	b := strictjson.NewBuilder().Bool("connections.auto_approve_in_person", s.AutoApproveInPerson).
		Uint("credential.unlock_ttl_seconds", ttl).Uint("feed.retention_days", feed).Uint("audit.retention_days", audit)
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
		case "audit.retention_days":
			if next.AuditRetentionDays, err = set.Uint(k, 30, 730); err != nil {
				return cur, errBadRequest
			}
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
	next, err := ApplySettings(s.Settings(), in.Body)
	if err != nil {
		return nil, err
	}
	s.host.SetSettings(next)
	s.SyncEvent("settings.changed", strictjson.NewBuilder().Uint("version", next.Version).Bytes())
	return strictjson.NewBuilder().Uint("version", next.Version).Bytes(), nil
}
