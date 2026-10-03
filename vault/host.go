package vault

import (
	"encoding/json"
	"sort"
	"time"
	"unicode/utf8"

	"github.com/vettid/vettid-vault/internal/strictjson"
)

// managerHost is the Host of the sessions a Manager builds. Its methods run
// with m.mu held (inside a batch or another locked section).
type managerHost struct{ m *Manager }

func (h managerHost) VaultID() string { return h.m.st.VaultID }

func (h managerHost) Connection(id string) (PeerInfo, bool) {
	p, ok := h.m.st.Connections[id]
	if !ok {
		return PeerInfo{}, false
	}
	return info(p), true
}

func (h managerHost) Connections() []PeerInfo {
	ids := make([]string, 0, len(h.m.st.Connections))
	for id := range h.m.st.Connections {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]PeerInfo, 0, len(ids))
	for _, id := range ids {
		out = append(out, info(h.m.st.Connections[id]))
	}
	return out
}

func (h managerHost) SendToConnection(id, typ string, body json.RawMessage, now time.Time) error {
	p, ok := h.m.st.Connections[id]
	if !ok || p.State != PeerActive {
		return ErrNoSession
	}
	if h.m.sendTo(p, typ, body, now) == "" {
		return ErrNoSession
	}
	return nil
}

func (h managerHost) NotifyDevices(typ string, body json.RawMessage, except string, now time.Time) {
	h.m.notifyDevices(typ, body, except, now)
}

func (h managerHost) NewID(now time.Time) string { return h.m.newID(now) }

func (h managerHost) Record(a Activity, now time.Time) { h.m.record(a, now) }

// MaxProfileBytes bounds a connection's stored profile (§10.8: 200 fields
// of up to 4 KiB plus a 64 KiB photo fit well below it).
const MaxProfileBytes = 192 * 1024

func (h managerHost) SetConnectionProfile(id string, profile json.RawMessage, _ time.Time) error {
	p, ok := h.m.st.Connections[id]
	if !ok {
		return errNotFound
	}
	if len(profile) > MaxProfileBytes {
		return errBadRequest
	}
	p.Profile = append(json.RawMessage(nil), profile...)
	if n := profileName(profile); n != "" {
		p.Name = n
	}
	h.m.dirty = true
	return nil
}

func (h managerHost) RotateIdentity(now time.Time) error { return h.m.rotateIdentity(now) }

func (h managerHost) Settings() Settings { return h.m.st.Settings.clone() }

func (h managerHost) SetSettings(s Settings) {
	h.m.st.Settings = s.clone()
	h.m.dirty = true
}

// session returns a session for vault-internal activity (no sender).
func (m *Manager) session(now time.Time) *Session {
	return &Session{m: m, host: managerHost{m}, now: now}
}

// record passes an activity to every ActivitySink feature (§10.9).
func (m *Manager) record(a Activity, now time.Time) {
	if m.st == nil {
		return
	}
	var s *Session
	for _, f := range m.features {
		if sink, ok := f.(ActivitySink); ok {
			if s == nil {
				s = m.session(now)
			}
			sink.RecordActivity(s, a)
		}
	}
}

// connectionAdded tells ConnectionObserver features that a connection
// became active (§9.3: profile.update on activation).
func (m *Manager) connectionAdded(id string, now time.Time) {
	for _, f := range m.features {
		if o, ok := f.(ConnectionObserver); ok {
			o.ConnectionAdded(m.session(now), id)
		}
	}
}

// displayName returns the vault's display name from a HandshakeProfiler
// feature ("" if none).
func (m *Manager) displayName() string {
	for _, f := range m.features {
		if p, ok := f.(HandshakeProfiler); ok {
			if n := p.DisplayName(); n != "" {
				return n
			}
		}
	}
	return ""
}

// handshakeProfile is the vault's hs.init profile for purpose connection:
// {name} only (§6.2).
func (m *Manager) handshakeProfile() json.RawMessage {
	n := m.displayName()
	if n == "" {
		return nil
	}
	return strictjson.NewBuilder().String("name", n).Bytes()
}

// dropReasons maps the runtime's audit events to the audit log's drop.*
// kinds (§10.9); events recorded otherwise are absent.
func auditKind(event string) string {
	switch event {
	case "peer_stale":
		return "" // recorded as connection.stale
	}
	return "drop." + event
}

// truncateUTF8 cuts s to at most n bytes without splitting a character.
func truncateUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
