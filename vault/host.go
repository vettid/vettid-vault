package vault

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/leashwire"
	"sort"
	"time"
	"unicode/utf8"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/callwire"
	"github.com/vettid/vettid-vault/vms/suite"
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
	return h.connInfo(p), true
}

// connInfo is a connection's PeerInfo with RotationPending (§10.8).
func (h managerHost) connInfo(p *Peer) PeerInfo {
	i := info(p)
	i.RotationPending = h.m.rotationPending(p)
	return i
}

func (h managerHost) Connections() []PeerInfo {
	ids := make([]string, 0, len(h.m.st.Connections))
	for id := range h.m.st.Connections {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]PeerInfo, 0, len(ids))
	for _, id := range ids {
		out = append(out, h.connInfo(h.m.st.Connections[id]))
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

func (h managerHost) IdentityKey() ed25519.PublicKey {
	return append(ed25519.PublicKey(nil), h.m.keys.ik.Public().(ed25519.PublicKey)...)
}

func (h managerHost) Device(id string) (PeerInfo, bool) {
	p, ok := h.m.st.Devices[id]
	if !ok || p.State != PeerActive || p.Recovering || !h.m.hasAccess(p, h.m.now()) {
		return PeerInfo{}, false
	}
	return info(p), true
}

func (h managerHost) PairedDevice(id string) (PeerInfo, bool) {
	p, ok := h.m.st.Devices[id]
	if !ok || p.State != PeerActive || p.Recovering {
		return PeerInfo{}, false
	}
	return info(p), true
}

func (h managerHost) Send(to, typ string, body json.RawMessage, o SendOptions, now time.Time) error {
	p := h.m.peer(to)
	if p == nil || p.State != PeerActive || p.Recovering || !h.m.hasAccess(p, now) {
		return ErrNoSession // a desktop or agent only within its access session (§6.8)
	}
	if h.m.sendWith(p, typ, body, o, now) == "" {
		return ErrNoSession
	}
	return nil
}

func (h managerHost) SignICEConfig(config []byte) ([]byte, error) {
	if _, err := callwire.ParseICEConfig(config); err != nil {
		return nil, err
	}
	return callwire.SignICE(h.m.keys.ik, config)
}

func (h managerHost) VouchCallShare(deviceIK ed25519.PublicKey, m []byte) ([]byte, error) {
	if len(deviceIK) != ed25519.PublicKeySize || !callwire.ValidShareMessage(m) {
		return nil, errBadRequest
	}
	return suite.Sign(h.m.keys.ik, callwire.LabelVouch, callwire.VouchMessage(deviceIK, m))
}

// IntroInviteTTL is the lifetime of an introduction's invitation
// (§10.15), lowered to the relay's limits.
const IntroInviteTTL = 24 * time.Hour

func (h managerHost) CreateIntroInvite(ctx context.Context, expectIK []byte, introBy string, now time.Time) (string, string, error) {
	if len(expectIK) != ed25519.PublicKeySize {
		return "", "", errBadRequest
	}
	ttl := IntroInviteTTL
	for _, l := range []int64{h.m.limits.OpenTokenMaxLifetimeSeconds, h.m.limits.ClaimTTLSeconds} {
		if l > 0 && time.Duration(l)*time.Second < ttl {
			ttl = time.Duration(l) * time.Second
		}
	}
	inv, link, err := h.m.createInvite(ctx, KindConnection, ttl, "intro", now)
	if err != nil {
		return "", "", err
	}
	inv.IntroIK, inv.IntroBy = append([]byte(nil), expectIK...), introBy
	h.m.dirty = true
	return inv.ID, link, nil
}

func (h managerHost) AcceptInviteLink(ctx context.Context, link, introBy string, now time.Time) (string, error) {
	og, err := h.m.acceptInvite(ctx, link, introBy, now)
	if err != nil {
		return "", err
	}
	return og.New.ID, nil
}

func (h managerHost) SignLeashStatus(statement []byte) ([]byte, error) {
	return leashwire.SignStatus(h.m.keys.ik, statement)
}

func (h managerHost) RotationsFrom(ik []byte) ([]json.RawMessage, bool) {
	if suite.EqualPublic(ik, h.m.keys.ik.Public().(ed25519.PublicKey)) {
		return nil, true
	}
	for i, raw := range h.m.st.Rotations {
		r, err := handshake.ParseRotation(raw)
		if err == nil && suite.EqualPublic(r.OldIK, ik) {
			out := make([]json.RawMessage, 0, len(h.m.st.Rotations)-i)
			for _, x := range h.m.st.Rotations[i:] {
				out = append(out, append(json.RawMessage(nil), x...))
			}
			return out, true
		}
	}
	return nil, false
}

func (h managerHost) CancelInvite(id string, now time.Time) {
	inv := h.m.st.Invites[id]
	if inv == nil || inv.Kind != KindConnection {
		return
	}
	h.m.denyJTI(inv.OpenJTI, now)
	h.m.queueDeleteClaim(inv.ClaimID, now)
	delete(h.m.st.Invites, id)
	h.m.dirty = true
}

func (h managerHost) NotifyDevicesWith(typ string, body json.RawMessage, except string, o SendOptions, now time.Time) {
	h.m.notifyDevicesWith(typ, body, except, o, now)
}

func (h managerHost) OwnerLastActive() time.Time {
	var t time.Time
	for _, p := range h.m.st.Devices {
		if p.State == PeerActive && (p.Kind == KindApp || p.Kind == KindDesktop) && p.LastActiveAt.After(t) {
			t = p.LastActiveAt
		}
	}
	return t
}

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
	// §10.4 (0.18.0): name is the display name of the kept profile,
	// absent when it has none.
	p.Name = profileName(profile)
	h.m.dirty = true
	return nil
}

func (h managerHost) CompleteRecovery(id string, now time.Time) error {
	return h.m.completeRecovery(id, now)
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
	m.countHeld(a)
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

// handshakeProfile is the vault's hs.init profile for purpose connection
// (§6.2, 0.18.0): {first_name, last_name, name?}, the core names and the
// display name, if any. ok is false without the account's names.
func (m *Manager) handshakeProfile() (json.RawMessage, bool) {
	first, last, ok := m.accountNames()
	if !ok {
		return nil, false
	}
	b := strictjson.NewBuilder().String("first_name", first).String("last_name", last)
	if n := m.displayName(); n != "" {
		b.String("name", n)
	}
	return b.Bytes(), true
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
