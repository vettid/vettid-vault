package vault

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// Account status through the vault (VAULT-MESSAGING 0.15.0, §11.13). The
// member API builds a display-only snapshot of the member's account and
// sends it with every unlock and, for a running vault, as the queue op
// `account`. The vault keeps the newest one in DEK state and its apps and
// desktops read it with account.get; agents and connections never see it
// (§13.7). Nothing in the vault depends on it.

// MaxAccountSnapshot bounds a snapshot (§11.13: at most 2 KiB).
const MaxAccountSnapshot = 2048

// AccountState is the stored snapshot: its compact bytes, its as_of, the
// vault's version counter (+1 per change) and when the vault received it.
type AccountState struct {
	Snapshot   json.RawMessage `json:"snapshot"`
	AsOf       time.Time       `json:"as_of"`
	Version    uint64          `json:"version"`
	ReceivedAt time.Time       `json:"received_at"`
}

// ErrAccount is a snapshot the vault refuses (malformed, wrong types, too
// large).
var ErrAccount = errors.New("vault: invalid account snapshot")

// ParseAccountSnapshot parses a snapshot strictly (§11.13): an object of
// at most 2 KiB, v = 1, as_of an RFC 3339 time; the members the spec
// names must have their types; unknown members are ignored. It returns
// the compact bytes and as_of.
func ParseAccountSnapshot(raw []byte) (json.RawMessage, time.Time, error) {
	if len(raw) == 0 || len(raw) > MaxAccountSnapshot {
		return nil, time.Time{}, ErrAccount
	}
	o, err := strictjson.ParseObject(raw)
	if err != nil {
		return nil, time.Time{}, ErrAccount
	}
	if v, err := o.Uint("v", 1, 1); err != nil || v != 1 {
		return nil, time.Time{}, ErrAccount
	}
	s, err := o.String("as_of")
	if err != nil {
		return nil, time.Time{}, ErrAccount
	}
	asOf, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return nil, time.Time{}, ErrAccount
	}
	for _, k := range []string{"email_hint", "state", "account_status"} {
		if o.Has(k) {
			if _, err := o.String(k); err != nil {
				return nil, time.Time{}, ErrAccount
			}
		}
	}
	if !nullOr(o, "deletes_at", func() bool { _, err := o.String("deletes_at"); return err == nil }) ||
		o.Has("voting_rights") && !isBool(o, "voting_rights") {
		return nil, time.Time{}, ErrAccount
	}
	if o.Has("terms") {
		t, err := o.Object("terms")
		if err != nil || t.Has("needs_acceptance") && !isBool(t, "needs_acceptance") {
			return nil, time.Time{}, ErrAccount
		}
	}
	if !nullOr(o, "subscription", func() bool {
		sub, err := o.Object("subscription")
		if err != nil {
			return false
		}
		for _, k := range []string{"type_name", "status", "expires_at"} {
			if sub.Has(k) {
				if _, err := sub.String(k); err != nil {
					return false
				}
			}
		}
		return !sub.Has("paid") || isBool(sub, "paid")
	}) {
		return nil, time.Time{}, ErrAccount
	}
	c, err := strictjson.CompactObject(raw)
	if err != nil {
		return nil, time.Time{}, ErrAccount
	}
	return c, asOf.UTC(), nil
}

func isBool(o strictjson.Object, k string) bool {
	_, err := o.Bool(k)
	return err == nil
}

// nullOr reports whether member k is absent, null, or passes ok.
func nullOr(o strictjson.Object, k string, ok func() bool) bool {
	raw, has := o[k]
	return !has || string(raw) == "null" || ok()
}

// applyAccount stores a snapshot if it is newer than the stored one
// (as_of later) and tells the owner's apps and desktops; it reports
// whether it changed anything. A refused or older snapshot is ignored.
func (m *Manager) applyAccount(raw []byte, now time.Time) bool {
	c, asOf, err := ParseAccountSnapshot(raw)
	if err != nil {
		m.audit(now, "account_snapshot", "")
		return false
	}
	cur := m.st.Account
	if cur != nil && !asOf.After(cur.AsOf) {
		return false
	}
	v := uint64(1)
	if cur != nil {
		v = cur.Version + 1
	}
	m.st.Account = &AccountState{Snapshot: c, AsOf: asOf, Version: v, ReceivedAt: now.UTC().Truncate(time.Millisecond)}
	m.dirty = true
	// Waits for the owner check like any other fan-out (§11.13).
	m.notifyDevices("sync.event", strictjson.NewBuilder().String("kind", "account.changed").Uint("version", v).Bytes(), "", now)
	return true
}

// AccountVersion returns the stored snapshot's version (0: none).
func (m *Manager) AccountVersion() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.st == nil || m.st.Account == nil {
		return 0
	}
	return m.st.Account.Version
}

// SetAccount applies the queue op `account` to the running vault
// (§11.13): stored and announced in one flush.
func (m *Manager) SetAccount(ctx context.Context, raw []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.locked {
		return ErrLocked
	}
	if !m.applyAccount(raw, m.now()) {
		return m.flushIfDirty(ctx) // an audit entry at most
	}
	if err := m.persist(ctx, false); err != nil {
		return err
	}
	m.drainOutbox(ctx)
	return m.flushIfDirty(ctx)
}

// hAccountGet answers account.get (§10.2): {account, version,
// received_at}; null and version 0 before any snapshot arrived.
func (m *Manager) hAccountGet(_ context.Context, _ *Session, in *envelope.Inner) (json.RawMessage, error) {
	if _, err := obj(in); err != nil {
		return nil, err
	}
	a := m.st.Account
	if a == nil {
		return strictjson.NewBuilder().Raw("account", []byte("null")).Uint("version", 0).Bytes(), nil
	}
	return strictjson.NewBuilder().Raw("account", a.Snapshot).Uint("version", a.Version).
		String("received_at", envelope.FormatTS(a.ReceivedAt)).Bytes(), nil
}
