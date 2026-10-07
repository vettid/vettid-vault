package vault

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// Account status through the vault (VAULT-MESSAGING 0.15.0, §11.13). The
// member API builds a display-only snapshot of the member's account and
// sends it with every unlock and, for a running vault, as the queue op
// `account`. The vault keeps the newest one in DEK state and its apps and
// desktops read it with account.get; agents and connections never see it
// (§13.7). Nothing in the vault depends on it. Since 0.20.0 it carries
// the member's full email, which only account.get returns, to the app and
// desktops: it never goes into a profile, an hs.init, an invitation, a
// feed item, an audit entry, a LEASH statement, a message to a connection
// or an agent, or an event to the host (§11.13, §13.7). The vault reads
// only the names and name_change out of it; the email stays in the
// stored bytes.

// MaxAccountSnapshot bounds a snapshot (§11.13: at most 2 KiB).
const MaxAccountSnapshot = 2048

// AccountState is the stored snapshot: its compact bytes, its as_of, the
// vault's version counter (+1 per change) and when the vault received it;
// since 0.18.0 also the account's names and name_change.allowed_after,
// parsed from it.
type AccountState struct {
	Snapshot   json.RawMessage `json:"snapshot"`
	AsOf       time.Time       `json:"as_of"`
	Version    uint64          `json:"version"`
	ReceivedAt time.Time       `json:"received_at"`
	FirstName  string          `json:"first_name,omitempty"`
	LastName   string          `json:"last_name,omitempty"`
	// AllowedAfter is name_change.allowed_after (zero: null).
	AllowedAfter time.Time `json:"allowed_after,omitempty"`
}

// ErrAccount is a snapshot the vault refuses (malformed, wrong types, too
// large).
var ErrAccount = errors.New("vault: invalid account snapshot")

// AccountSnapshot is a parsed snapshot (§11.13).
type AccountSnapshot struct {
	Raw       json.RawMessage // compact
	AsOf      time.Time
	FirstName string
	LastName  string
	// AllowedAfter is name_change.allowed_after (zero: null); Last is
	// name_change.last (nil: null).
	AllowedAfter time.Time
	Last         *NameResult
	// Email is the member's full verified address (0.20.0). The vault
	// returns it only in account.get, to the app and desktops (§11.13).
	Email string
}

// NameResult is a snapshot's name_change.last (0.18.0, §11.13): the member
// API's outcome of the vault's request seq.
type NameResult struct {
	Seq    uint64
	Status string // applied or refused
	Reason string // with refused only, as the API sent it ("" for none)
}

// MaxAccountName bounds an account name in the snapshot and the profile's
// core (§10.8, §11.13: 1–160 bytes).
const MaxAccountName = 160

// ValidAccountName reports whether s is a name as the snapshot and the
// shared profile's core carry it (§10.8, §11.13): a UTF-8 string of 1–160
// bytes without control characters (C0, C1, U+2028, U+2029).
func ValidAccountName(s string) bool {
	if s == "" || len(s) > MaxAccountName || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r >= 0x80 && r <= 0x9f || r == 0x2028 || r == 0x2029 {
			return false
		}
	}
	return true
}

// MinAccountEmail and MaxAccountEmail bound the snapshot's email (§11.13,
// 0.20.0: 3–1,016 bytes, the registration rule's 254 characters).
const (
	MinAccountEmail = 3
	MaxAccountEmail = 1016
)

// ValidAccountEmail reports whether s is an email as the snapshot carries
// it (§11.13, 0.20.0): a UTF-8 string of 3–1,016 bytes with an "@" and
// without control characters (C0, DEL, C1). The vault does not check it
// further: it is display only and shown only to the member.
func ValidAccountEmail(s string) bool {
	if len(s) < MinAccountEmail || len(s) > MaxAccountEmail || !utf8.ValidString(s) || !strings.Contains(s, "@") {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r >= 0x7f && r <= 0x9f {
			return false
		}
	}
	return true
}

// ParseAccountSnapshot parses a snapshot strictly (§11.13): an object of
// at most 2 KiB, v = 1, as_of an RFC 3339 time, (0.18.0, required)
// first_name and last_name (ValidAccountName) and name_change
// {allowed_after: RFC 3339 | null, last: {seq, status, reason?} | null},
// and (0.20.0, required) email (ValidAccountEmail); the other members the
// spec names must have their types; unknown members, 0.15.0's email_hint
// among them, are ignored.
func ParseAccountSnapshot(raw []byte) (*AccountSnapshot, error) {
	if len(raw) == 0 || len(raw) > MaxAccountSnapshot {
		return nil, ErrAccount
	}
	o, err := strictjson.ParseObject(raw)
	if err != nil {
		return nil, ErrAccount
	}
	if v, err := o.Uint("v", 1, 1); err != nil || v != 1 {
		return nil, ErrAccount
	}
	s, err := o.String("as_of")
	if err != nil {
		return nil, ErrAccount
	}
	asOf, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return nil, ErrAccount
	}
	a := &AccountSnapshot{AsOf: asOf.UTC()}
	if a.FirstName, err = o.String("first_name"); err != nil || !ValidAccountName(a.FirstName) {
		return nil, ErrAccount
	}
	if a.LastName, err = o.String("last_name"); err != nil || !ValidAccountName(a.LastName) {
		return nil, ErrAccount
	}
	nc, err := o.Object("name_change")
	if err != nil || !parseNameChange(nc, a) {
		return nil, ErrAccount
	}
	if a.Email, err = o.String("email"); err != nil || !ValidAccountEmail(a.Email) {
		return nil, ErrAccount
	}
	for _, k := range []string{"state", "account_status"} {
		if o.Has(k) {
			if _, err := o.String(k); err != nil {
				return nil, ErrAccount
			}
		}
	}
	if !nullOr(o, "deletes_at", func() bool { _, err := o.String("deletes_at"); return err == nil }) ||
		o.Has("voting_rights") && !isBool(o, "voting_rights") {
		return nil, ErrAccount
	}
	if o.Has("terms") {
		t, err := o.Object("terms")
		if err != nil || t.Has("needs_acceptance") && !isBool(t, "needs_acceptance") {
			return nil, ErrAccount
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
		return nil, ErrAccount
	}
	if a.Raw, err = strictjson.CompactObject(raw); err != nil {
		return nil, ErrAccount
	}
	return a, nil
}

// parseNameChange parses name_change (0.18.0): both members required,
// each possibly null. last's status is applied or refused (the outcomes
// §10.8 settles a request with); reason, a string, only with refused.
func parseNameChange(nc strictjson.Object, a *AccountSnapshot) bool {
	raw, ok := nc["allowed_after"]
	if !ok {
		return false
	}
	if string(raw) != "null" {
		s, err := nc.String("allowed_after")
		if err != nil {
			return false
		}
		t, err := time.Parse(time.RFC3339Nano, s)
		if err != nil {
			return false
		}
		a.AllowedAfter = t.UTC()
	}
	raw, ok = nc["last"]
	if !ok {
		return false
	}
	if string(raw) == "null" {
		return true
	}
	l, err := nc.Object("last")
	if err != nil {
		return false
	}
	r := &NameResult{}
	if r.Seq, err = l.Uint("seq", 1, strictjson.MaxSafeInteger); err != nil {
		return false
	}
	if r.Status, err = l.String("status"); err != nil || r.Status != NameApplied && r.Status != NameRefused {
		return false
	}
	reason, _, err := l.OptString("reason")
	if err != nil {
		return false
	}
	if r.Status == NameRefused {
		r.Reason = reason
	}
	a.Last = r
	return true
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
// Since 0.18.0 a stored snapshot also settles a pending name request
// (§10.8) and, when its names differ from the ones last sent, updates
// every connection's profile (the items feature decides, §10.8).
func (m *Manager) applyAccount(raw []byte, now time.Time) bool {
	a, err := ParseAccountSnapshot(raw)
	if err != nil {
		m.audit(now, "account_snapshot", "")
		return false
	}
	cur := m.st.Account
	if cur != nil && !a.AsOf.After(cur.AsOf) {
		return false
	}
	v := uint64(1)
	if cur != nil {
		v = cur.Version + 1
	}
	m.st.Account = &AccountState{Snapshot: a.Raw, AsOf: a.AsOf, Version: v, ReceivedAt: now.UTC().Truncate(time.Millisecond),
		FirstName: a.FirstName, LastName: a.LastName, AllowedAfter: a.AllowedAfter}
	m.dirty = true
	m.settleNameRequest(a.Last, now)
	// Waits for the owner check like any other fan-out (§11.13); it also
	// announces a settled name request (§10.8).
	m.notifyDevices("sync.event", strictjson.NewBuilder().String("kind", "account.changed").Uint("version", v).Bytes(), "", now)
	m.profileCoreChanged(now)
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
// received_at, name_request?}; null and version 0 before any snapshot
// arrived. name_request (0.18.0) is the latest account.name.set request.
func (m *Manager) hAccountGet(_ context.Context, _ *Session, in *envelope.Inner) (json.RawMessage, error) {
	if _, err := obj(in); err != nil {
		return nil, err
	}
	var b *strictjson.Builder
	if a := m.st.Account; a == nil {
		b = strictjson.NewBuilder().Raw("account", []byte("null")).Uint("version", 0)
	} else {
		b = strictjson.NewBuilder().Raw("account", a.Snapshot).Uint("version", a.Version).
			String("received_at", envelope.FormatTS(a.ReceivedAt))
	}
	if r := m.st.NameRequest; r != nil {
		b.Raw("name_request", r.JSON())
	}
	return b.Bytes(), nil
}
