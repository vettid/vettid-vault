package vault

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/suite"
)

// The account's names (VAULT-MESSAGING 0.18.0, §10.8, §11.13; owner
// decisions of 2026-10-07, §15 item 26). Every vault holds the account
// snapshot's first_name and last_name from its enrollment on, and every
// profile.update and connection hs.init profile carries them, with the
// vault's ik in the update, as the shared profile's read-only core. The
// member changes them only from the app: account.name.set (the credential
// feature checks the PIN and the password as an owner check does) stores
// a request here and reports the host event account_name after the flush
// that stored it; the member API applies or refuses it and pushes a
// snapshot whose name_change.last settles it.

// TypeAccountNameSet is the app's name change request (§10.8).
const TypeAccountNameSet = "account.name.set"

// EventAccountName reports a name request to the parent (§11.5, 0.18.0),
// after the flush that stored it.
const EventAccountName = "account_name"

// Name request states and outcomes (§10.8, §11.13).
const (
	NamePending = "pending"
	NameApplied = "applied"
	NameRefused = "refused"
)

// NameChangeInterval is the member API's rate limit, which the vault
// checks first from the snapshot's allowed_after (§10.8: once per 30
// days).
const NameChangeInterval = 30 * 24 * time.Hour

// MaxRequestedName is the registration rule's length, in UTF-16 code
// units (MEMBER-API /api/public/request).
const MaxRequestedName = 40

var requestedNameRE = regexp.MustCompile(`^[\p{L}\p{M}][\p{L}\p{M} '’.-]*$`)

// NormalizeRequestedName applies the registration rule to a requested
// name (§10.8): trimmed of leading and trailing spaces, it must match
// ^[\p{L}\p{M}][\p{L}\p{M} '’.-]*$ and be at most 40 UTF-16 code units.
func NormalizeRequestedName(s string) (string, bool) {
	s = strings.Trim(s, " ")
	if !requestedNameRE.MatchString(s) || len(utf16.Encode([]rune(s))) > MaxRequestedName {
		return "", false
	}
	return s, true
}

// NameRequest is the latest account.name.set request (§10.8), in DEK
// state.
type NameRequest struct {
	Seq         uint64    `json:"seq"`
	FirstName   string    `json:"first_name"`
	LastName    string    `json:"last_name"`
	RequestedAt time.Time `json:"requested_at"`
	State       string    `json:"state"`
	Reason      string    `json:"reason,omitempty"`
}

// JSON is the name request as account.get and account.name.set answer it:
// {seq, first_name, last_name, requested_at, state, reason?}.
func (r *NameRequest) JSON() json.RawMessage {
	b := strictjson.NewBuilder().Uint("seq", r.Seq).String("first_name", r.FirstName).String("last_name", r.LastName).
		String("requested_at", envelope.FormatTS(r.RequestedAt)).String("state", r.State)
	if r.Reason != "" {
		b.String("reason", r.Reason)
	}
	return b.Bytes()
}

// NameChange is the event account_name's content (§11.5): {seq,
// first_name, last_name}.
type NameChange struct {
	Seq       uint64
	FirstName string
	LastName  string
}

// ProfileHost is the runtime side of the shared profile's core (§10.8),
// for the items feature. The Manager implements it.
type ProfileHost interface {
	// AccountNames are the stored snapshot's first_name and last_name;
	// ok is false without them.
	AccountNames() (first, last string, ok bool)
	// PriorIdentity reports whether ik is an earlier identity key of
	// connection id: an old_ik in the rotation chain the vault stores for
	// it (§3.4, §10.8 step 3).
	PriorIdentity(id string, ik []byte) bool
}

// NameRequestHost is the runtime side of account.name.set (§10.8), for
// the credential feature. The Manager implements it.
type NameRequestHost interface {
	// AccountAllowedAfter is the stored snapshot's
	// name_change.allowed_after (zero: null or no snapshot).
	AccountAllowedAfter() time.Time
	// RequestAccountName stores a pending request with the next seq,
	// reports account_name after the flush, audits it and tells the
	// owner's other devices; it returns the request's JSON.
	RequestAccountName(first, last, by string, now time.Time) json.RawMessage
}

// ProfileObserver is implemented by the feature that keeps the shared
// profile (§10.8, 0.18.0).
type ProfileObserver interface {
	// ProfileCoreChanged: a snapshot was stored or the ik rotated; the
	// core may differ from the one last sent.
	ProfileCoreChanged(s *Session)
	// ConnectionRotated: connection id's first epoch under the vault's
	// current ik is active, after an ik rotation (§10.8): the update with
	// the new ik goes to that peer now, in that epoch.
	ConnectionRotated(s *Session, id string)
}

// AccountNames returns the account's names (§10.8); ok is false on a host
// without them.
func (s *Session) AccountNames() (string, string, bool) {
	if h, ok := s.host.(ProfileHost); ok {
		return h.AccountNames()
	}
	return "", "", false
}

// PriorIdentity reports whether ik is an earlier identity key of
// connection id.
func (s *Session) PriorIdentity(id string, ik []byte) bool {
	if h, ok := s.host.(ProfileHost); ok {
		return h.PriorIdentity(id, ik)
	}
	return false
}

// AccountAllowedAfter returns the snapshot's name_change.allowed_after.
func (s *Session) AccountAllowedAfter() time.Time {
	if h, ok := s.host.(NameRequestHost); ok {
		return h.AccountAllowedAfter()
	}
	return time.Time{}
}

// RequestAccountName records the sender's name request (§10.8 step 5).
func (s *Session) RequestAccountName(first, last string) (json.RawMessage, error) {
	h, ok := s.host.(NameRequestHost)
	if !ok {
		return nil, errUnavailable
	}
	return h.RequestAccountName(first, last, s.from.ID, s.now), nil
}

func (h managerHost) AccountNames() (string, string, bool) { return h.m.accountNames() }

func (h managerHost) PriorIdentity(id string, ik []byte) bool {
	p, ok := h.m.st.Connections[id]
	if !ok {
		return false
	}
	for _, raw := range p.Chain {
		if r, err := handshake.ParseRotation(raw); err == nil && suite.EqualPublic(r.OldIK, ik) {
			return true
		}
	}
	return false
}

func (h managerHost) AccountAllowedAfter() time.Time {
	if a := h.m.st.Account; a != nil {
		return a.AllowedAfter
	}
	return time.Time{}
}

func (h managerHost) RequestAccountName(first, last, by string, now time.Time) json.RawMessage {
	return h.m.requestAccountName(first, last, by, now)
}

// accountNames returns the stored snapshot's names.
func (m *Manager) accountNames() (string, string, bool) {
	a := m.st.Account
	if a == nil || a.FirstName == "" || a.LastName == "" {
		return "", "", false
	}
	return a.FirstName, a.LastName, true
}

// requestAccountName performs §10.8 steps 5 and 6 after the credential
// feature's checks: seq + 1, the request stored as pending (replacing one
// still pending), account_name reported after the flush.
func (m *Manager) requestAccountName(first, last, by string, now time.Time) json.RawMessage {
	m.st.NameSeq++
	r := &NameRequest{Seq: m.st.NameSeq, FirstName: first, LastName: last, RequestedAt: now.UTC().Truncate(time.Millisecond), State: NamePending}
	m.st.NameRequest = r
	m.nameReport = &NameChange{Seq: r.Seq, FirstName: first, LastName: last}
	m.dirty = true
	m.record(Activity{Kind: "account.name_requested", Ref: strconv.FormatUint(r.Seq, 10), Audit: true}, now)
	m.announceNameRequest(by, now)
	return r.JSON()
}

// announceNameRequest sends sync.event{account.changed} for a changed name
// request (§10.8) to the owner's devices except `except`.
func (m *Manager) announceNameRequest(except string, now time.Time) {
	var v uint64
	if m.st.Account != nil {
		v = m.st.Account.Version
	}
	m.notifyDevices("sync.event", strictjson.NewBuilder().String("kind", "account.changed").Uint("version", v).Bytes(), except, now)
}

// settleNameRequest applies a stored snapshot's name_change.last to the
// pending request (§10.8): the same seq sets its state and reason; a
// higher seq (an honest host never sends one) refuses it with "account".
// It reports whether the request changed; the caller announces it.
func (m *Manager) settleNameRequest(last *NameResult, now time.Time) bool {
	r := m.st.NameRequest
	if r == nil || r.State != NamePending || last == nil || last.Seq < r.Seq {
		return false
	}
	if last.Seq == r.Seq {
		r.State, r.Reason = last.Status, last.Reason
	} else {
		r.State, r.Reason = NameRefused, "account"
	}
	kind := "account.name_refused"
	if r.State == NameApplied {
		kind = "account.name_applied"
	}
	m.record(Activity{Kind: kind, Ref: strconv.FormatUint(r.Seq, 10), Audit: true}, now)
	return true
}

// pendingNameChange is the latest name request while it is still
// pending (0.19.0: re-reported with every unlocked report, §11.5), or nil.
func (m *Manager) pendingNameChange() *NameChange {
	r := m.st.NameRequest
	if r == nil || r.State != NamePending {
		return nil
	}
	return &NameChange{Seq: r.Seq, FirstName: r.FirstName, LastName: r.LastName}
}

// reportName reports a stored name request to the parent after the flush
// that stored it (§11.5, as app_key).
func (m *Manager) reportName() {
	n := m.nameReport
	if n == nil || m.st == nil {
		return
	}
	m.nameReport = nil
	if m.opt.Lifecycle != nil {
		m.opt.Lifecycle(LifecycleEvent{Event: EventAccountName, VaultID: m.st.VaultID, Release: m.opt.Release.PCR0,
			VaultVersion: m.opt.Release.PCR0, StateVersion: StateVersion, Name: n})
	}
}

// profileCoreChanged tells ProfileObserver features that the core may
// have changed (a stored snapshot, an ik rotation).
func (m *Manager) profileCoreChanged(now time.Time) {
	for _, f := range m.features {
		if o, ok := f.(ProfileObserver); ok {
			o.ProfileCoreChanged(m.session(now))
		}
	}
}

// connectionRotated tells ProfileObserver features that a connection's
// epoch caught up with the vault's current ik (§10.8).
func (m *Manager) connectionRotated(id string, now time.Time) {
	for _, f := range m.features {
		if o, ok := f.(ProfileObserver); ok {
			o.ConnectionRotated(m.session(now), id)
		}
	}
}

// rotationPending reports whether p's current epoch was made before the
// vault's latest ik rotation (§10.8: no profile.update with the new ik in
// it).
func (m *Manager) rotationPending(p *Peer) bool {
	return p.Kind == KindConnection && p.OwnChainAtEpoch < len(m.st.Rotations)
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
