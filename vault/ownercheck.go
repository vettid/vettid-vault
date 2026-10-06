package vault

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// The daily owner check and the hold (VAULT-MESSAGING 0.13.0, §3.6; owner
// decisions of 2026-10-05 and 2026-10-06). At least once per interval the
// member proves to the vault, with the PIN and the credential password
// together (vault.owner_check, handled by the credential feature), that
// they still hold the app. Past the deadline the app is gated: it may send
// only the check and what the check needs (owner_check_required, or
// drop.owner_check). With the hold on (the default), the rest of the vault
// holds too: desktops' access sessions are suspended, agents are paused
// (no LEASH status statements), calls do not ring, presence is not
// answered and the owner's devices get no fan-out but the content-free
// vault.held counts. The vault keeps serving its peers throughout.
//
// The record lives in DEK state (State.OwnerCheck), so it survives locks;
// the clock runs on the vault's own clock (Options.Now).

// TypeOwnerCheck is the owner check's message type (§3.6.1, §10.2):
// "vault.owner-check" (owner decision of 2026-10-06, VAULT-MESSAGING
// 0.15.2; 0.13.0's "vault.owner_check" broke §5.3's type grammar).
const TypeOwnerCheck = "vault.owner-check"

// Owner-check constants (§3.6.2, §3.6.3, §3.6.4, §3.6.7).
const (
	DefaultOwnerCheckInterval = 24 * time.Hour
	MinOwnerCheckInterval     = time.Hour
	MaxHoldOff                = 30 * 24 * time.Hour
	OwnerCheckLockAfter       = 10
	HeldNoticeEvery           = 10 * time.Minute
	LockOwnerCheck            = "owner_check" // vault.locking reason (§3.6.4)
)

// Owner-check states as vault.status reports them (§10.2).
const (
	OwnerCheckOK   = "ok"
	OwnerCheckDue  = "due"  // past the deadline, the hold off: only the app is gated
	OwnerCheckHeld = "held" // past the deadline, the hold on
)

// OwnerCheck is the owner-check record (§3.6.1): {last_at, deadline,
// failures}, plus the hold's own bookkeeping. A zero Deadline means the
// clock has not started (a vault before its first credential.create).
type OwnerCheck struct {
	LastAt   time.Time `json:"last_at,omitempty"`
	Deadline time.Time `json:"deadline,omitempty"`
	Failures int       `json:"failures,omitempty"`
	// Gate is the state the vault last acted on ("", "due" or "held"):
	// entering the hold runs once, and the counts start at the deadline.
	Gate string `json:"gate,omitempty"`
	// Waiting are vault.held's counts since the deadline; Notices the last
	// vault.held per device (at most one per HeldNoticeEvery, §3.6.3).
	Waiting HeldCounts            `json:"waiting"`
	Notices map[string]HeldNotice `json:"notices,omitempty"`
}

// HeldCounts are vault.held's content-free counts (§3.6.3).
type HeldCounts struct {
	Messages uint64 `json:"messages"`
	Requests uint64 `json:"requests"`
	Calls    uint64 `json:"calls"`
	Other    uint64 `json:"other"`
}

// HeldNotice is the last vault.held sent to one device.
type HeldNotice struct {
	At     time.Time  `json:"at"`
	Counts HeldCounts `json:"counts"`
}

// OwnerCheckInterval is the setting owner_check.interval_seconds (§3.6.2).
func (s Settings) OwnerCheckInterval() time.Duration {
	if s.OwnerCheckSeconds == 0 {
		return DefaultOwnerCheckInterval
	}
	return time.Duration(s.OwnerCheckSeconds) * time.Second
}

// HoldOn reports whether the vault holds past the deadline (§3.6.7):
// owner_check.hold, back on by itself at hold_off_until.
func (s Settings) HoldOn(now time.Time) bool {
	return !s.HoldOff || s.HoldOffUntil != nil && !now.Before(*s.HoldOffUntil)
}

// HoldChange is a hold change carried by a vault.owner_check (§3.6.7):
// On, or off (Until zero: until the member turns it on).
type HoldChange struct {
	On    bool
	Until time.Time
}

// OwnerCheckInfo is what a successful check answers (§3.6.1).
type OwnerCheckInfo struct {
	Deadline     time.Time
	Interval     time.Duration
	Hold         bool
	HoldOffUntil *time.Time
}

// Members adds {deadline, interval_seconds, hold, hold_off_until?}.
func (i OwnerCheckInfo) Members(b *strictjson.Builder) {
	b.String("deadline", envelope.FormatTS(i.Deadline)).Uint("interval_seconds", uint64(i.Interval/time.Second)).Bool("hold", i.Hold)
	if i.HoldOffUntil != nil {
		b.String("hold_off_until", envelope.FormatTS(*i.HoldOffUntil))
	}
}

// OwnerCheckHost is the runtime side of the owner check, for the features
// (the credential feature runs vault.owner_check; calls, presence and
// LEASH consult the hold). The Manager implements it.
type OwnerCheckHost interface {
	// OwnerCheckState is "ok", "due" or "held" (§3.6.3, §3.6.7).
	OwnerCheckState(now time.Time) string
	// OwnerCheckPassed records a successful check (or what starts the
	// clock like one: a completed transfer or recovery, §3.6.1), applies
	// a hold change and ends a hold. audit: audit owner_check.passed.
	OwnerCheckPassed(change *HoldChange, audit bool, by string, now time.Time) OwnerCheckInfo
	// OwnerCheckFailed counts a failed check (ref "pin" or "password");
	// the tenth consecutive one locks the vault after the batch (§3.6.4).
	OwnerCheckFailed(ref string, now time.Time)
	// OwnerCheckEnrolled starts the clock fresh at a credential.create
	// (§3.6.1; owner decision of 2026-10-06: every new credential).
	OwnerCheckEnrolled(now time.Time)
}

// OwnerHoldObserver is implemented by features that act when the hold
// begins or ends (§3.6.3): the credential's unlock window ends, a ringing
// call stops ringing, agents get fresh status statements after a check.
type OwnerHoldObserver interface {
	OwnerHoldStarted(s *Session)
	OwnerHoldEnded(s *Session)
}

// CallGate is implemented by the calls feature: whether a device answered
// a call, still active, before t (its call.ice and call.end pass the gate,
// §3.6.3).
type CallGate interface {
	CallAnsweredBefore(deviceID string, t time.Time) bool
}

// CredentialAlarm is implemented by the credential feature: the open clone
// alarm's state ("" for none), whose path stays open while held (§3.5.9).
type CredentialAlarm interface {
	AlarmState() string
}

func (s *Session) ownerHost() (OwnerCheckHost, bool) {
	h, ok := s.host.(OwnerCheckHost)
	return h, ok
}

// OwnerCheckState returns "ok", "due" or "held" (§3.6.3); "ok" on a host
// without the owner check.
func (s *Session) OwnerCheckState() string {
	if h, ok := s.ownerHost(); ok {
		return h.OwnerCheckState(s.now)
	}
	return OwnerCheckOK
}

// OwnerHeld reports whether the vault is held (the hold on, past the
// deadline).
func (s *Session) OwnerHeld() bool { return s.OwnerCheckState() == OwnerCheckHeld }

// OwnerCheckPassed records a successful owner check by the sender.
func (s *Session) OwnerCheckPassed(change *HoldChange, audit bool) (OwnerCheckInfo, error) {
	h, ok := s.ownerHost()
	if !ok {
		return OwnerCheckInfo{}, errUnavailable
	}
	return h.OwnerCheckPassed(change, audit, s.from.ID, s.now), nil
}

// OwnerCheckFailed counts a failed owner check.
func (s *Session) OwnerCheckFailed(ref string) {
	if h, ok := s.ownerHost(); ok {
		h.OwnerCheckFailed(ref, s.now)
	}
}

// OwnerCheckEnrolled starts the clock at enrollment.
func (s *Session) OwnerCheckEnrolled() {
	if h, ok := s.ownerHost(); ok {
		h.OwnerCheckEnrolled(s.now)
	}
}

// IsCode reports whether err is a handler error with code.
func IsCode(err error, code string) bool {
	var he *HandlerError
	return errors.As(err, &he) && he.Code == code
}

func (h managerHost) OwnerCheckState(now time.Time) string { return h.m.ownerCheckState(now) }

func (h managerHost) OwnerCheckPassed(c *HoldChange, audit bool, by string, now time.Time) OwnerCheckInfo {
	return h.m.ownerCheckPassed(c, audit, by, now)
}

func (h managerHost) OwnerCheckFailed(ref string, now time.Time) { h.m.ownerCheckFailed(ref, now) }

func (h managerHost) OwnerCheckEnrolled(now time.Time) { h.m.ownerCheckEnrolled(now) }

// ownerCheckRunning: the vault has a credential (the check needs one) and
// its clock has started.
func (m *Manager) ownerCheckRunning() bool {
	return m.st != nil && m.st.OwnerCheck != nil && !m.st.OwnerCheck.Deadline.IsZero() && m.ocCred
}

// refreshOwnerCred caches whether the vault has a credential, for the
// owner check. It asks the credential feature, so it runs only where no
// feature holds its own lock (before each batch and message, after each
// handler): the hold's checks also run inside handlers (fan-out).
func (m *Manager) refreshOwnerCred() {
	m.ocCred = m.st != nil && m.hasGate() && m.credentialExists()
}

// ownerCheckState is "ok", "due" or "held" at now (§3.6.3). A vault
// without a credential is never gated: the check needs the credential, and
// a restricted vault (§3.5.7) must still be able to create one.
func (m *Manager) ownerCheckState(now time.Time) string {
	now = m.ocTime(now)
	if !m.ownerCheckRunning() || now.Before(m.st.OwnerCheck.Deadline) {
		return OwnerCheckOK
	}
	if m.st.Settings.HoldOn(now) {
		return OwnerCheckHeld
	}
	return OwnerCheckDue
}

func (m *Manager) ownerCheckRecord() *OwnerCheck {
	if m.st.OwnerCheck == nil {
		m.st.OwnerCheck = &OwnerCheck{}
	}
	return m.st.OwnerCheck
}

// ownerCheckInit runs at every start (§3.6.1 "a vault from before
// 0.13.0"): a vault whose state has no record starts its clock now if it
// has a credential; otherwise its first credential.create starts it.
func (m *Manager) ownerCheckInit(now time.Time) {
	m.refreshOwnerCred()
	if m.st.OwnerCheck != nil || !m.hasGate() {
		return
	}
	rec := m.ownerCheckRecord()
	if m.ocCred {
		m.startClock(rec, now)
	}
	m.dirty = true
}

// ocTime is the time the owner check compares (Options.OwnerCheckClock,
// for tests; the vault's clock otherwise).
func (m *Manager) ocTime(now time.Time) time.Time {
	if c := m.opt.OwnerCheckClock; c != nil {
		return c()
	}
	return now
}

func (m *Manager) startClock(rec *OwnerCheck, now time.Time) {
	now = m.ocTime(now).UTC().Truncate(time.Millisecond)
	rec.LastAt, rec.Deadline, rec.Failures = now, now.Add(m.st.Settings.OwnerCheckInterval()), 0
}

// ownerCheckEnrolled starts the clock fresh when the vault gets a new
// credential by credential.create (owner decision of 2026-10-06: a vault
// is without a credential only during enrollment, and every new credential
// starts the clock fresh, as a recovery or a transfer does): the first one
// at enrollment, and one after a credential.delete, which also ends a
// hold.
func (m *Manager) ownerCheckEnrolled(now time.Time) {
	rec := m.ownerCheckRecord()
	if !rec.Deadline.IsZero() {
		m.ownerCheckPassed(nil, false, "", now)
		return
	}
	m.startClock(rec, now)
	m.dirty = true
}

// ownerCheckPassed applies step 8 of §3.6.1 (the CEK has rotated): the
// record, a hold change (§3.6.7), the end of a hold, the audit and the
// other devices' sync.event.
func (m *Manager) ownerCheckPassed(c *HoldChange, audit bool, by string, now time.Time) OwnerCheckInfo {
	rec := m.ownerCheckRecord()
	was := rec.Gate
	m.startClock(rec, now)
	set := &m.st.Settings
	changed := false
	switch {
	case c == nil:
	case c.On && set.HoldOff:
		set.HoldOff, set.HoldOffUntil, changed = false, nil, true
		m.record(Activity{Kind: "owner_check.hold_changed", Ref: "on", Audit: true, Feed: true, Priority: "high"}, now)
	case !c.On:
		var until *time.Time
		ref := "off"
		if !c.Until.IsZero() {
			u := c.Until.UTC().Truncate(time.Millisecond)
			until, ref = &u, "off_until:"+envelope.FormatTS(u)
		}
		if !set.HoldOff || !sameTime(set.HoldOffUntil, until) {
			set.HoldOff, set.HoldOffUntil, changed = true, until, true
			m.record(Activity{Kind: "owner_check.hold_changed", Ref: ref, Audit: true, Feed: true, Priority: "high"}, now)
		}
	}
	rec.Gate, rec.Waiting, rec.Notices = "", HeldCounts{}, nil
	m.dirty = true
	if audit {
		m.record(Activity{Kind: "owner_check.passed", DeviceID: by, Audit: true}, now)
	}
	if changed {
		set.Version++
		m.notifyDevices("sync.event", strictjson.NewBuilder().String("kind", "settings.changed").Uint("version", set.Version).Bytes(), by, now)
	}
	m.notifyDevices("sync.event", strictjson.NewBuilder().String("kind", "owner_check").
		String("deadline", envelope.FormatTS(rec.Deadline)).Bytes(), by, now)
	if was == OwnerCheckHeld {
		s := m.session(now)
		for _, f := range m.features {
			if o, ok := f.(OwnerHoldObserver); ok {
				o.OwnerHoldEnded(s) // agents get fresh status statements (§10.11)
			}
		}
	}
	return m.ownerCheckInfo()
}

func sameTime(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Equal(*b)
}

func (m *Manager) ownerCheckInfo() OwnerCheckInfo {
	set := m.st.Settings
	i := OwnerCheckInfo{Interval: set.OwnerCheckInterval(), Hold: !set.HoldOff}
	if rec := m.st.OwnerCheck; rec != nil {
		i.Deadline = rec.Deadline
	}
	if set.HoldOff && set.HoldOffUntil != nil {
		u := *set.HoldOffUntil
		i.HoldOffUntil = &u
	}
	return i
}

// ownerCheckFailed counts a failed check (§3.6.4).
func (m *Manager) ownerCheckFailed(ref string, now time.Time) {
	rec := m.ownerCheckRecord()
	rec.Failures++
	m.dirty = true
	m.record(Activity{Kind: "owner_check.failed", Ref: ref, Audit: true, Feed: true, Priority: "high"}, now)
	if rec.Failures >= OwnerCheckLockAfter {
		// Locks after the batch's flush, which answers the request first
		// (§3.6.4, §12.3).
		m.record(Activity{Kind: "owner_check.locked", Ref: uitoa(uint64(rec.Failures)), Audit: true, Feed: true, Priority: "urgent"}, now)
		m.lockPending, m.lockReason = true, LockOwnerCheck
	}
}

// ownerCheckTick compares the time with the deadline and hold_off_until
// (§3.6.3, §3.6.7): before each batch (at most 30 s apart), at the start
// and after a settings change.
func (m *Manager) ownerCheckTick(now time.Time) {
	if m.st == nil || m.st.OwnerCheck == nil {
		return
	}
	rec := m.st.OwnerCheck
	set := &m.st.Settings
	if set.HoldOff && set.HoldOffUntil != nil && !m.ocTime(now).Before(*set.HoldOffUntil) {
		set.HoldOff, set.HoldOffUntil = false, nil
		set.Version++
		m.dirty = true
		m.record(Activity{Kind: "owner_check.hold_changed", Ref: "on:expired", Audit: true, Feed: true, Priority: "high"}, now)
		m.notifyDevices("sync.event", strictjson.NewBuilder().String("kind", "settings.changed").Uint("version", set.Version).Bytes(), "", now)
	}
	gate := m.ownerCheckState(now)
	if gate == OwnerCheckOK {
		gate = ""
	}
	force := false
	if gate != rec.Gate {
		if rec.Gate == "" {
			rec.Waiting, rec.Notices = HeldCounts{}, nil // counted from the deadline
		}
		rec.Gate = gate
		m.dirty = true
		force = gate != ""
		if gate == OwnerCheckHeld {
			m.enterHold(now)
		}
	}
	if rec.Gate != "" {
		m.heldNotices(now, m.ocTime(now), force)
	}
}

// enterHold runs once when the hold begins (§3.6.3), in the batch's flush.
func (m *Manager) enterHold(now time.Time) {
	s := m.session(now)
	for _, f := range m.features {
		if o, ok := f.(OwnerHoldObserver); ok {
			o.OwnerHoldStarted(s) // the unlock window ends; ringing stops
		}
	}
	for _, id := range sortedKeys(m.st.Held) {
		m.answerHeld(m.st.Held[id], "owner_check_required", now)
		delete(m.st.Held, id)
	}
	for id := range m.st.AccessRequests {
		delete(m.st.AccessRequests, id)
	}
	m.dirty = true
	m.record(Activity{Kind: "owner_check.held", Audit: true}, now)
}

func sortedKeys[V any](mp map[string]V) []string {
	out := make([]string, 0, len(mp))
	for k := range mp {
		out = append(out, k)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// heldNotices sends vault.held to the app (and, held, to desktops in an
// access session) when the gate begins, then when the counts changed, at
// most once per device every HeldNoticeEvery (§3.6.3).
func (m *Manager) heldNotices(now, oc time.Time, force bool) {
	rec := m.st.OwnerCheck
	if rec.Notices == nil {
		rec.Notices = map[string]HeldNotice{}
	}
	body := strictjson.NewBuilder().String("deadline", envelope.FormatTS(rec.Deadline)).
		Raw("waiting", strictjson.NewBuilder().Uint("messages", rec.Waiting.Messages).Uint("requests", rec.Waiting.Requests).
			Uint("calls", rec.Waiting.Calls).Uint("other", rec.Waiting.Other).Bytes()).Bytes()
	for _, p := range m.ownerDevices() {
		if p.Kind != KindApp && rec.Gate != OwnerCheckHeld {
			continue // with the hold off only the app is gated
		}
		n, sent := rec.Notices[p.ID]
		if sent && oc.Sub(n.At) < HeldNoticeEvery {
			continue
		}
		if !force && (sent && n.Counts == rec.Waiting || !sent && rec.Waiting == (HeldCounts{})) {
			continue
		}
		if m.sendTo(p, "vault.held", body, now) != "" {
			rec.Notices[p.ID] = HeldNotice{At: oc, Counts: rec.Waiting}
			m.dirty = true
		}
	}
}

// countHeld counts an event that would have created a feed item while the
// owner's devices are gated (vault.held, §3.6.3).
func (m *Manager) countHeld(a Activity) {
	rec := m.st.OwnerCheck
	if rec == nil || rec.Gate == "" || !a.Feed {
		return
	}
	switch a.Kind {
	case "message.received":
		rec.Waiting.Messages++
	case "connection.request":
		rec.Waiting.Requests++
	case "call.missed":
		rec.Waiting.Calls++
	default:
		rec.Waiting.Other++
	}
	m.dirty = true
}

// holdAllows is the hold's allow list (§3.6.3) for a message from owner
// device p while the vault is due or held.
func (m *Manager) holdAllows(p *Peer, typ, state string) bool {
	switch typ {
	case tokenIssuedType, tokenRefreshType, "relay.address.update":
		return true // any device: the transport types
	}
	deadline := m.st.OwnerCheck.Deadline
	switch p.Kind {
	case KindApp: // the holder: gated whether or not the hold is on
		switch typ {
		case TypeOwnerCheck, "vault.status", "vault.lock", "credential.utk.get", "credential.get", "credential.ack",
			"credential.version", "credential.lock", "call.end":
			return true
		case "credential.alarm.confirm":
			return m.alarmState() != ""
		case "credential.rotate":
			return m.alarmState() == "rotation_required"
		case "device.transfer.approve", "device.transfer.reject":
			return m.st.Transfer != nil // a transfer opened before the hold
		case "call.ice":
			return m.callAnsweredBefore(p.ID, deadline)
		}
		return false
	case KindDesktop:
		if state != OwnerCheckHeld {
			return true
		}
		switch typ {
		case "vault.status", "vault.lock", "device.session.end":
			return true
		case "call.end", "call.ice":
			return m.callAnsweredBefore(p.ID, deadline)
		}
		return false
	case KindAgent:
		return state != OwnerCheckHeld || typ == "vault.status" || typ == "device.session.end"
	}
	return true
}

// holdDelivers reports whether a message to owner device p goes out while
// the vault is due or held (§3.6.3 "What the vault still sends its
// owner's devices"). Responses are not filtered.
func (m *Manager) holdDelivers(p *Peer, typ string, body json.RawMessage, now time.Time) bool {
	if p.Kind == KindConnection || p.Recovering {
		return true
	}
	state := m.ownerCheckState(now)
	if state == OwnerCheckOK || state == OwnerCheckDue && p.Kind != KindApp {
		return true
	}
	switch typ {
	case "vault.held", "vault.locking", "credential.alarm", "device.transfer.pending", "device.unlinked",
		tokenIssuedType, tokenRefreshType, "relay.address.update", "identity.rotate", "call.end", "call.ice":
		return true
	case "sync.event", "feed.event":
		o, err := strictjson.ParseObject(body)
		if err != nil {
			return false
		}
		k, _ := o.String("kind")
		return k == "credential.alarm"
	case "call.offer", "call.ringing":
		return state == OwnerCheckDue // with the hold off a call rings on the app
	}
	return false
}

func (m *Manager) alarmState() string {
	for _, f := range m.features {
		if a, ok := f.(CredentialAlarm); ok {
			return a.AlarmState()
		}
	}
	return ""
}

func (m *Manager) callAnsweredBefore(device string, t time.Time) bool {
	for _, f := range m.features {
		if c, ok := f.(CallGate); ok && c.CallAnsweredBefore(device, t) {
			return true
		}
	}
	return false
}

// ownerCheckStatus is vault.status's owner_check member (§10.2): the
// state alone to agents.
func (m *Manager) ownerCheckStatus(kind string, now time.Time) []byte {
	b := strictjson.NewBuilder().String("state", m.ownerCheckState(now))
	if kind == KindAgent {
		return b.Bytes()
	}
	i := m.ownerCheckInfo()
	if m.ownerCheckRunning() {
		b.String("deadline", envelope.FormatTS(i.Deadline))
	}
	b.Uint("interval_seconds", uint64(i.Interval/time.Second))
	failures := 0
	if rec := m.st.OwnerCheck; rec != nil {
		failures = rec.Failures
	}
	b.Uint("failures", uint64(failures)).Bool("hold", i.Hold)
	if i.HoldOffUntil != nil {
		b.String("hold_off_until", envelope.FormatTS(*i.HoldOffUntil))
	}
	return b.Bytes()
}

// settingsOwnerCheck applies an accepted settings.set to the record
// (§3.6.2, §3.6.7): a shorter interval moves the deadline earlier at once
// (a longer one waits for the next check), and turning the hold on is
// audited; the hold then applies at once if the deadline has passed.
func (m *Manager) settingsOwnerCheck(prev, next Settings, now time.Time) {
	if rec := m.st.OwnerCheck; rec != nil && !rec.Deadline.IsZero() && next.OwnerCheckInterval() < prev.OwnerCheckInterval() {
		if d := rec.LastAt.Add(next.OwnerCheckInterval()); d.Before(rec.Deadline) {
			rec.Deadline = d
			m.dirty = true
		}
	}
	if prev.HoldOff && !next.HoldOff {
		m.record(Activity{Kind: "owner_check.hold_changed", Ref: "on", Audit: true, Feed: true, Priority: "high"}, now)
	}
	m.ownerCheckTick(now)
}

// ownerCheckKeys are the settings only the holder may change (§3.6.2,
// §3.6.7): a desktop naming one is refused at once, never held.
var ownerCheckKeys = []string{"owner_check.interval_seconds", "owner_check.hold", "owner_check.hold_off_until"}
