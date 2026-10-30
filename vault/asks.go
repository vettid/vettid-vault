package vault

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"sort"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// Asks from a connection: no approval fatigue (VAULT-MESSAGING §10.4.1,
// 0.23.0). An ask is a message from a connection that, if accepted, waits
// for the member's decision: a grant request, a critical-item use, a
// prompt-each-time invocation, an authentication challenge, an
// introduction offer or a location request. The feature that receives one
// makes its own checks first and then asks the vault (Session.Ask), which
// suppresses it at the first of: muted, paused, cooldown, pending, rate.
// A suppressed ask is answered exactly as the member's decline of that
// kind, after a random delay, so that the connection cannot tell a
// decline from any of these.

// The §10.4.1 constants, fixed for v1.
const (
	AskCooldownTTL   = 7 * 24 * time.Hour
	AskRate          = 5
	AskRateWindow    = 24 * time.Hour
	AskMaxPending    = 8
	AskPauseDeclines = 3
	AskPauseWithin   = 30 * 24 * time.Hour
	AskBatchWindow   = 10 * time.Minute
	AskDelayMin      = time.Minute
	AskDelayMax      = 20 * time.Minute
	AskMaxHeld       = 16
	AskMaxCooldowns  = 64
	// askExpMargin: a held answer goes out at most until 1 minute before
	// the ask's exp.
	askExpMargin = time.Minute

	// Sign-in challenges (0.65.0): their own cooldown, rate and pending
	// cap, and their declines do not count toward a pause.
	AskSignInCooldownTTL = time.Hour
	AskSignInRate        = 10
	AskSignInMaxPending  = 2
)

// Rate buckets (0.65.0, §10.4.1 "Sign-in and approval challenges"): a
// challenge's purpose selects its bucket; every other ask is in the
// general bucket ("").
const (
	AskBucketGeneral  = ""
	AskBucketSignIn   = "signin"
	AskBucketApproval = "approval"
)

// askRate is a bucket's limit per AskRateWindow.
func askRate(bucket string) int {
	if bucket == AskBucketSignIn {
		return AskSignInRate
	}
	return AskRate
}

// askCooldownTTL is how long a decline in bucket cools its identities.
func askCooldownTTL(bucket string) time.Duration {
	if bucket == AskBucketSignIn {
		return AskSignInCooldownTTL
	}
	return AskCooldownTTL
}

// Suppression reasons (the audit kinds are "drop.ask_<reason>").
const (
	AskMuted    = "muted"
	AskPaused   = "paused"
	AskCooldown = "cooldown"
	AskPending  = "pending"
	AskRated    = "rate"
)

// AskState is one connection's §10.4.1 state, in DEK state with the
// connection (§7.4).
type AskState struct {
	Muted    bool      `json:"muted,omitempty"`
	PausedAt time.Time `json:"paused_at,omitempty"`
	// Declines are the times of the last three declines.
	Declines []time.Time `json:"declines,omitempty"`
	// Cooldowns are the ask identities in cooldown, oldest first.
	Cooldowns []AskCooldownEntry `json:"cooldowns,omitempty"`
	// The current ask-rate window of the general bucket (fixed, from the
	// first ask that reached the member).
	WindowStart time.Time `json:"window_start,omitempty"`
	WindowN     int       `json:"window_n,omitempty"`
	// Windows are the other buckets' windows (0.65.0), by bucket.
	Windows map[string]AskWindow `json:"windows,omitempty"`
	// Held are the neutral answers of suppressed asks, sent when due.
	Held []HeldAnswer `json:"held,omitempty"`
}

// AskWindow is one rate bucket's current window.
type AskWindow struct {
	Start time.Time `json:"start"`
	N     int       `json:"n"`
}

// window returns bucket's window.
func (st *AskState) window(bucket string) AskWindow {
	if bucket == AskBucketGeneral {
		return AskWindow{Start: st.WindowStart, N: st.WindowN}
	}
	return st.Windows[bucket]
}

func (st *AskState) setWindow(bucket string, w AskWindow) {
	if bucket == AskBucketGeneral {
		st.WindowStart, st.WindowN = w.Start, w.N
		return
	}
	if st.Windows == nil {
		st.Windows = map[string]AskWindow{}
	}
	st.Windows[bucket] = w
}

// AskCooldownEntry is one ask identity's cooldown.
type AskCooldownEntry struct {
	ID    string    `json:"id"`
	Until time.Time `json:"until"`
}

// HeldAnswer is a suppressed ask's decline-shaped answer, sent at Due.
type HeldAnswer struct {
	Due  time.Time       `json:"due"`
	Type string          `json:"type"`
	Ref  string          `json:"ref"`
	Body json.RawMessage `json:"body"`
}

// Paused reports whether the connection's asks are paused.
func (st *AskState) Paused() bool { return st != nil && !st.PausedAt.IsZero() }

// cooldownsInForce counts the cooldowns that have not ended.
func (st *AskState) cooldownsInForce(now time.Time) int {
	if st == nil {
		return 0
	}
	n := 0
	for _, c := range st.Cooldowns {
		if now.Before(c.Until) {
			n++
		}
	}
	return n
}

func (st *AskState) prune(now time.Time) {
	kept := st.Cooldowns[:0]
	for _, c := range st.Cooldowns {
		if now.Before(c.Until) {
			kept = append(kept, c)
		}
	}
	st.Cooldowns = kept
	if len(st.Cooldowns) == 0 {
		st.Cooldowns = nil
	}
}

func (st *AskState) cooled(id string, now time.Time) bool {
	for _, c := range st.Cooldowns {
		if c.ID == id && now.Before(c.Until) {
			return true
		}
	}
	return false
}

// AskJSON is <connection>.asks: {muted, paused, paused_at?, cooldowns}.
func (st *AskState) AskJSON(now time.Time) []byte {
	var s AskState
	if st != nil {
		s = *st
	}
	b := strictjson.NewBuilder().Bool("muted", s.Muted).Bool("paused", s.Paused())
	if s.Paused() {
		b.String("paused_at", envelope.FormatTS(s.PausedAt))
	}
	return b.Uint("cooldowns", uint64(st.cooldownsInForce(now))).Bytes()
}

// Ask is one ask from a connection, as the receiving feature describes it.
type Ask struct {
	// Source is the receiving feature's Name(): its own pending asks are
	// Pending, and it is not asked again (AskSource).
	Source string
	// Ref is the ask's id (request_id, invocation_id or intro_id), the
	// audit entries' ref.
	Ref string
	// Idents are the ask's identities for the cooldown: one per entry of
	// a grant request, one for the other kinds; none for a location
	// request.
	Idents []string
	// Pending is the number of this connection's asks the source already
	// holds for the member.
	Pending int
	// Bucket is the ask's rate bucket (AskBucketSignIn, AskBucketApproval
	// or AskBucketGeneral, 0.65.0); BucketPending, for AskBucketSignIn, is
	// the number of the connection's sign-in challenges already waiting.
	Bucket        string
	BucketPending int
	// Exp is the ask's exp (zero: none).
	Exp time.Time
	// AnswerType and Answer are the member's decline answer of this ask
	// (§10.4.1's table); "" for none (a location request).
	AnswerType string
	Answer     json.RawMessage
}

// AskVerdict is the vault's answer for one ask.
type AskVerdict struct {
	// Reason is "" when the ask reaches the member, else the reason it was
	// suppressed (AskMuted, ...).
	Reason string
	// Cooled marks, per Ask.Idents, the entries in cooldown: a grant
	// request reaches the member without them.
	Cooled []bool
	// Repeat: an answer to the same ask is already held; it is ignored.
	Repeat bool
}

// Passed reports whether the ask reaches the member.
func (v AskVerdict) Passed() bool { return v.Reason == "" && !v.Repeat }

// AskSource is implemented by the features that receive asks: how many
// of a connection's asks wait for the member (the pending cap counts all
// kinds together). It is called with the vault's lock held, while another
// feature's lock may be held: it must take only its own.
type AskSource interface {
	PendingAsks(connectionID string, now time.Time) int
}

// AskHost is implemented by Hosts that keep the §10.4.1 state. A Session
// on a Host without it lets every ask pass.
type AskHost interface {
	Ask(conn string, a Ask, now time.Time) AskVerdict
	AskDeclined(conn, bucket string, idents []string, now time.Time)
}

// Ask runs the §10.4.1 checks for an ask from conn. On a suppression the
// vault audits it and holds the decline-shaped answer; the feature does
// nothing more with it.
func (s *Session) Ask(conn string, a Ask) AskVerdict {
	if h, ok := s.host.(AskHost); ok {
		return h.Ask(conn, a, s.now)
	}
	return AskVerdict{Cooled: make([]bool, len(a.Idents))}
}

// HeldDropper is implemented by Hosts that keep held neutral answers: it
// drops, silently, the answer of type typ for the ask ref held for conn.
type HeldDropper interface {
	DropHeld(conn, typ, ref string) bool
}

// DropHeld drops, silently (no audit, no sync), the held neutral answer
// of type typ for the suppressed ask ref of conn, and reports whether
// there was one (VAULT-MESSAGING 0.80.0, §10.4 "Withdrawing a challenge").
func (s *Session) DropHeld(conn, typ, ref string) bool {
	if h, ok := s.host.(HeldDropper); ok {
		return h.DropHeld(conn, typ, ref)
	}
	return false
}

// DropHeldAnswer removes from st the held answer of type typ for ref.
func DropHeldAnswer(st *AskState, typ, ref string) bool {
	if st == nil {
		return false
	}
	for i, h := range st.Held {
		if h.Type == typ && h.Ref == ref {
			st.Held = append(append([]HeldAnswer(nil), st.Held[:i]...), st.Held[i+1:]...)
			if len(st.Held) == 0 {
				st.Held = nil
			}
			return true
		}
	}
	return false
}

// AskDeclined records the member's decline of a whole ask from conn
// (§10.4.1 Declines): each identity starts its cooldown, and a third
// decline within 30 days pauses the connection's asks.
func (s *Session) AskDeclined(conn string, idents []string) {
	s.AskDeclinedIn(conn, AskBucketGeneral, idents)
}

// AskDeclinedIn is AskDeclined for an ask in bucket (0.65.0): a sign-in
// decline cools its identities for AskSignInCooldownTTL and does not
// count toward a pause.
func (s *Session) AskDeclinedIn(conn, bucket string, idents []string) {
	if h, ok := s.host.(AskHost); ok {
		h.AskDeclined(conn, bucket, idents, s.now)
	}
}

// AskDelay draws the neutral answer's delay uniformly from 1 to 20
// minutes, at millisecond resolution; rnd(n) returns a uniform value in
// [0, n) (nil: crypto/rand).
func AskDelay(rnd func(n int64) int64) time.Duration {
	n := int64((AskDelayMax - AskDelayMin) / time.Millisecond)
	var v int64
	if rnd != nil {
		v = rnd(n + 1)
	} else {
		var b [8]byte
		_, _ = rand.Read(b[:])
		v = int64(binary.BigEndian.Uint64(b[:]) % uint64(n+1))
	}
	if v < 0 || v > n {
		v = 0
	}
	return AskDelayMin + time.Duration(v)*time.Millisecond
}

// CheckAsk applies §10.4.1 to an ask with st (the connection's state;
// others: the connection's asks other features hold). It records the
// audit entries through rec, holds the neutral answer of a suppressed ask
// (delay: AskDelay's draw) and counts a passed ask in the rate window.
// It is the vault's logic, shared with test hosts.
func CheckAsk(st *AskState, conn string, a Ask, others int, now time.Time, delay time.Duration, rec func(Activity)) AskVerdict {
	st.prune(now)
	v := AskVerdict{Cooled: make([]bool, len(a.Idents))}
	if a.AnswerType != "" {
		for _, h := range st.Held {
			if h.Type == a.AnswerType && h.Ref == a.Ref {
				v.Repeat = true
				return v
			}
		}
	}
	drop := func(reason string) AskVerdict {
		v.Reason = reason
		rec(Activity{Kind: "drop.ask_" + reason, ConnectionID: conn, Ref: a.Ref, Audit: true})
		if a.AnswerType != "" && len(st.Held) < AskMaxHeld {
			due := now.Add(delay)
			if !a.Exp.IsZero() {
				if last := a.Exp.Add(-askExpMargin); due.After(last) {
					due = last
				}
				if due.Before(now) {
					due = now
				}
			}
			st.Held = append(st.Held, HeldAnswer{Due: due.UTC().Truncate(time.Millisecond), Type: a.AnswerType, Ref: a.Ref,
				Body: append(json.RawMessage(nil), a.Answer...)})
		}
		return v
	}
	if st.Muted {
		return drop(AskMuted)
	}
	if st.Paused() {
		return drop(AskPaused)
	}
	if len(a.Idents) > 0 {
		all := true
		for i, id := range a.Idents {
			v.Cooled[i] = st.cooled(id, now)
			all = all && v.Cooled[i]
		}
		if all {
			return drop(AskCooldown)
		}
		for _, c := range v.Cooled {
			if c {
				// An entry removed from a grant request (§10.4.1 Audit).
				rec(Activity{Kind: "drop.ask_" + AskCooldown, ConnectionID: conn, Ref: a.Ref, Audit: true})
			}
		}
	}
	if a.Pending+others >= AskMaxPending || a.Bucket == AskBucketSignIn && a.BucketPending >= AskSignInMaxPending {
		return drop(AskPending)
	}
	w := st.window(a.Bucket)
	open := !w.Start.IsZero() && now.Before(w.Start.Add(AskRateWindow))
	if open && w.N >= askRate(a.Bucket) {
		return drop(AskRated)
	}
	if !open {
		w = AskWindow{Start: now.UTC().Truncate(time.Millisecond)}
	}
	w.N++
	st.setWindow(a.Bucket, w)
	return v
}

// DeclineAsk records a decline in st: the identities' cooldowns (at most
// 64, the oldest dropped first) and the decline time; it reports whether
// this decline paused the connection's asks.
func DeclineAsk(st *AskState, idents []string, now time.Time) (paused bool) {
	return DeclineAskIn(st, AskBucketGeneral, idents, now)
}

// DeclineAskIn is DeclineAsk for an ask in bucket (0.65.0): a sign-in
// decline cools its identities for AskSignInCooldownTTL only, and is not
// a decline that counts toward a pause.
func DeclineAskIn(st *AskState, bucket string, idents []string, now time.Time) (paused bool) {
	st.prune(now)
	t := now.UTC().Truncate(time.Millisecond)
	for _, id := range idents {
		kept := st.Cooldowns[:0]
		for _, c := range st.Cooldowns {
			if c.ID != id {
				kept = append(kept, c)
			}
		}
		st.Cooldowns = append(kept, AskCooldownEntry{ID: id, Until: t.Add(askCooldownTTL(bucket))})
		if len(st.Cooldowns) > AskMaxCooldowns {
			st.Cooldowns = append([]AskCooldownEntry(nil), st.Cooldowns[len(st.Cooldowns)-AskMaxCooldowns:]...)
		}
	}
	if bucket == AskBucketSignIn {
		return false
	}
	st.Declines = append(st.Declines, t)
	if len(st.Declines) > AskPauseDeclines {
		st.Declines = append([]time.Time(nil), st.Declines[len(st.Declines)-AskPauseDeclines:]...)
	}
	if !st.Paused() && len(st.Declines) == AskPauseDeclines && !st.Declines[AskPauseDeclines-1].After(st.Declines[0].Add(AskPauseWithin)) {
		st.PausedAt = t
		return true
	}
	return false
}

// ResumeAsks ends a pause, if any, and always clears the decline times
// and cooldowns (§10.4.1; 0.23.1, owner decision of 2026-10-09); it
// reports whether anything was cleared.
func ResumeAsks(st *AskState, now time.Time) bool {
	changed := st.Paused() || len(st.Declines) > 0 || len(st.Cooldowns) > 0
	st.PausedAt, st.Declines, st.Cooldowns = time.Time{}, nil, nil
	return changed
}

// DueAnswers removes and returns the held answers due at now.
func DueAnswers(st *AskState, now time.Time) []HeldAnswer {
	if st == nil || len(st.Held) == 0 {
		return nil
	}
	var due, kept []HeldAnswer
	for _, h := range st.Held {
		if !now.Before(h.Due) {
			due = append(due, h)
		} else {
			kept = append(kept, h)
		}
	}
	st.Held = kept
	return due
}

// --- the Manager's side ---

func (m *Manager) askState(p *Peer) *AskState {
	if p.Asks == nil {
		p.Asks = &AskState{}
	}
	return p.Asks
}

// askDelay draws a neutral answer's delay (Options.AskRand in tests).
func (m *Manager) askDelay() time.Duration { return AskDelay(m.opt.AskRand) }

// othersPending sums the asks of conn the features other than source hold.
func (m *Manager) othersPending(conn, source string, now time.Time) int {
	n := 0
	for _, f := range m.features {
		if src, ok := f.(AskSource); ok && f.Name() != source {
			n += src.PendingAsks(conn, now)
		}
	}
	return n
}

func (h managerHost) Ask(conn string, a Ask, now time.Time) AskVerdict {
	m := h.m
	p := m.st.Connections[conn]
	if p == nil {
		return AskVerdict{Cooled: make([]bool, len(a.Idents))}
	}
	st := m.askState(p)
	v := CheckAsk(st, conn, a, m.othersPending(conn, a.Source, now), now, m.askDelay(), func(x Activity) { m.record(x, now) })
	m.dirty = true
	return v
}

// A host that keeps the §10.4.1 state but drifts from AskHost would let
// every ask pass (Session.Ask); keep it a compile error.
var _ AskHost = managerHost{}
var _ HeldDropper = managerHost{}

func (h managerHost) DropHeld(conn, typ, ref string) bool {
	p := h.m.st.Connections[conn]
	if p == nil || !DropHeldAnswer(p.Asks, typ, ref) {
		return false
	}
	h.m.dirty = true
	return true
}

func (h managerHost) AskDeclined(conn, bucket string, idents []string, now time.Time) {
	m := h.m
	p := m.st.Connections[conn]
	if p == nil {
		return
	}
	if DeclineAskIn(m.askState(p), bucket, idents, now) {
		m.record(Activity{Kind: "connection.asks_paused", ConnectionID: conn, Audit: true, Feed: true, Priority: "high"}, now)
	}
	m.dirty = true
	m.connChanged(p, now)
}

// connChanged sends sync.event{connection.changed} to every owner device.
func (m *Manager) connChanged(p *Peer, now time.Time) {
	v := uint64(0)
	if p.Meta != nil {
		v = p.Meta.Version
	}
	m.notifyDevices("sync.event", strictjson.NewBuilder().String("kind", "connection.changed").String("connection_id", p.ID).
		Uint("version", v).Bytes(), "", now)
}

// sendHeldAnswers sends the neutral answers that are due (housekeeping);
// an answer to a connection that is no longer active is dropped.
func (m *Manager) sendHeldAnswers(now time.Time) {
	for _, id := range sortedPeerIDs(m.st.Connections) {
		p := m.st.Connections[id]
		due := DueAnswers(p.Asks, now)
		if len(due) == 0 {
			continue
		}
		m.dirty = true
		if p.State != PeerActive {
			continue
		}
		for _, h := range due {
			m.sendTo(p, h.Type, h.Body, now)
		}
	}
}

func sortedPeerIDs(ps map[string]*Peer) []string {
	ids := make([]string, 0, len(ps))
	for id := range ps {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func (m *Manager) registerAsks() {
	r := func(t string, h HandlerFunc) {
		m.register(TypeSpec{Type: t, Request: true, From: owners}, h)
	}
	r("connection.asks.mute", m.hAsksMute)
	r("connection.asks.resume", m.hAsksResume)
}

// hAsksMute mutes or unmutes a connection's asks (§10.4.1).
func (m *Manager) hAsksMute(_ context.Context, s *Session, in *envelope.Inner) (json.RawMessage, error) {
	o, err := obj(in)
	if err != nil {
		return nil, err
	}
	id, err := str(o, "connection_id")
	if err != nil {
		return nil, err
	}
	muted, err := o.Bool("muted")
	if err != nil {
		return nil, errBadRequest
	}
	p := m.st.Connections[id]
	if p == nil {
		return nil, errNotFound
	}
	st := m.askState(p)
	if st.Muted != muted {
		st.Muted = muted
		kind := "connection.asks_unmuted"
		if muted {
			kind = "connection.asks_muted"
		}
		m.dirty = true
		m.record(Activity{Kind: kind, ConnectionID: id, Audit: true}, s.now)
		m.connChanged(p, s.now)
	}
	return json.RawMessage(`{}`), nil
}

// hAsksResume always clears the decline times and cooldowns and ends a
// pause, if any (§10.4.1, 0.23.1).
func (m *Manager) hAsksResume(_ context.Context, s *Session, in *envelope.Inner) (json.RawMessage, error) {
	o, err := obj(in)
	if err != nil {
		return nil, err
	}
	id, err := str(o, "connection_id")
	if err != nil {
		return nil, err
	}
	p := m.st.Connections[id]
	if p == nil {
		return nil, errNotFound
	}
	// Always: a resume clears the decline history and cooldowns and ends
	// a pause if any, and is audited even when nothing was paused
	// (0.23.1).
	ResumeAsks(m.askState(p), s.now)
	m.dirty = true
	m.record(Activity{Kind: "connection.asks_resumed", ConnectionID: id, Audit: true}, s.now)
	m.connChanged(p, s.now)
	return json.RawMessage(`{}`), nil
}
