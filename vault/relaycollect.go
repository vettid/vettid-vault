package vault

import (
	"context"
	"sort"
	"sync"
	"time"
)

// Collecting the vault's own mailboxes across a relay-key rotation, only
// with Options.RelayKeyRotation (VAULT-MESSAGING §3.4 "Collecting while a
// key is pending", "Resending the new address" (a); §3.4.1 "Order of
// processing"; §3.4.2 RK14 step 1).
//
// After the second write the vault collects its current mailbox and each
// old one until RK14 step 1 ends it: 13 days after that key's anchor, on
// the vault's own clock (real time on staging too), at once if that has
// passed at the second write, and at any time once the relay answers
// mailbox_unknown for it. A key's mailbox that answers mailbox_unknown
// while a key is pending is not collected again either. While it collects
// more than one mailbox the vault processes each round's messages from all
// of them in (deposited_at, msg_id) order, and nothing deposited after the
// earliest collected-to time of the mailboxes in the set.
//
// The collect of the pending key's new mailbox before the second write
// (§3.4 "Collecting while a key is pending") needs no collector of its own
// here: a successful rotate is followed at once by the second write in
// memory, which collects the new mailbox from then on; a run that ends
// before that write is stored calls the rotate again at its next unlock.

const (
	// OldMailboxStop is how long after its anchor the vault ends its
	// collects of an old mailbox (§3.4.2 RK14 step 1: the relay's 14-day
	// grace less a day for clock drift). Not divided by time_scale.
	OldMailboxStop = 13 * 24 * time.Hour
	// collectedToWindow is RELAY-PROTOCOL §4.1's freshness window, which a
	// mailbox's collected-to time is less (§3.4.1 "Order of processing").
	collectedToWindow = 90 * time.Second
	// oldFailBound is how long an old mailbox's collects may fail (any
	// answer but mailbox_unknown: a 401, a 403, a 5xx, no answer) with no
	// collect succeeding before it stops holding back what the vault
	// processes from its other mailboxes: it is still collected, and its
	// collected-to counts again after a collect that returned fewer than
	// max. Without it a failing old mailbox would hold every message of
	// the current one, device requests too, until its stop. A reading of
	// this release (the spec should confirm).
	oldFailBound = 10 * time.Minute
)

// collectRec is the RK14 record of one of the vault's own mailboxes: the
// current one or an old one; nil for any other.
func (m *Manager) collectRec(mailbox string) *MailboxCollect {
	if mailbox == m.st.Relay.Mailbox {
		return &m.st.Relay.Collect
	}
	for i := range m.st.Relay.Old {
		if m.st.Relay.Old[i].Mailbox == mailbox {
			return &m.st.Relay.Old[i].Collect
		}
	}
	return nil
}

// oldStopDue reports whether RK14 step 1's timed stop of o is due. An old
// key with no anchor (none was stored before its rotate) stops at once: a
// reading of this release (the spec should confirm), fail closed.
func oldStopDue(o *OldRelayKey, now time.Time) bool {
	return o.Anchor.IsZero() || !now.Before(o.Anchor.Add(OldMailboxStop))
}

// stopOldCollects ends the collects of each old mailbox whose stop is due,
// with its last_msg_id, and queues its telling, in the write that follows
// (§3.4.2 RK14 step 1 "When it is recorded": the second write itself, or
// a write of its own). From then on nothing is collected from it, even
// before that write. It reports whether any stopped.
func (m *Manager) stopOldCollects(now time.Time) bool {
	changed := false
	for i := range m.st.Relay.Old {
		o := &m.st.Relay.Old[i]
		if o.Collect.Stopped.IsZero() && oldStopDue(o, now) {
			o.Collect.Stopped, o.Collect.TellingDue = now.UTC(), true
			changed = true
		}
	}
	if changed {
		m.dirty = true
		m.resetCollector()
	}
	return changed
}

// mailboxGone is a mailbox_unknown answer for one of the vault's own
// mailboxes (to a collect, or to the rotate on the registration path):
// while a key is pending, or for an old key, its collects end at once and
// for good (§3.4.2 RK14 step 1 "When P stops"; fail secure). Before the
// second write only the stop and last_msg_id are recorded; the second
// write queues the telling. The caller stores it at once.
func (m *Manager) mailboxGone(mailbox string, now time.Time) bool {
	if !m.relayRotation() || m.st == nil {
		return false
	}
	if mailbox == m.st.Relay.Mailbox && m.st.Relay.Pending == nil {
		return false // a current key with no key pending registers again (§12.2)
	}
	r := m.collectRec(mailbox)
	if r == nil || !r.Stopped.IsZero() {
		return false
	}
	r.Stopped = now.UTC()
	if mailbox != m.st.Relay.Mailbox {
		r.TellingDue = true
	}
	m.dirty = true
	m.resetCollector()
	return true
}

// collectTrack bounds MailboxCollect's Unprocessed and Done (each): a
// message past it holds last_msg_id at the Ceiling, or is not counted as
// processed, which errs low.
const collectTrack = 256

// insertID adds id to the ordered list l, without duplicates, keeping at
// most collectTrack; it returns the list and the id it dropped ("" for
// none: the highest goes).
func insertID(l []string, id string) ([]string, string) {
	i := sort.Search(len(l), func(i int) bool { return !msgIDBefore(l[i], id) })
	if i < len(l) && l[i] == id {
		return l, ""
	}
	l = append(l, "")
	copy(l[i+1:], l[i:])
	l[i] = id
	if len(l) > collectTrack {
		dropped := l[len(l)-1]
		return l[:len(l)-1], dropped
	}
	return l, ""
}

func removeID(l []string, id string) []string {
	for i, x := range l {
		if x == id {
			return append(l[:i], l[i+1:]...)
		}
	}
	return l
}

// given records a message the relay gave from the mailbox at now.
func (r *MailboxCollect) given(id string, now time.Time) {
	if id == "" || r.LastMsgID != "" && !msgIDBefore(r.LastMsgID, id) {
		return // at or below last_msg_id: already processed
	}
	for _, d := range r.Done {
		if d == id {
			return
		}
	}
	var dropped string
	r.Unprocessed, dropped = insertID(r.Unprocessed, id)
	if r.GivenAt == nil {
		r.GivenAt = map[string]time.Time{}
	}
	if dropped != id {
		r.GivenAt[id] = now.UTC()
	}
	if dropped != "" {
		delete(r.GivenAt, dropped)
		if r.Ceiling == "" || msgIDBefore(dropped, r.Ceiling) {
			r.Ceiling, r.CeilingAt = dropped, now.UTC()
		}
	}
}

// pruneUnhanded is a full drain of the mailbox at now (a collect that
// returned fewer than max, over HTTP) that gave the ids in got: each
// unprocessed id given more than bound before it, absent from it and not
// held, is one the relay no longer has (acked before a crash undid its
// processing, or dropped by the relay), so it holds last_msg_id no more.
// A ceiling older than bound goes the same way, but only once nothing
// from the mailbox is held and nothing given is unprocessed: a message it
// stood for and still unprocessed would be in got, given again, unless
// it is among those held or tracked.
func (r *MailboxCollect) pruneUnhanded(got, held map[string]bool, now time.Time, bound time.Duration) {
	keep := r.Unprocessed[:0]
	for _, id := range r.Unprocessed {
		if !got[id] && !held[id] && now.Sub(r.GivenAt[id]) > bound {
			delete(r.GivenAt, id)
			continue
		}
		keep = append(keep, id)
	}
	r.Unprocessed = keep
	if r.Ceiling != "" && len(held) == 0 && len(r.Unprocessed) == 0 && now.Sub(r.CeilingAt) > bound {
		r.Ceiling, r.CeilingAt = "", time.Time{}
	}
	r.advance()
}

// leaseBound is how long after a message was given a full drain without
// it shows the relay no longer has it: two of the relay's visibility
// timeouts (at least RuleTVisibility each), and a long-poll. false: the
// relay gave no visibility timeout, and nothing is pruned (fail closed).
func (m *Manager) leaseBound() (time.Duration, bool) {
	if m.limits.VisibilityTimeoutSeconds <= 0 {
		return 0, false
	}
	vis := time.Duration(m.limits.VisibilityTimeoutSeconds) * time.Second
	return 2*max(vis, RuleTVisibility) + LongPollWait, true
}

// noteDrained is pruneUnhanded for mailbox, under the lock.
func (m *Manager) noteDrained(mailbox string, got, held map[string]bool, now time.Time) {
	if !m.relayRotation() || m.st == nil {
		return
	}
	bound, ok := m.leaseBound()
	if !ok {
		return
	}
	if r := m.collectRec(mailbox); r != nil {
		r.pruneUnhanded(got, held, now, bound)
		m.dirty = true
	}
}

// processed records a message processed and flushed with this batch, and
// moves last_msg_id up to below the lowest message given and not yet
// processed.
func (r *MailboxCollect) processed(id string) {
	r.Unprocessed = removeID(r.Unprocessed, id)
	delete(r.GivenAt, id)
	if r.LastMsgID == "" || msgIDBefore(r.LastMsgID, id) {
		r.Done, _ = insertID(r.Done, id)
	}
}

func (r *MailboxCollect) advance() {
	limit := r.Ceiling
	if len(r.Unprocessed) > 0 && (limit == "" || msgIDBefore(r.Unprocessed[0], limit)) {
		limit = r.Unprocessed[0]
	}
	n := 0
	for n < len(r.Done) && (limit == "" || msgIDBefore(r.Done[n], limit)) {
		n++
	}
	if n > 0 {
		r.LastMsgID = r.Done[n-1]
		r.Done = append([]string(nil), r.Done[n:]...)
	}
}

// noteGiven records messages the relay gave from a mailbox (the order of
// processing holds some back before any batch sees them).
func (m *Manager) noteGiven(mailbox string, ids []string) {
	if !m.relayRotation() || m.st == nil {
		return
	}
	if r := m.collectRec(mailbox); r != nil {
		for _, id := range ids {
			r.given(id, m.now())
		}
		m.dirty = true
	}
}

// noteCollected keeps each mailbox's last_msg_id, in the flush of the batch
// (§3.4.2 RK14 step 1 "What P records"): processed is the batch's
// disposition per message (false: left unacked for redelivery). Every
// message the relay gave counts, in whatever order the batch has them.
func (m *Manager) noteCollected(c Collector, msgs []Message, processed []bool) {
	if !m.relayRotation() || len(msgs) == 0 {
		return
	}
	touched := map[*MailboxCollect]bool{}
	for i, msg := range msgs {
		r := m.collectRec(collectMailbox(c, msg.MsgID, m.st.Relay.Mailbox))
		if r == nil {
			continue
		}
		r.given(msg.MsgID, m.now())
		if processed[i] {
			r.processed(msg.MsgID)
		}
		touched[r] = true
	}
	for r := range touched {
		r.advance()
	}
	m.dirty = true
}

// collectedFrom is the vault mailbox the message being handled was
// collected from.
func (m *Manager) collectedFrom() string {
	if m.msgMailbox != "" {
		return m.msgMailbox
	}
	return m.st.Relay.Mailbox
}

// mailboxCollector reports the vault mailbox each collected message came
// from.
type mailboxCollector interface {
	mailboxOf(msgID string) string
}

// collectMailbox is the vault mailbox msgID was collected from through c:
// its own when c collects several, else the current one.
func collectMailbox(c Collector, msgID, current string) string {
	if mc, ok := c.(mailboxCollector); ok {
		if mb := mc.mailboxOf(msgID); mb != "" {
			return mb
		}
	}
	return current
}

// --- the collector of several mailboxes ---

// collectPart is one mailbox of a multiCollector.
type collectPart struct {
	mailbox string
	c       Collector
	main    bool
	// stream: a WebSocket session, whose batches end on a time window, not
	// at the relay's max, so they never tell that the backlog is empty:
	// its collected-to never moves.
	stream bool
	to     time.Time // collected-to: zero until a collect returned fewer than max
	gone   bool      // left the set (mailbox_unknown, or its collects ended)
	// failSince is the start of the first of the collects in a row that
	// failed (zero after one that succeeded); unbound: an old mailbox
	// whose collects failed for oldFailBound, out of the release limit
	// until a collect returns fewer than max.
	failSince time.Time
	unbound   bool
}

type heldMsg struct {
	msg  Message
	at   time.Time
	part *collectPart
}

// multiCollector collects the current mailbox (long-poll) and old ones
// (polled without waiting, before it), holds what is deposited after the
// earliest collected-to time of the set, and returns the rest in
// (deposited_at, msg_id) order (§3.4.1 "Order of processing"). Acks go to
// the mailbox a message came from.
type multiCollector struct {
	mu    sync.Mutex
	parts []*collectPart
	held  []heldMsg
	from  map[string]*collectPart
	now   func() time.Time
	idle  time.Duration // the wait of a round with no long-poll
	// gone reports a mailbox_unknown from an old mailbox; stopped whether
	// a mailbox's collects have ended. Both take the vault's lock.
	gone    func(mailbox string)
	stopped func(mailbox string) bool
	// given records what a collect gave (last_msg_id never passes a
	// message held here); it takes the vault's lock.
	given func(mailbox string, ids []string)
	// drained reports a full drain of a mailbox (pruneUnhanded): what it
	// gave and what is still held here from it. It takes the vault's lock.
	drained func(mailbox string, got, held map[string]bool, at time.Time)
}

func (c *multiCollector) mailboxOf(id string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if p := c.from[id]; p != nil {
		return p.mailbox
	}
	return ""
}

// heldAt is a message's position in time: its deposited_at, or for one
// the relay gave none, the start of the collect that brought it (held at
// least until every mailbox is collected past it: a reading of this
// release, fail closed).
func heldAt(msg Message, start time.Time) time.Time {
	if t, err := time.Parse(time.RFC3339Nano, msg.DepositedAt); err == nil {
		return t.UTC()
	}
	return start
}

func (c *multiCollector) Next(ctx context.Context) ([]Message, error) {
	for _, p := range c.parts {
		if p.gone {
			continue
		}
		if !p.main && c.stopped(p.mailbox) {
			p.gone = true // RK14 step 1: no collect after the stop
			continue
		}
		start := c.now()
		msgs, err := p.c.Next(ctx)
		if RelayCode(err) == CodeMailboxUnknown && !p.main {
			p.gone = true
			c.gone(p.mailbox)
			continue
		}
		if err != nil {
			if p.main {
				return nil, err
			}
			// A failure: its collected-to does not move, and after
			// oldFailBound of failures it holds nothing back.
			if p.failSince.IsZero() {
				p.failSince = start
			}
			if !start.Before(p.failSince.Add(oldFailBound)) {
				p.unbound = true
			}
			continue
		}
		p.failSince = time.Time{}
		if len(msgs) < MaxBatch && !p.stream {
			p.to = start.Add(-collectedToWindow)
			p.unbound = false
		}
		ids := make([]string, 0, len(msgs))
		for _, msg := range msgs {
			ids = append(ids, msg.MsgID)
		}
		if len(ids) > 0 {
			c.given(p.mailbox, ids)
		}
		c.mu.Lock()
		for _, msg := range msgs {
			c.from[msg.MsgID] = p // acks go where it came from
			if c.isHeld(msg.MsgID) {
				continue // a redelivery of a message still held here
			}
			c.held = append(c.held, heldMsg{msg: msg, at: heldAt(msg, start), part: p})
		}
		var drainedHeld map[string]bool
		if len(msgs) < MaxBatch && !p.stream && c.drained != nil {
			drainedHeld = map[string]bool{}
			for _, h := range c.held {
				if h.part == p {
					drainedHeld[h.msg.MsgID] = true
				}
			}
		}
		c.mu.Unlock()
		if drainedHeld != nil {
			got := map[string]bool{}
			for _, id := range ids {
				got[id] = true
			}
			c.drained(p.mailbox, got, drainedHeld, start)
		}
	}
	out := c.release()
	if len(out) == 0 && !c.hasMain() {
		// No long-poll in this round (the current mailbox is not
		// collected): wait as one would, so that the loop does not spin.
		if !sleep(ctx, c.idle) {
			return nil, ctx.Err()
		}
	}
	return out, nil
}

// isHeld reports whether id is held here, collected and not yet released
// (a message released and left unacked is handed back by the relay and
// held again). With c.mu held.
func (c *multiCollector) isHeld(id string) bool {
	for _, h := range c.held {
		if h.msg.MsgID == id {
			return true
		}
	}
	return false
}

func (c *multiCollector) hasMain() bool {
	for _, p := range c.parts {
		if p.main && !p.gone {
			return true
		}
	}
	return false
}

// release returns the held messages deposited no later than the earliest
// collected-to time of the mailboxes still in the set (less those unbound
// by their failures), in order, at most a batch.
func (c *multiCollector) release() []Message {
	var limit time.Time
	first := true
	for _, p := range c.parts {
		if p.gone || p.unbound {
			continue
		}
		if first || p.to.Before(limit) {
			limit, first = p.to, false
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	sort.SliceStable(c.held, func(i, j int) bool {
		a, b := c.held[i], c.held[j]
		if !a.at.Equal(b.at) {
			return a.at.Before(b.at)
		}
		return msgIDBefore(a.msg.MsgID, b.msg.MsgID)
	})
	var out []Message
	keep := c.held[:0]
	for _, h := range c.held {
		if len(out) < MaxBatch && (first || !h.at.After(limit)) {
			out = append(out, h.msg)
			continue
		}
		keep = append(keep, h)
	}
	c.held = keep
	return out
}

func (c *multiCollector) Ack(ctx context.Context, id string) error {
	c.mu.Lock()
	p := c.from[id]
	delete(c.from, id)
	c.mu.Unlock()
	if p == nil {
		return nil
	}
	return p.c.Ack(ctx, id)
}

func (c *multiCollector) Close() error {
	for _, p := range c.parts {
		_ = p.c.Close()
	}
	return nil
}

// idleCollector collects nothing (the current mailbox's collects ended
// while a key is pending, and no other is collected): the vault receives
// nothing until its key completes (§3.4.2 RK14 step 1).
type idleCollector struct{ wait time.Duration }

func (c idleCollector) Next(ctx context.Context) ([]Message, error) {
	if !sleep(ctx, c.wait) {
		return nil, ctx.Err()
	}
	return nil, nil
}
func (idleCollector) Ack(context.Context, string) error { return nil }
func (idleCollector) Close() error                      { return nil }

// rotationCollector wraps the current mailbox's collector main with the
// old mailboxes still collected; nil main: the current one is not
// collected. Called with the lock held.
func (m *Manager) rotationCollector(ctx context.Context, main Collector) Collector {
	parts := []*collectPart{}
	if main != nil {
		_, ws := main.(*wsCollector)
		parts = append(parts, &collectPart{mailbox: m.st.Relay.Mailbox, c: main, main: true, stream: ws})
	}
	wait := m.opt.PollWait
	if wait == 0 {
		wait = LongPollWait
	}
	now := m.now()
	m.stopOldCollects(now)
	for i, o := range m.st.Relay.Old {
		if !o.Collect.Stopped.IsZero() {
			continue
		}
		r := m.oldRelayClient(i)
		if r == nil {
			continue
		}
		var c Collector
		if cr, ok := r.(*ClientRelay); ok {
			c = cr.NewPollCollector(0)
		} else if oc, err := r.Collector(ctx, false); err == nil {
			c = oc
		} else {
			continue
		}
		parts = append(parts, &collectPart{mailbox: o.Mailbox, c: c})
	}
	switch {
	case len(parts) == 0:
		return idleCollector{wait: wait}
	case len(parts) == 1 && main != nil:
		return main
	}
	// Old mailboxes first: each is polled without waiting before the
	// current one's long-poll.
	sort.SliceStable(parts, func(i, j int) bool { return !parts[i].main && parts[j].main })
	return &multiCollector{parts: parts, from: map[string]*collectPart{}, now: m.now, idle: wait,
		gone: func(mb string) {
			m.mu.Lock()
			defer m.mu.Unlock()
			if m.mailboxGone(mb, m.now()) {
				_ = m.persist(ctx, false) // at once (a copy could register it again)
			}
		},
		drained: func(mb string, got, held map[string]bool, at time.Time) {
			m.mu.Lock()
			defer m.mu.Unlock()
			m.noteDrained(mb, got, held, at)
		},
		given: func(mb string, ids []string) {
			m.mu.Lock()
			defer m.mu.Unlock()
			m.noteGiven(mb, ids)
		},
		stopped: func(mb string) bool {
			m.mu.Lock()
			defer m.mu.Unlock()
			if m.st == nil {
				return true
			}
			m.stopOldCollects(m.now())
			r := m.collectRec(mb)
			return r == nil || !r.Stopped.IsZero()
		}}
}

// beforeCollect is §3.4.2 RK14 step 1 "The order once the anchor is old":
// while the current key's anchor is more than 13 days old and a key is
// pending, the vault collects the current mailbox only after an attempt
// that got no 200 since its last collect, or while no attempt may be made
// (a retry_after runs, the refused state's attempt was made, or the
// sooner retries' wait runs: a reading of this release, the spec should
// confirm, so that a relay failing fast does not get an attempt before
// every collect). An attempt that succeeds leads to the second write,
// which stops the collects of the old mailbox before any.
func (m *Manager) beforeCollect(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.locked {
		return ErrLocked
	}
	if !m.relayRotation() || m.st.Relay.Pending == nil || !m.st.Relay.Collect.Stopped.IsZero() || m.rk.noOK {
		return nil
	}
	if a := m.st.Relay.Anchor; a.IsZero() || !m.now().After(a.Add(OldMailboxStop)) {
		return nil
	}
	m.relayKeyStep(ctx, false)
	if m.locked {
		return ErrLocked
	}
	m.drainOutbox(ctx)
	return m.flushIfDirty(ctx)
}

// collectedCurrent notes a collect of the current mailbox.
func (m *Manager) collectedCurrent() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rk.noOK = false
}

// collectsOld reports whether an old mailbox is still collected: the
// current one is then collected over HTTP, whose batch shows when the
// backlog is empty (collected-to), not over a WebSocket.
func (m *Manager) collectsOld() bool {
	for _, o := range m.st.Relay.Old {
		if o.Collect.Stopped.IsZero() && !oldStopDue(&o, m.now()) {
			return true
		}
	}
	return false
}

// noteBatchDrained is pruneUnhanded for a batch of the current mailbox's
// own collector (not one of several, which reports its drains itself; not
// a WebSocket session, whose batches never show a drain) that returned
// fewer than max.
func (m *Manager) noteBatchDrained(c Collector, msgs []Message, now time.Time) {
	if !m.relayRotation() || len(msgs) >= MaxBatch {
		return
	}
	switch c.(type) {
	case *multiCollector, *wsCollector, idleCollector:
		return
	}
	got := map[string]bool{}
	for _, msg := range msgs {
		got[msg.MsgID] = true
	}
	m.noteDrained(m.st.Relay.Mailbox, got, nil, now)
}
