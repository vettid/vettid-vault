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

// noteCollected keeps each mailbox's last_msg_id, in the flush of the batch
// (§3.4.2 RK14 step 1 "What P records"): processed is the batch's
// disposition per message (false: left unacked for redelivery).
func (m *Manager) noteCollected(c Collector, msgs []Message, processed []bool) {
	if !m.relayRotation() || len(msgs) == 0 {
		return
	}
	idx := make([]int, len(msgs))
	for i := range idx {
		idx[i] = i
	}
	sort.SliceStable(idx, func(a, b int) bool { return msgIDBefore(msgs[idx[a]].MsgID, msgs[idx[b]].MsgID) })
	for _, i := range idx {
		r := m.collectRec(collectMailbox(c, msgs[i].MsgID, m.st.Relay.Mailbox))
		if r == nil {
			continue
		}
		id := msgs[i].MsgID
		if !processed[i] {
			if r.NoAckFloor == "" || msgIDBefore(id, r.NoAckFloor) {
				r.NoAckFloor = id
			}
			continue
		}
		if id == r.NoAckFloor {
			r.NoAckFloor = ""
		}
		if (r.NoAckFloor == "" || msgIDBefore(id, r.NoAckFloor)) && (r.LastMsgID == "" || msgIDBefore(r.LastMsgID, id)) {
			r.LastMsgID = id
		}
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
	to      time.Time // collected-to: zero until a collect returned fewer than max
	gone    bool      // left the set (mailbox_unknown, or its collects ended)
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
	// gone reports a mailbox_unknown from an old mailbox; stopped whether
	// a mailbox's collects have ended. Both take the vault's lock.
	gone    func(mailbox string)
	stopped func(mailbox string) bool
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
			continue // a transient failure: its collected-to does not move
		}
		if len(msgs) < MaxBatch {
			p.to = start.Add(-collectedToWindow)
		}
		c.mu.Lock()
		for _, msg := range msgs {
			if c.from[msg.MsgID] != nil {
				continue // a redelivery of a message held here
			}
			c.from[msg.MsgID] = p
			c.held = append(c.held, heldMsg{msg: msg, at: heldAt(msg, start), part: p})
		}
		c.mu.Unlock()
	}
	return c.release(), nil
}

// release returns the held messages deposited no later than the earliest
// collected-to time of the mailboxes still in the set, in order, at most
// a batch.
func (c *multiCollector) release() []Message {
	var limit time.Time
	first := true
	for _, p := range c.parts {
		if p.gone {
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
		parts = append(parts, &collectPart{mailbox: m.st.Relay.Mailbox, c: main, main: true})
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
		wait := m.opt.PollWait
		if wait == 0 {
			wait = LongPollWait
		}
		return idleCollector{wait: wait}
	case len(parts) == 1 && main != nil:
		return main
	}
	// Old mailboxes first: each is polled without waiting before the
	// current one's long-poll.
	sort.SliceStable(parts, func(i, j int) bool { return !parts[i].main && parts[j].main })
	return &multiCollector{parts: parts, from: map[string]*collectPart{}, now: m.now,
		gone: func(mb string) {
			m.mu.Lock()
			defer m.mu.Unlock()
			if m.mailboxGone(mb, m.now()) {
				_ = m.persist(ctx, false) // at once (a copy could register it again)
			}
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
// (a retry_after runs, the refused state's attempt was made). An attempt
// that succeeds leads to the second write, which stops the collects of the
// old mailbox before any.
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
	m.rk.force = true
	m.relayKeyStep(ctx, false)
	m.rk.force = false
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
