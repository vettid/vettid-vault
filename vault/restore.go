package vault

import (
	"bytes"
	"encoding/hex"
	"time"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Reconnect after a restore (VAULT-MESSAGING 0.72.0, 0.72.1; §6.6, §15 item
// 45). A service vault restored from a backup is behind the epoch its
// member's vault holds. A member vault therefore keeps, for a connection
// whose stored peer_kind is "service" only, the history of its epochs for 35
// days after each was superseded, and accepts a reconnect hs.init whose ctx
// names one of them. Person connections keep the exact match. Accepting an
// older epoch records the line it replaced; a later authenticated sign of
// that line means two copies of the service exist and suspends the
// connection.

const (
	// EpochHistoryWindow is how long an epoch stays acceptable as a
	// reconnect ctx after its successor took over: the service's backup and
	// point-in-time-recovery retention (§6.6 "Epoch history").
	EpochHistoryWindow = 35 * 24 * time.Hour
	// EpochHistoryMax bounds the ids kept per connection, the oldest
	// dropped first. The cap costs availability only (§6.6).
	EpochHistoryMax = 512
	// InitMarkRetention is how long the th1 of an answered reconnect hs.init
	// is kept: the durable ts window of §8.4, 16 days in the past plus 5
	// minutes in the future (§6.6 "Replay").
	InitMarkRetention = DedupeRetention + envelope.MaxClockSkewFuture
)

// ownChainNow is the own rotation-chain count that signs a handshake begun
// now (§6.6, 0.72.0): recorded with the epoch it makes.
func (m *Manager) ownChainNow() *int {
	n := len(m.st.Rotations)
	return &n
}

// chainOr returns *c, or def for a record written before the count was kept.
func chainOr(c *int, def int) int {
	if c == nil {
		return def
	}
	return *c
}

// --- th1 marks (§6.6 "Replay") ---

func initKey(th1 [32]byte) string { return hex.EncodeToString(th1[:]) }

// initAnswered reports whether a reconnect hs.init with this transcript hash
// was answered already.
func (m *Manager) initAnswered(th1 [32]byte) bool {
	_, ok := m.st.SeenInit[initKey(th1)]
	return ok
}

func (m *Manager) markInit(th1 [32]byte, now time.Time) {
	m.st.SeenInit[initKey(th1)] = now
	m.dirty = true
}

// --- epoch history (§6.6 "Epoch history") ---

// recordEpoch adds an activated epoch to a service connection's history and
// marks the previous current one superseded. A person connection keeps none.
func (m *Manager) recordEpoch(p *Peer, id []byte, ownChain int, now time.Time) {
	if !p.isService() {
		p.History = nil
		return
	}
	if n := len(p.History); n > 0 && p.History[n-1].Superseded.IsZero() {
		p.History[n-1].Superseded = now
	}
	p.History = append(p.History, EpochRecord{ID: append([]byte(nil), id...), Activated: now, OwnChain: ownChain})
	pruneHistory(p, now)
}

// pruneHistory drops the epochs superseded 35 days ago or more, the oldest
// past the cap of 512, and a fork watch past its window. The current epoch
// is never dropped.
func pruneHistory(p *Peer, now time.Time) {
	kept := p.History[:0]
	for i, r := range p.History {
		if i < len(p.History)-1 && !r.Superseded.IsZero() && now.Sub(r.Superseded) >= EpochHistoryWindow {
			continue
		}
		kept = append(kept, r)
	}
	for i := len(kept); i < len(p.History); i++ {
		p.History[i] = EpochRecord{}
	}
	p.History = kept
	if over := len(p.History) - EpochHistoryMax; over > 0 {
		p.History = append([]EpochRecord(nil), p.History[over:]...)
	}
	if p.Watch != nil && !now.Before(p.Watch.Until) {
		p.Watch = nil
	}
}

func (m *Manager) pruneHistories(now time.Time) {
	for _, p := range m.st.Connections {
		if len(p.History) > 0 || p.Watch != nil {
			pruneHistory(p, now)
		}
	}
}

// ctxKind is what a reconnect hs.init's ctx names (§6.6 "Accepting ctx").
type ctxKind int

const (
	ctxNone    ctxKind = iota // no epoch this vault accepts
	ctxCurrent                // the connection's last epoch
	ctxOlder                  // an older epoch of a service's history (a restore)
	ctxFork                   // an epoch of a line a restore replaced (two copies)
)

// classifyCtx decides what ctx names and, for ctxOlder and ctxFork, the
// index of the epoch in p.History. Precedence (§6.6): the last epoch first;
// then the replaced line, which is never accepted as a restore; then, on a
// service connection only, the history within the window.
func classifyCtx(p *Peer, ctx string, now time.Time) (ctxKind, int) {
	if len(p.LastEpochID) > 0 && ctx == handshake.EpochCtx(epochIDOf(p.LastEpochID)) {
		return ctxCurrent, -1
	}
	if !p.isService() {
		return ctxNone, -1
	}
	idx := -1
	for i, r := range p.History {
		if len(r.ID) == suite.EpochIDSize && ctx == handshake.EpochCtx(epochIDOf(r.ID)) {
			idx = i
		}
	}
	if idx < 0 {
		return ctxNone, -1
	}
	if p.Watch != nil && now.Before(p.Watch.Until) {
		for _, id := range p.Watch.Replaced {
			if bytes.Equal(id, p.History[idx].ID) {
				return ctxFork, idx
			}
		}
	}
	r := p.History[idx]
	if r.Superseded.IsZero() || now.Sub(r.Superseded) >= EpochHistoryWindow {
		// The current epoch is ctxCurrent above; an epoch past its window
		// is refused.
		return ctxNone, -1
	}
	return ctxOlder, idx
}

// setWatch records the line an accepted older reconnect replaced: the epochs
// after the one it named, and the hs.init's inner ts (§6.6 "Fork detection").
// A second restore adds to the line already watched.
func (m *Manager) setWatch(p *Peer, named []byte, ts, now time.Time) {
	idx := -1
	for i, r := range p.History {
		if bytes.Equal(r.ID, named) {
			idx = i
		}
	}
	w := p.Watch
	if w == nil || !now.Before(w.Until) {
		w = &ForkWatch{}
	}
	if idx >= 0 {
		for _, r := range p.History[idx+1:] {
			dup := false
			for _, id := range w.Replaced {
				dup = dup || bytes.Equal(id, r.ID)
			}
			if !dup {
				w.Replaced = append(w.Replaced, append([]byte(nil), r.ID...))
			}
		}
	}
	w.TS, w.Until = ts, now.Add(EpochHistoryWindow)
	p.Watch = w
	m.dirty = true
}

// activatedAt returns when the epoch with this id was activated.
func (p *Peer) activatedAt(id []byte) time.Time {
	for _, r := range p.History {
		if bytes.Equal(r.ID, id) {
			return r.Activated
		}
	}
	return time.Time{}
}

// forkEvidence reports whether a message that decrypted under epoch ep,
// with inner ts ts, is authenticated evidence of a replaced line (§6.6
// "Fork detection"): its epoch is one the restore replaced and its ts is
// later than the accepted reconnect's. Traffic the restored peer sent
// before its crash has an earlier ts and is processed normally.
func forkEvidence(p *Peer, ep *handshake.Epoch, ts, now time.Time) bool {
	w := p.Watch
	if w == nil || ep == nil || !now.Before(w.Until) || !ts.After(w.TS) {
		return false
	}
	id := ep.ID()
	for _, r := range w.Replaced {
		if bytes.Equal(r, id[:]) {
			return true
		}
	}
	return false
}

// suspendFork suspends a connection on fork evidence (§6.6, under the rules
// of §3.4): it sends nothing and accepts nothing; what was in flight for it
// is abandoned; connection.fork_suspected is audited and makes a feed item
// of priority high (apps show "<connection name> may be running from two
// copies of its data. The connection is paused. Contact <connection name>
// before you connect again.", approved 2026-10-28). There is nothing to
// resolve (connection.rotation.resolve answers not_found): only a new
// invitation resumes it, after the member has contacted the service.
func (m *Manager) suspendFork(p *Peer, now time.Time) {
	if p.Fork != nil {
		return
	}
	p.Fork = &ForkSuspension{At: now.UTC()}
	m.abandonHandshakes(p, true, true, now)
	for _, e := range m.st.Outbox {
		if e.PeerID == p.ID {
			e.Done = true // nothing is sent to a suspended connection
		}
	}
	m.dirty = true
	m.record(Activity{Kind: "connection.fork_suspected", ConnectionID: p.ID, Audit: true, Feed: true, Priority: "high"}, now)
}

// abandonHandshakes drops the reconnects (and with rekeys, when all is set)
// that are open for p: the responder state is aborted, the tokens issued in
// the hs.init or hs.resp are denylisted and the handshake message, if not
// yet deposited, is not sent (§6.6 "Crossing reconnects"). Answers
// (awaiting hs.fin) are dropped when answers is set; the vault's own
// hs.init always.
func (m *Manager) abandonHandshakes(p *Peer, all, answers bool, now time.Time) {
	if answers {
		for id := range m.st.Awaiting {
			aw := m.st.Awaiting[id]
			if aw.New == nil && aw.PeerID == p.ID && (all || aw.Purpose == handshake.PurposeReconnect) {
				m.abandonAwaiting(id, now)
			}
		}
	}
	for id, og := range m.st.Outgoing {
		if og.New == nil && og.PeerID == p.ID && (all || og.Purpose == handshake.PurposeReconnect) {
			m.abandonOutgoing(id, now)
		}
	}
}

// abandonAwaiting ends an answered handshake that did not complete: its
// state is aborted, its tokens denylisted and its hs.resp unsent.
func (m *Manager) abandonAwaiting(id string, now time.Time) {
	aw := m.st.Awaiting[id]
	if aw == nil {
		return
	}
	if r := m.awaiting[id]; r != nil {
		r.Abort()
	}
	for _, t := range aw.Issued {
		m.denyJTI(t.JTI, now)
	}
	m.dropOutboxEntry(aw.RespOutbox)
	delete(m.awaiting, id)
	delete(m.st.Awaiting, id)
	m.dirty = true
}

// abandonOutgoing ends a handshake the vault initiated that did not
// complete: a later hs.resp to it finds nothing and is dropped and audited
// (unknown_kid), the tokens its hs.init carried are denylisted and the
// hs.init, if not yet deposited, is not sent.
func (m *Manager) abandonOutgoing(id string, now time.Time) {
	og := m.st.Outgoing[id]
	if og == nil {
		return
	}
	for _, t := range og.Issued {
		m.denyJTI(t.JTI, now)
	}
	m.dropOutboxEntry(og.InitOutbox)
	m.dropOutgoing(id)
	m.dirty = true
}

// dropOutboxEntry marks a queued deposit done, so it is not sent.
func (m *Manager) dropOutboxEntry(id string) {
	if id == "" {
		return
	}
	for _, e := range m.st.Outbox {
		if e.ID == id {
			e.Done = true
		}
	}
}
