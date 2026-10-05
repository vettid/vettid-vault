package vault

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/vettid/vettid-relay/relayclient"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Outbox retry backoff for transport errors and 5xx (§8.6: full jitter,
// 0.25 s × 2ⁿ, capped at 30 s; relayclient retries within one attempt).
const outboxMaxBackoff = 30 * time.Second

func (m *Manager) queueDeposit(e *OutboxEntry, now time.Time) {
	e.ID = m.newID(now)
	e.Op = OpDeposit
	e.Created = now
	m.st.Outbox = append(m.st.Outbox, e)
	m.dirty = true
}

func (m *Manager) queueRevoke(kind, value string, now time.Time) {
	m.st.Outbox = append(m.st.Outbox, &OutboxEntry{ID: m.newID(now), Op: OpRevoke, Kind: kind, Value: value, Created: now})
	m.dirty = true
}

func (m *Manager) queueDeleteClaim(id string, now time.Time) {
	m.st.Outbox = append(m.st.Outbox, &OutboxEntry{ID: m.newID(now), Op: OpDeleteClaim, Value: id, Created: now})
	m.dirty = true
}

// sealAndQueue seals in to p's current epoch and queues the deposit.
// It returns the inner id, or "" if p has no session.
func (m *Manager) sealAndQueue(p *Peer, in *envelope.Inner) string {
	kr := m.sessions[p.ID]
	if kr == nil || kr.Current() == nil {
		return ""
	}
	raw, err := kr.Current().Seal(in)
	if err != nil {
		return ""
	}
	m.queueDeposit(&OutboxEntry{PeerID: p.ID, RelayURL: p.Relay.URL, Mailbox: p.Relay.Mailbox, Payload: raw}, m.now())
	return in.ID
}

// sendTo sends a durable event or request to p. It returns the inner id.
func (m *Manager) sendTo(p *Peer, typ string, body json.RawMessage, now time.Time) string {
	return m.sendWith(p, typ, body, SendOptions{}, now)
}

// sendWith sends a message to p with options: an `exp`, or memory-only
// delivery (sealed now, deposited after the flush behind p's queued
// deposits, never written to state). It returns the inner id, or "".
func (m *Manager) sendWith(p *Peer, typ string, body json.RawMessage, o SendOptions, now time.Time) string {
	in := &envelope.Inner{ID: m.newID(now), Type: typ, TS: now, Exp: o.Exp, Body: body}
	if !o.MemoryOnly {
		return m.sealAndQueue(p, in)
	}
	kr := m.sessions[p.ID]
	if kr == nil || kr.Current() == nil || p.Standing.Token == "" {
		return ""
	}
	raw, err := kr.Current().Seal(in)
	if err != nil {
		return ""
	}
	m.volatile = append(m.volatile, &OutboxEntry{ID: in.ID, Op: OpDeposit, PeerID: p.ID, RelayURL: p.Relay.URL,
		Mailbox: p.Relay.Mailbox, Payload: raw, BestEffort: true, Created: now})
	return in.ID
}

// ownerDevices returns the active owner devices that receive fan-out:
// apps, and desktops while their access session lasts (§6.8, §9.1).
// Agents receive only what their grants cover (§9.1), which until LEASH
// is nothing.
func (m *Manager) ownerDevices() []*Peer {
	var out []*Peer
	now := m.now()
	for _, p := range m.st.Devices {
		if p.State == PeerActive && !p.Recovering && (p.Kind == KindApp || p.Kind == KindDesktop && m.hasAccess(p, now)) {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// notifyDevices makes one deposit per owner device, each under that
// device's session (§9.1), except the device `except`.
func (m *Manager) notifyDevices(typ string, body json.RawMessage, except string, now time.Time) {
	m.notifyDevicesWith(typ, body, except, SendOptions{}, now)
}

func (m *Manager) notifyDevicesWith(typ string, body json.RawMessage, except string, o SendOptions, now time.Time) {
	for _, p := range m.ownerDevices() {
		if p.ID != except {
			m.sendWith(p, typ, body, o, now)
		}
	}
}

func (m *Manager) notifyApps(typ string, body json.RawMessage, now time.Time) {
	for _, p := range m.ownerDevices() {
		if p.Kind == KindApp {
			m.sendTo(p, typ, body, now)
		}
	}
}

// sendLocking deposits vault.locking (ephemeral) directly to each device.
func (m *Manager) sendLocking(ctx context.Context) {
	now := m.now()
	for _, p := range m.ownerDevices() {
		kr := m.sessions[p.ID]
		if kr == nil || kr.Current() == nil || p.Standing.Token == "" || m.outboxPending(p.ID) {
			// vault.locking is best effort and is deposited directly; it
			// must not overtake queued messages to the device (an hs.fin
			// still in the outbox would let it arrive in an epoch the
			// device has not activated yet).
			continue
		}
		body := json.RawMessage(`{}`)
		if m.lockReason != "" {
			body = json.RawMessage(`{"reason":"` + m.lockReason + `"}`)
		}
		in := &envelope.Inner{ID: m.newID(now), Type: "vault.locking", TS: now, Exp: now.Add(time.Minute), Body: body}
		if raw, err := kr.Current().Seal(in); err == nil {
			_, _ = m.relay.Deposit(ctx, p.Relay.URL, p.Relay.Mailbox, p.Standing.Token, raw)
		}
	}
}

// outboxPending reports whether deposits to peer are still queued.
func (m *Manager) outboxPending(peer string) bool {
	for _, e := range m.st.Outbox {
		if e.PeerID == peer && !e.Done && e.Op == OpDeposit {
			return true
		}
	}
	return false
}

// retryPeer makes p's waiting entries eligible again (after a token
// refresh or reconnect).
func (m *Manager) retryPeer(peer string) {
	for _, e := range m.st.Outbox {
		if e.PeerID == peer && !e.Done {
			e.NotBefore = time.Time{}
		}
	}
}

// drainOutbox performs due outbox entries (§8.3 step 5). An entry is
// marked done when the relay accepted it and removed at the next flush.
// Deposits to one mailbox stay in order: once an entry for a mailbox is
// not delivered (waiting for a retry, or failed now), later deposits to
// that mailbox wait too, so that a message never overtakes an earlier one
// (an hs.fin, in particular, must precede traffic in its new epoch).
func (m *Manager) drainOutbox(ctx context.Context) {
	now := m.now()
	blocked := map[string]bool{}
	for _, e := range m.st.Outbox {
		if e.Done {
			continue
		}
		key := e.RelayURL + "|" + e.Mailbox
		if e.Op == OpDeposit && blocked[key] {
			continue
		}
		if !e.NotAfter.IsZero() && !now.Before(e.NotAfter) {
			e.Done, m.dirty = true, true // past its retries (0.10.5)
			continue
		}
		if now.Before(e.NotBefore) {
			if e.Op == OpDeposit {
				blocked[key] = true
			}
			continue
		}
		var err error
		switch e.Op {
		case OpDeposit:
			err = m.deposit(ctx, e, now)
		case OpRevoke:
			err = m.relay.Revoke(ctx, e.Kind, e.Value)
		case OpDeleteClaim:
			err = m.relay.DeleteClaim(ctx, e.Value)
			if RelayCode(err) == CodeClaimUnknown {
				err = nil
			}
		}
		m.dirty = true
		if err == nil || e.BestEffort {
			e.Done = true
			continue
		}
		if e.Op == OpDeposit && !e.Done {
			blocked[key] = true
		}
		if e.Done || e.NotBefore.After(now) {
			continue // finished, or the error handler scheduled the retry
		}
		if ctx.Err() != nil {
			continue // interrupted (lock, shutdown): not an attempt
		}
		e.Attempts++
		d := time.Duration(250*(1<<min(e.Attempts, 7))) * time.Millisecond
		e.NotBefore = now.Add(min(d, outboxMaxBackoff))
	}
	// Volatile deposits go after everything durable to the same mailbox
	// (so a response never overtakes an hs.fin); one attempt each.
	vol := m.volatile
	m.volatile = nil
	for _, e := range vol {
		if blocked[e.RelayURL+"|"+e.Mailbox] || ctx.Err() != nil {
			suite.Wipe(e.Payload)
			continue // lost: the requester retransmits, which re-executes
		}
		if p := m.peer(e.PeerID); p != nil && p.Standing.Token != "" {
			_, _ = m.relay.Deposit(ctx, e.RelayURL, e.Mailbox, p.Standing.Token, e.Payload)
		}
		suite.Wipe(e.Payload)
	}
}

// deposit performs one deposit and applies the §8.6 error table.
func (m *Manager) deposit(ctx context.Context, e *OutboxEntry, now time.Time) error {
	tok := e.Token
	p := m.peer(e.PeerID)
	if tok == "" {
		if p == nil {
			e.Done = true // the principal is gone (§7.4: its outbox entries are deleted)
			return nil
		}
		tok = p.Standing.Token
	}
	if h := m.opt.Hooks.DropDeposit; h != nil && h(e) {
		e.Done = true
		return nil
	}
	_, err := m.relay.Deposit(ctx, e.RelayURL, e.Mailbox, tok, e.Payload)
	if err == nil {
		return nil
	}
	switch RelayCode(err) {
	case CodeTokenExpired:
		if p != nil && e.Token == "" {
			if p.Kind == KindConnection {
				m.startReconnect(p, now) // §6.6 "When to use it"
			}
			e.NotBefore = now.Add(time.Hour) // retried when a fresh token arrives
			e.Attempts++
			return err
		}
		e.Done = true
	case CodeTokenRevoked, CodeMailboxUnknown:
		// Terminal: stop sending to that mailbox.
		if p != nil && e.Token == "" {
			p.State = PeerStale
			m.audit(now, "peer_stale", p.ID)
			for _, o := range m.st.Outbox {
				if o.PeerID == p.ID {
					o.Done = true
				}
			}
			if p.Kind == KindConnection {
				m.notifyDevices("connection.event", connEvent(p.ID, "stale"), "", now)
				m.record(Activity{Kind: "connection.stale", ConnectionID: p.ID, Audit: true, Feed: true}, now)
			}
		}
		e.Done = true
	case CodeTokenUsed:
		m.audit(now, "open_token_used", e.PeerID)
		e.Done = true
	case "":
		return err // transport or 5xx after relayclient's own retries
	default:
		if st, ok := statusOf(err); ok && st < 500 && st != 429 {
			m.audit(now, "deposit_refused", e.PeerID)
			e.Done = true
		}
	}
	return err
}

func (m *Manager) flushIfDirty(ctx context.Context) error {
	if !m.dirty {
		return nil
	}
	return m.persist(ctx, false)
}

// housekeeping runs before each batch: expire invites, pairings and
// handshakes, rekey due sessions, refresh tokens.
func (m *Manager) housekeeping(now time.Time) {
	for id, inv := range m.st.Invites {
		if !inv.Used && !now.Before(inv.Exp) {
			if inv.OpenJTI != "" {
				m.denyJTI(inv.OpenJTI, now)
			}
			if inv.ClaimID != "" {
				m.queueDeleteClaim(inv.ClaimID, now)
			}
			delete(m.st.Invites, id)
		} else if inv.Used && now.Sub(inv.Exp) > 24*time.Hour {
			delete(m.st.Invites, id)
		}
	}
	m.expireTransfer(now)
	m.expireRequests(now)
	for id, aw := range m.st.Awaiting {
		if aw.New == nil && now.Sub(aw.Created) > HandshakeTTL {
			if r := m.awaiting[id]; r != nil {
				r.Abort()
			}
			delete(m.awaiting, id)
			delete(m.st.Awaiting, id)
		}
	}
	for id, og := range m.st.Outgoing {
		if og.New == nil && now.Sub(og.Created) > HandshakeTTL {
			m.dropOutgoing(id)
		}
	}
	for _, p := range m.allPeers() {
		if p.State != PeerActive {
			continue
		}
		if kr := m.sessions[p.ID]; kr != nil && kr.Current() != nil && kr.Current().NeedsRekey(now) {
			m.startRekey(p, now)
		}
	}
	m.refreshHeld(now)
	m.expireAccess(now)
	m.remintIssued(now)
	m.pruneIssued(now)
	m.pruneRetiredKEMs(now)
}

// unlockKey ordering keeps the sealed header deterministic.
func sortUnlockKeys(k []UnlockKey) {
	sort.Slice(k, func(i, j int) bool { return k[i].DeviceID < k[j].DeviceID })
}

func statusOf(err error) (int, bool) {
	var e *relayclient.Error
	if errors.As(err, &e) {
		return e.Status, true
	}
	return 0, false
}
