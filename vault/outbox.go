package vault

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/vettid/vettid-relay/relayclient"
	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Outbox retry backoff for transport errors and 5xx (§8.6: full jitter,
// 0.25 s × 2ⁿ, capped at 30 s; relayclient retries within one attempt).
const outboxMaxBackoff = 30 * time.Second

func (m *Manager) queueDeposit(e *OutboxEntry, now time.Time) {
	e.ID = m.newID(now)
	e.Op = OpDeposit
	e.Created = now
	m.queue(e)
}

func (m *Manager) queueRevoke(kind, value string, now time.Time) {
	m.queue(&OutboxEntry{ID: m.newID(now), Op: OpRevoke, Kind: kind, Value: value, Created: now})
}

func (m *Manager) queueDeleteClaim(id string, now time.Time) {
	m.queue(&OutboxEntry{ID: m.newID(now), Op: OpDeleteClaim, Value: id, Created: now})
}

// queue adds e to the outbox. It is not sent before a state write stores
// it (§11.14.2 "order of writes", §8.3: nothing leaves the vault before
// the write that commits it): until then it is unstored, and a drain
// passes it over and holds back the later deposits to its mailbox. A write
// that fails leaves it unstored; the in-memory state it belongs to is
// stored by the next write that succeeds, or never (a lock or crash first).
func (m *Manager) queue(e *OutboxEntry) {
	m.st.Outbox = append(m.st.Outbox, e)
	if m.unstored == nil {
		m.unstored = map[string]bool{}
	}
	m.unstored[e.ID] = true
	m.dirty = true
}

// flushThenDrain writes the state if it changed, and only then performs the
// due outbox entries (and writes their outcome): a drain sends only what a
// write stored.
func (m *Manager) flushThenDrain(ctx context.Context) error {
	if err := m.flushIfDirty(ctx); err != nil {
		return err
	}
	m.drainOutbox(ctx)
	return m.flushIfDirty(ctx)
}

// sealAndQueue seals in to p's current epoch and queues the deposit.
// It returns the inner id, or "" if p has no session.
func (m *Manager) sealAndQueue(p *Peer, in *envelope.Inner) string {
	return m.sealAndQueueWake(p, in, "")
}

// sealAndQueueWake is sealAndQueue with a push wake class (§14.2).
func (m *Manager) sealAndQueueWake(p *Peer, in *envelope.Inner, wake string) string {
	kr := m.sessions[p.ID]
	if kr == nil || kr.Current() == nil || p.Fork != nil {
		return "" // nothing is sent to a connection suspended on fork evidence (§6.6)
	}
	raw, err := m.sealFor(p, kr.Current(), in)
	if errors.Is(err, errDemoted) {
		m.holdDemoted(p, in, wake) // §3.4.1: held until a new epoch is established
		return in.ID
	}
	if err != nil {
		return ""
	}
	m.keepCopy(p, in, wake) // §6.3.1 "Deployment": kept for a revert
	m.queueDeposit(&OutboxEntry{PeerID: p.ID, RelayURL: p.Relay.URL, Mailbox: p.Relay.Mailbox, Payload: raw, Wake: wake}, m.now())
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
	if p.suspended() {
		return "" // suspended by a rotation conflict (release R, §3.4) or by fork evidence (§6.6, 0.72.0)
	}
	if !serviceMayReceive(p, typ) {
		return "" // §6.4: a service connection is sent upkeep, the profile, authentication answers and votes only
	}
	if !m.holdDelivers(p, typ, body, now) {
		return "" // the owner check's hold (§3.6.3): no fan-out
	}
	in := &envelope.Inner{ID: m.newID(now), Type: typ, TS: now, Exp: o.Exp, Body: body}
	if !o.MemoryOnly {
		return m.sealAndQueueWake(p, in, m.wakeClass(p, typ, body))
	}
	kr := m.sessions[p.ID]
	if kr == nil || kr.Current() == nil || p.Standing.Token == "" {
		return ""
	}
	raw, err := m.sealFor(p, kr.Current(), in)
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
		if p.ID != except && (o.Kind == "" || o.Kind == p.Kind) {
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

// sendLocking deposits vault.locking (ephemeral) directly to each device
// and returns the devices whose mailbox accepted it.
func (m *Manager) sendLocking(ctx context.Context) map[string]bool {
	now := m.now()
	ok := map[string]bool{}
	for _, p := range m.ownerDevices() {
		kr := m.sessions[p.ID]
		if kr == nil || kr.Current() == nil || p.Standing.Token == "" || m.outboxPending(p.ID) {
			// vault.locking is best effort and is deposited directly; it
			// must not overtake queued messages to the device (an hs.fin
			// still in the outbox would let it arrive in an epoch the
			// device has not activated yet).
			continue
		}
		// 0.29.0, release L (§10.2 "Locks"): vault.locking names the
		// unlock it ends, for a lock from any cause.
		lb := strictjson.NewBuilder()
		if m.lockReason != "" {
			lb.String("reason", m.lockReason)
		}
		body := json.RawMessage(lb.String("unlock_id", m.unlockID).Bytes())
		in := &envelope.Inner{ID: m.newID(now), Type: "vault.locking", TS: now, Exp: now.Add(time.Minute), Body: body}
		if raw, err := m.sealFor(p, kr.Current(), in); err == nil {
			if _, err := m.relay.Deposit(ctx, p.Relay.URL, p.Relay.Mailbox, p.Standing.Token, raw); err == nil {
				ok[p.ID] = true
			}
		}
	}
	return ok
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
			e.NotBefore, e.AwaitToken = time.Time{}, false
		}
	}
}

// drainOutbox performs due outbox entries (§8.3 step 5). An entry is
// marked done when the relay accepted it and removed at the next flush.
// Deposits to one mailbox stay in order: once an entry for a mailbox is
// not delivered (waiting for a retry, or failed now), later deposits to
// that mailbox wait too, so that a message never overtakes an earlier one
// (an hs.fin, in particular, must precede traffic in its new epoch).
// A deposit waiting for a fresh standing token (AwaitToken) holds back
// only the later deposits on the peer's standing token, not one with a
// token of its own: the reconnect's hs.init that brings the fresh token
// (§6.6) must not wait behind it.
func (m *Manager) drainOutbox(ctx context.Context) {
	if m.st == nil {
		return // zeroized (a split brain at the settled write below): nothing is sent
	}
	if m.holdForMark() {
		return
	}
	now := m.now()
	blocked := map[string]bool{}
	awaiting := map[string]bool{}
	held := map[string]bool{} // held for a pending reconnect (§6.3.1)
	for _, e := range m.st.Outbox {
		if e.Done {
			continue
		}
		key := e.RelayURL + "|" + e.Mailbox
		if m.unstored[e.ID] {
			if e.Op == OpDeposit {
				blocked[key] = true
			}
			continue // not stored yet (queue)
		}
		if e.Op == OpDeposit && (blocked[key] || awaiting[key] && e.Token == "" || e.PeerID != "" && held[e.PeerID] && !e.Handshake) {
			continue
		}
		if e.Op == OpDeposit && e.Held != nil && !e.HeldExp.IsZero() && !now.Before(e.HeldExp) {
			e.Done, e.Held, m.dirty = true, nil, true // held past its exp: discarded (§3.4.1)
			m.audit(now, "held_expired", e.PeerID)    // S12: counted and audited
			continue
		}
		if e.Op == OpDeposit && e.Held != nil {
			// Waiting, unsealed, for an epoch that is not demoted (§3.4.1);
			// the peer's later deposits wait behind it (by peer, not by
			// mailbox: a new invitation's first contact to the same
			// mailbox is not held, review 2), the handshake excepted.
			held[e.PeerID] = true
			continue
		}
		if e.Op == OpDeposit && !e.Handshake && m.pendingReconnectHold(e.PeerID) {
			// §6.3.1: while a reconnect's epoch is pending, nothing but the
			// handshake goes to the peer; the rest waits in order, and the
			// handshake's messages pass it.
			held[e.PeerID] = true
			continue
		}
		if !e.NotAfter.IsZero() && !now.Before(e.NotAfter) {
			e.Done, m.dirty = true, true // past its retries (0.10.5)
			continue
		}
		if now.Before(e.NotBefore) {
			if e.Op == OpDeposit && e.AwaitToken {
				awaiting[key] = true
			} else if e.Op == OpDeposit {
				blocked[key] = true
			}
			continue
		}
		var err error
		switch e.Op {
		case OpDeposit:
			err = m.deposit(ctx, e, now)
			if err == nil && !e.Done {
				m.pushDeposited(e.PeerID, e.Wake) // §14.2: after the relay accepted it
			}
			if e.Unlink != "" {
				m.unlinkOutcome(e, err, now) // §11.14.10: the notice settled, or not
			}
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
		if e.Op == OpDeposit && !e.Done && e.AwaitToken {
			awaiting[key] = true
		} else if e.Op == OpDeposit && !e.Done {
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
	if m.settledWrite {
		// The rotation made when the relay settled a transfer's notice
		// (unlinkOutcome): its state write, then its notices.
		m.settledWrite = false
		if ctx.Err() != nil {
			return // the state stays dirty: the next flush writes it
		}
		switch err := m.persist(ctx, false); {
		case err == nil:
			m.drainOutbox(ctx)
		case errors.Is(err, ErrSplitBrain):
			// Another copy wrote the state: this one is zeroized and
			// locked. It sends nothing more: the caller's flushIfDirty
			// returns ErrSplitBrain, and a later drain returns at once.
		default:
			// Not written: the state stays dirty, and the rotation's
			// notices wait (unstored) for the next flush and drain.
		}
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
			// 0.86.6 S5: with an epoch pending, token_expired abandons it
			// only if the token's exp has passed on the vault's own clock
			// (as rule J); a device is rekeyed, never reconnected (S7).
			if p.Kind == KindConnection && (p.Pending == nil || !now.Before(p.Standing.Exp)) {
				m.startReconnect(p, now) // §6.6 "When to use it"
			} else if p.Kind != KindConnection && p.Pending != nil && !now.Before(p.Standing.Exp) {
				m.abandonPending(p, "token_expired", true, now) // a device: rekeyed from the current epoch
			}
			e.NotBefore = now.Add(time.Hour) // retried when a fresh token arrives
			e.AwaitToken = true
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
	case CodeQuotaExceeded:
		// 0.86.6 S9: the reconnect token's quota is spent: for a reconnect
		// of rule E, rule L or after a demotion, the last try has failed.
		// (A reconnect's hs.init carries its own token and no peer id.)
		for _, og := range m.st.Outgoing {
			if og.InitOutbox == e.ID && (og.RuleRC != "" || og.Why != "") {
				if op := m.peer(og.PeerID); op != nil {
					m.markStale(op, now)
				}
				e.Done = true
				return err
			}
		}
		// Any other deposit: as before 0.86.6, a 429 is retried with the
		// backoff (the token's quota window moves on), another 4xx ends it.
		// (fdcc746 ended every one, dropping e.g. an att.deliver: the
		// e2e TestAttachmentMaliciousPeer failure on CI.)
		if st, ok := statusOf(err); ok && st < 500 && st != 429 {
			m.audit(now, "deposit_refused", e.PeerID)
			e.Done = true
		}
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
	if m.splitBrained {
		return ErrSplitBrain // a drain's settled write lost to another copy
	}
	if !m.dirty {
		return nil
	}
	return m.persist(ctx, false)
}

// housekeeping runs before each batch: expire invites, pairings and
// handshakes, rekey due sessions, refresh tokens.
func (m *Manager) housekeeping(now time.Time) {
	for id, inv := range m.st.Invites {
		if inv.CreatedBy == inviteByRecovery {
			// The recovered phone's: kept until it pairs or a later
			// recovery replaces it; its unlock renews it (§11.14.6, a
			// lost ok; owner decision of 2026-10-16).
			continue
		}
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
	m.recoveryHousekeeping(context.Background(), now)
	m.expirePendingUnlink(now) // release R: the presence retry, the counter notice
	m.expireRequests(now)
	for id, aw := range m.st.Awaiting {
		if aw.New == nil && now.Sub(aw.Created) > HandshakeTTL {
			m.abandonAwaiting(id, now) // its tokens are denylisted too (§6.6)
			if p := m.peer(aw.PeerID); p != nil && aw.Purpose == handshake.PurposeRekey {
				m.ruleL(p, now) // §3.4.1 rule L: the answer expired without hs.fin
			}
		}
	}
	for id, og := range m.st.Outgoing {
		if og.New == nil && now.Sub(og.Created) > HandshakeTTL && m.emu28() {
			m.dropOutgoing(id) // 0ee0078 outbox.go:427
			continue
		}
		if og.New == nil && now.Sub(og.Created) > HandshakeTTL {
			m.abandonOutgoing(id, now) // its tokens are revoked too (§6.6, review M3)
			p := m.peer(og.PeerID)
			switch {
			case p == nil:
			case og.RuleRC != "":
				m.ruleRCExpired(p, og, now) // tried again, up to 3 times; then stale
			case og.Why != "" || og.Purpose == handshake.PurposeReconnect:
				m.demotedReconnectExpired(p, now)
			case og.Purpose == handshake.PurposeRekey:
				m.ruleL(p, now) // rule L: the rekey went unanswered for its lifetime
			}
		}
	}
	for _, p := range m.allPeers() {
		m.tickDemoted(p, now)
		m.tickPending(p, now)
		m.tickRevert(p, now)
		m.pruneEpochs(p, now)
		if p.State != PeerActive {
			continue
		}
		if kr := m.sessions[p.ID]; kr != nil && kr.Current() != nil && kr.Current().NeedsRekey(now) {
			m.startRekey(p, now)
		}
	}
	m.refreshHeld(now)
	if !m.holdAnswers {
		m.sendHeldAnswers(now) // §10.4.1: the neutral answers that are due
	}
	m.expireAccess(now)
	m.ownerCheckTick(now)
	m.attHousekeeping(m.attNow())
	m.remintIssued(now)
	m.pruneHistories(now)
	m.pruneIssued(now)
	m.pruneRetiredKEMs(now)
	m.pruneDroppedAnswers(now)
	for id, fr := range m.featureReqs {
		if now.Sub(fr.at) > featureReqTTL {
			delete(m.featureReqs, id)
		}
	}
	m.tickFeatures(now)
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

// tickFeatures runs the work features have due by the clock (TickObserver).
func (m *Manager) tickFeatures(now time.Time) {
	for _, f := range m.features {
		if o, ok := f.(TickObserver); ok {
			o.Tick(m.session(now))
		}
	}
}
