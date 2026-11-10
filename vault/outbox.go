package vault

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"sort"
	"time"

	"github.com/vettid/vettid-relay/relayauth"
	"github.com/vettid/vettid-relay/relayclient"
	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/peerwire"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Outbox retry backoff for transport errors and 5xx (§8.6: full jitter,
// 0.25 s × 2ⁿ, capped at 30 s). (0.88.7) A deposit is one relayclient
// attempt (ClientRelay.depositClient): the outbox's backoff is the retry.
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
	m.queueDeposit(&OutboxEntry{PeerID: p.ID, RelayURL: p.Relay.URL, Mailbox: p.Relay.Mailbox, Payload: raw, Wake: wake, InnerID: in.ID}, m.now())
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
	for _, sortedK := range sortedKeys(m.st.Devices) {
		p, sortedOK := m.st.Devices[sortedK]
		if !sortedOK {
			continue // removed earlier in this loop
		}
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

// retryAfter is a 429's retry_after (0 for any other answer).
func retryAfter(err error) time.Duration {
	var re *relayclient.Error
	if errors.As(err, &re) && re.Status == 429 && re.RetryAfter > 0 {
		return time.Duration(re.RetryAfter) * time.Second
	}
	return 0
}

// mayHaveStored reports whether a deposit answered err may have been
// stored by the relay (0.88.7 §8.3): accepted, no answer (a transport
// error, a lost answer) or any 5xx, coded or not (the relay may have
// committed it before failing). A 4xx, 429 included, is a refusal. An
// outbox deposit is one attempt (withOneAttempt), so the answer is that
// attempt's.
func mayHaveStored(err error) bool {
	if err == nil {
		return true
	}
	st, ok := statusOf(err)
	return !ok || st >= 500
}

// memberDeposit reports whether e is a durable deposit to its peer that
// 0.88.7 §8.3 "Not delivered" covers: not a handshake message, an
// hs.confirm or a best-effort notice.
func memberDeposit(e *OutboxEntry) bool {
	return e.Op == OpDeposit && !e.Handshake && !e.Confirm && !e.BestEffort
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

// tokenQuota reports whether a deposit's quota_exceeded is its standing
// token's (§8.6): `quota: token`; with no `quota` (a relay before 0.9.2),
// the token's the first time, and the mailbox's for an entry refused
// before and now tried under a fresh token, and for any entry under a
// token the peer's quota was already read as the mailbox's under
// (Peer.QuotaMailbox, persisted: it never reverts under that token).
func (m *Manager) tokenQuota(err error, e *OutboxEntry, p *Peer) bool {
	switch RelayQuota(err) {
	case "token":
		return true
	case "":
		tag := tokenTag(p.Standing.Token)
		if p.QuotaMailbox == tag {
			return false
		}
		if e.QuotaTok != "" && e.QuotaTok != tag {
			p.QuotaMailbox, m.dirty = tag, true
			return false
		}
		return true
	}
	return false
}

// tokenTag names a token without holding it: the first 8 bytes of its
// SHA-256, in hex.
func tokenTag(tok string) string {
	h := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(h[:8])
}

// quotaAsk is what the vault knows of its quota refreshes to one peer, in
// memory only: after a restart the waiting entries ask again when due.
type quotaAsk struct {
	at    time.Time // when askQuotaRefresh last asked
	after time.Time // the peer's too_soon allowed_after to a quota refresh (§7.2)
}

// quotaReqsMax bounds Peer.QuotaReqs: a day of hourly asks.
const quotaReqsMax = 24

func (m *Manager) quotaFor(peer string) *quotaAsk {
	if m.quotaAsk == nil {
		m.quotaAsk = map[string]*quotaAsk{}
	}
	q := m.quotaAsk[peer]
	if q == nil {
		q = &quotaAsk{}
		m.quotaAsk[peer] = q
	}
	return q
}

// quotaAskEvery bounds askQuotaRefresh: a refresh lost on its way or
// unanswered is asked again when the waiting entries are next due, no
// sooner.
const quotaAskEvery = time.Hour

// quotaNext is when a deposit waiting for a fresh token for p's quota is
// next due: the next ask (not before a too_soon allowed_after), but no
// later than the standing token's exp (then it is tried, and
// token_expired reconnects, §6.6); an hour on once that exp has passed.
func (m *Manager) quotaNext(p *Peer, now time.Time) time.Time {
	t := now.Add(quotaAskEvery)
	if q := m.quotaAsk[p.ID]; q != nil && q.after.After(t) && !nearEnd(p, now) {
		t = q.after
	}
	if ne := p.Standing.Exp.Add(-HolderRefreshBelow); now.Before(ne) && ne.Before(t) {
		t = ne // the issuer grants a refresh hourly from then on (§7.2): a too_soon no longer holds
	}
	if now.Before(p.Standing.Exp) && p.Standing.Exp.Before(t) {
		t = p.Standing.Exp
	}
	return t
}

// nearEnd: p's standing token has under HolderRefreshBelow left, when the
// issuer grants a refresh hourly (§7.2): a quota too_soon no longer holds.
func nearEnd(p *Peer, now time.Time) bool {
	return p.Standing.Exp.Sub(now) <= HolderRefreshBelow
}

// askQuotaRefresh asks p for a fresh standing token after a quota refusal
// (§7.2): not while an earlier one is still queued (it goes first), at
// most once an hour, and not before the peer's too_soon allowed_after
// (except near the token's end). The earlier ones still unanswered stay
// open (Peer.QuotaReqs): the issuer grants the first and answers the
// later ones too_soon, so the first one's answer must still be taken. The
// refresh is the one deposit under the standing token that passes the
// quota wait (QuotaRefresh): it is small, and changes no epoch.
func (m *Manager) askQuotaRefresh(p *Peer, now time.Time) {
	q := m.quotaFor(p.ID)
	if !q.at.IsZero() && now.Sub(q.at) < quotaAskEvery || now.Before(q.after) && !nearEnd(p, now) {
		return
	}
	if p.Standing.Token == "" {
		return // none held: nothing to ask under (the open ones stay, quotaRequest)
	}
	tag := tokenTag(p.Standing.Token)
	for _, e := range m.st.Outbox {
		if e.PeerID == p.ID && e.QuotaRefresh && e.QuotaTok == tag && !e.Done {
			return
		}
	}
	if p.QuotaReqTok != tag {
		m.dropQuotaRequests(p)
		p.QuotaReqTok = tag
	}
	if len(p.QuotaReqs) >= quotaReqsMax {
		// A day of asks open: the first (the one the issuer grants, if
		// it ever got it) is kept, the next oldest makes room.
		m.forgetRequest(p, p.QuotaReqs[1])
	}
	n := len(m.st.Outbox)
	id := m.sendTo(p, tokenRefreshType, peerwire.TokenRefreshBody(), now)
	if id == "" {
		return
	}
	q.at = now
	p.QuotaReqs, m.dirty = append(p.QuotaReqs, id), true
	for _, e := range m.st.Outbox[n:] {
		e.QuotaRefresh, e.QuotaTok, e.QuotaReq = true, tag, id
	}
}

// quotaWaits reports whether a deposit to peer waits for a fresh token for
// its quota (QuotaWait).
func (m *Manager) quotaWaits(peer string) bool {
	for _, e := range m.st.Outbox {
		if e.PeerID == peer && e.QuotaWait && !e.Done {
			return true
		}
	}
	return false
}

// quotaRequest reports whether re is one of p's open quota refreshes,
// asked under the standing token p holds, or under one since dropped with
// none held now (revoked between the grant and its collect: the grant is
// still taken, or the connection could go stale). They are not in m.requests
// (so they never hold requestPending, the near-end refresh's and an
// attachment's), and handleResponse takes their answers from here.
func quotaRequest(p *Peer, re string) bool {
	if re == "" || p.QuotaReqTok == "" || p.Standing.Token != "" && p.QuotaReqTok != tokenTag(p.Standing.Token) {
		return false
	}
	return slices.Contains(p.QuotaReqs, re)
}

// forgetRequest drops one of p's quota refreshes (answered, ended unsent,
// or the oldest beyond quotaReqsMax).
func (m *Manager) forgetRequest(p *Peer, id string) {
	p.QuotaReqs = slices.DeleteFunc(p.QuotaReqs, func(x string) bool { return x == id })
	if len(p.QuotaReqs) == 0 {
		p.QuotaReqs = nil
	}
	m.dirty = true
}

// dropQuotaRequests forgets p's open quota refreshes once another standing
// token is held, so that requestPending (the near-end refresh, an
// attachment's token) is not held by them.
func (m *Manager) dropQuotaRequests(p *Peer) {
	if p.QuotaReqs != nil || p.QuotaReqTok != "" {
		p.QuotaReqs, p.QuotaReqTok, m.dirty = nil, "", true
	}
}

// quotaRefreshEnded drops a quota refresh's request when its deposit ends
// unsent (refused, or its wait over): no answer can come.
func (m *Manager) quotaRefreshEnded(e *OutboxEntry) {
	if p := m.peer(e.PeerID); p != nil && quotaRequest(p, e.QuotaReq) {
		m.forgetRequest(p, e.QuotaReq)
	}
}

// quotaTooSoon records the too_soon answer to a quota refresh (§7.2):
// asked again after allowed_after, bounded by the issuer's own period. A
// near-end refresh's too_soon (RenewEvery) is not one.
func (m *Manager) quotaTooSoon(p *Peer, re string, body []byte, now time.Time) {
	if !quotaRequest(p, re) {
		return
	}
	m.forgetRequest(p, re)
	t, err := peerwire.ParseTooSoon(body)
	if err != nil {
		return
	}
	if lim := now.Add(peerwire.QuotaRefreshEvery + time.Minute); t.After(lim) {
		t = lim
	}
	m.quotaFor(p.ID).after = t
}

// quotaReconnect starts a reconnect for a connection whose standing token
// cannot be refreshed (owner decision of 2026-11-10, GC #6840): its
// refresh was itself refused for the token's quota, or the token's exp
// passed with a quota refusal still answered. At once (§8.6 0.88.6), also
// while an own rekey's epoch is pending: unlike token_expired's clock-skew
// guard (rule J), a pending rekey changes nothing here (its hs.fin may be
// the very deposit refused), and the reconnect abandons it
// (startReconnectCtx). A rekey whose hs.fin the relay already took is
// then the abandon rules' case (§6.3.1), as after token_revoked. Not while carried tokens wait. Before the exp, not
// without a reconnect token (that would make the connection stale,
// §3.4.1, while the issuer's re-mint may still come). The reconnect's
// hs.init carries its own token and passes the wait.
func (m *Manager) quotaReconnect(p *Peer, now time.Time) {
	if now.Before(p.Standing.Exp) && noReconnectToken(p, now) {
		return
	}
	if !m.carriedWait(p, now) {
		m.startReconnect(p, now)
	}
}

// retryPeer makes p's waiting entries eligible again (after a token
// refresh or reconnect).
func (m *Manager) retryPeer(peer string) {
	if p := m.peer(peer); p != nil && p.QuotaReqTok != "" && p.Standing.Token != "" && p.QuotaReqTok != tokenTag(p.Standing.Token) {
		m.dropQuotaRequests(p) // another standing token is held: the quota refreshes still open are not needed
	}
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
		if e.Op == OpDeposit && (blocked[key] || awaiting[key] && e.Token == "" && !e.QuotaRefresh || e.PeerID != "" && held[e.PeerID] && !e.Handshake) {
			continue
		}
		if e.Op == OpDeposit && e.Held != nil && !e.HeldExp.IsZero() && !now.Before(e.HeldExp) {
			e.Done, e.Held, m.dirty = true, nil, true // held past its exp: discarded (§3.4.1)
			if e.QuotaRefresh {
				m.quotaRefreshEnded(e) // unsent: no answer can come
			}
			m.audit(now, "held_expired", e.PeerID) // S12: counted and audited
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
			if e.Op == OpDeposit && (e.AwaitToken || e.QuotaWait) {
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
		if err != nil && e.Done && e.QuotaRefresh {
			m.quotaRefreshEnded(e) // refused: no answer can come
		}
		if err == nil || e.BestEffort {
			e.Done = true
			continue
		}
		if e.Op == OpDeposit && !e.Done && (e.AwaitToken || e.QuotaWait) {
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
		if ra := retryAfter(err); now.Add(ra).After(e.NotBefore) {
			e.NotBefore = now.Add(ra) // a 429's retry_after is honoured (§8.6)
		}
	}
	// Volatile deposits go after everything durable to the same mailbox
	// (so a response never overtakes an hs.fin); one attempt each.
	vol := m.volatile
	m.volatile = nil
	// A deposit still waiting for a fresh token for its quota (whatever
	// held it back in this pass): a volatile one to that mailbox does not
	// pass it.
	quotaWaiting := map[string]bool{}
	for _, e := range m.st.Outbox {
		if e.Op == OpDeposit && e.QuotaWait && !e.Done {
			quotaWaiting[e.RelayURL+"|"+e.Mailbox] = true
		}
	}
	for _, e := range vol {
		if blocked[e.RelayURL+"|"+e.Mailbox] || quotaWaiting[e.RelayURL+"|"+e.Mailbox] || ctx.Err() != nil {
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
		if tok == "" && p.Kind == KindConnection {
			// No standing token held (0.88.2 §8.6: one revoked): the entry
			// waits for a valid one; the no-token path is already taken.
			e.NotBefore, e.AwaitToken = now.Add(time.Hour), true
			return errNoStandingToken
		}
		if e.QuotaRefresh && tokenTag(tok) != e.QuotaTok {
			// Asked under a token since replaced: the wait it was for is
			// over, and under the new one it would only spend the daily
			// quota refresh (§7.2).
			e.Done = true
			m.quotaRefreshEnded(e)
			return nil
		}
		if e.QuotaWait && tokenTag(tok) == e.QuotaTok {
			// RELAY-PROTOCOL §7.1: not retried unchanged under the token
			// refused for its quota; only a fresh one cures it. Asked
			// again (askQuotaRefresh's bounds); from the token's exp on,
			// a reconnect (as token_expired's, §6.6).
			if now.Before(p.Standing.Exp) {
				m.askQuotaRefresh(p, now)
			} else {
				m.quotaReconnect(p, now)
			}
			e.NotBefore = m.quotaNext(p, now)
			return errQuotaWait
		}
		e.QuotaWait = false // under a fresh token (or the exp): the wait is over
	}
	if h := m.opt.Hooks.DropDeposit; h != nil && h(e) {
		e.Done = true
		return nil
	}
	_, err := m.relay.Deposit(withOneAttempt(ctx), e.RelayURL, e.Mailbox, tok, e.Payload)
	if mayHaveStored(err) {
		e.Tried = true // 0.88.7 §8.3: it may have reached the relay
	}
	if err == nil {
		return nil
	}
	switch RelayCode(err) {
	case CodeTokenExpired:
		if p != nil && e.Token == "" {
			// 0.86.6 S5: with an epoch pending, token_expired abandons it
			// only if the token's exp has passed on the vault's own clock
			// (as rule J); a device is rekeyed, never reconnected (S7).
			if p.Kind == KindConnection && (p.Pending == nil || !now.Before(p.Standing.Exp)) && !m.carriedWait(p, now) {
				m.startReconnect(p, now) // §6.6 "When to use it"; 0.88.2: not while carried tokens wait
			} else if p.Kind != KindConnection && p.Pending != nil && !now.Before(p.Standing.Exp) {
				m.abandonPending(p, "token_expired", true, now) // a device: rekeyed from the current epoch
			}
			if e.Done {
				return err // this entry was an abandoned epoch's own hs.fin, withdrawn with it
			}
			e.NotBefore = now.Add(time.Hour) // retried when a fresh token arrives
			e.AwaitToken = true
			e.Attempts++
			return err
		}
		e.Done = true
	case CodeTokenRevoked, CodeMailboxUnknown:
		if RelayCode(err) == CodeTokenRevoked && m.tokenRevoked(p, e, tok, now) {
			return err // 0.88.2 §8.6: between two vaults, that token only
		}
		// Terminal: stop sending to that mailbox.
		if p != nil && e.Token == "" {
			p.State = PeerStale
			m.audit(now, "peer_stale", p.ID)
			for _, o := range m.st.Outbox {
				if o.PeerID == p.ID && !o.Done && p.Kind == KindConnection && memberDeposit(o) {
					m.notDelivered(o, "undelivered_mailbox_unknown", now) // 0.88.7 §8.3: never silently
				} else if o.PeerID == p.ID {
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
		// §3.4.1 "The reconnect bound": a relay refusing a reconnect's
		// hs.init with quota_exceeded (the reconnect token's quota) makes
		// the connection stale, whatever started the reconnect. (A
		// reconnect's hs.init carries its own token and no peer id.)
		for _, sortedK := range sortedKeys(m.st.Outgoing) {
			og, sortedOK := m.st.Outgoing[sortedK]
			if !sortedOK {
				continue // removed earlier in this loop
			}
			if og.InitOutbox == e.ID && og.New == nil && og.Purpose == handshake.PurposeReconnect {
				if op := m.peer(og.PeerID); op != nil {
					m.markStale(op, now)
				}
				e.Done = true
				return err
			}
		}
		if p != nil && e.Token == "" && p.Kind == KindConnection && m.tokenQuota(err, e, p) {
			tag := tokenTag(p.Standing.Token)
			if e.QuotaRefresh {
				// The refresh itself refused for the token's quota (its
				// msgs are spent): no refresh can be asked under it, and
				// the issuer's re-mint may come only after the waiting
				// messages are too old (MaxDurableAge). Reconnect at once
				// (owner decision of 2026-11-10, GC #6840). Without
				// `quota` it may be the mailbox's: asked again in an hour.
				m.note(now, "quota_refresh_refused", p.ID)
				e.Done = true
				m.quotaRefreshEnded(e)
				if RelayQuota(err) == "token" {
					m.quotaReconnect(p, now)
				}
				return err
			}
			// §8.6 quota_exceeded `token` (RELAY-PROTOCOL §7.1: never
			// retried unchanged): ask for a fresh standing token (§7.2)
			// and try once more with it (retryPeer when it arrives).
			e.QuotaWait, e.QuotaTok = true, tag
			e.Attempts++
			if !now.Before(p.Standing.Exp) {
				// Refused for its quota past the token's exp (the relay's
				// clock behind ours): no refresh, reconnect (§6.6).
				m.quotaReconnect(p, now)
			} else {
				m.askQuotaRefresh(p, now)
			}
			e.NotBefore = m.quotaNext(p, now)
			return err
		}
		// Any other deposit (the mailbox's quota, or a reconnect token's
		// elsewhere): as before 0.86.6, a 429 is retried with the
		// backoff, another 4xx ends it.
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
	for _, id := range sortedKeys(m.st.Invites) {
		inv, sortedOK := m.st.Invites[id]
		if !sortedOK {
			continue // removed earlier in this loop
		}
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
	for _, id := range sortedKeys(m.st.Awaiting) {
		aw, sortedOK := m.st.Awaiting[id]
		if !sortedOK {
			continue // removed earlier in this loop
		}
		if aw.New == nil && now.Sub(aw.Created) > HandshakeTTL {
			m.abandonAwaiting(id, now) // its tokens are denylisted too (§6.6)
		}
	}
	for _, id := range sortedKeys(m.st.Outgoing) {
		og, sortedOK := m.st.Outgoing[id]
		if !sortedOK {
			continue // removed earlier in this loop
		}
		if og.New == nil && now.Sub(og.Created) > HandshakeTTL {
			m.abandonOutgoing(id, now) // its tokens are revoked too (§6.6, review M3)
			p := m.peer(og.PeerID)
			switch {
			case p == nil:
			case og.Purpose == handshake.PurposeReconnect:
				m.reconnectFailed(p, og.Named, now)
			}
		}
	}
	for _, p := range m.allPeers() {
		m.tickDemoted(p, now)
		m.tickStale(p, now)
		m.tickPending(p, now)
		m.sweepCarried(p, now) // 0.88.2 §6.3.1: the carried tokens' bound
		m.tickConfirm(p, now)
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

// errNoStandingToken: a deposit to a connection waits, the vault holding
// no standing token for it.
var errNoStandingToken = errors.New("vault: no standing token held for the peer")

// errQuotaWait: a deposit refused for its standing token's quota waits for
// a fresh token (QuotaWait), not sent again under that one.
var errQuotaWait = errors.New("vault: waiting for a fresh standing token (quota)")

// tokenRevoked is §8.6's token_revoked between two vaults (0.88.2, owner
// decision a, GC 01M6SRQ1B7NM0Q00G0CEGHFES8): for a deposit to a
// connection with a standing token (held, or carried by an hs.init or
// hs.resp) the answer ends that token only, not the connection. The
// token is dropped and never used again (a later offer of it is refused,
// heldToken); the entry waits for a valid token; with no other valid
// standing token held, the vault takes the "no valid standing token" path
// (a pending rekey abandoned, §6.3.1; a reconnect, §6.6, bounded by the
// reconnect bound). A reconnect's own hs.init answered token_revoked is a
// failed try. It reports whether it handled the answer; a device's path
// (toward a device's own vault) is unchanged.
func (m *Manager) tokenRevoked(p *Peer, e *OutboxEntry, tok string, now time.Time) bool {
	for _, id := range sortedKeys(m.st.Outgoing) {
		og, sortedOK := m.st.Outgoing[id]
		if !sortedOK {
			continue // removed earlier in this loop
		}
		if og.InitOutbox != e.ID || og.New != nil || og.Purpose != handshake.PurposeReconnect {
			continue
		}
		op := m.peer(og.PeerID)
		if op == nil || op.Kind != KindConnection {
			return false
		}
		named := og.Named
		m.audit(now, "reconnect_token_revoked", op.ID)
		m.abandonOutgoing(id, now)
		e.Done = true
		m.reconnectFailed(op, named, now)
		return true
	}
	if p == nil || p.Kind != KindConnection {
		return false
	}
	if m.carriedRevoked(p, e, tok, now) {
		return true // 0.88.2 §6.3.1 "A carried token refused"
	}
	m.dropHeldToken(p, tok, now)
	m.audit(now, "standing_token_revoked", p.ID)
	e.Token = "" // from now on the held standing token, once a valid one is held
	e.NotBefore, e.AwaitToken = now.Add(time.Hour), true
	e.Attempts++
	if (p.Standing.Token == "" || !now.Before(p.Standing.Exp)) && !m.carriedWait(p, now) {
		m.noStandingToken(p, now)
	}
	m.dirty = true
	return true
}

// dropHeldToken forgets tok as p's standing token and records its jti as
// revoked until its exp, so that it is refused if offered again.
func (m *Manager) dropHeldToken(p *Peer, tok string, now time.Time) {
	if p.Standing.Token == tok {
		p.Standing = HeldToken{}
	}
	if c, err := relayauth.ParseToken(tok, p.Relay.PK); err == nil {
		kept := p.RevokedHeld[:0]
		for _, r := range p.RevokedHeld {
			if now.Before(r.Exp) && r.JTI != c.Jti {
				kept = append(kept, r)
			}
		}
		p.RevokedHeld = append(kept, RevokedToken{JTI: c.Jti, Exp: c.Exp})
	}
	m.dirty = true
}

// noStandingToken is the "no valid standing token" case for connection
// p: a pending rekey is abandoned (§6.3.1, restarting as a reconnect),
// otherwise the vault reconnects (§6.6).
func (m *Manager) noStandingToken(p *Peer, now time.Time) {
	if pe := p.Pending; pe != nil && pe.Purpose == handshake.PurposeRekey {
		m.abandonPending(p, "no_token", true, now)
		return
	}
	m.startReconnect(p, now)
}
