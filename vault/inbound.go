package vault

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"time"

	"github.com/vettid/vettid-relay/relayauth"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Retention windows (§8.2).
const (
	DedupeRetention   = 16 * 24 * time.Hour
	ResponseRetention = 24 * time.Hour
	EphemeralDedupe   = 10 * time.Minute
	AuditMax          = 1000
)

// disposition of one collected message.
type disposition int

const (
	ackAfterFlush disposition = iota // durable: ack once the batch is flushed
	ackNow                           // ephemeral: ack after handling
	noAck                            // leave for redelivery (inactive epoch)
)

// Start runs the unlock sequence of §12.2 (re-mint tokens and start
// reconnects, rekey device sessions, drain the outbox) and opens the
// collector. Run calls it; tests that drive Step call it once.
func (m *Manager) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.locked {
		return ErrLocked
	}
	if m.started {
		m.attStart(ctx) // a run loop after an earlier one ended
		return nil
	}
	m.started = true
	now := m.now()
	m.record(Activity{Kind: "vault.unlocked", DeviceID: m.unlockedBy, Audit: true}, now)
	m.ownerCheckInit(now)
	m.retryOwedRotation(now) // §11.14.10: a rotation owed since a recovery
	m.remintIssued(now)
	m.markDeviceTokens(now)
	m.reconnectExpired(now)
	for _, p := range m.st.Devices {
		if p.State == PeerActive {
			m.startRekey(p, now) // device sessions rekey on every unlock (§6.5)
		}
	}
	m.ownerCheckTick(now) // past the deadline: held from the unlock on (§3.6.3)
	m.attLateAtUnlock(m.attNow())
	if err := m.persist(ctx, false); err != nil {
		return err
	}
	m.attStart(ctx)  // finishes what a lock or crash interrupted, from the index (§10.5.1)
	m.reportAppKey() // a backup bit first recorded by this release (0.16.0)
	m.drainOutbox(ctx)
	return m.flushIfDirty(ctx)
}

// Run collects and processes batches until ctx ends or the vault locks.
func (m *Manager) Run(ctx context.Context) error {
	if err := m.Start(ctx); err != nil {
		return err
	}
	// Vaults that start together do not send their first poll together
	// (tests set PollWait and poll at once).
	if m.opt.PollWait == 0 && !sleep(ctx, rand.N(firstPollSpread)) {
		return ctx.Err()
	}
	// §3.6.8 (0.29.0, release L): the idle lock does not wait for the
	// collect loop, which a host can stall (a relay that never answers,
	// a collect that blocks); its own timer locks the vault.
	wctx, stopWatch := context.WithCancel(ctx)
	defer stopWatch()
	go m.idleWatch(wctx)
	refused := 0
	for {
		_, err := m.Step(ctx)
		if err == nil {
			refused = 0
			continue
		}
		if errors.Is(err, ErrLocked) || errors.Is(err, ErrSplitBrain) || errors.Is(err, ErrCrash) || ctx.Err() != nil {
			return err
		}
		switch RelayCode(err) {
		case CodeMailboxUnknown, CodeTimestampStale:
			refused++
		default:
			refused = 0
		}
		if !sleep(ctx, retryWait(refused)) {
			return ctx.Err()
		}
	}
}

// Waits of the collect loop (VAULT-RELAY-SCALING §4 G): no vault retries
// at a fixed interval, or every vault of a host would ask again in the
// same instant after a relay error.
const (
	firstPollSpread = time.Second
	retryBase       = time.Second
	retryMax        = 15 * time.Second
)

// retryWait is the wait before the next poll after a failed one: about a
// second after a transient relay error, as before. refused counts the
// polls in a row that the relay refused for a reason another poll will
// not change by itself (the mailbox is unknown to it, or the vault's
// clock is off): the wait then doubles each time, up to about 15 s. Not
// further: nothing but the next poll tells the vault that the mailbox is
// back or the clock right, and until then it is deaf. Every wait is
// spread by half either way.
func retryWait(refused int) time.Duration {
	d := retryBase
	if refused > 1 {
		d = min(retryBase<<min(refused-1, 16), retryMax)
	}
	return jitter(d, 0.5)
}

// sleep waits d; false if ctx ended first.
func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// Step collects one batch (blocking up to the long-poll wait) and processes
// it. It returns the number of messages collected.
func (m *Manager) Step(ctx context.Context) (int, error) {
	c, err := m.getCollector(ctx)
	if err != nil {
		return 0, err
	}
	msgs, err := c.Next(ctx)
	if err != nil {
		m.mu.Lock()
		if m.collector == c {
			_ = c.Close()
			m.collector = nil
		}
		m.mu.Unlock()
		return 0, err
	}
	return len(msgs), m.ProcessBatch(ctx, c, msgs)
}

func (m *Manager) getCollector(ctx context.Context) (Collector, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.locked {
		return nil, ErrLocked
	}
	if m.collector != nil {
		return m.collector, nil
	}
	var c Collector
	if cr, ok := m.relay.(*ClientRelay); ok && !m.opt.WebSocket && m.opt.PollWait > 0 {
		c = cr.NewPollCollector(m.opt.PollWait)
	} else {
		var err error
		if c, err = m.relay.Collector(ctx, m.opt.WebSocket); err != nil {
			return nil, err
		}
	}
	m.collector = c
	return c, nil
}

// HeldAnswerHoldBound is the longest the first batches after an unlock
// hold back the due held neutral answers (0.80.0): the hold ends at the
// first drain or this long after the unlock, whichever is first.
const HeldAnswerHoldBound = 60 * time.Second

// ProcessBatch handles one batch as §8.3 prescribes: for each message, in
// order, dedupe, decrypt, authorize, apply and record; then flush state;
// then ack; then deposit the outbox.
func (m *Manager) ProcessBatch(ctx context.Context, c Collector, msgs []Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.locked {
		return ErrLocked
	}
	now := m.now()
	m.refreshOwnerCred()
	// Held neutral answers that fell due while the vault was locked go out
	// only after the first mailbox drain after the unlock, so that a
	// withdraw collected in that drain still drops them (0.80.0, §10.4.1).
	m.holdAnswers = !m.drainedOnce && now.Sub(m.openedAt) < HeldAnswerHoldBound
	m.housekeeping(now)
	m.notifyUnlocked(now)
	var durable, ephemeral []string
	for _, msg := range msgs {
		switch m.handleMessage(ctx, msg, now) {
		case ackAfterFlush:
			durable = append(durable, msg.MsgID)
		case ackNow:
			ephemeral = append(ephemeral, msg.MsgID)
		case noAck:
			if m.st != nil {
				delete(m.st.SeenMsgIDs, msg.MsgID) // process it again on redelivery
			}
		}
		if m.locked {
			return ErrSplitBrain
		}
	}
	if len(msgs) < MaxBatch {
		m.attDrained()
		m.drainedOnce = true
	}
	if m.holdAnswers {
		m.holdAnswers = false
		if m.drainedOnce {
			m.sendHeldAnswers(now) // a bound that ended the hold sent them in housekeeping
		}
	}
	for _, id := range ephemeral {
		_ = c.Ack(ctx, id)
	}
	if len(msgs) > 0 || m.dirty {
		if err := m.persist(ctx, false); err != nil {
			m.alarms, m.appKeyChanged, m.nameReport = nil, false, nil
			return err
		}
	}
	m.reportAlarms()
	m.reportAppKey()
	if h := m.opt.Hooks.AfterFlush; h != nil {
		if err := h(); err != nil {
			m.zeroize()
			return ErrCrash
		}
	}
	for _, id := range durable {
		_ = c.Ack(ctx, id) // idempotent; a lost ack means redelivery, which dedupe absorbs
	}
	if m.deletePending {
		m.deletePending = false
		return m.finishDelete(ctx) // §12.5; the vault is locked afterwards
	}
	m.drainOutbox(ctx)
	if err := m.flushIfDirty(ctx); err != nil {
		return err
	}
	if m.lockPending {
		return m.lockLocked(ctx)
	}
	return nil
}

// handleMessage classifies one message only by its collect sender, its
// recipient_kid and the session that decrypts it (§13.6).
func (m *Manager) handleMessage(ctx context.Context, msg Message, now time.Time) disposition {
	if m.st.Deleting != nil {
		return ackAfterFlush // being deleted (§12.5): nothing more is handled
	}
	if _, seen := m.st.SeenMsgIDs[msg.MsgID]; seen {
		return ackAfterFlush // relay msg_id dedupe (§8.2 layer 1)
	}
	m.st.SeenMsgIDs[msg.MsgID] = now
	m.relayAt = time.Time{}
	if t, err := time.Parse(time.RFC3339Nano, msg.DepositedAt); err == nil {
		m.relayAt = t.UTC()
	}
	sender, ok := relayauth.DecodeKey(msg.Sender)
	if !ok {
		m.audit(now, "bad_sender", "")
		return ackAfterFlush
	}
	env, err := envelope.Parse(msg.Payload)
	if err != nil {
		m.audit(now, "bad_envelope", "")
		return ackAfterFlush
	}
	p := m.peerByRelayKey(sender)
	// §7.1 (0.10.3): a request token covers only the rest of a handshake
	// that awaits approval and connection.approved.
	if m.issuedKind(msg.JTI) == TokRequest {
		return m.handleOnRequestToken(ctx, env, msg.Payload, sender, p, now)
	}
	// §6.6 permitted use, decided by the collect jti (RELAY-PROTOCOL 0.4.0):
	// a connection's deposit on its reconnect token (or without a jti) may
	// only be a sealed hs.init with purpose reconnect, which is the only
	// message addressed to our static KEM key from a known connection that
	// handleInit accepts.
	if p != nil && p.Kind == KindConnection && m.reconnectClass(msg.JTI) {
		if env.Mode() != envelope.ModeSealed || m.lookupKEM(env.RecipientKid()) == nil {
			m.audit(now, "reconnect_token_misuse", p.ID)
			return ackAfterFlush
		}
		return m.handleInit(ctx, msg.Payload, sender, p, true, now)
	}
	if env.Mode() == envelope.ModeSealed {
		return m.handleSealed(ctx, env, msg.Payload, sender, p, now)
	}
	if p != nil {
		kr := m.sessions[p.ID]
		if kr != nil {
			in, ep, err := kr.Open(env, now)
			if err == nil {
				return m.dispatch(ctx, p, in, ep, msg.Payload, sender, now)
			}
			if !errors.Is(err, envelope.ErrKid) {
				m.audit(now, "decrypt_failed", p.ID)
				return ackAfterFlush
			}
		}
	}
	// Not an active epoch: perhaps hs.fin for a handshake awaiting it, or
	// a message under a request's epoch before activation (0.10.3).
	if id := m.awaitingByKids(env, sender); id != "" {
		return m.handleFin(ctx, id, msg.Payload, sender, now)
	}
	if id := m.requestByKids(env, sender); id != "" {
		return m.handleRequestMessage(id, env, now)
	}
	m.audit(now, "unknown_kid", peerID(p))
	return ackAfterFlush
}

func peerID(p *Peer) string {
	if p == nil {
		return ""
	}
	return p.ID
}

func (m *Manager) handleSealed(ctx context.Context, env *envelope.Envelope, raw []byte, sender ed25519.PublicKey, p *Peer, now time.Time) disposition {
	rk := env.RecipientKid()
	if m.lookupKEM(rk) != nil {
		return m.handleInit(ctx, raw, sender, p, false, now)
	}
	for id, og := range m.st.Outgoing {
		if kid, err := kidFrom(og.EphKid); err == nil && kid.Equal(rk) {
			return m.handleResp(ctx, id, raw, sender, now)
		}
	}
	m.audit(now, "unknown_kid", peerID(p))
	return ackAfterFlush
}

// lookupKEM returns the static KEM key (current or retired, §6.6) for kid.
func (m *Manager) lookupKEM(kid suite.Kid) *suite.PrivateKey {
	if kid.Equal(m.keys.kem.Public().Kid()) {
		return m.keys.kem
	}
	for _, r := range m.keys.retired {
		if kid.Equal(r.Public().Kid()) {
			return r
		}
	}
	return nil
}

func kidFrom(b []byte) (suite.Kid, error) {
	var k suite.Kid
	if len(b) != suite.KidSize {
		return k, ErrState
	}
	copy(k[:], b)
	return k, nil
}

func (m *Manager) peerByRelayKey(pk ed25519.PublicKey) *Peer {
	for _, p := range m.st.Devices {
		if suite.EqualPublic(p.Relay.PK, pk) {
			return p
		}
	}
	for _, p := range m.st.Connections {
		if suite.EqualPublic(p.Relay.PK, pk) {
			return p
		}
	}
	return nil
}

// dispatch handles a decrypted session-mode message from principal p.
func (m *Manager) dispatch(ctx context.Context, p *Peer, in *envelope.Inner, ep *handshake.Epoch, raw []byte, sender ed25519.PublicKey, now time.Time) disposition {
	if p.Kind == KindConnection && p.Fork != nil {
		// §6.6 (0.72.0): a connection suspended on fork evidence accepts
		// nothing, identity.rotate included.
		m.audit(now, "fork_suspended_drop", p.ID)
		return ackAfterFlush
	}
	if forkEvidence(p, ep, in.TS, now) {
		// §6.6 "Fork detection": authenticated traffic of a line a restore
		// replaced, later than the accepted reconnect: two copies of the
		// peer exist. Suspend; the message is not processed.
		m.suspendFork(p, now)
		return ackAfterFlush
	}
	if p.Kind == KindConnection && p.Conflict != nil && in.Type != "identity.rotate" {
		// Release R (§3.4): a connection with two successors of one key
		// is suspended; nothing is accepted from either.
		m.audit(now, "rotation_conflict_drop", p.ID)
		return ackAfterFlush
	}
	if in.Type == handshake.TypeInit {
		return m.handleRekeyInit(ctx, p, in, ep, raw, sender, now)
	}
	te := m.registry[in.Type]
	eph := te != nil && te.spec.Ephemeral
	if err := in.CheckTime(now, !eph); err != nil {
		m.audit(now, "stale_or_future", p.ID)
		return ackAfterFlush
	}
	if eph {
		if in.Exp.IsZero() {
			m.audit(now, "ephemeral_without_exp", p.ID)
			return ackNow
		}
		key := p.ID + "|" + in.ID
		if _, dup := m.ephemeralSeen[key]; dup {
			return ackNow
		}
		m.ephemeralSeen[key] = now
	}
	if !eph && p.Kind == KindConnection && !m.rateAllow(p.ID, now) {
		m.audit(now, "rate_limited", p.ID) // §7.3: acked, dropped, audited
		return ackAfterFlush
	}
	key := p.ID + "|" + in.ID
	// Volatile responses (§8.2) also to an agent whose grant covers the
	// type (LEASH decides below): an agent's answer is never cached either.
	volatile := te != nil && te.spec.Volatile && te.spec.Request && in.Re == "" && (te.allows(p.Kind) || p.Kind == KindAgent)
	if !eph {
		if _, dup := m.st.SeenInner[key]; dup {
			// §8.2 layer 2: a retransmission. Re-send a cached response, in a
			// new envelope; never re-execute. A volatile request is seen
			// only while it is held for an approval.
			if cr, ok := m.st.Responses[key]; ok {
				m.resendCached(p, cr.Inner)
			}
			return ackAfterFlush
		}
		if !volatile {
			m.st.SeenInner[key] = now
		}
	}
	// rkey is the key the answers below are cached under: none for a
	// volatile request, errors included (§8.2), so that no answer to its id
	// is ever resent from a cache.
	rkey := key
	if volatile {
		rkey = volatileKey
	}
	if !eph {
		p.LastActiveAt = now.UTC().Truncate(time.Minute) // listings (§10.3, §10.4)
	}
	if in.Re != "" {
		m.handleResponse(p, in, now)
		return disp(eph)
	}
	if p.Kind == KindConnection && m.gateConnection(p, in, te, rkey, now) {
		return disp(eph) // §6.4: a service's allow-list, the votes' kinds
	}
	if te == nil {
		m.respondError(p, in, rkey, "unsupported_type", "", now)
		return disp(eph)
	}
	if te.spec.Request {
		// §3.5.4 "Using a UTK" (0.52.0): the UTK the request presents is
		// spent before any other check, so every refusal below leaves it
		// spent too. A body without a readable utk_id spends nothing.
		m.spendPresented(p, in, now)
		defer m.endPresented()
	}
	if te.spec.Shape != nil && te.spec.Request && te.allows(p.Kind) && !te.spec.Shape(in.Body) {
		// A shape checked before the credential and the hold (§10.5.1
		// "Compatibility": message.attachment.get{} is bad_request whether
		// or not the vault is held).
		m.respondError(p, in, rkey, "bad_request", "", now)
		return disp(eph)
	}
	handled := false
	if in.Type == "message.send" {
		// §10.5.1: every refusal of a message.send that names a blob deletes
		// the blob, the refusals before its handler included.
		defer func() {
			if !handled {
				m.attRefusedSendBody(in.Body)
			}
		}()
	}
	// After the blob cleanup above: the refusal deletes a named blob too.
	if p.Kind != KindConnection && te.spec.Request && m.serviceDeviceRefused(in.Type, in.Body) {
		// §6.4: a request naming a service connection for a type it never
		// takes; nothing is sent.
		m.respondError(p, in, rkey, "forbidden", "", now)
		return disp(eph)
	}
	if !allowedWithoutCredential[in.Type] && !m.credentialReady() &&
		!(p.Recovering && recoveryAllowed[in.Type] && m.credentialExists()) {
		// §3.5.7: a vault without a credential is restricted; so is one
		// with a credential but no holder (§3.5.9, 0.52.0), which says so
		// in the body. Never during enrollment: no credential, no body.
		if te.spec.Request {
			var body json.RawMessage
			if m.credentialExists() {
				body = NoHolderBody
			}
			m.respondErrorBody(p, in, rkey, "credential_required", "", body, now)
		} else {
			m.audit(now, "credential_required", p.ID)
		}
		return disp(eph)
	}
	m.refreshOwnerCred()
	if p.Kind != KindConnection && !p.Recovering {
		// The daily owner check (§3.6.3): past the deadline the app, and
		// with the hold on every owner device, may send only the hold's
		// allow list. A recovering app keeps its own set (§11.11.5).
		if st := m.ownerCheckState(now); st != OwnerCheckOK && !m.holdAllows(p, in.Type, st) {
			if te.spec.Request {
				m.respondError(p, in, rkey, "owner_check_required", "", now)
			} else {
				m.audit(now, "owner_check", p.ID)
			}
			return disp(eph)
		}
	}
	s := &Session{m: m, peer: p, host: managerHost{m}, from: info(p), ctx: ctx, now: now, inner: in, relayAt: m.relayAt}
	allowed := te.allows(p.Kind) && !(p.Recovering && !recoveryAllowed[in.Type])
	if (p.Kind == KindAgent || p.Kind == KindDesktop) && !te.spec.DesktopApproval {
		if af, ok := te.handler.(AppOnlyForms); ok && af.AppOnly(in.Type, in.Body) {
			// A form only the app may send, whatever the sender's grants
			// (message.send with an attachment, §10.5.1).
			if te.spec.Request {
				m.respondError(p, in, rkey, "forbidden", "", now)
			} else {
				m.audit(now, "forbidden_type", p.ID)
			}
			return disp(eph)
		}
	}
	ask := false
	if p.Kind == KindAgent && m.hasAccess(p, now) && (!allowed || te.spec.AgentPolicy) {
		// LEASH hook (§6.8, §10.11): the agent's policy may allow an owner
		// type or refer it to the owner, and decides every agent.request;
		// app-only types never.
		switch m.agentDecision(s, te, in) {
		case AgentAllow:
			allowed = true
		case AgentAsk:
			allowed, ask = true, true
		default:
			allowed = false
		}
	}
	if !allowed {
		if te.spec.Request {
			m.respondError(p, in, rkey, "forbidden", "", now)
		} else {
			m.audit(now, "forbidden_type", p.ID)
		}
		return disp(eph)
	}
	if !accessExempt[in.Type] && !m.hasAccess(p, now) {
		// §6.8: a desktop or agent acts only within an access session.
		if te.spec.Request {
			m.respondError(p, in, rkey, "session_required", "", now)
		} else {
			m.audit(now, "session_required", p.ID)
		}
		return disp(eph)
	}
	if p.Kind == KindDesktop && te.spec.DesktopApproval {
		if af, ok := te.handler.(AppOnlyForms); ok && af.AppOnly(in.Type, in.Body) ||
			in.Type == "settings.set" && namesOwnerCheck(in.Body) { // §3.6.2, §3.6.7
			// A form only an app may send (§10.7, §10.12): refused at once,
			// never held for an approval it could not pass.
			m.respondError(p, in, rkey, "forbidden", "", now)
			return disp(eph)
		}
		// A read-only form (a dry run, §10.7 0.21.0) changes nothing: no
		// step-up.
		if rf, ok := te.handler.(ReadOnlyForms); !ok || !rf.ReadOnly(in.Type, in.Body) {
			ask = true
		}
	}
	if ask {
		if te.spec.Request && !eph {
			m.hold(p, in, key, volatile, now)
		} else {
			m.audit(now, "approval_required", p.ID)
		}
		return disp(eph)
	}
	handled = true
	m.replInHandler = false
	body, herr := te.handler.Handle(ctx, s, in)
	if herr != nil && !errors.Is(herr, ErrDeferred) {
		// Release R (§11.14.2): a handler that failed after step 1 of a
		// DEK replacement changes nothing more: the `next` part is dropped
		// (a generation it closed stays closed), and a transfer it
		// approved does not complete.
		if m.replInHandler {
			m.dropNext(now)
		}
		m.transferAfter = ""
		if t := m.st.Transfer; t != nil && t.State == TransferApproved {
			// The new phone's secret was spent by the approval: the transfer
			// ends and is started again (§11.14.10).
			m.abortTransfer("failed", now)
		}
	}
	m.replInHandler = false
	m.afterHandle(now)
	if te.spec.Request {
		var he *HandlerError
		switch {
		case errors.Is(herr, ErrDeferred) && volatile:
			// Answered later from memory (message.attachment.get, §10.5.1).
		case herr == nil:
			m.respond(p, in, rkey, body, now)
		case errors.As(herr, &he):
			m.respondErrorBody(p, in, rkey, he.Code, he.Message, he.Body, now)
		default:
			m.respondError(p, in, rkey, "internal", "", now)
		}
	}
	m.afterRespond(now)
	return disp(eph)
}

func disp(eph bool) disposition {
	if eph {
		return ackNow
	}
	return ackAfterFlush
}

// respond deposits a response to the requester only (§9.1), and caches it
// for 24 h (§8.2).
func (m *Manager) respond(p *Peer, req *envelope.Inner, key string, body json.RawMessage, now time.Time) {
	if body == nil {
		body = json.RawMessage(`{}`)
	}
	m.sendResponse(p, req, key, &envelope.Inner{Type: req.Type, Re: req.ID, Status: envelope.StatusOK, Body: body}, now)
}

// volatileKey is the response key of an answer to a volatile request
// (§8.2): every answer to it, an error too, is never cached and never in
// vault state (not in the outbox either); it is deposited from memory
// after the batch's flush, and lost if that deposit fails.
const volatileKey = ""

// ErrResponseTooLarge is the error code of a response that could not be
// sealed within §5.5's bound (§8.1, §10.1; 0.32.0).
const ErrResponseTooLarge = "response_too_large"

// tooLarge is the response_too_large answer that replaces out (§8.1): the
// same id, type and re, no body.
func tooLarge(out *envelope.Inner) *envelope.Inner {
	return &envelope.Inner{ID: out.ID, TS: out.TS, Type: out.Type, Re: out.Re, Status: envelope.StatusError,
		Error: &envelope.Error{Code: ErrResponseTooLarge}}
}

func (m *Manager) respondError(p *Peer, req *envelope.Inner, key, code, msg string, now time.Time) {
	m.respondErrorBody(p, req, key, code, msg, nil, now)
}

func (m *Manager) respondErrorBody(p *Peer, req *envelope.Inner, key, code, msg string, body json.RawMessage, now time.Time) {
	m.sendResponse(p, req, key, &envelope.Inner{Type: req.Type, Re: req.ID, Status: envelope.StatusError,
		Error: &envelope.Error{Code: code, Message: msg}, Body: body}, now)
}

func (m *Manager) sendResponse(p *Peer, req *envelope.Inner, key string, out *envelope.Inner, now time.Time) {
	if !envelope.ValidType(out.Type) {
		out.Type = "error"
	}
	id, err := envelope.NewULID(now)
	if err != nil {
		return
	}
	out.ID, out.TS = id, now
	// §8.1 (0.32.0): a response is never silence. One that cannot be
	// sealed within §5.5's bound is replaced by response_too_large, which
	// is cached and sent instead (sent only, for a volatile request).
	if !m.fits(out) {
		out = tooLarge(out)
	}
	if key == volatileKey {
		kr := m.sessions[p.ID]
		if kr == nil || kr.Current() == nil {
			return
		}
		raw, err := kr.Current().Seal(out)
		if err != nil {
			return
		}
		m.volatile = append(m.volatile, &OutboxEntry{ID: id, Op: OpDeposit, PeerID: p.ID, RelayURL: p.Relay.URL,
			Mailbox: p.Relay.Mailbox, Payload: raw, BestEffort: true, Created: now})
		return
	}
	if j, err := out.Marshal(envelope.ModeSealed); err == nil { // cached without seq
		m.st.Responses[key] = CachedResponse{Inner: j, Expires: now.Add(ResponseRetention)}
	}
	m.sealAndQueue(p, out)
}

// fits reports whether in, sealed in session mode, stays within §5.5's
// bound (its padded inner plaintext at most MaxPadded bytes). The seq is
// counted at its widest, so that a response which fits now also fits
// when it is sealed again for a retransmission.
func (m *Manager) fits(in *envelope.Inner) bool {
	c := *in
	c.Seq = strictjson.MaxSafeInteger
	j, err := c.Marshal(envelope.ModeSession)
	if err != nil {
		return true // not a size problem: sealing reports it as before
	}
	_, err = envelope.PaddedLen(len(j))
	return err == nil
}

func (m *Manager) resendCached(p *Peer, raw []byte) {
	in, err := envelope.ParseInner(raw, envelope.ModeSealed)
	if err != nil {
		return
	}
	if !m.fits(in) {
		in = tooLarge(in) // cached by a release before §8.1's rule
	}
	m.sealAndQueue(p, in)
}

// handleResponse matches a response to one of the vault's own requests.
func (m *Manager) handleResponse(p *Peer, in *envelope.Inner, now time.Time) {
	if p.Kind == KindConnection && m.attUnsupported(p, in, now) {
		return // a peer without release A answered our attachment's deliver (§10.5.1)
	}
	peer, ok := m.requests[in.Re]
	if !ok || peer != p.ID {
		if p.isService() {
			// §6.4: a response from a service that matches no request.
			m.record(Activity{Kind: auditServiceType, ConnectionID: p.ID, Ref: p.ID + " " + in.Type, Audit: true}, now)
		}
		return // §8.1: a response matching no pending request is dropped
	}
	delete(m.requests, in.Re)
	if in.Type == "relay.token.refresh" && in.Status == envelope.StatusOK {
		m.storeIssuedTo(p, in.Body, now)
	}
}

func (m *Manager) audit(now time.Time, event, peer string) {
	m.st.Audit = append(m.st.Audit, AuditEntry{At: now, Event: event, PeerID: peer})
	if k := auditKind(event); k != "" {
		a := Activity{Kind: k, Audit: true}
		if _, ok := m.st.Connections[peer]; ok {
			a.ConnectionID = peer
		} else if peer != "" {
			a.DeviceID = peer
		}
		m.record(a, now)
	}
	if n := len(m.st.Audit); n > AuditMax {
		m.st.Audit = append([]AuditEntry(nil), m.st.Audit[n-AuditMax:]...)
	}
}

// rateWindow counts durable messages per peer per minute (§7.3).
type rateWindow struct {
	start time.Time
	n     int
}

// PeerRateLimit is the durable-message limit per peer per minute (§7.3).
const PeerRateLimit = 60

func (m *Manager) rateAllow(peer string, now time.Time) bool {
	w := m.rates[peer]
	if w == nil || now.Sub(w.start) >= time.Minute {
		w = &rateWindow{start: now}
		m.rates[peer] = w
	}
	w.n++
	return w.n <= PeerRateLimit
}

// prune drops expired dedupe, response-cache and ephemeral entries.
func (m *Manager) prune() {
	now := m.now()
	for k, t := range m.st.SeenMsgIDs {
		if now.Sub(t) > DedupeRetention {
			delete(m.st.SeenMsgIDs, k)
		}
	}
	for k, t := range m.st.SeenInner {
		if now.Sub(t) > DedupeRetention {
			delete(m.st.SeenInner, k)
		}
	}
	for k, t := range m.st.SeenInit {
		if now.Sub(t) > InitMarkRetention { // §6.6 "Replay"
			delete(m.st.SeenInit, k)
		}
	}
	for k, r := range m.st.Responses {
		if now.After(r.Expires) {
			delete(m.st.Responses, k)
		}
	}
	for k, t := range m.ephemeralSeen {
		if now.Sub(t) > EphemeralDedupe {
			delete(m.ephemeralSeen, k)
		}
	}
	kept := m.st.Outbox[:0]
	for _, e := range m.st.Outbox {
		if !e.Done {
			kept = append(kept, e)
		}
	}
	m.st.Outbox = kept
	for _, kr := range m.sessions {
		kr.Prune(now)
	}
}
