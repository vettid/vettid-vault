package vault

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"time"

	"github.com/vettid/vettid-relay/relayauth"

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
		return nil
	}
	m.started = true
	now := m.now()
	m.remintIssued(now)
	m.reconnectExpired(now)
	for _, p := range m.st.Devices {
		if p.State == PeerActive {
			m.startRekey(p, now) // device sessions rekey on every unlock (§6.5)
		}
	}
	if err := m.persist(ctx, false); err != nil {
		return err
	}
	m.drainOutbox(ctx)
	return m.flushIfDirty(ctx)
}

// Run collects and processes batches until ctx ends or the vault locks.
func (m *Manager) Run(ctx context.Context) error {
	if err := m.Start(ctx); err != nil {
		return err
	}
	for {
		if _, err := m.Step(ctx); err != nil {
			if errors.Is(err, ErrLocked) || errors.Is(err, ErrSplitBrain) || errors.Is(err, ErrCrash) || ctx.Err() != nil {
				return err
			}
			select { // transient relay error: back off a little
			case <-time.After(time.Second):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
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
	m.housekeeping(now)
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
	for _, id := range ephemeral {
		_ = c.Ack(ctx, id)
	}
	if len(msgs) > 0 || m.dirty {
		if err := m.persist(ctx, false); err != nil {
			return err
		}
	}
	if h := m.opt.Hooks.AfterFlush; h != nil {
		if err := h(); err != nil {
			m.zeroize()
			return ErrCrash
		}
	}
	for _, id := range durable {
		_ = c.Ack(ctx, id) // idempotent; a lost ack means redelivery, which dedupe absorbs
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
	if _, seen := m.st.SeenMsgIDs[msg.MsgID]; seen {
		return ackAfterFlush // relay msg_id dedupe (§8.2 layer 1)
	}
	m.st.SeenMsgIDs[msg.MsgID] = now
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
	// Not an active epoch: perhaps hs.fin for a handshake awaiting it.
	if id := m.awaitingByKids(env, sender); id != "" {
		return m.handleFin(ctx, id, msg.Payload, sender, now)
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
		return m.handleInit(ctx, raw, sender, p, now)
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
	if in.Type == handshake.TypeInit {
		return m.handleRekeyInit(ctx, p, in, ep, raw, sender, now)
	}
	// §6.6 permitted use: a connection holding no live standing token from
	// us can only have deposited on its reconnect token, which carries
	// nothing but a sealed reconnect hs.init.
	if p.Kind == KindConnection && !m.hasLiveIssued(p.ID, TokStanding, now) {
		m.audit(now, "reconnect_token_misuse", p.ID)
		return ackAfterFlush
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
	if !eph {
		if _, dup := m.st.SeenInner[key]; dup {
			// §8.2 layer 2: a retransmission. Re-send a cached response, in a
			// new envelope; never re-execute.
			if cr, ok := m.st.Responses[key]; ok {
				m.resendCached(p, cr.Inner)
			}
			return ackAfterFlush
		}
		m.st.SeenInner[key] = now
	}
	if in.Re != "" {
		m.handleResponse(p, in, now)
		return disp(eph)
	}
	if te == nil {
		m.respondError(p, in, key, "unsupported_type", "", now)
		return disp(eph)
	}
	if !te.allows(p.Kind) {
		if te.spec.Request {
			m.respondError(p, in, key, "forbidden", "", now)
		} else {
			m.audit(now, "forbidden_type", p.ID)
		}
		return disp(eph)
	}
	s := &Session{m: m, peer: p, ctx: ctx, now: now, inner: in}
	body, herr := te.handler.Handle(ctx, s, in)
	if te.spec.Request {
		var he *HandlerError
		switch {
		case herr == nil:
			m.respond(p, in, key, body, now)
		case errors.As(herr, &he):
			m.respondError(p, in, key, he.Code, he.Message, now)
		default:
			m.respondError(p, in, key, "internal", "", now)
		}
	}
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

func (m *Manager) respondError(p *Peer, req *envelope.Inner, key, code, msg string, now time.Time) {
	m.sendResponse(p, req, key, &envelope.Inner{Type: req.Type, Re: req.ID, Status: envelope.StatusError,
		Error: &envelope.Error{Code: code, Message: msg}}, now)
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
	if j, err := out.Marshal(envelope.ModeSealed); err == nil { // cached without seq
		m.st.Responses[key] = CachedResponse{Inner: j, Expires: now.Add(ResponseRetention)}
	}
	m.sealAndQueue(p, out)
}

func (m *Manager) resendCached(p *Peer, raw []byte) {
	in, err := envelope.ParseInner(raw, envelope.ModeSealed)
	if err != nil {
		return
	}
	m.sealAndQueue(p, in)
}

// handleResponse matches a response to one of the vault's own requests.
func (m *Manager) handleResponse(p *Peer, in *envelope.Inner, now time.Time) {
	peer, ok := m.requests[in.Re]
	if !ok || peer != p.ID {
		return // §8.1: a response matching no pending request is dropped
	}
	delete(m.requests, in.Re)
	if in.Type == "relay.token.refresh" && in.Status == envelope.StatusOK {
		m.storeIssuedTo(p, in.Body, now)
	}
}

func (m *Manager) audit(now time.Time, event, peer string) {
	m.st.Audit = append(m.st.Audit, AuditEntry{At: now, Event: event, PeerID: peer})
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
