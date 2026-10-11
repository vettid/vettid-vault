package vault

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/pushwire"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Push (VAULT-MESSAGING 0.24.0 §14): the holder registers its FCM or APNs
// token with push.register; the vault keeps the gateway's sealed wake
// blob, a fresh wake key and a hash of the token (never the token), and
// wakes the app through the gateway after the relay accepted certain
// deposits to it, debounced and capped (§14.2). A wake carries nothing of
// the vault's.

// PushGateway is the channel's push gateway (PUSH-GATEWAY 0.4.0 §5) as the
// vault calls it: one attempt per call. *pushwire.Client implements it.
// Gateway error answers are *pushwire.Error.
type PushGateway interface {
	Register(ctx context.Context, wakeKey ed25519.PrivateKey, r pushwire.Registration) (blob string, err error)
	Wake(ctx context.Context, wakeKey ed25519.PrivateKey, blob string) (reseal string, err error)
}

// TypePushTokenNeeded is the event that asks the app for a fresh token
// (§14.1, §14.2). The spec writes it push.token_needed, which §5.3's type
// grammar ([a-z][a-z0-9-]* segments) forbids; as with vault.owner-check
// (0.15.2) the vault sends the grammar's form (docs/V4-NOTES.md "Push").
const TypePushTokenNeeded = "push.token-needed"

// Push limits (§10.1, §14.1).
const (
	MaxPushRegistrations = 20
	PushRegistrationsWin = 24 * time.Hour
)

// Push results in the push state (§14.1).
const (
	PushSent         = "sent"
	PushRateLimited  = "rate_limited"
	PushGatewayError = "gateway_error"
)

// PushRegistration is the app's one push registration (§14.1) in DEK
// state. The token is never stored; WakeSeed is the wake key's Ed25519
// seed, made for this registration only (PUSH-GATEWAY §3).
type PushRegistration struct {
	DeviceID     string    `json:"device_id"`
	WakeSeed     []byte    `json:"wake_sk"`
	WakeBlob     string    `json:"wake_blob"`
	TokenHash    []byte    `json:"token_hash"`
	Platform     string    `json:"platform"`
	Environment  string    `json:"environment,omitempty"`
	AppID        string    `json:"app_id"`
	RegisteredAt time.Time `json:"registered_at"`
	State        string    `json:"state"`
	// LastWakeAt and LastResult change in memory and are written with the
	// next state flush (§14.1); not synced to other devices.
	LastWakeAt time.Time `json:"last_wake_at,omitzero"`
	LastResult string    `json:"last_result,omitempty"`
}

// stateJSON is the push state of §14.1.
func (r *PushRegistration) stateJSON() []byte {
	b := strictjson.NewBuilder().String("platform", r.Platform)
	if r.Environment != "" {
		b.String("environment", r.Environment)
	}
	b.String("app_id", r.AppID).String("state", r.State).String("registered_at", envelope.FormatTS(r.RegisteredAt))
	if !r.LastWakeAt.IsZero() {
		b.String("last_wake_at", envelope.FormatTS(r.LastWakeAt))
	}
	if r.LastResult != "" {
		b.String("last_result", r.LastResult)
	}
	return b.Bytes()
}

func (m *Manager) pushTiming() PushTiming {
	if m.opt.PushTiming != nil {
		return m.opt.PushTiming.withDefaults()
	}
	return DefaultPushTiming.withDefaults()
}

func (m *Manager) registerPush() {
	m.register(TypeSpec{Type: "push.register", Request: true, From: apps}, HandlerFunc(m.hPushRegister))
	m.register(TypeSpec{Type: "push.unregister", Request: true, From: apps}, HandlerFunc(m.hPushUnregister))
}

var errPushUnavailable = &HandlerError{Code: "unavailable"}

// hPushRegister is §14.1: the checks in order (each failure changing
// nothing), then a fresh wake key, the gateway's registration with the
// enclave's attestation, and the new registration in the batch's flush.
func (m *Manager) hPushRegister(ctx context.Context, s *Session, in *envelope.Inner) (json.RawMessage, error) {
	p := s.peer
	// 1. The holder only (the framework already refuses desktops, agents
	// and a recovering app).
	if p == nil || p.Kind != KindApp || p.Recovering {
		return nil, errForbiddenH
	}
	// 2. The body.
	r, err := pushwire.ParseRegistration(in.Body)
	if err != nil {
		return nil, errBadRequest
	}
	// 3. The release has a gateway.
	if m.opt.Push == nil {
		return nil, errPushUnavailable
	}
	// 4. Idempotence.
	th := r.TokenHash()
	if cur := m.st.Push; cur != nil && cur.DeviceID == p.ID && pushwire.EqualHash(cur.TokenHash, th[:]) {
		return strictjson.NewBuilder().Raw("push", cur.stateJSON()).Bytes(), nil
	}
	// 5. 20 registrations that reached the gateway in 24 hours.
	now := s.now
	m.prunePushRegs(now)
	if len(m.st.PushRegs) >= MaxPushRegistrations {
		return nil, LimitError("push_registrations", MaxPushRegistrations)
	}
	_, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, NewError("internal", "")
	}
	defer suite.Wipe(sk)
	rctx, cancel := context.WithTimeout(ctx, m.pushTiming().RegisterTimeout)
	blob, err := m.opt.Push.Register(rctx, sk, r)
	cancel()
	if pushwire.Answered(err) {
		// It reached the gateway: counted, whatever the answer, an
		// unparsable or oversized one included (§14.1 check 5, 0.24.1).
		m.st.PushRegs = append(m.st.PushRegs, now.UTC())
		m.dirty = true
	}
	if err != nil {
		return nil, pushRegisterError(err)
	}
	m.clearPush()
	m.pushGen++
	m.st.Push = &PushRegistration{DeviceID: p.ID, WakeSeed: append([]byte(nil), sk.Seed()...), WakeBlob: blob,
		TokenHash: append([]byte(nil), th[:]...), Platform: r.Platform, Environment: r.Environment, AppID: r.AppID,
		RegisteredAt: now.UTC().Truncate(time.Millisecond), State: "active"}
	m.dirty = true
	m.record(Activity{Kind: "push.registered", DeviceID: p.ID, Ref: r.Platform, Audit: true}, now)
	m.pushSync()
	return strictjson.NewBuilder().Raw("push", m.st.Push.stateJSON()).Bytes(), nil
}

// pushRegisterError maps a failed registration (§14.1): the gateway's
// 400 platform_invalid, app_invalid or token_invalid is bad_request with
// the code as message; everything else (403 attestation_invalid, 401, 429,
// 5xx, a timeout, no connection, an unreadable answer) is gateway_error,
// with retry_after from a 429 or 502.
func pushRegisterError(err error) error {
	var ge *pushwire.Error
	if errors.As(err, &ge) && ge.Status == 400 {
		switch ge.Code {
		case pushwire.CodePlatformInvalid, pushwire.CodeAppInvalid, pushwire.CodeTokenInvalid:
			return &HandlerError{Code: "bad_request", Message: ge.Code}
		}
	}
	b := strictjson.NewBuilder()
	if ge != nil && (ge.Status == 429 || ge.Status == 502) && ge.RetryAfter > 0 {
		b.Uint("retry_after", uint64(ge.RetryAfter))
	}
	return &HandlerError{Code: "gateway_error", Body: b.Bytes()}
}

func (m *Manager) prunePushRegs(now time.Time) {
	i := 0
	for i < len(m.st.PushRegs) && now.Sub(m.st.PushRegs[i]) >= PushRegistrationsWin {
		i++
	}
	if i > 0 {
		m.st.PushRegs = append([]time.Time(nil), m.st.PushRegs[i:]...)
		m.dirty = true
	}
}

// hPushUnregister erases the registration in one flush (§14.1); without
// one it answers {} and writes nothing. No gateway call.
func (m *Manager) hPushUnregister(_ context.Context, s *Session, in *envelope.Inner) (json.RawMessage, error) {
	o, err := obj(in)
	if err != nil || len(o) != 0 {
		return nil, errBadRequest
	}
	if cur := m.st.Push; cur != nil && cur.DeviceID == s.from.ID {
		m.erasePush("app", s.now)
	}
	return json.RawMessage(`{}`), nil
}

// erasePush erases the registration (its wake key and blob) and audits
// push.unregistered with ref app, transferred or replaced (§14.1, §10.9).
func (m *Manager) erasePush(ref string, now time.Time) {
	cur := m.st.Push
	if cur == nil {
		return
	}
	dev := cur.DeviceID
	m.clearPush()
	m.record(Activity{Kind: "push.unregistered", DeviceID: dev, Ref: ref, Audit: true}, now)
}

// clearPush wipes and drops the registration and stops its wakes.
func (m *Manager) clearPush() {
	if cur := m.st.Push; cur != nil {
		suite.Wipe(cur.WakeSeed)
		m.st.Push = nil
		m.pushGen++
		m.dirty = true
	}
	if m.push != nil {
		m.push.setReg(nil)
	}
}

// pushRemoved erases the registration of an app that a transfer or a
// recovery removed (§6.7.1, §11.11.5): ref transferred or replaced.
func (m *Manager) pushRemoved(deviceID, reason string, now time.Time) {
	if cur := m.st.Push; cur != nil && cur.DeviceID == deviceID {
		m.erasePush(reason, now)
	}
}

// pushSync gives the wake loop the current registration (none, a new one,
// or a resealed blob). The loop starts with the first registration.
func (m *Manager) pushSync() {
	if m.opt.Push == nil || m.st == nil || m.locked {
		return
	}
	cur := m.st.Push
	if cur == nil {
		if m.push != nil {
			m.push.setReg(nil)
		}
		return
	}
	if m.push == nil {
		m.push = newPusher(m.opt.Push, m.pushTiming(), m.now, m.pushOutcome)
	}
	m.push.setReg(&pushReg{gen: m.pushGen, key: ed25519.NewKeyFromSeed(cur.WakeSeed), blob: cur.WakeBlob})
}

// Wake classes of an outbox deposit (OutboxEntry.Wake).
const (
	wakeNormal = "n"
	wakeExempt = "x" // skips the hourly cap (§14.2)
)

// wakeClass is the §14.2 trigger class of a durable message to owner
// device p ("" for none): a new feed item of priority normal, high or
// urgent that is not a guide (urgent: exempt), vault.held, and
// credential.alarm (exempt). Only the registered app is woken.
func (m *Manager) wakeClass(p *Peer, typ string, body json.RawMessage) string {
	cur := m.st.Push
	if cur == nil || p.Kind != KindApp || p.ID != cur.DeviceID {
		return ""
	}
	switch typ {
	case "vault.held":
		return wakeNormal
	case "credential.alarm":
		return wakeExempt
	case "feed.event":
		o, err := strictjson.ParseObject(body)
		if err != nil {
			return ""
		}
		kind, _ := o.String("kind")
		pr, _ := o.String("priority")
		if kind == "guide" {
			return ""
		}
		switch pr {
		case "urgent":
			return wakeExempt
		case "normal", "high":
			return wakeNormal
		}
	}
	return ""
}

// pushDeposited is called once the relay accepted a deposit marked with
// a wake class (§14.2: wakes follow accepted deposits only).
func (m *Manager) pushDeposited(peerID, class string) {
	cur := m.st.Push
	if class == "" || cur == nil || cur.DeviceID != peerID {
		return
	}
	if m.push == nil {
		m.pushSync()
	}
	if m.push != nil {
		m.push.trigger(class == wakeExempt)
	}
}

// pushLockWake wakes the app after vault.locking reached its mailbox,
// unless the app itself asked for the lock: one attempt, at most
// LockBudget, before the vault zeroizes (§14.2 trigger 3).
func (m *Manager) pushLockWake(deposited map[string]bool) {
	cur := m.st.Push
	if cur == nil || !deposited[cur.DeviceID] || m.lockReason == "" && m.lockBy == cur.DeviceID {
		return
	}
	if m.push == nil {
		m.pushSync()
	}
	if m.push != nil {
		m.push.lockWake(m.pushTiming().LockBudget)
	}
}

// pushOutcome applies a wake's outcome to the registration (§14.2): sent
// and a reseal (written at the next flush), rate_limited, gateway_error,
// or a dead token: the registration erased, push.token_gone audited and
// push.token-needed{reason} deposited to the app, in one flush.
func (m *Manager) pushOutcome(o pushOutcome) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.locked || m.st == nil || m.st.Push == nil || o.gen != m.pushGen {
		return
	}
	cur := m.st.Push
	switch o.result {
	case wakeSent:
		cur.LastWakeAt, cur.LastResult = o.at.UTC().Truncate(time.Millisecond), PushSent
		if o.reseal != "" && o.reseal != cur.WakeBlob {
			cur.WakeBlob = o.reseal
			m.dirty = true
		}
	case wakeRateLimited:
		cur.LastResult = PushRateLimited
	case wakeFailed:
		cur.LastResult = PushGatewayError
	case wakeGone:
		dev := cur.DeviceID
		now := m.now()
		m.clearPush()
		m.record(Activity{Kind: "push.token_gone", DeviceID: dev, Ref: o.code, Audit: true}, now)
		if p := m.st.Devices[dev]; p != nil && p.State == PeerActive {
			m.sendTo(p, TypePushTokenNeeded, strictjson.NewBuilder().String("reason", o.code).Bytes(), now)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if err := m.persist(ctx, false); err != nil {
			return
		}
		m.drainOutbox(ctx)
		_ = m.flushIfDirty(ctx)
	}
}

// devicesJSON is device.list's answer: the devices, with the push state
// on the registered app's entry (§10.3, 0.24.0).
func (m *Manager) devicesJSON(now time.Time) json.RawMessage {
	ids := make([]string, 0, len(m.st.Devices))
	for id := range m.st.Devices {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	arr := []byte{'['}
	for i, id := range ids {
		if i > 0 {
			arr = append(arr, ',')
		}
		p := m.st.Devices[id]
		e := peerJSON(p, now)
		if cur := m.st.Push; cur != nil && cur.DeviceID == p.ID && p.Kind == KindApp {
			e = append(append(append(e[:len(e)-1], `,"push":`...), cur.stateJSON()...), '}')
		}
		if sg := m.signerJSON(p); sg != nil {
			// 0.27.0 (§10.3, §11.7.1): the vault's signer binding, on
			// the app's entry only.
			e = append(append(append(e[:len(e)-1], `,"signer":`...), sg...), '}')
		}
		arr = append(arr, e...)
	}
	arr = append(arr, ']')
	return strictjson.NewBuilder().Raw("devices", arr).Bytes()
}

// --- the wake loop ---

type pushReg struct {
	gen  uint64
	key  ed25519.PrivateKey
	blob string
}

type pushOutcome struct {
	gen    uint64
	result wakeResult
	code   string // wakeGone: the gateway's code
	reseal string
	at     time.Time
}

// pusher sends one registration's wakes from its own goroutine, so that
// a slow gateway never holds up a batch. It holds a copy of the wake key
// while the vault is unlocked; stop wipes it. Outcomes go to the manager
// through a second goroutine, so the loop never waits for the manager's
// lock (which a lock holds while it waits for the lock wake).
type pusher struct {
	gw    PushGateway
	t     PushTiming
	now   func() time.Time
	apply func(pushOutcome)

	mu       sync.Mutex
	s        wakeSched
	reg      *pushReg
	stopped  bool
	cancel   context.CancelFunc
	final    chan struct{} // a lock wake waits on it
	finalBy  time.Time
	kick     chan struct{}
	stopCh   chan struct{}
	outcomes chan pushOutcome
}

func newPusher(gw PushGateway, t PushTiming, now func() time.Time, apply func(pushOutcome)) *pusher {
	p := &pusher{gw: gw, t: t, now: now, apply: apply, s: newWakeSched(t), kick: make(chan struct{}, 1),
		stopCh: make(chan struct{}), outcomes: make(chan pushOutcome, 16)}
	go p.run()
	go p.applier()
	return p
}

func (p *pusher) poke() {
	select {
	case p.kick <- struct{}{}:
	default:
	}
}

// setReg replaces the registration (nil: none). A new registration starts
// with fresh limits; the same one with a new blob keeps them.
func (p *pusher) setReg(r *pushReg) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.stopped {
		if r != nil {
			suite.Wipe(r.key)
		}
		return
	}
	if p.reg != nil && r != nil && p.reg.gen == r.gen {
		suite.Wipe(r.key)
		p.reg.blob = r.blob
		return
	}
	if p.reg != nil {
		suite.Wipe(p.reg.key)
	}
	p.reg = r
	p.s = newWakeSched(p.t)
	p.poke()
}

func (p *pusher) trigger(exempt bool) {
	p.mu.Lock()
	if p.reg != nil && !p.stopped {
		p.s.trigger(exempt)
	}
	p.mu.Unlock()
	p.poke()
}

// lockWake triggers an exempt wake and waits at most budget for it to be
// sent (the debounce and caps still apply; a wake that could not go out
// within the budget is not sent).
func (p *pusher) lockWake(budget time.Duration) {
	p.mu.Lock()
	if p.reg == nil || p.stopped {
		p.mu.Unlock()
		return
	}
	p.s.trigger(true)
	done := make(chan struct{})
	p.final, p.finalBy = done, p.now().Add(budget)
	p.mu.Unlock()
	p.poke()
	t := time.NewTimer(budget)
	defer t.Stop()
	select {
	case <-done:
	case <-t.C:
	}
	p.mu.Lock()
	if p.final == done {
		p.final = nil
	}
	p.mu.Unlock()
}

// stop ends the loop and wipes the key; it never blocks (the manager
// holds its lock).
func (p *pusher) stop() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.stopped {
		return
	}
	p.stopped = true
	close(p.stopCh)
	if p.cancel != nil {
		p.cancel()
	}
	if p.reg != nil {
		suite.Wipe(p.reg.key)
		p.reg = nil
	}
}

func (p *pusher) endFinal() {
	if p.final != nil {
		close(p.final)
		p.final = nil
	}
}

func (p *pusher) run() {
	for {
		p.mu.Lock()
		if p.stopped {
			p.mu.Unlock()
			return
		}
		now := p.now()
		wait := time.Duration(-1)
		send := false
		if p.reg == nil {
			p.endFinal()
		} else if at, ok := p.s.next(now); ok {
			switch {
			case p.final != nil && at.After(p.finalBy):
				p.endFinal() // cannot go out within the lock's budget
				wait = at.Sub(now)
			case !at.After(now):
				send = true
			default:
				wait = at.Sub(now)
			}
		} else if p.final != nil && !p.s.inflight && !p.s.pending {
			p.endFinal()
		}
		if !send {
			p.mu.Unlock()
			var t *time.Timer
			var tc <-chan time.Time
			if wait >= 0 {
				t = time.NewTimer(wait)
				tc = t.C
			}
			select {
			case <-p.stopCh:
			case <-p.kick:
			case <-tc:
			}
			if t != nil {
				t.Stop()
			}
			continue
		}
		gen, blob := p.reg.gen, p.reg.blob
		key := append(ed25519.PrivateKey(nil), p.reg.key...)
		final := p.final != nil
		timeout := p.t.WakeTimeout
		if final {
			timeout = max(p.finalBy.Sub(now), time.Millisecond)
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		p.cancel = cancel
		p.s.start(now)
		p.mu.Unlock()

		reseal, err := p.gw.Wake(ctx, key, blob)
		cancel()
		suite.Wipe(key)

		o := pushOutcome{gen: gen, reseal: reseal, at: now}
		var ge *pushwire.Error
		var retryAfter time.Duration
		switch {
		case err == nil:
			o.result = wakeSent
		case errors.As(err, &ge) && ge.Gone():
			o.result, o.code = wakeGone, ge.Code
		case errors.As(err, &ge) && ge.Status == 429:
			o.result, retryAfter = wakeRateLimited, time.Duration(ge.RetryAfter)*time.Second
		default:
			o.result = wakeFailed
		}
		p.mu.Lock()
		p.cancel = nil
		if p.stopped {
			p.mu.Unlock()
			return
		}
		if p.reg != nil && p.reg.gen == gen {
			p.s.done(p.now(), o.result, retryAfter)
			if o.result == wakeGone {
				suite.Wipe(p.reg.key)
				p.reg = nil
			} else if reseal != "" {
				p.reg.blob = reseal
			}
		}
		if final {
			p.endFinal()
		}
		p.mu.Unlock()
		if o.result == wakeGone {
			select { // must reach the manager: the app needs push.token-needed
			case p.outcomes <- o:
			case <-p.stopCh:
				return
			}
			continue
		}
		select {
		case p.outcomes <- o:
		default: // the manager is behind; last_result is advisory
		}
	}
}

func (p *pusher) applier() {
	for {
		select {
		case <-p.stopCh:
			return
		case o := <-p.outcomes:
			p.apply(o)
		}
	}
}
