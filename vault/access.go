package vault

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// Access sessions and approvals for desktops and agents (VAULT-MESSAGING
// §6.8, §10.3). An access session is an owner app's time-limited
// authorization for a paired desktop or agent to act; it is not the E2E
// session of §6.1. Within it, a desktop's requests of step-up types
// (TypeSpec.DesktopApproval) and an agent's requests that its policy
// (AgentPolicy, LEASH) refers to the owner are held until an app approves
// each one.
const (
	DefaultAccessSeconds = 3600
	MinAccessSeconds     = 60
	MaxAccessSeconds     = 24 * 3600
	AccessRequestTTL     = 10 * time.Minute
	ApprovalTTL          = 5 * time.Minute
	MaxHeldPerDevice     = 8
)

// accessExempt are the types a desktop or agent may send without an
// access session (§6.8).
var accessExempt = map[string]bool{"vault.status": true, "device.session.request": true, "device.session.end": true,
	tokenIssuedType: true, tokenRefreshType: true, "relay.address.update": true}

// needsAccess reports whether a principal kind needs an access session.
func needsAccess(kind string) bool { return kind == KindDesktop || kind == KindAgent }

// hasAccess reports whether p may act now.
func (m *Manager) hasAccess(p *Peer, now time.Time) bool {
	return !needsAccess(p.Kind) || p.Access != nil && now.Before(p.Access.Expires)
}

func accessSeconds(o strictjson.Object, name string) (uint64, bool, error) {
	v, present, err := o.OptUint(name, MinAccessSeconds, MaxAccessSeconds)
	if err != nil {
		return 0, false, errBadRequest
	}
	if !present {
		v = DefaultAccessSeconds
	}
	return v, present, nil
}

func (m *Manager) registerAccess() {
	r := func(t string, from []string, h HandlerFunc) {
		m.register(TypeSpec{Type: t, Request: true, From: from}, h)
	}
	r("device.session.request", []string{KindDesktop, KindAgent}, m.hSessionRequest)
	r("device.session.approve", apps, m.hSessionApprove)
	r("device.session.deny", apps, m.hSessionDeny)
	r("device.session.end", devices, m.hSessionEnd)
	r("approval.decide", apps, m.hApprovalDecide)
}

// hSessionRequest: a desktop or agent asks for an access session (or an
// extension); the apps are asked.
func (m *Manager) hSessionRequest(_ context.Context, s *Session, in *envelope.Inner) (json.RawMessage, error) {
	o, err := obj(in)
	if err != nil {
		return nil, err
	}
	secs, _, err := accessSeconds(o, "seconds")
	if err != nil {
		return nil, err
	}
	for id, r := range m.st.AccessRequests {
		if r.DeviceID == s.peer.ID {
			delete(m.st.AccessRequests, id) // the newest request replaces an older one
		}
	}
	r := &AccessRequest{ID: m.newID(s.now), DeviceID: s.peer.ID, Seconds: secs, Created: s.now, Expires: s.now.Add(AccessRequestTTL)}
	m.st.AccessRequests[r.ID] = r
	exp := envelope.FormatTS(r.Expires)
	m.notifyApps("device.session.pending", strictjson.NewBuilder().String("request_id", r.ID).String("device_id", s.peer.ID).
		String("role", s.peer.Kind).String("name", s.peer.Name).Uint("seconds", secs).String("exp", exp).Bytes(), s.now)
	m.record(Activity{Kind: "device.session.pending", DeviceID: s.peer.ID, Ref: r.ID, Feed: true, Priority: "high"}, s.now)
	m.dirty = true
	return strictjson.NewBuilder().String("request_id", r.ID).String("exp", exp).Bytes(), nil
}

// grantAccess starts or extends p's access session.
func (m *Manager) grantAccess(p *Peer, secs uint64, by string, now time.Time) {
	p.Access = &AccessSession{ID: m.newID(now), Expires: now.Add(time.Duration(secs) * time.Second).UTC().Truncate(time.Millisecond), GrantedBy: by}
	m.dirty = true
}

func (m *Manager) hSessionApprove(_ context.Context, s *Session, in *envelope.Inner) (json.RawMessage, error) {
	o, err := obj(in)
	if err != nil {
		return nil, err
	}
	rid, err := str(o, "request_id")
	if err != nil {
		return nil, err
	}
	r := m.st.AccessRequests[rid]
	if r == nil || !s.now.Before(r.Expires) {
		return nil, errNotFound
	}
	secs, present, err := accessSeconds(o, "seconds")
	if err != nil {
		return nil, err
	}
	if !present {
		secs = r.Seconds
	}
	p := m.st.Devices[r.DeviceID]
	delete(m.st.AccessRequests, rid)
	if p == nil || p.State != PeerActive {
		return nil, errNotFound
	}
	m.grantAccess(p, secs, s.peer.ID, s.now)
	exp := envelope.FormatTS(p.Access.Expires)
	m.sendTo(p, "device.session.granted", strictjson.NewBuilder().String("session_id", p.Access.ID).String("expires_at", exp).Bytes(), s.now)
	m.record(Activity{Kind: "device.session.granted", DeviceID: p.ID, Ref: p.Access.ID, Audit: true}, s.now)
	m.notifyDevices("sync.event", strictjson.NewBuilder().String("kind", "device.session").String("device_id", p.ID).
		String("expires_at", exp).Bytes(), s.peer.ID, s.now)
	return strictjson.NewBuilder().String("device_id", p.ID).String("session_id", p.Access.ID).String("expires_at", exp).Bytes(), nil
}

func (m *Manager) hSessionDeny(_ context.Context, s *Session, in *envelope.Inner) (json.RawMessage, error) {
	o, err := obj(in)
	if err != nil {
		return nil, err
	}
	rid, err := str(o, "request_id")
	if err != nil {
		return nil, err
	}
	r := m.st.AccessRequests[rid]
	if r == nil {
		return nil, errNotFound
	}
	delete(m.st.AccessRequests, rid)
	if p := m.st.Devices[r.DeviceID]; p != nil && p.State == PeerActive {
		m.sendTo(p, "device.session.ended", strictjson.NewBuilder().String("reason", "denied").Bytes(), s.now)
	}
	m.dirty = true
	return nil, nil
}

// hSessionEnd ends an access session: an app names the device, a desktop
// or agent ends its own. Requests it has held for approval are answered
// `denied`.
func (m *Manager) hSessionEnd(ctx context.Context, s *Session, in *envelope.Inner) (json.RawMessage, error) {
	o, err := obj(in)
	if err != nil {
		return nil, err
	}
	target := s.peer
	if s.peer.Kind == KindApp {
		id, err := str(o, "device_id")
		if err != nil {
			return nil, err
		}
		if target = m.st.Devices[id]; target == nil || !needsAccess(target.Kind) {
			return nil, errNotFound
		}
	}
	m.endAccess(ctx, target, s.peer.ID != target.ID, "ended", s.now)
	m.record(Activity{Kind: "device.session.ended", DeviceID: target.ID, Audit: true}, s.now)
	return nil, nil
}

// endAccess ends p's access session, drops its pending request and answers
// its held requests (notify: tell p).
func (m *Manager) endAccess(ctx context.Context, p *Peer, notify bool, reason string, now time.Time) {
	had := p.Access != nil
	p.Access = nil
	for id, r := range m.st.AccessRequests {
		if r.DeviceID == p.ID {
			delete(m.st.AccessRequests, id)
		}
	}
	for id, h := range m.st.Held {
		if h.DeviceID == p.ID {
			m.answerHeld(h, "denied", now)
			delete(m.st.Held, id)
		}
	}
	m.dirty = true
	if notify && p.State == PeerActive {
		m.sendTo(p, "device.session.ended", strictjson.NewBuilder().String("reason", reason).Bytes(), now)
	}
	if had {
		m.notifyDevices("sync.event", strictjson.NewBuilder().String("kind", "device.session").String("device_id", p.ID).Bytes(), "", now)
	}
}

// hold keeps a request for an owner app's approval (§6.8).
func (m *Manager) hold(p *Peer, in *envelope.Inner, key string, now time.Time) {
	n := 0
	for _, h := range m.st.Held {
		if h.DeviceID == p.ID {
			n++
		}
	}
	if n >= MaxHeldPerDevice {
		m.respondError(p, in, key, "limit", "", now)
		return
	}
	c := *in
	c.Seq = 0 // kept without the session's seq, like cached responses
	raw, err := c.Marshal(envelope.ModeSealed)
	if err != nil {
		m.respondError(p, in, key, "internal", "", now)
		return
	}
	h := &HeldRequest{ID: m.newID(now), DeviceID: p.ID, Key: key, Inner: raw, Created: now, Expires: now.Add(ApprovalTTL)}
	m.st.Held[h.ID] = h
	exp := envelope.FormatTS(h.Expires)
	m.notifyApps("approval.pending", strictjson.NewBuilder().String("approval_id", h.ID).String("device_id", p.ID).
		String("role", p.Kind).String("name", p.Name).String("type", in.Type).Raw("body", in.Body).String("exp", exp).Bytes(), now)
	m.sendTo(p, "approval.waiting", strictjson.NewBuilder().String("approval_id", h.ID).String("request_id", in.ID).
		String("exp", exp).Bytes(), now)
	m.record(Activity{Kind: "approval.pending", DeviceID: p.ID, Ref: h.ID, Feed: true, Priority: "high"}, now)
	m.dirty = true
}

// answerHeld sends the held request's requester an error response.
func (m *Manager) answerHeld(h *HeldRequest, code string, now time.Time) {
	p := m.st.Devices[h.DeviceID]
	in, err := envelope.ParseInner(h.Inner, envelope.ModeSealed)
	if p == nil || err != nil {
		return
	}
	m.respondError(p, in, h.Key, code, "", now)
}

// hApprovalDecide: an app approves or denies a held request. An approved
// request is executed as its sender's, now, and answered to it.
func (m *Manager) hApprovalDecide(ctx context.Context, s *Session, in *envelope.Inner) (json.RawMessage, error) {
	o, err := obj(in)
	if err != nil {
		return nil, err
	}
	aid, err := str(o, "approval_id")
	if err != nil {
		return nil, err
	}
	approve, err := o.Bool("approve")
	if err != nil {
		return nil, errBadRequest
	}
	h := m.st.Held[aid]
	if h == nil || !s.now.Before(h.Expires) {
		return nil, errNotFound
	}
	delete(m.st.Held, aid)
	m.dirty = true
	m.notifyDevices("sync.event", strictjson.NewBuilder().String("kind", "approval.decided").String("approval_id", aid).
		Bool("approved", approve).Bytes(), s.peer.ID, s.now)
	result := "denied"
	if !approve {
		m.answerHeld(h, "denied", s.now)
		m.record(Activity{Kind: "approval.denied", DeviceID: h.DeviceID, Ref: aid, Audit: true}, s.now)
	} else {
		m.record(Activity{Kind: "approval.granted", DeviceID: h.DeviceID, Ref: aid, Audit: true}, s.now)
		result = m.runHeld(ctx, h, s.now)
	}
	return strictjson.NewBuilder().String("result", result).Bytes(), nil
}

// runHeld executes an approved request as its sender and answers it. It
// returns "ok" or the error code sent.
func (m *Manager) runHeld(ctx context.Context, h *HeldRequest, now time.Time) string {
	p := m.st.Devices[h.DeviceID]
	in, err := envelope.ParseInner(h.Inner, envelope.ModeSealed)
	if p == nil || p.State != PeerActive || err != nil {
		return "not_found"
	}
	code := ""
	te := m.registry[in.Type]
	switch {
	case te == nil:
		code = "unsupported_type"
	case !m.hasAccess(p, now):
		code = "session_required"
	case !m.credentialReady():
		code = "credential_required"
	}
	s := &Session{m: m, peer: p, host: managerHost{m}, from: info(p), ctx: ctx, now: now, inner: in}
	if code == "" && p.Kind == KindAgent && (te.spec.AgentPolicy || !te.allows(KindAgent)) && m.agentDecision(s, te, in) == AgentDeny {
		code = "forbidden" // no grant covers it any more (§6.8, §10.11)
	}
	if code != "" {
		m.respondError(p, in, h.Key, code, "", now)
		return code
	}
	body, herr := te.handler.Handle(ctx, s, in)
	var he *HandlerError
	switch {
	case herr == nil:
		m.respond(p, in, h.Key, body, now)
		return "ok"
	case errors.As(herr, &he):
		m.respondError(p, in, h.Key, he.Code, he.Message, now)
		return he.Code
	default:
		m.respondError(p, in, h.Key, "internal", "", now)
		return "internal"
	}
}

// expireAccess drops expired access requests and answers expired held
// requests `approval_timeout` (housekeeping).
func (m *Manager) expireAccess(now time.Time) {
	for id, r := range m.st.AccessRequests {
		if !now.Before(r.Expires) {
			delete(m.st.AccessRequests, id)
			m.dirty = true
		}
	}
	for id, h := range m.st.Held {
		if !now.Before(h.Expires) {
			m.answerHeld(h, "approval_timeout", now)
			delete(m.st.Held, id)
			m.dirty = true
		}
	}
	for _, p := range m.st.Devices {
		if p.Access != nil && !now.Before(p.Access.Expires) {
			p.Access = nil
			m.dirty = true
		}
	}
}

// agentDecision consults the AgentPolicy feature (LEASH) for an agent's
// request of an owner type it is not listed for, or of an AgentPolicy
// type. Without one, or for an app-only type, the answer is AgentDeny.
func (m *Manager) agentDecision(s *Session, te *typeEntry, in *envelope.Inner) AgentDecision {
	if !te.spec.AgentPolicy && !te.allows(KindDesktop) {
		return AgentDeny // app-only types are never delegated
	}
	for _, f := range m.features {
		if pol, ok := f.(AgentPolicy); ok {
			return pol.AgentDecision(s, in.Type, in.Body)
		}
	}
	return AgentDeny
}

// agentGrantor returns the feature that installs an agent's initial grants
// (LEASH), or nil.
func (m *Manager) agentGrantor() AgentGrantor {
	for _, f := range m.features {
		if g, ok := f.(AgentGrantor); ok {
			return g
		}
	}
	return nil
}
