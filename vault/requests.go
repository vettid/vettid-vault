package vault

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"sort"
	"time"

	"github.com/vettid/vettid-relay/relayauth"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/invite"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Connection requests, pairings and transfers after their handshake
// (VAULT-MESSAGING 0.10.2, 0.10.3, §6.3, §6.4, §6.7, §7.1, §10.4).
//
// The handshake runs before anyone approves: the SAS depends on both
// sides' nonces and exists only after hs.resp (the initiator) and hs.fin
// (the responder). Its epoch is then established but not active. A
// connection becomes active when the vault holds both its own member's
// approval and the peer's connection.approved, which carries the standing
// and reconnect tokens; a pairing or transfer, at the owner's approval.
// Until then the peer holds only a request token (8 messages / 64 KiB).

// Request token parameters (§7.1).
const (
	RequestTokenQuotaMsgs   = 8
	RequestTokenQuotaBytes  = 65536
	RequestTokenConnection  = 16 * 24 * time.Hour // ≤ 16 d for a peer vault
	RequestTokenDevice      = 10 * time.Minute    // ≤ 10 min for a new device
	connectionApprovedType  = "connection.approved"
	connectionDeclinedType  = "connection.declined"
	devicePairRejectedType  = "device.pair.rejected"
	connectionRequestKind   = "connection.request"
	requestStatePending     = "pending"
	requestStateApproved    = "approved"
	requestStateWaiting     = "waiting"
	requestStatePeerApprove = "peer_approved"
	requestStateDeclined    = "declined"
	requestStatePeerDecline = "peer_declined"
	requestStateExpired     = "expired"
)

// mintRequest issues a request token to p (§7.1): it covers only the rest
// of the handshake and connection.approved. It is recorded at once, so
// that deposits made on it are classified by jti (§6.6).
func (m *Manager) mintRequest(p *Peer, now time.Time) (string, error) {
	ttl := RequestTokenConnection
	if p.Kind != KindConnection {
		ttl = RequestTokenDevice
	}
	if max := time.Duration(m.limits.MaxTokenLifetimeSeconds) * time.Second; max > 0 && max < ttl {
		ttl = max
	}
	quota := &relayauth.Quota{Msgs: i64(RequestTokenQuotaMsgs), Bytes: i64(RequestTokenQuotaBytes)}
	tok, issued, err := m.mint(p, TokRequest, ttl, quota, now, nil)
	if err != nil {
		return "", err
	}
	m.st.Issued = append(m.st.Issued, issued...)
	m.dirty = true
	return tok, nil
}

// issuedKind returns the kind of a token the vault issued, by jti ("" if
// unknown).
func (m *Manager) issuedKind(jti string) string {
	if jti == "" {
		return ""
	}
	for _, t := range m.st.Issued {
		if t.JTI == jti {
			return t.Kind
		}
	}
	return ""
}

// countRequests counts connection requests in one direction, including
// those whose handshake is still running (§10.4: at most 256 each).
func (m *Manager) countRequests(dir string) int {
	n := 0
	for _, r := range m.st.Requests {
		if r.Dir == dir && r.Peer.Kind == KindConnection {
			n++
		}
	}
	if dir == ReqIn {
		for _, aw := range m.st.Awaiting {
			if aw.New != nil && aw.New.Kind == KindConnection {
				n++
			}
		}
	} else {
		for _, og := range m.st.Outgoing {
			if og.New != nil {
				n++
			}
		}
	}
	return n
}

// newRequest records an incoming handshake whose hs.fin checked out and
// tells the owner's devices, with the SAS (§6.4, §6.7, §6.7.1).
func (m *Manager) newRequest(aw *AwaitingHS, fr *handshake.FinResult, now time.Time) {
	p := aw.New
	r := &Request{ID: aw.ID, Dir: ReqIn, Peer: p, SAS: fr.SAS, InviteID: aw.InviteID, Remote: aw.Remote,
		IntroBy: aw.IntroBy, Created: aw.Created, Expires: aw.Expires}
	m.st.Requests[r.ID] = r
	m.reqEpochs[r.ID] = fr.Epoch
	m.dirty = true
	switch {
	case p.Kind == KindConnection:
		if invite.AutoApproveAllowed(r.Remote, false, m.st.Settings.AutoApproveInPerson) {
			// In-person auto-approval skips the inviter's approval only;
			// its app still shows the code for the accepter (§6.4).
			if err := m.approveRequest(r, now); err != nil {
				return
			}
		}
		if m.st.Requests[r.ID] == nil {
			return // activated at once (the peer's approval came first)
		}
		m.notifyDevices("connection.request.pending", m.incomingJSON(r, false), "", now)
		m.record(Activity{Kind: "connection.request", Ref: r.ID, Feed: true}, now)
	case m.st.Transfer != nil && m.st.Transfer.Inbound == r.ID:
		m.transferScanned(r, now)
	default:
		b := strictjson.NewBuilder().String("pairing_id", r.InviteID).String("pending_id", r.ID).
			String("role", p.Kind).String("name", p.Name).String("sas", r.SAS)
		m.notifyApps("device.pair.pending", b.Bytes(), now)
		m.record(Activity{Kind: "device.pair.pending", Ref: r.ID, Feed: true, Priority: "high"}, now)
	}
}

// outgoingEstablished runs at the accepting vault once hs.resp verified:
// hs.fin goes out at once on the inviter's request token, and the SAS to
// every app and desktop (§6.4, 0.10.3).
func (m *Manager) outgoingEstablished(og *OutgoingHS, res *handshake.Result, now time.Time) {
	p := og.New
	held, err := m.heldToken(res.Resp.Token, p)
	if err != nil {
		res.Epoch.Destroy()
		m.audit(now, "hs_resp_bad_token", p.ID)
		m.denyPeerTokens(p, now)
		m.notifyDevices("connection.event", connEvent(p.ID, "failed"), "", now)
		return
	}
	p.Standing = held
	r := &Request{ID: p.ID, Dir: ReqOut, Peer: p, SAS: res.SAS, Remote: og.Remote, Name: og.Name, IntroBy: og.IntroBy,
		Created: og.Created, Expires: og.Expires}
	if r.Expires.IsZero() {
		r.Expires = og.Created.Add(OutgoingRequestTTL)
	}
	m.st.Requests[r.ID] = r
	m.reqEpochs[r.ID] = res.Epoch
	m.queueDeposit(&OutboxEntry{Op: OpDeposit, RelayURL: p.Relay.URL, Mailbox: p.Relay.Mailbox, Token: held.Token, Payload: res.Fin}, now)
	b := strictjson.NewBuilder().String("connection_id", r.ID).String("sas", r.SAS).Bool("remote", r.Remote).
		String("exp", envelope.FormatTS(r.Expires))
	if r.Name != "" {
		b.String("name", r.Name)
	}
	if r.IntroBy != "" {
		b.String("introduced_by", r.IntroBy)
	}
	m.notifyDevices("connection.request.outgoing", b.Bytes(), "", now)
}

// approveRequest is the member's approval of a connection request after
// comparing the SAS (§6.4, 0.10.3): the peer gets connection.approved with
// its standing and reconnect tokens, under the handshake's epoch, on its
// request token; the connection activates if the peer approved already.
func (m *Manager) approveRequest(r *Request, now time.Time) error {
	if r.Approved {
		return nil
	}
	ep := m.reqEpochs[r.ID]
	if ep == nil {
		return errNotFound
	}
	p := r.Peer
	tok, issued, err := m.mintStanding(p, now, nil)
	if err != nil {
		return NewError("relay_error", "")
	}
	rt, issued, err := m.mintReconnect(p, now, issued)
	if err != nil {
		return NewError("relay_error", "")
	}
	body := strictjson.NewBuilder().String("token", tok).String("reconnect_token", rt).Bytes()
	raw, err := ep.Seal(&envelope.Inner{ID: m.newID(now), Type: connectionApprovedType, TS: now, Body: body})
	if err != nil {
		return NewError("internal", "")
	}
	m.st.Issued = append(m.st.Issued, issued...)
	m.queueDeposit(&OutboxEntry{Op: OpDeposit, RelayURL: p.Relay.URL, Mailbox: p.Relay.Mailbox, Token: p.Standing.Token, Payload: raw}, now)
	r.Approved = true
	if r.Dir == ReqIn {
		r.Expires = r.Created.Add(ApprovedRetention) // §6.4 retention after approval
	}
	m.dirty = true
	m.record(Activity{Kind: "connection.request.approved", Ref: r.ID, Audit: true}, now)
	if r.PeerApproved {
		m.activateRequest(r, now)
	}
	return nil
}

// peerApproved handles the peer's connection.approved (§6.4, §10.4): the
// standing and reconnect tokens for the peer's mailbox.
func (m *Manager) peerApproved(r *Request, in *envelope.Inner, now time.Time) {
	if r.PeerApproved {
		return
	}
	o, err := strictjson.ParseObject(in.Body)
	if err != nil {
		m.audit(now, "bad_connection_approved", "")
		return
	}
	tok, err1 := o.String("token")
	rtok, err2 := o.String("reconnect_token")
	if err1 != nil || err2 != nil {
		m.audit(now, "bad_connection_approved", "")
		return
	}
	st, err1 := m.heldToken(tok, r.Peer)
	rt, err2 := m.heldToken(rtok, r.Peer)
	if err1 != nil || err2 != nil {
		m.audit(now, "bad_connection_approved", "")
		return
	}
	if r.PeerRequest == nil {
		// connection.declined still goes on the request token (§6.4, 0.10.5).
		held := r.Peer.Standing
		r.PeerRequest = &held
	}
	r.Peer.Standing, r.Peer.Reconnect = st, rt
	r.PeerApproved = true
	m.dirty = true
	m.notifyDevices("sync.event", m.requestSync(r, requestStatePeerApprove), "", now)
	if r.Approved {
		m.activateRequest(r, now)
	}
}

// activateRequest makes an approved request active (§6.3): the epoch
// becomes the principal's first, counted from now (§6.5).
func (m *Manager) activateRequest(r *Request, now time.Time) {
	ep := m.reqEpochs[r.ID]
	delete(m.reqEpochs, r.ID)
	delete(m.st.Requests, r.ID)
	m.dirty = true
	if ep == nil {
		return
	}
	ep.MarkActivated(now)
	pendingID := ""
	purpose := handshake.Purpose(r.Peer.Kind)
	if r.Peer.Kind == KindConnection && r.Dir == ReqIn {
		pendingID = r.ID
	}
	m.activate(r.Peer, ep, purpose, nil, pendingID, now)
}

// dropRequest ends a request without activation (§6.4, §6.7, §7.4): the
// tokens issued to the peer (the request token, and the standing and
// reconnect tokens of a connection.approved already sent) are denylisted,
// the tokens held for it and the handshake state deleted.
func (m *Manager) dropRequest(r *Request, now time.Time) {
	if e := m.reqEpochs[r.ID]; e != nil {
		e.Destroy()
	}
	delete(m.reqEpochs, r.ID)
	delete(m.st.Requests, r.ID)
	m.denyPeerTokens(r.Peer, now)
	m.dirty = true
}

// peerRequestToken is the token the peer issued for this request: its
// request token, kept aside once the peer's connection.approved replaced
// it with the standing token.
func (r *Request) peerRequestToken() HeldToken {
	if r.PeerRequest != nil {
		return *r.PeerRequest
	}
	return r.Peer.Standing
}

// sendEnded tells the peer that its member (or ours) ended the request
// (VAULT-MESSAGING 0.10.5): connection.declined to a peer vault (§6.4),
// device.pair.rejected to a new device (§6.7). It is sealed under the
// handshake's epoch, which is never activated, and queued on the token
// the peer issued, before the request is dropped in the same flush (§7.4):
// the entry carries its own copy of the token, so dropping the request
// does not cancel it, and the tokens denylisted then are the vault's own.
// Best effort: retried as any deposit (§8.6) until `until` (a pairing's
// 10 minutes) or the token's expiry, whichever is first. Without the epoch or a token nothing is sent.
func (m *Manager) sendEnded(r *Request, typ string, until time.Time, now time.Time) {
	ep, tok := m.reqEpochs[r.ID], r.peerRequestToken()
	if ep == nil || tok.Token == "" {
		return
	}
	raw, err := ep.Seal(&envelope.Inner{ID: m.newID(now), Type: typ, TS: now, Body: []byte(`{}`)})
	if err != nil {
		return
	}
	if !tok.Exp.IsZero() && (until.IsZero() || tok.Exp.Before(until)) {
		until = tok.Exp
	}
	p := r.Peer
	m.queueDeposit(&OutboxEntry{Op: OpDeposit, RelayURL: p.Relay.URL, Mailbox: p.Relay.Mailbox, Token: tok.Token, Payload: raw,
		NotAfter: until}, now)
}

// declineRequest is our member's decline (or block) of a connection
// request whose SAS is known: connection.declined to the peer first, then
// the drop (§6.4, §7.4, 0.10.5).
func (m *Manager) declineRequest(r *Request, now time.Time) {
	m.sendEnded(r, connectionDeclinedType, time.Time{}, now)
	m.dropRequest(r, now)
}

// peerDeclined handles the peer's connection.declined before activation
// (§6.4, 0.10.5): the request ends as a drop, the devices learn it
// (peer_declined; failed with reason declined on the accepter's side), and
// it is audited with a feed item.
func (m *Manager) peerDeclined(r *Request, now time.Time) {
	m.dropRequest(r, now)
	m.notifyDevices("sync.event", m.requestSync(r, requestStatePeerDecline), "", now)
	if r.Dir == ReqOut {
		m.notifyDevices("connection.event", strictjson.NewBuilder().String("connection_id", r.ID).String("event", "failed").
			String("reason", "declined").Bytes(), "", now)
	}
	m.record(Activity{Kind: "connection.request.peer_declined", Ref: r.ID, Audit: true, Feed: true}, now)
}

// peerDeclinedActive handles a connection.declined that reaches a
// connection already active on our side (§6.4 "After activation"): the
// decliner has denylisted every token it issued, so it is handled as
// connection.removed from that peer, without a notice back.
func (m *Manager) peerDeclinedActive(p *Peer, now time.Time) {
	m.record(Activity{Kind: "connection.request.peer_declined", ConnectionID: p.ID, Ref: p.ID, Audit: true}, now)
	m.removeConnection(p, "in", now)
}

// dropAwaiting ends a first-contact handshake that has not completed: its
// request token is denylisted; a transfer it belonged to is aborted.
func (m *Manager) dropAwaiting(id, reason string, now time.Time) {
	aw := m.st.Awaiting[id]
	if aw != nil && aw.New != nil {
		m.denyPeerTokens(aw.New, now) // also the tokens minted in its hs.resp
	}
	if r := m.awaiting[id]; r != nil {
		r.Abort()
	}
	delete(m.awaiting, id)
	delete(m.st.Awaiting, id)
	m.dirty = true
	if aw == nil || aw.New == nil {
		return
	}
	if t := m.st.Transfer; t != nil && t.Inbound == id {
		t.Inbound = ""
		m.abortTransfer(reason, now)
	}
}

// requestByKids finds the request whose established epoch this
// session-mode message is for, from the peer's relay key.
func (m *Manager) requestByKids(env *envelope.Envelope, sender ed25519.PublicKey) string {
	for id, e := range m.reqEpochs {
		r := m.st.Requests[id]
		if r == nil || !suite.EqualPublic(r.Peer.Relay.PK, sender) {
			continue
		}
		if env.RecipientKid().Equal(e.RecvKid()) {
			return id
		}
	}
	return ""
}

// handleRequestMessage handles a message under a request's epoch before
// activation (§6.4 "Before activation", §6.7): connection.approved is
// processed, and (0.10.5) connection.declined ends the request; before
// our member's approval anything else is acked,
// dropped and audited; after it, left unacked for activation.
func (m *Manager) handleRequestMessage(id string, env *envelope.Envelope, now time.Time) disposition {
	r, ep := m.st.Requests[id], m.reqEpochs[id]
	in, err := ep.Open(env)
	if err != nil {
		m.audit(now, "decrypt_failed", "")
		return ackAfterFlush
	}
	if in.Type == handshake.TypeFin {
		return ackAfterFlush // a redelivered hs.fin: already processed
	}
	if r.Peer.Kind == KindConnection && in.Type == connectionApprovedType && in.Re == "" {
		if err := in.CheckTime(now, true); err != nil {
			m.audit(now, "stale_or_future", "")
			return ackAfterFlush
		}
		m.peerApproved(r, in, now)
		return ackAfterFlush
	}
	if r.Peer.Kind == KindConnection && in.Type == connectionDeclinedType && in.Re == "" {
		// Whether or not our member approved (§6.4, 0.10.5).
		if err := in.CheckTime(now, true); err != nil {
			m.audit(now, "stale_or_future", "")
			return ackAfterFlush
		}
		m.peerDeclined(r, now)
		return ackAfterFlush
	}
	if r.Peer.Kind == KindConnection && r.Approved {
		return noAck // the peer may be active already: processed at activation
	}
	m.audit(now, "unapproved_peer", "")
	return ackAfterFlush
}

// handleOnRequestToken handles a deposit made on a request token we
// issued (§7.1): only the rest of the handshake (hs.resp, hs.fin),
// connection.approved and connection.declined are accepted (the last also
// once the connection is active, 0.10.5); relay.token.refresh is answered
// forbidden; anything else is acked, dropped and audited.
func (m *Manager) handleOnRequestToken(ctx context.Context, env *envelope.Envelope, raw []byte, sender ed25519.PublicKey, p *Peer, now time.Time) disposition {
	if env.Mode() == envelope.ModeSealed {
		rk := env.RecipientKid()
		for id, og := range m.st.Outgoing {
			if kid, err := kidFrom(og.EphKid); err == nil && kid.Equal(rk) && og.New != nil {
				return m.handleResp(ctx, id, raw, sender, now)
			}
		}
		m.audit(now, "request_token_misuse", peerID(p))
		return ackAfterFlush
	}
	if id := m.awaitingByKids(env, sender); id != "" {
		return m.handleFin(ctx, id, raw, sender, now)
	}
	if id := m.requestByKids(env, sender); id != "" {
		return m.handleRequestMessage(id, env, now)
	}
	if p != nil {
		if kr := m.sessions[p.ID]; kr != nil {
			if in, _, err := kr.Open(env, now); err == nil && in.Re == "" {
				switch {
				case in.Type == tokenRefreshType:
					m.respondError(p, in, p.ID+"|"+in.ID, "forbidden", "", now)
					return ackAfterFlush
				case in.Type == connectionDeclinedType && p.Kind == KindConnection && p.State == PeerActive:
					// §6.4 "After activation" (0.10.5).
					if err := in.CheckTime(now, true); err != nil {
						m.audit(now, "stale_or_future", p.ID)
						return ackAfterFlush
					}
					m.peerDeclinedActive(p, now)
					return ackAfterFlush
				}
			}
		}
	}
	m.audit(now, "request_token_misuse", peerID(p))
	return ackAfterFlush
}

// --- requests: approval, decline, listing (§10.4) ---

// requestRef parses {pending_id} or {connection_id}, exactly one.
func requestRef(in *envelope.Inner) (id, dir string, err error) {
	o, err := obj(in)
	if err != nil {
		return "", "", err
	}
	pid, hasP, err1 := o.OptString("pending_id")
	cid, hasC, err2 := o.OptString("connection_id")
	if err1 != nil || err2 != nil || hasP == hasC {
		return "", "", errBadRequest
	}
	if hasP {
		if pid == "" || len(pid) > 128 {
			return "", "", errBadRequest
		}
		return pid, ReqIn, nil
	}
	if cid == "" || len(cid) > 128 {
		return "", "", errBadRequest
	}
	return cid, ReqOut, nil
}

// connRequest returns a connection request by id and direction; waiting
// reports a request whose SAS is not yet known (its handshake runs).
func (m *Manager) connRequest(id, dir string) (r *Request, waiting bool) {
	if r := m.st.Requests[id]; r != nil && r.Dir == dir && r.Peer.Kind == KindConnection {
		return r, false
	}
	if dir == ReqIn {
		if aw := m.st.Awaiting[id]; aw != nil && aw.New != nil && aw.New.Kind == KindConnection {
			return nil, true
		}
		return nil, false
	}
	return nil, m.waitingOutgoing(id) != ""
}

// waitingOutgoing returns the outgoing handshake of connection id.
func (m *Manager) waitingOutgoing(connID string) string {
	for oid, og := range m.st.Outgoing {
		if og.New != nil && og.New.ID == connID {
			return oid
		}
	}
	return ""
}

func (m *Manager) hConnApprove(_ context.Context, s *Session, in *envelope.Inner) (json.RawMessage, error) {
	id, dir, err := requestRef(in)
	if err != nil {
		return nil, err
	}
	r, waiting := m.connRequest(id, dir)
	if r == nil {
		if waiting {
			return nil, errBadRequest // the SAS is not known yet (0.10.3)
		}
		return nil, errNotFound
	}
	if r.Approved {
		return nil, nil
	}
	if err := m.approveRequest(r, s.now); err != nil {
		if he, ok := err.(*HandlerError); ok {
			return nil, he
		}
		return nil, NewError("approve_failed", "")
	}
	m.notifyDevices("sync.event", m.requestSync(r, requestStateApproved), s.peer.ID, s.now)
	return nil, nil
}

func (m *Manager) hConnDecline(_ context.Context, s *Session, in *envelope.Inner) (json.RawMessage, error) {
	id, dir, err := requestRef(in)
	if err != nil {
		return nil, err
	}
	r, waiting := m.connRequest(id, dir)
	switch {
	case r != nil:
		m.declineRequest(r, s.now) // connection.declined first (§6.4, 0.10.5)
	case waiting && dir == ReqOut:
		oid := m.waitingOutgoing(id)
		p := m.st.Outgoing[oid].New
		m.dropOutgoing(oid)
		m.denyPeerTokens(p, s.now)
		r = &Request{ID: id, Dir: ReqOut}
	case waiting:
		m.dropAwaiting(id, "", s.now)
		r = &Request{ID: id, Dir: ReqIn}
	default:
		return nil, errNotFound
	}
	// A decline in waiting (the accepter: no token to the inviter, no
	// epoch) or of an hs.init without hs.fin (the inviter: never shown)
	// sends nothing (§6.4, 0.10.5); the peer's request ends by expiry.
	m.record(Activity{Kind: "connection.request.declined", Ref: id, Audit: true}, s.now)
	m.notifyDevices("sync.event", m.requestSync(r, requestStateDeclined), s.peer.ID, s.now)
	return nil, nil
}

// requestSync is the sync.event{kind: connection.request} body (§10.1).
func (m *Manager) requestSync(r *Request, state string) json.RawMessage {
	b := strictjson.NewBuilder().String("kind", connectionRequestKind)
	if r.Dir == ReqIn {
		b.String("pending_id", r.ID)
	} else {
		b.String("connection_id", r.ID)
	}
	return b.String("state", state).Bytes()
}

func requestState(r *Request) string {
	if r.Approved {
		return requestStateApproved
	}
	return requestStatePending
}

// incomingJSON is an incoming request as connection.request.pending
// (list: with peer_approved and created_at) shows it (§10.4).
func (m *Manager) incomingJSON(r *Request, list bool) []byte {
	b := strictjson.NewBuilder().String("pending_id", r.ID).String("invite_id", r.InviteID).String("sas", r.SAS).
		Bool("remote", r.Remote).String("state", requestState(r))
	if list {
		b.Bool("peer_approved", r.PeerApproved).String("created_at", envelope.FormatTS(r.Created))
	}
	b.String("exp", envelope.FormatTS(r.Expires))
	if len(r.Peer.Profile) > 0 {
		b.Raw("profile", r.Peer.Profile)
	}
	if r.IntroBy != "" {
		b.String("introduced_by", r.IntroBy) // §10.15
	}
	return b.Bytes()
}

type listedRequest struct {
	created time.Time
	id      string
	json    []byte
}

func sortedJSON(ls []listedRequest) []byte {
	sort.Slice(ls, func(i, j int) bool {
		if !ls[i].created.Equal(ls[j].created) {
			return ls[i].created.After(ls[j].created) // newest first
		}
		return ls[i].id > ls[j].id
	})
	arr := []byte{'['}
	for i, l := range ls {
		if i > 0 {
			arr = append(arr, ',')
		}
		arr = append(arr, l.json...)
	}
	return append(arr, ']')
}

// hRequestList answers connection.request.list (§10.4): incoming requests
// once their hs.fin checked out, and outgoing ones from the accept on.
func (m *Manager) hRequestList(_ context.Context, s *Session, in *envelope.Inner) (json.RawMessage, error) {
	if _, err := obj(in); err != nil {
		return nil, err
	}
	var inc, out []listedRequest
	for _, r := range m.st.Requests {
		if r.Peer.Kind != KindConnection {
			continue
		}
		if r.Dir == ReqIn {
			inc = append(inc, listedRequest{r.Created, r.ID, m.incomingJSON(r, true)})
			continue
		}
		b := strictjson.NewBuilder().String("connection_id", r.ID).String("sas", r.SAS).Bool("remote", r.Remote).
			String("state", requestState(r)).Bool("peer_approved", r.PeerApproved).
			String("created_at", envelope.FormatTS(r.Created)).String("exp", envelope.FormatTS(r.Expires))
		if r.Name != "" {
			b.String("name", r.Name)
		}
		if r.IntroBy != "" {
			b.String("introduced_by", r.IntroBy)
		}
		out = append(out, listedRequest{r.Created, r.ID, b.Bytes()})
	}
	for _, og := range m.st.Outgoing {
		if og.New == nil {
			continue
		}
		b := strictjson.NewBuilder().String("connection_id", og.New.ID).Bool("remote", og.Remote).
			String("state", requestStateWaiting).Bool("peer_approved", false).
			String("created_at", envelope.FormatTS(og.Created)).String("exp", envelope.FormatTS(og.Expires))
		if og.Name != "" {
			b.String("name", og.Name)
		}
		if og.IntroBy != "" {
			b.String("introduced_by", og.IntroBy)
		}
		out = append(out, listedRequest{og.Created, og.New.ID, b.Bytes()})
	}
	return strictjson.NewBuilder().Raw("incoming", sortedJSON(inc)).Raw("outgoing", sortedJSON(out)).Bytes(), nil
}

// expireRequests runs in housekeeping (§6.4 "Request expiry and
// retention", §6.7): first-contact handshakes without hs.fin, requests
// past their expiry, and outgoing requests not active after 8 days.
func (m *Manager) expireRequests(now time.Time) {
	for id, aw := range m.st.Awaiting {
		if aw.New != nil && !aw.Expires.IsZero() && !now.Before(aw.Expires) {
			m.dropAwaiting(id, "expired", now)
		}
	}
	for id, og := range m.st.Outgoing {
		if og.New != nil && !og.Expires.IsZero() && !now.Before(og.Expires) {
			p := og.New
			m.dropOutgoing(id)
			m.denyPeerTokens(p, now)
			m.notifyDevices("connection.event", connEvent(p.ID, "failed"), "", now)
		}
	}
	for _, r := range m.sortedRequests() {
		if now.Before(r.Expires) {
			continue
		}
		if t := m.st.Transfer; t != nil && t.Inbound == r.ID {
			m.abortTransfer("expired", now) // drops the request too
			continue
		}
		m.dropRequest(r, now)
		switch {
		case r.Peer.Kind != KindConnection:
			if inv := m.st.Invites[r.InviteID]; inv != nil && inv.OpenJTI != "" {
				m.denyJTI(inv.OpenJTI, now)
			}
		case r.Dir == ReqIn:
			m.notifyDevices("sync.event", m.requestSync(r, requestStateExpired), "", now)
		default:
			m.notifyDevices("connection.event", connEvent(r.ID, "failed"), "", now)
		}
	}
}

func (m *Manager) sortedRequests() []*Request {
	out := make([]*Request, 0, len(m.st.Requests))
	for _, r := range m.st.Requests {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// pairingRequest returns the pairing (desktop or agent) request for a
// pairing id; waiting reports one whose handshake still runs.
func (m *Manager) pairingRequest(pairingID string) (r *Request, waitingID string) {
	for _, x := range m.st.Requests {
		if x.Dir == ReqIn && x.Peer.Kind != KindConnection && (x.InviteID == pairingID || x.ID == pairingID) {
			return x, ""
		}
	}
	for id, aw := range m.st.Awaiting {
		if aw.New != nil && aw.New.Kind != KindConnection && !aw.Direct && (aw.InviteID == pairingID || id == pairingID) {
			return nil, id
		}
	}
	return nil, ""
}
