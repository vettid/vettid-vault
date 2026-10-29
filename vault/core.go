package vault

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/altchan"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/peerwire"
	"github.com/vettid/vettid-vault/vms/suite"
)

// HandlerFunc adapts a function to Handler.
type HandlerFunc func(ctx context.Context, s *Session, in *envelope.Inner) (json.RawMessage, error)

// Handle implements Handler.
func (f HandlerFunc) Handle(ctx context.Context, s *Session, in *envelope.Inner) (json.RawMessage, error) {
	return f(ctx, s, in)
}

var (
	owners  = []string{KindApp, KindDesktop}
	apps    = []string{KindApp}
	devices = []string{KindApp, KindDesktop, KindAgent}
	all     = []string{KindApp, KindDesktop, KindAgent, KindConnection}
	conns   = []string{KindConnection}
)

// registerCore registers the core types the runtime implements itself
// (§10: lifecycle, sessions, connections, devices).
func (m *Manager) registerCore() {
	r := func(t string, req bool, from []string, h HandlerFunc) {
		m.register(TypeSpec{Type: t, Request: req, From: from}, h)
	}
	r("vault.status", true, devices, m.hStatus)
	r("vault.lock", true, owners, m.hLock)
	r("vault.enroll.confirm", true, apps, m.hEnrollConfirm)
	r("device.pair.create", true, apps, m.hPairCreate)
	r("device.pair.approve", true, apps, m.hPairApprove)
	r("device.pair.reject", true, apps, m.hPairReject)
	r("device.list", true, owners, m.hDeviceList)
	r("device.unlink", true, apps, m.hDeviceUnlink)
	// Only the member's phone creates or accepts connections (owner
	// decision 2026-10-13, §6.8): inviting, accepting an invitation and
	// approving an incoming request are app-only, refused to a desktop or
	// an agent at once with forbidden. Declining, cancelling and listing
	// stay open to desktops.
	r("connection.invite.create", true, apps, m.hInviteCreate)
	r("connection.invite.list", true, owners, m.hInviteList)
	r("connection.invite.cancel", true, owners, m.hInviteCancel)
	r("connection.invite.accept", true, apps, m.hInviteAccept)
	r("connection.approve", true, apps, m.hConnApprove)
	r("connection.decline", true, owners, m.hConnDecline)
	r("connection.request.list", true, owners, m.hRequestList)
	// connection.approved is handled before activation (requests.go); a
	// copy that arrives once the connection is active is ignored.
	r(connectionApprovedType, false, conns, func(context.Context, *Session, *envelope.Inner) (json.RawMessage, error) { return nil, nil })
	r("connection.list", true, owners, m.hConnList)
	r("connection.get", true, owners, m.hConnGet)
	r("connection.remove", true, owners, m.hConnRemove)
	r(peerwire.TypeConnectionRemoved, false, conns, m.hConnRemoved)
	r(tokenIssuedType, false, all, m.hTokenIssued)
	r(tokenRefreshType, true, all, m.hTokenRefresh)
	r("identity.rotate", false, conns, m.hIdentityRotate)
	r(TypeRotationResolve, true, []string{KindApp}, m.hRotationResolve) // release R (§3.4)
	r("relay.address.update", false, all, m.hAddressUpdate)
	r("settings.get", true, owners, m.hSettingsGet)
	r("settings.set", true, owners, m.hSettingsSet)
	r("account.get", true, owners, m.hAccountGet)
	m.registerAccess()
	m.registerPending()
	m.registerConnections()
	m.registerAsks()
	m.registerPush()
}

func obj(in *envelope.Inner) (strictjson.Object, error) {
	o, err := strictjson.ParseObject(in.Body)
	if err != nil {
		return nil, errBadRequest
	}
	return o, nil
}

func str(o strictjson.Object, k string) (string, error) {
	v, err := o.String(k)
	if err != nil || v == "" || len(v) > 4096 {
		return "", errBadRequest
	}
	return v, nil
}

func (m *Manager) hStatus(_ context.Context, s *Session, _ *envelope.Inner) (json.RawMessage, error) {
	if s.peer.Recovering {
		// 0.16.0 (§10.2, §11.11.5): nothing about the vault before the
		// credential password.
		return strictjson.NewBuilder().String("vault_id", m.st.VaultID).Uint("state_seq", m.st.StateSeq).
			Uint("header_seq", m.hdr.HeaderSeq).Bytes(), nil
	}
	b := strictjson.NewBuilder().String("vault_id", m.st.VaultID).Uint("state_seq", m.st.StateSeq).
		Uint("header_seq", m.hdr.HeaderSeq).Bool("provisional", m.hdr.Provisional).
		Uint("devices", uint64(len(m.st.Devices))).Uint("connections", uint64(len(m.st.Connections))).
		Raw("owner_check", m.ownerCheckStatus(s.peer, s.now))
	if s.peer.Kind == KindApp || s.peer.Kind == KindDesktop {
		// 0.29.0, release L (§10.2 "Locks"): the name of this unlock, to
		// the app and desktops (a desktop locks with it), not to agents.
		b.String("unlock_id", m.unlockID)
		b.Raw("attachments", m.attStatusJSON()) // §10.2 (0.32.0, release A)
		// 0.43.0 (§10.2, §11.10.8): the release's time scale, 1 in
		// production.
		b.Uint("time_scale", m.opt.timeScale())
	}
	// Release R (§11.14.11): the app gets the recovery state, attempts,
	// presence and counter; desktops the state alone; agents nothing.
	switch s.peer.Kind {
	case KindApp:
		b.Raw("recovery", m.recoveryStatus(true))
	case KindDesktop:
		b.Raw("recovery", m.recoveryStatus(false))
	}
	return b.Bytes(), nil
}

// hLock is vault.lock (§10.2, §12.3). 0.29.0, release L (§10.2 "Locks"):
// a lock that names an unlock is carried out only for the current one;
// one that names another answers stale_lock and does nothing (that unlock
// is over, the vault is open under a newer one); a malformed value is
// bad_request. A lock without unlock_id (a device from before release L)
// is carried out as before (VAULT-LOCK L2).
func (m *Manager) hLock(_ context.Context, s *Session, in *envelope.Inner) (json.RawMessage, error) {
	o, err := obj(in)
	if err != nil {
		return nil, err
	}
	id, named, err := o.OptString("unlock_id")
	if err != nil || named && !altchan.ValidUnlockID(id) {
		return nil, errBadRequest
	}
	if named && subtle.ConstantTimeCompare([]byte(id), []byte(m.unlockID)) != 1 {
		return nil, NewError("stale_lock", "")
	}
	m.lockPending = true // after this batch: flush, vault.locking, zeroize (§12.3)
	m.lockBy = s.from.ID // audited on vault.locked (0.23.2)
	return nil, nil
}

func (m *Manager) hEnrollConfirm(_ context.Context, _ *Session, _ *envelope.Inner) (json.RawMessage, error) {
	m.hdr.Provisional = false // written with the batch's flush
	return nil, nil
}

// --- device pairing (§6.7) ---

func (m *Manager) hPairCreate(ctx context.Context, s *Session, in *envelope.Inner) (json.RawMessage, error) {
	o, err := obj(in)
	if err != nil {
		return nil, err
	}
	role, err := str(o, "role")
	if err != nil || (role != KindApp && role != KindDesktop && role != KindAgent) {
		return nil, errBadRequest
	}
	if role == KindAgent && !m.hasFeature(featureLeash) {
		// 0.26.0, §11.10.8: an agent acts only through LEASH grants, so
		// an image that does not register leash knows no agent role and
		// answers as for any unknown role.
		return nil, errBadRequest
	}
	if role == KindApp {
		// One app per vault (§6.7, 0.9.0): a new phone takes over by a
		// direct transfer (§6.7.1), never as a second app.
		return nil, NewError("one_app", "")
	}
	inv, link, err := m.createInvite(ctx, role, PairingApprovalTTL, s.peer.ID, s.now)
	if err != nil {
		return nil, NewError("relay_error", "")
	}
	return strictjson.NewBuilder().String("pairing_id", inv.ID).String("link", link).
		String("exp", inv.Exp.UTC().Format(time.RFC3339)).Bytes(), nil
}

func (m *Manager) hPairApprove(ctx context.Context, s *Session, in *envelope.Inner) (json.RawMessage, error) {
	o, err := obj(in)
	if err != nil {
		return nil, err
	}
	pid, err := str(o, "pairing_id")
	if err != nil {
		return nil, err
	}
	r, waiting := m.pairingRequest(pid)
	if r == nil {
		if waiting != "" && !m.isTransferRequest(waiting) {
			return nil, errBadRequest // the SAS is not known yet (0.10.3)
		}
		return nil, errNotFound
	}
	if m.isTransferRequest(r.ID) {
		return nil, errNotFound
	}
	// An initial access session for a desktop or agent may come with the
	// pairing approval (§6.8), and an agent's initial LEASH grants
	// (§6.7, §10.11).
	secs, present, err := accessSeconds(o, "session_seconds")
	if err != nil || present && !needsAccess(r.Peer.Kind) {
		return nil, errBadRequest
	}
	grants, hasGrants := o["grants"]
	if hasGrants {
		g := m.agentGrantor()
		if r.Peer.Kind != KindAgent || g == nil {
			return nil, errBadRequest
		}
		// Every grant is a delegation signed by the member's credential
		// key (§10.11): it is signed now, within the unlock window, for
		// the agent's identity key from its hs.init.
		prepared, err := g.PrepareAgentGrants(s, r.Peer.IK, grants)
		if err != nil {
			var he *HandlerError
			if errors.As(err, &he) {
				return nil, he
			}
			return nil, errBadRequest
		}
		grants = prepared
	}
	// The approval activates the epoch and creates the device record,
	// which gets device.paired with its standing token (§6.7, 0.10.3).
	p := r.Peer
	if present && needsAccess(p.Kind) {
		m.grantAccess(p, secs, s.peer.ID, s.now)
	}
	if hasGrants {
		p.PairGrants = append(json.RawMessage(nil), grants...)
	}
	m.activateRequest(r, s.now)
	if present && needsAccess(p.Kind) {
		m.record(Activity{Kind: "device.session.granted", DeviceID: p.ID, Ref: p.Access.ID, Audit: true}, s.now)
		m.notifyDevices("sync.event", strictjson.NewBuilder().String("kind", "device.session").String("device_id", p.ID).
			String("expires_at", envelope.FormatTS(p.Access.Expires)).Bytes(), s.peer.ID, s.now)
	}
	return nil, nil
}

func (m *Manager) hPairReject(_ context.Context, s *Session, in *envelope.Inner) (json.RawMessage, error) {
	o, err := obj(in)
	if err != nil {
		return nil, err
	}
	pid, err := str(o, "pairing_id")
	if err != nil {
		return nil, err
	}
	r, waiting := m.pairingRequest(pid)
	switch {
	case r != nil && !m.isTransferRequest(r.ID):
		// After hs.fin the device is told first (§6.7, 0.10.5).
		pid = r.InviteID
		m.sendEnded(r, devicePairRejectedType, r.Expires, s.now)
		m.dropRequest(r, s.now)
	case waiting != "" && !m.isTransferRequest(waiting):
		pid = m.st.Awaiting[waiting].InviteID
		m.dropAwaiting(waiting, "rejected", s.now)
	default:
		return nil, errNotFound
	}
	if inv := m.st.Invites[pid]; inv != nil && inv.OpenJTI != "" {
		m.denyJTI(inv.OpenJTI, s.now)
	}
	return nil, nil
}

func (m *Manager) hDeviceList(_ context.Context, s *Session, _ *envelope.Inner) (json.RawMessage, error) {
	return m.devicesJSON(s.now), nil
}

// hDeviceUnlink applies §7.4 "Device unlinked": device.unlinked (best
// effort), denylist sub, remove from the unlock keys (next flush), delete.
func (m *Manager) hDeviceUnlink(_ context.Context, s *Session, in *envelope.Inner) (json.RawMessage, error) {
	o, err := obj(in)
	if err != nil {
		return nil, err
	}
	id, err := str(o, "device_id")
	if err != nil {
		return nil, err
	}
	p, ok := m.st.Devices[id]
	if !ok {
		return nil, errNotFound
	}
	if p.Kind == KindApp {
		// The one app leaves only by a transfer or a recovery (§6.7).
		return nil, errForbiddenH
	}
	m.endAccess(context.Background(), p, false, "", s.peer.ID, s.now) // its access session and held requests go with it
	m.removePeer(p, "device.unlinked", s.now)
	for _, f := range m.features {
		if ob, ok := f.(DeviceRemovedObserver); ok {
			ob.DeviceRemoved(m.session(s.now), id) // §7.4: an agent's grants go too
		}
	}
	m.record(Activity{Kind: "device.unlinked", DeviceID: id, Audit: true, Feed: true}, s.now)
	m.notifyDevices("sync.event", strictjson.NewBuilder().String("kind", "device.unlinked").String("device_id", id).Bytes(), s.peer.ID, s.now)
	return nil, nil
}

// removePeer sends a best-effort notice, denylists the peer's sub, and
// deletes its tokens, sessions and outbox entries (§7.4).
func (m *Manager) removePeer(p *Peer, notice string, now time.Time) {
	m.removePeerWith(p, notice, json.RawMessage(`{}`), now)
}

// removePeerWith is removePeer with a notice body.
func (m *Manager) removePeerWith(p *Peer, notice string, body json.RawMessage, now time.Time) {
	if kr := m.sessions[p.ID]; kr != nil && kr.Current() != nil && p.Standing.Token != "" && p.State == PeerActive {
		in := &envelope.Inner{ID: m.newID(now), Type: notice, TS: now, Body: body}
		if raw, err := kr.Current().Seal(in); err == nil {
			m.queueDeposit(&OutboxEntry{RelayURL: p.Relay.URL, Mailbox: p.Relay.Mailbox, Token: p.Standing.Token,
				Payload: raw, BestEffort: true}, now)
		}
	}
	if p.Kind == KindConnection {
		// §7.4: every token issued to the peer is denylisted by jti, so
		// none of them works again, while a later invitation can still
		// make a fresh connection with the same relay key.
		m.denyPeerTokens(p, now)
	} else {
		m.denySub(p, now) // §6.7: a re-paired device needs a new relay key
	}
	for _, e := range m.st.Outbox {
		if e.PeerID == p.ID {
			e.Done = true
		}
	}
	if kr := m.sessions[p.ID]; kr != nil {
		kr.Destroy()
	}
	delete(m.sessions, p.ID)
	for id, og := range m.st.Outgoing {
		if og.PeerID == p.ID {
			m.dropOutgoing(id)
		}
	}
	delete(m.st.Devices, p.ID)
	delete(m.st.Connections, p.ID)
	m.dirty = true
}

// --- connections and invitations (§6.4) ---

func (m *Manager) hInviteCreate(ctx context.Context, s *Session, in *envelope.Inner) (json.RawMessage, error) {
	o, err := obj(in)
	if err != nil {
		return nil, err
	}
	secs, err := o.Uint("ttl_seconds", 1, 30*24*3600)
	if err != nil {
		return nil, errBadRequest
	}
	inv, link, err := m.createInvite(ctx, KindConnection, time.Duration(secs)*time.Second, s.peer.ID, s.now)
	if err != nil {
		if _, ok := err.(*HandlerError); ok {
			return nil, err
		}
		return nil, NewError("ttl_not_allowed", "")
	}
	return strictjson.NewBuilder().String("invite_id", inv.ID).String("link", link).
		String("exp", inv.Exp.UTC().Format(time.RFC3339)).Bool("remote", inv.Remote).Bytes(), nil
}

func (m *Manager) hInviteList(context.Context, *Session, *envelope.Inner) (json.RawMessage, error) {
	var ids []string
	for id, inv := range m.st.Invites {
		if !inv.Used && inv.Kind == KindConnection {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	arr := []byte{'['}
	for i, id := range ids {
		if i > 0 {
			arr = append(arr, ',')
		}
		inv := m.st.Invites[id]
		arr = append(arr, strictjson.NewBuilder().String("invite_id", id).String("exp", inv.Exp.UTC().Format(time.RFC3339)).
			Bool("remote", inv.Remote).Bytes()...)
	}
	return strictjson.NewBuilder().Raw("invites", append(arr, ']')).Bytes(), nil
}

// hInviteCancel: §6.4 revocation and §7.4: denylist the open token's jti and
// DELETE the claim.
func (m *Manager) hInviteCancel(_ context.Context, s *Session, in *envelope.Inner) (json.RawMessage, error) {
	o, err := obj(in)
	if err != nil {
		return nil, err
	}
	id, err := str(o, "invite_id")
	if err != nil {
		return nil, err
	}
	inv := m.st.Invites[id]
	if inv == nil || inv.Kind != KindConnection {
		return nil, errNotFound
	}
	m.denyJTI(inv.OpenJTI, s.now)
	m.queueDeleteClaim(inv.ClaimID, s.now)
	delete(m.st.Invites, id)
	return nil, nil
}

func (m *Manager) hInviteAccept(ctx context.Context, s *Session, in *envelope.Inner) (json.RawMessage, error) {
	o, err := obj(in)
	if err != nil {
		return nil, err
	}
	link, err := str(o, "link")
	if err != nil {
		return nil, err
	}
	og, err := m.acceptInvite(ctx, link, "", s.now)
	if err != nil {
		if he, ok := err.(*HandlerError); ok {
			return nil, he
		}
		return nil, NewError("accept_failed", "")
	}
	// §10.4 (0.10.3): the SAS follows in connection.request.outgoing once
	// the handshake has run.
	b := strictjson.NewBuilder().String("connection_id", og.New.ID).String("state", requestStateWaiting).
		Bool("remote", og.Remote).String("exp", envelope.FormatTS(og.Expires))
	if og.Name != "" {
		b.String("name", og.Name)
	}
	if og.New.PeerKind != "" {
		b.String("peer_kind", og.New.PeerKind) // §10.4 (0.69.0): shown with the SAS before approval
	}
	return b.Bytes(), nil
}

func (m *Manager) hConnList(_ context.Context, s *Session, _ *envelope.Inner) (json.RawMessage, error) {
	return peersJSON("connections", m.st.Connections, s.now), nil
}

func (m *Manager) hConnGet(_ context.Context, s *Session, in *envelope.Inner) (json.RawMessage, error) {
	o, err := obj(in)
	if err != nil {
		return nil, err
	}
	id, err := str(o, "connection_id")
	if err != nil {
		return nil, err
	}
	p, ok := m.st.Connections[id]
	if !ok {
		return nil, errNotFound
	}
	return peerJSON(p, s.now), nil
}

// hConnRemove applies §7.4 "Connection removed".
func (m *Manager) hConnRemove(_ context.Context, s *Session, in *envelope.Inner) (json.RawMessage, error) {
	o, err := obj(in)
	if err != nil {
		return nil, err
	}
	id, err := str(o, "connection_id")
	if err != nil {
		return nil, err
	}
	p, ok := m.st.Connections[id]
	if !ok {
		return nil, errNotFound
	}
	m.removeConnection(p, "out", s.now)
	return nil, nil
}

func (m *Manager) hConnRemoved(_ context.Context, s *Session, _ *envelope.Inner) (json.RawMessage, error) {
	m.removeConnection(s.peer, "in", s.now)
	return nil, nil
}

// --- tokens (§7.2) ---

func (m *Manager) hTokenIssued(_ context.Context, s *Session, in *envelope.Inner) (json.RawMessage, error) {
	m.storeIssuedTo(s.peer, in.Body, s.now)
	return nil, nil
}

// RenewEvery bounds a connection's refreshes near its token's end (§7.2).
const RenewEvery = peerwire.RenewEvery

func (m *Manager) hTokenRefresh(_ context.Context, s *Session, _ *envelope.Inner) (json.RawMessage, error) {
	// §7.2 (0.32.0, release A): a connection whose standing token still
	// has HolderRefreshBelow or more left asks after quota_exceeded. It is
	// granted a fresh token at most once in 24 hours, and the old one is
	// denylisted, so that a refresh never doubles what it may deposit.
	// Classified by the latest standing token issued to the peer, not by
	// the one the request came under: a refresh while that one still has
	// HolderRefreshBelow or more left is a quota refresh, so that no older
	// token can mint fresh ones beyond the daily one.
	quota := false
	if s.peer.Kind == KindConnection {
		if t := m.latestIssued(s.peer.ID, TokStanding); t != nil {
			quota = t.Exp.Sub(s.now) >= HolderRefreshBelow
		}
	}
	tooSoon := func(t time.Time) error {
		return &HandlerError{Code: peerwire.CodeTooSoon, Body: peerwire.TooSoonBody(t)}
	}
	if quota {
		if t, ok := m.st.attach().Refreshed[s.peer.ID]; ok && s.now.Sub(t) < peerwire.QuotaRefreshEvery {
			return nil, tooSoon(t.Add(peerwire.QuotaRefreshEvery))
		}
	} else if s.peer.Kind == KindConnection {
		// A refresh near the token's end is bounded too: one an hour.
		if t, ok := m.st.attach().Renewed[s.peer.ID]; ok && s.now.Sub(t) < RenewEvery {
			return nil, tooSoon(t.Add(RenewEvery))
		}
		m.st.attach().Renewed[s.peer.ID] = s.now
		m.dirty = true
	}
	tok, issued, err := m.mintStanding(s.peer, s.now, nil)
	if err != nil {
		return nil, NewError("relay_error", "")
	}
	if quota {
		for i := range m.st.Issued {
			t := &m.st.Issued[i]
			if t.PeerID == s.peer.ID && t.Kind == TokStanding && !t.Denied {
				t.Denied = true
				m.queueRevoke("jti", t.JTI, s.now)
			}
		}
		m.st.attach().Refreshed[s.peer.ID] = s.now
		m.dirty = true
	}
	m.st.Issued = append(m.st.Issued, issued...)
	return peerwire.TokenIssuedBody(TokStanding, tok), nil
}

// --- rotation (§3.4) ---

// hIdentityRotate follows one link of a connection's rotation chain.
func (m *Manager) hIdentityRotate(_ context.Context, s *Session, in *envelope.Inner) (json.RawMessage, error) {
	o, err := obj(in)
	if err != nil {
		return nil, err
	}
	raw, ok := o["rotation"]
	if !ok {
		return nil, errBadRequest
	}
	r, err := handshake.ParseRotation(raw)
	if err != nil {
		return nil, errBadRequest
	}
	if c := m.rotationConflict(s.peer, r, s.now); c {
		return nil, nil
	}
	if s.peer.suspended() {
		return nil, nil
	}
	final, kem, err := handshake.ResolveChain(s.peer.IK, []*handshake.Rotation{r})
	if err != nil {
		m.audit(s.now, "bad_rotation", s.peer.ID)
		return nil, nil
	}
	s.peer.IK, s.peer.KEM = final, kem.Bytes()
	s.peer.Chain = append(s.peer.Chain, r.Marshal())
	return nil, nil
}

// hAddressUpdate records a principal's new relay address and tokens after
// it rotated its relay key (§3.4).
func (m *Manager) hAddressUpdate(_ context.Context, s *Session, in *envelope.Inner) (json.RawMessage, error) {
	o, err := obj(in)
	if err != nil {
		return nil, err
	}
	ro, err := o.Object("relay")
	if err != nil {
		return nil, errBadRequest
	}
	var a handshake.RelayAddr
	a.URL, _ = ro.String("url")
	a.Mailbox, _ = ro.String("mailbox")
	if a.PK, err = ro.Base64("pk", ed25519.PublicKeySize); err != nil || handshake.ValidateRelayAddr(a) != nil {
		return nil, errBadRequest
	}
	np := *s.peer
	np.Relay = PeerRelay{URL: a.URL, Mailbox: a.Mailbox, PK: a.PK}
	tok, err := str(o, "token")
	if err != nil {
		return nil, err
	}
	st, err := m.heldToken(tok, &np)
	if err != nil {
		return nil, errBadRequest
	}
	var rt HeldToken
	if rs, ok, _ := o.OptString("reconnect_token"); ok {
		if rt, err = m.heldToken(rs, &np); err != nil {
			return nil, errBadRequest
		}
	}
	old := *s.peer
	s.peer.Relay, s.peer.Standing = np.Relay, st
	if rt.Token != "" {
		s.peer.Reconnect = rt
	}
	// Tokens we issued to the old key stop working after the grace period
	// (the relay denylists the old sub); issue fresh ones to the new key.
	m.denySub(&old, s.now)
	m.issueTo(s.peer, TokStanding, s.now)
	if s.peer.Kind == KindConnection {
		m.issueTo(s.peer, TokReconnect, s.now)
	}
	return nil, nil
}

// RotateIdentity rotates the vault's identity and KEM keys (§3.4): an
// identity.rotate statement signed by both keys goes to every device and
// connection, the old KEM key is retired (kept 400 days for reconnects),
// and every session is rekeyed.
func (m *Manager) RotateIdentity(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.locked {
		return ErrLocked
	}
	if err := m.rotateIdentity(m.now()); err != nil {
		return err
	}
	if err := m.persist(ctx, false); err != nil {
		return err
	}
	m.drainOutbox(ctx)
	return m.flushIfDirty(ctx)
}

// retryOwedRotation makes the rotation a recovery owes (§11.14.10 "Failure":
// audited identity.rotation_failed, kept, tried again). It never fails what
// calls it. While the recovered phone has not paired (its recovery invite is
// pending) it waits: the phone's first handshake verifies the vault's
// identity key as the open's vault_bundle gave it, and a key rotated in
// between would fail the pairing (vms/handshake/initiator.go); the pairing
// calls it (recoveredPhonePaired).
func (m *Manager) retryOwedRotation(now time.Time) {
	o := m.st.RotationOwed
	if o == nil || (o.Recovery == "" && o.Transfer == "") {
		return
	}
	for _, inv := range m.st.Invites {
		if inv.CreatedBy == inviteByRecovery {
			return
		}
	}
	ref := "recovery"
	if o.Transfer != "" {
		ref = o.Transfer
	}
	if err := m.rotateIdentity(now); err != nil {
		m.record(Activity{Kind: "identity.rotation_failed", Ref: ref, Audit: true, Feed: true, Priority: "high"}, now)
	}
}

// rotateIdentity performs the rotation in memory; the caller persists it
// (in a batch, the batch's flush does).
func (m *Manager) rotateIdentity(now time.Time) error {
	draw := suite.RandomBytes
	if m.opt.KeyRand != nil {
		draw = m.opt.KeyRand
	}
	ikSeed, err := draw(32)
	if err != nil {
		return err
	}
	kemSeed, err := draw(32)
	if err != nil {
		return err
	}
	newIK := ed25519.NewKeyFromSeed(ikSeed)
	newKEM, err := suite.NewPrivateKey(kemSeed)
	if err != nil {
		return err
	}
	rot, err := handshake.NewRotation(m.keys.ik, newIK, newKEM.Public())
	if err != nil {
		return err
	}
	m.st.Rotations = append(m.st.Rotations, rot.Marshal())
	m.st.RetiredKEMs = append(m.st.RetiredKEMs, RetiredKEM{Seed: m.st.KEMSeed, RetiredAt: now})
	m.keys.retired = append(m.keys.retired, m.keys.kem)
	m.st.IdentitySeed, m.st.KEMSeed = ikSeed, kemSeed
	m.keys.ik, m.keys.kem = newIK, newKEM
	body := strictjson.NewBuilder().Raw("rotation", rot.Marshal()).Bytes()
	for _, p := range m.allPeers() {
		if p.State == PeerActive {
			m.sendTo(p, "identity.rotate", body, now)
			m.startRekey(p, now)
		}
	}
	m.dirty = true
	// One rotation clears every owed mark (§11.14.10); its audit entry
	// says which: ref "recovery" when it cleared a recovery's, none when
	// nothing was owed (0.69.2; a transfer's mark would carry its
	// transfer_id).
	ref := ""
	if o := m.st.RotationOwed; o != nil {
		switch {
		case o.Transfer != "":
			ref = o.Transfer // wins when one rotation clears both
		case o.Recovery != "":
			ref = "recovery"
		}
		m.st.RotationOwed = nil
	}
	m.record(Activity{Kind: "identity.rotated", Ref: ref, Audit: true}, now)
	// §10.8 (0.18.0): the core's ik changed; each connection gets the
	// update once its epoch under the new ik is active.
	m.profileCoreChanged(now)
	return nil
}

// pruneRetiredKEMs drops retired KEM keys after 400 days (§6.6).
func (m *Manager) pruneRetiredKEMs(now time.Time) {
	var keep []RetiredKEM
	var keys []*suite.PrivateKey
	for i, r := range m.st.RetiredKEMs {
		if now.Sub(r.RetiredAt) < handshake.RetiredKEMRetention {
			keep = append(keep, r)
			keys = append(keys, m.keys.retired[i])
		} else {
			m.keys.retired[i].Destroy()
		}
	}
	m.st.RetiredKEMs, m.keys.retired = keep, keys
}
