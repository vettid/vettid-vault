package vault

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"sort"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
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
	r("connection.invite.create", true, owners, m.hInviteCreate)
	r("connection.invite.list", true, owners, m.hInviteList)
	r("connection.invite.cancel", true, owners, m.hInviteCancel)
	r("connection.invite.accept", true, owners, m.hInviteAccept)
	r("connection.approve", true, owners, m.hConnApprove)
	r("connection.decline", true, owners, m.hConnDecline)
	r("connection.list", true, owners, m.hConnList)
	r("connection.get", true, owners, m.hConnGet)
	r("connection.remove", true, owners, m.hConnRemove)
	r("connection.removed", false, conns, m.hConnRemoved)
	r(tokenIssuedType, false, all, m.hTokenIssued)
	r(tokenRefreshType, true, all, m.hTokenRefresh)
	r("identity.rotate", false, conns, m.hIdentityRotate)
	r("relay.address.update", false, all, m.hAddressUpdate)
	r("settings.get", true, owners, m.hSettingsGet)
	r("settings.set", true, owners, m.hSettingsSet)
	m.registerAccess()
	m.registerConnections()
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
	return strictjson.NewBuilder().String("vault_id", m.st.VaultID).Uint("state_seq", m.st.StateSeq).
		Uint("header_seq", m.hdr.HeaderSeq).Bool("provisional", m.hdr.Provisional).
		Uint("devices", uint64(len(m.st.Devices))).Uint("connections", uint64(len(m.st.Connections))).Bytes(), nil
}

func (m *Manager) hLock(_ context.Context, _ *Session, _ *envelope.Inner) (json.RawMessage, error) {
	m.lockPending = true // after this batch: flush, vault.locking, zeroize (§12.3)
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
	inv, link, err := m.createInvite(ctx, role, PairingApprovalTTL, s.peer.ID, s.now)
	if err != nil {
		return nil, NewError("relay_error", "")
	}
	return strictjson.NewBuilder().String("pairing_id", inv.ID).String("link", link).
		String("exp", inv.Exp.UTC().Format(time.RFC3339)).Bytes(), nil
}

func (m *Manager) inboundFor(inviteID, kind string) string {
	for id, ib := range m.st.Inbound {
		if (ib.InviteID == inviteID || id == inviteID) && (kind == "" || (kind == KindConnection) == (ib.Kind == KindConnection)) {
			return id
		}
	}
	return ""
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
	id := m.inboundFor(pid, "device")
	if id == "" {
		return nil, errNotFound
	}
	// An initial access session for a desktop or agent may come with the
	// pairing approval (§6.8).
	secs, present, err := accessSeconds(o, "session_seconds")
	if err != nil || present && !needsAccess(m.st.Inbound[id].Kind) {
		return nil, errBadRequest
	}
	if present {
		m.pairAccess = &pendingAccess{inbound: id, seconds: secs, by: s.peer.ID}
		defer func() { m.pairAccess = nil }()
	}
	if err := m.approveInbound(ctx, id, s.now); err != nil {
		return nil, NewError("approve_failed", "")
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
	id := m.inboundFor(pid, "device")
	if id == "" {
		return nil, errNotFound
	}
	if inv := m.st.Invites[m.st.Inbound[id].InviteID]; inv != nil && inv.OpenJTI != "" {
		m.denyJTI(inv.OpenJTI, s.now)
	}
	m.dropInbound(id)
	return nil, nil
}

func (m *Manager) hDeviceList(_ context.Context, s *Session, _ *envelope.Inner) (json.RawMessage, error) {
	return peersJSON("devices", m.st.Devices, s.now), nil
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
	m.endAccess(context.Background(), p, false, "", s.now) // its access session and held requests go with it
	m.removePeer(p, "device.unlinked", s.now)
	m.record(Activity{Kind: "device.unlinked", DeviceID: id, Audit: true, Feed: true}, s.now)
	m.notifyDevices("sync.event", strictjson.NewBuilder().String("kind", "device.unlinked").String("device_id", id).Bytes(), "", s.now)
	return nil, nil
}

// removePeer sends a best-effort notice, denylists the peer's sub, and
// deletes its tokens, sessions and outbox entries (§7.4).
func (m *Manager) removePeer(p *Peer, notice string, now time.Time) {
	if kr := m.sessions[p.ID]; kr != nil && kr.Current() != nil && p.Standing.Token != "" && p.State == PeerActive {
		in := &envelope.Inner{ID: m.newID(now), Type: notice, TS: now, Body: json.RawMessage(`{}`)}
		if raw, err := kr.Current().Seal(in); err == nil {
			m.queueDeposit(&OutboxEntry{RelayURL: p.Relay.URL, Mailbox: p.Relay.Mailbox, Token: p.Standing.Token,
				Payload: raw, BestEffort: true}, now)
		}
	}
	m.denySub(p, now)
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
	p, err := m.acceptInvite(ctx, link, s.now)
	if err != nil {
		if he, ok := err.(*HandlerError); ok {
			return nil, he
		}
		return nil, NewError("accept_failed", "")
	}
	return strictjson.NewBuilder().String("connection_id", p.ID).String("state", PeerPending).Bytes(), nil
}

func (m *Manager) hConnApprove(ctx context.Context, s *Session, in *envelope.Inner) (json.RawMessage, error) {
	o, err := obj(in)
	if err != nil {
		return nil, err
	}
	pid, err := str(o, "pending_id")
	if err != nil {
		return nil, err
	}
	id := m.inboundFor(pid, KindConnection)
	if id == "" {
		return nil, errNotFound
	}
	if err := m.approveInbound(ctx, id, s.now); err != nil {
		return nil, NewError("approve_failed", "")
	}
	return nil, nil
}

func (m *Manager) hConnDecline(_ context.Context, s *Session, in *envelope.Inner) (json.RawMessage, error) {
	o, err := obj(in)
	if err != nil {
		return nil, err
	}
	pid, err := str(o, "pending_id")
	if err != nil {
		return nil, err
	}
	id := m.inboundFor(pid, KindConnection)
	if id == "" {
		return nil, errNotFound
	}
	m.dropInbound(id)
	return nil, nil
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

func (m *Manager) hTokenRefresh(_ context.Context, s *Session, _ *envelope.Inner) (json.RawMessage, error) {
	tok, issued, err := m.mintStanding(s.peer, s.now, nil)
	if err != nil {
		return nil, NewError("relay_error", "")
	}
	m.st.Issued = append(m.st.Issued, issued...)
	return strictjson.NewBuilder().String("kind", TokStanding).String("token", tok).Bytes(), nil
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

// rotateIdentity performs the rotation in memory; the caller persists it
// (in a batch, the batch's flush does).
func (m *Manager) rotateIdentity(now time.Time) error {
	ikSeed, err := suite.RandomBytes(32)
	if err != nil {
		return err
	}
	kemSeed, err := suite.RandomBytes(32)
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
	m.record(Activity{Kind: "identity.rotated", Audit: true}, now)
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
