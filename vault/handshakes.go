package vault

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/invite"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Handshake time limits.
const (
	PairingApprovalTTL = 10 * time.Minute    // §6.7
	ConnectionPending  = 7 * 24 * time.Hour  // remote invites stay pending at most the longest TTL
	HandshakeTTL       = 16 * 24 * time.Hour // awaiting hs.resp / hs.fin
	EnrollWindow       = 24 * time.Hour      // provisional window (§11.3)
)

func policyFor(kind string) handshake.Policy {
	if kind == KindConnection {
		return handshake.PolicyVaultToVault
	}
	return handshake.PolicyVaultToDevice
}

func (m *Manager) ownAddr() handshake.RelayAddr {
	return handshake.RelayAddr{URL: m.st.Relay.URL, Mailbox: m.st.Relay.Mailbox, PK: m.keys.relay.Public().(ed25519.PublicKey)}
}

func peerFromPrincipal(id, kind string, pr handshake.Principal, now time.Time) *Peer {
	return &Peer{ID: id, Kind: kind, State: PeerPending, IK: pr.IK, KEM: pr.KEM.Bytes(),
		Relay: PeerRelay{URL: pr.Relay.URL, Mailbox: pr.Relay.Mailbox, PK: pr.Relay.PK}, CreatedAt: now}
}

func (m *Manager) newID(now time.Time) string {
	id, err := envelope.NewULID(now)
	if err != nil {
		panic("vault: randomness unavailable")
	}
	return id
}

// handleInit processes a sealed hs.init addressed to the vault's static KEM
// key (§6.1): first contact on an open token (pairing, invitation, the
// first app after enrollment) or a reconnect (§6.6).
func (m *Manager) handleInit(ctx context.Context, raw []byte, sender ed25519.PublicKey, p *Peer, now time.Time) disposition {
	pi, err := handshake.OpenInit(raw, m.lookupKEM, now)
	if err != nil {
		m.audit(now, "hs_init_rejected", peerID(p))
		return ackAfterFlush
	}
	body := pi.Init()
	if !suite.EqualPublic(sender, body.From.Relay.PK) { // §6.3
		m.audit(now, "hs_init_sender_mismatch", peerID(p))
		return ackAfterFlush
	}
	if body.Purpose == handshake.PurposeReconnect {
		if p == nil || p.Kind != KindConnection {
			m.audit(now, "reconnect_unknown_peer", "")
			return ackAfterFlush
		}
		if err := handshake.CheckReconnectTokenUse(envelope.ModeSealed, pi); err != nil {
			m.audit(now, "reconnect_token_misuse", p.ID)
			return ackAfterFlush
		}
		m.respondReconnect(pi, p, sender, now)
		return ackAfterFlush
	}
	if p != nil {
		m.audit(now, "hs_init_from_known_peer", p.ID)
		return ackAfterFlush
	}
	// §6.7: a re-paired device MUST use a new relay key; a relay key whose
	// sub we denylisted (unlinked device, removed connection) is refused.
	if m.subDenied(sender) {
		m.audit(now, "hs_init_from_revoked_key", "")
		return ackAfterFlush
	}
	inv := m.st.Invites[body.Ctx]
	if inv == nil || inv.Used || !now.Before(inv.Exp) || inv.Kind != string(body.Purpose) {
		m.audit(now, "invite_invalid", "")
		return ackAfterFlush // single use; expired, used or revoked invites are rejected (§6.4)
	}
	if inv.EnrollIK != nil {
		// The first app (§11.3): its identity was bound at enrollment.
		if !suite.EqualPublic(body.From.IK, inv.EnrollIK) || !suite.EqualPublic(sender, inv.EnrollRelayPK) {
			m.audit(now, "enroll_identity_mismatch", "")
			return ackAfterFlush
		}
	}
	inv.Used = true
	if inv.OpenJTI != "" {
		m.queueRevoke("jti", inv.OpenJTI, now)
	}
	if inv.ClaimID != "" {
		m.queueDeleteClaim(inv.ClaimID, now)
	}
	id := m.newID(now)
	exp := now.Add(PairingApprovalTTL)
	if inv.Kind == KindConnection {
		exp = now.Add(ConnectionPending)
	}
	ps, err := pi.Export()
	if err != nil {
		return ackAfterFlush
	}
	m.st.Inbound[id] = &InboundHS{ID: id, InviteID: inv.ID, Kind: inv.Kind, Remote: inv.Remote, Sender: sender,
		Created: now, Expires: exp, Pending: ps}
	m.inbound[id] = pi
	switch {
	case inv.EnrollIK != nil:
		_ = m.approveInbound(ctx, id, now) // pre-authorized at enrollment
	case inv.Kind == KindConnection:
		if invite.AutoApproveAllowed(inv.Remote, false, m.st.Settings.AutoApproveInPerson) {
			_ = m.approveInbound(ctx, id, now)
			break
		}
		// §6.4: remote invites stay pending until the owner approves; the
		// profile is self-asserted and shown as such, with the SAS.
		b := strictjson.NewBuilder().String("pending_id", id).String("invite_id", inv.ID).
			String("sas", pi.SAS()).Bool("remote", inv.Remote)
		if len(body.Profile) > 0 {
			b.Raw("profile", body.Profile)
		}
		m.notifyDevices("connection.request.pending", b.Bytes(), "", now)
	default:
		// §6.7: approval first; only apps approve.
		b := strictjson.NewBuilder().String("pairing_id", inv.ID).String("pending_id", id).
			String("role", inv.Kind).String("name", profileName(body.Profile)).String("sas", pi.SAS())
		m.notifyApps("device.pair.pending", b.Bytes(), now)
	}
	return ackAfterFlush
}

func profileName(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	o, err := strictjson.ParseObject(raw)
	if err != nil {
		return ""
	}
	n, _, _ := o.OptString("name")
	if len(n) > 128 {
		n = n[:128]
	}
	return n
}

// approveInbound answers a pending hs.init: this is the approval point
// (§6.4, §6.7). It mints the tokens for the new principal and deposits
// hs.resp.
func (m *Manager) approveInbound(ctx context.Context, id string, now time.Time) error {
	ib, pi := m.st.Inbound[id], m.inbound[id]
	if ib == nil || pi == nil {
		return errNotFound
	}
	body := pi.Init()
	newPeer := peerFromPrincipal(m.newID(now), ib.Kind, body.From, now)
	newPeer.Name = profileName(body.Profile)
	newPeer.Profile = body.Profile
	cfg := handshake.ResponderConfig{Identity: m.keys.ik, Policy: policyFor(ib.Kind), CollectSender: ib.Sender, Now: now}
	var issued []IssuedToken
	var err error
	if cfg.Token, issued, err = m.mintStanding(newPeer, now, issued); err != nil {
		return err
	}
	if ib.Kind == KindConnection {
		if cfg.ReconnectToken, issued, err = m.mintReconnect(newPeer, now, issued); err != nil {
			return err
		}
	}
	resp, env, err := pi.Respond(cfg)
	if err != nil {
		m.audit(now, "respond_failed", "")
		m.dropInbound(id)
		return err
	}
	if newPeer.Standing, err = m.heldToken(body.Token, newPeer); err != nil {
		resp.Abort()
		m.dropInbound(id)
		return err
	}
	if body.ReconnectToken != "" {
		if newPeer.Reconnect, err = m.heldToken(body.ReconnectToken, newPeer); err != nil {
			resp.Abort()
			m.dropInbound(id)
			return err
		}
	}
	rs, err := resp.Export()
	if err != nil {
		return err
	}
	m.st.Awaiting[id] = &AwaitingHS{ID: id, PeerID: newPeer.ID, New: newPeer, Purpose: body.Purpose, Created: now, Resp: rs, Issued: issued}
	m.awaiting[id] = resp
	m.queueDeposit(&OutboxEntry{Op: OpDeposit, RelayURL: newPeer.Relay.URL, Mailbox: newPeer.Relay.Mailbox,
		Token: body.Token, Payload: env}, now)
	delete(m.st.Inbound, id)
	delete(m.inbound, id)
	return nil
}

func (m *Manager) dropInbound(id string) {
	if pi := m.inbound[id]; pi != nil {
		pi.Discard()
	}
	delete(m.inbound, id)
	delete(m.st.Inbound, id)
}

// respondReconnect answers a reconnect hs.init (§6.6): no SAS or approval,
// but the sender must be the relay key on record (the reconnect token's
// sub), from.ik must be the stored ik or reached through a valid chain, and
// sig_I is verified in hs.fin.
func (m *Manager) respondReconnect(pi *handshake.PendingInit, p *Peer, sender ed25519.PublicKey, now time.Time) {
	cfg := handshake.ResponderConfig{
		Identity: m.keys.ik, Policy: policyFor(p.Kind), PinnedSuite: p.Suite,
		CollectSender: sender, RecordRelayKey: p.Relay.PK, KnownInitiatorIK: p.IK,
		ExpectedCtx: handshake.EpochCtx(epochIDOf(p.LastEpochID)), Now: now,
		Rotations: m.ownRotationsSince(p.OwnChainAtEpoch),
	}
	var issued []IssuedToken
	var err error
	if cfg.Token, issued, err = m.mintStanding(p, now, issued); err != nil {
		return
	}
	if cfg.ReconnectToken, issued, err = m.mintReconnect(p, now, issued); err != nil {
		return
	}
	resp, env, err := pi.Respond(cfg)
	if err != nil {
		m.audit(now, "reconnect_refused", p.ID)
		return
	}
	body := pi.Init()
	// The peer's identity may have advanced through its chain.
	if len(body.Rotations) > 0 {
		p.IK = body.From.IK
		p.KEM = body.From.KEM.Bytes()
		for _, r := range body.Rotations {
			p.Chain = append(p.Chain, r.Marshal())
		}
	}
	st, err1 := m.heldToken(body.Token, p)
	rt, err2 := m.heldToken(body.ReconnectToken, p)
	if err1 != nil || err2 != nil {
		resp.Abort()
		return
	}
	p.Standing, p.Reconnect = st, rt
	rs, err := resp.Export()
	if err != nil {
		return
	}
	id := m.newID(now)
	m.st.Awaiting[id] = &AwaitingHS{ID: id, PeerID: p.ID, Purpose: handshake.PurposeReconnect, Created: now, Resp: rs, Issued: issued}
	m.awaiting[id] = resp
	m.queueDeposit(&OutboxEntry{Op: OpDeposit, PeerID: p.ID, RelayURL: p.Relay.URL, Mailbox: p.Relay.Mailbox, Payload: env}, now)
}

func epochIDOf(b []byte) [suite.EpochIDSize]byte {
	var id [suite.EpochIDSize]byte
	copy(id[:], b)
	return id
}

// handleRekeyInit handles a rekey hs.init that arrived in session mode
// (§6.2, §6.5).
func (m *Manager) handleRekeyInit(ctx context.Context, p *Peer, in *envelope.Inner, ep *handshake.Epoch, raw []byte, sender ed25519.PublicKey, now time.Time) disposition {
	kr := m.sessions[p.ID]
	if kr == nil || kr.Current() != ep {
		m.audit(now, "rekey_not_current_epoch", p.ID)
		return ackAfterFlush
	}
	pi, err := handshake.AcceptRekey(raw, in, ep, now)
	if err != nil {
		m.audit(now, "rekey_rejected", p.ID)
		return ackAfterFlush
	}
	// Crossing rekeys: the lower th1 wins (§6.5).
	for id, og := range m.st.Outgoing {
		if og.PeerID == p.ID && og.Purpose == handshake.PurposeRekey {
			var ours [32]byte
			copy(ours[:], og.Th1)
			if handshake.SimultaneousRekeyWinner(ours, pi.Th1()) {
				pi.Discard()
				return ackAfterFlush
			}
			m.dropOutgoing(id)
		}
	}
	resp, env, err := pi.Respond(handshake.ResponderConfig{
		Identity: m.keys.ik, Policy: policyFor(p.Kind), PinnedSuite: p.Suite,
		CollectSender: sender, RecordRelayKey: p.Relay.PK, KnownInitiatorIK: p.IK, Now: now,
	})
	if err != nil {
		m.audit(now, "rekey_refused", p.ID)
		return ackAfterFlush
	}
	rs, err := resp.Export()
	if err != nil {
		return ackAfterFlush
	}
	id := m.newID(now)
	m.st.Awaiting[id] = &AwaitingHS{ID: id, PeerID: p.ID, Purpose: handshake.PurposeRekey, Created: now, Resp: rs}
	m.awaiting[id] = resp
	m.queueDeposit(&OutboxEntry{Op: OpDeposit, PeerID: p.ID, RelayURL: p.Relay.URL, Mailbox: p.Relay.Mailbox, Payload: env}, now)
	return ackAfterFlush
}

// awaitingByKids finds the handshake awaiting this hs.fin by its new-epoch
// kids and the expected sender.
func (m *Manager) awaitingByKids(env *envelope.Envelope, sender ed25519.PublicKey) string {
	for id, r := range m.awaiting {
		rk, sk := r.Kids()
		if !env.RecipientKid().Equal(rk) || !env.SenderKid().Equal(sk) {
			continue
		}
		aw := m.st.Awaiting[id]
		var pk []byte
		if aw.New != nil {
			pk = aw.New.Relay.PK
		} else if p := m.peer(aw.PeerID); p != nil {
			pk = p.Relay.PK
		}
		if suite.EqualPublic(pk, sender) {
			return id
		}
	}
	return ""
}

func (m *Manager) peer(id string) *Peer {
	if p, ok := m.st.Devices[id]; ok {
		return p
	}
	return m.st.Connections[id]
}

// handleFin completes a handshake the vault responded to. The epoch is
// activated only after sig_I verifies (§6.3); a bad hs.fin is dropped and
// the handshake stays pending until it expires.
func (m *Manager) handleFin(ctx context.Context, id string, raw []byte, sender ed25519.PublicKey, now time.Time) disposition {
	aw, r := m.st.Awaiting[id], m.awaiting[id]
	ep, _, err := r.HandleFin(raw, sender, now)
	if errors.Is(err, handshake.ErrType) {
		// A message in the new epoch that arrived before hs.fin: the epoch
		// is not active yet, so leave it unacked for redelivery (§6.3).
		return noAck
	}
	if err != nil {
		m.audit(now, "hs_fin_rejected", aw.PeerID)
		return ackAfterFlush
	}
	p := aw.New
	if p == nil {
		p = m.peer(aw.PeerID)
	}
	delete(m.st.Awaiting, id)
	delete(m.awaiting, id)
	if p == nil {
		ep.Destroy()
		return ackAfterFlush
	}
	m.activate(p, ep, aw.Purpose, aw.Issued, now)
	return ackAfterFlush
}

// activate installs a new epoch for p and finishes the bookkeeping of a
// completed handshake.
func (m *Manager) activate(p *Peer, ep *handshake.Epoch, purpose handshake.Purpose, issued []IssuedToken, now time.Time) {
	isNew := m.peer(p.ID) == nil
	if isNew {
		if p.Kind == KindConnection {
			m.st.Connections[p.ID] = p
		} else {
			m.st.Devices[p.ID] = p
		}
		m.sessions[p.ID] = &handshake.Keyring{}
	}
	kr := m.sessions[p.ID]
	if kr == nil {
		kr = &handshake.Keyring{}
		m.sessions[p.ID] = kr
	}
	kr.Activate(ep, now)
	id := ep.ID()
	p.LastEpochID = id[:]
	p.OwnChainAtEpoch = len(m.st.Rotations)
	if ep.Suite() > p.Suite {
		p.Suite = ep.Suite() // §13.4 pin
	}
	p.State = PeerActive
	for _, t := range issued {
		t.PeerID = p.ID
		m.st.Issued = append(m.st.Issued, t)
	}
	switch {
	case isNew && p.Kind == KindConnection:
		m.notifyDevices("connection.event", connEvent(p.ID, "added"), "", now)
	case isNew:
		b := strictjson.NewBuilder().String("device_id", p.ID).String("role", p.Kind).String("vault_id", m.st.VaultID).Bytes()
		m.sendTo(p, "device.paired", b, now)
		m.notifyDevices("sync.event", strictjson.NewBuilder().String("kind", "device.paired").String("device_id", p.ID).
			String("role", p.Kind).Bytes(), p.ID, now)
	case purpose == handshake.PurposeReconnect:
		m.notifyDevices("connection.event", connEvent(p.ID, "reconnected"), "", now)
		m.retryPeer(p.ID)
	case purpose == handshake.PurposeRekey && p.Kind == KindConnection:
		m.notifyDevices("connection.event", connEvent(p.ID, "rekeyed"), "", now)
	}
}

func connEvent(id, ev string) json.RawMessage {
	return strictjson.NewBuilder().String("connection_id", id).String("event", ev).Bytes()
}

// handleResp processes hs.resp for a handshake the vault initiated.
func (m *Manager) handleResp(ctx context.Context, id string, raw []byte, sender ed25519.PublicKey, now time.Time) disposition {
	og, ini := m.st.Outgoing[id], m.outgoing[id]
	res, err := ini.HandleResp(raw, sender, now)
	if err != nil {
		if _, xerr := ini.Export(); errors.Is(xerr, handshake.ErrDone) {
			// Aborted (§6.3): the handshake is gone.
			m.audit(now, "hs_resp_aborted", og.PeerID)
			delete(m.st.Outgoing, id)
			delete(m.outgoing, id)
			if og.New != nil {
				m.notifyDevices("connection.event", connEvent(og.PeerID, "failed"), "", now)
			}
		} else {
			m.audit(now, "hs_resp_dropped", og.PeerID)
		}
		return ackAfterFlush
	}
	delete(m.st.Outgoing, id)
	delete(m.outgoing, id)
	p := og.New
	if p == nil {
		p = m.peer(og.PeerID)
	}
	if p == nil {
		res.Epoch.Destroy()
		return ackAfterFlush
	}
	if res.Resp.Token != "" {
		if t, err := m.heldToken(res.Resp.Token, p); err == nil {
			p.Standing = t
		}
	}
	if res.Resp.ReconnectToken != "" {
		if t, err := m.heldToken(res.Resp.ReconnectToken, p); err == nil {
			p.Reconnect = t
		}
	}
	if og.Purpose == handshake.PurposeReconnect && !suite.EqualPublic(res.ResponderIK, p.IK) {
		p.IK = res.ResponderIK
		if res.ResponderKEM != nil {
			p.KEM = res.ResponderKEM.Bytes()
		}
		for _, r := range res.Resp.Rotations {
			p.Chain = append(p.Chain, r.Marshal())
		}
	}
	fin := res.Fin
	m.activate(p, res.Epoch, og.Purpose, og.Issued, now)
	m.queueDeposit(&OutboxEntry{Op: OpDeposit, PeerID: p.ID, RelayURL: p.Relay.URL, Mailbox: p.Relay.Mailbox, Payload: fin}, now)
	return ackAfterFlush
}

func (m *Manager) dropOutgoing(id string) {
	if i := m.outgoing[id]; i != nil {
		i.Abort()
	}
	delete(m.outgoing, id)
	delete(m.st.Outgoing, id)
}

func (m *Manager) recordOutgoing(ini *handshake.Initiator, peerID string, newPeer *Peer, purpose handshake.Purpose, issued []IssuedToken, now time.Time) (string, error) {
	s, err := ini.Export()
	if err != nil {
		return "", err
	}
	id := m.newID(now)
	kid := ini.EphKid()
	th1 := ini.Th1()
	m.st.Outgoing[id] = &OutgoingHS{ID: id, PeerID: peerID, New: newPeer, Purpose: purpose,
		EphKid: kid[:], Th1: th1[:], Created: now, Init: s, Issued: issued}
	m.outgoing[id] = ini
	return id, nil
}

func (m *Manager) hasOutgoing(peerID string, purpose handshake.Purpose) bool {
	for _, og := range m.st.Outgoing {
		if og.PeerID == peerID && og.Purpose == purpose {
			return true
		}
	}
	return false
}

// startRekey initiates a rekey of p's session (§6.5).
func (m *Manager) startRekey(p *Peer, now time.Time) {
	kr := m.sessions[p.ID]
	if kr == nil || kr.Current() == nil || m.hasOutgoing(p.ID, handshake.PurposeRekey) || p.Standing.Token == "" {
		return
	}
	ini, err := handshake.NewInitiator(handshake.InitiatorConfig{
		Purpose: handshake.PurposeRekey, Identity: m.keys.ik, StaticKEM: m.keys.kem.Public(), Relay: m.ownAddr(),
		ResponderIK: p.IK, ResponderRelayKey: p.Relay.PK, Current: kr.Current(), PinnedSuite: p.Suite,
		Policy: policyFor(p.Kind), Now: now,
	})
	if err != nil {
		return
	}
	if _, err := m.recordOutgoing(ini, p.ID, nil, handshake.PurposeRekey, nil, now); err != nil {
		return
	}
	m.queueDeposit(&OutboxEntry{Op: OpDeposit, PeerID: p.ID, RelayURL: p.Relay.URL, Mailbox: p.Relay.Mailbox, Payload: ini.Envelope()}, now)
}

// startReconnect initiates a reconnect to connection p with its reconnect
// token (§6.6).
func (m *Manager) startReconnect(p *Peer, now time.Time) {
	if p.Kind != KindConnection || m.hasOutgoing(p.ID, handshake.PurposeReconnect) ||
		p.Reconnect.Token == "" || !now.Before(p.Reconnect.Exp) || len(p.LastEpochID) == 0 {
		return
	}
	kem, err := suite.ParsePublicKey(p.KEM)
	if err != nil {
		return
	}
	var issued []IssuedToken
	cfg := handshake.InitiatorConfig{
		Purpose: handshake.PurposeReconnect, Ctx: handshake.EpochCtx(epochIDOf(p.LastEpochID)),
		Identity: m.keys.ik, StaticKEM: m.keys.kem.Public(), Relay: m.ownAddr(),
		Rotations:   m.ownRotationsSince(p.OwnChainAtEpoch),
		ResponderIK: p.IK, ResponderEK: kem, ResponderRelayKey: p.Relay.PK, PinnedSuite: p.Suite,
		Policy: policyFor(p.Kind), Now: now,
	}
	if cfg.Token, issued, err = m.mintStanding(p, now, issued); err != nil {
		return
	}
	if cfg.ReconnectToken, issued, err = m.mintReconnect(p, now, issued); err != nil {
		return
	}
	ini, err := handshake.NewInitiator(cfg)
	if err != nil {
		return
	}
	if _, err := m.recordOutgoing(ini, p.ID, nil, handshake.PurposeReconnect, issued, now); err != nil {
		return
	}
	m.queueDeposit(&OutboxEntry{Op: OpDeposit, RelayURL: p.Relay.URL, Mailbox: p.Relay.Mailbox,
		Token: p.Reconnect.Token, Payload: ini.Envelope()}, now)
}

// reconnectExpired starts reconnects for connections whose standing token
// we hold has expired (§7.2 step 3).
func (m *Manager) reconnectExpired(now time.Time) {
	for _, p := range m.st.Connections {
		if p.State != PeerPending && handshake.ShouldUseReconnect(false, p.Standing.Exp, now) {
			m.startReconnect(p, now)
		}
	}
}

func (m *Manager) ownRotationsSince(n int) []*handshake.Rotation {
	var out []*handshake.Rotation
	for i := n; i < len(m.st.Rotations); i++ {
		if r, err := handshake.ParseRotation(m.st.Rotations[i]); err == nil {
			out = append(out, r)
		}
	}
	return out
}

// createInvite makes a connection invitation or a pairing (§6.4, §6.7): an
// open token, an encrypted bundle left as a claim, and the QR / link.
func (m *Manager) createInvite(ctx context.Context, kind string, ttl time.Duration, by string, now time.Time) (*Invite, string, error) {
	remote := kind == KindConnection && invite.IsRemote(ttl)
	limits := invite.RelayLimits{
		OpenTokenMaxLifetime: time.Duration(m.limits.OpenTokenMaxLifetimeSeconds) * time.Second,
		ClaimTTL:             time.Duration(m.limits.ClaimTTLSeconds) * time.Second,
	}
	if err := invite.CheckTTL(ttl, limits); err != nil {
		return nil, "", err
	}
	id := m.newID(now)
	jti := m.newID(now)
	tok, err := m.relay.MintOpenToken(ttl, jti)
	if err != nil {
		return nil, "", err
	}
	exp := now.Add(ttl).Truncate(time.Second)
	b := &invite.Bundle{Kind: kind, InviteID: id, Remote: remote,
		Vault: handshake.Principal{IK: m.keys.ik.Public().(ed25519.PublicKey), KEM: m.keys.kem.Public(), Relay: m.ownAddr()},
		Token: tok, Exp: exp}
	bj, err := b.Marshal()
	if err != nil {
		return nil, "", err
	}
	blob, kb, h, err := invite.SealBundle(bj)
	if err != nil {
		return nil, "", err
	}
	claimID, _, err := m.relay.PutClaim(ctx, blob, ttl)
	if err != nil {
		return nil, "", err
	}
	qk := map[string]invite.Kind{"connection": invite.KindConnection, "app": invite.KindApp, "desktop": invite.KindDesktop, "agent": invite.KindAgent}[kind]
	q := &invite.QR{Kind: qk, Relay: m.st.Relay.URL, ClaimID: claimID, Hash: h, Key: kb, Exp: exp.Unix()}
	link, err := q.Link()
	if err != nil {
		return nil, "", err
	}
	inv := &Invite{ID: id, Kind: kind, Remote: remote, Exp: exp, OpenJTI: jti, ClaimID: claimID, CreatedBy: by}
	m.st.Invites[id] = inv
	m.st.Issued = append(m.st.Issued, IssuedToken{JTI: jti, Kind: TokOpen, Sub: "*", Exp: exp})
	return inv, link, nil
}

// acceptInvite starts a connection from an invitation link (§6.4): fetch
// the claim, check the commitment, decrypt the bundle, and send hs.init on
// the open token.
func (m *Manager) acceptInvite(ctx context.Context, link string, now time.Time) (*Peer, error) {
	q, err := invite.ParseLink(link)
	if err != nil || q.Kind != invite.KindConnection {
		return nil, errBadRequest
	}
	blob, err := m.relay.GetClaim(ctx, q.Relay, q.ClaimID)
	if err != nil {
		return nil, errClaim
	}
	b, err := invite.OpenBundle(blob, q, now)
	if err != nil {
		return nil, errBadRequest
	}
	if suite.EqualPublic(b.Vault.IK, m.keys.ik.Public().(ed25519.PublicKey)) {
		return nil, errBadRequest // our own invitation
	}
	p := peerFromPrincipal(m.newID(now), KindConnection, b.Vault, now)
	var issued []IssuedToken
	cfg := handshake.InitiatorConfig{
		Purpose: handshake.PurposeConnection, Ctx: b.InviteID,
		Identity: m.keys.ik, StaticKEM: m.keys.kem.Public(), Relay: m.ownAddr(),
		ResponderIK: b.Vault.IK, ResponderEK: b.Vault.KEM, ResponderRelayKey: b.Vault.Relay.PK,
		Policy: handshake.PolicyVaultToVault, Now: now,
	}
	if cfg.Token, issued, err = m.mintStanding(p, now, issued); err != nil {
		return nil, err
	}
	if cfg.ReconnectToken, issued, err = m.mintReconnect(p, now, issued); err != nil {
		return nil, err
	}
	ini, err := handshake.NewInitiator(cfg)
	if err != nil {
		return nil, err
	}
	if _, err := m.recordOutgoing(ini, p.ID, p, handshake.PurposeConnection, issued, now); err != nil {
		return nil, err
	}
	m.queueDeposit(&OutboxEntry{Op: OpDeposit, RelayURL: b.Vault.Relay.URL, Mailbox: b.Vault.Relay.Mailbox,
		Token: b.Token, Payload: ini.Envelope()}, now)
	return p, nil
}

// enrollApp binds the first app (§11.3) and deposits vault.enrolled on the
// app's open token. Dev builds have no attestation: the field is absent.
func (m *Manager) enrollApp(ctx context.Context, app *EnrollApp, now time.Time) error {
	bundle := strictjson.NewBuilder().Uint("v", 1).Uint("suite", uint64(suite.Suite2)).
		Raw("vault", handshake.MarshalPrincipal(handshake.Principal{IK: m.keys.ik.Public().(ed25519.PublicKey), KEM: m.keys.kem.Public(), Relay: m.ownAddr()})).
		Bytes()
	pseudo := &Peer{ID: "enroll", Kind: KindApp, Relay: app.Relay}
	tok, issued, err := m.mintStanding(pseudo, now, nil)
	if err != nil {
		return err
	}
	m.st.Issued = append(m.st.Issued, issued...)
	m.st.Invites[m.st.VaultID] = &Invite{ID: m.st.VaultID, Kind: KindApp, Exp: now.Add(EnrollWindow),
		EnrollIK: app.IK, EnrollRelayPK: app.Relay.PK, CreatedBy: "enroll"}
	reqID := app.RequestID
	if reqID == "" {
		reqID = m.newID(now)
	}
	body := strictjson.NewBuilder().String("request_id", reqID).String("vault_id", m.st.VaultID).
		Uint("state_seq", m.st.StateSeq+1).Base64("vault_bundle", bundle).String("token", tok).Bytes()
	in := &envelope.Inner{ID: reqID, Type: "vault.enrolled", TS: now, Body: body}
	padded, err := envelope.EncodeInner(in, envelope.ModeSealed)
	if err != nil {
		return err
	}
	env, _, err := envelope.SealSealed(app.KEM, suite.Anonymous, padded)
	if err != nil {
		return err
	}
	m.queueDeposit(&OutboxEntry{Op: OpDeposit, RelayURL: app.Relay.URL, Mailbox: app.Relay.Mailbox, Token: app.OpenToken, Payload: env}, now)
	return nil
}
