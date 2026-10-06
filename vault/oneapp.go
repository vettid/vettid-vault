package vault

import (
	"context"
	"crypto/subtle"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/altchan"
	"github.com/vettid/vettid-vault/vms/suite"
)

// One app per vault (VAULT-MESSAGING 0.9.0, owner decision of 2026-10-03):
// the vault has exactly one device of role app, the holder of the Protean
// Credential. A second app cannot pair (one_app); the app moves to a new
// phone by a direct transfer (§6.7.1), or a recovery replaces it
// (§11.11.5). Desktops and agents are unaffected. The credential feature
// keeps the holder and the clone alarm (§3.5.9); this file is the runtime
// side: the transfer, the PIN check it needs, the removal of a replaced
// app, and the host alarm report (§11.5).

// Transfer states (§6.7.1).
const (
	TransferOpen = "open" // the QR is out, or the new app scanned it
	// TransferApproved lasts only within the batch of the approval, which
	// completes the transfer (0.10.3).
	TransferApproved = "approved"
)

// AlarmCredentialClone is the content-free host alarm of a clone (§11.5).
const AlarmCredentialClone = "credential_clone"

// Transfer is a direct transfer in progress (§6.7.1).
type Transfer struct {
	ID        string    `json:"id"` // the pairing invite id: transfer_id
	OldDevice string    `json:"old_device"`
	State     string    `json:"state"`
	Exp       time.Time `json:"exp"`
	Inbound   string    `json:"inbound,omitempty"`  // the new app's handshake, then its request
	NewPeer   string    `json:"new_peer,omitempty"` // its device id, at approval
}

// TransferInfo is the credential feature's view of a transfer.
type TransferInfo struct {
	ID        string
	OldDevice string
	State     string
	Exp       time.Time
	Scanned   bool
}

// CredentialHost is the runtime the credential feature needs for one app
// per vault. The Manager implements it; feature tests may.
type CredentialHost interface {
	// VerifyPIN checks the vault PIN against the DEK under the §11.8
	// unlock backoff (bad_pin, backoff).
	VerifyPIN(pin string, now time.Time) error
	// CreateTransfer opens a direct transfer from the device `by` and
	// returns its id, QR link and expiry (exists if one is open).
	CreateTransfer(ctx context.Context, by string, now time.Time) (id, link string, exp time.Time, err error)
	// Transfer returns the transfer in progress.
	Transfer() (TransferInfo, bool)
	// ApproveTransfer approves the new app, whose handshake is complete
	// (Scanned): the transfer completes in the same flush (0.10.3).
	ApproveTransfer(ctx context.Context, id string, now time.Time) error
	// EndTransfer aborts the transfer (rejected, alarm, ...).
	EndTransfer(id, reason string, now time.Time) error
	// ReportAlarm reports a content-free alarm to the host after the
	// batch's flush (§11.5).
	ReportAlarm(kind string)
}

// TransferObserver is told when a transfer completes: the credential
// moves its holder to the new app (§6.7.1).
type TransferObserver interface {
	TransferCompleted(s *Session, oldDevice, newDevice string)
}

// CredentialVersioner is implemented by the credential feature: the
// current credential version, for device.paired after a transfer.
type CredentialVersioner interface {
	CredentialVersion() uint64
}

func (s *Session) credHost() (CredentialHost, bool) {
	h, ok := s.host.(CredentialHost)
	return h, ok
}

var errUnavailable = &HandlerError{Code: "internal"}

// VerifyPIN checks the vault PIN (§6.7.1).
func (s *Session) VerifyPIN(pin string) error {
	h, ok := s.credHost()
	if !ok {
		return errUnavailable
	}
	return h.VerifyPIN(pin, s.now)
}

// CreateTransfer opens a direct transfer from the sending app (§6.7.1).
func (s *Session) CreateTransfer() (id, link string, exp time.Time, err error) {
	h, ok := s.credHost()
	if !ok {
		return "", "", time.Time{}, errUnavailable
	}
	return h.CreateTransfer(s.Context(), s.from.ID, s.now)
}

// Transfer returns the transfer in progress.
func (s *Session) Transfer() (TransferInfo, bool) {
	h, ok := s.credHost()
	if !ok {
		return TransferInfo{}, false
	}
	return h.Transfer()
}

// ApproveTransfer approves the transfer's new app (§6.7.1).
func (s *Session) ApproveTransfer(id string) error {
	h, ok := s.credHost()
	if !ok {
		return errUnavailable
	}
	return h.ApproveTransfer(s.Context(), id, s.now)
}

// EndTransfer aborts a transfer.
func (s *Session) EndTransfer(id, reason string) error {
	h, ok := s.credHost()
	if !ok {
		return errUnavailable
	}
	return h.EndTransfer(id, reason, s.now)
}

// ReportAlarm reports a content-free alarm to the host (§11.5).
func (s *Session) ReportAlarm(kind string) {
	if h, ok := s.credHost(); ok {
		h.ReportAlarm(kind)
	}
}

func (h managerHost) VerifyPIN(pin string, now time.Time) error { return h.m.verifyPIN(pin, now) }

func (h managerHost) CreateTransfer(ctx context.Context, by string, now time.Time) (string, string, time.Time, error) {
	return h.m.createTransfer(ctx, by, now)
}

func (h managerHost) Transfer() (TransferInfo, bool) {
	t := h.m.st.Transfer
	if t == nil {
		return TransferInfo{}, false
	}
	// Scanned: the new app's handshake is complete and its SAS known.
	return TransferInfo{ID: t.ID, OldDevice: t.OldDevice, State: t.State, Exp: t.Exp, Scanned: h.m.st.Requests[t.Inbound] != nil}, true
}

func (h managerHost) ApproveTransfer(ctx context.Context, id string, now time.Time) error {
	return h.m.approveTransfer(ctx, id, now)
}

func (h managerHost) EndTransfer(id, reason string, now time.Time) error {
	t := h.m.st.Transfer
	if t == nil || t.ID != id {
		return errNotFound
	}
	h.m.abortTransfer(reason, now)
	return nil
}

func (h managerHost) ReportAlarm(kind string) {
	if kind == AlarmCredentialClone {
		h.m.alarms = append(h.m.alarms, kind)
	}
}

// verifyPIN derives the DEK from pin with the header's KDF and pepper and
// compares it with the running vault's DEK. Failures count in the unlock
// backoff (§11.8) and are written with the batch's header.
func (m *Manager) verifyPIN(pin string, now time.Time) error {
	if !altchan.ValidPIN(pin) {
		return errBadRequest
	}
	if now.Before(m.hdr.Backoff.NotBefore) {
		return BackoffError(m.hdr.Backoff.NotBefore.Sub(now))
	}
	dek, err := deriveDEK(pin, m.hdr.KDF, m.hdr.Pepper, m.st.VaultID)
	ok := err == nil && subtle.ConstantTimeCompare(dek, m.dek) == 1
	suite.Wipe(dek)
	m.dirty = true
	if !ok {
		m.hdr.Backoff.Failures++
		m.hdr.Backoff.NotBefore = now.Add(backoffFor(m.hdr.Backoff.Failures))
		m.record(Activity{Kind: "vault.pin_failed", Audit: true}, now)
		return NewError("bad_pin", "")
	}
	m.hdr.Backoff = Backoff{}
	return nil
}

// createTransfer opens the transfer's pairing (QR t "p", bundle kind app).
func (m *Manager) createTransfer(ctx context.Context, by string, now time.Time) (string, string, time.Time, error) {
	if m.st.Transfer != nil {
		return "", "", time.Time{}, NewError("exists", "")
	}
	inv, link, err := m.createInvite(ctx, KindApp, PairingApprovalTTL, by, now)
	if err != nil {
		return "", "", time.Time{}, NewError("relay_error", "")
	}
	inv.Transfer = true
	m.st.Transfer = &Transfer{ID: inv.ID, OldDevice: by, State: TransferOpen, Exp: inv.Exp}
	m.dirty = true
	m.record(Activity{Kind: "device.transfer.started", DeviceID: by, Ref: inv.ID, Audit: true}, now)
	return inv.ID, link, inv.Exp, nil
}

// transferStarted records the new app's attested hs.init, answered at
// once (called from handleInit).
func (m *Manager) transferStarted(inviteID, id string, exp time.Time, now time.Time) {
	t := m.st.Transfer
	if t == nil || t.ID != inviteID || t.State != TransferOpen || t.Inbound != "" {
		m.dropAwaiting(id, "", now)
		return
	}
	t.Inbound, t.Exp = id, exp
	m.dirty = true
}

// transferScanned asks the old app once the new app's hs.fin checked out
// and the SAS is known (§6.7.1 step 2).
func (m *Manager) transferScanned(r *Request, now time.Time) {
	t := m.st.Transfer
	old := m.st.Devices[t.OldDevice]
	if old == nil {
		m.abortTransfer("expired", now)
		return
	}
	m.sendTo(old, "device.transfer.pending", strictjson.NewBuilder().String("transfer_id", t.ID).
		String("name", r.Peer.Name).String("sas", r.SAS).Bytes(), now)
}

// approveTransfer approves the new app (§6.7.1, step 3). The credential
// feature has checked the PIN and the password and rotated the CEK. The
// new app's handshake is complete, so the approval completes the transfer
// (step 4), after the handler returns (afterHandle), in the same flush.
func (m *Manager) approveTransfer(_ context.Context, id string, now time.Time) error {
	t := m.st.Transfer
	if t == nil || t.ID != id || t.State != TransferOpen || t.Inbound == "" {
		return errNotFound
	}
	r := m.st.Requests[t.Inbound]
	if r == nil {
		return errNotFound
	}
	t.State, t.NewPeer = TransferApproved, r.Peer.ID
	m.transferAfter = r.ID
	m.dirty = true
	m.record(Activity{Kind: "device.transfer.approved", DeviceID: t.OldDevice, Ref: t.ID, Audit: true}, now)
	return nil
}

// abortTransfer ends a transfer that has not completed: the old app stays
// the holder and keeps everything (§6.7.1).
func (m *Manager) abortTransfer(reason string, now time.Time) {
	t := m.st.Transfer
	if t == nil {
		return
	}
	if r := m.st.Requests[t.Inbound]; r != nil && reason == "rejected" {
		// The holder's rejection after the new app's hs.fin is sent to it
		// first (§6.7, 0.10.5); an expiry, alarm or recovery sends nothing.
		m.sendEnded(r, devicePairRejectedType, r.Expires, now)
	}
	if inv := m.st.Invites[t.ID]; inv != nil {
		if inv.OpenJTI != "" {
			m.denyJTI(inv.OpenJTI, now)
		}
		if !inv.Used && inv.ClaimID != "" {
			m.queueDeleteClaim(inv.ClaimID, now)
		}
		delete(m.st.Invites, t.ID)
	}
	if id := t.Inbound; id != "" {
		// The new app's handshake state and request token (§7.4).
		t.Inbound = ""
		if r := m.st.Requests[id]; r != nil {
			m.dropRequest(r, now)
		}
		if m.st.Awaiting[id] != nil {
			m.dropAwaiting(id, reason, now)
		}
	}
	m.st.Transfer = nil
	m.dirty = true
	m.record(Activity{Kind: "device.transfer.aborted", DeviceID: t.OldDevice, Ref: t.ID, Audit: true}, now)
	m.notifyDevices("sync.event", strictjson.NewBuilder().String("kind", "device.transfer").String("transfer_id", t.ID).
		String("state", "aborted").String("reason", reason).Bytes(), "", now)
}

// expireTransfer runs in housekeeping.
func (m *Manager) expireTransfer(now time.Time) {
	t := m.st.Transfer
	if t == nil {
		return
	}
	if !now.Before(t.Exp) || m.st.Devices[t.OldDevice] == nil {
		m.abortTransfer("expired", now)
		return
	}
	if t.State == TransferOpen && t.Inbound != "" && m.st.Awaiting[t.Inbound] == nil && m.st.Requests[t.Inbound] == nil {
		m.abortTransfer("expired", now) // the new app's handshake went away
	}
}

// isTransferPeer reports whether p is the approved transfer's new app.
func (m *Manager) isTransferPeer(p *Peer) bool {
	t := m.st.Transfer
	return t != nil && t.State == TransferApproved && p.Kind == KindApp && p.ID == t.NewPeer
}

// completeTransfer runs at the approval, in the flush that adds the new
// app's device record (§6.7.1, step 4): the new app becomes the holder and
// the old app is removed.
func (m *Manager) completeTransfer(p *Peer, now time.Time) {
	t := m.st.Transfer
	m.st.Transfer = nil
	if inv := m.st.Invites[t.ID]; inv != nil {
		delete(m.st.Invites, t.ID)
	}
	if old := m.st.Devices[t.OldDevice]; old != nil {
		// What is queued for the old app (the approval's response) still
		// goes out, before device.unlinked, on its token.
		for _, e := range m.st.Outbox {
			if e.PeerID == old.ID && e.Op == OpDeposit && !e.Done && e.Token == "" {
				e.PeerID, e.Token, e.BestEffort = "", old.Standing.Token, true
			}
		}
		m.removeApp(old, "transferred", now)
	}
	if len(p.APIKey) > 0 {
		m.setAppKey(p.APIKey) // §6.7.1 step 4 (0.15.0): reported after the flush
	}
	sess := m.session(now)
	for _, f := range m.features {
		if o, ok := f.(TransferObserver); ok {
			o.TransferCompleted(sess, t.OldDevice, p.ID)
		}
	}
	m.record(Activity{Kind: "device.transferred", DeviceID: p.ID, Ref: t.ID, Audit: true, Feed: true}, now)
	m.notifyDevices("sync.event", strictjson.NewBuilder().String("kind", "device.transferred").String("device_id", p.ID).
		String("old_device_id", t.OldDevice).Bytes(), p.ID, now)
}

// removeApp unlinks an app that a transfer or a recovery replaced (§7.4):
// a best-effort device.unlinked{reason}, its relay key denylisted, its
// unlock key removed at the flush, its per-device feature data dropped.
func (m *Manager) removeApp(p *Peer, reason string, now time.Time) {
	m.removePeerWith(p, "device.unlinked", strictjson.NewBuilder().String("reason", reason).Bytes(), now)
	sess := m.session(now)
	for _, f := range m.features {
		if ob, ok := f.(DeviceRemovedObserver); ok {
			ob.DeviceRemoved(sess, p.ID)
		}
	}
}

// replaceApps runs after credential.recover or credential.reset completed
// a recovery (§11.11.5): every other app is removed; desktops and agents
// are kept. It runs after the handler returns, outside the credential
// feature's lock.
func (m *Manager) replaceApps(keep string, now time.Time) {
	for _, p := range m.sortedDevices() {
		if p.ID == keep || p.Kind != KindApp {
			continue
		}
		m.removeApp(p, "replaced", now)
		m.record(Activity{Kind: "device.replaced", DeviceID: p.ID, Audit: true, Feed: true}, now)
		m.notifyDevices("sync.event", strictjson.NewBuilder().String("kind", "device.unlinked").String("device_id", p.ID).Bytes(), "", now)
	}
	if t := m.st.Transfer; t != nil {
		m.abortTransfer("replaced", now)
	}
}

func (m *Manager) sortedDevices() []*Peer {
	out := make([]*Peer, 0, len(m.st.Devices))
	for _, p := range m.st.Devices {
		out = append(out, p)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].ID < out[j-1].ID; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// afterHandle runs deferred work of a handler: the apps a completed
// recovery replaced.
func (m *Manager) afterHandle(now time.Time) {
	m.refreshOwnerCred()
	if via := m.deleteRequest; via != "" {
		m.deleteRequest = ""
		m.beginDelete(via, now)
		return
	}
	if keep := m.replaceAfter; keep != "" {
		m.replaceAfter = ""
		m.replaceApps(keep, now)
	}
}

// afterRespond runs deferred work that must follow the handler's
// response: a transfer approved by the old app completes now (§6.7.1,
// 0.10.3), so that the old app gets its {} before device.unlinked.
func (m *Manager) afterRespond(now time.Time) {
	if id := m.transferAfter; id != "" {
		m.transferAfter = ""
		if r := m.st.Requests[id]; r != nil && m.st.Transfer != nil && m.st.Transfer.State == TransferApproved {
			m.activateRequest(r, now) // completes the transfer (isTransferPeer)
		}
	}
}

// reportAlarms sends the batch's alarms to the host after its flush.
func (m *Manager) reportAlarms() {
	if len(m.alarms) == 0 || m.st == nil {
		return
	}
	for _, k := range m.alarms {
		m.report("alarm."+k, m.st.VaultID, m.opt.Release.PCR0)
	}
	m.alarms = nil
}

// transferPairedBody adds the transfer members to device.paired: since
// 0.17.0 also the member's user_guid from the sealed header, which the new
// app's unlocks name and sign (§6.7.1, §11.4) and which it has no other
// way to learn.
func (m *Manager) transferPairedBody(b *strictjson.Builder) {
	b.Bool("transfer", true)
	b.String("user_guid", m.hdr.UserGUID)
	for _, f := range m.features {
		if v, ok := f.(CredentialVersioner); ok {
			b.Uint("credential_version", v.CredentialVersion())
		}
	}
}

var errForbiddenH = &HandlerError{Code: "forbidden"}

// isTransferRequest reports whether a handshake or request (by id) is a
// transfer's new app.
func (m *Manager) isTransferRequest(id string) bool {
	if m.st.Transfer != nil && m.st.Transfer.Inbound == id {
		return true
	}
	inviteID := ""
	if r := m.st.Requests[id]; r != nil {
		inviteID = r.InviteID
	} else if aw := m.st.Awaiting[id]; aw != nil {
		inviteID = aw.InviteID
	}
	inv := m.st.Invites[inviteID]
	return inv != nil && inv.Transfer
}
