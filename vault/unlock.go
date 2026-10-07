package vault

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"time"

	"github.com/vettid/vettid-vault/vault/store"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Unlock result codes (§11.4, §11.9, §11.10.4).
const (
	CodeBadPIN        = "bad_pin"
	CodeBackoff       = "backoff"
	CodeUnknownDevice = "unknown_device"
	CodeAttestation   = "attestation"
	CodeRollback      = "state_rollback"
	CodeMissing       = "vault_missing"
	CodeManifest      = "manifest"
	CodeWrongRelease  = "wrong_release"
	CodeReleaseKey    = "release_key"
	CodeRetry         = "retry"
)

// Release update results and refusal codes (§11.4, §11.10.4).
const (
	UpdateMoved     = "moved"
	UpdateRefused   = "refused"
	UpdateAbandoned = "abandoned"

	RefuseTarget    = "target"
	RefuseDowngrade = "downgrade"
	RefuseApproval  = "approval"
	RefuseSealKey   = "seal_key"
	RefusePending   = "pending"
	RefuseWrite     = "write"
)

// Errors the enclave's callbacks return.
var (
	// ErrDeviceSig: the unlock signature does not verify under device_ik.
	// The request is dropped (there is no authenticated device to answer).
	ErrDeviceSig = errors.New("vault: unlock signature invalid")
	// ErrDeviceAttestation: the device assertion or approval failed.
	ErrDeviceAttestation = errors.New("vault: device attestation failed")
	// ErrSealKeyNamespace: the target's seal_key is outside the pinned
	// account and region (§11.10.2).
	ErrSealKeyNamespace = errors.New("vault: sealing key outside the pinned namespace")
	// ErrSealKey: the target key failed the §11.10.7 checks.
	ErrSealKey = errors.New("vault: sealing key failed its policy check")
)

// ReleaseEntry is the part of a manifest entry the vault needs.
type ReleaseEntry struct {
	PCR0    string
	Number  uint64
	Status  string
	SealKey string
}

// ManifestView is a verified manifest (§11.10.1) as the vault sees it.
type ManifestView struct {
	Serial uint64
	Own    ReleaseEntry
	Lookup func(pcr0 string) (ReleaseEntry, bool)
}

// UpdateRequest is a release_update in an unlock (§11.10.3).
type UpdateRequest struct {
	To        string
	ToRelease uint64
	// VerifyApproval checks the approval under the attested device key of
	// the unlock key (the enclave builds the approval string with its own
	// PCR0 as from_pcr0) and returns the updated binding.
	VerifyApproval func(k *UnlockKey) (json.RawMessage, error)
}

// AltUnlockParams is an alternate-channel unlock (§11.4), after the enclave
// decrypted the request and checked its binding, freshness and replay.
type AltUnlockParams struct {
	Options
	VaultID      string
	UserGUID     string
	DeviceIK     ed25519.PublicKey
	PIN          string
	MinStateSeq  uint64
	MinHeaderSeq uint64
	// DeviceToken is the fresh standing token for the device's mailbox
	// (sub = the vault's relay key).
	DeviceToken string
	// VerifyDevice checks the unlock signature and the device assertion
	// with the unlock key found for DeviceIK and returns the updated
	// binding. It returns ErrDeviceSig or ErrDeviceAttestation.
	VerifyDevice func(k *UnlockKey) (json.RawMessage, error)
	// Manifest verifies the request's manifest against the serial the
	// header has seen (§11.10.4 step 1).
	Manifest func(serialSeen uint64) (*ManifestView, error)
	// OwnKeyCheck runs §11.10.7 on the running release's sealing key when
	// the header has no record of it verified by this release.
	OwnKeyCheck func(ctx context.Context, own ReleaseEntry) (*SealKeyRecord, error)
	// SealerFor returns a sealer for another release after checking its
	// key (§11.10.7); errors are ErrSealKeyNamespace or ErrSealKey.
	SealerFor func(ctx context.Context, target ReleaseEntry) (Sealer, *SealKeyRecord, error)
	Update    *UpdateRequest
	// CancelRecovery: the unlock also cancels a pending recovery
	// (§11.11.4); without it, a device other than the recovery's own is
	// refused with recovery_pending while a recovery is in progress.
	CancelRecovery bool
	// Account is the queue message's account snapshot (0.15.0, §11.13),
	// applied after a successful unlock; nil for none.
	Account []byte

	pinOnly bool // Unlock: no device, manifest or release checks
}

// UpdateOutcome is the `update` member of the result.
type UpdateOutcome struct {
	To     string
	Result string
	Code   string
}

// AltUnlockOutcome is what the enclave seals into vault.unlock.result.
type AltUnlockOutcome struct {
	OK   bool
	Code string
	// Drop is set when no authenticated device can be answered (unknown
	// header or device key, bad signature): the enclave returns bytes
	// indistinguishable from a sealed result.
	Drop       bool
	DeviceKEM  []byte
	StateSeq   uint64
	HeaderSeq  uint64
	RetryAfter time.Duration
	Release    ReleaseEntry
	Serial     uint64
	Token      string
	Update     *UpdateOutcome
	Events     []LifecycleEvent
	// RecoveryCancelled: this unlock cancelled a recovery (§11.11.4).
	RecoveryCancelled bool
	// VaultBundle is set for the recovered app (§11.11.5).
	VaultBundle []byte
	// CredentialBackup is set with VaultBundle: the credential.backup
	// setting (§11.11.5 step 1, 0.10.6).
	CredentialBackup *bool

	cause error
}

func (o *AltUnlockOutcome) err() error {
	if o.cause != nil {
		return o.cause
	}
	switch o.Code {
	case CodeBadPIN:
		return ErrBadPIN
	case CodeBackoff:
		return ErrBackoff
	case CodeRollback:
		return ErrRollback
	case CodeMissing:
		return ErrMissing
	case CodeWrongRelease:
		return ErrRelease
	}
	return ErrHeader
}

func (o *AltUnlockOutcome) fail(code string, cause error) *AltUnlockOutcome {
	o.OK, o.Code, o.cause = false, code, cause
	return o
}

func (o *AltUnlockOutcome) drop(cause error) *AltUnlockOutcome {
	o.Drop = true
	return o.fail(CodeUnknownDevice, cause)
}

func lifecycle(o Options, event, vaultID, release string) LifecycleEvent {
	return LifecycleEvent{Event: event, VaultID: vaultID, Release: release, VaultVersion: o.Release.PCR0, StateVersion: StateVersion}
}

// findUnlockKey looks up device_ik among the unlock keys in constant time
// per key.
func findUnlockKey(h *Header, ik ed25519.PublicKey) *UnlockKey {
	var found *UnlockKey
	for i := range h.UnlockKeys {
		if suite.EqualPublic(h.UnlockKeys[i].IK, ik) {
			found = &h.UnlockKeys[i]
		}
	}
	return found
}

// UnlockAlt runs an unlock in the order of §11.4 and §11.10.4: header,
// identity, unlock key and signature, device assertion, backoff, header
// rollback, manifest, DEK and state, state rollback, then the release
// rules (pending move, wrong release, update, confirmation). It returns
// the running manager when the vault resumes.
func UnlockAlt(ctx context.Context, p AltUnlockParams) (*Manager, *AltUnlockOutcome) {
	p.Options.defaults()
	now := p.Now()
	out := &AltUnlockOutcome{}
	own := p.Release
	if !validRelease(own) || p.Store == nil || p.Sealer == nil {
		return nil, out.drop(ErrHeader)
	}
	hkey := store.HeaderKey(p.VaultID, own.PCR0)
	if !store.ValidKey(hkey) {
		return nil, out.drop(ErrMissing)
	}
	hblob, hver, err := p.Store.Get(ctx, hkey)
	if err != nil {
		return nil, out.drop(ErrMissing) // no header sealed to this release: no device to answer
	}
	hdr, err := unsealHeader(ctx, p.Sealer, hblob, p.VaultID, own.PCR0)
	if err != nil {
		return nil, out.drop(ErrHeader)
	}
	if hdr.Deleting {
		// A deletion was interrupted (§12.5): finish it, never open.
		suite.Wipe(hdr.Pepper)
		_ = EraseStored(ctx, p.Store, p.VaultID, hdr.UserGUID, nil, own.PCR0, "", "")
		return nil, out.drop(ErrDeleted)
	}
	out.HeaderSeq = hdr.HeaderSeq
	var key *UnlockKey
	if !p.pinOnly {
		if hdr.UserGUID != p.UserGUID {
			return nil, out.drop(ErrHeader) // redirected request (§11.6)
		}
		if key = findUnlockKey(hdr, p.DeviceIK); key == nil {
			return nil, out.drop(ErrHeader)
		}
		out.DeviceKEM = key.KEM
		nb, err := p.VerifyDevice(key)
		if errors.Is(err, ErrDeviceSig) || err != nil && !errors.Is(err, ErrDeviceAttestation) {
			return nil, out.drop(err)
		}
		if err != nil {
			return nil, out.fail(CodeAttestation, err)
		}
		key.Attestation = nb // persisted with the next header write
		if hdr.Recovery != nil && !hdr.isRecoveryKey(key.IK) && !p.CancelRecovery {
			return nil, out.fail(CodeRecoveryPending, nil) // not a PIN attempt
		}
	}
	if now.Before(hdr.Backoff.NotBefore) {
		out.RetryAfter = hdr.Backoff.NotBefore.Sub(now)
		return nil, out.fail(CodeBackoff, nil)
	}
	if hdr.HeaderSeq < p.MinHeaderSeq {
		return nil, out.fail(CodeRollback, nil)
	}
	var mv *ManifestView
	if !p.pinOnly {
		if mv, err = p.Manifest(hdr.ManifestSerial); err != nil || mv.Own.PCR0 != own.PCR0 || mv.Own.Number != own.Number {
			return nil, out.fail(CodeManifest, err) // not a PIN failure, not counted
		}
		out.Release, out.Serial = mv.Own, mv.Serial
		if mv.Serial > hdr.ManifestSerial {
			hdr.ManifestSerial = mv.Serial // recorded at the next header write
		}
	}
	sblob, sver, err := p.Store.Get(ctx, store.StateKey(p.VaultID))
	if err != nil {
		return nil, out.fail(CodeMissing, err)
	}
	dek, err := deriveDEK(p.PIN, hdr.KDF, hdr.Pepper, p.VaultID)
	if err != nil {
		return nil, out.fail(CodeBadPIN, ErrBadPIN)
	}
	pt, blobSeq, err := decryptState(dek, p.VaultID, sblob)
	if err != nil {
		suite.Wipe(dek)
		hdr.Backoff.Failures++
		hdr.Backoff.NotBefore = now.Add(backoffFor(hdr.Backoff.Failures))
		hdr.HeaderSeq++
		out.HeaderSeq = hdr.HeaderSeq
		out.RetryAfter = backoffFor(hdr.Backoff.Failures)
		if b, err := sealHeader(ctx, p.Sealer, hdr); err == nil {
			_, _ = p.Store.Put(ctx, hkey, b, hver)
		}
		return nil, out.fail(CodeBadPIN, ErrBadPIN)
	}
	var st State
	err = json.Unmarshal(pt, &st)
	suite.Wipe(pt)
	if err != nil || st.VaultID != p.VaultID || st.StateSeq != blobSeq {
		suite.Wipe(dek)
		return nil, out.fail(CodeMissing, ErrState)
	}
	if st.StateSeq < hdr.StateSeq || st.StateSeq < p.MinStateSeq {
		suite.Wipe(dek)
		return nil, out.fail(CodeRollback, ErrRollback)
	}
	st.init()
	if st.SealedRelease == "" {
		st.SealedRelease = hdr.SealedRelease
	}
	m := newManager(p.Options, &st, hdr, dek)
	m.stateVer, m.headerVer = sver, hver
	m.hadFailures = hdr.Backoff.Failures > 0
	hdr.Backoff = Backoff{} // a correct PIN resets the backoff (§11.8)
	if p.CancelRecovery && key != nil && hdr.Recovery != nil && !hdr.isRecoveryKey(key.IK) {
		hdr.cancelRecovery(now, "recovery.cancelled")
		out.RecoveryCancelled = true
	}
	out.StateSeq = st.StateSeq
	if p.pinOnly {
		if st.ReleaseMove != nil || st.SealedRelease != own.PCR0 {
			m.zeroize()
			return nil, out.fail(CodeWrongRelease, nil)
		}
		return m.resume(ctx, p, out, now)
	}
	return m.releaseRules(ctx, p, key, mv, out, now)
}

// releaseRules applies §11.10.4 steps 2-8 and the confirmation and
// abandonment rules to an opened vault.
func (m *Manager) releaseRules(ctx context.Context, p AltUnlockParams, key *UnlockKey, mv *ManifestView, out *AltUnlockOutcome, now time.Time) (*Manager, *AltUnlockOutcome) {
	own := p.Release
	st := m.st
	pending := st.ReleaseMove
	switch {
	case pending != nil && pending.To == own.PCR0:
		// Confirmation at the new release: from this flush on the move is
		// final; then the old header is deleted.
		old := pending.From
		st.ReleaseMove = nil
		st.SealedRelease = own.PCR0
		mm, o := m.resume(ctx, p, out, now)
		if o.OK && old != "" && old != own.PCR0 {
			deleteHeader(ctx, p.Store, p.VaultID, old)
		}
		return mm, o
	case st.SealedRelease != own.PCR0:
		// A stale header served to a release the vault has left.
		m.zeroize()
		return nil, out.fail(CodeWrongRelease, ErrRelease)
	case pending != nil:
		if u := p.Update; u != nil && u.To == own.PCR0 && u.ToRelease == own.Number {
			nb, err := u.VerifyApproval(key)
			if err == nil {
				// Abandon the unconfirmed move and run under this release.
				key.Attestation = nb
				target := pending.To
				st.ReleaseMove = nil
				out.Update = &UpdateOutcome{To: own.PCR0, Result: UpdateAbandoned}
				mm, o := m.resume(ctx, p, out, now)
				if o.OK {
					deleteHeader(ctx, p.Store, p.VaultID, target)
					o.Events = append(o.Events, lifecycle(p.Options, "moved", p.VaultID, own.PCR0))
				}
				return mm, o
			}
		}
		// Never resume with a pending move: complete it (step 7).
		entry, ok := mv.Lookup(pending.To)
		if !ok || entry.Number != pending.ToRelease {
			m.zeroize()
			return nil, out.fail(CodeManifest, nil)
		}
		return m.completeMove(ctx, p, entry, out)
	}
	u := p.Update
	if u == nil {
		return m.resume(ctx, p, out, now)
	}
	// Step 4: check the update; a refusal still unlocks.
	refuse := func(code string) (*Manager, *AltUnlockOutcome) {
		out.Update = &UpdateOutcome{To: u.To, Result: UpdateRefused, Code: code}
		return m.resume(ctx, p, out, now)
	}
	entry, ok := mv.Lookup(u.To)
	if !ok || entry.Status != "active" || entry.Number != u.ToRelease {
		return refuse(RefuseTarget)
	}
	if u.ToRelease <= own.Number {
		return refuse(RefuseDowngrade)
	}
	nb, err := u.VerifyApproval(key)
	if err != nil {
		return refuse(RefuseApproval)
	}
	key.Attestation = nb
	sealer, rec, err := p.SealerFor(ctx, entry)
	if errors.Is(err, ErrSealKeyNamespace) {
		return refuse(RefuseTarget)
	}
	if err != nil {
		return refuse(RefuseSealKey)
	}
	// Step 6: record the move. From here on the vault does not resume
	// under this release.
	st.ReleaseMove = &ReleaseMove{To: entry.PCR0, ToRelease: entry.Number, From: own.PCR0, ManifestSerial: mv.Serial,
		ApprovedBy: key.DeviceID}
	m.syncUnlockKeysWith(key)
	if err := m.persist(ctx, false); err != nil {
		if errors.Is(err, ErrSplitBrain) {
			return nil, out.fail(CodeRetry, err)
		}
		st.ReleaseMove = nil
		return refuse(RefuseWrite)
	}
	return m.completeMoveWith(ctx, p, entry, sealer, rec, out)
}

// completeMove is step 7 for a move recorded earlier.
func (m *Manager) completeMove(ctx context.Context, p AltUnlockParams, entry ReleaseEntry, out *AltUnlockOutcome) (*Manager, *AltUnlockOutcome) {
	sealer, rec, err := p.SealerFor(ctx, entry)
	if err != nil {
		m.zeroize()
		return nil, out.fail(CodeReleaseKey, err)
	}
	// Persist the iOS counter and manifest serial before sealing onward.
	if err := m.writeHeader(ctx); err != nil {
		m.zeroize()
		return nil, out.fail(CodeRetry, err)
	}
	return m.completeMoveWith(ctx, p, entry, sealer, rec, out)
}

// completeMoveWith seals the header to the target release (§11.10.4 step
// 7) and locks without collecting (step 8).
func (m *Manager) completeMoveWith(ctx context.Context, p AltUnlockParams, entry ReleaseEntry, sealer Sealer, rec *SealKeyRecord, out *AltUnlockOutcome) (*Manager, *AltUnlockOutcome) {
	defer m.zeroize()
	if d, ok := sealer.(interface{ Destroy() }); ok {
		defer d.Destroy()
	}
	nh := *m.hdr
	nh.UnlockKeys = append([]UnlockKey(nil), m.hdr.UnlockKeys...)
	nh.HeaderSeq++
	nh.SealedRelease = entry.PCR0
	nh.StateSeq = m.st.StateSeq
	nh.SealKeyVerified = rec
	if out.Serial > nh.ManifestSerial {
		nh.ManifestSerial = out.Serial
	}
	b, err := sealHeader(ctx, sealer, &nh)
	if err != nil {
		return nil, out.fail(CodeRetry, err)
	}
	key := store.HeaderKey(p.VaultID, entry.PCR0)
	_, err = p.Store.Put(ctx, key, b, "")
	if errors.Is(err, store.ErrConflict) {
		// Only admitted enclaves can seal to this key and moves only go
		// forward: an existing object is a leftover of this same move.
		if _, v, gerr := p.Store.Get(ctx, key); gerr == nil {
			_, err = p.Store.Put(ctx, key, b, v)
		}
	}
	if err != nil {
		return nil, out.fail(CodeRetry, err)
	}
	out.OK, out.Code = true, ""
	out.HeaderSeq, out.StateSeq = nh.HeaderSeq, m.st.StateSeq
	out.Update = &UpdateOutcome{To: entry.PCR0, Result: UpdateMoved}
	out.Events = append(out.Events, lifecycle(p.Options, "moved", p.VaultID, entry.PCR0))
	return nil, out
}

func deleteHeader(ctx context.Context, s store.Store, vaultID, release string) {
	key := store.HeaderKey(vaultID, release)
	if !store.ValidKey(key) {
		return
	}
	if _, v, err := s.Get(ctx, key); err == nil {
		_ = s.Delete(ctx, key, v) // conditional; failure is ignored (§11.10.4)
	}
}

// syncUnlockKeysWith makes sure the verified key's updated binding is the
// one written.
func (m *Manager) syncUnlockKeysWith(k *UnlockKey) {
	if k == nil {
		return
	}
	for i := range m.hdr.UnlockKeys {
		if suite.EqualPublic(m.hdr.UnlockKeys[i].IK, k.IK) {
			m.hdr.UnlockKeys[i].Attestation = k.Attestation
		}
	}
}

// resume starts the vault under this release: keys, sessions, relay
// registration, the device's fresh token, a header write recording the
// reset backoff, counter and manifest serial, and the result fields.
func (m *Manager) resume(ctx context.Context, p AltUnlockParams, out *AltUnlockOutcome, now time.Time) (*Manager, *AltUnlockOutcome) {
	fail := func(code string, err error) (*Manager, *AltUnlockOutcome) {
		m.zeroize()
		return nil, out.fail(code, err)
	}
	if !p.pinOnly {
		rec := m.hdr.SealKeyVerified
		if rec == nil || rec.VerifiedBy != p.Release.PCR0 || rec.KeyARN != out.Release.SealKey {
			if p.OwnKeyCheck == nil {
				return fail(CodeReleaseKey, ErrSealKey)
			}
			r, err := p.OwnKeyCheck(ctx, out.Release)
			if err != nil {
				return fail(CodeReleaseKey, err)
			}
			m.hdr.SealKeyVerified = r
		}
	}
	if !p.pinOnly && m.hdr.isRecoveryKey(p.DeviceIK) && !(m.hasGate() && m.credentialExists() && m.backupCopy()) {
		// §11.11.5 step 1 (0.16.0): a vault without a backup copy is not
		// recovered. The recovery and its unlock key go (as a cancel), the
		// header is written and the vault locks again before it serves
		// anything; no token, no bundle.
		m.hdr.cancelRecovery(now, "recovery.cancelled")
		if err := m.writeHeader(ctx); err != nil && errors.Is(err, ErrSplitBrain) {
			return nil, out.fail(CodeRetry, err)
		}
		out.HeaderSeq = m.hdr.HeaderSeq
		return fail(CodeNoBackup, ErrRecoveryNoBackup)
	}
	if err := m.loadKeys(); err != nil {
		return fail(CodeMissing, err)
	}
	if err := m.restoreLive(); err != nil {
		return fail(CodeMissing, err)
	}
	m.applyRecovery(now)
	var err error
	m.relay = p.Relay(m.st.Relay.URL, m.keys.relay)
	if m.limits, err = m.relay.Register(ctx); err != nil {
		return fail(CodeRetry, err)
	}
	if !p.pinOnly {
		m.syncUnlockKeysWith(findUnlockKey(m.hdr, p.DeviceIK))
		for i := range m.hdr.UnlockKeys {
			if suite.EqualPublic(m.hdr.UnlockKeys[i].IK, p.DeviceIK) {
				out.Token = m.unlockTokens(&m.hdr.UnlockKeys[i], p.DeviceToken, now)
			}
		}
		if m.hdr.isRecoveryKey(p.DeviceIK) {
			out.VaultBundle = VaultBundle(handshake.Principal{IK: m.keys.ik.Public().(ed25519.PublicKey), KEM: m.keys.kem.Public(), Relay: m.ownAddr()})
			backup := true // 0.16.0: always true here (no_backup refused above)
			out.CredentialBackup = &backup
		}
		if len(p.Account) > 0 {
			m.applyAccount(p.Account, now) // §11.13: with every unlock
		}
		if m.st.AnnouncedRelease != p.Release.PCR0 {
			m.st.AnnouncedRelease = p.Release.PCR0
			m.notifyDevices("sync.event", releaseEvent(p.Release), "", now)
		}
	}
	// Persist: the state (release fields, tokens) and the header (backoff
	// reset, counter, manifest serial) under this release. A PIN-only
	// (development) unlock writes only a header that recorded failures.
	var err2 error
	switch {
	case !p.pinOnly:
		err2 = m.persist(ctx, false)
	case m.hadFailures:
		err2 = m.writeHeader(ctx)
	}
	if err := err2; err != nil {
		if errors.Is(err, ErrSplitBrain) {
			return nil, out.fail(CodeRetry, err)
		}
		return fail(CodeRetry, err)
	}
	out.OK, out.Code = true, ""
	out.StateSeq, out.HeaderSeq = m.st.StateSeq, m.hdr.HeaderSeq
	ev := lifecycle(p.Options, "unlocked", p.VaultID, p.Release.PCR0)
	ev.AppKey, ev.AppKeySeq = m.AppKey()
	out.Events = append(out.Events, ev)
	if n := m.pendingNameChange(); n != nil {
		// §11.5 (0.19.0): a still-pending name request again with every
		// unlocked report (the row's seq condition makes it idempotent).
		ne := lifecycle(p.Options, EventAccountName, p.VaultID, p.Release.PCR0)
		ne.Name = n
		out.Events = append(out.Events, ne)
	}
	return m, out
}

// unlockTokens handles the tokens of an unlock (§11.4): it stores the
// device's fresh standing token for its mailbox (if valid) and mints the
// standing token for the vault's mailbox that the result carries.
func (m *Manager) unlockTokens(k *UnlockKey, deviceToken string, now time.Time) string {
	var p *Peer
	for _, d := range m.st.Devices {
		if suite.EqualPublic(d.IK, k.IK) && d.Kind == KindApp {
			p = d
		}
	}
	if p == nil {
		// The first app before its enrollment handshake: the enrollment
		// binding names its relay key.
		inv := m.st.Invites[m.st.VaultID]
		if r := m.hdr.Recovery; r != nil && m.hdr.isRecoveryKey(k.IK) {
			inv = m.st.Invites[r.ID] // the recovered app before its handshake (§11.11.5)
		}
		if inv == nil || inv.EnrollIK == nil || !suite.EqualPublic(inv.EnrollIK, k.IK) {
			return ""
		}
		p = &Peer{ID: enrollDeviceID, Kind: KindApp, Relay: PeerRelay{PK: inv.EnrollRelayPK}}
	} else if deviceToken != "" {
		if ht, err := m.heldToken(deviceToken, p); err == nil && ht.Exp.After(p.Standing.Exp) {
			p.Standing = ht
		}
	}
	tok, issued, err := m.mintStanding(p, now, nil)
	if err != nil {
		return ""
	}
	m.st.Issued = append(m.st.Issued, issued...)
	m.dirty = true
	return tok
}

func releaseEvent(r Release) json.RawMessage {
	return json.RawMessage(`{"kind":"vault.release","release":"` + r.PCR0 + `","release_number":` + uitoa(r.Number) + `}`)
}

func uitoa(n uint64) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
