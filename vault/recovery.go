package vault

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/json"
	"errors"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault/store"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Recovery (VAULT-MESSAGING §11.11): the member lost every owner app. The
// recovery record lives in the sealed header, so that a locked vault (no
// DEK) can be put into recovery, cancelled and given a new app; the
// vault's DEK state is reached only by a later PIN unlock of that app.
const (
	RecoveryDelay       = 24 * time.Hour // the code becomes usable after it
	RecoveryValidity    = 24 * time.Hour // ... and stays usable for this long
	RecoveryMaxAttempts = 5              // wrong codes before the recovery is void
	RecoveryCodeBytes   = 20             // 160 bits, 32 base32 characters
	recoveryDeviceID    = "recovery"
	labelRecoveryCode   = "vettid/vms/2/recovery-code"
	maxRecoveryLog      = 64
)

// Recovery states.
const (
	RecoveryPending    = "pending"    // waiting for the code to be presented
	RecoveryRegistered = "registered" // a new app is registered as an unlock key
)

// RecoveryApp is the new app a recovery registers.
type RecoveryApp struct {
	IK          []byte          `json:"ik"`
	KEM         []byte          `json:"kem"`
	RelayPK     []byte          `json:"relay_pk"`
	Name        string          `json:"name,omitempty"`
	Attestation json.RawMessage `json:"attestation,omitempty"`
	// APIKey is the recovering app's app key (0.15.0, §11.11.3): the
	// vault's app key once the recovery completes.
	APIKey []byte `json:"api_key,omitempty"`
}

// RecoveryRecord is the header's recovery state.
type RecoveryRecord struct {
	ID          string       `json:"id"`
	State       string       `json:"state"`
	RequestedAt time.Time    `json:"requested_at"`
	NotBefore   time.Time    `json:"not_before"`
	Expires     time.Time    `json:"expires"`
	CodeHash    []byte       `json:"code_hash,omitempty"`
	Attempts    int          `json:"attempts,omitempty"`
	App         *RecoveryApp `json:"app,omitempty"`
}

// RecoveryEvent is a recovery step recorded while the vault was locked; it
// moves into the audit log at the next unlock (§10.9).
type RecoveryEvent struct {
	At   time.Time `json:"at"`
	Kind string    `json:"kind"`
	Ref  string    `json:"ref"`
}

// Recovery errors and result codes.
var (
	ErrRecoveryNone    = errors.New("vault: no recovery in progress")
	ErrRecoveryEarly   = errors.New("vault: recovery code not yet valid")
	ErrRecoveryExpired = errors.New("vault: recovery expired")
	ErrRecoveryCode    = errors.New("vault: wrong recovery code")
	ErrRecoveryUsed    = errors.New("vault: recovery code already used")
	// ErrRecoveryNoCredential: a vault without a credential cannot be
	// recovered (§11.11.1).
	ErrRecoveryNoCredential = errors.New("vault: no credential; recovery refused")
	// ErrRecoveryNoBackup: a vault that keeps no backup copy of its
	// credential cannot be recovered (0.16.0, §11.11.1).
	ErrRecoveryNoBackup = errors.New("vault: no backup copy of the credential; recovery refused")
)

// Recovery result codes (§11.11).
const (
	CodeRecoveryPending = "recovery_pending"
	CodeRecoveryNone    = "no_recovery"
	CodeRecoveryEarly   = "too_early"
	CodeRecoveryExpired = "expired"
	CodeRecoveryCode    = "bad_code"
	CodeRecoveryUsed    = "used"
	// CodeNoBackup refuses a register or the registered app's unlock when
	// the vault keeps no backup copy of its credential (0.16.0).
	CodeNoBackup = "no_backup"
)

// RecoveryRefusal is the sealed refusal's error for a header (§11.11.1):
// "no_credential", "no_backup" (0.16.0), or "" when it may be recovered.
// A header from before 0.16.0 has no backup bit and counts as having a
// copy; the registered app's unlock then decides from the state.
func (h *Header) RecoveryRefusal() string {
	switch {
	case !h.HasCredential:
		return "no_credential"
	case h.CredentialBackup != nil && !*h.CredentialBackup:
		return "no_backup"
	}
	return ""
}

var codeEnc = base32.NewEncoding("0123456789ABCDEFGHJKMNPQRSTVWXYZ").WithPadding(base32.NoPadding)

// RecoveryCodeHash is the hash the header keeps (§11.11.2).
func RecoveryCodeHash(vaultID, recoveryID, code string) []byte {
	h := sha256.Sum256([]byte(labelRecoveryCode + "\x00" + vaultID + "\x00" + recoveryID + "\x00" + code))
	return h[:]
}

// ValidRecoveryCode reports whether s has the code's form (32 Crockford
// base32 characters, upper case).
func ValidRecoveryCode(s string) bool {
	if len(s) != 32 {
		return false
	}
	b, err := codeEnc.DecodeString(s)
	return err == nil && len(b) == RecoveryCodeBytes && codeEnc.EncodeToString(b) == s
}

// HeaderParams address one vault's sealed header without its PIN.
type HeaderParams struct {
	Options
	VaultID  string
	UserGUID string
}

// headerTx reads the header, applies fn and writes it back (header_seq + 1)
// with a conditional write. fn returning an error writes nothing unless
// keep is set (failure counters).
func headerTx(ctx context.Context, p HeaderParams, fn func(h *Header, now time.Time) (keep bool, err error)) error {
	p.Options.defaults()
	now := p.Now()
	if !validRelease(p.Release) || p.Store == nil || p.Sealer == nil {
		return ErrHeader
	}
	key := store.HeaderKey(p.VaultID, p.Release.PCR0)
	if !store.ValidKey(key) {
		return ErrMissing
	}
	blob, ver, err := p.Store.Get(ctx, key)
	if err != nil {
		return ErrMissing
	}
	h, err := unsealHeader(ctx, p.Sealer, blob, p.VaultID, p.Release.PCR0)
	if err != nil {
		return ErrHeader
	}
	defer suite.Wipe(h.Pepper)
	if h.UserGUID != p.UserGUID {
		return ErrHeader
	}
	if h.Deleting {
		// A deletion was interrupted (§12.5): finish it.
		_ = EraseStored(ctx, p.Store, p.VaultID, h.UserGUID, nil, p.Release.PCR0, "", "")
		return ErrMissing
	}
	keep, ferr := fn(h, now)
	if ferr != nil && !keep {
		return ferr
	}
	h.HeaderSeq++
	b, err := sealHeader(ctx, p.Sealer, h)
	if err != nil {
		return err
	}
	if _, err := p.Store.Put(ctx, key, b, ver); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return ErrSplitBrain
		}
		return err
	}
	return ferr
}

func (h *Header) logRecovery(now time.Time, kind, ref string) {
	h.RecoveryLog = append(h.RecoveryLog, RecoveryEvent{At: now, Kind: kind, Ref: ref})
	if n := len(h.RecoveryLog); n > maxRecoveryLog {
		h.RecoveryLog = append([]RecoveryEvent(nil), h.RecoveryLog[n-maxRecoveryLog:]...)
	}
}

// RecoveryRequest starts a recovery (§11.11.1): it mints the one-time code,
// records its hash, the delay and the expiry in the sealed header, and
// returns the code (which the caller seals to the member's browser key and
// never stores). A newer request replaces an older one.
func RecoveryRequest(ctx context.Context, p HeaderParams, recoveryID string, delay time.Duration) (code string, rec RecoveryRecord, err error) {
	raw, err := suite.RandomBytes(RecoveryCodeBytes)
	if err != nil {
		return "", rec, err
	}
	code = codeEnc.EncodeToString(raw)
	suite.Wipe(raw)
	err = headerTx(ctx, p, func(h *Header, now time.Time) (bool, error) {
		switch h.RecoveryRefusal() {
		case "no_credential":
			return false, ErrRecoveryNoCredential
		case "no_backup":
			return false, ErrRecoveryNoBackup
		}
		if h.Recovery != nil {
			h.logRecovery(now, "recovery.replaced", h.Recovery.ID)
			h.dropRecoveryKey()
		}
		rec = RecoveryRecord{ID: recoveryID, State: RecoveryPending, RequestedAt: now, NotBefore: now.Add(delay),
			Expires: now.Add(delay + RecoveryValidity), CodeHash: RecoveryCodeHash(p.VaultID, recoveryID, code)}
		h.Recovery = &rec
		h.logRecovery(now, "recovery.requested", recoveryID)
		return false, nil
	})
	if err != nil {
		return "", rec, err
	}
	return code, rec, nil
}

// RecoveryCancel ends a recovery (§11.11.4): the record and any registered
// key are removed. recoveryID "" cancels whatever is in progress.
func RecoveryCancel(ctx context.Context, p HeaderParams, recoveryID string) error {
	return headerTx(ctx, p, func(h *Header, now time.Time) (bool, error) {
		if h.Recovery == nil || recoveryID != "" && h.Recovery.ID != recoveryID {
			return false, ErrRecoveryNone
		}
		h.cancelRecovery(now, "recovery.cancelled")
		return false, nil
	})
}

func (h *Header) cancelRecovery(now time.Time, kind string) {
	if h.Recovery == nil {
		return
	}
	h.logRecovery(now, kind, h.Recovery.ID)
	h.dropRecoveryKey()
	h.Recovery = nil
}

// dropRecoveryKey removes a registered recovery app's unlock key.
func (h *Header) dropRecoveryKey() {
	if h.Recovery == nil || h.Recovery.App == nil {
		return
	}
	kept := h.UnlockKeys[:0]
	for _, k := range h.UnlockKeys {
		if !suite.EqualPublic(k.IK, h.Recovery.App.IK) {
			kept = append(kept, k)
		}
	}
	h.UnlockKeys = kept
}

// RecoveryRegister presents the code and registers the new app as an
// unlock key (§11.11.3). verify checks the app's device attestation and
// returns its binding; it runs only after the code matched.
func RecoveryRegister(ctx context.Context, p HeaderParams, recoveryID, code string, app RecoveryApp,
	verify func() (json.RawMessage, error)) error {
	return headerTx(ctx, p, func(h *Header, now time.Time) (bool, error) {
		r := h.Recovery
		if r == nil || r.ID != recoveryID {
			return false, ErrRecoveryNone
		}
		if r.State != RecoveryPending {
			return false, ErrRecoveryUsed
		}
		if h.RecoveryRefusal() != "" {
			// §11.11.3 check 2 (0.16.0): no credential or no backup copy.
			h.cancelRecovery(now, "recovery.cancelled")
			return true, ErrRecoveryNoBackup
		}
		if !now.Before(r.Expires) {
			h.cancelRecovery(now, "recovery.expired")
			return true, ErrRecoveryExpired
		}
		if now.Before(r.NotBefore) {
			return false, ErrRecoveryEarly
		}
		want := RecoveryCodeHash(p.VaultID, recoveryID, code)
		if !ValidRecoveryCode(code) || subtle.ConstantTimeCompare(want, r.CodeHash) != 1 {
			r.Attempts++
			h.logRecovery(now, "recovery.bad_code", r.ID)
			if r.Attempts >= RecoveryMaxAttempts {
				h.cancelRecovery(now, "recovery.voided")
			}
			return true, ErrRecoveryCode
		}
		b, err := verify()
		if err != nil {
			h.logRecovery(now, "recovery.attestation_failed", r.ID)
			return true, ErrDeviceAttestation
		}
		app.Attestation = b
		r.State, r.CodeHash, r.App = RecoveryRegistered, nil, &app
		h.UnlockKeys = append(h.UnlockKeys, UnlockKey{DeviceID: recoveryDeviceID, IK: app.IK, KEM: app.KEM, Attestation: b})
		sortUnlockKeys(h.UnlockKeys)
		h.logRecovery(now, "recovery.registered", r.ID)
		return false, nil
	})
}

// RecoveryCodeResult maps a register error to its result code.
func RecoveryCodeResult(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrRecoveryNone):
		return CodeRecoveryNone
	case errors.Is(err, ErrRecoveryEarly):
		return CodeRecoveryEarly
	case errors.Is(err, ErrRecoveryExpired):
		return CodeRecoveryExpired
	case errors.Is(err, ErrRecoveryCode):
		return CodeRecoveryCode
	case errors.Is(err, ErrRecoveryUsed):
		return CodeRecoveryUsed
	case errors.Is(err, ErrRecoveryNoBackup), errors.Is(err, ErrRecoveryNoCredential):
		return CodeNoBackup
	case errors.Is(err, ErrDeviceAttestation):
		return CodeAttestation
	}
	return CodeRetry
}

// isRecoveryKey reports whether k is the registered recovery app's key.
func (h *Header) isRecoveryKey(ik []byte) bool {
	return h.Recovery != nil && h.Recovery.State == RecoveryRegistered && h.Recovery.App != nil &&
		suite.EqualPublic(h.Recovery.App.IK, ik)
}

// --- after the PIN unlock (DEK state available) ---

// applyRecovery runs at every resume: it moves the header's recovery log
// into the audit log, removes recovering devices whose recovery is gone,
// and lets the registered app run its first handshake (like the first app
// at enrollment, §11.3) with ctx = recovery id.
func (m *Manager) applyRecovery(now time.Time) {
	for _, e := range m.hdr.RecoveryLog {
		m.record(Activity{Kind: e.Kind, Ref: e.Ref, Audit: true}, e.At)
	}
	m.hdr.RecoveryLog = nil
	r := m.hdr.Recovery
	for _, p := range m.st.Devices {
		if p.Recovering && (r == nil || r.App == nil || !suite.EqualPublic(r.App.IK, p.IK)) {
			m.removePeer(p, "device.unlinked", now)
		}
	}
	if r == nil || r.State != RecoveryRegistered || r.App == nil {
		return
	}
	if inv := m.st.Invites[r.ID]; inv == nil {
		m.st.Invites[r.ID] = &Invite{ID: r.ID, Kind: KindApp, Exp: r.Expires, EnrollIK: r.App.IK, EnrollRelayPK: r.App.RelayPK,
			EnrollKEM: r.App.KEM, EnrollAttest: r.App.Attestation, CreatedBy: inviteByRecovery}
		m.dirty = true
	}
}

const inviteByRecovery = "recovery"

// completeRecovery ends a recovery after credential.recover (§11.11.5): the
// device becomes an ordinary app and the header's record goes.
func (m *Manager) completeRecovery(deviceID string, now time.Time) error {
	p := m.st.Devices[deviceID]
	if p == nil || !p.Recovering {
		return errNotFound
	}
	p.Recovering = false
	m.replaceAfter = deviceID // the other apps go (§11.11.5), after the handler
	if r := m.hdr.Recovery; r != nil && r.App != nil && len(r.App.APIKey) > 0 {
		m.setAppKey(r.App.APIKey) // §11.11.5 step 3 (0.15.0)
	}
	if m.hdr.Recovery != nil {
		m.hdr.logRecovery(now, "recovery.completed", m.hdr.Recovery.ID)
		delete(m.st.Invites, m.hdr.Recovery.ID)
		m.hdr.Recovery = nil
	}
	for _, e := range m.hdr.RecoveryLog {
		m.record(Activity{Kind: e.Kind, Ref: e.Ref, DeviceID: deviceID, Audit: true}, e.At)
	}
	m.hdr.RecoveryLog = nil
	m.dirty = true
	m.notifyDevices("sync.event", strictjson.NewBuilder().String("kind", "device.paired").String("device_id", p.ID).
		String("role", p.Kind).Bytes(), p.ID, now)
	return nil
}

// recoveryAllowed lists what a recovering device may send (§11.11.5).
// 0.16.0 removed credential.reset and vault.delete: there is no recovery
// with the backup off.
var recoveryAllowed = map[string]bool{"credential.recover": true, "credential.utk.get": true, "vault.status": true,
	"relay.token.issued": true, "relay.token.refresh": true, "relay.address.update": true}
