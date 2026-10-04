package enclave

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vault/store"
	"github.com/vettid/vettid-vault/vms/altchan"
	"github.com/vettid/vettid-vault/vms/devattest"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/manifest"
	"github.com/vettid/vettid-vault/vms/nitro"
	"github.com/vettid/vettid-vault/vms/suite"
)

// CoreDeps are what a vault's enroll and unlock logic needs. In the
// enclave (D4) a Core runs inside the vault's own process, and every
// dependency reaches the supervisor over the vault's channel; in tests and
// development (LocalHost) they are in-process.
type CoreDeps struct {
	Config Config
	// Meas are the enclave's PCRs (from the NSM, through the supervisor).
	Meas  nitro.Measurements
	Store store.Store
	KMS   KMS
	// AttestRecipient returns an attestation document binding the
	// Recipient public key (DER) for KMS (§11.10.2).
	AttestRecipient func(publicKey []byte) ([]byte, error)
	// AttestVault returns the vault.enrolled attestation: user_data =
	// SHA-256("vettid/vms/2/vault" || bundle), nonce (§11.3).
	AttestVault func(bundle, nonce []byte) ([]byte, error)
	StatusList  func() *devattest.StatusList
	// Vault is the template for the vault's options.
	Vault     vault.Options
	Features  func() []vault.Feature
	Lifecycle func(vault.LifecycleEvent)
	Now       func() time.Time
}

// Core runs enroll and unlock (§11.3, §11.4, §11.10.4) for requests the
// outer instance has already decrypted and bound (Job). It owns the
// vault's secrets and its KMS Recipient key.
type Core struct {
	d    CoreDeps
	cfg  Config
	meas nitro.Measurements
	st   store.Store
	kms  KMS
	rcpt *recipient
	now  func() time.Time
}

// NewCore checks the dependencies and creates the Recipient key.
func NewCore(d CoreDeps) (*Core, error) {
	if d.Store == nil || d.KMS == nil || d.AttestRecipient == nil || d.AttestVault == nil || d.Config.DeviceAttest == nil ||
		!manifest.ValidPCR(d.Meas.PCR0) || d.Meas.IsDebug() {
		return nil, ErrConfig
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Config.KDF == nil {
		d.Config.KDF = vault.DefaultKDF
	}
	r, err := newRecipient()
	if err != nil {
		return nil, err
	}
	return &Core{d: d, cfg: d.Config, meas: d.Meas, st: d.Store, kms: d.KMS, rcpt: r, now: d.Now}, nil
}

func (c *Core) release() vault.Release {
	return vault.Release{PCR0: c.meas.PCR0, Number: c.cfg.ReleaseNumber}
}

// Open runs an enroll or unlock job and returns the sealed result (or
// random bytes of its size) and the unlocked manager, if the vault is now
// open. The caller runs the manager.
func (c *Core) Open(ctx context.Context, j *Job) ([]byte, *vault.Manager) {
	var m *vault.Manager
	var res []byte
	switch j.Op {
	case OpEnroll:
		res = c.enroll(ctx, j, &m)
	case OpUnlock:
		res = c.unlock(ctx, j, &m)
	case OpRecovery:
		res = c.recoveryRequest(ctx, j)
	case OpRecoveryCancel:
		c.recoveryCancel(ctx, j)
	case OpRecoveryRegister:
		res = c.recoveryRegister(ctx, j)
	default:
		res = opaque()
	}
	return res, m
}

// UserIndexKey is the store key of the enclave's member index object.
func UserIndexKey(userGUID string) string { return store.UserKey(userHash(userGUID)) }

func (c *Core) statusList() *devattest.StatusList {
	if c.d.StatusList == nil {
		return nil
	}
	return c.d.StatusList()
}

// verifyManifest checks the served manifest the host supplied (doc)
// against the hash and serial in the sealed request (0.10.0, M1) and under
// the pinned keys, applies the serial rule, and finds this release's
// entry, which must match the embedded release number and the measured
// PCR1 and PCR2. Every failure is the result code manifest.
func (c *Core) verifyManifest(doc []byte, sha256Hex string, serial, serialSeen uint64) (*manifest.Manifest, *manifest.Release, error) {
	m, err := manifest.VerifyByHash(doc, sha256Hex, serial, c.cfg.ManifestKeys)
	if err != nil {
		return nil, nil, err
	}
	if err := m.CheckSerial(serialSeen); err != nil {
		return nil, nil, err
	}
	own, ok := m.ByPCR0(c.meas.PCR0)
	if !ok || own.Number != c.cfg.ReleaseNumber || own.PCR1 != c.meas.PCR1 || own.PCR2 != c.meas.PCR2 {
		return nil, nil, manifest.ErrNoRelease
	}
	return m, own, nil
}

func entryOf(r *manifest.Release) vault.ReleaseEntry {
	return vault.ReleaseEntry{PCR0: r.PCR0, Number: r.Number, Status: r.Status, SealKey: r.SealKey}
}

// vaultOptions builds a vault's options for this instance and release.
func (c *Core) vaultOptions(sealer vault.Sealer) vault.Options {
	o := c.d.Vault
	o.Store, o.Sealer, o.Release = c.st, sealer, c.release()
	o.Now = c.now
	if c.d.Features != nil {
		o.Features = c.d.Features()
	}
	o.Lifecycle = c.emit
	pol := c.cfg.DeviceAttest
	o.DeviceAttest = func(d *altchan.DeviceAttest, ch [32]byte, now time.Time) (json.RawMessage, error) {
		b, err := devattest.VerifyAttest(pol, d, ch, now, c.statusList())
		if err != nil {
			return nil, err
		}
		return json.Marshal(b)
	}
	return o
}

func (c *Core) emit(ev vault.LifecycleEvent) {
	if c.d.Lifecycle != nil {
		c.d.Lifecycle(ev)
	}
}

// userHash is the store key component for a member (hex SHA-256).
func userHash(guid string) string {
	h := sha256.Sum256([]byte("vettid/vms/2/user\x00" + guid))
	return hex.EncodeToString(h[:])
}

func (c *Core) enroll(ctx context.Context, q *Job, started **vault.Manager) []byte {
	inner := q.Inner
	now := c.now()
	o, err := strictjson.ParseObject(inner.Body)
	if err != nil {
		return opaque()
	}
	kem, err := altchan.EnrollKEM(o)
	if err != nil {
		return opaque()
	}
	answer := func(r *altchan.EnrollResult) []byte {
		env, err := altchan.SealResult(kem, altchan.TypeEnrollResult, q.RequestID, r.Marshal(), now)
		if err != nil {
			return opaque()
		}
		return env
	}
	fail := func(code string) []byte { return answer(&altchan.EnrollResult{Code: code}) }
	r, err := altchan.ParseEnrollRequest(o)
	if err != nil || handshake.ValidateRelayAddr(handshake.RelayAddr{URL: r.Relay.URL, Mailbox: r.Relay.Mailbox, PK: r.Relay.PK}) != nil {
		return fail("bad_request")
	}
	if r.UserGUID != q.UserGUID || r.RequestID != q.RequestID {
		return opaque() // binding (§11.3): a redirected request is rejected
	}
	m, own, err := c.verifyManifest(q.Manifest, r.ManifestSHA256, r.ManifestSerial, 0)
	if err != nil || own.Status != manifest.StatusActive {
		return fail("manifest") // enrollment goes only to an active release
	}
	ch, err := altchan.DevattChallenge(q.RequestID, "", envelope.FormatTS(inner.TS))
	if err != nil {
		return fail("bad_request")
	}
	b, err := devattest.VerifyAttest(c.cfg.DeviceAttest, r.Attest, ch, now, c.statusList())
	if err != nil {
		return fail("attestation")
	}
	binding, err := json.Marshal(b)
	if err != nil {
		return fail("retry")
	}
	if !c.inNamespace(own.SealKey) {
		return fail("release_key")
	}
	replace, code := c.checkExisting(ctx, q, own.SealKey, now)
	if code != "" {
		return fail(code)
	}
	rec, err := c.checkKey(ctx, m, own)
	if err != nil {
		return fail("release_key")
	}
	kdf, err := c.cfg.KDF()
	if err != nil {
		return fail("retry")
	}
	sealer := c.sealerFor(own.SealKey, c.meas.PCR0)
	nonce := r.Nonce
	mgr, err := vault.Create(ctx, vault.CreateParams{
		Options: c.vaultOptions(sealer), VaultID: q.VaultID, UserGUID: q.UserGUID, PIN: r.PIN, KDF: kdf,
		RelayURL: c.cfg.RelayURL, Provisional: true, ManifestSerial: m.Serial, SealKeyVerified: rec, Replace: replace,
		App: &vault.EnrollApp{Name: r.Name, IK: r.IK, KEM: r.KEM, OpenToken: r.OpenToken, RequestID: q.RequestID,
			Relay:       vault.PeerRelay{URL: r.Relay.URL, Mailbox: r.Relay.Mailbox, PK: r.Relay.PK},
			Attestation: binding,
			Attest: func(bundle []byte) ([]byte, error) {
				return c.d.AttestVault(bundle, nonce)
			}},
	})
	if err != nil {
		sealer.Destroy()
		if errors.Is(err, store.ErrConflict) {
			return fail("vault_exists")
		}
		return fail("retry")
	}
	c.indexUser(ctx, q.UserGUID, q.VaultID)
	c.emit(vault.LifecycleEvent{Event: "enrolled", VaultID: q.VaultID, Release: c.meas.PCR0, VaultVersion: c.meas.PCR0, StateVersion: vault.StateVersion})
	c.emit(vault.LifecycleEvent{Event: "unlocked", VaultID: q.VaultID, Release: c.meas.PCR0, VaultVersion: c.meas.PCR0, StateVersion: vault.StateVersion})
	*started = mgr
	return answer(&altchan.EnrollResult{OK: true, VaultID: q.VaultID})
}

// checkExisting applies §11.3 "Provisional vaults" and "Re-enrollment".
// The API reuses a member's vault_id, so an enrollment may name a vault
// that exists: it is refused with vault_exists if that vault is confirmed,
// provisional for less than 24 h, or sealed to another release (the
// enclave cannot tell), and otherwise replaced (the returned versions make
// the new objects overwrite the old ones). The same rule applies through
// the enclave's member index to another vault_id of the same member.
func (c *Core) checkExisting(ctx context.Context, q *Job, ownKey string, now time.Time) (*vault.Replace, string) {
	// replaceable reports whether vault id may be replaced, with the
	// versions of its state and this release's header.
	replaceable := func(id string) (*vault.Replace, bool, error) {
		_, sv, err := c.st.Get(ctx, store.StateKey(id))
		if errors.Is(err, store.ErrNotFound) {
			if _, hv, herr := c.st.Get(ctx, store.HeaderKey(id, c.meas.PCR0)); herr == nil {
				return &vault.Replace{Header: hv}, true, nil // a header without state: a broken enrollment
			}
			return nil, true, nil
		}
		if err != nil {
			return nil, false, err
		}
		hblob, hv, err := c.st.Get(ctx, store.HeaderKey(id, c.meas.PCR0))
		if err != nil {
			return nil, false, nil // sealed to another release: cannot tell, refuse
		}
		s := c.sealerFor(ownKey, c.meas.PCR0)
		defer s.Destroy()
		h, err := vault.PeekHeader(ctx, s, hblob, id, c.meas.PCR0)
		if err != nil || !h.Provisional || now.Sub(h.CreatedAt) < vault.EnrollWindow {
			return nil, false, nil
		}
		return &vault.Replace{State: sv, Header: hv}, true, nil
	}
	rep, ok, err := replaceable(q.VaultID)
	if err != nil {
		return nil, "retry"
	}
	if !ok {
		return nil, "vault_exists"
	}
	idx, _, err := c.st.Get(ctx, store.UserKey(userHash(q.UserGUID)))
	if errors.Is(err, store.ErrNotFound) {
		return rep, ""
	}
	if err != nil {
		return nil, "retry"
	}
	prev := string(idx)
	if prev == q.VaultID {
		return rep, ""
	}
	if !validID(prev) {
		return nil, "vault_exists"
	}
	if _, ok, err := replaceable(prev); err != nil {
		return nil, "retry"
	} else if !ok {
		return nil, "vault_exists"
	}
	return rep, ""
}

func (c *Core) indexUser(ctx context.Context, guid, vaultID string) {
	k := store.UserKey(userHash(guid))
	if _, err := c.st.Put(ctx, k, []byte(vaultID), ""); errors.Is(err, store.ErrConflict) {
		if _, v, err := c.st.Get(ctx, k); err == nil {
			_, _ = c.st.Put(ctx, k, []byte(vaultID), v)
		}
	}
}

func (c *Core) unlock(ctx context.Context, q *Job, started **vault.Manager) []byte {
	inner := q.Inner
	now := c.now()
	o, err := strictjson.ParseObject(inner.Body)
	if err != nil {
		return opaque()
	}
	r, err := altchan.ParseUnlockRequest(o)
	if err != nil {
		return opaque()
	}
	if r.UserGUID != q.UserGUID || r.VaultID != q.VaultID || r.RequestID != q.RequestID {
		return opaque() // redirected (§11.6)
	}
	ts := envelope.FormatTS(inner.TS)
	ch, err := altchan.DevattChallenge(q.RequestID, q.VaultID, ts)
	if err != nil {
		return opaque()
	}
	toPCR0 := ""
	if r.Update != nil {
		toPCR0 = r.Update.To
	}
	signing, err := altchan.UnlockSigningString(altchan.UnlockFields{UserGUID: r.UserGUID, VaultID: r.VaultID,
		RequestID: r.RequestID, TS: ts, ETKKid: q.ETKKid, MinStateSeq: r.MinStateSeq, MinHeaderSeq: r.MinHeaderSeq,
		PIN: r.PIN, Token: r.Token, ManifestSHA256: r.ManifestSHA256, ToPCR0: toPCR0, CancelRecovery: r.CancelRecovery})
	if err != nil {
		return opaque()
	}
	pol := c.cfg.DeviceAttest
	list := c.statusList()
	var man *manifest.Manifest
	var preCounter, unlockCounter uint32
	sealer := c.sealerFor("", c.meas.PCR0)
	p := vault.AltUnlockParams{
		Options: c.vaultOptions(sealer), VaultID: q.VaultID, UserGUID: q.UserGUID, DeviceIK: r.DeviceIK, PIN: r.PIN,
		MinStateSeq: r.MinStateSeq, MinHeaderSeq: r.MinHeaderSeq, DeviceToken: r.Token, CancelRecovery: r.CancelRecovery,
	}
	p.VerifyDevice = func(k *vault.UnlockKey) (json.RawMessage, error) {
		if !ed25519.Verify(ed25519.PublicKey(k.IK), []byte(signing), r.Sig) {
			return nil, vault.ErrDeviceSig
		}
		var b devattest.Binding
		if len(k.Attestation) == 0 || json.Unmarshal(k.Attestation, &b) != nil {
			return nil, vault.ErrDeviceAttestation
		}
		preCounter = b.Counter
		nb, err := devattest.VerifyAssertion(pol, &b, r.Assertion, devattest.ForChallenge(ch), b.Counter, now, list)
		if err != nil {
			return nil, vault.ErrDeviceAttestation
		}
		unlockCounter = nb.Counter
		return json.Marshal(nb)
	}
	p.Manifest = func(seen uint64) (*vault.ManifestView, error) {
		m, own, err := c.verifyManifest(q.Manifest, r.ManifestSHA256, r.ManifestSerial, seen)
		if err != nil {
			return nil, err
		}
		if sealer.OpenedKey() != own.SealKey {
			return nil, manifest.ErrNoRelease // the header is not under this release's listed key
		}
		man = m
		return &vault.ManifestView{Serial: m.Serial, Own: entryOf(own), Lookup: func(pcr0 string) (vault.ReleaseEntry, bool) {
			e, ok := m.ByPCR0(pcr0)
			if !ok {
				return vault.ReleaseEntry{}, false
			}
			return entryOf(e), true
		}}, nil
	}
	p.OwnKeyCheck = func(ctx context.Context, own vault.ReleaseEntry) (*vault.SealKeyRecord, error) {
		e, ok := man.ByPCR0(own.PCR0)
		if !ok || !c.inNamespace(e.SealKey) {
			return nil, vault.ErrSealKeyNamespace
		}
		return c.checkKey(ctx, man, e)
	}
	p.SealerFor = func(ctx context.Context, t vault.ReleaseEntry) (vault.Sealer, *vault.SealKeyRecord, error) {
		e, ok := man.ByPCR0(t.PCR0)
		if !ok || !c.inNamespace(e.SealKey) {
			return nil, nil, vault.ErrSealKeyNamespace
		}
		rec, err := c.checkKey(ctx, man, e)
		if err != nil {
			return nil, nil, vault.ErrSealKey
		}
		return c.sealerFor(e.SealKey, e.PCR0), rec, nil
	}
	if u := r.Update; u != nil {
		p.Update = &vault.UpdateRequest{To: u.To, ToRelease: u.ToRelease, VerifyApproval: func(k *vault.UnlockKey) (json.RawMessage, error) {
			var b devattest.Binding
			if man == nil || json.Unmarshal(k.Attestation, &b) != nil {
				return nil, vault.ErrDeviceAttestation
			}
			s, err := altchan.ApprovalSigningString(q.VaultID, q.RequestID, c.meas.PCR0, u.To, u.ToRelease, man.Serial)
			if err != nil {
				return nil, vault.ErrDeviceAttestation
			}
			nb, err := devattest.VerifyAssertion(pol, &b, u.Approval, devattest.ForString(s), preCounter, now, list)
			if err != nil || b.Platform == altchan.PlatformIOS && nb.Counter == unlockCounter {
				return nil, vault.ErrDeviceAttestation
			}
			if nb.Counter < b.Counter {
				nb.Counter = b.Counter
			}
			return json.Marshal(nb)
		}}
	}
	mgr, out := vault.UnlockAlt(ctx, p)
	for _, ev := range out.Events {
		c.emit(ev)
	}
	if out.Drop {
		sealer.Destroy()
		return opaque()
	}
	kem, err := suite.ParsePublicKey(out.DeviceKEM)
	if err != nil {
		sealer.Destroy()
		if mgr != nil {
			_ = mgr.Lock(ctx)
		}
		return opaque()
	}
	res := &altchan.UnlockResult{OK: out.OK, Code: out.Code, StateSeq: out.StateSeq, HeaderSeq: out.HeaderSeq,
		RetryAfter: uint64((out.RetryAfter + time.Second - 1) / time.Second), Token: out.Token,
		Release: c.meas.PCR0, ReleaseNumber: c.cfg.ReleaseNumber, ReleaseStatus: out.Release.Status, ManifestSerial: out.Serial,
		RecoveryCancelled: out.RecoveryCancelled, VaultBundle: out.VaultBundle}
	if u := out.Update; u != nil {
		res.Update = &altchan.UpdateResult{To: u.To, Result: u.Result, Code: u.Code}
	}
	if mgr != nil {
		*started = mgr
	} else {
		sealer.Destroy()
	}
	env, err := altchan.SealResult(kem, altchan.TypeUnlockResult, q.RequestID, res.Marshal(), now)
	if err != nil {
		return opaque()
	}
	return env
}
