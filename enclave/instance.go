package enclave

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
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

// Options configure an Instance.
type Options struct {
	Config Config
	NSM    NSM
	KMS    KMS
	Store  store.Store
	// StatusList returns the cached Google attestation status list
	// (§11.7); nil means none has been fetched. The fetch is phase V3b.
	StatusList func() *devattest.StatusList
	// Vault is the template for every vault's options (relay transport,
	// collect mode, features); Store, Sealer, Release, DeviceAttest and
	// Lifecycle are set by the instance.
	Vault vault.Options
	// Features returns fresh feature handlers for one vault.
	Features func() []vault.Feature
	// Lifecycle receives lifecycle events for the parent (§11.5).
	Lifecycle func(vault.LifecycleEvent)
	// Stopped, if set, is told when a vault's run loop ends and why (an
	// error is a sentinel without secrets).
	Stopped func(vaultID string, err error)
	Now     func() time.Time
}

// Instance is one enclave instance: its ETKs and the vaults it holds.
type Instance struct {
	opt  Options
	cfg  Config
	nsm  NSM
	kms  KMS
	st   store.Store
	meas nitro.Measurements
	rcpt *recipient
	now  func() time.Time

	mu     sync.Mutex // ETKs and replay sets
	reqMu  sync.Mutex // serializes alternate-channel requests
	etks   []*etk
	vmu    sync.Mutex
	vaults map[string]*running
}

type running struct {
	m      *vault.Manager
	cancel context.CancelFunc
	done   chan struct{}
}

// Errors.
var (
	ErrConfig = errors.New("enclave: invalid configuration")
	errDrop   = errors.New("enclave: request dropped")
)

// New starts an instance: it reads its measurements, creates its KMS
// recipient key and its first ETK.
func New(opt Options) (*Instance, error) {
	if opt.NSM == nil || opt.KMS == nil || opt.Store == nil || opt.Config.DeviceAttest == nil || !altchan.ValidInstanceID(opt.Config.InstanceID) {
		return nil, ErrConfig
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.Config.KDF == nil {
		opt.Config.KDF = vault.DefaultKDF
	}
	in := &Instance{opt: opt, cfg: opt.Config, nsm: opt.NSM, kms: opt.KMS, st: opt.Store, now: opt.Now, vaults: map[string]*running{}}
	m, err := opt.NSM.Measurements()
	if err != nil || !manifest.ValidPCR(m.PCR0) || m.IsDebug() {
		return nil, ErrConfig // a debug-mode enclave has no release to run as
	}
	in.meas = m
	if in.rcpt, err = newRecipient(); err != nil {
		return nil, err
	}
	if err := in.RotateETK(); err != nil {
		return nil, err
	}
	return in, nil
}

// Release returns the running release.
func (in *Instance) Release() vault.Release {
	return vault.Release{PCR0: in.meas.PCR0, Number: in.cfg.ReleaseNumber}
}

// ProcessRaw handles one raw queue message and returns the raw response.
// A message that does not parse gets no response (nil).
func (in *Instance) ProcessRaw(ctx context.Context, b []byte) []byte {
	q, err := ParseQueueMessage(b)
	if err != nil {
		return nil
	}
	return in.Process(ctx, q).Marshal()
}

// Process handles one queue message (§11.5).
func (in *Instance) Process(ctx context.Context, q *QueueMessage) *Response {
	in.reqMu.Lock()
	defer in.reqMu.Unlock()
	resp := &Response{RequestID: q.RequestID, Status: StatusDone}
	switch q.Op {
	case OpLock:
		in.lockVault(ctx, q.VaultID)
	case OpDelete:
		in.deleteVault(ctx, q.VaultID)
	case OpEnroll, OpUnlock:
		inner, e, err := in.openRequest(q)
		if errors.Is(err, errETKUnknown) {
			resp.Status = StatusETKUnknown
			return resp
		}
		if err != nil {
			resp.Envelope = opaque()
			return resp
		}
		if q.Op == OpEnroll {
			resp.Envelope = in.enroll(ctx, q, inner, e)
		} else {
			resp.Envelope = in.unlock(ctx, q, inner, e)
		}
	}
	return resp
}

var errETKUnknown = errors.New("enclave: unknown or expired etk_kid")

// openRequest decrypts and binds an alternate-channel request (§11.3
// "Binding", §11.6): the ETK by kid, a sealed envelope with an all-zero
// sender kid, exactly 12,288 bytes of padding, the inner type for the op,
// inner id = request_id, ts within 5 minutes, and a request_id not seen
// under this ETK.
func (in *Instance) openRequest(q *QueueMessage) (*envelope.Inner, *etk, error) {
	now := in.now()
	env, err := envelope.Parse(q.Envelope)
	if err != nil || env.Mode() != envelope.ModeSealed || !env.SenderKid().Equal(suite.Anonymous) {
		in.mu.Lock()
		known := in.lookupETK(q.ETKKid, now) != nil
		in.mu.Unlock()
		if !known {
			return nil, nil, errETKUnknown
		}
		return nil, nil, errDrop
	}
	// Decrypt under the ETK lock, so that rotation cannot destroy the key
	// in use.
	in.mu.Lock()
	e := in.lookupETK(q.ETKKid, now)
	if e == nil {
		in.mu.Unlock()
		return nil, nil, errETKUnknown
	}
	padded, _, err := envelope.OpenSealed(env, e.key)
	in.mu.Unlock()
	if err != nil {
		return nil, nil, errDrop
	}
	js, err := envelope.UnpadFixed(padded, altchan.RequestPaddedSize)
	if err != nil {
		return nil, nil, errDrop
	}
	inner, err := envelope.ParseInner(js, envelope.ModeSealed)
	if err != nil {
		return nil, nil, errDrop
	}
	want := map[string]string{OpEnroll: altchan.TypeEnroll, OpUnlock: altchan.TypeUnlock}[q.Op]
	if inner.Type != want || inner.ID != q.RequestID || inner.Re != "" {
		return nil, nil, errDrop
	}
	if d := now.Sub(inner.TS); d > MaxSkew || d < -MaxSkew {
		return nil, nil, errDrop
	}
	in.mu.Lock()
	defer in.mu.Unlock()
	if e.seen == nil || len(e.seen) >= maxSeen {
		return nil, nil, errDrop
	}
	if _, dup := e.seen[q.RequestID]; dup {
		return nil, nil, errDrop // replay (§11.6)
	}
	e.seen[q.RequestID] = struct{}{}
	return inner, e, nil
}

func (in *Instance) statusList() *devattest.StatusList {
	if in.opt.StatusList == nil {
		return nil
	}
	return in.opt.StatusList()
}

// verifyManifest checks the served manifest under the pinned keys and
// finds this release's entry, which must match the embedded release number
// and the measured PCR1 and PCR2.
func (in *Instance) verifyManifest(s *manifest.Served, serialSeen uint64) (*manifest.Manifest, *manifest.Release, error) {
	m, err := manifest.Verify(s, in.cfg.ManifestKeys)
	if err != nil {
		return nil, nil, err
	}
	if err := m.CheckSerial(serialSeen); err != nil {
		return nil, nil, err
	}
	own, ok := m.ByPCR0(in.meas.PCR0)
	if !ok || own.Number != in.cfg.ReleaseNumber || own.PCR1 != in.meas.PCR1 || own.PCR2 != in.meas.PCR2 {
		return nil, nil, manifest.ErrNoRelease
	}
	return m, own, nil
}

func entryOf(r *manifest.Release) vault.ReleaseEntry {
	return vault.ReleaseEntry{PCR0: r.PCR0, Number: r.Number, Status: r.Status, SealKey: r.SealKey}
}

// vaultOptions builds a vault's options for this instance and release.
func (in *Instance) vaultOptions(sealer vault.Sealer) vault.Options {
	o := in.opt.Vault
	o.Store, o.Sealer, o.Release = in.st, sealer, in.Release()
	o.Now = in.now
	if in.opt.Features != nil {
		o.Features = in.opt.Features()
	}
	o.Lifecycle = in.emit
	pol := in.cfg.DeviceAttest
	o.DeviceAttest = func(d *altchan.DeviceAttest, ch [32]byte, now time.Time) (json.RawMessage, error) {
		b, err := devattest.VerifyAttest(pol, d, ch, now, in.statusList())
		if err != nil {
			return nil, err
		}
		return json.Marshal(b)
	}
	return o
}

func (in *Instance) emit(ev vault.LifecycleEvent) {
	if in.opt.Lifecycle != nil {
		in.opt.Lifecycle(ev)
	}
}

// userHash is the store key component for a member (hex SHA-256).
func userHash(guid string) string {
	h := sha256.Sum256([]byte("vettid/vms/2/user\x00" + guid))
	return hex.EncodeToString(h[:])
}

// --- enrollment (§11.3) ---

func (in *Instance) enroll(ctx context.Context, q *QueueMessage, inner *envelope.Inner, _ *etk) []byte {
	now := in.now()
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
	m, own, err := in.verifyManifest(r.Manifest, 0)
	if err != nil || own.Status != manifest.StatusActive {
		return fail("manifest") // enrollment goes only to an active release
	}
	ch, err := altchan.DevattChallenge(q.RequestID, "", envelope.FormatTS(inner.TS))
	if err != nil {
		return fail("bad_request")
	}
	b, err := devattest.VerifyAttest(in.cfg.DeviceAttest, r.Attest, ch, now, in.statusList())
	if err != nil {
		return fail("attestation")
	}
	binding, err := json.Marshal(b)
	if err != nil {
		return fail("retry")
	}
	if !in.inNamespace(own.SealKey) {
		return fail("release_key")
	}
	replace, code := in.checkExisting(ctx, q, own.SealKey, now)
	if code != "" {
		return fail(code)
	}
	rec, err := in.checkKey(ctx, m, own)
	if err != nil {
		return fail("release_key")
	}
	kdf, err := in.cfg.KDF()
	if err != nil {
		return fail("retry")
	}
	sealer := in.sealerFor(own.SealKey, in.meas.PCR0)
	nonce := r.Nonce
	mgr, err := vault.Create(ctx, vault.CreateParams{
		Options: in.vaultOptions(sealer), VaultID: q.VaultID, UserGUID: q.UserGUID, PIN: r.PIN, KDF: kdf,
		RelayURL: in.cfg.RelayURL, Provisional: true, ManifestSerial: m.Serial, SealKeyVerified: rec, Replace: replace,
		App: &vault.EnrollApp{Name: r.Name, IK: r.IK, KEM: r.KEM, OpenToken: r.OpenToken, RequestID: q.RequestID,
			Relay:       vault.PeerRelay{URL: r.Relay.URL, Mailbox: r.Relay.Mailbox, PK: r.Relay.PK},
			Attestation: binding,
			Attest: func(bundle []byte) ([]byte, error) {
				ud := altchan.VaultUserData(bundle)
				return in.nsm.Attest(ud[:], nonce, nil)
			}},
	})
	if err != nil {
		sealer.Destroy()
		if errors.Is(err, store.ErrConflict) {
			return fail("vault_exists")
		}
		return fail("retry")
	}
	in.indexUser(ctx, q.UserGUID, q.VaultID)
	in.emit(vault.LifecycleEvent{Event: "enrolled", VaultID: q.VaultID, Release: in.meas.PCR0, VaultVersion: in.meas.PCR0, StateVersion: vault.StateVersion})
	in.emit(vault.LifecycleEvent{Event: "unlocked", VaultID: q.VaultID, Release: in.meas.PCR0, VaultVersion: in.meas.PCR0, StateVersion: vault.StateVersion})
	in.startVault(q.VaultID, mgr)
	return answer(&altchan.EnrollResult{OK: true, VaultID: q.VaultID})
}

// checkExisting applies §11.3 "Provisional vaults" and "Re-enrollment".
// The API reuses a member's vault_id, so an enrollment may name a vault
// that exists: it is refused with vault_exists if that vault is confirmed,
// provisional for less than 24 h, or sealed to another release (the
// enclave cannot tell), and otherwise replaced (the returned versions make
// the new objects overwrite the old ones). The same rule applies through
// the enclave's member index to another vault_id of the same member.
func (in *Instance) checkExisting(ctx context.Context, q *QueueMessage, ownKey string, now time.Time) (*vault.Replace, string) {
	// replaceable reports whether vault id may be replaced, with the
	// versions of its state and this release's header.
	replaceable := func(id string) (*vault.Replace, bool, error) {
		_, sv, err := in.st.Get(ctx, store.StateKey(id))
		if errors.Is(err, store.ErrNotFound) {
			if _, hv, herr := in.st.Get(ctx, store.HeaderKey(id, in.meas.PCR0)); herr == nil {
				return &vault.Replace{Header: hv}, true, nil // a header without state: a broken enrollment
			}
			return nil, true, nil
		}
		if err != nil {
			return nil, false, err
		}
		hblob, hv, err := in.st.Get(ctx, store.HeaderKey(id, in.meas.PCR0))
		if err != nil {
			return nil, false, nil // sealed to another release: cannot tell, refuse
		}
		s := in.sealerFor(ownKey, in.meas.PCR0)
		defer s.Destroy()
		h, err := vault.PeekHeader(ctx, s, hblob, id, in.meas.PCR0)
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
	idx, _, err := in.st.Get(ctx, store.UserKey(userHash(q.UserGUID)))
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

func (in *Instance) indexUser(ctx context.Context, guid, vaultID string) {
	k := store.UserKey(userHash(guid))
	if _, err := in.st.Put(ctx, k, []byte(vaultID), ""); errors.Is(err, store.ErrConflict) {
		if _, v, err := in.st.Get(ctx, k); err == nil {
			_, _ = in.st.Put(ctx, k, []byte(vaultID), v)
		}
	}
}

// --- unlock (§11.4, §11.10.4) ---

func (in *Instance) unlock(ctx context.Context, q *QueueMessage, inner *envelope.Inner, _ *etk) []byte {
	now := in.now()
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
		PIN: r.PIN, Token: r.Token, Manifest: r.Manifest.Manifest, ToPCR0: toPCR0})
	if err != nil {
		return opaque()
	}
	// One manager per vault (D4): a vault this instance runs is locked
	// (flushed) before it is opened again.
	in.lockVault(ctx, q.VaultID)

	pol := in.cfg.DeviceAttest
	list := in.statusList()
	var man *manifest.Manifest
	var preCounter, unlockCounter uint32
	sealer := in.sealerFor("", in.meas.PCR0)
	p := vault.AltUnlockParams{
		Options: in.vaultOptions(sealer), VaultID: q.VaultID, UserGUID: q.UserGUID, DeviceIK: r.DeviceIK, PIN: r.PIN,
		MinStateSeq: r.MinStateSeq, MinHeaderSeq: r.MinHeaderSeq, DeviceToken: r.Token,
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
		m, own, err := in.verifyManifest(r.Manifest, seen)
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
		if !ok || !in.inNamespace(e.SealKey) {
			return nil, vault.ErrSealKeyNamespace
		}
		return in.checkKey(ctx, man, e)
	}
	p.SealerFor = func(ctx context.Context, t vault.ReleaseEntry) (vault.Sealer, *vault.SealKeyRecord, error) {
		e, ok := man.ByPCR0(t.PCR0)
		if !ok || !in.inNamespace(e.SealKey) {
			return nil, nil, vault.ErrSealKeyNamespace
		}
		rec, err := in.checkKey(ctx, man, e)
		if err != nil {
			return nil, nil, vault.ErrSealKey
		}
		return in.sealerFor(e.SealKey, e.PCR0), rec, nil
	}
	if u := r.Update; u != nil {
		p.Update = &vault.UpdateRequest{To: u.To, ToRelease: u.ToRelease, VerifyApproval: func(k *vault.UnlockKey) (json.RawMessage, error) {
			var b devattest.Binding
			if man == nil || json.Unmarshal(k.Attestation, &b) != nil {
				return nil, vault.ErrDeviceAttestation
			}
			s, err := altchan.ApprovalSigningString(q.VaultID, q.RequestID, in.meas.PCR0, u.To, u.ToRelease, man.Serial)
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
		in.emit(ev)
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
		Release: in.meas.PCR0, ReleaseNumber: in.cfg.ReleaseNumber, ReleaseStatus: out.Release.Status, ManifestSerial: out.Serial}
	if u := out.Update; u != nil {
		res.Update = &altchan.UpdateResult{To: u.To, Result: u.Result, Code: u.Code}
	}
	if mgr != nil {
		in.startVault(q.VaultID, mgr)
	} else {
		sealer.Destroy()
	}
	env, err := altchan.SealResult(kem, altchan.TypeUnlockResult, q.RequestID, res.Marshal(), now)
	if err != nil {
		return opaque()
	}
	return env
}

// --- running vaults ---

func (in *Instance) startVault(id string, m *vault.Manager) {
	ctx, cancel := context.WithCancel(context.Background())
	r := &running{m: m, cancel: cancel, done: make(chan struct{})}
	in.vmu.Lock()
	in.vaults[id] = r
	in.vmu.Unlock()
	go func() {
		defer close(r.done)
		err := m.Run(ctx)
		if in.opt.Stopped != nil && ctx.Err() == nil {
			in.opt.Stopped(id, err)
		}
		if m.Locked() {
			// Locked from inside (owner request, split brain): the run loop
			// ends; drop the vault from this instance.
			in.vmu.Lock()
			if in.vaults[id] == r {
				delete(in.vaults, id)
			}
			in.vmu.Unlock()
		}
	}()
}

// Manager returns the running manager of a vault (tests, supervisors).
func (in *Instance) Manager(vaultID string) *vault.Manager {
	in.vmu.Lock()
	defer in.vmu.Unlock()
	if r := in.vaults[vaultID]; r != nil {
		return r.m
	}
	return nil
}

// lockVault locks a vault this instance runs (§12.3 owner request):
// finish the batch, flush, vault.locking, zeroize.
func (in *Instance) lockVault(ctx context.Context, id string) {
	in.vmu.Lock()
	r := in.vaults[id]
	delete(in.vaults, id)
	in.vmu.Unlock()
	if r == nil {
		return
	}
	r.cancel()
	<-r.done
	_ = r.m.Lock(ctx)
}

// deleteVault locks the vault and destroys its state and this release's
// header (§12.3). The §7.4 revocations on deletion need the unlocked vault
// and arrive with vault.delete (phase V4).
func (in *Instance) deleteVault(ctx context.Context, id string) {
	in.lockVault(ctx, id)
	for _, k := range []string{store.StateKey(id), store.HeaderKey(id, in.meas.PCR0)} {
		if _, v, err := in.st.Get(ctx, k); err == nil {
			_ = in.st.Delete(ctx, k, v)
		}
	}
	in.emit(vault.LifecycleEvent{Event: "deleted", VaultID: id, Release: in.meas.PCR0, VaultVersion: in.meas.PCR0, StateVersion: vault.StateVersion})
}

// Close locks every vault and destroys the ETKs.
func (in *Instance) Close(ctx context.Context) {
	in.vmu.Lock()
	ids := make([]string, 0, len(in.vaults))
	for id := range in.vaults {
		ids = append(ids, id)
	}
	in.vmu.Unlock()
	for _, id := range ids {
		in.lockVault(ctx, id)
	}
	in.mu.Lock()
	for _, e := range in.etks {
		e.destroy()
	}
	in.etks = nil
	in.mu.Unlock()
}
