package enclave

import (
	"context"
	"crypto/ed25519"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vault/store"
	"github.com/vettid/vettid-vault/vms/altchan"
	"github.com/vettid/vettid-vault/vms/devattest"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/manifest"
	"github.com/vettid/vettid-vault/vms/nitro"
	"github.com/vettid/vettid-vault/vms/pushwire"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Options configure an Instance.
type Options struct {
	Config Config
	NSM    NSM
	// Store is the vault object store (deletions, and the in-process host).
	Store store.Store
	// Host runs the vaults. Nil: an in-process LocalHost built from the
	// fields below (tests and development); the enclave's supervisor
	// passes a host that runs one process per vault (D4).
	Host Host

	// For the in-process host only:
	KMS KMS
	// StatusList returns the cached Google attestation status list
	// (§11.7); nil means none has been fetched.
	StatusList func() *devattest.StatusList
	// Vault is the template for every vault's options (relay transport,
	// collect mode, features); Store, Sealer, Release, DeviceAttest and
	// Lifecycle are set by the instance.
	Vault vault.Options
	// Features returns fresh feature handlers for one vault.
	Features func() []vault.Feature
	// Stopped, if set, is told when a vault's run loop ends and why (an
	// error is a sentinel without secrets).
	Stopped func(vaultID string, err error)

	// Lifecycle receives lifecycle events for the parent (§11.5).
	Lifecycle func(vault.LifecycleEvent)
	Now       func() time.Time
}

// Host runs vaults for an instance: in process (LocalHost) or one OS
// process per vault (the supervisor's host, VAULT-MESSAGING §12.4).
type Host interface {
	// Open runs a decrypted enroll or unlock job, locking a running
	// instance of the vault first (one manager per vault, D4), and returns
	// the sealed result (or random bytes of its size), and whether it is a
	// recovery_register's {"ok": true} (the clear marker, 0.10.6).
	Open(ctx context.Context, j *Job) ([]byte, Marker, error)
	// Lock locks a running vault (§12.3); it reports whether it ran.
	Lock(ctx context.Context, vaultID string) (bool, error)
	// LockReason is Lock with a reason in vault.locking (§11.11.1).
	LockReason(ctx context.Context, vaultID, reason string) (bool, error)
	// RecoveryRefusal asks a running vault whether it refuses a recovery
	// ("no_credential", "no_backup" or ""; 0.16.0, §11.11.1) without
	// locking it; ran reports whether it runs here.
	RecoveryRefusal(ctx context.Context, vaultID string) (ran bool, why string)
	// Account gives a running vault the member's account snapshot (the
	// queue op account, 0.15.0, §11.13); it reports whether the vault
	// runs here (otherwise the snapshot is dropped).
	Account(ctx context.Context, vaultID string, snapshot []byte) (bool, error)
	// Vaults returns the ids of the running vaults.
	Vaults() []string
	// Close locks every vault.
	Close(ctx context.Context)
}

// Instance is one enclave instance: its ETKs, the outer decryption and
// binding of alternate-channel requests, and the host its vaults run on.
// With a process host it holds no vault's secrets (§12.4).
type Instance struct {
	opt  Options
	cfg  Config
	nsm  NSM
	st   store.Store
	meas nitro.Measurements
	host Host
	now  func() time.Time

	mu    sync.Mutex // ETKs and replay sets
	reqMu sync.Mutex // serializes alternate-channel requests
	etks  []*etk
	// recoverySeen are the signed recovery requests seen (release R,
	// §11.14.8), by op and request_id.
	recoverySeen map[string]time.Time
}

// Errors.
var (
	ErrConfig = errors.New("enclave: invalid configuration")
	errDrop   = errors.New("enclave: request dropped")
)

// New starts an instance: it reads its measurements and creates its first
// ETK (and, without a Host, the in-process host).
func New(opt Options) (*Instance, error) {
	if opt.NSM == nil || opt.Store == nil || opt.Config.DeviceAttest == nil || !altchan.ValidInstanceID(opt.Config.InstanceID) {
		return nil, ErrConfig
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.Config.KDF == nil {
		opt.Config.KDF = vault.DefaultKDF
	}
	in := &Instance{opt: opt, cfg: opt.Config, nsm: opt.NSM, st: opt.Store, now: opt.Now, host: opt.Host}
	m, err := opt.NSM.Measurements()
	if err != nil || !manifest.ValidPCR(m.PCR0) || m.IsDebug() {
		return nil, ErrConfig // a debug-mode enclave has no release to run as
	}
	in.meas = m
	if in.host == nil {
		if opt.KMS == nil {
			return nil, ErrConfig
		}
		nsm := opt.NSM
		if opt.Vault.Push == nil && opt.Config.PushURL != "" {
			// In process (tests, development): the client attests itself.
			opt.Vault.Push = &pushwire.Client{BaseURL: opt.Config.PushURL, HTTP: opt.Vault.HTTP,
				Attest: func(pub ed25519.PublicKey, d [32]byte) ([]byte, error) { return nsm.Attest(d[:], nil, pub) }}
		}
		core, err := NewCore(CoreDeps{Config: opt.Config, Meas: m, Store: opt.Store, KMS: opt.KMS,
			AttestRecipient: func(pub []byte) ([]byte, error) { return nsm.Attest(nil, nil, pub) },
			AttestVault: func(bundle, nonce []byte) ([]byte, error) {
				ud := altchan.VaultUserData(bundle)
				return nsm.Attest(ud[:], nonce, nil)
			},
			StatusList: opt.StatusList, Vault: opt.Vault, Features: opt.Features, Lifecycle: in.emit, Now: opt.Now})
		if err != nil {
			return nil, err
		}
		in.host = NewLocalHost(core, opt.Stopped)
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

// Measurements returns the enclave's PCR0-2.
func (in *Instance) Measurements() nitro.Measurements { return in.meas }

func (in *Instance) emit(ev vault.LifecycleEvent) {
	if in.opt.Lifecycle != nil {
		in.opt.Lifecycle(ev)
	}
}

// ProcessRaw handles one raw queue message, with the manifest document
// the parent supplied for it (enroll and unlock, 0.10.0; may be empty),
// and returns the raw response. A message that does not parse gets no
// response (nil).
func (in *Instance) ProcessRaw(ctx context.Context, b, manifestDoc []byte) []byte {
	q, err := ParseQueueMessage(b)
	if err != nil {
		return nil
	}
	return in.Process(ctx, q, manifestDoc).Marshal()
}

// Process handles one queue message (§11.5). manifestDoc is the served
// manifest the parent supplied for an enroll or unlock (host input,
// verified in the vault against the sealed request's hash); a document
// over the size limit is dropped.
func (in *Instance) Process(ctx context.Context, q *QueueMessage, manifestDoc []byte) *Response {
	in.reqMu.Lock()
	defer in.reqMu.Unlock()
	resp := &Response{RequestID: q.RequestID, Status: StatusDone}
	switch q.Op {
	case OpLock:
		_, _ = in.host.Lock(ctx, q.VaultID)
	case OpDelete:
		in.deleteVault(ctx, q.VaultID, q.UserGUID)
	case OpDeleteResume:
		in.resumeDelete(ctx, q)
	case OpAccount:
		_, _ = in.host.Account(ctx, q.VaultID, q.Account) // no running vault: dropped (§11.5)
	case OpRecovery, OpRecoveryCancel:
		// Release R (§11.14.8): the member API's signature first; a
		// recovery that fails is answered with random bytes of the sealed
		// code's size, a cancel is ignored; nothing is locked or recorded.
		if !in.verifyRecoverySig(q) {
			if q.Op == OpRecovery {
				resp.Envelope = opaque()
			}
			return resp
		}
		if q.Op == OpRecovery && !in.cfg.Recovery.Offered {
			// §11.14.13: a release that refuses every recovery, without
			// locking the vault.
			res, _ := RefuseRecovery(q.BrowserKey, q.VaultID, q.RequestID, "not_offered")
			resp.Envelope, resp.Code, resp.Clear.Reason = res, CodeRecoveryUnavailable, "not_offered"
			return resp
		}
		// A recovery locks a running vault first, telling its devices why
		// (§11.11.1); the vault process then works on the sealed header.
		// 0.16.0: a running vault that cannot be recovered (no credential,
		// no backup copy) refuses from its own state before anything is
		// locked or recorded.
		if q.Op == OpRecovery {
			if ran, why := in.host.RecoveryRefusal(ctx, q.VaultID); ran && why != "" {
				res, _ := RefuseRecovery(q.BrowserKey, q.VaultID, q.RequestID, why)
				resp.Envelope, resp.Code, resp.Clear.Reason = res, CodeRecoveryUnavailable, why
				return resp
			}
			_, _ = in.host.LockReason(ctx, q.VaultID, "recovery")
		}
		body := []byte(`{}`)
		if q.Op == OpRecovery {
			body = strictjson.NewBuilder().Base64("browser_key", q.BrowserKey).Bytes()
		}
		if q.Op == OpRecoveryCancel && q.RecoveryID != "" {
			// 0.49.0 (§11.14.8): the signed recovery_id, to the vault
			// process's vault.RecoveryCancel.
			body = strictjson.NewBuilder().String("recovery_id", q.RecoveryID).Bytes()
		}
		j := &Job{Op: q.Op, VaultID: q.VaultID, UserGUID: q.UserGUID, RequestID: q.RequestID,
			Inner: &envelope.Inner{Type: requestType[q.Op], ID: q.RequestID, TS: in.now(), Body: body}}
		res, mk, err := in.host.Open(ctx, j)
		if q.Op == OpRecovery {
			if err != nil || len(res) != altchan.SealedCodeSize {
				res, mk = opaque(), Marker{}
			}
			resp.Envelope = res
			if mk.Code == CodeRecoveryUnavailable {
				resp.Code, resp.Clear.Reason = CodeRecoveryUnavailable, mk.Reason // §11.11.2 (0.16.0)
			} else {
				resp.Clear = Marker{NotBefore: mk.NotBefore, Expires: mk.Expires, Earliest: mk.Earliest} // §11.14.5
			}
		}
		if q.Op == OpRecoveryCancel && err == nil && mk.Code == CodeRecoveryNotCurrent && q.RecoveryID != "" {
			// 0.49.0 (§11.14.8): a named cancel that cancelled nothing;
			// the answer has no envelope, as for every cancel.
			resp.Code, resp.Clear.Code = CodeRecoveryNotCurrent, CodeRecoveryNotCurrent
		}
	case OpEnroll, OpUnlock, OpRecoveryRegister, OpRecoveryOpen:
		inner, padded, err := in.openRequest(q)
		if errors.Is(err, errETKUnknown) {
			resp.Status = StatusETKUnknown
			return resp
		}
		if err != nil {
			resp.Envelope = opaque()
			return resp
		}
		j := &Job{Op: q.Op, VaultID: q.VaultID, UserGUID: q.UserGUID, RequestID: q.RequestID, ETKKid: q.ETKKid, Inner: inner,
			AppKey: q.AppKey}
		if q.Op == OpUnlock || q.Op == OpEnroll {
			j.Account = q.Account // enroll: REQUIRED, checked by the job (0.18.0)
		}
		if (q.Op == OpEnroll || q.Op == OpUnlock || q.Op == OpRecoveryOpen) && len(manifestDoc) <= manifest.MaxServed {
			j.Manifest = manifestDoc
		}
		res, mk, err := in.host.Open(ctx, j)
		// The decrypted request (with the PIN) is wiped as soon as the
		// vault has it (§12.4).
		j.Wipe()
		suite.Wipe(padded)
		if err != nil || res == nil {
			res, mk = opaque(), Marker{}
		}
		resp.Envelope = res
		switch {
		case mk.Code == CodeRecoveryRegistered && q.Op == OpRecoveryRegister:
			// §11.5, §11.11.3 (0.10.6): a successful register says so in
			// the clear, so that the member API retires the spent code.
			resp.Code = CodeRecoveryRegistered
		case mk.Code == CodeRecoveryAttempt && q.Op == OpRecoveryOpen:
			// Release R (§11.14.11): a counted attempt, with retry_at and
			// expires when a wait began; never whether it was right.
			resp.Code = CodeRecoveryAttempt
			resp.Clear = Marker{RetryAt: mk.RetryAt, Expires: mk.Expires}
		case mk.Code == CodeRecoveryCancelled && q.Op == OpUnlock && envelope.ValidULID(mk.CancelledRecoveryID):
			// 0.49.0 (§11.5): the unlock's stored cancel, with the id of
			// the recovery it ended.
			resp.Code = CodeRecoveryCancelled
			resp.Clear = Marker{Code: CodeRecoveryCancelled, CancelledRecoveryID: mk.CancelledRecoveryID}
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
func (in *Instance) openRequest(q *QueueMessage) (*envelope.Inner, []byte, error) {
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
		suite.Wipe(padded)
		return nil, nil, errDrop
	}
	js, err := envelope.UnpadFixed(padded, altchan.RequestPaddedSize)
	if err != nil {
		suite.Wipe(padded)
		return nil, nil, errDrop
	}
	inner, err := envelope.ParseInner(js, envelope.ModeSealed)
	if err != nil {
		suite.Wipe(padded)
		return nil, nil, errDrop
	}
	want := requestType[q.Op]
	if inner.Type != want || inner.ID != q.RequestID || inner.Re != "" {
		suite.Wipe(padded)
		return nil, nil, errDrop
	}
	if d := now.Sub(inner.TS); d > MaxSkew || d < -MaxSkew {
		suite.Wipe(padded)
		return nil, nil, errDrop
	}
	in.mu.Lock()
	defer in.mu.Unlock()
	if e.seen == nil || len(e.seen) >= maxSeen {
		suite.Wipe(padded)
		return nil, nil, errDrop
	}
	if _, dup := e.seen[q.RequestID]; dup {
		suite.Wipe(padded)
		return nil, nil, errDrop // replay (§11.6)
	}
	e.seen[q.RequestID] = struct{}{}
	return inner, padded, nil
}

// Manager returns the running manager of a vault with the in-process
// host (tests, development); nil otherwise.
func (in *Instance) Manager(vaultID string) *vault.Manager {
	if lh, ok := in.host.(*LocalHost); ok {
		return lh.Manager(vaultID)
	}
	return nil
}

// Lock locks a running vault outside the alternate channel: memory
// pressure, a lost lease, or a supervisor shutdown (§12.3). It is
// serialized with alternate-channel requests.
func (in *Instance) Lock(ctx context.Context, vaultID string) (bool, error) {
	in.reqMu.Lock()
	defer in.reqMu.Unlock()
	return in.host.Lock(ctx, vaultID)
}

// LockAll locks every running vault (§12.3 "Enclave release or restart",
// when signalled). The ETKs stay.
func (in *Instance) LockAll(ctx context.Context) {
	in.reqMu.Lock()
	defer in.reqMu.Unlock()
	for _, id := range in.host.Vaults() {
		_, _ = in.host.Lock(ctx, id)
	}
}

// Vaults returns the ids of the vaults this instance runs.
func (in *Instance) Vaults() []string { return in.host.Vaults() }

// deleteVault is the host's deletion (account cancellation, §12.5): a
// running vault deletes itself with the full semantics (notices,
// revocations, keys destroyed, storage erased, `deleted` reported);
// otherwise the stored objects are erased here. Either way the result is
// idempotent: a missing object is already deleted.
func (in *Instance) deleteVault(ctx context.Context, id, userGUID string) {
	ran, err := in.host.LockReason(ctx, id, vault.LockDelete)
	if ran && err == nil {
		return
	}
	if err := vault.EraseStored(ctx, in.st, id, userGUID, nil, in.meas.PCR0, "", ""); err != nil {
		return // retried by the next delete request
	}
	in.emit(vault.LifecycleEvent{Event: "deleted", VaultID: id, Release: in.meas.PCR0, VaultVersion: in.meas.PCR0, StateVersion: vault.StateVersion})
}

// resumeDelete is the queue op delete_resume (0.51.0, §12.5 "Without the
// app: the resume"; VAULT-HOST-PROTOCOL §6.1, P20). A vault that runs here
// is not touched: one being deleted finishes its own deletion, and one
// that is not must not be. The host checks again, with the opens under
// way, in the same step as it starts the resume's process (procHost
// reserve), and locks nothing for it. A vault process reads the vault's
// header sealed to this release and decides alone (vault.ResumeDelete);
// the message is never an authority to delete. The answer is done, with
// no envelope and no code, whatever happened.
func (in *Instance) resumeDelete(ctx context.Context, q *QueueMessage) {
	if slices.Contains(in.host.Vaults(), q.VaultID) {
		return
	}
	j := &Job{Op: OpDeleteResume, VaultID: q.VaultID, UserGUID: q.UserGUID, RequestID: q.RequestID,
		Inner: &envelope.Inner{Type: typeDeleteResume, ID: q.RequestID, TS: in.now(), Body: []byte(`{}`)}}
	_, _, _ = in.host.Open(ctx, j)
}

// Close locks every vault and destroys the ETKs.
func (in *Instance) Close(ctx context.Context) {
	in.host.Close(ctx)
	in.mu.Lock()
	for _, e := range in.etks {
		e.destroy()
	}
	in.etks = nil
	in.mu.Unlock()
}
