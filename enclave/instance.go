package enclave

import (
	"context"
	"errors"
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
	// the sealed result (or random bytes of its size).
	Open(ctx context.Context, j *Job) ([]byte, error)
	// Lock locks a running vault (§12.3); it reports whether it ran.
	Lock(ctx context.Context, vaultID string) (bool, error)
	// LockReason is Lock with a reason in vault.locking (§11.11.1).
	LockReason(ctx context.Context, vaultID, reason string) (bool, error)
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
		_, _ = in.host.Lock(ctx, q.VaultID)
	case OpDelete:
		in.deleteVault(ctx, q.VaultID, q.UserGUID)
	case OpRecovery, OpRecoveryCancel:
		// No envelope: the job carries the browser key (not secret). A
		// recovery locks a running vault first, telling its devices why
		// (§11.11.1); the vault process then works on the sealed header.
		if q.Op == OpRecovery {
			_, _ = in.host.LockReason(ctx, q.VaultID, "recovery")
		}
		body := []byte(`{}`)
		if q.Op == OpRecovery {
			body = strictjson.NewBuilder().Base64("browser_key", q.BrowserKey).Bytes()
		}
		j := &Job{Op: q.Op, VaultID: q.VaultID, UserGUID: q.UserGUID, RequestID: q.RequestID,
			Inner: &envelope.Inner{Type: requestType[q.Op], ID: q.RequestID, TS: in.now(), Body: body}}
		res, err := in.host.Open(ctx, j)
		if q.Op == OpRecovery {
			if err != nil || len(res) != altchan.SealedCodeSize {
				res = opaque()
			}
			resp.Envelope = res
		}
	case OpEnroll, OpUnlock, OpRecoveryRegister:
		inner, padded, err := in.openRequest(q)
		if errors.Is(err, errETKUnknown) {
			resp.Status = StatusETKUnknown
			return resp
		}
		if err != nil {
			resp.Envelope = opaque()
			return resp
		}
		j := &Job{Op: q.Op, VaultID: q.VaultID, UserGUID: q.UserGUID, RequestID: q.RequestID, ETKKid: q.ETKKid, Inner: inner}
		res, err := in.host.Open(ctx, j)
		// The decrypted request (with the PIN) is wiped as soon as the
		// vault has it (§12.4).
		j.Wipe()
		suite.Wipe(padded)
		if err != nil || res == nil {
			res = opaque()
		}
		resp.Envelope = res
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
