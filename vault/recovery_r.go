package vault

import (
	"context"
	"strconv"
	"sync"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault/counter"
	"github.com/vettid/vettid-vault/vms/recovery"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Release R's recovery in a running vault (VAULT-MESSAGING 0.33.0
// §11.14.3, §11.14.5, §11.14.9, §11.14.11): arming, new generations at
// changes of secret, presence, the counter's record in the audit log.

// recoveryRuntime is a running vault's recovery state in memory.
type recoveryRuntime struct {
	ctr *counter.Counter
	// last is the last Status of the current generation; lastErr whether
	// the last read failed; unavailableSince when reads began failing.
	last             *counter.View
	lastErr          bool
	unavailableSince time.Time
	// presentAt is the counter's time of the last presence recorded;
	// while presentRetryUntil is set, a presence that could not be
	// recorded is tried again every minute until then.
	presentAt         time.Time
	presentRetryUntil time.Time
	presentNextTry    time.Time
}

// Recovery states (vault.status, §11.14.11).
const (
	RecoveryArmed          = "armed"
	RecoveryOff            = "off"
	RecoveryNeedsCheck     = "needs_check"
	RecoveryChangeRequired = "change_required"
	RecoveryUnknown        = "unknown"
)

// Errors of release R (§10.1).
var (
	errBusy               = &HandlerError{Code: "busy"}
	errCounterUnavailable = &HandlerError{Code: "counter_unavailable"}
)

// WeakPasswordError is weak_password{reason} (§11.14.7).
func WeakPasswordError(reason string) error {
	return &HandlerError{Code: "weak_password", Body: strictjson.NewBuilder().String("reason", reason).Bytes()}
}

const (
	defaultWaitUnit = 24 * time.Hour
	defaultQuiet    = 72 * time.Hour
	presentRetry    = time.Hour
	presentEvery    = time.Minute
)

// CounterUnavailableNotice is how long the counter may be unreadable
// before the vault raises the urgent recovery.counter_unavailable
// (§11.14.5, §11.14.11), in real time (divided by the time scale).
const CounterUnavailableNotice = 24 * time.Hour

func (m *Manager) waitUnit() time.Duration {
	if m.opt.RecoveryWaitUnit > 0 {
		return m.opt.RecoveryWaitUnit
	}
	return defaultWaitUnit
}

// counter returns the vault's counter, or nil when it has none.
func (m *Manager) counter() *counter.Counter {
	if m.rec.ctr != nil {
		return m.rec.ctr
	}
	if m.opt.Counter == nil || len(m.hdr.Rec.CounterKey) != recovery.SecretSize {
		return nil
	}
	n, err := recovery.NewNames(m.hdr.Rec.CounterKey, m.hdr.VaultID)
	if err != nil {
		return nil
	}
	m.rec.ctr = counter.New(m.opt.Counter, n, m.waitUnit()).WithQuiet(m.opt.RecoveryQuiet).WithRecordLock(m.opt.RecoveryCounterLock)
	return m.rec.ctr
}

// status reads the current generation and remembers the result.
func (m *Manager) status(ctx context.Context, g uint64) (*counter.View, error) {
	c := m.counter()
	if c == nil {
		m.noteCounter(false)
		return nil, counter.ErrUnavailable
	}
	v, err := c.Status(ctx, g)
	m.noteCounter(err == nil)
	if err == nil && g == m.hdr.Rec.Generation {
		m.rec.last = v
	}
	return v, err
}

func (m *Manager) noteCounter(ok bool) {
	m.rec.lastErr = !ok
	if ok {
		m.rec.unavailableSince = time.Time{}
	} else if m.rec.unavailableSince.IsZero() {
		m.rec.unavailableSince = m.now()
	}
}

// permit takes the heavy-derivation permit, waiting up to wait for it.
func (m *Manager) permit(ctx context.Context, wait time.Duration) (func(), bool) {
	if m.opt.HeavyPermit == nil {
		return func() {}, true
	}
	end := time.Now().Add(wait)
	for {
		if rel, ok := m.opt.HeavyPermit(ctx); ok {
			return rel, true
		}
		if wait <= 0 || time.Now().After(end) {
			return nil, false
		}
		select {
		case <-ctx.Done():
			return nil, false
		case <-time.After(time.Second):
		}
	}
}

// armed reports whether the header holds a wrap for the current generation.
func (m *Manager) armed() bool {
	w := m.hdr.Rec.Wrap
	return w != nil && w.Generation == m.hdr.Rec.Generation && m.hdr.Rec.Generation > 0
}

// RecoveryState is vault.status's recovery.state.
func (m *Manager) recoveryState() string { return m.recoveryStateWith(m.backupCopy()) }

// recoveryStateWith is the state given whether the vault keeps a backup
// copy of the credential (the credential feature says so from inside its
// own handler, where asking it would deadlock).
func (m *Manager) recoveryStateWith(backup bool) string {
	switch {
	case !backup:
		return RecoveryOff
	case m.hdr.Rec.ChangeRequired:
		return RecoveryChangeRequired
	case m.rec.lastErr:
		return RecoveryUnknown
	case m.armed():
		return RecoveryArmed
	}
	return RecoveryNeedsCheck
}

// heavyX is the recovery wrap's derivation on the pair.
func heavyX(pin string, pw []byte, k KDFParams) ([]byte, error) {
	secrets, err := recovery.Secrets(pin, pw)
	if err != nil {
		return nil, err
	}
	defer suite.Wipe(secrets)
	return recovery.HeavyX(secrets, toParams(k))
}

// makeWrap computes a new wrap for generation g on the pair, with a fresh
// recovery key and the opener for dek at dekVersion. The caller holds the
// permit.
func (m *Manager) makeWrap(pin string, pw []byte, g uint64, dek []byte, dekVersion uint64) (*RecoveryWrap, error) {
	p, err := recovery.NewHeavyParams()
	if err != nil {
		return nil, err
	}
	k := fromParams(p)
	x, err := heavyX(pin, pw, k)
	if err != nil {
		return nil, err
	}
	defer suite.Wipe(x)
	key, err := recovery.WrapKey(x, m.hdr.Pepper, m.hdr.VaultID, g)
	if err != nil {
		return nil, err
	}
	defer suite.Wipe(key)
	rk, err := suite.RandomBytes(recovery.SecretSize)
	if err != nil {
		return nil, err
	}
	defer suite.Wipe(rk)
	w, err := recovery.WrapRecoveryKey(key, rk, m.hdr.VaultID, g)
	if err != nil {
		return nil, err
	}
	op, err := recovery.MakeOpener(rk, dek, m.hdr.VaultID, g, dekVersion)
	if err != nil {
		return nil, err
	}
	return &RecoveryWrap{V: 1, Generation: g, KDF: k, Wrap: w, Opener: op, OpenerDEKVersion: dekVersion}, nil
}

// openWrap opens the current wrap with the pair and returns the recovery
// key (the caller holds the permit).
func (m *Manager) openWrap(w *RecoveryWrap, pin string, pw []byte) ([]byte, error) {
	x, err := heavyX(pin, pw, w.KDF)
	if err != nil {
		return nil, err
	}
	defer suite.Wipe(x)
	key, err := recovery.WrapKey(x, m.hdr.Pepper, m.hdr.VaultID, w.Generation)
	if err != nil {
		return nil, err
	}
	defer suite.Wipe(key)
	return recovery.OpenRecoveryKey(key, w.Wrap, m.hdr.VaultID, w.Generation)
}

// reopen makes a wrap's opener for another DEK with the recovery key.
func reopen(w *RecoveryWrap, rk []byte, vaultID string, dek []byte, dekVersion uint64) (*RecoveryWrap, error) {
	op, err := recovery.MakeOpener(rk, dek, vaultID, w.Generation, dekVersion)
	if err != nil {
		return nil, err
	}
	nw := *w
	nw.Opener, nw.OpenerDEKVersion = op, dekVersion
	return &nw, nil
}

// arm makes the wrap when the vault has just verified the PIN and the
// password in one request (§11.14.3): with a backup copy of the
// credential, a password that meets rules 1, 2 and 5, no wrap for the
// current generation, and the counter showing the generation open and not
// used up. It waits up to wait for the permit. It reports the state.
func (m *Manager) arm(ctx context.Context, pin string, pw []byte, wait time.Duration, backup bool, now time.Time) string {
	if !backup || m.repl != nil || m.hdr.Next != nil || m.armed() || m.hdr.Rec.ChangeRequired {
		return m.recoveryStateWith(backup)
	}
	if !recovery.ArmingAllowed(pw) {
		m.hdr.Rec.ChangeRequired = true
		m.dirty = true
		m.record(Activity{Kind: "recovery.change_required", Ref: "password", Feed: true, Priority: "high"}, now)
		return RecoveryChangeRequired
	}
	g := m.hdr.Rec.Generation
	if g == 0 {
		g = 1
	}
	v, err := m.status(ctx, g)
	if err != nil {
		return RecoveryNeedsCheck
	}
	for i := 0; v.Closed && i < 4; i++ {
		// A generation is never armed again once closed: move to the next,
		// under the rule for one closed with the secrets unchanged.
		g++
		m.hdr.Rec.Generation, m.hdr.Rec.ClosedUnchanged, m.hdr.Rec.Wrap = g, true, nil
		m.dirty = true
		if v, err = m.status(ctx, g); err != nil {
			return RecoveryNeedsCheck
		}
	}
	if v.Closed {
		return RecoveryNeedsCheck
	}
	if v.Exhausted() {
		m.hdr.Rec.ChangeRequired = true
		m.dirty = true
		return RecoveryChangeRequired
	}
	if m.hdr.Rec.ClosedUnchanged && g > 1 {
		pv, err := m.status(ctx, g-1)
		if err != nil {
			return RecoveryNeedsCheck
		}
		if pv.Used > 0 {
			m.hdr.Rec.ChangeRequired = true
			m.dirty = true
			m.record(Activity{Kind: "recovery.change_required", Ref: strconv.FormatUint(g-1, 10), Feed: true, Priority: "high"}, now)
			return RecoveryChangeRequired
		}
	}
	rel, ok := m.permit(ctx, wait)
	if !ok {
		return RecoveryNeedsCheck // busy: the next check arms
	}
	defer rel()
	w, err := m.makeWrap(pin, pw, g, m.dek, m.hdr.DEKVersion)
	if err != nil {
		return RecoveryNeedsCheck
	}
	m.hdr.Rec.Wrap, m.hdr.Rec.Generation, m.hdr.Rec.ClosedUnchanged = w, g, false
	m.dirty = true
	m.record(Activity{Kind: "recovery.armed", Ref: strconv.FormatUint(g, 10), Audit: true}, now)
	return RecoveryArmed
}

// SecretChange is a change of PIN, password or phone secret
// (§11.14.9), with the request's secrets (the passwords NFC-normalized).
type SecretChange struct {
	Reason string // ReplacePIN, ReplacePassword, ReplaceReset, ReplaceRenew
	// BackupCopy: the vault keeps a backup copy of the credential, so the
	// new generation is armed.
	BackupCopy      bool
	PIN, NewPIN     string
	Password        []byte
	NewPassword     []byte
	NewUnlockSecret []byte
}

// changeSecrets runs a change's part before its state write: the permit,
// the new generation's wrap computed before the old one is closed, the
// close at the counter, and step 1 of the DEK replacement. On error
// nothing has changed (busy, counter_unavailable, retry), except that a
// generation closed by a change whose step 1 then failed stays closed.
func (m *Manager) changeSecrets(ctx context.Context, c SecretChange, now time.Time) error {
	if m.repl != nil {
		return errRetry
	}
	// The heavy-derivation permit is taken first (busy changes nothing)
	// and returned after the derivations, before any counter call.
	rel0, ok := m.permit(ctx, 0)
	if !ok {
		return errBusy
	}
	rel := sync.OnceFunc(rel0)
	defer rel()
	pin, pw, secret, kdf := c.PIN, c.Password, m.unlockSecret, m.hdr.KDF
	switch c.Reason {
	case ReplacePIN:
		pin, secret = c.NewPIN, c.NewUnlockSecret
		salt, err := suite.RandomBytes(16)
		if err != nil {
			return errUnavailable
		}
		kdf.Salt = salt // a fresh salt when the PIN changes (§11.14.2)
	case ReplacePassword, ReplaceReset:
		pw = c.NewPassword
	case ReplaceRenew:
		secret = c.NewUnlockSecret
	default:
		return errUnavailable
	}
	if len(secret) != recovery.SecretSize {
		return errBadRequest
	}
	r, err := m.nextFor(c.Reason, pin, secret, kdf, nil, now)
	if err != nil {
		return errUnavailable
	}
	g := m.hdr.Rec.Generation
	if c.Reason == ReplaceRenew {
		// Same generation: the pair opens the current wrap; a new opener.
		if m.armed() {
			rk, err := m.openWrap(m.hdr.Rec.Wrap, c.PIN, c.Password)
			if err != nil {
				r.wipe()
				return errRetry
			}
			w, err := reopen(m.hdr.Rec.Wrap, rk, m.hdr.VaultID, r.dek1, r.next.DEKVersion)
			suite.Wipe(rk)
			if err != nil {
				r.wipe()
				return errUnavailable
			}
			r.next.Wrap = w
		}
		rel()
		return m.beginReplace(ctx, r)
	}
	// A new generation for the new pair, computed before the old closes.
	// The current generation (at least 1) is always closed, whatever the
	// header says about a wrap: a header served from before an arming must
	// not leave an armed generation open against the old pair; and a
	// generation number is never used for a second pair.
	cg := max(g, 1)
	ng := cg + 1
	ctr := m.counter()
	if ctr == nil {
		r.wipe()
		return errCounterUnavailable
	}
	if c.BackupCopy && recovery.ArmingAllowed(pw) {
		w, err := m.makeWrap(pin, pw, ng, r.dek1, r.next.DEKVersion)
		if err != nil {
			r.wipe()
			return errUnavailable
		}
		r.next.Wrap = w
	}
	rel() // the permit covers the derivations only
	// A next generation the counter already knows (closed, or with an
	// attempt: an older timeline a host served) is never used again: the
	// change is refused with retry and the next one moves past it.
	if v, err := ctr.Status(ctx, ng); err != nil {
		r.wipe()
		m.noteCounter(false)
		return errCounterUnavailable
	} else if v.Closed || v.Used > 0 {
		// Both are closed (idempotent) and the vault moves past them; the
		// member sends the change again.
		r.wipe()
		for _, cl := range []uint64{cg, ng} {
			if ctr.Close(ctx, cl) != nil {
				m.noteCounter(false)
				return errCounterUnavailable
			}
			m.record(Activity{Kind: "recovery.generation_closed", Ref: strconv.FormatUint(cl, 10) + "/stale", Audit: true}, now)
		}
		m.hdr.Rec.Generation, m.hdr.Rec.Wrap, m.hdr.Rec.ClosedUnchanged = ng+1, nil, true
		m.dirty = true
		return errRetry
	}
	if ctr.Close(ctx, cg) != nil {
		r.wipe()
		m.noteCounter(false)
		return errCounterUnavailable
	}
	m.noteCounter(true)
	m.record(Activity{Kind: "recovery.generation_closed", Ref: strconv.FormatUint(cg, 10) + "/" + c.Reason, Audit: true}, now)
	m.hdr.Rec.Generation = ng
	m.hdr.Rec.Wrap = nil
	m.hdr.Rec.ClosedUnchanged = true // until the change completes
	m.hdr.Rec.ChangeRequired = false
	m.rec.last = nil
	m.dirty = true
	armedNew := r.next.Wrap != nil
	r.promoteFn = func() {
		m.hdr.Rec.ClosedUnchanged = false
		if armedNew {
			m.record(Activity{Kind: "recovery.armed", Ref: strconv.FormatUint(ng, 10), Audit: true}, m.now())
		}
	}
	if err := m.beginReplace(ctx, r); err != nil {
		return err
	}
	return nil
}

// closeForBackupOff closes the generation when the backup is turned off
// (§11.14.3): counter_unavailable when the counter does not confirm.
func (m *Manager) closeForBackupOff(ctx context.Context, now time.Time) error {
	// Always the current generation (at least 1), whatever the header
	// says about a wrap (a header from before an arming), and never reused.
	g := max(m.hdr.Rec.Generation, 1)
	ctr := m.counter()
	if ctr == nil || ctr.Close(ctx, g) != nil {
		m.noteCounter(false)
		return errCounterUnavailable
	}
	m.noteCounter(true)
	m.hdr.Rec.Wrap = nil
	m.hdr.Rec.Generation = g + 1
	m.hdr.Rec.ClosedUnchanged = true
	m.dirty = true
	m.record(Activity{Kind: "recovery.generation_closed", Ref: strconv.FormatUint(g, 10) + "/backup_off", Audit: true}, now)
	return nil
}

// markPresent records the member present at the counter (§11.14.5). If
// the counter cannot record it, it is tried again every minute for an
// hour while the vault stays unlocked.
func (m *Manager) markPresent(ctx context.Context, now time.Time) bool {
	c := m.counter()
	if c == nil {
		m.presentFailed(now)
		return false
	}
	at, err := c.MarkPresent(ctx)
	if err != nil {
		m.noteCounter(false)
		m.presentFailed(now)
		return false
	}
	m.noteCounter(true)
	m.rec.presentAt, m.rec.presentRetryUntil = at, time.Time{}
	return true
}

func (m *Manager) presentFailed(now time.Time) {
	if m.rec.presentRetryUntil.IsZero() {
		m.rec.presentRetryUntil = now.Add(presentRetry)
		m.record(Activity{Kind: "recovery.presence_unrecorded", Audit: true}, now)
	}
	m.rec.presentNextTry = now.Add(presentEvery)
}

// recoveryHousekeeping retries a presence that could not be recorded and
// raises the 24-hour counter notice (§11.14.5, §11.14.11).
func (m *Manager) recoveryHousekeeping(ctx context.Context, now time.Time) {
	if u := m.rec.presentRetryUntil; !u.IsZero() {
		if now.After(u) {
			m.rec.presentRetryUntil = time.Time{}
		} else if !now.Before(m.rec.presentNextTry) {
			m.markPresent(ctx, now)
		}
	}
	// The 24 h are divided by the time scale (0.43.0, S8); the start is
	// in memory only, so it always began under the running release.
	if s := m.rec.unavailableSince; !s.IsZero() && now.Sub(s) >= m.opt.scale(CounterUnavailableNotice) && m.st.RecoveryCounterNotice.IsZero() {
		m.st.RecoveryCounterNotice = now
		m.record(Activity{Kind: "recovery.counter_unavailable", Feed: true, Priority: "urgent"}, now)
		m.dirty = true
	}
}

// recordAttempts writes one audit entry for each attempt of the current
// generation the vault has not recorded (§11.14.11), from a status read
// while unlocked; when attempts.used rises it also audits
// recovery.attempts_used. The tenth used disarms (change_required).
func (m *Manager) recordAttempts(v *counter.View, now time.Time) {
	if v == nil {
		return
	}
	g := strconv.FormatUint(v.Generation, 10)
	if m.st.RecoveryAttempts == nil {
		m.st.RecoveryAttempts = map[string]string{}
	}
	for _, a := range v.Attempts {
		ref := g + "/" + strconv.Itoa(a.N)
		outcome := "not_success"
		if a.Success {
			outcome = "success"
		}
		if m.st.RecoveryAttempts[ref] == outcome {
			continue
		}
		first := m.st.RecoveryAttempts[ref] == ""
		m.st.RecoveryAttempts[ref] = outcome
		pri := "urgent"
		if m.st.RecoveredGeneration == v.Generation {
			pri = ""
		}
		if first || outcome == "success" {
			m.record(Activity{Kind: "recovery.attempt", Ref: ref + "/" + outcome + "/counter", Audit: true, Feed: true, Priority: pri}, a.At)
		}
	}
	if v.Used > m.st.RecoveryUsed[g] {
		if m.st.RecoveryUsed == nil {
			m.st.RecoveryUsed = map[string]int{}
		}
		m.st.RecoveryUsed[g] = v.Used
		m.record(Activity{Kind: "recovery.attempts_used", Ref: g + "/" + strconv.Itoa(v.Used), Audit: true}, now)
	}
	if v.Exhausted() && m.hdr.Rec.Wrap != nil && m.hdr.Rec.Wrap.Generation == v.Generation {
		m.hdr.Rec.Wrap = nil
		m.hdr.Rec.ChangeRequired = true
		m.record(Activity{Kind: "recovery.generation_closed", Ref: g + "/exhausted", Audit: true}, now)
		m.record(Activity{Kind: "recovery.change_required", Ref: g, Feed: true, Priority: "high"}, now)
	}
	m.dirty = true
}

// ownerCheckRecovery is what a passed owner check does for recovery
// (§3.6.1 step 8, §11.14.5): presence, the counter's record, arming.
func (m *Manager) ownerCheckRecovery(ctx context.Context, pin string, pw []byte, wait time.Duration, backup bool, now time.Time) (state string, present bool) {
	present = m.markPresent(ctx, now)
	if present {
		m.st.PresentPending = false
	}
	m.retryPendingSucceed(ctx)
	if g := m.hdr.Rec.Generation; g > 0 {
		if v, err := m.status(ctx, g); err == nil {
			m.recordAttempts(v, now)
		}
	}
	state = m.arm(ctx, pin, pw, wait, backup, now)
	return state, present
}

// recoveryStatus is vault.status's recovery member (§11.14.11): full to
// the app, the state alone to desktops.
func (m *Manager) recoveryStatus(full bool) []byte {
	b := strictjson.NewBuilder().String("state", m.recoveryState())
	if !full {
		return b.Bytes()
	}
	used := 0
	if v := m.rec.last; v != nil {
		used = v.Used
	}
	b.Raw("attempts", strictjson.NewBuilder().Uint("used", uint64(used)).Uint("of", recovery.MaxAttempts).Bytes())
	if !m.rec.presentAt.IsZero() {
		b.String("present_recorded_at", m.rec.presentAt.UTC().Format(time.RFC3339))
	}
	c := "ok"
	if m.rec.lastErr {
		c = "unavailable"
	}
	return b.String("counter", c).Bytes()
}
