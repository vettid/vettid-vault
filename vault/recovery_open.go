package vault

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"
	"unicode/utf8"

	"github.com/vettid/vettid-vault/vault/counter"
	"github.com/vettid/vettid-vault/vault/store"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/recovery"
	"github.com/vettid/vettid-vault/vms/suite"
)

// The recovery open of release R (VAULT-MESSAGING 0.33.0 §11.14.6): the
// registered phone's attempt at the PIN and the password together, counted
// at the attempt counter before it is tested.

// Recovery open answers (§11.14.6).
const (
	OpenWrong          = "wrong"
	OpenWrongAgain     = "wrong_again"
	OpenAttemptLost    = "attempt_lost"
	OpenQuiet          = "quiet"
	OpenWait           = "wait"
	OpenBusy           = "busy"
	OpenExhausted      = "exhausted"
	OpenClosed         = "closed"
	OpenNotArmed       = "not_armed"
	OpenStoredMismatch = "stored_mismatch"
	OpenCounterDown    = "counter_unavailable"
	OpenNoRecovery     = "no_recovery"
	OpenExpired        = "expired"
	OpenRetry          = "retry"
)

// RecoveryCredential is implemented by the credential feature: the last
// step of a recovery (§11.14.6 step 6) opens the vault's backup copy with
// the password, re-keys the critical items, rotates the CEK and leaves the
// holder to the recovered phone's pairing. ErrBadPassword-like failures
// are returned as errors.
type RecoveryCredential interface {
	RecoverFromBackup(s *Session, password []byte) error
}

// RecoveryOpenParams is a recovery open after the enclave decrypted the
// request and checked its binding, freshness and replay.
type RecoveryOpenParams struct {
	Options
	VaultID, UserGUID, RecoveryID string
	DeviceIK                      ed25519.PublicKey
	PIN                           string
	Password                      []byte
	UnlockSecret                  []byte
	// DeviceToken is the open token for the phone's mailbox.
	DeviceToken string
	// VerifyDevice checks the request's signature and device assertion
	// with the registered phone's keys; ErrDeviceSig drops the request.
	VerifyDevice func(app *RecoveryApp) (json.RawMessage, error)
	Manifest     func(serialSeen uint64) (*ManifestView, error)
	// RecoveryNow is the clock of the recovery record's expiry (the
	// development stack's recovery clock; nil: Options.Now).
	RecoveryNow func() time.Time
}

// RecoveryOpenOutcome is what the enclave seals into the result, and the
// clear marker.
type RecoveryOpenOutcome struct {
	OK      bool
	Code    string
	Drop    bool
	Counted bool // spent or lost: attempt_used and the clear recovery_attempt marker
	Used    int
	HasUsed bool
	RetryAt time.Time
	// Expires is the recovery's moved expiry when a wait began.
	Expires     time.Time
	DeviceKEM   []byte
	StateSeq    uint64
	HeaderSeq   uint64
	Token       string
	VaultBundle []byte
	Release     ReleaseEntry
	Serial      uint64
	Events      []LifecycleEvent
}

// AttemptUsed is the result's attempt_used (VAULT-MESSAGING 0.34.0
// §11.14.6): true if and only if this request's Spend was answered spent
// or lost, whatever went wrong after it. It is right only because a Spend
// is never repeated, by the vault or underneath it: the counter's S3 calls
// (enclave/s3counter) make each create-only put of a token once and never
// retry it automatically, so one request can take at most one attempt and
// an attempt this request did not take is never reported as its own. A
// transport that retried the put could take a second attempt unseen.
func (o *RecoveryOpenOutcome) AttemptUsed() bool { return o.Counted }

func (o *RecoveryOpenOutcome) fail(code string) *RecoveryOpenOutcome {
	o.OK, o.Code = false, code
	return o
}

// openWriter writes the header of a recovery open that changes it (a
// wrong pair's tag, the moved expiry, the log) with a conditional write.
type openWriter struct {
	p    *RecoveryOpenParams
	hkey string
	ver  store.Version
	hdr  *Header
}

func (w *openWriter) write(ctx context.Context) {
	w.hdr.HeaderSeq++
	if b, err := sealHeader(ctx, w.p.Sealer, w.hdr); err == nil {
		if v, err := w.p.Store.Put(ctx, w.hkey, b, w.ver); err == nil {
			w.ver = v
		}
	}
}

// RecoveryOpen runs §11.14.6 steps 1 to 6 and, on success, returns the
// running vault.
func RecoveryOpen(ctx context.Context, p RecoveryOpenParams) (*Manager, *RecoveryOpenOutcome) {
	p.Options.defaults()
	now := p.Now()
	recNow := now
	if p.RecoveryNow != nil {
		recNow = p.RecoveryNow()
	}
	out := &RecoveryOpenOutcome{}
	own := p.Release
	drop := func() (*Manager, *RecoveryOpenOutcome) { out.Drop = true; return nil, out.fail(OpenNoRecovery) }
	if !validRelease(own) || p.Store == nil || p.Sealer == nil {
		return drop()
	}
	hkey := store.HeaderKey(p.VaultID, own.PCR0)
	hblob, hver, err := p.Store.Get(ctx, hkey)
	if err != nil {
		return drop()
	}
	hdr, err := unsealHeader(ctx, p.Sealer, hblob, p.VaultID, own.PCR0)
	if err != nil || hdr.UserGUID != p.UserGUID || hdr.Deleting {
		return drop()
	}
	defer suite.Wipe(hdr.Pepper)
	w := &openWriter{p: &p, hkey: hkey, ver: hver, hdr: hdr}
	out.HeaderSeq = hdr.HeaderSeq
	// Step 1: the recovery record names this recovery and this phone.
	r := hdr.Recovery
	if r == nil || r.ID != p.RecoveryID || r.State != RecoveryRegistered || r.App == nil || !suite.EqualPublic(r.App.IK, p.DeviceIK) {
		return drop()
	}
	out.DeviceKEM = r.App.KEM
	if _, err := p.VerifyDevice(r.App); err != nil {
		if errors.Is(err, ErrDeviceSig) {
			return drop()
		}
		return nil, out.fail(CodeAttestation)
	}
	if !recNow.Before(r.Expires) {
		return nil, out.fail(OpenExpired)
	}
	mv, err := p.Manifest(hdr.ManifestSerial)
	if err != nil || mv.Own.PCR0 != own.PCR0 || mv.Own.Number != own.Number {
		return nil, out.fail(CodeManifest)
	}
	out.Release, out.Serial = mv.Own, mv.Serial
	if len(p.UnlockSecret) != recovery.SecretSize {
		return nil, out.fail(CodeBadRequest)
	}
	pw, ok := recovery.NormalizePassword(p.Password)
	if !ok {
		return nil, out.fail(CodeBadRequest)
	}
	defer suite.Wipe(pw)
	sblob, sver, err := p.Store.Get(ctx, store.StateKey(p.VaultID))
	if err != nil {
		return nil, out.fail(CodeMissing)
	}
	stateVer, ok := StateDEKVersion(sblob)
	if !ok {
		return nil, out.fail(OpenStoredMismatch)
	}
	// A recovery whose step 1 is stored: repeated through the `next` wrap
	// without a new attempt (§11.14.2); the password must open the
	// credential.
	if nx := hdr.Next; nx != nil && nx.Reason == ReplaceRecovery {
		return resumeRecovery(ctx, p, hdr, hver, sblob, sver, stateVer, pw, mv, out, now)
	}
	// Step 2: armed, and an opener for the stored state's DEK.
	wrap := hdr.Rec.Wrap
	if wrap == nil || wrap.Generation != hdr.Rec.Generation || hdr.Rec.Generation == 0 {
		return nil, out.fail(OpenNotArmed)
	}
	if wrap.OpenerDEKVersion != stateVer {
		// A replacement stopped after its step 2 (a transfer whose new
		// phone was then lost): the `next` part's opener of the same
		// generation is for the stored state's DEK (§11.14.6 step 2).
		if nx := hdr.Next; nx != nil && nx.Wrap != nil && nx.Wrap.Generation == wrap.Generation && nx.Wrap.OpenerDEKVersion == stateVer {
			wrap = nx.Wrap
		} else {
			return nil, out.fail(OpenStoredMismatch) // nothing used
		}
	}
	g := wrap.Generation
	// Step 2a: the permit, x, and the same wrong pair from this phone.
	rel := func() {}
	if p.HeavyPermit != nil {
		var got bool
		if rel, got = p.HeavyPermit(ctx); !got {
			hdr.logRecovery(now, "recovery.open", openRef(r, OpenBusy))
			return nil, out.fail(OpenBusy)
		}
	}
	x, err := heavyX(p.PIN, pw, wrap.KDF)
	rel() // the permit covers the derivation only, never the counter's calls
	if err != nil {
		return nil, out.fail(CodeBadRequest)
	}
	defer suite.Wipe(x)
	tag, err := recovery.WrongTag(x, hdr.Pepper, p.VaultID, r.ID, r.App.IK)
	if err != nil {
		return nil, out.fail(CodeBadRequest)
	}
	if r.WrongAgain < recovery.MaxWrongAgain && len(r.LastWrong) > 0 && suite.Equal(tag, r.LastWrong) {
		r.WrongAgain++
		hdr.logRecovery(now, "recovery.open", openRef(r, OpenWrongAgain))
		w.write(ctx)
		out.HeaderSeq = hdr.HeaderSeq
		return nil, out.fail(OpenWrongAgain)
	}
	// Step 3: the first look.
	n, err := recovery.NewNames(hdr.Rec.CounterKey, p.VaultID)
	if err != nil || p.Counter == nil {
		return nil, out.fail(OpenCounterDown)
	}
	unit, quiet := p.RecoveryWaitUnit, p.RecoveryQuiet
	if unit == 0 {
		unit = defaultWaitUnit
	}
	if quiet == 0 {
		quiet = defaultQuiet
	}
	ctr := counter.New(p.Counter, n, unit).WithQuiet(quiet).WithRecordLock(p.RecoveryCounterLock)
	sent := time.Now()
	v, err := ctr.Status(ctx, g)
	if err != nil {
		return nil, out.fail(OpenCounterDown)
	}
	out.HasUsed, out.Used = true, v.Used
	if vd, at := counter.FirstLook(v, quiet); vd != counter.VerdictTest {
		out.RetryAt = at
		return nil, out.fail(verdictCode(vd))
	}
	if time.Since(sent) > recovery.StatusMaxAgeSecs*time.Second { // 3b, the enclave's clock
		return nil, out.fail(OpenRetry)
	}
	// Step 4: spend exactly the next attempt.
	k := v.Next()
	sp := ctr.Spend(ctx, g, k)
	switch sp.Outcome {
	case counter.Spent, counter.Lost:
		out.Counted, out.Used = true, sp.Used
		if sp.WaitUntil.After(v.Now) && recovery.WaitUnits(k) > 0 {
			out.RetryAt = sp.WaitUntil
			// The recovery stays open across the wait (§11.14.5).
			// The wait itself is W(k), whose unit is a release constant
			// and is not scaled; the validity after it is (0.43.0, S6).
			r.Expires = recNow.Add(sp.WaitUntil.Sub(v.Now) + p.Options.scale(RecoveryValidity))
			out.Expires = r.Expires
		}
	case counter.Unavailable:
		return nil, out.fail(OpenCounterDown)
	default:
		out.RetryAt = sp.WaitUntil
		return nil, out.fail(spendCode(sp.Outcome))
	}
	if sp.Outcome == counter.Lost {
		hdr.logRecovery(now, "recovery.open", openRef(r, OpenAttemptLost))
		w.write(ctx)
		out.HeaderSeq = hdr.HeaderSeq
		return nil, out.fail(OpenAttemptLost)
	}
	// Step 4b: decided against the attempt's own time.
	cv, err := ctr.Confirm(ctx, g)
	if err != nil {
		hdr.logRecovery(now, "recovery.open", openRef(r, OpenAttemptLost))
		w.write(ctx)
		return nil, out.fail(OpenAttemptLost)
	}
	out.Used = cv.Used
	if vd, at := counter.AfterSpend(cv, k, sp.At, v.Now, quiet, unit); vd != counter.VerdictTest {
		if !at.IsZero() {
			out.RetryAt = at
		}
		hdr.logRecovery(now, "recovery.open", openRef(r, verdictCode(vd)))
		w.write(ctx)
		return nil, out.fail(verdictCode(vd))
	}
	// Step 5: only now the wrap.
	key, err := recovery.WrapKey(x, hdr.Pepper, p.VaultID, g)
	if err != nil {
		return nil, out.fail(OpenRetry)
	}
	rk, err := recovery.OpenRecoveryKey(key, wrap.Wrap, p.VaultID, g)
	suite.Wipe(key)
	if err != nil {
		r.LastWrong, r.WrongAgain = tag, 0
		hdr.logRecovery(now, "recovery.open", openRef(r, OpenWrong))
		w.write(ctx)
		out.HeaderSeq = hdr.HeaderSeq
		return nil, out.fail(OpenWrong)
	}
	defer suite.Wipe(rk)
	// Step 6: the success, the DEK of the stored state, the completion.
	var serr error
	for i := 0; i < 3; i++ {
		if serr = ctr.Succeed(ctx, g, k); serr == nil {
			break
		}
	}
	dek, err := recovery.OpenOpener(rk, wrap.Opener, p.VaultID, g, stateVer)
	if err != nil {
		return nil, out.fail(OpenStoredMismatch)
	}
	m, code := openState(ctx, p, hdr, hver, sblob, sver, dek)
	if code == codeDeleted {
		return drop()
	}
	if code != "" {
		return nil, out.fail(code)
	}
	if stateVer != m.hdr.DEKVersion {
		// The state is under the stopped replacement's DEK: that part is
		// abandoned and its DEK version is the current one from here on.
		m.hdr.DEKVersion = stateVer
		m.dropNext(now)
	}
	m.rec.ctr = ctr
	m.st.RecoveredAttempt = []uint64{g, uint64(k)}
	if serr != nil {
		m.st.PendingSucceed = []uint64{g, uint64(k)}
	}
	return m.completeRecoveryR(ctx, p, r, wrap, rk, pw, mv, out, now)
}

// maxOpenName is the most bytes of the attempting phone's name an open's
// ref carries (§11.14.11, 0.50.0).
const maxOpenName = 64

// openRef is a noted open's ref (§11.14.11, 0.50.0):
// `<recovery_id>/<outcome>`, with a third part, the attempting phone's
// self-reported name (`app.name` of vault.recovery.register, §11.11.3),
// when it has one after cleaning. The name is only recorded: nothing
// reads it to decide anything.
func openRef(r *RecoveryRecord, outcome string) string {
	ref := r.ID + "/" + outcome
	if r.App != nil {
		if n := cleanOpenName(r.App.Name); n != "" {
			ref += "/" + base64.RawURLEncoding.EncodeToString([]byte(n))
		}
	}
	return ref
}

// cleanOpenName removes control characters (C0, DEL, C1) and any byte
// that is not UTF-8 from a phone's name and cuts it to at most
// maxOpenName bytes at a character boundary (§11.14.11, 0.50.0).
func cleanOpenName(name string) string {
	b := make([]byte, 0, maxOpenName)
	for i := 0; i < len(name); {
		c, size := utf8.DecodeRuneInString(name[i:])
		i += size
		if c == utf8.RuneError && size == 1 {
			continue // not UTF-8
		}
		if c < 0x20 || (c >= 0x7f && c <= 0x9f) {
			continue // C0, DEL, C1
		}
		if len(b)+size > maxOpenName {
			break
		}
		b = utf8.AppendRune(b, c)
	}
	return string(b)
}

func verdictCode(vd string) string {
	switch vd {
	case counter.VerdictClosed:
		return OpenClosed
	case counter.VerdictQuiet:
		return OpenQuiet
	case counter.VerdictExhaus:
		return OpenExhausted
	}
	return OpenWait
}

func spendCode(o string) string {
	switch o {
	case counter.Exhausted:
		return OpenExhausted
	case counter.Closed:
		return OpenClosed
	}
	return OpenWait
}

// openState decrypts the stored state under dek and makes the manager.
func openState(ctx context.Context, p RecoveryOpenParams, hdr *Header, hver store.Version, sblob []byte, sver store.Version, dek []byte) (*Manager, string) {
	pt, seq, err := decryptState(dek, p.VaultID, sblob)
	if err != nil {
		suite.Wipe(dek)
		return nil, OpenStoredMismatch
	}
	var st State
	err = json.Unmarshal(pt, &st)
	suite.Wipe(pt)
	if err != nil || st.VaultID != p.VaultID || st.StateSeq != seq || st.StateSeq < hdr.StateSeq {
		suite.Wipe(dek)
		return nil, OpenStoredMismatch
	}
	st.init()
	if st.SealedRelease == "" {
		st.SealedRelease = hdr.SealedRelease
	}
	h := *hdr
	h.Pepper = append([]byte(nil), hdr.Pepper...)
	m := newManager(p.Options, &st, &h, dek)
	m.stateVer, m.headerVer = sver, hver
	if st.Deleting != nil {
		// 0.51.0 (§12.5): a state that records deleting never runs; the
		// deletion is finished instead and the open is answered as for a
		// missing vault.
		m.finishMarked(ctx)
		return nil, codeDeleted
	}
	return m, ""
}

// codeDeleted is openState's answer for a state that records Deleting
// (0.51.0): the caller drops the request, as for a missing vault.
const codeDeleted = "deleted"

// completeRecoveryR is step 6 after the state is loaded: the credential
// from its backup copy with the password, the phone as the vault's app
// (its pairing completes the hand-over), every other app removed, the
// vault's keys rotated (a failure never fails the recovery), and the DEK
// replaced for the request's PIN and the phone's secret in the order of
// writes; the presence is recorded after step 2.
func (m *Manager) completeRecoveryR(ctx context.Context, p RecoveryOpenParams, r *RecoveryRecord, wrap *RecoveryWrap, rk, pw []byte,
	mv *ManifestView, out *RecoveryOpenOutcome, now time.Time) (*Manager, *RecoveryOpenOutcome) {
	fail := func(code string) (*Manager, *RecoveryOpenOutcome) {
		m.zeroize()
		return nil, out.fail(code)
	}
	if err := m.loadKeys(); err != nil {
		return fail(CodeMissing)
	}
	if err := m.restoreLive(); err != nil {
		return fail(CodeMissing)
	}
	m.unlockSecret = append([]byte(nil), p.UnlockSecret...)
	var cred RecoveryCredential
	for _, f := range m.features {
		if c, ok := f.(RecoveryCredential); ok {
			cred = c
		}
	}
	sess := m.session(now)
	if cred == nil || cred.RecoverFromBackup(sess, pw) != nil {
		return fail(OpenStoredMismatch) // the pair opened the wrap but not the backup copy
	}
	// The replacement: DEK_1 for the PIN and the phone's secret, the same
	// generation, an opener for DEK_1, and the phone as the next app.
	kdf := m.hdr.KDF
	salt, err := suite.RandomBytes(16)
	if err != nil {
		return fail(OpenRetry)
	}
	kdf.Salt = salt
	rep, err := m.nextFor(ReplaceRecovery, p.PIN, p.UnlockSecret, kdf, nil, now)
	if err != nil {
		return fail(OpenRetry)
	}
	if rep.next.Wrap, err = reopen(wrap, rk, m.hdr.VaultID, rep.dek1, rep.next.DEKVersion); err != nil {
		rep.wipe()
		return fail(OpenRetry)
	}
	rep.next.RecoveryAttempt = append([]uint64(nil), m.st.RecoveredAttempt...)
	rep.next.App = &UnlockKey{DeviceID: recoveryDeviceID, IK: r.App.IK, KEM: r.App.KEM, Attestation: r.App.Attestation}
	if len(r.App.APIKey) > 0 {
		rep.next.AppKey, rep.next.AppKeySeq = append([]byte(nil), r.App.APIKey...), m.hdr.AppKeySeq+1
	}
	// The event in the state (step 2): the phone's first handshake
	// (ctx = recovery_id, no approval), the other apps removed, the keys
	// rotated, the attempt's success recorded.
	m.setRecoveredInvite(&Invite{ID: r.ID, Kind: KindApp, Exp: now.Add(RecoveredInviteWindow), EnrollIK: r.App.IK, EnrollRelayPK: r.App.RelayPK,
		EnrollKEM: r.App.KEM, EnrollAttest: r.App.Attestation, CreatedBy: inviteByRecovery}, now)
	m.keepRecoveredSigner()
	m.replaceApps("", now)
	m.sendPendingUnlink(now) // a transfer's old phone, before the keys rotate (§11.14.10)
	// A rotation that cannot be made never fails the recovery: the owed
	// mark, in this state write, makes the next unlock try again (§11.14.6
	// step 6, §11.14.10 "The owed mark"). A rotation clears it.
	m.st.RotationOwed = r.ID
	m.dirty = true
	if err := m.rotateIdentity(now); err != nil {
		m.record(Activity{Kind: "identity.rotation_failed", Ref: "recovery", Audit: true, Feed: true, Priority: "high"}, now)
	}
	m.record(Activity{Kind: "recovery.completed", Ref: r.ID, Audit: true, Feed: true}, now)
	recID := r.ID
	appKeyFn := m.replacementPromoteFn(rep.next)
	rep.promoteFn = func() {
		if appKeyFn != nil {
			appKeyFn()
		}
		if m.hdr.Recovery != nil && m.hdr.Recovery.ID == recID {
			m.hdr.logRecovery(now, "recovery.completed", recID)
			m.hdr.Recovery = nil
		}
	}
	if err := m.beginReplace(ctx, rep); err != nil {
		return fail(OpenRetry)
	}
	return m.finishOpen(ctx, p, mv, out, true, now)
}

// completionStatusTimeout bounds the counter's status read after a
// completion: the ok never waits long on it; the next owner check reads it.
const completionStatusTimeout = 10 * time.Second

// finishOpen registers the relay, mints the phone's token, flushes (steps
// 2 and 3), records the presence and answers ok. passwordProved: this run
// opened the credential's backup copy with the password, so it starts the
// owner check's clock.
func (m *Manager) finishOpen(ctx context.Context, p RecoveryOpenParams, mv *ManifestView, out *RecoveryOpenOutcome, passwordProved bool,
	now time.Time) (*Manager, *RecoveryOpenOutcome) {
	var err error
	m.relay = p.Relay(m.st.Relay.URL, m.keys.relay)
	if m.limits, err = m.relay.Register(ctx); err != nil {
		m.zeroize()
		return nil, out.fail(OpenRetry)
	}
	if mv != nil && mv.Serial > m.hdr.ManifestSerial {
		m.hdr.ManifestSerial = mv.Serial
	}
	out.Token = m.unlockTokens(&UnlockKey{IK: p.DeviceIK}, p.DeviceToken, now)
	// The successful recovery open proves the PIN and the password
	// together and starts the owner check's clock like a check, ending a
	// hold (§3.6.1 "What else starts the clock", §11.14.6), as
	// credential.recover does before release R. It is written with the
	// completion's state (step 2), so a run that does not store it starts
	// nothing, and a repeat through the `next` wrap whose step 2 was not
	// stored (it opens the backup copy with the password) starts it then.
	// A repeat after step 2 was stored proves only the PIN and the phone's
	// secret: the clock stays as the stored completion set it. Nor does
	// the recovered phone's later unlock after a lost ok restart it (an
	// unlock is not a check, §3.6.1).
	if passwordProved {
		m.ownerCheckPassed(nil, false, "", now)
	}
	if err := m.persist(ctx, false); err != nil {
		m.zeroize()
		return nil, out.fail(OpenRetry)
	}
	// After step 2: the presence (a failed completion starts no quiet
	// period); Succeed again if it was not recorded.
	if !m.markPresent(ctx, now) {
		m.st.PresentPending = true // sent again at every later unlock and owner check
		m.dirty = true
	}
	m.retryPendingSucceed(ctx)
	// After step 2, and after the success is sent again: the counter's
	// record of this generation's attempts (§11.14.11, "a completed
	// recovery"), once each; the next owner check adds only what is new.
	// Written with the next flush; if that never happens the next owner
	// check writes them instead.
	if g := m.hdr.Rec.Generation; g > 0 {
		sctx, cancel := context.WithTimeout(ctx, completionStatusTimeout)
		v, err := m.status(sctx, g)
		cancel()
		if err == nil {
			m.recordAttempts(v, now)
		}
	}
	m.started = false
	out.OK, out.Code = true, ""
	out.StateSeq, out.HeaderSeq = m.st.StateSeq, m.hdr.HeaderSeq
	out.VaultBundle = VaultBundle(handshake.Principal{IK: m.keys.ik.Public().(ed25519.PublicKey), KEM: m.keys.kem.Public(), Relay: m.ownAddr()})
	ev := lifecycle(p.Options, "unlocked", p.VaultID, p.Release.PCR0)
	ev.AppKey, ev.AppKeySeq = m.AppKey()
	out.Events = append(out.Events, ev)
	return m, out
}

// retryPendingSucceed sends Succeed again until the counter confirms it
// (§11.14.6: at every later unlock and owner check).
func (m *Manager) retryPendingSucceed(ctx context.Context) {
	if ps := m.st.PendingSucceed; len(ps) == 2 {
		if c := m.counter(); c != nil && c.Succeed(ctx, ps[0], int(ps[1])) == nil {
			m.st.PendingSucceed = nil
			m.dirty = true
		}
	}
	if m.st.PresentPending && m.markPresent(ctx, m.now()) {
		m.st.PresentPending = false
		m.dirty = true
	}
}

// resumeRecovery repeats a recovery whose step 1 is stored, through the
// `next` wrap and without a new attempt (§11.14.2): the PIN and the phone's
// secret open dek_wrap_next, and the password must open the credential.
func resumeRecovery(ctx context.Context, p RecoveryOpenParams, hdr *Header, hver store.Version, sblob []byte, sver store.Version,
	stateVer uint64, pw []byte, mv *ManifestView, out *RecoveryOpenOutcome, now time.Time) (*Manager, *RecoveryOpenOutcome) {
	nx := hdr.Next
	sc, _ := recovery.SecretCheck(hdr.Pepper, p.VaultID, p.UnlockSecret)
	if sc == nil || !suite.Equal(sc, nx.SecretCheck) {
		return nil, out.fail(CodeDeviceSecret)
	}
	uk, err := deriveUnlockKey(p.PIN, p.UnlockSecret, nx.KDF, hdr.Pepper, p.VaultID)
	if err != nil {
		return nil, out.fail(OpenWrong)
	}
	d0, d1, err := recovery.OpenDEKNext(uk, nx.DEKWrapNext, p.VaultID, nx.DEKVersion)
	if err != nil {
		suite.Wipe(uk)
		return nil, out.fail(OpenWrong)
	}
	dek := d0
	if stateVer == nx.DEKVersion {
		dek = d1
	} else if stateVer != hdr.DEKVersion {
		return nil, out.fail(OpenStoredMismatch)
	}
	m, code := openState(ctx, p, hdr, hver, sblob, sver, append([]byte(nil), dek...))
	if code == codeDeleted {
		suite.Wipe(uk)
		suite.Wipe(d0)
		suite.Wipe(d1)
		out.Drop = true
		return nil, out.fail(OpenNoRecovery)
	}
	if code != "" {
		return nil, out.fail(code)
	}
	if stateVer == hdr.DEKVersion {
		// Step 2 was not stored: the credential's password must open the
		// backup copy; the event is applied again under DEK_1.
		if err := m.loadKeys(); err != nil {
			m.zeroize()
			return nil, out.fail(CodeMissing)
		}
		if err := m.restoreLive(); err != nil {
			m.zeroize()
			return nil, out.fail(CodeMissing)
		}
		var cred RecoveryCredential
		for _, f := range m.features {
			if c, ok := f.(RecoveryCredential); ok {
				cred = c
			}
		}
		if cred == nil || cred.RecoverFromBackup(m.session(now), pw) != nil {
			m.zeroize()
			return nil, out.fail(OpenWrong)
		}
		// The event's attempt, as the first run set it, and its success
		// sent again: the first run's PendingSucceed was in the state
		// that was not stored. A `next` part from before the field has
		// none: its attempts stay urgent.
		if ra := nx.RecoveryAttempt; len(ra) == 2 {
			m.st.RecoveredAttempt = []uint64{ra[0], ra[1]}
			m.st.PendingSucceed = []uint64{ra[0], ra[1]}
		}
		r := hdr.Recovery
		if r != nil && r.App != nil {
			m.setRecoveredInvite(&Invite{ID: r.ID, Kind: KindApp, Exp: now.Add(RecoveredInviteWindow), EnrollIK: r.App.IK, EnrollRelayPK: r.App.RelayPK,
				EnrollKEM: r.App.KEM, EnrollAttest: r.App.Attestation, CreatedBy: inviteByRecovery}, now)
			// The first run's RecoveredSigner was in the state that was
			// not stored: recorded again before the apps go (§11.7.1).
			m.keepRecoveredSigner()
			m.replaceApps("", now)
		}
	} else {
		if err := m.loadKeys(); err != nil {
			m.zeroize()
			return nil, out.fail(CodeMissing)
		}
		if err := m.restoreLive(); err != nil {
			m.zeroize()
			return nil, out.fail(CodeMissing)
		}
		// Step 2 was stored, by this recovery's open or by an earlier
		// recovery's: the stored recovered invite is bound to the phone
		// that ran it. The full proof is behind us here (the code and
		// the attestation at register, the record's phone, its signature
		// and current assertion in step 1, the PIN and the phone's
		// secret through dek_wrap_next).
		m.resumeRecoveredInvite(hdr.Recovery, p.DeviceIK, now)
	}
	m.unlockSecret = append([]byte(nil), p.UnlockSecret...)
	m.repl = &replacement{next: nx, dek1: d1, uk1: uk, secret1: append([]byte(nil), p.UnlockSecret...)}
	recID := ""
	if hdr.Recovery != nil {
		recID = hdr.Recovery.ID
	}
	appKeyFn := m.replacementPromoteFn(nx)
	m.repl.promoteFn = func() {
		if appKeyFn != nil {
			appKeyFn()
		}
		if m.hdr.Recovery != nil && m.hdr.Recovery.ID == recID {
			m.hdr.Recovery = nil
		}
	}
	suite.Wipe(d0)
	m.record(Activity{Kind: "recovery.completed", Ref: recID + "/resumed", Audit: true}, now)
	// Only the branch whose step 2 was not stored opened the backup copy
	// with the password.
	return m.finishOpen(ctx, p, mv, out, stateVer == hdr.DEKVersion, now)
}

// The recovered phone before its first handshake (owner decision of
// 2026-10-16, VAULT-MESSAGING 0.34.0 §11.14.6 "A lost ok"). Its recovery
// invite, in the vault state, is what marks it: it is the phone's unlock
// key (syncUnlockKeys) for as long as it exists, whatever its expiry, and
// it ends only when the phone's first handshake completes
// (recoveredPhonePaired) or a later recovery replaces it. The state is
// encrypted, conditional and checked against the header's state_seq like
// every other state, so a host cannot bring back an invite that pairing
// removed without a rollback the unlock refuses (§13.2).

// setRecoveredInvite records the recovered phone's invite and ends any
// earlier recovered phone's (a later recovery replaces it, with its
// handshake if one is under way).
func (m *Manager) setRecoveredInvite(inv *Invite, now time.Time) {
	for id, old := range m.st.Invites {
		if old.CreatedBy == inviteByRecovery && id != inv.ID {
			m.dropRecoveredHandshake(id, now)
			delete(m.st.Invites, id)
		}
	}
	m.st.Invites[inv.ID] = inv
	m.dirty = true
}

// recoveredInvite is the invite of the recovered phone whose identity is
// ik, before its first handshake; nil for every other device.
func (m *Manager) recoveredInvite(ik ed25519.PublicKey) *Invite {
	for _, inv := range m.st.Invites {
		if inv.CreatedBy == inviteByRecovery && inv.EnrollIK != nil && suite.EqualPublic(inv.EnrollIK, ik) {
			return inv
		}
	}
	return nil
}

// dropRecoveredHandshake ends a first handshake begun with invite id that
// has not completed.
func (m *Manager) dropRecoveredHandshake(id string, now time.Time) {
	for aid, aw := range m.st.Awaiting {
		if aw.InviteID == id {
			m.dropAwaiting(aid, "replaced", now)
		}
	}
}

// resumeLostOK is the recovered phone's own unlock before its first
// handshake: the result carries the vault's bundle again (the token it
// carries anyway), and the phone's pairing starts afresh: a handshake
// begun and not completed is dropped, and the invite is usable for
// another RecoveredInviteWindow. It may repeat until the phone pairs; no
// attempt is used and the counter is not called.
func (m *Manager) resumeLostOK(inv *Invite, now time.Time) []byte {
	m.renewRecoveredInvite(inv, now)
	return VaultBundle(handshake.Principal{IK: m.keys.ik.Public().(ed25519.PublicKey), KEM: m.keys.kem.Public(), Relay: m.ownAddr()})
}

// renewRecoveredInvite restarts a recovered phone's pairing: a first
// handshake begun with the invite and not completed is dropped, and the
// invite is usable for another RecoveredInviteWindow.
func (m *Manager) renewRecoveredInvite(inv *Invite, now time.Time) {
	m.dropRecoveredHandshake(inv.ID, now)
	inv.Used = false
	inv.Exp = now.Add(RecoveredInviteWindow)
	m.dirty = true
}

// resumeRecoveredInvite is a repeated recovery open whose step 2 is
// stored (§11.14.6 "A phone that could not tell"). r is the header's
// current recovery record, whose registered phone (device) the open has
// proved in full.
//
//   - The stored invite is this phone's identity (the same ik registered
//     again for a later recovery, with a new attested key on iOS): it is
//     set again from the current registration, as a run whose step 2 was
//     not stored sets it: ctx = the current recovery_id, the current
//     relay key, KEM and attestation binding. The earlier recovery's
//     invite goes, with any first handshake begun with it. Without this
//     the phone, which pairs with the current recovery_id and asserts
//     with its current key, could neither pair nor unlock.
//   - The stored invite is another identity's (the phone registered a
//     new identity, and an earlier recovery's run with its earlier
//     identity stored step 2): the repeat keeps that invitation (the
//     earlier identity pairs with the earlier recovery_id).
//
// Either way the invite is renewed as a lost ok's unlock renews it. If
// the phone has paired there is no recovered invite and nothing changes.
//
// Accepted gap: until step 3 is stored the header's `next` part still
// names the phone as the run that stored step 1 registered it
// (findUnlockKey), with that run's attestation binding. If this repeat
// stores its state and its step-3 header write fails, the phone's lost-ok
// unlock with its new attested key is refused until it opens again while
// the current recovery is registered; that repeat is idempotent.
func (m *Manager) resumeRecoveredInvite(r *RecoveryRecord, device ed25519.PublicKey, now time.Time) {
	if r != nil && r.App != nil && r.App.IK != nil && suite.EqualPublic(r.App.IK, device) {
		if inv := m.recoveredInvite(r.App.IK); inv != nil {
			inv = &Invite{ID: r.ID, Kind: KindApp, Exp: now.Add(RecoveredInviteWindow), EnrollIK: r.App.IK, EnrollRelayPK: r.App.RelayPK,
				EnrollKEM: r.App.KEM, EnrollAttest: r.App.Attestation, CreatedBy: inviteByRecovery}
			m.setRecoveredInvite(inv, now)
			m.renewRecoveredInvite(inv, now)
			return
		}
	}
	for _, inv := range m.st.Invites {
		if inv.CreatedBy == inviteByRecovery {
			m.renewRecoveredInvite(inv, now)
		}
	}
}

// keepRecoveredSigner records the vault's signer binding (the old app's
// signer, or the signer kept across an iOS app, VA4) as RecoveredSigner,
// before the recovery open removes the apps, so that the recovered
// phone's first handshake compares its signer with it (§11.7.1,
// §11.14.6). Both the first run and a resumed one call it.
func (m *Manager) keepRecoveredSigner() {
	if d, c := m.vaultSigner(""); d != "" {
		m.st.RecoveredSigner = []string{d, c}
	}
}
