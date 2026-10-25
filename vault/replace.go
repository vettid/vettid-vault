package vault

import (
	"bytes"
	"context"
	"errors"
	"time"

	"github.com/vettid/vettid-vault/vault/store"
	"github.com/vettid/vettid-vault/vms/recovery"
	"github.com/vettid/vettid-vault/vms/suite"
)

// The order of writes of a DEK replacement (§11.14.2): (1) a header that
// keeps everything current and adds the `next` part, read back; (2) the
// state with the event applied, under DEK_1 (the batch's flush); (3) the
// header with `next` made current (the flush's header write).

// replacement is a DEK replacement whose step 1 is stored.
type replacement struct {
	next      *HeaderNext
	dek1      []byte
	uk1       []byte
	secret1   []byte
	promoteFn func() // the event's own header changes at step 3
}

func (r *replacement) wipe() {
	if r == nil {
		return
	}
	suite.Wipe(r.dek1)
	suite.Wipe(r.uk1)
	suite.Wipe(r.secret1)
}

// errRetry answers a change whose first header write could not be stored
// and read back: nothing changed but the spent UTK (§11.14.2).
var errRetry = &HandlerError{Code: "retry"}

// nextFor builds a replacement for the running vault: a fresh DEK_1 at the
// next dek_version, wrapped with DEK_0 under the unlock key of pin and
// secret at kdf (dek_wrap_next), and the secret's check.
func (m *Manager) nextFor(reason, pin string, secret []byte, kdf KDFParams, wrap *RecoveryWrap, now time.Time) (*replacement, error) {
	dek1, err := suite.RandomBytes(recovery.SecretSize)
	if err != nil {
		return nil, err
	}
	vid := m.st.VaultID
	uk1, err := deriveUnlockKey(pin, secret, kdf, m.hdr.Pepper, vid)
	if err != nil {
		suite.Wipe(dek1)
		return nil, err
	}
	ver := m.hdr.DEKVersion + 1
	wn, err := recovery.WrapDEKNext(uk1, m.dek, dek1, vid, ver)
	if err != nil {
		suite.Wipe(dek1)
		suite.Wipe(uk1)
		return nil, err
	}
	sc, err := recovery.SecretCheck(m.hdr.Pepper, vid, secret)
	if err != nil {
		return nil, err
	}
	return &replacement{
		next: &HeaderNext{Reason: reason, DEKVersion: ver, KDF: kdf, DEKWrapNext: wn, SecretCheck: sc, Wrap: wrap, At: now.UTC()},
		dek1: dek1, uk1: uk1, secret1: append([]byte(nil), secret...),
	}, nil
}

// beginReplace is step 1: the header with the `next` part, written and
// read back. On failure nothing has changed (errRetry, or ErrSplitBrain).
func (m *Manager) beginReplace(ctx context.Context, r *replacement) error {
	if m.repl != nil || m.hdr.Next != nil {
		m.dropNext(m.now())
	}
	r.next.HeaderSeq = m.hdr.HeaderSeq + 1
	if r.next.AppKey != nil {
		// §11.5: the host confirms that the row names the next app key
		// BEFORE any header names it (appkeyconfirm.go): a header with
		// the key is never stored without it. If it is not confirmed
		// nothing is stored. An app_key_next the host did write stays on
		// the row (an orphan that admits a key the member's phone sent
		// through the replacement; it is cleared by the next_cleared that
		// follows a later header write, or by the next unlock).
		if err := m.confirmKey(ctx, AppKeyModeNext, r.next.AppKey, r.next.AppKeySeq, r.next.HeaderSeq); err != nil {
			m.clearOrphanNext(r.next) // the host may have written it before the answer was lost
			r.wipe()
			return errRetry
		}
	}
	m.hdr.Next = r.next
	if err := m.writeHeaderWith(ctx, false); err != nil {
		m.hdr.Next = nil
		m.clearOrphanNext(r.next) // the confirmed key is on the row, no header names it
		r.wipe()
		if errors.Is(err, ErrSplitBrain) {
			return err
		}
		return errRetry
	}
	// Read it back: a store that loses the write at once is caught here.
	blob, ver, err := m.opt.Store.Get(ctx, store.HeaderKey(m.hdr.VaultID, m.hdr.SealedRelease))
	ok := err == nil && ver == m.headerVer
	if ok {
		h, uerr := unsealHeader(ctx, m.opt.Sealer, blob, m.hdr.VaultID, m.hdr.SealedRelease)
		ok = uerr == nil && h.Next != nil && h.Next.DEKVersion == r.next.DEKVersion && h.HeaderSeq == m.hdr.HeaderSeq
		if h != nil {
			suite.Wipe(h.Pepper)
		}
	}
	if !ok {
		m.hdr.Next = nil
		m.clearOrphanNext(r.next)
		r.wipe()
		return errRetry
	}
	if r.next.AppKey != nil {
		// Confirm again, live, before step 2 whether or not the key is
		// acked: the entry on the row then carries this instance's latest
		// stamp. In a split brain another instance may have confirmed the
		// same key at the same header_seq after this one (its stamp then
		// replaced ours), and its orphan clear, bound to its own stamp,
		// would otherwise remove the entry although the header stored
		// here names the key. Step 1 is stored, so a failure is not an
		// orphan (no clear: the header names the key): stop and answer
		// retry; the next attempt drops this `next` and begins again.
		if err := m.confirmKey(ctx, AppKeyModeNext, r.next.AppKey, r.next.AppKeySeq, r.next.HeaderSeq); err != nil {
			r.wipe()
			return errRetry
		}
	}
	if r.next.AppKey != nil && m.opt.Lifecycle != nil {
		ev := lifecycle(m.opt, EventAppKeyNext, m.hdr.VaultID, m.opt.Release.PCR0)
		ev.AppKey, ev.AppKeySeq, ev.HeaderSeq = append([]byte(nil), r.next.AppKey...), r.next.AppKeySeq, r.next.HeaderSeq
		m.opt.Lifecycle(ev)
	}
	m.repl = r
	m.replInHandler = true
	m.dirty = true
	return nil
}

// clearOrphanNext tells the parent to remove an app_key_next that a failed
// step 1 left on the row: the key was confirmed (or may have been) but no
// stored header names it (or one may, if the failure was a Put that stored
// or a read-back that failed: the key is then confirmed again before it is
// adopted). The event, app_key_next_clear, names the attempted key and
// header_seq, and the parent removes the row's next key only if it is that
// key at that header_seq: never an older pending key, never another
// vault's. It is sent at once and again at the next flush (a link to the
// parent that is down drops it), and the parent writes it again until it
// has. The key is no longer taken as confirmed.
func (m *Manager) clearOrphanNext(nx *HeaderNext) {
	if nx == nil || nx.AppKey == nil {
		return
	}
	m.unack(nx.AppKey, nx.AppKeySeq)
	c := orphanClear{key: append([]byte(nil), nx.AppKey...), seq: nx.AppKeySeq, hseq: nx.HeaderSeq}
	m.orphans = append(m.orphans, c)
	m.sendOrphan(c)
}

// orphanClear is a confirmed key that no stored header names.
type orphanClear struct {
	key       []byte
	seq, hseq uint64
}

func (m *Manager) sendOrphan(c orphanClear) {
	if m.opt.Lifecycle == nil {
		return
	}
	ev := lifecycle(m.opt, EventAppKeyNextClear, m.hdr.VaultID, m.opt.Release.PCR0)
	ev.AppKey, ev.AppKeySeq, ev.HeaderSeq = append([]byte(nil), c.key...), c.seq, c.hseq
	m.opt.Lifecycle(ev)
}

// resendOrphans sends the clears again once (at the next flush) and forgets
// them.
func (m *Manager) resendOrphans() {
	for _, c := range m.orphans {
		m.sendOrphan(c)
	}
	m.orphans = nil
}

// forgetOrphan drops a pending clear of a key that is confirmed again.
func (m *Manager) forgetOrphan(key []byte, seq uint64) {
	out := m.orphans[:0]
	for _, c := range m.orphans {
		if !(c.seq == seq && bytes.Equal(c.key, key)) {
			out = append(out, c)
		}
	}
	m.orphans = out
}

// promote is step 3, applied in memory after step 2 is stored: `next`
// made current; the next header write stores it.
func (m *Manager) promote() error {
	r := m.repl
	if r == nil {
		return nil
	}
	nx := r.next
	wrap, err := recovery.WrapDEK(r.uk1, r.dek1, m.st.VaultID, nx.DEKVersion)
	if err != nil {
		return err
	}
	if !suite.Equal(m.dek, r.dek1) {
		suite.Wipe(m.dek)
	}
	suite.Wipe(m.unlockKey)
	suite.Wipe(m.unlockSecret)
	m.dek, m.unlockKey, m.unlockSecret = r.dek1, r.uk1, r.secret1
	m.hdr.DEKVersion, m.hdr.KDF, m.hdr.DEKWrap, m.hdr.SecretCheck = nx.DEKVersion, nx.KDF, wrap, nx.SecretCheck
	m.hdr.Rec.Wrap = nx.Wrap
	if nx.Wrap != nil {
		m.hdr.Rec.Generation = nx.Wrap.Generation
	}
	if r.promoteFn != nil {
		r.promoteFn()
	}
	m.hdr.Next = nil
	m.repl = nil
	m.replaced = append(m.replaced, nx.Reason)
	return nil
}

// dropNext abandons a stored `next` part (the old phone unlocked first, a
// transfer ran out, step 1 is written again): with the next header write
// the parent is told to clear app_key_next (§11.14.2).
func (m *Manager) dropNext(_ time.Time) {
	if nx := m.hdr.Next; nx != nil && nx.AppKey != nil {
		m.nextCleared = true
	}
	m.hdr.Next = nil
	if m.repl != nil {
		m.repl.wipe()
		m.repl = nil
	}
	m.dirty = true
}

// replacementPromoteFn is a replacement's own step-3 change: the next app
// key becomes the vault's (a transfer, a recovery), reported as app_key
// after the flush (§11.5).
func (m *Manager) replacementPromoteFn(nx *HeaderNext) func() {
	if nx == nil || nx.AppKey == nil {
		return nil
	}
	key, seq := append([]byte(nil), nx.AppKey...), nx.AppKeySeq
	return func() {
		m.hdr.AppKey, m.hdr.AppKeySeq = key, seq
		m.appKeyChanged = true
	}
}
