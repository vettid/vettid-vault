package vault

import (
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
	m.hdr.Next = r.next
	if err := m.writeHeaderWith(ctx, false); err != nil {
		m.hdr.Next = nil
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
		r.wipe()
		return errRetry
	}
	if r.next.AppKey != nil {
		// §11.5: app_key_next with this header write, confirmed by the host
		// before the vault can adopt the key (appkeyconfirm.go). If it is
		// not, nothing is adopted: the part is dropped as for a failed
		// read-back, and the row is told to clear any app_key_next the
		// host did write.
		if err := m.confirmKey(ctx, AppKeyModeNext, r.next.AppKey, r.next.AppKeySeq, r.next.HeaderSeq); err != nil {
			m.hdr.Next = nil
			m.nextCleared = true
			r.wipe()
			return errRetry
		}
		if m.opt.Lifecycle != nil {
			ev := lifecycle(m.opt, EventAppKeyNext, m.hdr.VaultID, m.opt.Release.PCR0)
			ev.AppKey, ev.AppKeySeq, ev.HeaderSeq = append([]byte(nil), r.next.AppKey...), r.next.AppKeySeq, r.next.HeaderSeq
			m.opt.Lifecycle(ev)
		}
	}
	m.repl = r
	m.replInHandler = true
	m.dirty = true
	return nil
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
