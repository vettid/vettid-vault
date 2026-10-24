package vault

import (
	"bytes"
	"context"
	"errors"
	"time"
)

// The host's record of the vault's app key is how the account side knows
// which phone key the vault adopted (the vault row's app_key and
// app_key_next, VAULT-MESSAGING §11.5). Before any header is written that
// names a key the stored header does not, the host must confirm that the
// row names that key as app_key_next (an acknowledged request, retried);
// without the confirmation the header is not written and the operation
// fails as any failed header or state write does. So a crash, a lost
// report or a parent restart can leave the row behind the vault by a
// report, never without the key the vault adopted.

// AppKeyConfirm is the host request of ConfirmAppKey.
type AppKeyConfirm struct {
	VaultID string
	// Mode is "next" (the row gets app_key_next = Key, unless its app_key
	// already is Key) or "enroll" (the vault's first header: the row gets
	// app_key = Key, as the enrolled report will).
	Mode string
	// Key (SPKI DER) and Seq are the key and its change count; HeaderSeq
	// is the header_seq of the write that will carry it.
	Key       []byte
	Seq       uint64
	HeaderSeq uint64
}

// Confirm modes.
const (
	AppKeyModeNext   = "next"
	AppKeyModeEnroll = "enroll"
)

// ErrAppKeyRefused is the host's definite refusal of an AppKeyConfirm (the
// row names another key at that seq or higher, or is gone): not retried.
var ErrAppKeyRefused = errors.New("vault: the host refused the app key")

// errNoConfirmAppKey: Options.ConfirmAppKey is not set.
var errNoConfirmAppKey = errors.New("vault: no ConfirmAppKey")

// NoHostAppKey is Options.ConfirmAppKey for a vault that has no host
// (development, tests): it confirms at once. Without any ConfirmAppKey a
// header that adopts a key is never written (fail closed).
func NoHostAppKey(context.Context, AppKeyConfirm) error { return nil }

// AppKeyRetry overrides the confirmation's retry schedule (tests); a zero
// field keeps its default.
type AppKeyRetry struct {
	Budget, First, Cap time.Duration
}

const (
	// appKeyConfirmFor is the whole wait for one confirmation. A phone
	// waits 30 s for an answer, and a recovery open spends the unlock-key
	// derivation and a status read of up to 10 s (completionStatusTimeout)
	// before its flush, so the confirmation gets 10 s: an open that
	// cannot be confirmed is answered `retry` in time for the phone to try
	// again, not after it gave up.
	appKeyConfirmFor   = 10 * time.Second
	appKeyConfirmFirst = 500 * time.Millisecond
	appKeyConfirmCap   = 2 * time.Second
)

// appKeyToConfirm is the app key the next header write would adopt: the
// key a replacement's step 3 promotes, or else the header's own (set by a
// transfer, a recovery or an enrollment); nil if none.
func (m *Manager) appKeyToConfirm() (key []byte, seq, headerSeq uint64) {
	if r := m.repl; r != nil && r.promoteFn != nil && r.next != nil && len(r.next.AppKey) > 0 {
		return r.next.AppKey, r.next.AppKeySeq, r.next.HeaderSeq
	}
	if len(m.hdr.AppKey) > 0 {
		return m.hdr.AppKey, m.hdr.AppKeySeq, m.hdr.HeaderSeq + 1
	}
	return nil, 0, 0
}

// ackedAppKey reports whether the header already stored names key (loaded
// with it, or confirmed by the host).
func (m *Manager) ackedAppKey(key []byte, seq uint64) bool {
	if len(m.pinned.key) > 0 && m.pinned.seq == seq && bytes.Equal(m.pinned.key, key) {
		return true
	}
	for _, a := range m.acked {
		if a.seq == seq && bytes.Equal(a.key, key) {
			return true
		}
	}
	return false
}

// ackedKey is an app key the stored header names or the host confirmed.
type ackedKey struct {
	key []byte
	seq uint64
}

// unack forgets that key was confirmed.
func (m *Manager) unack(key []byte, seq uint64) {
	out := m.acked[:0]
	for _, a := range m.acked {
		if !(a.seq == seq && bytes.Equal(a.key, key)) {
			out = append(out, a)
		}
	}
	m.acked = out
}

// pin makes key the header's own: the key the stored header names is never
// forgotten, whatever abandoned replacements were confirmed since.
func (m *Manager) pin(key []byte, seq uint64) {
	m.pinned = ackedKey{append([]byte(nil), key...), seq}
}

// ack records key as named; the last few are kept (a replacement confirms
// its next key while the header still names the current one).
func (m *Manager) ack(key []byte, seq uint64) {
	if m.ackedAppKey(key, seq) {
		return
	}
	m.acked = append(m.acked, ackedKey{append([]byte(nil), key...), seq})
	if len(m.acked) > 4 {
		m.acked = m.acked[1:]
	}
}

// confirmAppKey makes sure the host's row names the app key the next
// header write adopts, if it is one the stored header does not name. It
// runs before the state is written (persist) and again before the header
// is (writeHeaderWith); the second is a no-op after the first.
func (m *Manager) confirmAppKey(ctx context.Context) error {
	key, seq, hseq := m.appKeyToConfirm()
	if len(key) == 0 || m.ackedAppKey(key, seq) {
		return nil
	}
	mode := AppKeyModeNext
	if m.enrolling {
		mode = AppKeyModeEnroll
	}
	return m.confirmKey(ctx, mode, key, seq, hseq)
}

// confirmKey asks the host to confirm key, retrying with backoff.
func (m *Manager) confirmKey(ctx context.Context, mode string, key []byte, seq, hseq uint64) error {
	if m.opt.ConfirmAppKey == nil {
		return errNoConfirmAppKey
	}
	r := AppKeyRetry{Budget: appKeyConfirmFor, First: appKeyConfirmFirst, Cap: appKeyConfirmCap}
	if o := m.opt.AppKeyRetry; o != nil {
		for _, f := range []struct{ to, from *time.Duration }{{&r.Budget, &o.Budget}, {&r.First, &o.First}, {&r.Cap, &o.Cap}} {
			if *f.from != 0 {
				*f.to = *f.from
			}
		}
	}
	req := AppKeyConfirm{VaultID: m.hdr.VaultID, Mode: mode, Key: append([]byte(nil), key...), Seq: seq, HeaderSeq: hseq}
	var refused error
	err := retryFor(ctx, r.Budget, r.First, r.Cap, func(c context.Context) error {
		err := m.opt.ConfirmAppKey(c, req)
		if errors.Is(err, ErrAppKeyRefused) {
			refused = err // definite: not retried
			return nil
		}
		return err
	})
	if err == nil {
		err = refused
	}
	if err != nil {
		return err
	}
	m.ack(key, seq)
	m.enrolling = false
	return nil
}
