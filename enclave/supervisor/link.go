package supervisor

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vettid/vettid-vault/enclave/awskms"
	"github.com/vettid/vettid-vault/internal/hostproto"
	"github.com/vettid/vettid-vault/vault/store"
)

// link is the current control connection to the parent. Calls made while
// it is down fail at once.
//
// It also keeps the one clock of the "parent unreachable" rule (§12.3):
// how long the parent has been silent. Only the parent's Ping stops it. A
// connection alone does not: a parent that is connected and silent is as
// unreachable as one that is gone, and a parent cannot keep vaults
// unlocked by dialling again and again. A Ping proves that whoever holds
// the other end of the socket is alive, and nothing more: that the leases
// are renewed cannot be checked from here.
type link struct {
	mu   sync.Mutex
	conn *hostproto.Conn
	// heard is when the parent was last heard: its last Ping, or, if
	// later, the last time no vault was running (Supervisor.checkParent).
	heard time.Time
	// The time since heard in which the supervisor itself was not reading
	// the connection (its reader waiting at the request limit): waited,
	// plus the time since waitSince if that is set. A Ping the parent sent
	// in that time is still unread, so that time is not the parent's
	// silence.
	waited    time.Duration
	waitSince time.Time
	// logDropped counts the log records that were not sent because the
	// parent was not reading.
	logDropped atomic.Uint64
}

var errDown = errors.New("supervisor: parent connection down")

func (l *link) set(c *hostproto.Conn) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.conn = c
}

func (l *link) get() *hostproto.Conn {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.conn
}

// hear notes that the parent was heard now.
func (l *link) hear(now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.heard, l.waited = now, 0
	if !l.waitSince.IsZero() {
		l.waitSince = now
	}
}

// waiting notes that the connection's reader starts or stops waiting at
// the request limit (hostproto.Options.OnWait).
func (l *link) waiting(now time.Time, on bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.waitSince.IsZero() {
		l.waited += now.Sub(l.waitSince)
		l.waitSince = time.Time{}
	}
	if on {
		l.waitSince = now
	}
}

// silent returns for how long the parent has not been heard. Time in which
// the supervisor was not reading is left out, but never more than most of
// it: whatever holds the reader, the silence is counted in the end.
func (l *link) silent(now time.Time, most time.Duration) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	w := l.waited
	if !l.waitSince.IsZero() {
		w += now.Sub(l.waitSince)
	}
	return now.Sub(l.heard) - min(w, most)
}

// callTimeout bounds one request to the parent.
const callTimeout = 60 * time.Second

// writeTimeout bounds the writing of one frame to the parent: a parent
// that has stopped reading loses the connection instead of holding every
// sender. As long as a call may take, so that a parent that is only slow
// (its reader waits while it handles 128 store requests, or while its
// table writes are behind) is not cut off before the calls it is slow
// with have failed anyway.
const writeTimeout = callTimeout

func (l *link) call(ctx context.Context, k hostproto.Kind, fields ...[]byte) ([][]byte, error) {
	c := l.get()
	if c == nil {
		return nil, errDown
	}
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	return c.Call(ctx, k, fields...)
}

// notify sends a notification the parent acts on (a lifecycle event, a
// stopped vault, a descriptor). It is never dropped while the connection
// lives: when the outgoing queue is full it waits, for writeTimeout at
// most, after which the connection has either moved or ended.
func (l *link) notify(k hostproto.Kind, fields ...[]byte) {
	if c := l.get(); c != nil {
		_ = c.Notify(k, fields...)
	}
}

// logRecord sends a log record if the connection takes it at once and
// drops it otherwise: logging never waits for the parent. Dropped records
// are counted (Supervisor.reportDropped).
func (l *link) logRecord(fields ...[]byte) {
	if c := l.get(); c != nil && errors.Is(c.TryNotify(hostproto.KindLog, fields...), hostproto.ErrFull) {
		l.logDropped.Add(1)
	}
}

// hostStore is the vault object store through the parent (S3 with
// create-only and version-matched writes). The parent sees only keys,
// versions and ciphertext.
type hostStore struct {
	l *link
	// onWrite is told about every successful state write (activity for
	// memory-pressure eviction).
	onWrite func(key string)
}

var _ store.Store = (*hostStore)(nil)

var errHost = errors.New("supervisor: store request failed")

func status(r [][]byte) string {
	if len(r) == 0 {
		return ""
	}
	return string(r[0])
}

func validVersion(v []byte) bool { return len(v) > 0 && len(v) <= 256 }

// Get implements store.Store.
func (h *hostStore) Get(ctx context.Context, key string) ([]byte, store.Version, error) {
	if !store.ValidKey(key) {
		return nil, "", store.ErrKey
	}
	r, err := h.l.call(ctx, hostproto.KindStoreGet, []byte(key))
	if err != nil {
		return nil, "", errHost
	}
	switch status(r) {
	case hostproto.StatusOK:
		if len(r) != 3 || !validVersion(r[2]) {
			return nil, "", errHost
		}
		return append([]byte(nil), r[1]...), store.Version(r[2]), nil
	case hostproto.StatusNotFound:
		return nil, "", store.ErrNotFound
	}
	return nil, "", errHost
}

// Put implements store.Store. A conditional write is never abandoned
// half way: cancelling it (a vault being locked mid-batch) would leave its
// outcome unknown, and the vault's next write would then conflict with its
// own and be taken for a split brain. It runs to completion (bounded by
// callTimeout) whatever ctx does.
func (h *hostStore) Put(ctx context.Context, key string, data []byte, ifMatch store.Version) (store.Version, error) {
	if !store.ValidKey(key) {
		return "", store.ErrKey
	}
	r, err := h.l.call(context.WithoutCancel(ctx), hostproto.KindStorePut, []byte(key), data, []byte(ifMatch))
	if err != nil {
		return "", errHost
	}
	switch status(r) {
	case hostproto.StatusOK:
		if len(r) != 2 || !validVersion(r[1]) {
			return "", errHost
		}
		if h.onWrite != nil {
			h.onWrite(key)
		}
		return store.Version(r[1]), nil
	case hostproto.StatusConflict:
		return "", store.ErrConflict
	}
	return "", errHost
}

// Delete implements store.Store.
func (h *hostStore) Delete(ctx context.Context, key string, ifMatch store.Version) error {
	if !store.ValidKey(key) {
		return store.ErrKey
	}
	r, err := h.l.call(context.WithoutCancel(ctx), hostproto.KindStoreDelete, []byte(key), []byte(ifMatch)) // see Put
	if err != nil {
		return errHost
	}
	switch status(r) {
	case hostproto.StatusOK:
		return nil
	case hostproto.StatusNotFound:
		return store.ErrNotFound
	case hostproto.StatusConflict:
		return store.ErrConflict
	}
	return errHost
}

// vaultOfStateKey returns the vault id of a state key.
func vaultOfStateKey(key string) (string, bool) {
	rest, ok := strings.CutPrefix(key, "vaults/")
	if !ok {
		return "", false
	}
	id, ok := strings.CutSuffix(rest, "/state")
	if !ok || id == "" || strings.Contains(id, "/") {
		return "", false
	}
	return id, true
}

// hostCredentials fetches the host role's temporary credentials from the
// parent (for SigV4; they authorize KMS calls but cannot alter KMS
// responses, §11.10.7).
func (l *link) credentials(ctx context.Context) (awskms.Credentials, error) {
	r, err := l.call(ctx, hostproto.KindCredentials)
	if err != nil || status(r) != hostproto.StatusOK || len(r) != 5 {
		return awskms.Credentials{}, awskms.ErrNoCreds
	}
	c := awskms.Credentials{AccessKeyID: string(r[1]), SecretAccessKey: string(r[2]), SessionToken: string(r[3])}
	if len(r[4]) > 0 {
		t, err := time.Parse(time.RFC3339, string(r[4]))
		if err != nil {
			return awskms.Credentials{}, awskms.ErrNoCreds
		}
		c.Expires = t
	}
	return c, nil
}
