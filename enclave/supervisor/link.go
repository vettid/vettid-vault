package supervisor

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/vettid/vettid-vault/enclave/awskms"
	"github.com/vettid/vettid-vault/internal/hostproto"
	"github.com/vettid/vettid-vault/vault/store"
)

// link is the current control connection to the parent. Calls made while
// it is down fail at once.
type link struct {
	mu   sync.Mutex
	conn *hostproto.Conn
	// downSince is when the connection was lost (zero while up).
	downSince time.Time
}

var errDown = errors.New("supervisor: parent connection down")

func (l *link) set(c *hostproto.Conn, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.conn = c
	if c == nil {
		if l.downSince.IsZero() {
			l.downSince = now
		}
	} else {
		l.downSince = time.Time{}
	}
}

func (l *link) get() *hostproto.Conn {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.conn
}

func (l *link) down() time.Time {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.downSince
}

// callTimeout bounds one request to the parent.
const callTimeout = 60 * time.Second

func (l *link) call(ctx context.Context, k hostproto.Kind, fields ...[]byte) ([][]byte, error) {
	c := l.get()
	if c == nil {
		return nil, errDown
	}
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	return c.Call(ctx, k, fields...)
}

func (l *link) notify(k hostproto.Kind, fields ...[]byte) {
	if c := l.get(); c != nil {
		_ = c.Notify(k, fields...)
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
