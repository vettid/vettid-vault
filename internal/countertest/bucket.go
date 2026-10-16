// Package countertest is a stand-in for the recovery attempt counter's S3
// bucket (versioning, Object Lock in compliance mode, conditional create)
// with the adversary of VAULT-MESSAGING 0.33.0 §11.14.14: a conditional
// create that succeeds over a delete marker (as S3 does), an error for a
// stored write, versions inserted with old dates, deletion of anything
// unlocked, withheld answers, and its own clock (the counter's clock, the
// only recovery clock tests move). TEST ONLY: never linked into a release
// package (check-tcb).
package countertest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vettid/vettid-vault/vault/counter"
)

// Ops, for fault injection.
const (
	OpList         = "list"
	OpPutCreate    = "put_create"
	OpPut          = "put"
	OpGetRetention = "get_retention"
	OpGetVersion   = "get_version"
)

type version struct {
	id           string
	body         []byte
	lastModified time.Time
	deleteMarker bool
	mode         string
	until        time.Time
}

// Bucket is the stand-in. The zero value is not usable; use New.
type Bucket struct {
	mu   sync.Mutex
	now  time.Time
	objs map[string][]*version
	// faults
	down      bool
	failNext  map[string]int
	storeFail map[string]int
	hook      func(op, key string)
	calls     map[string]int
}

// New returns an empty bucket whose clock starts at t0.
func New(t0 time.Time) *Bucket {
	return &Bucket{now: t0.UTC(), objs: map[string][]*version{}, failNext: map[string]int{}, storeFail: map[string]int{}, calls: map[string]int{}}
}

var _ counter.Bucket = (*Bucket)(nil)

// Now is the counter's clock.
func (b *Bucket) Now() time.Time {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.now
}

// Advance moves the counter's clock.
func (b *Bucket) Advance(d time.Duration) {
	b.mu.Lock()
	b.now = b.now.Add(d)
	b.mu.Unlock()
}

// SetDown makes every call fail (the way to S3 cut).
func (b *Bucket) SetDown(down bool) {
	b.mu.Lock()
	b.down = down
	b.mu.Unlock()
}

// FailNext makes the next n calls of op fail with ErrUnknown before
// anything is stored.
func (b *Bucket) FailNext(op string, n int) {
	b.mu.Lock()
	b.failNext[op] = n
	b.mu.Unlock()
}

// StoreThenFail makes the next n writes of op store and then answer
// ErrUnknown (an error for a stored write).
func (b *Bucket) StoreThenFail(op string, n int) {
	b.mu.Lock()
	b.storeFail[op] = n
	b.mu.Unlock()
}

// SetHook runs f (outside the lock) before every call answers: tests hold
// answers back, advance the clock or act as another enclave there.
func (b *Bucket) SetHook(f func(op, key string)) {
	b.mu.Lock()
	b.hook = f
	b.mu.Unlock()
}

// Calls returns how many calls of op were made.
func (b *Bucket) Calls(op string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.calls[op]
}

var errDown = errors.New("countertest: unavailable")

func (b *Bucket) enter(op, key string) error {
	b.mu.Lock()
	h := b.hook
	b.mu.Unlock()
	if h != nil {
		h(op, key)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls[op]++
	if b.down {
		return errDown
	}
	if b.failNext[op] > 0 {
		b.failNext[op]--
		return counter.ErrUnknown
	}
	return nil
}

func newID() string {
	var r [12]byte
	_, _ = rand.Read(r[:])
	return hex.EncodeToString(r[:])
}

// List implements counter.Bucket.
func (b *Bucket) List(_ context.Context, prefix string) (counter.Listing, error) {
	if err := b.enter(OpList, prefix); err != nil {
		return counter.Listing{}, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	l := counter.Listing{Date: b.now}
	keys := make([]string, 0, len(b.objs))
	for k := range b.objs {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range b.objs[k] {
			l.Entries = append(l.Entries, counter.Entry{Key: k, VersionID: v.id, LastModified: v.lastModified, DeleteMarker: v.deleteMarker})
		}
	}
	return l, nil
}

func (b *Bucket) store(key string, body []byte, until time.Time) *version {
	v := &version{id: newID(), body: append([]byte(nil), body...), lastModified: b.now, mode: counter.ModeCompliance, until: until}
	b.objs[key] = append(b.objs[key], v)
	return v
}

func (b *Bucket) storeFails(op string) bool {
	if b.storeFail[op] > 0 {
		b.storeFail[op]--
		return true
	}
	return false
}

// PutCreate implements counter.Bucket with S3's semantics: the condition
// is on the current version only, so it succeeds over a delete marker.
func (b *Bucket) PutCreate(_ context.Context, key string, body []byte, until time.Time) (int, string, error) {
	if err := b.enter(OpPutCreate, key); err != nil {
		return 0, "", err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if !until.After(b.now) {
		return 0, "", counter.ErrUnknown // S3 refuses a retain-until date in the past (400)
	}
	if vs := b.objs[key]; len(vs) > 0 && !vs[len(vs)-1].deleteMarker {
		return counter.PutPrecondition, "", nil
	}
	v := b.store(key, body, until)
	if b.storeFails(OpPutCreate) {
		return 0, "", counter.ErrUnknown
	}
	return counter.PutOK, v.id, nil
}

// Put implements counter.Bucket.
func (b *Bucket) Put(_ context.Context, key string, body []byte, until time.Time) (string, error) {
	if err := b.enter(OpPut, key); err != nil {
		return "", err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if !until.After(b.now) {
		return "", counter.ErrUnknown
	}
	v := b.store(key, body, until)
	if b.storeFails(OpPut) {
		return "", counter.ErrUnknown
	}
	return v.id, nil
}

func (b *Bucket) find(key, id string) *version {
	for _, v := range b.objs[key] {
		if v.id == id {
			return v
		}
	}
	return nil
}

// GetRetention implements counter.Bucket.
func (b *Bucket) GetRetention(_ context.Context, key, id string) (counter.Retention, error) {
	if err := b.enter(OpGetRetention, key); err != nil {
		return counter.Retention{}, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	v := b.find(key, id)
	if v == nil || v.deleteMarker {
		return counter.Retention{}, counter.ErrUnknown
	}
	return counter.Retention{Mode: v.mode, Until: v.until}, nil
}

// GetVersion implements counter.Bucket.
func (b *Bucket) GetVersion(_ context.Context, key, id string) ([]byte, error) {
	if err := b.enter(OpGetVersion, key); err != nil {
		return nil, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	v := b.find(key, id)
	if v == nil || v.deleteMarker {
		return nil, counter.ErrUnknown
	}
	return append([]byte(nil), v.body...), nil
}

// --- the adversary: what the instance role or VettID can do directly ---

// AddDeleteMarker puts a delete marker on key (allowed: it removes no
// version).
func (b *Bucket) AddDeleteMarker(key string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.objs[key] = append(b.objs[key], &version{id: newID(), lastModified: b.now, deleteMarker: true})
}

// InsertVersion adds a version of key with a LastModified of the caller's
// choosing (a multipart upload or a replica can carry an old time).
func (b *Bucket) InsertVersion(key string, lastModified time.Time, until time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.objs[key] = append(b.objs[key], &version{id: newID(), lastModified: lastModified, mode: counter.ModeCompliance, until: until})
}

// DeleteUnlocked removes every version of every key under prefix whose
// lock has ended, and every delete marker (what no permission can do to a
// locked version).
func (b *Bucket) DeleteUnlocked(prefix string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := 0
	for k, vs := range b.objs {
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		kept := vs[:0]
		for _, v := range vs {
			if v.deleteMarker || !v.until.After(b.now) {
				n++
				continue
			}
			kept = append(kept, v)
		}
		if len(kept) == 0 {
			delete(b.objs, k)
		} else {
			b.objs[k] = kept
		}
	}
	return n
}

// Keys returns every key under prefix (tests).
func (b *Bucket) Keys(prefix string) []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []string
	for k := range b.objs {
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}
