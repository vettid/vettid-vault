package parent

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// listObjects is a bucket with a listing; failList fails that many
// listings first (the sweep retries until the prefix is empty).
type listObjects struct {
	mu       sync.Mutex
	objs     map[string]string // key -> etag
	failList int
	deletes  []string
}

func (o *listObjects) Get(context.Context, string) ([]byte, string, error) {
	return nil, "", ErrNotFound
}
func (o *listObjects) Put(context.Context, string, []byte, string) (string, error) {
	return "", ErrConflict
}
func (o *listObjects) Delete(_ context.Context, key, ifMatch string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	e, ok := o.objs[key]
	if !ok {
		return ErrNotFound
	}
	if e != ifMatch {
		return ErrConflict
	}
	delete(o.objs, key)
	o.deletes = append(o.deletes, key)
	return nil
}
func (o *listObjects) ListObjects(_ context.Context, prefix string) ([]ObjectRef, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.failList > 0 {
		o.failList--
		return nil, ErrConflict
	}
	var out []ObjectRef
	for k, e := range o.objs {
		if strings.HasPrefix(k, prefix) {
			out = append(out, ObjectRef{k, e})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

func (o *listObjects) keys() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	var ks []string
	for k := range o.objs {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// lifeTables answers Lifecycle as the vault row would (marked; refused
// because another instance holds the lease; marked but the notice not
// written), and the sweep's reads of the row.
type lifeTables struct {
	Tables
	result   error
	mu       sync.Mutex
	state    string // the row's state; "" for no row
	pending  []string
	done     []string
	failScan int
}

func (t *lifeTables) Lifecycle(context.Context, Lifecycle, string, time.Time) error { return t.result }
func (t *lifeTables) VaultState(context.Context, string) (string, bool, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.state, t.state != "", nil
}
func (t *lifeTables) PendingSweeps(context.Context) ([]string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.failScan > 0 {
		t.failScan--
		return nil, errors.New("scan")
	}
	return t.pending, nil
}
func (t *lifeTables) SweepDone(_ context.Context, id string, _ time.Time) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.done = append(t.done, id)
	return nil
}

// VAULT-HOST-PROTOCOL 0.1.9 P15: after the parent's own conditional update
// marked a vault's row deleted (whether or not the vault_deleted notice
// was written), it deletes every object under vaults/<vault_id>/att/,
// retrying until the prefix is empty, and nothing else, then removes the
// row's record of the pending sweep; when the update was refused it sweeps
// nothing; a row that is no longer deleted (the vault id enrolled again)
// stops the sweep; sweeps an earlier parent left pending resume at start.
func TestAttachmentSweepAfterDeleted(t *testing.T) {
	const vid = "0123456789abcdef0123456789abcdef"
	for _, c := range []struct {
		name   string
		result error
		state  string
		resume bool
		swept  bool
		fail   int
	}{
		{"marked", nil, "deleted", false, true, 0},
		{"marked, rows gone", nil, "", false, true, 0},
		{"marked, notice not written", errors.Join(ErrAlarmNotWritten, errors.New("ddb")), "deleted", false, true, 0},
		{"lease held elsewhere", ErrNotMarked, "deleted", false, false, 0},
		{"enrolled again", nil, "enrolling", false, false, 0},
		{"resumed after a restart", ErrNotMarked, "deleted", true, true, 0},
		{"resumed after a failed scan", ErrNotMarked, "deleted", true, true, 2},
	} {
		t.Run(c.name, func(t *testing.T) {
			objs := &listObjects{failList: 1, objs: map[string]string{
				"vaults/" + vid + "/att/01jb2z6v9k3m4n5p6q7r8s9t60":   `"1"`,
				"vaults/" + vid + "/att/01jb2z6v9k3m4n5p6q7r8s9t60.t": `"2"`,
				"vaults/" + vid + "/att/01jb2z6v9k3m4n5p6q7r8s9t61":   `"3"`,
				"vaults/" + vid + "/state":                            `"4"`,
				"vaults/" + vid + "x/att/01jb2z6v9k3m4n5p6q7r8s9t60":  `"5"`,
				"vaults/other/att/01jb2z6v9k3m4n5p6q7r8s9t60":         `"6"`,
			}}
			all := objs.keys()
			tb := &lifeTables{result: c.result, state: c.state, failScan: c.fail}
			if c.resume {
				tb.pending = []string{vid}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			p := &Parent{cfg: Config{Objects: objs, Tables: tb, SweepRetry: 10 * time.Millisecond},
				log: slog.New(slog.NewTextHandler(io.Discard, nil)), now: time.Now, running: map[string]*lease{}, taking: map[string]int{},
				events: make(chan func(context.Context), 8), runCtx: ctx}
			go p.eventWorker(ctx)
			if c.resume {
				go p.resumeSweeps(ctx)
			} else {
				p.onLifecycle(Lifecycle{Event: "deleted", VaultID: vid})
			}
			want := all
			if c.swept {
				want = []string{"vaults/" + vid + "/state", "vaults/" + vid + "x/att/01jb2z6v9k3m4n5p6q7r8s9t60", "vaults/other/att/01jb2z6v9k3m4n5p6q7r8s9t60"}
			}
			deadline := time.Now().Add(5 * time.Second)
			for strings.Join(objs.keys(), ",") != strings.Join(want, ",") && time.Now().Before(deadline) {
				time.Sleep(10 * time.Millisecond)
			}
			time.Sleep(100 * time.Millisecond)
			if got := objs.keys(); strings.Join(got, ",") != strings.Join(want, ",") {
				t.Fatalf("left %v", got)
			}
			tb.mu.Lock()
			done := len(tb.done)
			tb.mu.Unlock()
			if c.swept != (done == 1) {
				t.Fatalf("sweep records removed: %d", done)
			}
		})
	}
}
