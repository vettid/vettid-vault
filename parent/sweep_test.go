package parent

import (
	"context"
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

func (o *listObjects) Get(context.Context, string) ([]byte, string, error) { return nil, "", ErrNotFound }
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

// lifeTables answers Lifecycle as the vault row would: marked, or refused
// because another instance holds the lease.
type lifeTables struct {
	Tables
	held bool
}

func (t lifeTables) Lifecycle(context.Context, Lifecycle, string, time.Time) error {
	if t.held {
		return ErrNotMarked
	}
	return nil
}

// VAULT-HOST-PROTOCOL 0.1.9 P15: after the parent's own conditional update
// marked a vault's row deleted, it deletes every object under
// vaults/<vault_id>/att/ (retrying until the prefix is empty), and nothing
// else; when the update was refused (another instance holds the lease) it
// sweeps nothing.
func TestAttachmentSweepAfterDeleted(t *testing.T) {
	const vid = "0123456789abcdef0123456789abcdef"
	for _, held := range []bool{false, true} {
		objs := &listObjects{failList: 1, objs: map[string]string{
			"vaults/" + vid + "/att/01jb2z6v9k3m4n5p6q7r8s9t60":   `"1"`,
			"vaults/" + vid + "/att/01jb2z6v9k3m4n5p6q7r8s9t60.t": `"2"`,
			"vaults/" + vid + "/att/01jb2z6v9k3m4n5p6q7r8s9t61":   `"3"`,
			"vaults/" + vid + "/state":                            `"4"`,
			"vaults/" + vid + "x/att/01jb2z6v9k3m4n5p6q7r8s9t60":  `"5"`,
			"vaults/other/att/01jb2z6v9k3m4n5p6q7r8s9t60":         `"6"`,
		}}
		ctx, cancel := context.WithCancel(context.Background())
		p := &Parent{cfg: Config{Objects: objs, Tables: lifeTables{held: held}, SweepRetry: 10 * time.Millisecond},
			log: slog.New(slog.NewTextHandler(io.Discard, nil)), now: time.Now, running: map[string]*lease{}, taking: map[string]int{},
			events: make(chan func(context.Context), 8), runCtx: ctx}
		go p.eventWorker(ctx)
		p.onLifecycle(Lifecycle{Event: "deleted", VaultID: vid})
		want := []string{"vaults/" + vid + "/state", "vaults/" + vid + "x/att/01jb2z6v9k3m4n5p6q7r8s9t60", "vaults/other/att/01jb2z6v9k3m4n5p6q7r8s9t60"}
		if held {
			want = nil
			for k := range objs.objs {
				want = append(want, k)
			}
			sort.Strings(want)
		}
		deadline := time.Now().Add(5 * time.Second)
		for strings.Join(objs.keys(), ",") != strings.Join(want, ",") && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		time.Sleep(50 * time.Millisecond)
		if got := objs.keys(); strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("held=%v: left %v", held, got)
		}
		cancel()
	}
}
