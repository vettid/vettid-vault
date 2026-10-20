package enclave_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/client"
	"github.com/vettid/vettid-vault/enclave"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vault/store"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// VAULT-MESSAGING 0.51.0 §12.5 "Without the app: the resume",
// VAULT-HOST-PROTOCOL 0.1.14 §6.1, P20: the queue op delete_resume, row by
// row of its table; it is never an authority to delete.

func (f *fx) resume(vid, guid string) {
	f.t.Helper()
	rid, _ := envelope.NewULID(f.clk.Now())
	q := &enclave.QueueMessage{Op: enclave.OpDeleteResume, VaultID: vid, UserGUID: guid, RequestID: rid, EnqueuedAt: f.clk.Now()}
	resp := f.w.Instance(3).Process(f.ctx, q, nil)
	if resp.Status != enclave.StatusDone || resp.Envelope != nil || resp.Code != "" || resp.RequestID != rid {
		f.t.Fatalf("answer %+v", resp)
	}
}

func (f *fx) deletedReports(vid string) int {
	n := 0
	for _, ev := range f.w.Events() {
		if ev.Event == "deleted" && ev.VaultID == vid {
			n++
		}
	}
	return n
}

func (f *fx) stored(key string) bool {
	f.t.Helper()
	_, _, err := f.w.Store.Get(f.ctx, key)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		f.t.Fatal(err)
	}
	return err == nil
}

// objects are a vault's state, its header sealed to r3 and its member's
// index object.
func (f *fx) objects(a *app) []string {
	return []string{store.StateKey(a.vid), store.HeaderKey(a.vid, r3.PCR0Hex()), enclave.UserIndexKey(a.guid)}
}

func (f *fx) allThere(a *app) {
	f.t.Helper()
	for _, k := range f.objects(a) {
		if !f.stored(k) {
			f.t.Fatalf("%s erased", k)
		}
	}
}

func waitStopped(t *testing.T, in *enclave.Instance, vid string) {
	t.Helper()
	for end := time.Now().Add(5 * time.Second); slices.Contains(in.Vaults(), vid); {
		if time.Now().After(end) {
			t.Fatal("the vault still runs")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestDeleteResume(t *testing.T) {
	t.Run("a process for the vault runs", func(t *testing.T) {
		f := newFx(t)
		a := f.newApp("user-run", android(0x61))
		f.enroll(a, pin)
		f.resume(a.vid, a.guid)
		if f.w.Instance(3).Manager(a.vid) == nil {
			t.Fatal("the running vault was touched")
		}
		f.allThere(a)
		if f.deletedReports(a.vid) != 0 {
			t.Fatal("reported deleted")
		}
	})
	t.Run("the header records no deletion", func(t *testing.T) {
		f := newFx(t)
		a := f.newApp("user-live", android(0x62))
		f.enroll(a, pin)
		f.lock(a)
		// A forged resume (the host writes deleting_at and sends it).
		f.resume(a.vid, a.guid)
		f.allThere(a)
		if f.deletedReports(a.vid) != 0 {
			t.Fatal("reported deleted")
		}
		if r := f.mustUnlock(a, pin, client.UnlockOptions{}, ""); !r.OK {
			t.Fatalf("the live vault no longer opens: %+v", r)
		}
	})
	t.Run("the header records deleting", func(t *testing.T) {
		f := newFx(t)
		// A deletion whose host mark got no ok: the vault ends locked,
		// marked, with nothing erased.
		f.w.VaultOptions.MarkDeleting = func(context.Context, string) error { return errors.New("parent: error") }
		f.w.VaultOptions.DeleteRetry = &vault.DeleteRetry{First: time.Millisecond, Cap: time.Millisecond, Mark: 20 * time.Millisecond}
		if _, err := f.w.Start(3); err != nil {
			t.Fatal(err)
		}
		a := f.newApp("user-del", android(0x63))
		f.enroll(a, pin)
		in := f.w.Instance(3)
		if err := in.Manager(a.vid).Delete(f.ctx); !errors.Is(err, vault.ErrNotMarked) {
			t.Fatalf("delete: %v", err)
		}
		waitStopped(t, in, a.vid)
		f.allThere(a)
		f.resume(a.vid, a.guid)
		for _, k := range f.objects(a) {
			if f.stored(k) {
				t.Fatalf("%s left", k)
			}
		}
		if f.deletedReports(a.vid) != 1 {
			t.Fatalf("%d deleted reports", f.deletedReports(a.vid))
		}
		// No header and no state now: the rest of step 4 (an index that
		// still names the vault), and `deleted` again.
		if _, err := f.w.Store.Put(f.ctx, enclave.UserIndexKey(a.guid), []byte(a.vid), ""); err != nil {
			t.Fatal(err)
		}
		f.resume(a.vid, a.guid)
		if f.stored(enclave.UserIndexKey(a.guid)) || f.deletedReports(a.vid) != 2 {
			t.Fatalf("index left or %d reports", f.deletedReports(a.vid))
		}
	})
	t.Run("no header, but a state", func(t *testing.T) {
		f := newFx(t)
		a := f.newApp("user-other", android(0x64))
		f.enroll(a, pin)
		f.lock(a)
		hk := store.HeaderKey(a.vid, r3.PCR0Hex())
		_, v, _ := f.w.Store.Get(f.ctx, hk)
		if err := f.w.Store.Delete(f.ctx, hk, v); err != nil {
			t.Fatal(err)
		}
		f.resume(a.vid, a.guid)
		if !f.stored(store.StateKey(a.vid)) || !f.stored(enclave.UserIndexKey(a.guid)) || f.deletedReports(a.vid) != 0 {
			t.Fatal("a vault that may live under another release was erased")
		}
	})
	t.Run("a header it cannot read", func(t *testing.T) {
		f := newFx(t)
		a := f.newApp("user-garbled", android(0x65))
		f.enroll(a, pin)
		f.lock(a)
		hk := store.HeaderKey(a.vid, r3.PCR0Hex())
		_, v, _ := f.w.Store.Get(f.ctx, hk)
		if _, err := f.w.Store.Put(f.ctx, hk, []byte("deleting"), v); err != nil {
			t.Fatal(err)
		}
		f.resume(a.vid, a.guid)
		f.allThere(a)
		if f.deletedReports(a.vid) != 0 {
			t.Fatal("reported deleted")
		}
	})
}

// A delete_resume parses without an envelope and not with one.
func TestDeleteResumeWire(t *testing.T) {
	rid, _ := envelope.NewULID(time.Now())
	q := &enclave.QueueMessage{Op: enclave.OpDeleteResume, VaultID: "0123456789abcdef0123456789abcdef", UserGUID: "u1", RequestID: rid,
		EnqueuedAt: time.Now()}
	b := q.Marshal()
	p, err := enclave.ParseQueueMessage(b)
	if err != nil || p.Op != enclave.OpDeleteResume || p.Envelope != nil {
		t.Fatalf("%v %+v", err, p)
	}
	withEnv := append(b[:len(b)-1:len(b)-1], []byte(`,"etk_kid":"0011223344556677","envelope":"AAAA"}`)...)
	if _, err := enclave.ParseQueueMessage(withEnv); err == nil {
		t.Fatal("a delete_resume with an envelope parsed")
	}
}

// The host's delete of a running vault whose host mark gets no ok: the
// vault ends locked without telling its devices, and the instance erases
// what is left without the DEK (the host's authority is unconditional;
// that erase sends nothing).
func TestHostDeleteAfterRefusedMark(t *testing.T) {
	f := newFx(t)
	f.w.VaultOptions.MarkDeleting = func(context.Context, string) error { return errors.New("parent: error") }
	f.w.VaultOptions.DeleteRetry = &vault.DeleteRetry{First: time.Millisecond, Cap: time.Millisecond, Mark: 20 * time.Millisecond}
	if _, err := f.w.Start(3); err != nil {
		t.Fatal(err)
	}
	a := f.newApp("user-hostdel", android(0x66))
	f.enroll(a, pin)
	told := len(f.w.Relays.DepositsTo(a.dev.RelayAddr().Mailbox))
	rid, _ := envelope.NewULID(f.clk.Now())
	in := f.w.Instance(3)
	in.Process(f.ctx, &enclave.QueueMessage{Op: enclave.OpDelete, VaultID: a.vid, UserGUID: a.guid, RequestID: rid, EnqueuedAt: f.clk.Now()}, nil)
	for _, k := range f.objects(a) {
		if f.stored(k) {
			t.Fatalf("%s left", k)
		}
	}
	if f.deletedReports(a.vid) != 1 {
		t.Fatalf("%d deleted reports", f.deletedReports(a.vid))
	}
	if got := len(f.w.Relays.DepositsTo(a.dev.RelayAddr().Mailbox)); got != told {
		t.Fatalf("%d notices without the host's mark", got-told)
	}
}

// LocalHost: a resume's open neither runs beside nor locks a running vault.
func TestLocalHostResumeLocksNothing(t *testing.T) {
	f := newFx(t)
	a := f.newApp("user-localresume", android(0x67))
	f.enroll(a, pin)
	in := f.w.Instance(3)
	// Past the instance's own check: straight to the host, as a resume
	// that raced with the vault's open would be.
	h := enclave.HostOf(in)
	res, _, err := h.Open(f.ctx, &enclave.Job{Op: enclave.OpDeleteResume, VaultID: a.vid, UserGUID: a.guid})
	if res != nil || err != nil || in.Manager(a.vid) == nil {
		t.Fatal("the running vault was touched")
	}
	f.allThere(a)
}
