//go:build devenclave && e2e

package e2e

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/enclave"
	"github.com/vettid/vettid-vault/internal/enclavetest"
	"github.com/vettid/vettid-vault/vault/store"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// VAULT-MESSAGING 0.51.0 §12.5, VAULT-HOST-PROTOCOL 0.1.14 §5.6, §6.1:
// through the real parent, supervisor and vault processes. The holder's
// deletion is marked on the vault row (MarkDeleting from the vault's
// process) before it is told, and delete_resume runs in a vault process
// (the job on the channel, an empty result, the process stopped).

func (hs *hostStack) resume(hi *hostInstance, vid, guid string) {
	hs.t.Helper()
	rid, _ := envelope.NewULID(time.Now())
	hs.tables.PutSlot(rid, hi.id)
	b, _ := json.Marshal(map[string]any{"v": 1, "op": "delete_resume", "vault_id": vid, "user_guid": guid, "request_id": rid,
		"enqueued_at": time.Now().UTC().Format(time.RFC3339Nano)})
	if !hs.queues.Send(hi.queue, string(b)) {
		hs.t.Fatal("no queue")
	}
	if s := hs.waitSlot(rid); s.Status != "done" || s.Envelope != nil || s.Code != "" {
		hs.t.Fatalf("resume slot %+v", s)
	}
}

func (hs *hostStack) deletedEvents(vid string) int {
	n := 0
	for _, e := range hs.tables.LifecycleEvents(vid) {
		if e == "deleted" {
			n++
		}
	}
	return n
}

func (hs *hostStack) stored(key string) bool {
	_, _, err := hs.objs.Get(context.Background(), key)
	return err == nil
}

func TestDeleteResumeHostStack(t *testing.T) {
	hs := newHostStack(t)
	hi := hs.start("i-resume", 3, 0)
	const vidA, vidB = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1", "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2"
	a := hs.newApp("member-resume-a", 0x51)
	a.enroll(hi, vidA)
	b := hs.newApp("member-resume-b", 0x52)
	b.enroll(hi, vidB)
	objects := func(vid, guid string) []string {
		return []string{store.StateKey(vid), store.HeaderKey(vid, enclavetest.Spec(3, "active").PCR0Hex()), enclave.UserIndexKey(guid)}
	}

	// A running vault: nothing, and it keeps running.
	hs.resume(hi, vidB, b.guid)
	if hi.sup.VaultPid(vidB) == 0 || hs.deletedEvents(vidB) != 0 {
		t.Fatal("the running vault was touched")
	}
	// A live vault that does not run: nothing.
	b.lock(hi)
	waitUntil(t, "B stopped", func() bool { return hi.sup.VaultPid(vidB) == 0 })
	hs.resume(hi, vidB, b.guid)
	for _, k := range objects(vidB, b.guid) {
		if !hs.stored(k) {
			t.Fatalf("%s erased", k)
		}
	}
	if hs.deletedEvents(vidB) != 0 {
		t.Fatal("a live vault reported deleted")
	}

	// The holder's deletion: the row is marked (deleting_at) through the
	// vault's process, then the deletion runs to `deleted`.
	if err := a.dev.VaultDelete(ctxT(t, 60*time.Second), pin, credPW); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "A deleted", func() bool { r, _ := hs.tables.Vault(vidA); return r.State == "deleted" })
	if r, _ := hs.tables.Vault(vidA); r.DeletingAt == 0 {
		t.Fatalf("the row was not marked: %+v", r)
	}
	for _, k := range objects(vidA, a.guid) {
		if hs.stored(k) {
			t.Fatalf("%s left", k)
		}
	}
	// No header and no state: the member index if it still names the
	// vault, and `deleted` again (once the deleting process has ended: a
	// resume never runs beside it).
	waitUntil(t, "A's process ended", func() bool { return hi.sup.VaultPid(vidA) == 0 })
	if _, err := hs.objs.Put(context.Background(), enclave.UserIndexKey(a.guid), []byte(vidA), ""); err != nil {
		t.Fatal(err)
	}
	n := hs.deletedEvents(vidA)
	hs.resume(hi, vidA, a.guid)
	waitUntil(t, "the resume's deleted", func() bool { return hs.deletedEvents(vidA) == n+1 })
	if hs.stored(enclave.UserIndexKey(a.guid)) {
		t.Fatal("the index is left")
	}
}
