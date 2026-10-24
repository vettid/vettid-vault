package parent_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/vettid/vettid-vault/internal/parenttest"
)

// VAULT-MESSAGING 0.29.0 §11.5 (release L): the parent copies a lock's
// answer codes locked, not_running and stale into a lock's slot, and into
// no other operation's.
func TestLockCodesSlots(t *testing.T) {
	h := newHarness(t, nil)
	h.tables.PutVault(parenttest.VaultRow{VaultID: vaultID, UserGUID: "u1", State: "locked"})
	env := bytes.Repeat([]byte{7}, 5252)
	codes := map[string]string{
		"01JAAAAAAAAAAAAAAAAAAAAAAA": "locked", "01JBBBBBBBBBBBBBBBBBBBBBBB": "not_running", "01JCCCCCCCCCCCCCCCCCCCCCCC": "stale",
		"01JDDDDDDDDDDDDDDDDDDDDDDD": "locked",               // on an unlock: not copied
		"01JEEEEEEEEEEEEEEEEEEEEEEE": "recovery_not_current", // another op's code on a lock: not copied
		"01JFFFFFFFFFFFFFFFFFFFFFFF": "",                     // a release before L: no code
		"01JGGGGGGGGGGGGGGGGGGGGGGG": "locked",               // on a delete (no envelope): not copied
		"01JHHHHHHHHHHHHHHHHHHHHHHH": "stale",                // on a recovery_cancel (no envelope): not copied
	}
	e := h.connect("boot-1", func(msg []byte) []byte {
		var m struct {
			RequestID string `json:"request_id"`
		}
		_ = json.Unmarshal(msg, &m)
		if m.RequestID == "01JDDDDDDDDDDDDDDDDDDDDDDD" {
			return cancelAnswer(m.RequestID, env, "locked", "")
		}
		return cancelAnswer(m.RequestID, nil, codes[m.RequestID], "")
	})
	e.descriptor()
	waitFor(t, "ready", func() bool { return h.p.Health().Release == pcr })
	send := func(op, rid string) parenttest.SlotRow {
		t.Helper()
		h.tables.PutSlot(rid, "i-test")
		h.queues.Send(h.queue, queueMsg(op, rid))
		var s parenttest.SlotRow
		waitFor(t, "slot "+rid, func() bool { s, _ = h.tables.Slot(rid); return s.Status != "queued" })
		return s
	}
	for _, rid := range []string{"01JAAAAAAAAAAAAAAAAAAAAAAA", "01JBBBBBBBBBBBBBBBBBBBBBBB", "01JCCCCCCCCCCCCCCCCCCCCCCC"} {
		if s := send("lock", rid); s.Status != "done" || s.Code != codes[rid] || len(s.Envelope) != 0 {
			t.Fatalf("lock %s: %+v", codes[rid], s)
		}
	}
	if s := send("unlock", "01JDDDDDDDDDDDDDDDDDDDDDDD"); s.Code != "" {
		t.Fatalf("locked on an unlock %+v", s)
	}
	if s := send("lock", "01JEEEEEEEEEEEEEEEEEEEEEEE"); s.Status != "done" || s.Code != "" {
		t.Fatalf("another op's code on a lock %+v", s)
	}
	if s := send("lock", "01JFFFFFFFFFFFFFFFFFFFFFFF"); s.Status != "done" || s.Code != "" {
		t.Fatalf("pre-L lock %+v", s)
	}
	if s := send("delete", "01JGGGGGGGGGGGGGGGGGGGGGGG"); s.Code != "" {
		t.Fatalf("locked on a delete %+v", s)
	}
	h.tables.PutSlot("01JHHHHHHHHHHHHHHHHHHHHHHH", "i-test")
	h.queues.Send(h.queue, cancelQueueMsg("recovery_cancel", "01JHHHHHHHHHHHHHHHHHHHHHHH"))
	var cs parenttest.SlotRow
	waitFor(t, "cancel slot", func() bool { cs, _ = h.tables.Slot("01JHHHHHHHHHHHHHHHHHHHHHHH"); return cs.Status != "queued" })
	if cs.Status != "done" || cs.Code != "" {
		t.Fatalf("stale on a recovery_cancel %+v", cs)
	}
}
