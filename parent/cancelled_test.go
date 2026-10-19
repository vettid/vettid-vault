package parent_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/hostproto"
	"github.com/vettid/vettid-vault/internal/parenttest"
	"github.com/vettid/vettid-vault/parent"
)

// VAULT-MESSAGING 0.49.0 §11.5, §11.14.8; VAULT-HOST-PROTOCOL 0.1.13 §6.1,
// §7.2: the parent copies recovery_cancelled with cancelled_recovery_id
// into an unlock's slot only, recovery_not_current (no envelope) into a
// cancel's slot only, and writes a lifecycle event's
// cancelled_recovery_id to the vault row.

const cancelledID = "01JB2Z6V9K3M4N5P6Q7R8S9T32"

func cancelAnswer(rid string, env []byte, code, id string) []byte {
	m := map[string]any{"v": 1, "request_id": rid, "status": "done"}
	if env != nil {
		m["envelope"] = base64.StdEncoding.EncodeToString(env)
	}
	if code != "" {
		m["code"] = code
	}
	if id != "" {
		m["cancelled_recovery_id"] = id
	}
	b, _ := json.Marshal(m)
	return b
}

// lifecycle15 is a fifteen-field lifecycle frame (0.49.0).
func (e *fakeEnclave) lifecycle15(ev, cancelled string) {
	_ = e.conn.Notify(hostproto.KindLifecycle, hostproto.Strings(ev, vaultID, pcr, pcr, "1", "", "0", "", "0", "", "", "", "0", "", cancelled)...)
}

func cancelQueueMsg(op, rid string) string {
	if op == "recovery_cancel" {
		return `{"v":1,"op":"recovery_cancel","vault_id":"` + vaultID + `","user_guid":"u1","request_id":"` + rid +
			`","signed_at":"2026-10-15T12:00:00Z","key_id":"k","sig":"MAA=","recovery_id":"` + cancelledID + `","enqueued_at":"2026-10-02T12:00:00.000Z"}`
	}
	return queueMsg(op, rid)
}

func TestRecoveryCancelledSlots(t *testing.T) {
	h := newHarness(t, nil)
	h.tables.PutVault(parenttest.VaultRow{VaultID: vaultID, UserGUID: "u1", State: "locked"})
	env := bytes.Repeat([]byte{7}, 5252)
	e := h.connect("boot-1", func(msg []byte) []byte {
		var m struct {
			RequestID string `json:"request_id"`
		}
		_ = json.Unmarshal(msg, &m)
		switch m.RequestID {
		case "01JAAAAAAAAAAAAAAAAAAAAAAA": // an unlock that cancelled
			return cancelAnswer(m.RequestID, env, "recovery_cancelled", cancelledID)
		case "01JBBBBBBBBBBBBBBBBBBBBBBB": // a malformed id drops both
			return cancelAnswer(m.RequestID, env, "recovery_cancelled", "not-a-ulid")
		case "01JCCCCCCCCCCCCCCCCCCCCCCC", "01JDDDDDDDDDDDDDDDDDDDDDDD": // the marker on another op
			return cancelAnswer(m.RequestID, env, "recovery_cancelled", cancelledID)
		case "01JEEEEEEEEEEEEEEEEEEEEEEE": // a named cancel that cancelled nothing
			return cancelAnswer(m.RequestID, nil, "recovery_not_current", "")
		case "01JFFFFFFFFFFFFFFFFFFFFFFF", "01JGGGGGGGGGGGGGGGGGGGGGGG": // recovery_not_current on another op
			return cancelAnswer(m.RequestID, nil, "recovery_not_current", "")
		case "01JHHHHHHHHHHHHHHHHHHHHHHH": // with an envelope
			return cancelAnswer(m.RequestID, env, "recovery_not_current", "")
		case "01JJJJJJJJJJJJJJJJJJJJJJJJ": // recovery_cancelled without an envelope
			return cancelAnswer(m.RequestID, nil, "recovery_cancelled", cancelledID)
		}
		return response(m.RequestID, "done", env)
	})
	e.descriptor()
	waitFor(t, "ready", func() bool { return h.p.Health().Release == pcr })
	send := func(op, rid string) parenttest.SlotRow {
		t.Helper()
		h.tables.PutSlot(rid, "i-test")
		h.queues.Send(h.queue, cancelQueueMsg(op, rid))
		var s parenttest.SlotRow
		waitFor(t, "slot "+rid, func() bool { s, _ = h.tables.Slot(rid); return s.Status != "queued" })
		return s
	}
	if s := send("unlock", "01JAAAAAAAAAAAAAAAAAAAAAAA"); s.Status != "done" || s.Code != "recovery_cancelled" || s.CancelledRecoveryID != cancelledID || len(s.Envelope) != 5252 {
		t.Fatalf("unlock slot %+v", s)
	}
	if s := send("unlock", "01JBBBBBBBBBBBBBBBBBBBBBBB"); s.Status != "done" || s.Code != "" || s.CancelledRecoveryID != "" || len(s.Envelope) != 5252 {
		t.Fatalf("malformed id %+v", s)
	}
	if s := send("recovery_register", "01JCCCCCCCCCCCCCCCCCCCCCCC"); s.Code != "" || s.CancelledRecoveryID != "" {
		t.Fatalf("recovery_cancelled on a register %+v", s)
	}
	if s := send("enroll", "01JDDDDDDDDDDDDDDDDDDDDDDD"); s.Code != "" || s.CancelledRecoveryID != "" {
		t.Fatalf("recovery_cancelled on an enroll %+v", s)
	}
	if s := send("recovery_cancel", "01JEEEEEEEEEEEEEEEEEEEEEEE"); s.Status != "done" || s.Code != "recovery_not_current" || len(s.Envelope) != 0 {
		t.Fatalf("cancel slot %+v", s)
	}
	if s := send("unlock", "01JFFFFFFFFFFFFFFFFFFFFFFF"); s.Code != "" {
		t.Fatalf("recovery_not_current on an unlock %+v", s)
	}
	if s := send("lock", "01JGGGGGGGGGGGGGGGGGGGGGGG"); s.Code != "" {
		t.Fatalf("recovery_not_current on a lock %+v", s)
	}
	if s := send("recovery_cancel", "01JHHHHHHHHHHHHHHHHHHHHHHH"); s.Code != "" {
		t.Fatalf("recovery_not_current with an envelope %+v", s)
	}
	if s := send("unlock", "01JJJJJJJJJJJJJJJJJJJJJJJJ"); s.Code != "" || s.CancelledRecoveryID != "" {
		t.Fatalf("recovery_cancelled without an envelope %+v", s)
	}
}

// A lost answer (the parent's call timed out after the enclave stored the
// cancel; the redelivery meets the replay set and gets random bytes and no
// code): the slot shows no cancel, but the unlocked event that came first
// is written to the vault row as recovery_cancelled.
func TestRecoveryCancelledLostAnswerEventWritten(t *testing.T) {
	h := newHarness(t, func(c *parent.Config) { c.RequestTimeout = 300 * time.Millisecond })
	h.tables.PutVault(parenttest.VaultRow{VaultID: vaultID, UserGUID: "u1", State: "locked"})
	env := bytes.Repeat([]byte{7}, 5252)
	var calls atomic.Int64
	var e *fakeEnclave
	e = h.connect("boot-1", func(msg []byte) []byte {
		if calls.Add(1) == 1 {
			e.lifecycle15("unlocked", cancelledID)
			time.Sleep(time.Second) // past the parent's timeout: the answer is lost
			return cancelAnswer("01JAAAAAAAAAAAAAAAAAAAAAAA", env, "recovery_cancelled", cancelledID)
		}
		return response("01JAAAAAAAAAAAAAAAAAAAAAAA", "done", env) // the replay's random bytes
	})
	e.descriptor()
	waitFor(t, "ready", func() bool { return h.p.Health().Release == pcr })
	h.tables.PutSlot("01JAAAAAAAAAAAAAAAAAAAAAAA", "i-test")
	h.queues.Send(h.queue, queueMsg("unlock", "01JAAAAAAAAAAAAAAAAAAAAAAA"))
	waitFor(t, "recovery_cancelled on the vault row", func() bool {
		r, _ := h.tables.Vault(vaultID)
		return r.RecoveryCancelledID == cancelledID && r.RecoveryCancelledAt > 0
	})
	if s, _ := h.tables.Slot("01JAAAAAAAAAAAAAAAAAAAAAAA"); s.Code != "" || s.CancelledRecoveryID != "" {
		t.Fatalf("slot %+v", s)
	}
}

// The vault row's recovery_cancelled is written from unlocked and moved
// in the same update as the event, under the event's lease rule.
func TestRecoveryCancelledRowWrite(t *testing.T) {
	tb := parenttest.NewTables()
	tb.PutVault(parenttest.VaultRow{VaultID: "v1", UserGUID: "u1", State: "locked"})
	ctx, now := context.Background(), time.Unix(1_800_000_000, 0)
	for _, e := range []string{"unlocked", "moved"} {
		tb.PutVault(parenttest.VaultRow{VaultID: "v1", UserGUID: "u1", State: "locked"})
		if err := tb.Lifecycle(ctx, parent.Lifecycle{Event: e, VaultID: "v1", CancelledRecoveryID: cancelledID}, "me", now); err != nil {
			t.Fatal(err)
		}
		if r, _ := tb.Vault("v1"); r.RecoveryCancelledID != cancelledID || r.RecoveryCancelledAt != now.Unix() {
			t.Fatalf("%s: %+v", e, r)
		}
	}
	tb.PutVault(parenttest.VaultRow{VaultID: "v2", UserGUID: "u1", State: "locked", LeaseInstance: "other", LeaseExpires: now.Add(time.Hour).Unix()})
	_ = tb.Lifecycle(ctx, parent.Lifecycle{Event: "unlocked", VaultID: "v2", CancelledRecoveryID: cancelledID}, "me", now)
	if r, _ := tb.Vault("v2"); r.RecoveryCancelledID != "" {
		t.Fatal("written without the lease")
	}
}
