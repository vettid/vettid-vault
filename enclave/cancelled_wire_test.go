package enclave

import (
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vault"
)

// VAULT-MESSAGING 0.49.0 §11.5, §11.14.8; VAULT-HOST-PROTOCOL 0.1.13: the
// unlock's recovery_cancelled marker with cancelled_recovery_id, a named
// cancel's recovery_id and its recovery_not_current answer, and the
// lifecycle frame's fifteenth field.

const wireRecID = "01JB2Z6V9K3M4N5P6Q7R8S9T32"

func TestQueueCancelRecoveryID(t *testing.T) {
	base := QueueMessage{Op: OpRecoveryCancel, VaultID: "v1", UserGUID: "u1", RequestID: "01JB2Z6V9K3M4N5P6Q7R8S9T21", EnqueuedAt: time.Unix(1700000000, 0),
		SignedAt: "2026-10-15T12:00:00Z", KeyID: "test-key-1", Sig: []byte{0x30, 1, 2}}
	named := base
	named.RecoveryID = wireRecID
	q, err := ParseQueueMessage(named.Marshal())
	if err != nil || q.RecoveryID != wireRecID {
		t.Fatalf("named cancel: %v %+v", err, q)
	}
	if q, err := ParseQueueMessage(base.Marshal()); err != nil || q.RecoveryID != "" {
		t.Fatalf("seven-line cancel: %v %+v", err, q)
	}
	s := string(named.Marshal())
	for name, b := range map[string]string{
		"not a ULID": strings.Replace(s, wireRecID, "not-a-ulid", 1),
		"lower case": strings.Replace(s, wireRecID, strings.ToLower(wireRecID), 1),
		"on a recovery": strings.Replace(strings.Replace(s, `"op":"recovery_cancel"`, `"op":"recovery"`, 1), `"signed_at"`,
			`"browser_key":"BAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","signed_at"`, 1),
	} {
		if _, err := ParseQueueMessage([]byte(b)); err == nil {
			t.Errorf("%s accepted: %s", name, b)
		}
	}
	lock := `{"v":1,"op":"lock","vault_id":"v1","user_guid":"u1","request_id":"01JB2Z6V9K3M4N5P6Q7R8S9T21","recovery_id":"` + wireRecID + `","enqueued_at":"2023-11-14T22:13:20Z"}`
	if _, err := ParseQueueMessage([]byte(lock)); err == nil {
		t.Error("recovery_id on a lock accepted")
	}
}

func TestMarkerRecoveryCancelled(t *testing.T) {
	m := Marker{Code: CodeRecoveryCancelled, CancelledRecoveryID: wireRecID}
	got, ok := DecodeMarker(OpUnlock, m.Encode())
	if !ok || got != m {
		t.Fatalf("unlock marker: %+v %v", got, ok)
	}
	for _, op := range []string{OpEnroll, OpRecovery, OpRecoveryOpen, OpRecoveryRegister, OpRecoveryCancel} {
		if _, ok := DecodeMarker(op, m.Encode()); ok {
			t.Errorf("recovery_cancelled passed for %s", op)
		}
	}
	for name, b := range map[string]string{
		"no id":             `{"code":"recovery_cancelled"}`,
		"bad id":            `{"code":"recovery_cancelled","cancelled_recovery_id":"x"}`,
		"id without code":   `{"code":"recovery_attempt","cancelled_recovery_id":"` + wireRecID + `"}`,
		"other unlock code": `{"code":"recovery_attempt"}`,
	} {
		if _, ok := DecodeMarker(OpUnlock, []byte(b)); ok {
			t.Errorf("%s passed", name)
		}
	}
	nc := Marker{Code: CodeRecoveryNotCurrent}
	if got, ok := DecodeMarker(OpRecoveryCancel, nc.Encode()); !ok || got != nc {
		t.Fatalf("cancel marker: %+v %v", got, ok)
	}
	for _, op := range []string{OpUnlock, OpEnroll, OpRecovery, OpRecoveryOpen, OpRecoveryRegister} {
		if _, ok := DecodeMarker(op, nc.Encode()); ok {
			t.Errorf("recovery_not_current passed for %s", op)
		}
	}
	if _, ok := DecodeMarker(OpRecoveryCancel, []byte(`{"code":"recovery_not_current","cancelled_recovery_id":"`+wireRecID+`"}`)); ok {
		t.Error("an id on recovery_not_current passed")
	}
}

func TestResponseRecoveryCancelled(t *testing.T) {
	r := &Response{RequestID: "01JB2Z6V9K3M4N5P6Q7R8S9T21", Status: StatusDone, Envelope: opaque(), Code: CodeRecoveryCancelled,
		Clear: Marker{CancelledRecoveryID: wireRecID}}
	b := r.Marshal()
	if !strings.HasSuffix(string(b), `","code":"recovery_cancelled","cancelled_recovery_id":"`+wireRecID+`"}`) {
		t.Fatalf("member order: %s", b)
	}
	p, err := ParseResponse(b)
	if err != nil || p.Code != CodeRecoveryCancelled || p.Clear.CancelledRecoveryID != wireRecID {
		t.Fatalf("parse: %v %+v", err, p)
	}
	// recovery_not_current comes without an envelope, and only so.
	nc := &Response{RequestID: r.RequestID, Status: StatusDone, Code: CodeRecoveryNotCurrent}
	if p, err := ParseResponse(nc.Marshal()); err != nil || p.Code != CodeRecoveryNotCurrent || p.Envelope != nil {
		t.Fatalf("recovery_not_current: %v %+v", err, p)
	}
	for _, bad := range []*Response{
		{RequestID: r.RequestID, Status: StatusDone, Code: CodeRecoveryCancelled, Clear: Marker{CancelledRecoveryID: wireRecID}}, // no envelope
		{RequestID: r.RequestID, Status: StatusDone, Envelope: r.Envelope, Code: CodeRecoveryCancelled},                          // no id
		{RequestID: r.RequestID, Status: StatusDone, Envelope: r.Envelope, Code: CodeRecoveryCancelled, Clear: Marker{CancelledRecoveryID: "x"}},
		{RequestID: r.RequestID, Status: StatusDone, Envelope: r.Envelope, Clear: Marker{CancelledRecoveryID: wireRecID}}, // id alone
		{RequestID: r.RequestID, Status: StatusDone, Envelope: r.Envelope, Code: CodeRecoveryAttempt, Clear: Marker{CancelledRecoveryID: wireRecID}},
		{RequestID: r.RequestID, Status: StatusDone, Envelope: r.Envelope, Code: CodeRecoveryNotCurrent}, // with an envelope
		{RequestID: r.RequestID, Status: StatusDone, Code: CodeRecoveryAttempt},                          // other codes need one
	} {
		if _, err := ParseResponse(bad.Marshal()); err == nil {
			t.Errorf("accepted %s", bad.Marshal())
		}
	}
}

func TestLifecycleCancelledField(t *testing.T) {
	ev := vault.LifecycleEvent{Event: "unlocked", VaultID: "v1", Release: "r", VaultVersion: "r", StateVersion: 1, CancelledRecoveryID: wireRecID}
	f := LifecycleFields(ev)
	if len(f) != LifecycleFieldCount || LifecycleFieldCount != 15 || string(f[14]) != wireRecID {
		t.Fatalf("fields %q", f)
	}
	for _, e := range []string{"unlocked", "moved"} {
		if id, ok := ParseCancelledField(e, f[14]); !ok || id != wireRecID {
			t.Fatalf("%s: %q %v", e, id, ok)
		}
	}
	plain := LifecycleFields(vault.LifecycleEvent{Event: "locked", VaultID: "v1"})
	if id, ok := ParseCancelledField("locked", plain[14]); !ok || id != "" || len(plain[14]) != 0 {
		t.Fatalf("plain: %q %v", plain[14], ok)
	}
	for _, e := range []string{"locked", "enrolled", "deleted", vault.EventAppKey, vault.EventAccountName} {
		if _, ok := ParseCancelledField(e, []byte(wireRecID)); ok {
			t.Errorf("an id on %s accepted", e)
		}
	}
	if _, ok := ParseCancelledField("unlocked", []byte("not-a-ulid")); ok {
		t.Error("a malformed id accepted")
	}
}
