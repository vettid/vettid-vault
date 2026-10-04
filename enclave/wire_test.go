package enclave

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/altchan"
	"github.com/vettid/vettid-vault/vms/suite"
)

func sampleQueue() *QueueMessage {
	return &QueueMessage{Op: OpUnlock, VaultID: "0123456789abcdef0123456789abcdef", UserGUID: "user-1",
		RequestID: "01JB2Z6V9K3M4N5P6Q7R8S9T21", ETKKid: suite.Kid{1, 2, 3, 4, 5, 6, 7, 8},
		Envelope: bytes.Repeat([]byte{1}, altchan.RequestEnvelopeSize), EnqueuedAt: time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC),
		ManifestSHA256: strings.Repeat("ab", 32)}
}

func TestQueueMessage(t *testing.T) {
	b := sampleQueue().Marshal()
	q, err := ParseQueueMessage(b)
	if err != nil || q.Op != OpUnlock || len(q.Envelope) != altchan.RequestEnvelopeSize || q.ManifestSHA256 != strings.Repeat("ab", 32) {
		t.Fatalf("%v", err)
	}
	lock := &QueueMessage{Op: OpLock, VaultID: "v", UserGUID: "u", RequestID: "01JB2Z6V9K3M4N5P6Q7R8S9T21", EnqueuedAt: time.Now()}
	if _, err := ParseQueueMessage(lock.Marshal()); err != nil || strings.Contains(string(lock.Marshal()), "etk_kid") {
		t.Fatal("lock message", err)
	}
	// As the member API sends it (§11.5): no etk_kid, no envelope.
	api := `{"v":1,"op":"lock","vault_id":"0123456789abcdef0123456789abcdef","user_guid":"u","request_id":"01JB2Z6V9K3M4N5P6Q7R8S9T21","enqueued_at":"2026-10-02T12:00:00Z"}`
	if _, err := ParseQueueMessage([]byte(api)); err != nil {
		t.Fatal(err)
	}
	for name, s := range map[string]string{
		"op":             strings.Replace(string(b), `"op":"unlock"`, `"op":"rotate"`, 1),
		"vault id path":  strings.Replace(string(b), `"vault_id":"0123456789abcdef0123456789abcdef"`, `"vault_id":"../x"`, 1),
		"upper kid":      strings.Replace(string(b), `"etk_kid":"0102030405060708"`, `"etk_kid":"01020304050607AB"`, 1),
		"no envelope":    strings.Replace(string(b), `"envelope"`, `"envelopex"`, 1),
		"duplicate":      strings.Replace(string(b), `"op":"unlock",`, `"op":"unlock","op":"unlock",`, 1),
		"v2":             strings.Replace(string(b), `"v":1`, `"v":2`, 1),
		"envelope short": strings.Replace(string(b), `"envelope":"AQEB`, `"envelope":"`, 1),
		// 0.10.0: enroll and unlock name their manifest by hash.
		"no manifest_sha256":    strings.Replace(string(b), `"manifest_sha256"`, `"manifest_sha256x"`, 1),
		"upper manifest_sha256": strings.Replace(string(b), strings.Repeat("ab", 32), strings.Repeat("AB", 32), 1),
		"short manifest_sha256": strings.Replace(string(b), strings.Repeat("ab", 32), strings.Repeat("ab", 31), 1),
	} {
		if _, err := ParseQueueMessage([]byte(s)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	hashLock := strings.Replace(string(lock.Marshal()), `"enqueued_at"`, `"manifest_sha256":"`+strings.Repeat("ab", 32)+`","enqueued_at"`, 1)
	if _, err := ParseQueueMessage([]byte(hashLock)); err == nil {
		t.Error("lock with a manifest_sha256 accepted")
	}
	envLock := strings.Replace(string(lock.Marshal()), `"enqueued_at"`, `"envelope":"AAAA","enqueued_at"`, 1)
	if _, err := ParseQueueMessage([]byte(envLock)); err == nil {
		t.Error("lock with an envelope accepted")
	}
}

func TestParseSealed(t *testing.T) {
	for _, b := range [][]byte{{1, 0, 0}, {2, 0, 1, 'a', 0, 1, 1}, {1, 0, 1, 'a', 0, 0}} {
		if _, _, _, _, ok := parseSealed(b); ok {
			t.Errorf("%x accepted", b)
		}
	}
}

func FuzzParseQueueMessage(f *testing.F) {
	f.Add(sampleQueue().Marshal())
	f.Add((&QueueMessage{Op: OpRecovery, VaultID: "v1", UserGUID: "u1", RequestID: "01JB2Z6V9K3M4N5P6Q7R8S9T21",
		BrowserKey: append([]byte{4}, bytes.Repeat([]byte{1}, 64)...), EnqueuedAt: time.Unix(1700000000, 0)}).Marshal())
	f.Fuzz(func(t *testing.T, b []byte) {
		q, err := ParseQueueMessage(b)
		if err != nil {
			return
		}
		if _, err := ParseQueueMessage(q.Marshal()); err != nil {
			t.Fatal("re-marshalled message does not parse")
		}
	})
}

func FuzzParseResponse(f *testing.F) {
	f.Add((&Response{RequestID: "01JB2Z6V9K3M4N5P6Q7R8S9T21", Status: StatusDone, Envelope: opaque()}).Marshal())
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = ParseResponse(b)
	})
}

func FuzzParseSealed(f *testing.F) {
	f.Add([]byte{1, 0, 3, 'a', 'r', 'n', 0, 2, 9, 9})
	f.Fuzz(func(t *testing.T, b []byte) {
		arn, blob, nonce, ct, ok := parseSealed(b)
		if ok && (arn == "" || len(blob) == 0 || len(nonce) != suite.XNonceSize || len(ct) < suite.TagSize) {
			t.Fatal("inconsistent parse")
		}
	})
}

// §11.11: recovery messages carry no envelope; only "recovery" carries
// the browser key (65 bytes); recovery_register carries an envelope.
func TestQueueRecoveryOps(t *testing.T) {
	bk := append([]byte{4}, bytes.Repeat([]byte{1}, 64)...)
	base := QueueMessage{VaultID: "v1", UserGUID: "u1", RequestID: "01JB2Z6V9K3M4N5P6Q7R8S9T21", EnqueuedAt: time.Unix(1700000000, 0)}
	rq := base
	rq.Op, rq.BrowserKey = OpRecovery, bk
	q, err := ParseQueueMessage(rq.Marshal())
	if err != nil || !bytes.Equal(q.BrowserKey, bk) {
		t.Fatalf("recovery: %v", err)
	}
	cq := base
	cq.Op = OpRecoveryCancel
	if _, err := ParseQueueMessage(cq.Marshal()); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	for name, s := range map[string]string{
		"recovery without key": `{"v":1,"op":"recovery","vault_id":"v1","user_guid":"u1","request_id":"01JB2Z6V9K3M4N5P6Q7R8S9T21","enqueued_at":"2023-11-14T22:13:20Z"}`,
		"cancel with key":      `{"v":1,"op":"recovery_cancel","vault_id":"v1","user_guid":"u1","request_id":"01JB2Z6V9K3M4N5P6Q7R8S9T21","browser_key":"` + base64.StdEncoding.EncodeToString(bk) + `","enqueued_at":"2023-11-14T22:13:20Z"}`,
		"short key":            `{"v":1,"op":"recovery","vault_id":"v1","user_guid":"u1","request_id":"01JB2Z6V9K3M4N5P6Q7R8S9T21","browser_key":"AAAA","enqueued_at":"2023-11-14T22:13:20Z"}`,
		"register without env": `{"v":1,"op":"recovery_register","vault_id":"v1","user_guid":"u1","request_id":"01JB2Z6V9K3M4N5P6Q7R8S9T21","enqueued_at":"2023-11-14T22:13:20Z"}`,
	} {
		if _, err := ParseQueueMessage([]byte(s)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
