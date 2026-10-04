package enclave_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/enclave"
	"github.com/vettid/vettid-vault/internal/enclavetest"
	"github.com/vettid/vettid-vault/vms/altchan"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// FuzzProcessBody seals arbitrary enroll and unlock bodies to a real ETK
// (valid envelope, inner and binding), so the enclave's request parsers,
// attestation checks and result paths see them. Every answer must be a
// result of the uniform size.
func FuzzProcessBody(f *testing.F) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	w := enclavetest.NewWorld(func() time.Time { return now }, relayURL)
	w.AddRelease(r3)
	in, err := w.Start(3)
	if err != nil {
		f.Fatal(err)
	}
	defer w.Close()
	desc, _ := in.Descriptor()
	d, err := altchan.ParseDescriptor(desc)
	if err != nil {
		f.Fatal(err)
	}
	// The manifest document is host input (0.10.0): fuzzed with the body.
	doc := w.Served()
	f.Add([]byte(`{"user_guid":"u","request_id":"01JB2Z6V9K3M4N5P6Q7R8S9T21","app":{}}`), true, doc)
	f.Add([]byte(`{"user_guid":"u","vault_id":"v","request_id":"01JB2Z6V9K3M4N5P6Q7R8S9T21","pin":"123456"}`), false, doc)
	f.Add([]byte(`{"user_guid":"u","vault_id":"vault-1","request_id":"01JB2Z6V9K3M4N5P6Q7R8S9T21","pin":"123456","manifest_sha256":"`+
		strings.Repeat("0", 64)+`","manifest_serial":1}`), false, []byte(`{}`))
	n := 0
	f.Fuzz(func(t *testing.T, body []byte, enroll bool, doc []byte) {
		n++
		rid, _ := envelope.NewULID(now.Add(time.Duration(n) * time.Millisecond))
		typ, op := altchan.TypeUnlock, enclave.OpUnlock
		if enroll {
			typ, op = altchan.TypeEnroll, enclave.OpEnroll
		}
		env, err := altchan.SealRequest(d.ETK, typ, rid, now, body)
		if err != nil {
			return // not a JSON object, or too large
		}
		resp := in.Process(context.Background(), &enclave.QueueMessage{Op: op, VaultID: "vault-1", UserGUID: "u", RequestID: rid,
			ETKKid: d.Kid, Envelope: env, EnqueuedAt: now, ManifestSHA256: strings.Repeat("0", 64)}, doc)
		if len(resp.Envelope) != altchan.ResultEnvelopeSize {
			t.Fatalf("answer of %d bytes", len(resp.Envelope))
		}
	})
}
