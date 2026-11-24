package vault

import (
	"context"
	"testing"

	"github.com/vettid/vettid-vault/vms/envelope"
)

// §11.3 "Confirming twice" (0.93.2): vault.enroll.confirm on a vault
// already confirmed answers {} and changes nothing: no audit line, no
// event, the vault stays confirmed. (Each batch is still written: the
// message seen and its answer cached.)
func TestEnrollConfirmTwice(t *testing.T) {
	d := newDevFixture(t)
	d.m.mu.Lock()
	d.m.hdr.Provisional = true
	d.m.mu.Unlock()
	_ = d.send("vault.enroll.confirm", []byte(`{}`))
	if r := one(t, d); r.Status != envelope.StatusOK {
		t.Fatalf("the first confirmation: %+v", r)
	}
	if err := d.m.persist(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	audits := len(d.m.Audit()) // Audit takes the lock
	d.m.mu.Lock()
	provisional := d.m.hdr.Provisional
	d.m.mu.Unlock()
	if provisional {
		t.Fatal("still provisional after the first confirmation")
	}
	d.relay.mu.Lock()
	d.relay.deposits = nil // every deposit from here on is the second confirmation's
	d.relay.mu.Unlock()
	_ = d.send("vault.enroll.confirm", []byte(`{}`)) // again, under a new id
	d.relay.mu.Lock()
	deposited := len(d.relay.deposits) // to any mailbox: the answer, and nothing for others
	d.relay.mu.Unlock()
	if deposited != 1 {
		t.Fatalf("the second confirmation deposited %d messages, want its answer alone", deposited)
	}
	r := one(t, d)
	if r.Status != envelope.StatusOK || string(r.Body) != "{}" {
		t.Fatalf("the second confirmation: %s %s", r.Status, r.Body)
	}
	after := len(d.m.Audit())
	d.m.mu.Lock()
	defer d.m.mu.Unlock()
	if after != audits || d.m.hdr.Provisional {
		t.Fatalf("the second confirmation changed the vault: audits %d->%d, provisional %v", audits, after, d.m.hdr.Provisional)
	}
}
