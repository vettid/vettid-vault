package vault

import (
	"context"
	"testing"
)

// backupFeature is a credential stand-in whose backup copy tests toggle.
type backupFeature struct {
	recSink
	copy bool
}

func (b *backupFeature) Name() string           { return "backup" }
func (b *backupFeature) CredentialReady() bool  { return true }
func (b *backupFeature) CredentialExists() bool { return true }
func (b *backupFeature) HasBackupCopy() bool    { return b.copy }

// §3.3, §11.5 (0.16.0): the header records the backup bit at every write;
// a change on a running vault is reported as credential_backup after the
// flush; locked carries the bit.
func TestCredentialBackupBit(t *testing.T) {
	d := newDevFixture(t)
	bf := &backupFeature{copy: true}
	d.m.addFeature(bf)
	var evs []LifecycleEvent
	d.m.opt.Lifecycle = func(ev LifecycleEvent) { evs = append(evs, ev) }
	if err := d.m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if b := d.m.CredentialBackup(); b == nil || !*b {
		t.Fatalf("bit %v", b)
	}
	evs = nil
	bf.copy = false
	_ = d.m.ProcessBatch(context.Background(), &fakeCollector{}, nil)
	d.m.mu.Lock()
	d.m.dirty = true
	d.m.mu.Unlock()
	_ = d.m.ProcessBatch(context.Background(), &fakeCollector{}, nil)
	if len(evs) != 1 || evs[0].Event != EventCredentialBackup || evs[0].CredentialBackup == nil || *evs[0].CredentialBackup {
		t.Fatalf("events %+v", evs)
	}
	if r := d.m.RecoveryRefusal(); r != "no_backup" {
		t.Fatalf("refusal %q", r)
	}
	evs = nil
	if err := d.m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(evs) != 1 || evs[0].Event != "locked" || evs[0].CredentialBackup == nil || *evs[0].CredentialBackup {
		t.Fatalf("locked %+v", evs)
	}
}

// §10.2, §11.11.5 (0.16.0): a recovering app's vault.status is
// {vault_id, state_seq, header_seq} only.
func TestRecoveringStatusReduced(t *testing.T) {
	d := newDevFixture(t)
	rec := d.addDevice(t, "rec1", KindApp, 0x80)
	rec.peer.Recovering = true
	id := d.sendAs(rec, "vault.status", `{}`)
	r := find(d.inbox(rec)["rec1"], reply(id))
	if r == nil || errCode(r) != "" {
		t.Fatalf("%+v", r)
	}
	o := map[string]bool{}
	for _, k := range []string{"vault_id", "state_seq", "header_seq", "devices", "connections", "owner_check", "provisional"} {
		o[k] = contains(string(r.Body), `"`+k+`"`)
	}
	if !o["vault_id"] || !o["state_seq"] || !o["header_seq"] || o["devices"] || o["connections"] || o["owner_check"] || o["provisional"] {
		t.Fatalf("recovering status %s", r.Body)
	}
	for _, typ := range []string{"credential.reset", "vault.delete", "settings.get"} {
		id := d.sendAs(rec, typ, `{}`)
		if r := find(d.inbox(rec)["rec1"], reply(id)); errCode(r) != "forbidden" && errCode(r) != "unsupported_type" {
			t.Fatalf("%s: %+v", typ, r)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
