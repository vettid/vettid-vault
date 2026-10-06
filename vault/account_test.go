package vault

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/envelope"
)

func snapshotAt(t time.Time, extra string) []byte {
	return []byte(`{"v":1,"as_of":"` + envelope.FormatTS(t) + `","email_hint":"m***@example.org","state":"member","account_status":"active",` +
		`"deletes_at":null,"terms":{"needs_acceptance":false},"subscription":{"type_name":"Member","status":"active","paid":true,` +
		`"expires_at":"2027-10-06T00:00:00.000Z"},"voting_rights":false` + extra + `}`)
}

// §11.13 (0.15.0): the snapshot is parsed strictly (unknown members
// ignored, wrong types refused, over 2 KiB refused).
func TestParseAccountSnapshot(t *testing.T) {
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	if _, asOf, err := ParseAccountSnapshot(snapshotAt(now, `,"future":{"x":1}`)); err != nil || !asOf.Equal(now) {
		t.Fatalf("%v %v", asOf, err)
	}
	if _, _, err := ParseAccountSnapshot([]byte(`{"v":1,"as_of":"2026-10-06T12:00:00Z","subscription":null,"deletes_at":"2026-10-13T00:00:00Z"}`)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		`[]`, `{"v":2,"as_of":"2026-10-06T12:00:00Z"}`, `{"v":1}`, `{"v":1,"as_of":"yesterday"}`,
		`{"v":1,"as_of":"2026-10-06T12:00:00Z","state":1}`,
		`{"v":1,"as_of":"2026-10-06T12:00:00Z","voting_rights":"no"}`,
		`{"v":1,"as_of":"2026-10-06T12:00:00Z","terms":{"needs_acceptance":1}}`,
		`{"v":1,"as_of":"2026-10-06T12:00:00Z","subscription":{"paid":"yes"}}`,
		`{"v":1,"as_of":"2026-10-06T12:00:00Z","subscription":"x"}`,
		`{"v":1,"as_of":"2026-10-06T12:00:00Z","deletes_at":5}`,
		`{"v":1,"as_of":"2026-10-06T12:00:00Z","pad":"` + strings.Repeat("x", MaxAccountSnapshot) + `"}`,
	} {
		if _, _, err := ParseAccountSnapshot([]byte(bad)); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
}

// §11.13: the running vault stores a newer snapshot (version + 1,
// received_at) and tells the app and desktops (account.changed); an older
// or invalid one is ignored; account.get answers apps and desktops, null
// before any; agents may not ask.
func TestAccountInVault(t *testing.T) {
	d := newDevFixture(t)
	app := d.self()
	desk := d.addDevice(t, "desk1", KindDesktop, 0x60)
	desk.peer.Access = &AccessSession{ID: "s", Expires: time.Now().Add(time.Hour)}
	ag := d.addDevice(t, "agent1", KindAgent, 0x70)
	ag.peer.Access = &AccessSession{ID: "s2", Expires: time.Now().Add(time.Hour)}
	id := d.sendAs(app, "account.get", `{}`)
	if r := find(d.inbox(app)["dev1"], reply(id)); r == nil || string(r.Body) != `{"account":null,"version":0}` {
		t.Fatalf("before any: %+v", r)
	}
	now := time.Now()
	if err := d.m.SetAccount(context.Background(), snapshotAt(now, "")); err != nil {
		t.Fatal(err)
	}
	in := d.inbox(app, desk, ag)
	for _, dev := range []string{"dev1", "desk1"} {
		if ev := find(in[dev], ofType("sync.event")); ev == nil || string(ev.Body) != `{"kind":"account.changed","version":1}` {
			t.Fatalf("%s: %+v", dev, in[dev])
		}
	}
	if len(in["agent1"]) != 0 {
		t.Fatal("an agent was told (§13.7)")
	}
	_ = d.m.SetAccount(context.Background(), snapshotAt(now.Add(-time.Minute), ""))
	_ = d.m.SetAccount(context.Background(), []byte(`{"v":1}`))
	if d.m.AccountVersion() != 1 || len(d.inbox(app)["dev1"]) != 0 {
		t.Fatal("older or invalid snapshot applied")
	}
	id = d.sendAs(desk, "account.get", `{}`)
	r := find(d.inbox(desk)["desk1"], reply(id))
	if r == nil || errCode(r) != "" || !bytes.Contains(r.Body, []byte(`"account":{"v":1,`)) || !bytes.Contains(r.Body, []byte(`"version":1,"received_at":`)) {
		t.Fatalf("desktop account.get: %+v", r)
	}
	id = d.sendAs(ag, "account.get", `{}`)
	if r := find(d.inbox(ag)["agent1"], reply(id)); errCode(r) != "forbidden" {
		t.Fatalf("agent: %+v", r)
	}
}

// §11.11.5 step 3 (0.15.0): a completed recovery makes the registered
// app's key the vault's app key (seq + 1), reported after the flush.
func TestRecoveryAppKey(t *testing.T) {
	d := newDevFixture(t)
	key := testAppKeyDER(t, 0x41)
	rec := &Peer{ID: "rec1", Kind: KindApp, State: PeerActive, Recovering: true}
	d.m.st.Devices[rec.ID] = rec
	d.m.hdr.AppKey, d.m.hdr.AppKeySeq = []byte{1}, 1
	d.m.hdr.Recovery = &RecoveryRecord{ID: "01JB2Z6V9K3M4N5P6Q7R8S9T30", State: RecoveryRegistered, App: &RecoveryApp{IK: make([]byte, 32), APIKey: key}}
	d.m.mu.Lock()
	err := d.m.completeRecovery(rec.ID, time.Now())
	d.m.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(d.m.hdr.AppKey, key) || d.m.hdr.AppKeySeq != 2 || !d.m.appKeyChanged {
		t.Fatalf("app key after recovery: seq %d", d.m.hdr.AppKeySeq)
	}
}
