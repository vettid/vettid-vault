package vault

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"

	"github.com/vettid/vettid-vault/vms/altchan"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/suite"
)

func (d *devFixture) errorCode(t *testing.T, typ, body string) string {
	t.Helper()
	if err := d.send(typ, []byte(body)); err != nil {
		t.Fatal(err)
	}
	for _, r := range d.responses(t) {
		if r.Type == typ && r.Re != "" {
			if r.Error != nil {
				return r.Error.Code
			}
			return ""
		}
	}
	t.Fatalf("no response to %s", typ)
	return ""
}

func attestOK(d *devFixture) {
	d.m.opt.DeviceAttest = func(*altchan.DeviceAttest, [32]byte, time.Time) (json.RawMessage, error) {
		return json.RawMessage(`{"platform":"android","pk":"AQ==","counter":0}`), nil
	}
}

var testAttest = &altchan.DeviceAttest{Platform: altchan.PlatformAndroid, Chain: [][]byte{{1}}}

// §6.7 (0.9.0): one app per vault. A second app cannot pair (one_app),
// and the one app cannot be unlinked: it leaves by a transfer or a
// recovery. Desktops still pair.
func TestOneApp(t *testing.T) {
	d := newDevFixture(t)
	if c := d.errorCode(t, "device.pair.create", `{"role":"app"}`); c != "one_app" {
		t.Fatalf("app pairing: %q", c)
	}
	if c := d.errorCode(t, "device.pair.create", `{"role":"desktop"}`); c != "" {
		t.Fatalf("desktop pairing: %q", c)
	}
	if c := d.errorCode(t, "device.unlink", `{"device_id":"dev1"}`); c != "forbidden" {
		t.Fatalf("unlinking the app: %q", c)
	}
	if d.m.st.Devices["dev1"] == nil {
		t.Fatal("app removed")
	}
}

// §6.7.1: the transfer's runtime side: one at a time; the new app's
// attested hs.init is answered at once and, once hs.fin checked out, asks
// only the old app with the SAS; device.pair.approve cannot approve it;
// the approval completes it (0.10.3), making the new app the vault's only
// app and unlock key.
func TestTransferRuntime(t *testing.T) {
	d := newDevFixture(t)
	sinkOf(d)
	attestOK(d)
	inv := d.transferInvite(t)
	d.m.mu.Lock()
	if _, _, _, err := d.m.createTransfer(context.Background(), "dev1", d.m.now()); err == nil {
		t.Fatal("second transfer")
	}
	d.m.mu.Unlock()
	if !inv.Transfer {
		t.Fatal("not a transfer invite")
	}
	n := newNewcomer(t, 0x50)
	n.hsInitAttest(t, d.m, handshake.PurposeApp, inv.ID, "t1", testAttest)
	if d.m.st.Transfer.Inbound == "" || d.depositsTo(n.addr.Mailbox) != 1 {
		t.Fatal("hs.init not answered at once")
	}
	if d.depositsTo(d.devPeer.Relay.Mailbox) != 0 {
		t.Fatal("old app asked before hs.fin")
	}
	sas := n.finish(t, d)
	var pending bool
	for _, r := range d.responses(t) {
		pending = pending || r.Type == "device.transfer.pending" && bodyStr(t, r, "sas") == sas &&
			strings.Contains(string(r.Body), inv.ID)
	}
	if !pending {
		t.Fatal("old app not asked")
	}
	if c := d.errorCode(t, "device.pair.approve", `{"pairing_id":"`+inv.ID+`"}`); c != "not_found" {
		t.Fatalf("device.pair.approve on a transfer: %q", c)
	}
	r := d.m.st.Requests[d.m.st.Transfer.Inbound]
	if r == nil || len(r.Peer.Attestation) == 0 {
		t.Fatal("the new app's request lost its attestation")
	}
	p := r.Peer
	// The approval completes the transfer after the handler (afterHandle).
	d.m.mu.Lock()
	err := d.m.approveTransfer(context.Background(), inv.ID, d.m.now())
	if err == nil {
		d.m.afterRespond(d.m.now())
		d.m.syncUnlockKeys()
		d.m.drainOutbox(context.Background())
	}
	d.m.mu.Unlock()
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	got := n.received(d)
	if len(got) != 1 || got[0].Type != "device.paired" || !strings.Contains(string(got[0].Body), `"transfer":true`) || bodyStr(t, got[0], "token") == "" {
		t.Fatalf("device.paired: %+v", got)
	}
	if d.m.st.Devices["dev1"] != nil || d.m.st.Transfer != nil {
		t.Fatal("old app kept")
	}
	if !containsStr(d.m.st.DeniedSubs, relayauth.EncodeKey(d.devPeer.Relay.PK)) {
		t.Fatal("old app's relay key not denylisted")
	}
	keys := d.m.hdr.UnlockKeys
	if len(keys) != 1 || !suite.EqualPublic(keys[0].IK, p.IK) {
		t.Fatalf("unlock keys %+v", keys)
	}
	if !d.hasActivity("device.transferred") {
		t.Fatal("not audited")
	}
}

func sinkOf(d *devFixture) *recSink {
	for _, f := range d.m.features {
		if s, ok := f.(*recSink); ok {
			return s
		}
	}
	s := &recSink{}
	d.m.addFeature(s)
	return s
}

func (d *devFixture) hasActivity(kind string) bool { return sinkOf(d).has(kind) }

// §6.7.1: a new app that does not finish in time aborts the transfer; the
// old app stays. A transfer whose old app goes away aborts too.
func TestTransferExpiry(t *testing.T) {
	d := newDevFixture(t)
	attestOK(d)
	inv := d.transferInvite(t)
	n := newNewcomer(t, 0x50)
	n.hsInitAttest(t, d.m, handshake.PurposeApp, inv.ID, "t1", testAttest)
	n.finish(t, d)
	d.m.mu.Lock()
	later := time.Now().Add(PairingApprovalTTL + time.Minute)
	d.m.housekeeping(later)
	d.m.mu.Unlock()
	if d.m.st.Transfer != nil || len(d.m.st.Awaiting) != 0 || len(d.m.st.Requests) != 0 || d.m.st.Devices["dev1"] == nil {
		t.Fatal("expired transfer not aborted cleanly")
	}
	// Before the scan: the invitation's own expiry.
	inv = d.transferInvite(t)
	d.m.mu.Lock()
	d.m.housekeeping(time.Now().Add(PairingApprovalTTL + time.Minute))
	d.m.mu.Unlock()
	if d.m.st.Transfer != nil || d.m.st.Invites[inv.ID] != nil {
		t.Fatal("unscanned transfer kept")
	}
}

// §11.11.5 (0.9.0): a completed recovery removes every other app and
// keeps desktops and agents.
func TestRecoveryReplacesApps(t *testing.T) {
	d := newDevFixture(t)
	sinkOf(d)
	now := time.Now()
	desk := &Peer{ID: "desk1", Kind: KindDesktop, State: PeerActive}
	rec := &Peer{ID: "rec1", Kind: KindApp, State: PeerActive}
	d.m.st.Devices[desk.ID], d.m.st.Devices[rec.ID] = desk, rec
	d.m.mu.Lock()
	d.m.replaceAfter = rec.ID
	d.m.afterHandle(now)
	d.m.mu.Unlock()
	if d.m.st.Devices["dev1"] != nil || d.m.st.Devices["desk1"] == nil || d.m.st.Devices["rec1"] == nil {
		t.Fatalf("devices after recovery: %v", d.m.st.Devices)
	}
	if !d.hasActivity("device.replaced") {
		t.Fatal("not audited")
	}
}

// §6.7.1: the PIN check of a transfer's approval runs against the DEK,
// under the unlock backoff (§11.8).
func TestVerifyPIN(t *testing.T) {
	d := newDevFixture(t)
	now := time.Now()
	d.m.mu.Lock()
	defer d.m.mu.Unlock()
	if err := d.m.verifyPIN(testPIN, now); err != nil {
		t.Fatal(err)
	}
	if err := d.m.verifyPIN("12a456", now); err == nil {
		t.Fatal("malformed PIN")
	}
	for i := 0; i < 3; i++ {
		if err := d.m.verifyPIN("999999", now); err == nil || err.(*HandlerError).Code != "bad_pin" {
			t.Fatalf("wrong PIN: %v", err)
		}
	}
	if err := d.m.verifyPIN(testPIN, now); err == nil || err.(*HandlerError).Code != "backoff" {
		t.Fatalf("backoff: %v", err)
	}
	if err := d.m.verifyPIN(testPIN, now.Add(time.Minute)); err != nil || d.m.hdr.Backoff.Failures != 0 {
		t.Fatalf("after the backoff: %v", err)
	}
}

// §11.5: a host alarm is reported after the batch's flush, never before.
func TestAlarmReportedAfterFlush(t *testing.T) {
	d := newDevFixture(t)
	var got []string
	d.m.opt.Lifecycle = func(ev LifecycleEvent) { got = append(got, ev.Event) }
	d.m.mu.Lock()
	managerHost{d.m}.ReportAlarm(AlarmCredentialClone)
	managerHost{d.m}.ReportAlarm("unknown")
	d.m.dirty = true
	d.m.mu.Unlock()
	if len(got) != 0 {
		t.Fatal("reported before the flush")
	}
	if err := d.m.ProcessBatch(context.Background(), &fakeCollector{}, nil); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "alarm.credential_clone" {
		t.Fatalf("reported %v", got)
	}
}
