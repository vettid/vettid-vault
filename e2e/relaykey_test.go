//go:build devenclave && e2e

package e2e

import (
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/client"
	"github.com/vettid/vettid-vault/internal/enclavetest"
	"github.com/vettid/vettid-vault/internal/relaytest"
	"github.com/vettid/vettid-vault/vault"
)

// waitRelayKey polls the vault's relay-key state until ok holds.
func waitRelayKey(t *testing.T, tv *testVault, what string, ok func(vault.RelayKeyStatus) bool) vault.RelayKeyStatus {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for {
		s := tv.manager().RelayKeyStatus()
		if ok(s) {
			return s
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: %+v", what, s)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// waitVaultMailbox collects the device's mailbox until it follows the
// vault to mailbox.
func waitVaultMailbox(t *testing.T, d *client.Device, mailbox string) {
	t.Helper()
	ctx := ctxT(t, 60*time.Second)
	for {
		if _, mb := d.VaultMailbox(); mb == mailbox {
			return
		}
		if err := d.Poll(ctx); err != nil && ctx.Err() != nil {
			_, mb := d.VaultMailbox()
			t.Fatalf("the device did not follow the new address: %s, want %s", mb, mailbox)
		}
	}
}

// VAULT-MESSAGING §3.4 "The order of a relay-key rotation" and "Resending
// the new address", through the real relay: the member's credential.rotate
// stores a new relay key as pending, the relay's rotate makes its mailbox,
// and the second write makes it current and sends relay.address.update;
// the app, a paired desktop, an agent and a connection's vault each follow
// the new address and acknowledge it (relay.token.issued for the new key),
// after which the old key is deleted; messages then flow both ways.
func TestRelayKeyRotationCredentialRotateE2E(t *testing.T) {
	// A short rotation grace: once it has run, only the new mailbox exists,
	// so the traffic at the end goes to the new address.
	r := relaytest.Start(t, relaytest.Options{"RELAY_ROTATION_GRACE": "3s", "RELAY_SWEEP_INTERVAL": "1s"})
	a := newTestVault(t, r.URL, "a", nil)
	b := newTestVault(t, r.URL, "b", nil)
	aConn, bConn := connect(t, a, b, 600)
	desk := pairDevice(t, a, r.URL, vault.KindDesktop, 3600)
	agent := pairDevice(t, a, r.URL, vault.KindAgent, 3600)
	before := a.manager().RelayKeyStatus().Mailbox
	if _, mb := desk.VaultMailbox(); mb != before {
		t.Fatalf("the desktop holds %s, the vault %s", mb, before)
	}

	ctx := ctxT(t, 180*time.Second)
	if err := a.app.CredentialRotate(ctx, credPW); err != nil {
		t.Fatal(err)
	}
	st := waitRelayKey(t, a, "the new key is not current", func(s vault.RelayKeyStatus) bool {
		return !s.Pending && s.Mailbox != before && s.Mailbox != ""
	})
	after := st.Mailbox
	for _, d := range []*client.Device{a.app, desk, agent} {
		waitVaultMailbox(t, d, after)
	}
	// Every recipient acknowledges, the connection's vault included (its
	// relay.token.issued for the new key reaches the new mailbox), and the
	// old key goes.
	waitRelayKey(t, a, "not acknowledged, or the old key kept", func(s vault.RelayKeyStatus) bool {
		if len(s.Unacknowledged) == 0 && s.OldKeys == 0 {
			return true
		}
		for _, d := range []*client.Device{a.app, desk, agent} {
			_ = d.Poll(ctx)
		}
		return false
	})

	// Once the grace has run the old mailbox is gone: no longer collected,
	// its key deleted. Messages both ways, and the devices' requests, on
	// the new address.
	waitRelayKey(t, a, "the old mailbox still collected after the grace", func(s vault.RelayKeyStatus) bool {
		return s.Collecting == 0
	})
	id1 := sendText(t, a, a.app, aConn, "after the rotation")
	waitEvent(t, b.app, "message.new", has("message_id", id1))
	id2 := sendText(t, b, b.app, bConn, "and back")
	waitEvent(t, a.app, "message.new", has("message_id", id2))
	waitEvent(t, desk, "message.new", has("message_id", id2))
	for _, d := range []*client.Device{desk, agent} {
		mustOK(t, a.request(d, "vault.status", `{}`))
	}
	// A restart of the vault keeps the new address (no second rotation).
	a.restart()
	if s := a.manager().RelayKeyStatus(); s.Mailbox != after || s.Pending {
		t.Fatalf("after a restart: %+v", s)
	}
	mustOK(t, a.request(a.app, "vault.status", `{}`))
}

// acPairDevice pairs a desktop or an agent with an alternate-channel
// world's app.
func acPairDevice(t *testing.T, aw *acWorld, a *acApp, role string) *client.Device {
	t.Helper()
	ctx := ctxT(t, 60*time.Second)
	d, err := client.New(ctx, client.Config{Role: role, Name: a.guid + "-" + role, RelayURL: aw.relay, PollWait: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	pc, err := a.dev.Request(ctx, "device.pair.create", []byte(`{"role":"`+role+`"}`))
	if err != nil || !pc.OK() {
		t.Fatalf("pair.create: %v", err)
	}
	pid := field(t, pc.Body(), "pairing_id")
	if _, err := d.Pair(ctx, field(t, pc.Body(), "link")); err != nil {
		t.Fatal(err)
	}
	waitEvent(t, a.dev, "device.pair.pending", has("pairing_id", pid))
	if r, err := a.dev.Request(ctx, "device.pair.approve", []byte(`{"pairing_id":"`+pid+`","session_seconds":3600}`)); err != nil || !r.OK() {
		t.Fatalf("approve: %v", err)
	}
	if err := d.AwaitPaired(ctx); err != nil {
		t.Fatal(err)
	}
	return d
}

// acRelayKey polls the relay-key state of a's vault in an
// alternate-channel world until ok holds, polling the devices meanwhile.
func acRelayKey(t *testing.T, aw *acWorld, a *acApp, what string, ok func(vault.RelayKeyStatus) bool, devs ...*client.Device) vault.RelayKeyStatus {
	t.Helper()
	ctx := ctxT(t, 90*time.Second)
	for {
		var s vault.RelayKeyStatus
		if m := aw.instanceOf(a).Manager(a.vid); m != nil {
			s = m.RelayKeyStatus()
			if s.Mailbox != "" && ok(s) {
				return s
			}
		}
		if ctx.Err() != nil {
			t.Fatalf("%s: %+v", what, s)
		}
		for _, d := range devs {
			_ = d.Poll(ctx)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// A transfer's owed rotation (§11.14.10) rotates the relay key by §3.4's
// order at the new phone's first unlock: the new phone, a desktop and an
// agent paired before the move, and a connection's vault follow the new
// address and acknowledge it; the old key goes; the connection still
// reaches the member.
func TestRelayKeyRotationTransferE2E(t *testing.T) {
	w := newTKWorld(t, 0xa4)
	desk := acPairDevice(t, w.aw, w.a, vault.KindDesktop)
	agent := acPairDevice(t, w.aw, w.a, vault.KindAgent)
	before := acRelayKey(t, w.aw, w.a, "no vault", func(vault.RelayKeyStatus) bool { return true }).Mailbox
	b := w.move(w.a, "new-phone-rk", 0xb4)
	if s := acRelayKey(t, w.aw, w.a, "", func(vault.RelayKeyStatus) bool { return true }); s.Mailbox != before || s.Pending {
		t.Fatalf("the relay key moved at the approval: %+v", s)
	}
	w.finish(b)
	st := acRelayKey(t, w.aw, b, "the new key is not current", func(s vault.RelayKeyStatus) bool {
		return !s.Pending && s.Mailbox != before
	})
	for _, d := range []*client.Device{b.dev, desk, agent} {
		waitVaultMailbox(t, d, st.Mailbox)
	}
	acRelayKey(t, w.aw, b, "not acknowledged, or the old key kept", func(s vault.RelayKeyStatus) bool {
		return len(s.Unacknowledged) == 0 && s.OldKeys == 0
	}, b.dev, desk, agent)
	if res := w.auth(b.dev); !strings.Contains(res, `"authenticated":true`) {
		t.Fatalf("the connection after the move: %s", res)
	}
	for _, d := range []*client.Device{desk, agent} {
		if r, err := d.Request(ctxT(t, 30*time.Second), "vault.status", []byte(`{}`)); err != nil || !r.OK() {
			t.Fatalf("vault.status after the move: %v", err)
		}
	}
}

// A completed recovery (§11.14.6 step 6) rotates the relay key by §3.4's
// order once the recovered phone has paired (its first handshake checks
// the address its vault_bundle gave): the recovered phone, a desktop and
// an agent kept by the recovery, and a connection's vault follow the new
// address and acknowledge it, and the old key goes.
func TestRelayKeyRotationRecoveryE2E(t *testing.T) {
	rr := newRecR(t)
	a := rr.newApp("member-rk", enclavetest.NewAndroidAttester(0xa6, enclavetest.AndroidOptions{}))
	if r := rr.enroll(a, acPIN); !r.OK {
		t.Fatal(r.Code)
	}
	p := rr.newApp("member-rk-peer", enclavetest.NewAndroidAttester(0xa7, enclavetest.AndroidOptions{}))
	if r := rr.enroll(p, acPIN); !r.OK {
		t.Fatal(r.Code)
	}
	pConn, _ := acConnectIDs(t, p, a)
	desk := acPairDevice(t, rr.acWorld, a, vault.KindDesktop)
	agent := acPairDevice(t, rr.acWorld, a, vault.KindAgent)
	before := acRelayKey(t, rr.acWorld, a, "no vault", func(vault.RelayKeyStatus) bool { return true }).Mailbox
	// As recR.setup: the request, then the recovered phone registers.
	rr.advance(73 * time.Hour)
	qr, _ := rr.request(a)
	waitEvent(t, a.dev, "vault.locking", has("reason", "recovery"))
	rr.advance(25 * time.Hour)
	b := rr.newApp("member-rk", enclavetest.NewAndroidAttester(0xa8, enclavetest.AndroidOptions{}))
	b.vid = a.vid
	rr.register(b, qr)
	rr.advance(10 * time.Minute)
	if r, _ := rr.open(b, acPIN, recPW); !r.OK {
		t.Fatalf("open: %+v", r)
	}
	// Pending until the recovered phone pairs.
	if s := acRelayKey(t, rr.acWorld, b, "", func(vault.RelayKeyStatus) bool { return true }); !s.Pending || s.Mailbox != before {
		t.Fatalf("before the pairing: %+v", s)
	}
	if err := b.dev.CompleteRecoveryHandshake(ctxT(t, 30*time.Second)); err != nil {
		t.Fatalf("the recovered phone's first handshake: %v", err)
	}
	st := acRelayKey(t, rr.acWorld, b, "the new key is not current", func(s vault.RelayKeyStatus) bool {
		return !s.Pending && s.Mailbox != before
	})
	for _, d := range []*client.Device{b.dev, desk, agent} {
		waitVaultMailbox(t, d, st.Mailbox)
	}
	acRelayKey(t, rr.acWorld, b, "not acknowledged, or the old key kept", func(s vault.RelayKeyStatus) bool {
		return len(s.Unacknowledged) == 0 && s.OldKeys == 0
	}, b.dev, desk, agent)
	// The connection reaches the member on the new address.
	ctx := ctxT(t, 60*time.Second)
	id, err := p.dev.AuthRequest(ctx, pConn, "still you?")
	if err != nil {
		t.Fatal(err)
	}
	waitEvent(t, b.dev, "connection.authenticate.pending", has("request_id", id))
}
