//go:build devenclave && e2e

package e2e

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayclient"

	"github.com/vettid/vettid-vault/client"
	"github.com/vettid/vettid-vault/internal/enclavetest"
	"github.com/vettid/vettid-vault/internal/relaytest"
	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
)

// One app per vault (VAULT-MESSAGING 0.9.0, owner decisions of
// 2026-10-03) through the real relay: no second app; the clone alarm, the
// freeze while messaging goes on, the confirmation and the forced
// rotation; the direct transfer and its aborts; recovery replacing the
// app while a desktop stays; recovery with backup off; GrapheneOS.

func alarmOf(t *testing.T, d *client.Device) (id, state string) {
	t.Helper()
	o, err := d.CredentialVersion(ctxT(t, 30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	raw, ok := o["alarm"]
	if !ok {
		return "", ""
	}
	a, err := strictjson.ParseObject(raw)
	if err != nil {
		t.Fatal(err)
	}
	id, _ = a.String("alarm_id")
	state, _ = a.String("state")
	return id, state
}

// §6.7: a second app cannot pair.
func TestSecondAppRefused(t *testing.T) {
	r := relaytest.Start(t, nil)
	a := newTestVault(t, r.URL, "a", nil)
	if rr := a.request(a.app, "device.pair.create", `{"role":"app"}`); rr.ErrorCode() != "one_app" {
		t.Fatalf("second app: %q", rr.ErrorCode())
	}
	desk := pairDesktop(t, a, r.URL) // desktops still pair
	if rr := a.request(a.app, "device.unlink", `{"device_id":"`+a.app.DeviceID()+`"}`); rr.ErrorCode() != "forbidden" {
		t.Fatalf("unlinking the app: %q", rr.ErrorCode())
	}
	if rr := a.request(desk, "credential.get", `{}`); rr.ErrorCode() != "forbidden" {
		t.Fatalf("desktop fetched the credential: %q", rr.ErrorCode())
	}
}

// §3.5.9: a stale copy presented after the holder confirmed the current
// version is a clone: refused, the app alerted urgently, the host told
// (alarm.credential_clone, which the member API mails), the desktop told;
// credential operations freeze while messaging and other features keep
// working; "not me" → rotation_required → the forced rotation → every old
// copy is dead.
func TestCloneAlarm(t *testing.T) {
	r := relaytest.Start(t, nil)
	var mu sync.Mutex
	var events []string
	a := newTestVault(t, r.URL, "a", func(o *vault.Options) {
		o.Lifecycle = func(ev vault.LifecycleEvent) { mu.Lock(); events = append(events, ev.Event); mu.Unlock() }
	})
	b := newTestVault(t, r.URL, "b", nil)
	aConn, _ := connect(t, a, b, 600)
	desk := pairDesktop(t, a, r.URL)
	ctx := ctxT(t, 180*time.Second)

	// (The holder's own retry of the previous version, before it confirmed
	// the current one, is not a clone: credential.TestCloneAlarmFreezeConfirmRotate.)
	b1 := a.app.CredentialBlob()
	if _, err := a.app.CredentialUnlock(ctx, credPW); err != nil {
		t.Fatal(err)
	}
	b2 := a.app.CredentialBlob()
	if _, err := a.app.CredentialUnlock(ctx, credPW); err != nil {
		t.Fatal(err)
	}
	b3 := a.app.CredentialBlob()
	// A stolen copy (b1) presented: a clone.
	if _, err := a.app.CredentialRaw(ctx, "credential.unlock", takeUTK(t, a.app), b1, map[string]any{"password": credPW}); client.Code(err) != "credential_frozen" {
		t.Fatalf("clone: %v", err)
	}
	al := waitEvent(t, a.app, "credential.alarm", has("state", "frozen"))
	if !strings.Contains(string(al.Body), `"kind":"clone"`) {
		t.Fatalf("alert %s", al.Body)
	}
	waitEvent(t, desk, "sync.event", syncKind("credential.alarm"))
	waitEvent(t, desk, "feed.event", has("kind", "credential.alarm"))
	deadline := time.Now().Add(10 * time.Second)
	for {
		mu.Lock()
		n := strings.Count(strings.Join(events, ","), "alarm.credential_clone")
		mu.Unlock()
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("host alarm %v", events)
		}
		time.Sleep(50 * time.Millisecond)
	}
	id, st := alarmOf(t, a.app)
	if id == "" || st != "frozen" {
		t.Fatalf("alarm %q %q", id, st)
	}
	// Frozen: credential operations, the current copy included.
	if _, err := a.app.CredentialUnlock(ctx, credPW); client.Code(err) != "credential_frozen" {
		t.Fatalf("frozen unlock: %v", err)
	}
	if _, _, err := a.app.ItemPutCritical(ctx, credPW, "", 0, nil, client.ItemContent{Name: "seed",
		Fields: []client.ItemField{{Label: "Words", Kind: "multiline", Value: "abandon"}}}); client.Code(err) != "credential_frozen" {
		t.Fatalf("frozen critical item: %v", err)
	}
	// Only the owner's devices hear of it (§3.5.9): never a connection.
	quiet, qcancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer qcancel()
	if _, err := b.app.WaitEvent(quiet, "credential.alarm", nil); err == nil {
		t.Fatal("a connection's app received the alarm")
	}
	// Normal messaging and other features keep working.
	sendText(t, a, a.app, aConn, "still here")
	waitEvent(t, b.app, "message.new", nil)
	mustOK(t, a.request(a.app, "vault.status", `{}`))
	// A second presentation: refused, no second host alarm.
	if _, err := a.app.CredentialRaw(ctx, "credential.unlock", takeUTK(t, a.app), b2, map[string]any{"password": credPW}); client.Code(err) != "credential_frozen" {
		t.Fatalf("second clone: %v", err)
	}
	// "Not me": the rotation is required next.
	if st, err := a.app.CredentialAlarmConfirm(ctx, id, false); err != nil || st != "rotation_required" {
		t.Fatalf("confirm: %q %v", st, err)
	}
	if _, err := a.app.CredentialUnlock(ctx, credPW); client.Code(err) != "rotation_required" {
		t.Fatalf("unlock before the rotation: %v", err)
	}
	if err := a.app.CredentialRotate(ctx, credPW); err != nil {
		t.Fatalf("forced rotation: %v", err)
	}
	waitEvent(t, desk, "sync.event", has("state", "resolved"))
	if id, _ := alarmOf(t, a.app); id != "" {
		t.Fatal("alarm still open")
	}
	if _, err := a.app.CredentialUnlock(ctx, credPW); err != nil {
		t.Fatalf("after the rotation: %v", err)
	}
	// Every older copy is dead (and a new presentation a new alarm).
	if _, err := a.app.CredentialRaw(ctx, "credential.unlock", takeUTK(t, a.app), b3, map[string]any{"password": credPW}); client.Code(err) != "credential_frozen" {
		t.Fatalf("old copy after the rotation: %v", err)
	}
	mu.Lock()
	n := strings.Count(strings.Join(events, ","), "alarm.credential_clone")
	mu.Unlock()
	if n < 1 || n > 2 {
		t.Fatalf("host alarms %d", n)
	}
	au, err := a.app.AuditList(ctx, map[string]any{"kinds": []string{"credential"}}, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"credential.clone_detected", "credential.alarm.confirmed", "credential.alarm.resolved", "credential.rotated"} {
		if !strings.Contains(string(au["entries"]), `"`+k+`"`) {
			t.Errorf("audit lacks %s", k)
		}
	}
}

// acPairDesktop pairs a desktop with an alternate-channel world's app.
func acPairDesktop(t *testing.T, aw *acWorld, a *acApp) *client.Device {
	t.Helper()
	ctx := ctxT(t, 60*time.Second)
	desk, err := client.New(ctx, client.Config{Role: vault.KindDesktop, Name: a.guid + "-desk", RelayURL: aw.relay, PollWait: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	pc, err := a.dev.Request(ctx, "device.pair.create", []byte(`{"role":"desktop"}`))
	if err != nil || !pc.OK() {
		t.Fatalf("pair.create: %v", err)
	}
	pid := field(t, pc.Body(), "pairing_id")
	if _, err := desk.Pair(ctx, field(t, pc.Body(), "link")); err != nil {
		t.Fatal(err)
	}
	waitEvent(t, a.dev, "device.pair.pending", has("pairing_id", pid))
	if r, err := a.dev.Request(ctx, "device.pair.approve", []byte(`{"pairing_id":"`+pid+`","session_seconds":3600}`)); err != nil || !r.OK() {
		t.Fatalf("approve: %v", err)
	}
	if err := desk.AwaitPaired(ctx); err != nil {
		t.Fatal(err)
	}
	return desk
}

func appCount(t *testing.T, d *client.Device) (apps int, body string) {
	t.Helper()
	dl, err := d.Request(ctxT(t, 30*time.Second), "device.list", []byte(`{}`))
	if err != nil || !dl.OK() {
		t.Fatalf("device.list: %v", err)
	}
	return strings.Count(string(dl.Body()), `"kind":"app"`), string(dl.Body())
}

// §6.7.1: direct transfer to a new phone with the old one in hand: the
// old app shows the QR, the new app scans and attests, the old app
// approves with the PIN and the password, the credential moves (CEK
// rotated) and the old app is removed at once; desktops stay. Since
// 0.10.3 the approval completes the transfer (the new app's handshake ran
// first). Aborts: a rejection, also after failed approvals, leaves the old
// app as it was, and the new app learns it from device.pair.rejected
// (0.10.5).
func TestTransfer(t *testing.T) {
	aw := newACWorld(t)
	a := aw.newApp("member-tr", enclavetest.NewAndroidAttester(0x81, enclavetest.AndroidOptions{}))
	if r := aw.enroll(a, acPIN); !r.OK {
		t.Fatal(r.Code)
	}
	desk := acPairDesktop(t, aw, a)
	ctx := ctxT(t, 240*time.Second)
	sid, _, err := a.dev.ItemPutCritical(ctx, credPW, "", 0, nil, client.ItemContent{Name: "seed",
		Fields: []client.ItemField{{Label: "Words", Kind: "multiline", Value: "legal winner thank year"}}})
	if err != nil {
		t.Fatal(err)
	}

	// Abort 1: the old app rejects after the scan.
	id, link, err := a.dev.TransferCreate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.dev.TransferCreate(ctx); client.Code(err) != "exists" {
		t.Fatalf("second transfer: %v", err)
	}
	c := aw.newApp(a.guid, enclavetest.NewIOSAttester(0x91, enclavetest.IOSOptions{}))
	if _, err := c.dev.PairAttested(ctx, link, c.att); err != nil {
		t.Fatal(err)
	}
	waitEvent(t, a.dev, "device.transfer.pending", has("transfer_id", id))
	if err := a.dev.TransferReject(ctx, id); err != nil {
		t.Fatal(err)
	}
	waitEvent(t, desk, "sync.event", has("state", "aborted"))
	// After its hs.fin the new app is told (device.pair.rejected, 0.10.5).
	if err := c.dev.AwaitPaired(ctxT(t, 30*time.Second)); !errors.Is(err, client.ErrPairRejected) {
		t.Fatalf("new app after a rejection: %v", err)
	}
	if _, err := a.dev.CredentialUnlock(ctx, credPW); err != nil {
		t.Fatalf("old app after a rejection: %v", err)
	}

	// Abort 2: wrong PIN and password at the approval change nothing; the
	// old app then rejects and keeps the credential.
	id, link, err = a.dev.TransferCreate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	c = aw.newApp(a.guid, enclavetest.NewIOSAttester(0x92, enclavetest.IOSOptions{}))
	if _, err := c.dev.PairAttested(ctx, link, c.att); err != nil {
		t.Fatal(err)
	}
	waitEvent(t, a.dev, "device.transfer.pending", has("transfer_id", id))
	if err := a.dev.TransferApprove(ctx, id, "999999", credPW); client.Code(err) != "bad_pin" {
		t.Fatalf("wrong PIN: %v", err)
	}
	if err := a.dev.TransferApprove(ctx, id, acPIN, "not the password"); client.Code(err) != "bad_password" {
		t.Fatalf("wrong password: %v", err)
	}
	if err := a.dev.TransferReject(ctx, id); err != nil {
		t.Fatal(err)
	}
	if err := c.dev.AwaitPaired(ctxT(t, 30*time.Second)); !errors.Is(err, client.ErrPairRejected) {
		t.Fatalf("the aborted new app: %v", err)
	}
	if _, err := a.dev.CredentialUnlock(ctx, credPW); err != nil {
		t.Fatalf("old app after the abort: %v", err)
	}

	// The happy path.
	id, link, err = a.dev.TransferCreate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	old := a.dev.CredentialBlob()
	b := aw.newApp(a.guid, enclavetest.NewIOSAttester(0x93, enclavetest.IOSOptions{}))
	if _, err := b.dev.PairAttested(ctx, link, b.att); err != nil {
		t.Fatal(err)
	}
	waitEvent(t, a.dev, "device.transfer.pending", has("transfer_id", id))
	if err := a.dev.TransferApprove(ctx, id, acPIN, credPW); err != nil {
		t.Fatal(err)
	}
	if err := b.dev.AwaitPaired(ctx); err != nil {
		t.Fatalf("new app: %v", err)
	}
	b.vid = a.vid
	waitEvent(t, desk, "sync.event", syncKind("device.transferred"))
	if err := b.dev.CredentialFetch(ctx); err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if string(b.dev.CredentialBlob()) == string(old) {
		t.Fatal("the CEK did not rotate")
	}
	v, err := b.dev.ItemRevealCritical(ctx, credPW, sid)
	if err != nil || !strings.Contains(string(v), "legal winner") {
		t.Fatalf("critical item on the new app: %v", err)
	}
	if n, body := appCount(t, b.dev); n != 1 || !strings.Contains(body, b.dev.DeviceID()) || !strings.Contains(body, `"kind":"desktop"`) {
		t.Fatalf("devices after the transfer: %s", body)
	}
	// The new app unlocks over the alternate channel; the old one cannot.
	aw.lock(b)
	if r, err := aw.unlock(a, acPIN, client.UnlockOptions{}, ""); err == nil && r.OK {
		t.Fatal("the old app still unlocks")
	}
	if r := aw.mustUnlock(b, acPIN, client.UnlockOptions{}, ""); !r.OK {
		t.Fatalf("new app unlock: %+v", r)
	}
	aw.status(b)
	au, err := b.dev.AuditList(ctx, map[string]any{"kinds": []string{"device"}}, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"device.transfer.started", "device.transfer.approved", "device.transfer.aborted", "device.transferred"} {
		if !strings.Contains(string(au["entries"]), `"`+k+`"`) {
			t.Errorf("audit lacks %s", k)
		}
	}
}

// §11.11.5 (0.9.0): a recovery replaces the old app (removed, its unlock
// key revoked, its copy dead) and keeps the desktop.
func TestRecoveryReplacesApp(t *testing.T) {
	aw, off := newRecWorld(t)
	a := aw.newApp("member-rr", enclavetest.NewAndroidAttester(0x82, enclavetest.AndroidOptions{}))
	if r := aw.enroll(a, acPIN); !r.OK {
		t.Fatal(r.Code)
	}
	desk := acPairDesktop(t, aw, a)
	ctx := ctxT(t, 180*time.Second)
	qr := requestRecovery(t, aw, a)
	off.Store(int64(24*time.Hour + time.Minute))
	b := aw.newApp(a.guid, enclavetest.NewIOSAttester(0x94, enclavetest.IOSOptions{}))
	b.vid = a.vid
	if res := register(t, aw, b, qr); !res.OK {
		t.Fatalf("register: %+v", res)
	}
	if r := aw.mustUnlock(b, acPIN, client.UnlockOptions{}, ""); !r.OK {
		t.Fatalf("unlock: %+v", r)
	}
	if err := b.dev.CompleteRecoveryHandshake(ctx); err != nil {
		t.Fatal(err)
	}
	if err := b.dev.CredentialRecover(ctx, credPW); err != nil {
		t.Fatalf("recover: %v", err)
	}
	if n, body := appCount(t, b.dev); n != 1 || strings.Contains(body, a.dev.DeviceID()) || !strings.Contains(body, desk.DeviceID()) {
		t.Fatalf("devices after the recovery: %s", body)
	}
	// The desktop keeps working (its session after the vault's restart).
	if r, err := desk.Request(ctx, "vault.status", []byte(`{}`)); err != nil || !r.OK() {
		t.Fatalf("desktop after the recovery: %v", err)
	}
	// The old app's unlock key is revoked.
	aw.lock(b)
	if r, err := aw.unlock(a, acPIN, client.UnlockOptions{}, ""); err == nil && r.OK {
		t.Fatal("the replaced app still unlocks")
	}
}

// §11.11.5, §3.5.6 (0.9.0): with backup off, losing the app loses the
// credential and its critical items: the recovery answers credential_lost
// and continues only with a new credential (OWNER DECISION).
func TestRecoveryBackupOffLosesCredential(t *testing.T) {
	aw, off := newRecWorld(t)
	a := aw.newApp("member-ro", enclavetest.NewAndroidAttester(0x83, enclavetest.AndroidOptions{}))
	if r := aw.enroll(a, acPIN); !r.OK {
		t.Fatal(r.Code)
	}
	ctx := ctxT(t, 180*time.Second)
	if _, _, err := a.dev.ItemPutCritical(ctx, credPW, "", 0, nil, client.ItemContent{Name: "seed",
		Fields: []client.ItemField{{Label: "Words", Kind: "multiline", Value: "abandon abandon about"}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.dev.SettingsSet(ctx, 0, map[string]any{"credential.backup": false}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.dev.CredentialUnlock(ctx, credPW); err != nil { // a new version, confirmed
		t.Fatal(err)
	}
	qr := requestRecovery(t, aw, a)
	off.Store(int64(24*time.Hour + time.Minute))
	b := aw.newApp(a.guid, enclavetest.NewAndroidAttester(0x84, enclavetest.AndroidOptions{}))
	b.vid = a.vid
	if res := register(t, aw, b, qr); !res.OK {
		t.Fatalf("register: %+v", res)
	}
	if r := aw.mustUnlock(b, acPIN, client.UnlockOptions{}, ""); !r.OK {
		t.Fatalf("unlock: %+v", r)
	}
	if err := b.dev.CompleteRecoveryHandshake(ctx); err != nil {
		t.Fatal(err)
	}
	if err := b.dev.CredentialRecover(ctx, credPW); client.Code(err) != "credential_lost" {
		t.Fatalf("recover with backup off: %v", err)
	}
	if rr, err := b.dev.Request(ctx, "item.list", []byte(`{}`)); err != nil || rr.ErrorCode() != "forbidden" {
		t.Fatal("restricted until a new credential")
	}
	if err := b.dev.CredentialReset(ctx, "a brand new password"); err != nil {
		t.Fatalf("reset: %v", err)
	}
	l, err := b.dev.ItemList(ctx, map[string]any{"sensitivity": "critical"})
	if err != nil || strings.Contains(string(l["items"]), "seed") {
		t.Fatalf("critical items survived: %s %v", l["items"], err)
	}
	if _, err := b.dev.CredentialUnlock(ctx, "a brand new password"); err != nil {
		t.Fatal(err)
	}
	if n, _ := appCount(t, b.dev); n != 1 {
		t.Fatal("old app kept")
	}
}

// §11.7 (0.9.0): GrapheneOS: SelfSigned boot with a pinned OS key enrolls
// and unlocks; another self-signed OS is refused.
func TestGrapheneOS(t *testing.T) {
	aw := newACWorld(t)
	g := aw.newApp("member-gos", enclavetest.NewAndroidAttester(0x85, enclavetest.AndroidOptions{BootState: 1,
		BootKey: enclavetest.TestGrapheneOSBootKey[:]}))
	if r := aw.enroll(g, acPIN); !r.OK {
		t.Fatalf("GrapheneOS enrollment: %+v", r)
	}
	aw.lock(g)
	if r := aw.mustUnlock(g, acPIN, client.UnlockOptions{}, ""); !r.OK {
		t.Fatalf("GrapheneOS unlock: %+v", r)
	}
	aw.status(g)
	aw.lock(g)
	other := make([]byte, 32)
	other[0] = 1
	x := aw.newApp("member-custom", enclavetest.NewAndroidAttester(0x86, enclavetest.AndroidOptions{BootState: 1, BootKey: other}))
	if r := aw.enroll(x, acPIN); r.OK || r.Code != "attestation" {
		t.Fatalf("another self-signed OS: %+v", r)
	}
	u := aw.newApp("member-unverified", enclavetest.NewAndroidAttester(0x87, enclavetest.AndroidOptions{BootState: 2,
		BootKey: enclavetest.TestGrapheneOSBootKey[:]}))
	if r := aw.enroll(u, acPIN); r.OK || r.Code != "attestation" {
		t.Fatalf("unverified boot: %+v", r)
	}
}

// acConnect connects two alternate-channel apps' vaults (§6.4).
func acConnect(t *testing.T, a, b *acApp) {
	t.Helper()
	ctx := ctxT(t, 60*time.Second)
	inv, err := a.dev.Request(ctx, "connection.invite.create", []byte(`{"ttl_seconds":600}`))
	if err != nil || !inv.OK() {
		t.Fatalf("invite: %v", err)
	}
	acc, err := b.dev.Request(ctx, "connection.invite.accept", []byte(`{"link":"`+field(t, inv.Body(), "link")+`"}`))
	if err != nil || !acc.OK() {
		t.Fatalf("accept: %v", err)
	}
	pend := waitEvent(t, a.dev, "connection.request.pending", nil)
	out := waitEvent(t, b.dev, "connection.request.outgoing", nil)
	if field(t, pend.Body, "sas") != field(t, out.Body, "sas") {
		t.Fatal("the two members see different codes")
	}
	if r, err := a.dev.Request(ctx, "connection.approve", []byte(`{"pending_id":"`+field(t, pend.Body, "pending_id")+`"}`)); err != nil || !r.OK() {
		t.Fatalf("approve: %v", err)
	}
	if r, err := b.dev.Request(ctx, "connection.approve", []byte(`{"connection_id":"`+field(t, acc.Body(), "connection_id")+`"}`)); err != nil || !r.OK() {
		t.Fatalf("approve (accepter): %v", err)
	}
	waitEvent(t, b.dev, "connection.event", has("event", "added"))
	waitEvent(t, a.dev, "connection.event", has("event", "added"))
}

func storeHas(t *testing.T, aw *acWorld, key string) bool {
	t.Helper()
	_, _, err := aw.w.Store.Get(context.Background(), key)
	return err == nil
}

// §12.5: vault.delete from the app: the PIN and the password (refused
// while a clone alarm is open); connections and devices are told, the
// vault's relay mailbox is deleted (RELAY-PROTOCOL 0.5.0: deposits get
// mailbox_unknown), the stored objects are erased, the host reports
// `deleted`, and the member can enroll afresh.
func TestVaultDelete(t *testing.T) {
	aw := newACWorld(t)
	a := aw.newApp("member-del", enclavetest.NewAndroidAttester(0x88, enclavetest.AndroidOptions{}))
	if r := aw.enroll(a, acPIN); !r.OK {
		t.Fatal(r.Code)
	}
	b := aw.newApp("member-del-peer", enclavetest.NewAndroidAttester(0x89, enclavetest.AndroidOptions{}))
	if r := aw.enroll(b, acPIN); !r.OK {
		t.Fatal(r.Code)
	}
	acConnect(t, a, b)
	desk := acPairDesktop(t, aw, a)
	ctx := ctxT(t, 180*time.Second)
	vid := a.vid

	// Refused during a clone alarm, until the forced rotation.
	old := a.dev.CredentialBlob()
	if _, err := a.dev.CredentialUnlock(ctx, credPW); err != nil {
		t.Fatal(err)
	}
	if _, err := a.dev.CredentialUnlock(ctx, credPW); err != nil {
		t.Fatal(err)
	}
	if _, err := a.dev.CredentialRaw(ctx, "credential.unlock", takeUTK(t, a.dev), old, map[string]any{"password": credPW}); client.Code(err) != "credential_frozen" {
		t.Fatalf("clone: %v", err)
	}
	if err := a.dev.VaultDelete(ctx, acPIN, credPW); client.Code(err) != "credential_frozen" {
		t.Fatalf("delete during an alarm: %v", err)
	}
	id, _ := alarmOf(t, a.dev)
	if _, err := a.dev.CredentialAlarmConfirm(ctx, id, true); err != nil {
		t.Fatal(err)
	}
	if err := a.dev.CredentialRotate(ctx, credPW); err != nil {
		t.Fatal(err)
	}
	if err := a.dev.VaultDelete(ctx, "999999", credPW); client.Code(err) != "bad_pin" {
		t.Fatalf("wrong PIN: %v", err)
	}
	if err := a.dev.VaultDelete(ctx, acPIN, "not the password"); client.Code(err) != "bad_password" {
		t.Fatalf("wrong password: %v", err)
	}
	// The vault's mailbox exists: a deposit with a bogus token gets past
	// the mailbox check (§5.3 step 1) and fails on the token.
	relayURL, mailbox := a.dev.VaultMailbox()
	probe := relayclient.New(relayURL, ed25519.NewKeyFromSeed(make([]byte, 32)))
	probe.MaxAttempts = 1
	if _, err := probe.Deposit(ctx, mailbox, "v4.public.bogus", []byte("x")); !relayclient.IsCode(err, "token_invalid") {
		t.Fatalf("probe before deletion: %v", err)
	}
	if err := a.dev.VaultDelete(ctx, acPIN, credPW); err != nil {
		t.Fatalf("delete: %v", err)
	}
	waitEvent(t, b.dev, "connection.event", has("event", "removed"))
	waitEvent(t, desk, "device.unlinked", has("reason", "vault_deleted"))
	deadline := time.Now().Add(15 * time.Second)
	for storeHas(t, aw, "vaults/"+vid+"/state") || storeHas(t, aw, "vaults/"+vid+"/header/"+aw.w.SealedRelease(vid)) {
		if time.Now().After(deadline) {
			t.Fatal("storage not erased")
		}
		time.Sleep(50 * time.Millisecond)
	}
	deleted := false
	for _, ev := range aw.w.Events() {
		deleted = deleted || ev.Event == "deleted" && ev.VaultID == vid
	}
	if !deleted {
		t.Fatal("no deleted lifecycle event")
	}
	// The vault's relay mailbox is gone (RELAY-PROTOCOL 0.5.0 §6.10), so
	// the relay refuses every deposit, the desktop's included.
	if _, err := probe.Deposit(ctx, mailbox, "v4.public.bogus", []byte("x")); !relayclient.IsCode(err, "mailbox_unknown") {
		t.Fatalf("vault mailbox after deletion: %v", err)
	}
	short, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if r, err := desk.Request(short, "vault.status", []byte(`{}`)); err == nil && r.OK() {
		t.Fatal("deleted vault answered")
	}
	// Nothing unlocks; the member enrolls afresh.
	if r, err := aw.unlock(a, acPIN, client.UnlockOptions{}, ""); err == nil && r.OK {
		t.Fatal("deleted vault unlocked")
	}
	fresh := aw.newApp(a.guid, enclavetest.NewAndroidAttester(0x8a, enclavetest.AndroidOptions{}))
	if r := aw.enroll(fresh, acPIN); !r.OK {
		t.Fatalf("fresh enrollment: %+v", r)
	}
}

// §11.11.5, §12.5: with the backup off, a recovery restores access only;
// the recovering app may delete the vault with the PIN alone.
func TestVaultDeleteViaRecoveryBackupOff(t *testing.T) {
	aw, off := newRecWorld(t)
	a := aw.newApp("member-rd", enclavetest.NewAndroidAttester(0x8b, enclavetest.AndroidOptions{}))
	if r := aw.enroll(a, acPIN); !r.OK {
		t.Fatal(r.Code)
	}
	ctx := ctxT(t, 180*time.Second)
	if _, err := a.dev.SettingsSet(ctx, 0, map[string]any{"credential.backup": false}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.dev.CredentialUnlock(ctx, credPW); err != nil {
		t.Fatal(err)
	}
	qr := requestRecovery(t, aw, a)
	off.Store(int64(24*time.Hour + time.Minute))
	b := aw.newApp(a.guid, enclavetest.NewIOSAttester(0x95, enclavetest.IOSOptions{}))
	b.vid = a.vid
	if res := register(t, aw, b, qr); !res.OK {
		t.Fatalf("register: %+v", res)
	}
	if r := aw.mustUnlock(b, acPIN, client.UnlockOptions{}, ""); !r.OK {
		t.Fatalf("unlock: %+v", r)
	}
	if err := b.dev.CompleteRecoveryHandshake(ctx); err != nil {
		t.Fatal(err)
	}
	if err := b.dev.CredentialRecover(ctx, credPW); client.Code(err) != "credential_lost" {
		t.Fatalf("recover: %v", err)
	}
	if rr, err := b.dev.Request(ctx, "credential.get", []byte(`{}`)); err != nil || rr.ErrorCode() != "forbidden" {
		t.Fatal("a recovering app fetched the credential")
	}
	if err := b.dev.VaultDelete(ctx, acPIN, ""); err != nil {
		t.Fatalf("delete: %v", err)
	}
	deadline := time.Now().Add(15 * time.Second)
	for storeHas(t, aw, "vaults/"+a.vid+"/state") {
		if time.Now().After(deadline) {
			t.Fatal("storage not erased")
		}
		time.Sleep(50 * time.Millisecond)
	}
}
