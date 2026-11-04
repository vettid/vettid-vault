//go:build devenclave && e2e

package e2e

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/client"
	"github.com/vettid/vettid-vault/internal/enclavetest"
)

// acConnectIDs connects two alternate-channel apps' vaults (§6.4), a
// inviting, and returns each side's connection id.
func acConnectIDs(t *testing.T, a, b *acApp) (aConn, bConn string) {
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
	bConn = field(t, acc.Body(), "connection_id")
	pend := waitEvent(t, a.dev, "connection.request.pending", nil)
	waitEvent(t, b.dev, "connection.request.outgoing", has("connection_id", bConn))
	pid := field(t, pend.Body, "pending_id")
	if r, err := a.dev.Request(ctx, "connection.approve", []byte(`{"pending_id":"`+pid+`"}`)); err != nil || !r.OK() {
		t.Fatalf("approve: %v", err)
	}
	if r, err := b.dev.Request(ctx, "connection.approve", []byte(`{"connection_id":"`+bConn+`"}`)); err != nil || !r.OK() {
		t.Fatalf("approve (accepter): %v", err)
	}
	waitEvent(t, b.dev, "connection.event", has("event", "added"))
	ev := waitEvent(t, a.dev, "connection.event", func(m json.RawMessage) bool {
		return has("event", "added")(m) && has("pending_id", pid)(m)
	})
	return field(t, ev.Body, "connection_id"), bConn
}

// VAULT-MESSAGING §11.14.10 "The credential key, at the approval": a
// transfer rotates the credential key K0→K1 at the approval and holds the
// statement; a connection that pinned K0 is told nothing until the new
// phone's first unlock from storage, then follows the statement to K1, and
// a later credential.rotate (K1→K2) continues the chain.
func TestTransferRotatesCredentialKey(t *testing.T) {
	aw := newACWorld(t)
	a := aw.newApp("member-tk", enclavetest.NewAndroidAttester(0x84, enclavetest.AndroidOptions{}))
	if r := aw.enroll(a, acPIN); !r.OK {
		t.Fatal(r.Code)
	}
	p := aw.newApp("member-tk-peer", enclavetest.NewAndroidAttester(0x85, enclavetest.AndroidOptions{}))
	if r := aw.enroll(p, acPIN); !r.OK {
		t.Fatal(r.Code)
	}
	pConn, _ := acConnectIDs(t, p, a)
	ctx := ctxT(t, 300*time.Second)
	// The peer asks the member; the member's phone approves (unlock window
	// open); the peer pins the key that signed.
	authOnce := func(member *client.Device) string {
		t.Helper()
		id, err := p.dev.AuthRequest(ctx, pConn, "prove it")
		if err != nil {
			t.Fatal(err)
		}
		waitEvent(t, member, "connection.authenticate.pending", has("request_id", id))
		if _, err := member.CredentialUnlock(ctx, credPW); err != nil {
			t.Fatal(err)
		}
		if err := member.AuthApprove(ctx, id); err != nil {
			t.Fatal(err)
		}
		return string(waitEvent(t, p.dev, "connection.authenticate.result", has("request_id", id)).Body)
	}
	keyOf := func(d *client.Device) string {
		t.Helper()
		v, err := d.CredentialVersion(ctx)
		if err != nil {
			t.Fatal(err)
		}
		k, _ := v.String("key")
		return k
	}
	k0 := keyOf(a.dev)
	if res := authOnce(a.dev); !strings.Contains(res, `"authenticated":true`) || !strings.Contains(res, k0) {
		t.Fatalf("first authentication: %s", res)
	}

	// The transfer.
	id, link, err := a.dev.TransferCreate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	b := aw.newApp("new-phone-tk", enclavetest.NewIOSAttester(0x94, enclavetest.IOSOptions{}))
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
	b.guid, b.vid = b.dev.UserGUID(), a.vid
	if err := b.dev.CredentialFetch(ctx); err != nil {
		t.Fatal(err)
	}
	k1 := keyOf(b.dev)
	if k1 == k0 {
		t.Fatal("the credential key did not rotate at the approval")
	}
	// Held: the peer hears nothing before the new phone's first unlock.
	if in, err := p.dev.WaitEvent(ctxT(t, 5*time.Second), "connection.authenticate.key", nil); err == nil {
		t.Fatalf("the statement was sent before the new phone's unlock: %s", in.Body)
	}

	// "Finish the move": the statement goes out, then the old phone's notice.
	aw.lock(b)
	if r := aw.mustUnlock(b, acPIN, client.UnlockOptions{}, ""); !r.OK {
		t.Fatalf("new app unlock: %+v", r)
	}
	waitEvent(t, p.dev, "connection.authenticate.key", has("key", k1))
	waitEvent(t, a.dev, "device.unlinked", has("reason", "transferred"))
	if res := authOnce(b.dev); !strings.Contains(res, `"key_changed":false`) || !strings.Contains(res, k1) {
		t.Fatalf("K0→K1 not followed: %s", res)
	}

	// A later credential.rotate continues the chain.
	if err := b.dev.CredentialRotate(ctx, credPW); err != nil {
		t.Fatal(err)
	}
	k2 := keyOf(b.dev)
	waitEvent(t, p.dev, "connection.authenticate.key", has("key", k2))
	if res := authOnce(b.dev); !strings.Contains(res, `"key_changed":false`) || !strings.Contains(res, k2) {
		t.Fatalf("K1→K2 not followed: %s", res)
	}
}

// tkWorld is a member, a peer that pinned the member's credential key K0,
// and helpers to move the member's vault to new phones.
type tkWorld struct {
	t     *testing.T
	aw    *acWorld
	a, p  *acApp
	pConn string
	k0    string
}

func newTKWorld(t *testing.T, seed byte) *tkWorld {
	aw := newACWorld(t)
	w := &tkWorld{t: t, aw: aw}
	w.a = aw.newApp("member-tk", enclavetest.NewAndroidAttester(seed, enclavetest.AndroidOptions{}))
	if r := aw.enroll(w.a, acPIN); !r.OK {
		t.Fatal(r.Code)
	}
	w.p = aw.newApp("member-tk-peer", enclavetest.NewAndroidAttester(seed+1, enclavetest.AndroidOptions{}))
	if r := aw.enroll(w.p, acPIN); !r.OK {
		t.Fatal(r.Code)
	}
	w.pConn, _ = acConnectIDs(t, w.p, w.a)
	w.k0 = w.key(w.a.dev)
	if res := w.auth(w.a.dev); !strings.Contains(res, w.k0) {
		t.Fatalf("first authentication: %s", res)
	}
	return w
}

func (w *tkWorld) auth(member *client.Device) string {
	w.t.Helper()
	ctx := ctxT(w.t, 120*time.Second)
	id, err := w.p.dev.AuthRequest(ctx, w.pConn, "prove it")
	if err != nil {
		w.t.Fatal(err)
	}
	waitEvent(w.t, member, "connection.authenticate.pending", has("request_id", id))
	if _, err := member.CredentialUnlock(ctx, credPW); err != nil {
		w.t.Fatal(err)
	}
	if err := member.AuthApprove(ctx, id); err != nil {
		w.t.Fatal(err)
	}
	return string(waitEvent(w.t, w.p.dev, "connection.authenticate.result", has("request_id", id)).Body)
}

func (w *tkWorld) key(d *client.Device) string {
	w.t.Helper()
	v, err := d.CredentialVersion(ctxT(w.t, 60*time.Second))
	if err != nil {
		w.t.Fatal(err)
	}
	k, _ := v.String("key")
	return k
}

// move transfers the vault from the app from to a new phone, which pairs
// and fetches the credential but does not unlock.
func (w *tkWorld) move(from *acApp, name string, seed byte) *acApp {
	w.t.Helper()
	ctx := ctxT(w.t, 120*time.Second)
	id, link, err := from.dev.TransferCreate(ctx)
	if err != nil {
		w.t.Fatal(err)
	}
	b := w.aw.newApp(name, enclavetest.NewIOSAttester(seed, enclavetest.IOSOptions{}))
	if _, err := b.dev.PairAttested(ctx, link, b.att); err != nil {
		w.t.Fatal(err)
	}
	waitEvent(w.t, from.dev, "device.transfer.pending", has("transfer_id", id))
	if err := from.dev.TransferApprove(ctx, id, acPIN, credPW); err != nil {
		w.t.Fatal(err)
	}
	if err := b.dev.AwaitPaired(ctx); err != nil {
		w.t.Fatalf("new app: %v", err)
	}
	b.guid, b.vid = b.dev.UserGUID(), from.vid
	if err := b.dev.CredentialFetch(ctx); err != nil {
		w.t.Fatal(err)
	}
	return b
}

// finish is the new phone's "Finish the move" unlock.
func (w *tkWorld) finish(b *acApp) {
	w.t.Helper()
	w.aw.lock(b)
	if r := w.aw.mustUnlock(b, acPIN, client.UnlockOptions{}, ""); !r.OK {
		w.t.Fatalf("new app unlock: %+v", r)
	}
}

func (w *tkWorld) noKeyEvent() {
	w.t.Helper()
	if in, err := w.p.dev.WaitEvent(ctxT(w.t, 5*time.Second), "connection.authenticate.key", nil); err == nil {
		w.t.Fatalf("the peer was told of a key: %s", in.Body)
	}
}

// §11.14.10 "The owed mark": a credential.rotate while the transfer's
// statement is held sends K0→K1 and K1→K2 as one chain; the peer that
// pinned K0 follows it to K2, and the later unlock sends nothing more.
func TestTransferRotateWhileHeld(t *testing.T) {
	w := newTKWorld(t, 0x86)
	b := w.move(w.a, "new-phone-tk-b", 0x95)
	w.noKeyEvent()
	if err := b.dev.CredentialRotate(ctxT(t, 120*time.Second), credPW); err != nil {
		t.Fatal(err)
	}
	k2 := w.key(b.dev)
	waitEvent(t, w.p.dev, "connection.authenticate.key", has("key", k2))
	w.finish(b)
	w.noKeyEvent()
	if res := w.auth(b.dev); !strings.Contains(res, `"key_changed":false`) || !strings.Contains(res, k2) {
		t.Fatalf("K0→K2 not followed: %s", res)
	}
}

// Two transfers before the first new phone unlocked: both statements are
// held and go as one chain at the last phone's first unlock.
func TestDoubleTransferChain(t *testing.T) {
	w := newTKWorld(t, 0x87)
	b := w.move(w.a, "new-phone-tk-1", 0x96)
	k1 := w.key(b.dev)
	c := w.move(b, "new-phone-tk-2", 0x97)
	k2 := w.key(c.dev)
	if k1 == w.k0 || k2 == k1 {
		t.Fatal("the credential key did not rotate at each approval")
	}
	w.noKeyEvent()
	w.finish(c)
	waitEvent(t, w.p.dev, "connection.authenticate.key", has("key", k2))
	if res := w.auth(c.dev); !strings.Contains(res, `"key_changed":false`) || !strings.Contains(res, k2) {
		t.Fatalf("K0→K2 not followed: %s", res)
	}
}
