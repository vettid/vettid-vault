//go:build devenclave && e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/client"
	"github.com/vettid/vettid-vault/internal/relaytest"
	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/callwire"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// V4 batch 2, block (§7.4, §10.4) through the real relay: A blocks B (its
// connection.removed notice dropped by fault injection, so B keeps
// sending); the relay refuses B's deposits and B marks the connection
// stale; nothing reaches A. B's later attempt to connect through a new
// invite is refused by A's vault (the identity is blocked), and A cannot
// accept B's invitation either; after unblock a new connection works.
func TestBlockRefusesPeer(t *testing.T) {
	r := relaytest.Start(t, nil)
	var dropNotices atomic.Bool
	a := newTestVault(t, r.URL, "a", func(o *vault.Options) {
		o.Hooks.DropDeposit = func(e *vault.OutboxEntry) bool { return e.BestEffort && dropNotices.Load() }
	})
	b := newTestVault(t, r.URL, "b", nil)
	ctx := ctxT(t, 120*time.Second)
	aConn, bConn := connect(t, a, b, 600)
	id := sendText(t, b, b.app, bConn, "before")
	waitEvent(t, a.app, "message.new", has("message_id", id))

	dropNotices.Store(true)
	blockID, err := a.app.BlockConnection(ctx, aConn, "spam")
	if err != nil {
		t.Fatal(err)
	}
	waitEvent(t, a.app, "connection.event", has("event", "removed"))
	dropNotices.Store(false)

	// B's deposits are refused by the relay (token_revoked): stale.
	sendText(t, b, b.app, bConn, "after block")
	waitEvent(t, b.app, "connection.event", has("event", "stale"))
	for _, ev := range a.app.Events() {
		if ev.Type == "message.new" && has("text", "after block")(ev.Body) {
			t.Fatal("blocked peer's message delivered")
		}
	}
	bl, err := a.app.BlockList(ctx)
	if err != nil || !strings.Contains(string(bl["blocks"]), blockID) || !strings.Contains(string(bl["blocks"]), `"note":"spam"`) {
		t.Fatalf("block.list: %s %v", bl["blocks"], err)
	}

	// A new invite from A, accepted by B: A's vault refuses the blocked
	// identity's hs.init (audited), and asks nobody.
	inv := mustOK(t, a.request(a.app, "connection.invite.create", `{"ttl_seconds":3600}`))
	link, _ := inv.String("link")
	refused := mustOK(t, b.request(b.app, "connection.invite.accept", `{"link":"`+link+`"}`))
	refusedID, _ := refused.String("connection_id")
	deadline := time.Now().Add(30 * time.Second)
	for {
		au, err := a.app.AuditList(ctx, map[string]any{"kinds": []string{"drop.blocked"}}, false)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(au["entries"]), "drop.blocked") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("blocked identity's handshake not refused")
		}
		time.Sleep(500 * time.Millisecond)
	}
	for _, ev := range a.app.Events() {
		if ev.Type == "connection.request.pending" {
			t.Fatal("blocked identity reached the owner")
		}
	}
	// A blocked identity's own invitation is refused too.
	binv := mustOK(t, b.request(b.app, "connection.invite.create", `{"ttl_seconds":600}`))
	blink, _ := binv.String("link")
	if rr := a.request(a.app, "connection.invite.accept", `{"link":"`+blink+`"}`); rr.ErrorCode() != "blocked" {
		t.Fatalf("accepting a blocked identity's invite: %q", rr.ErrorCode())
	}

	// Unblock: a fresh connection (same relay keys) works again, through a
	// new invitation and approval (§7.4: tokens were denied by jti).
	if err := a.app.BlockRemove(ctx, blockID); err != nil {
		t.Fatal(err)
	}
	// B's refused request is still outgoing (waiting; it would fail after
	// 8 days): a new link from A is answered exists with its id, before
	// any hs.init (0.10.2), until B's member declines it.
	inv = mustOK(t, a.request(a.app, "connection.invite.create", `{"ttl_seconds":600}`))
	link, _ = inv.String("link")
	ex := b.request(b.app, "connection.invite.accept", `{"link":"`+link+`"}`)
	if ex.ErrorCode() != "exists" || field(t, ex.Body(), "connection_id") != refusedID {
		t.Fatalf("accept with an outgoing request: %q %s", ex.ErrorCode(), ex.Body())
	}
	rl := mustOK(t, b.request(b.app, "connection.request.list", `{}`))
	if !strings.Contains(string(rl["outgoing"]), refusedID) || !strings.Contains(string(rl["outgoing"]), `"state":"waiting"`) {
		t.Fatalf("request list: %s", rl["outgoing"])
	}
	mustOK(t, b.request(b.app, "connection.decline", `{"connection_id":"`+refusedID+`"}`))
	_, bConn2 := connect(t, a, b, 600)
	id = sendText(t, b, b.app, bConn2, "after unblock")
	waitEvent(t, a.app, "message.new", has("message_id", id))
}

// V4 batch 2, calls (§10.10) between two vaults through the real relay:
// offer with the caller's and the callee's own signed ICE configurations,
// ringing on the callee's app and desktop, the answer from the app (the
// desktop told answered_elsewhere), the media key agreed device to device,
// trickle ICE both ways (memory-only, ephemeral), and a hang-up reaching
// the other side's app.
func TestCallSignalling(t *testing.T) {
	r := relaytest.Start(t, nil)
	a := newTestVault(t, r.URL, "a", nil)
	b := newTestVault(t, r.URL, "b", nil)
	bDesk := pairDesktop(t, b, r.URL)
	ctx := ctxT(t, 120*time.Second)
	aConn, bConn := connect(t, a, b, 600)

	call, err := a.app.CallStart(ctx, aConn, "video", "v=0 offer")
	if err != nil {
		t.Fatal(err)
	}
	defer call.Destroy()
	ev := waitEvent(t, b.app, "call.offer", has("call_id", call.ID))
	if ev.Exp.IsZero() {
		t.Fatal("offer without exp")
	}
	in, err := b.app.IncomingCall(ev)
	if err != nil {
		t.Fatalf("callee's ICE config: %v", err)
	}
	if in.Conn != bConn {
		t.Fatal("offer names the wrong connection")
	}
	waitEvent(t, bDesk, "call.offer", has("call_id", call.ID))
	if err := b.app.CallRinging(ctx, call.ID); err != nil {
		t.Fatal(err)
	}
	waitEvent(t, a.app, "call.ringing", has("call_id", call.ID))

	if err := b.app.CallAnswer(ctx, in, "v=0 answer"); err != nil {
		t.Fatal(err)
	}
	ans := waitEvent(t, a.app, "call.answer", has("call_id", call.ID))
	sdp, err := a.app.CallAccept(call, ans)
	if err != nil || sdp != "v=0 answer" {
		t.Fatalf("accept: %q %v", sdp, err)
	}
	if !bytes.Equal(call.Key, in.Key) || len(call.Key) != 32 {
		t.Fatal("devices derived different media keys")
	}
	waitEvent(t, bDesk, "call.end", has("reason", "answered_elsewhere"))

	cand := []map[string]any{{"candidate": "candidate:1 1 udp 2122260223 192.0.2.10 54321 typ host", "sdp_mid": "0", "sdp_mline_index": 0}}
	if err := a.app.CallICE(ctx, call.ID, cand); err != nil {
		t.Fatal(err)
	}
	ice := waitEvent(t, b.app, "call.ice", has("call_id", call.ID))
	if ice.Exp.IsZero() || !strings.Contains(string(ice.Body), "192.0.2.10") {
		t.Fatalf("ICE at the callee: %s", ice.Body)
	}
	if err := b.app.CallICE(ctx, call.ID, cand); err != nil {
		t.Fatal(err)
	}
	waitEvent(t, a.app, "call.ice", has("call_id", call.ID))

	if err := a.app.CallEnd(ctx, call.ID, "hangup"); err != nil {
		t.Fatal(err)
	}
	waitEvent(t, b.app, "call.end", has("reason", "hangup"))
	for _, tv := range []*testVault{a, b} {
		l := mustOK(t, tv.request(tv.app, "call.list", `{}`))
		if !strings.Contains(string(l["calls"]), call.ID) || !strings.Contains(string(l["calls"]), `"state":"ended"`) {
			t.Fatalf("%s history: %s", tv.name, l["calls"])
		}
	}
	au, err := b.app.AuditList(ctx, map[string]any{"kinds": []string{"call"}}, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"call.incoming", "call.answered", "call.ended"} {
		if !strings.Contains(string(au["entries"]), `"`+k+`"`) {
			t.Errorf("callee audit lacks %s", k)
		}
	}

	// A second call that the caller abandons is a missed call for B.
	c2, err := a.app.CallStart(ctx, aConn, "audio", "v=0")
	if err != nil {
		t.Fatal(err)
	}
	waitEvent(t, b.app, "call.offer", has("call_id", c2.ID))
	if err := a.app.CallEnd(ctx, c2.ID, "timeout"); err != nil {
		t.Fatal(err)
	}
	waitEvent(t, b.app, "feed.event", has("kind", "call.missed"))
}

// V4 batch 2, access sessions (§6.8) through the real relay: a desktop
// paired without a session is refused; it requests one, an app approves;
// a secret item revealed from the desktop is held until an app approves it; the
// app ends the session and the desktop is refused again. An agent gets
// nothing beyond its listed types (no LEASH yet).
func TestDesktopSession(t *testing.T) {
	r := relaytest.Start(t, nil)
	a := newTestVault(t, r.URL, "a", nil)
	ctx := ctxT(t, 120*time.Second)
	desk := pairDevice(t, a, r.URL, vault.KindDesktop, 0)
	if rr := a.request(desk, "connection.list", `{}`); rr.ErrorCode() != "session_required" {
		t.Fatalf("no session: %q", rr.ErrorCode())
	}
	mustOK(t, a.request(desk, "vault.status", `{}`))

	reqID, err := desk.SessionRequest(ctx, 600)
	if err != nil {
		t.Fatal(err)
	}
	pend := waitEvent(t, a.app, "device.session.pending", has("request_id", reqID))
	if field(t, pend.Body, "role") != vault.KindDesktop || field(t, pend.Body, "device_id") != desk.DeviceID() {
		t.Fatalf("pending: %s", pend.Body)
	}
	if _, err := a.app.SessionApprove(ctx, reqID, 0); err != nil {
		t.Fatal(err)
	}
	waitEvent(t, desk, "device.session.granted", nil)
	mustOK(t, a.request(desk, "connection.list", `{}`))
	dl := mustOK(t, a.request(a.app, "device.list", `{}`))
	if !strings.Contains(string(dl["devices"]), "session_expires_at") {
		t.Fatalf("device.list: %s", dl["devices"])
	}

	// Step-up: the desktop's item.reveal waits for the app's approval.
	sid, _, err := a.app.ItemPut(ctx, "", 0, "secret", nil, client.ItemContent{Name: "wifi",
		Fields: []client.ItemField{{Label: "Password", Kind: "password", Value: "hunter22"}}})
	if err != nil {
		t.Fatal(err)
	}
	type res struct {
		r   *client.Response
		err error
	}
	done := make(chan res, 1)
	go func() {
		rr, err := desk.Request(ctxT(t, 60*time.Second), "item.reveal", json.RawMessage(`{"item_id":"`+sid+`"}`))
		done <- res{rr, err}
	}()
	ap := waitEvent(t, a.app, "approval.pending", has("type", "item.reveal"))
	if field(t, ap.Body, "device_id") != desk.DeviceID() {
		t.Fatal("approval names the wrong device")
	}
	result, err := a.app.ApprovalDecide(ctx, field(t, ap.Body, "approval_id"), true)
	if err != nil || result != "ok" {
		t.Fatalf("decide: %q %v", result, err)
	}
	got := <-done
	if got.err != nil || !got.r.OK() || !strings.Contains(string(got.r.Body()), "hunter22") {
		t.Fatalf("held item.reveal: %v %+v", got.err, got.r)
	}
	if ws := waitEvent(t, desk, "approval.waiting", nil); field(t, ws.Body, "approval_id") != field(t, ap.Body, "approval_id") {
		t.Fatal("approval.waiting names another approval")
	}

	// The app ends the session.
	if err := a.app.SessionEnd(ctx, desk.DeviceID()); err != nil {
		t.Fatal(err)
	}
	waitEvent(t, desk, "device.session.ended", has("reason", "ended"))
	if rr := a.request(desk, "connection.list", `{}`); rr.ErrorCode() != "session_required" {
		t.Fatalf("after end: %q", rr.ErrorCode())
	}

	// An agent, even with a session, may not act beyond its types.
	agent := pairDevice(t, a, r.URL, vault.KindAgent, 600)
	if rr := a.request(agent, "settings.get", `{}`); rr.ErrorCode() != "forbidden" {
		t.Fatalf("agent settings.get: %q", rr.ErrorCode())
	}
	st := mustOK(t, a.request(agent, "vault.status", `{}`))
	if _, err := st.String("vault_id"); err != nil {
		t.Fatal("agent vault.status")
	}
	au, err := a.app.AuditList(ctx, map[string]any{"kinds": []string{"device.session", "approval"}}, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"device.session.granted", "approval.granted", "device.session.ended"} {
		if !strings.Contains(string(au["entries"]), `"`+k+`"`) {
			t.Errorf("audit lacks %s", k)
		}
	}
}

// V4 batch 2, member authentication (§10.4): A asks B's member; B's app
// opens the credential unlock window and approves; A verifies the
// signature by B's credential key and pins it.
func TestConnectionAuthenticate(t *testing.T) {
	r := relaytest.Start(t, nil)
	a := newTestVault(t, r.URL, "a", nil)
	b := newTestVault(t, r.URL, "b", nil)
	ctx := ctxT(t, 120*time.Second)
	aConn, _ := connect(t, a, b, 600)
	reqID, err := a.app.AuthRequest(ctx, aConn, "prove it")
	if err != nil {
		t.Fatal(err)
	}
	pend := waitEvent(t, b.app, "connection.authenticate.pending", has("request_id", reqID))
	if field(t, pend.Body, "context") != "prove it" {
		t.Fatal("context")
	}
	if err := b.app.AuthApprove(ctx, reqID); client.Code(err) != "credential_locked" {
		t.Fatalf("approve without the unlock window: %v", err)
	}
	if _, err := b.app.CredentialUnlock(ctx, credPW); err != nil {
		t.Fatal(err)
	}
	if err := b.app.AuthApprove(ctx, reqID); err != nil {
		t.Fatal(err)
	}
	res := waitEvent(t, a.app, "connection.authenticate.result", has("request_id", reqID))
	o, _ := strictjson.ParseObject(res.Body)
	if ok, _ := o.Bool("authenticated"); !ok {
		t.Fatalf("result: %s", res.Body)
	}
	v, err := b.app.CredentialVersion(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if key, _ := v.String("key"); key != field(t, res.Body, "key") {
		t.Fatal("signed by a key other than B's credential key")
	}
	l := mustOK(t, a.request(a.app, "connection.authenticate.list", `{}`))
	if !strings.Contains(string(l["states"]), `"last_result":"authenticated"`) {
		t.Fatalf("list: %s", l["states"])
	}

	// B rotates its credential: the statement (signed by the old and the
	// new key) reaches A, which follows it; the next authentication is no
	// key change.
	if err := b.app.CredentialRotate(ctx, credPW); err != nil {
		t.Fatal(err)
	}
	v, _ = b.app.CredentialVersion(ctx)
	newKey, _ := v.String("key")
	waitEvent(t, a.app, "connection.authenticate.key", has("key", newKey))
	authOnce := func() json.RawMessage {
		t.Helper()
		id, err := a.app.AuthRequest(ctx, aConn, "again")
		if err != nil {
			t.Fatal(err)
		}
		waitEvent(t, b.app, "connection.authenticate.pending", has("request_id", id))
		if _, err := b.app.CredentialUnlock(ctx, credPW); err != nil {
			t.Fatal(err)
		}
		if err := b.app.AuthApprove(ctx, id); err != nil {
			t.Fatal(err)
		}
		return waitEvent(t, a.app, "connection.authenticate.result", has("request_id", id)).Body
	}
	if res := authOnce(); !strings.Contains(string(res), `"key_changed":false`) || !strings.Contains(string(res), newKey) {
		t.Fatalf("rotation not followed: %s", res)
	}
	// A new credential without a rotation statement (delete and create):
	// the key change is reported.
	if err := b.app.CredentialDelete(ctx, credPW); err != nil {
		t.Fatal(err)
	}
	if err := b.app.CredentialCreate(ctx, credPW); err != nil {
		t.Fatal(err)
	}
	if res := authOnce(); !strings.Contains(string(res), `"key_changed":true`) {
		t.Fatalf("unsigned key change not reported: %s", res)
	}
}

// V4 batch 2, calls on the desktop (§6.8, §10.10) through the real relay:
// a desktop within its access session places a call to a peer's phone and
// answers an incoming one (first answer wins over the app; the late answer
// is refused); a desktop without a session does not ring and cannot call;
// a key-exchange share the device did not sign is refused.
func TestDesktopCalls(t *testing.T) {
	r := relaytest.Start(t, nil)
	a := newTestVault(t, r.URL, "a", nil)
	b := newTestVault(t, r.URL, "b", nil)
	desk := pairDesktop(t, a, r.URL)
	idle := pairDevice(t, a, r.URL, vault.KindDesktop, 0) // no access session
	ctx := ctxT(t, 120*time.Second)
	aConn, bConn := connect(t, a, b, 600)

	// The desktop calls B's phone.
	c, err := desk.CallStart(ctx, aConn, "video", "v=0 desk")
	if err != nil {
		t.Fatal(err)
	}
	ev := waitEvent(t, b.app, "call.offer", has("call_id", c.ID))
	if field(t, ev.Body, "media") != "video" {
		t.Fatal("media flag")
	}
	in, err := b.app.IncomingCall(ev)
	if err != nil {
		t.Fatalf("phone cannot verify the desktop's offer: %v", err)
	}
	if err := b.app.CallAnswer(ctx, in, "v=0 phone"); err != nil {
		t.Fatal(err)
	}
	if _, err := desk.CallAccept(c, waitEvent(t, desk, "call.answer", has("call_id", c.ID))); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(c.Key, in.Key) {
		t.Fatal("desktop and phone keys differ")
	}
	if err := desk.CallEnd(ctx, c.ID, "hangup"); err != nil {
		t.Fatal(err)
	}
	waitEvent(t, b.app, "call.end", has("call_id", c.ID))

	// B calls A: A's app and session desktop ring; the desktop answers
	// first; the app is told answered_elsewhere and its late answer is
	// refused; the idle desktop never rings.
	bc, err := b.app.CallStart(ctx, bConn, "audio", "v=0 b")
	if err != nil {
		t.Fatal(err)
	}
	evApp := waitEvent(t, a.app, "call.offer", has("call_id", bc.ID))
	evDesk := waitEvent(t, desk, "call.offer", has("call_id", bc.ID))
	inDesk, err := desk.IncomingCall(evDesk)
	if err != nil {
		t.Fatal(err)
	}
	inApp, err := a.app.IncomingCall(evApp)
	if err != nil {
		t.Fatal(err)
	}
	if err := desk.CallAnswer(ctx, inDesk, "v=0 desk answer"); err != nil {
		t.Fatal(err)
	}
	if _, err := b.app.CallAccept(bc, waitEvent(t, b.app, "call.answer", has("call_id", bc.ID))); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bc.Key, inDesk.Key) {
		t.Fatal("keys differ")
	}
	waitEvent(t, a.app, "call.end", has("reason", "answered_elsewhere"))
	if err := a.app.CallAnswer(ctx, inApp, "v=0 late"); err != nil {
		t.Fatal(err)
	}
	waitEvent(t, a.app, "call.end", has("reason", "unavailable"))
	if err := b.app.CallEnd(ctx, bc.ID, "hangup"); err != nil {
		t.Fatal(err)
	}
	waitEvent(t, desk, "call.end", has("reason", "hangup"))
	short, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if _, err := idle.WaitEvent(short, "call.offer", nil); err == nil {
		t.Fatal("a desktop without a session rang")
	}
	if _, err := idle.CallStart(ctx, aConn, "audio", "v=0"); client.Code(err) != "session_required" {
		t.Fatalf("call.start without a session: %v", err)
	}

	// A share the device did not sign (another ek under its signature).
	sk, _ := callwire.NewOfferKey()
	other, _ := callwire.NewOfferKey()
	cid, _ := envelope.NewULID(time.Now())
	esig, _ := callwire.SignShare(featuretestKey(t), callwire.ShareMessage(callwire.RoleOffer, cid, "audio", sk.Public().Bytes()))
	body, _ := json.Marshal(map[string]any{"connection_id": aConn, "call_id": cid, "media": "audio", "sdp": "v=0",
		"ek": other.Public().Bytes(), "ek_sig": esig})
	if rr := a.request(desk, "call.start", string(body)); rr.ErrorCode() != "bad_request" {
		t.Fatalf("unsigned share: %q", rr.ErrorCode())
	}
}

// featuretestKey is some key that is not the desktop's.
func featuretestKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, 32))
}
