package vault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"
	"github.com/vettid/vettid-relay/relayclient"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/peerwire"
)

// Gap F, pinned (VAULT-MESSAGING 0.87.1 §3.4.1 Invariants, "The device
// exception"; §6.3.1 "Initiator": "A vault toward its device or agent
// rekeys from its current epoch instead, also at B with no valid token").
// The vault rekeys toward a desktop, which activates E1 at hs.fin; the
// desktop's hs.confirm is lost and the vault's standing token for it
// expires. The vault abandons E1 for want of a valid standing token
// (§6.3.1 "Initiator", R29-I6) and rekeys from E0, a rekey it cannot
// deposit (refused token_expired, it waits for a token); it neither makes the device stale nor reconnects; after 16
// days it no longer opens E1, while the device stays on E1; the member is
// shown nothing. This is today's behaviour, a stated gap of release 29:
// flip this test when the post-29 device work fixes it.

// gapF is the in-process desktop: its keys and the epochs it holds.
type gapF struct {
	t     *testing.T
	d     *devFixture
	td    *tdev
	clk   time.Time
	ik    ed25519.PrivateKey
	relay ed25519.PrivateKey
	e0    *handshake.Epoch // device side
	e1    *handshake.Epoch
	sink  *recSink
	n     int
}

func newGapF(t *testing.T) *gapF {
	t.Helper()
	d := newDevFixture(t)
	g := &gapF{t: t, d: d, clk: time.Now().UTC().Truncate(time.Millisecond)}
	d.m.now = func() time.Time { return g.clk }
	g.sink = sinkOf(d)
	const seed = 0x51
	g.td = d.addDevice(t, "desk1", KindDesktop, seed)
	g.ik = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
	g.relay = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed + 1}, 32))
	g.e0 = g.td.ep
	g.take()
	return g
}

func (g *gapF) vaultRelay() ed25519.PublicKey { return g.d.m.keys.relay.Public().(ed25519.PublicKey) }

// take removes and returns the vault's deposits to the desktop.
func (g *gapF) take() [][]byte {
	g.d.relay.mu.Lock()
	defer g.d.relay.mu.Unlock()
	var out [][]byte
	kept := g.d.relay.deposits[:0]
	for _, dep := range g.d.relay.deposits {
		if dep.mailbox == g.td.peer.Relay.Mailbox {
			out = append(out, dep.payload)
			continue
		}
		kept = append(kept, dep)
	}
	g.d.relay.deposits = kept
	return out
}

// drain flushes the vault and drains its outbox.
func (g *gapF) drain() {
	g.d.withLock(func(m *Manager) {
		if err := m.flushThenDrain(context.Background()); err != nil {
			g.t.Fatal(err)
		}
	})
}

// fromDevice hands the vault one deposit from the desktop.
func (g *gapF) fromDevice(raw []byte) {
	g.n++
	msg := Message{MsgID: fmt.Sprintf("gf%d", g.n), Sender: relayauth.EncodeKey(g.relay.Public().(ed25519.PublicKey)), Payload: raw}
	if err := g.d.m.ProcessBatch(context.Background(), &fakeCollector{}, []Message{msg}); err != nil {
		g.t.Fatal(err)
	}
}

// sendUnder seals a message from the desktop under ep.
func (g *gapF) sendUnder(ep *handshake.Epoch, typ string, body []byte) {
	id, _ := envelope.NewULID(g.clk)
	raw, err := ep.Seal(&envelope.Inner{ID: id, Type: typ, TS: g.clk, Body: body, Features: []string{handshake.CapConfirm}})
	if err != nil {
		g.t.Fatal(err)
	}
	g.fromDevice(raw)
}

// answerRekey: the desktop answers the vault's rekey hs.init (sealed under
// ep) among deposits and returns its responder state.
func (g *gapF) answerRekey(deps [][]byte, ep *handshake.Epoch) *handshake.Responder {
	g.t.Helper()
	var kr handshake.Keyring
	kr.Activate(ep, g.clk)
	for _, raw := range deps {
		env, err := envelope.Parse(raw)
		if err != nil || env.Mode() != envelope.ModeSession {
			continue
		}
		in, _, err := kr.Open(env, g.clk)
		if err != nil || in.Type != handshake.TypeInit {
			continue
		}
		pi, err := handshake.AcceptRekey(raw, in, ep, g.clk)
		if err != nil {
			g.t.Fatal(err)
		}
		resp, renv, err := pi.Respond(handshake.ResponderConfig{Identity: g.ik, Policy: handshake.PolicyVaultToDevice,
			CollectSender: g.vaultRelay(), RecordRelayKey: g.vaultRelay(), KnownInitiatorIK: g.d.m.keys.ik.Public().(ed25519.PublicKey),
			Now: g.clk, Features: []string{handshake.CapConfirm}})
		if err != nil {
			g.t.Fatal(err)
		}
		g.fromDevice(renv)
		return resp
	}
	g.t.Fatal("no rekey hs.init to the desktop")
	return nil
}

// finish: the desktop takes the vault's hs.fin and activates the epoch.
func (g *gapF) finish(resp *handshake.Responder) *handshake.Epoch {
	g.t.Helper()
	for _, raw := range g.take() {
		if fr, err := resp.HandleFin(raw, g.vaultRelay(), g.clk); err == nil {
			return fr.Epoch
		}
	}
	g.t.Fatal("no hs.fin to the desktop")
	return nil
}

func (g *gapF) feedShown() bool {
	for _, a := range g.sink.got {
		if a.Feed {
			return true
		}
	}
	return false
}

// setup runs the gap up to the abandonment: E1 active at the desktop,
// pending at the vault, the hs.confirm lost; the standing token expired,
// so the vault's next batch abandons E1 and rekeys from E0, whose hs.init
// the relay refuses token_expired.
func (g *gapF) setup() (e1ID []byte) {
	g.t.Helper()
	p := g.td.peer
	g.d.withLock(func(m *Manager) { m.startRekey(p, g.clk) })
	g.drain()
	resp := g.answerRekey(g.take(), g.e0)
	if p.Pending == nil {
		g.t.Fatal("setup: no pending epoch at the vault")
	}
	e1ID = append([]byte(nil), p.Pending.ID...)
	g.e1 = g.finish(resp) // the desktop activates E1; its hs.confirm is lost
	g.clk = g.clk.Add(21 * 24 * time.Hour)
	if g.clk.Before(p.Standing.Exp) {
		g.t.Fatal("setup: the standing token has not expired")
	}
	g.d.relay.mu.Lock()
	g.d.relay.failMailbox = map[string]error{p.Relay.Mailbox: &relayclient.Error{Status: 401, Code: CodeTokenExpired}}
	g.d.relay.mu.Unlock()
	if err := g.d.m.ProcessBatch(context.Background(), &fakeCollector{}, nil); err != nil {
		g.t.Fatal(err)
	}
	g.drain()
	if !g.d.audited("pending_abandoned_no_token") {
		g.t.Fatal("setup: E1 was not abandoned for want of a token")
	}
	return e1ID
}

func (g *gapF) assertAbandonedWaiting(e1ID []byte) {
	g.t.Helper()
	p := g.td.peer
	if p.Pending != nil {
		g.t.Fatal("the vault did not abandon E1")
	}
	if e := p.epochMeta(e1ID); e == nil || !e.Abandoned {
		g.t.Fatal("E1 is not recorded abandoned")
	}
	var rekey *OutgoingHS
	for _, og := range g.d.m.st.Outgoing {
		if og.PeerID == p.ID && og.Purpose == handshake.PurposeRekey {
			rekey = og
		}
		if og.PeerID == p.ID && og.Purpose == handshake.PurposeReconnect {
			g.t.Fatal("the vault reconnects to a device")
		}
	}
	if rekey == nil {
		g.t.Fatal("no rekey from the current epoch")
	}
	// Its hs.init, refused token_expired, waits in the outbox
	// (AwaitToken): undeposited until a fresh token arrives.
	waiting, awaiting := false, false
	for _, e := range g.d.m.st.Outbox {
		waiting = waiting || e.ID == rekey.InitOutbox && !e.Done
		awaiting = awaiting || e.PeerID == p.ID && !e.Done && e.AwaitToken
	}
	if !waiting || !awaiting {
		g.t.Fatal("the rekey's hs.init is not waiting for a token")
	}
	if len(g.take()) != 0 {
		g.t.Fatal("something was deposited to the desktop without a token")
	}
	if p.State != PeerActive || g.feedShown() {
		g.t.Fatal("the device was made stale, or the member was shown something")
	}
}

func TestR29GapFDeviceStuckAfterAbandon(t *testing.T) {
	g := newGapF(t)
	e1ID := g.setup()
	g.assertAbandonedWaiting(e1ID)
	// 16 days on, the vault's keys for E1 have ended; the desktop is on E1.
	g.clk = g.clk.Add(handshake.ReceiveKeyRetention + time.Hour)
	if err := g.d.m.ProcessBatch(context.Background(), &fakeCollector{}, nil); err != nil {
		t.Fatal(err)
	}
	before := len(g.d.m.st.Audit)
	g.sendUnder(g.e1, "vault.status", []byte(`{}`))
	opened := true
	for _, a := range g.d.m.st.Audit[before:] {
		if a.Event == "unknown_kid" {
			opened = false
		}
	}
	if opened {
		t.Fatal("the vault still opens E1 after 16 days")
	}
	if len(g.take()) != 0 {
		t.Fatal("the desktop received something: it is not stuck on E1")
	}
	if g.td.peer.State != PeerActive || g.feedShown() {
		t.Fatal("the member was shown something, or the device state changed")
	}
}

// Within the 16 days a fresh standing token from the desktop (under E1,
// processed without confirming it) lets the waiting rekey go; the desktop
// answers it from E0, and the pair converges on E2.
func TestR29GapFFreshTokenConverges(t *testing.T) {
	g := newGapF(t)
	e1ID := g.setup()
	g.assertAbandonedWaiting(e1ID)
	g.clk = g.clk.Add(time.Hour)
	g.d.relay.mu.Lock()
	g.d.relay.failMailbox = nil
	g.d.relay.mu.Unlock()
	rc := relayclient.New(g.td.peer.Relay.URL, g.relay)
	tok, err := rc.MintToken(relayauth.EncodeKey(g.vaultRelay()), g.td.peer.Relay.URL, relayclient.TokenOptions{TTL: 60 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	g.sendUnder(g.e1, peerwire.TypeTokenIssued, peerwire.TokenIssuedBody(TokStanding, tok))
	if !g.td.peer.Standing.Exp.After(g.clk) {
		t.Fatal("setup: the fresh token was not stored")
	}
	g.drain()
	resp := g.answerRekey(g.take(), g.e0)
	e2 := g.finish(resp)
	g.sendUnder(e2, handshake.TypeConfirm, []byte(`{}`))
	id := e2.ID()
	if g.td.peer.Pending != nil || !bytes.Equal(g.td.peer.LastEpochID, id[:]) {
		t.Fatal("the pair did not converge on the new epoch")
	}
	if g.td.peer.State != PeerActive || g.feedShown() {
		t.Fatal("the member was shown something, or the device state changed")
	}
}
