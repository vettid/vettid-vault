package vault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"
	"github.com/vettid/vettid-relay/relayclient"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/suite"
)

// The lead's review of #206 at ffec32a and its spec review (0.86.6, part
// 2): one test per change, each failing without it.

// restart locks side s and unlocks it again from its store (the relay
// outlives it).
func (f *r29Fx) restart(s int) {
	f.t.Helper()
	d := f.d[s]
	old := d.relay
	if err := d.m.Lock(context.Background()); err != nil {
		f.t.Fatal(err)
	}
	m, _, err := d.unlock(testPIN, 0, 0)
	if err != nil {
		f.t.Fatal(err)
	}
	d.m = m
	old.mu.Lock()
	d.relay.mu.Lock()
	d.relay.deposits, d.relay.revoked, d.relay.claims, d.relay.blobs = old.deposits, old.revoked, old.claims, old.blobs
	d.relay.now, d.relay.check, d.relay.checkPayload = old.now, old.check, old.checkPayload // the scenario's clock and relay checks (0.88.2)
	d.relay.mu.Unlock()
	old.mu.Unlock()
	m.now = func() time.Time { return f.clk }
	m.register(TypeSpec{Type: "test.note", From: []string{KindConnection}, Connections: PeersBoth},
		HandlerFunc(func(_ context.Context, _ *Session, in *envelope.Inner) (json.RawMessage, error) {
			f.got[s] = append(f.got[s], string(in.Body))
			return nil, nil
		}))
	m.features = append(m.features, f.sink[s])
}

func (f *r29Fx) jtisOf(ts []IssuedToken) []string {
	var out []string
	for _, t := range ts {
		out = append(out, t.JTI)
	}
	return out
}

func (f *r29Fx) denied(s int, jti string) bool {
	for _, it := range f.m(s).st.Issued {
		if it.JTI == jti && it.Denied {
			return true
		}
	}
	return false
}

// Code 4: rule E drops an hs.fin of the vault's own for an epoch it
// destroys, not yet sent.
func TestR29RuleEDropsUnsentFin(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	var entry *OutboxEntry
	f.do(0, func(m *Manager, p *Peer) {
		ghost := bytes.Repeat([]byte{0x77}, suite.EpochIDSize)
		p.Epochs = append(p.Epochs, EpochMeta{ID: ghost, Signer: p.IK, Mine: true})
		entry = &OutboxEntry{PeerID: p.ID, RelayURL: p.Relay.URL, Mailbox: p.Relay.Mailbox, Payload: []byte("x"), Handshake: true, FinEpoch: ghost}
		m.queueDeposit(entry, f.clk)
		m.unstored[entry.ID] = true // not yet sent
		m.ruleE(p, f.clk, f.clk)
	})
	if !entry.Done {
		t.Fatal("rule E left an unsent hs.fin for the epoch it destroyed")
	}
}

// Code 2: held entries are done at stale and at removal; after stale, a
// new invitation to the same peer connects (the hold is by peer, not by
// mailbox, so the first contact is not held behind them).
func TestR29HeldAtStaleAndNewInvitation(t *testing.T) {
	f := demoted(t, nil)
	f.note(0, "held")
	f.do(0, func(m *Manager, p *Peer) { m.markStale(p, f.clk) })
	for _, e := range f.m(0).st.Outbox {
		if e.Held != nil && !e.Done {
			t.Fatal("a held entry survived stale")
		}
	}
	// side 1's member removes the connection (its record is active), then
	// invites again; side 0 accepts with its stale record.
	f.do(1, func(m *Manager, p *Peer) { m.removePeer(p, "", f.clk) })
	f.lose(1, 0, kAny)
	a, b := f.d[1], f.d[0]
	_, link := a.linkFor(t, time.Hour)
	r, _ := b.request(t, "connection.invite.accept", `{"link":"`+link+`"}`)
	cid := bodyStr(t, r, "connection_id")
	pump(t, b, a)
	pump(t, a, b)
	b.appInbox()
	pump(t, b, a)
	aPend := event(a.appInbox(), "connection.request.pending")
	if aPend == nil {
		t.Fatal("the new invitation's request did not arrive")
	}
	a.request(t, "connection.approve", `{"pending_id":"`+bodyStr(t, aPend, "pending_id")+`"}`)
	pump(t, a, b)
	b.request(t, "connection.approve", `{"connection_id":"`+cid+`"}`)
	pump(t, b, a)
	if p := b.m.st.Connections[cid]; p == nil || p.State != PeerActive {
		t.Fatal("the new invitation did not connect")
	}
}

func TestR29HeldAtRemoval(t *testing.T) {
	f := demoted(t, nil)
	f.note(0, "held")
	f.do(0, func(m *Manager, p *Peer) { m.removePeer(p, "", f.clk) })
	for _, e := range f.m(0).st.Outbox {
		if e.Held != nil && !e.Done {
			t.Fatal("a held entry survived removal")
		}
	}
}

// Code 3: an hs.resp that aborts (sig_R fails after it decrypted) revokes
// the tokens the hs.init carried, for any handshake (not only a new
// connection's); S5: a refused reconnect does not make it stale.
func TestR29AbortRevokesTokens(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	var og *OutgoingHS
	f.do(0, func(m *Manager, p *Peer) { og = m.startReconnectCtx(p, p.LastEpochID, f.clk) })
	jtis := f.jtisOf(og.Issued)
	f.m(0).mu.Lock()
	_ = f.m(0).flushThenDrain(context.Background())
	f.m(0).mu.Unlock()
	var raw []byte
	f.d[0].relay.mu.Lock()
	for _, d := range f.d[0].relay.deposits {
		if env, err := envelope.Parse(d.payload); err == nil && env.Mode() == envelope.ModeSealed && f.m(1).lookupKEM(env.RecipientKid()) != nil {
			raw = d.payload
		}
	}
	f.d[0].relay.deposits = nil
	f.d[0].relay.mu.Unlock()
	pi, err := handshake.OpenInit(raw, f.m(1).lookupKEM, f.clk)
	if err != nil {
		t.Fatal(err)
	}
	wrong := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x5a}, 32))
	var tok, rt string
	f.do(1, func(m *Manager, p *Peer) {
		tok, _, _ = m.mintStanding(p, f.clk, nil)
		rt, _, _ = m.mintReconnect(p, f.clk, nil)
	})
	_, env, err := pi.Respond(handshake.ResponderConfig{Identity: wrong, Policy: handshake.PolicyVaultToVault, Token: tok, ReconnectToken: rt,
		CollectSender: f.pk(0), RecordRelayKey: f.pk(0), KnownInitiatorIK: f.p(1).IK, ExpectedCtx: pi.Init().Ctx, Now: f.clk})
	if err != nil {
		t.Fatal(err)
	}
	jti := ""
	for _, it := range f.m(0).st.Issued {
		if it.PeerID == f.id[0] && it.Kind == TokStanding && !it.Denied {
			jti = it.JTI
		}
	}
	msg := Message{MsgID: "forged-resp", Sender: relayauth.EncodeKey(f.pk(1)), JTI: jti, Payload: env}
	if err := f.m(0).ProcessBatch(context.Background(), &fakeCollector{}, []Message{msg}); err != nil {
		t.Fatal(err)
	}
	if !f.audited(0, "hs_resp_aborted") {
		t.Fatal("setup: no abort")
	}
	for _, j := range jtis {
		if !f.denied(0, j) {
			t.Fatal("an aborted reconnect's token was not revoked")
		}
	}
	if f.p(0).State == PeerStale {
		t.Fatal("a refused reconnect made the connection stale (0.86.6 S5)")
	}
}

// Code 5: a refused rekey's links are not recorded as seen (only once it
// passed rekeyPrecheck), and Seen is capped.
func TestR29SeenOnlyAfterPrecheckAndCapped(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	f.rotate(1)
	link := parseRotations(f.m(1).st.Rotations)
	f.lose(1, 0, kAny)
	f.do(1, func(m *Manager, p *Peer) {
		forged := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x6b}, 32))
		ini, err := handshake.NewInitiator(handshake.InitiatorConfig{Purpose: handshake.PurposeRekey, Identity: forged,
			StaticKEM: m.keys.kem.Public(), Relay: m.ownAddr(), ResponderIK: p.IK, ResponderRelayKey: p.Relay.PK,
			Current: m.sessions[p.ID].Current(), Policy: policyFor(p.Kind), Now: f.clk, Rotations: link})
		if err != nil {
			t.Fatal(err)
		}
		m.queueDeposit(&OutboxEntry{PeerID: p.ID, RelayURL: p.Relay.URL, Mailbox: p.Relay.Mailbox, Payload: ini.Envelope()}, f.clk)
	})
	f.deliver(1, 0, kHSInit)
	if !f.audited(0, "rekey_rejected") || len(f.p(0).Seen) != 0 {
		t.Fatalf("a refused rekey's link recorded as seen (%d)", len(f.p(0).Seen))
	}
	// the cap: a chain of links from the current ik, longer than MaxSeen
	m := f.m(0)
	p := f.p(0)
	prev := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x01}, 32))
	p.IK = prev.Public().(ed25519.PublicKey)
	for i := 0; i < MaxSeen+5; i++ {
		next := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{byte(i + 2)}, 32))
		kem, _ := suite.NewPrivateKey(bytes.Repeat([]byte{byte(i + 2)}, 32))
		r, err := handshake.NewRotation(prev, next, kem.Public())
		if err != nil {
			t.Fatal(err)
		}
		m.rotationConflict(p, r, f.clk)
		prev = next
	}
	if len(p.Seen) != MaxSeen {
		t.Fatalf("Seen holds %d links (cap %d)", len(p.Seen), MaxSeen)
	}
}

// §3.4.1 "Pending epochs at a link" with R29-K9 (the K2 case): a pending
// epoch abandoned by the link of P's identity.rotate is judged by K9 in the
// same write and, its flag clear, ended (audited, no feed item), not
// demoted: a later message under it (here from P's old copy) suspends.
// One abandoned otherwise processes them without confirming it
// (TestR29ReviewAbandonedPendingDoesNotConfirm).
func TestR29LinkAbandonedPendingEnded(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	f.rekey(0)
	f.deliver(0, 1, kHSInit)
	snap := f.snapshot(1) // holds the answer
	f.rotate(1)           // S5: the real side 1 drops it
	f.deliver(1, 0, kHSResp)
	e1 := append([]byte(nil), f.p(0).Pending.ID...)
	f.deliver(1, 0, kRotate) // side 0 follows: its pending epoch abandoned by the link, then ended (K9)
	if f.p(0).Pending != nil {
		t.Fatal("setup: still pending")
	}
	if e := f.p(0).epochMeta(e1); e == nil || !e.Ended || e.Demoted {
		f.dump()
		t.Fatal("the epoch abandoned by the identity.rotate's link was not ended (or was demoted)")
	}
	if !f.activity(0, "connection.fork_suspected", "epoch") || f.p(0).suspended() || f.forkFeed(0) {
		t.Fatal("no fork_suspected audit, or suspended or a feed item at the link")
	}
	f.startCopy(1, snap)
	f.deliver(0, 2, kHSFin)
	f.note(2, "copy-under-abandoned")
	f.deliver(2, 0, kNote)
	if f.arrived(0, "copy-under-abandoned") != 0 || !f.suspendedRef(0, "epoch") {
		f.dump()
		t.Fatal("a message under a pending epoch ended at identity.rotate did not suspend")
	}
}

// S6: a verified hs.fin comes first whatever the purposes: the vault's own
// open reconnect is abandoned when the peer's rekey it answered finishes.
func TestR29FinFirstAbandonsOwnReconnect(t *testing.T) {
	for try := 0; try < 50; try++ {
		f := newR29Fx(t)
		f.longTokens()
		f.do(0, func(m *Manager, p *Peer) { m.startReconnect(p, f.clk) })
		f.lose(0, 1, kAny)
		f.rekey(1)
		var mine, theirs []byte
		for _, og := range f.m(0).st.Outgoing {
			mine = og.Th1
		}
		for _, og := range f.m(1).st.Outgoing {
			theirs = og.Th1
		}
		if bytes.Compare(mine, theirs) >= 0 {
			continue // want side 0's reconnect lower: kept beside the answer
		}
		f.deliver(1, 0, kHSInit)
		if f.answerCount(0) != 1 || f.openReconnect(0) == nil {
			t.Fatal("setup: not both")
		}
		f.deliver(0, 1, kHSResp)
		f.deliver(1, 0, kHSFin)
		if f.openReconnect(0) != nil {
			t.Fatal("the verified hs.fin did not come first over the vault's own reconnect")
		}
		return
	}
	t.Skip("no th1 order found")
}

// S8: a demotion by position is audited fork_suspected (ref epoch).
func TestR29PositionDemotionAudited(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	f.rekey(0)
	f.deliver(0, 1, kHSInit)
	f.deliver(1, 0, kHSResp)
	f.rotate(0)
	f.deliverAt(0, 1, kHSFin, "pump-z")
	f.deliverAt(0, 1, kRotate, "pump-a")
	if !f.activity(1, "connection.fork_suspected", "epoch") || f.p(1).suspended() {
		f.dump()
		t.Fatal("a demotion by position was not audited fork_suspected (epoch), or suspended")
	}
}

// S9: the reconnect token's quota spent on a demotion reconnect counts as
// its last failure: stale.
func TestR29QuotaExhaustionLastFailure(t *testing.T) {
	f := demoted(t, nil)
	r := f.d[0].relay
	f.lose(0, 1, kAny)
	f.advance(HandshakeTTL + time.Hour)
	r.mu.Lock()
	r.failMailbox = map[string]error{f.m(1).st.Relay.Mailbox: &relayclient.Error{Status: 429, Code: CodeQuotaExceeded}}
	r.mu.Unlock()
	f.tick(0) // the first expired; the next try's deposit refused quota_exceeded
	f.do(0, func(*Manager, *Peer) {})
	if f.p(0).State != PeerStale {
		f.dump()
		t.Fatal("quota exhaustion did not end it")
	}
}

// §3.4.1 "The reconnect bound" (R29-K6): a plain reconnect, started after
// an abandoned pending epoch (B passed, the hs.fin lost), whose hs.init a
// relay refuses quota_exceeded makes the connection stale.
func TestR29PlainReconnectQuotaExceededStale(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	f.rekey(0)
	f.deliver(0, 1, kHSInit)
	f.deliver(1, 0, kHSResp)
	if f.p(0).Pending == nil {
		t.Fatal("setup: no pending epoch")
	}
	f.lose(0, 1, kAny) // the hs.fin is lost: nothing confirms the epoch
	r := f.d[0].relay
	r.mu.Lock()
	r.failMailbox = map[string]error{f.m(1).st.Relay.Mailbox: &relayclient.Error{Status: 429, Code: CodeQuotaExceeded}}
	r.mu.Unlock()
	f.advance(PendingLife + time.Hour)
	f.tick(0) // B passes: the pending epoch is abandoned and a reconnect starts
	f.tick(0)
	if !f.audited(0, "pending_abandoned_b_passed") {
		f.dump()
		t.Fatal("setup: B did not abandon the pending epoch")
	}
	f.do(0, func(*Manager, *Peer) {})
	for _, a := range f.m(0).st.Audit {
		if strings.HasPrefix(a.Event, "reconnect_") {
			t.Fatalf("setup: not a plain reconnect (%s)", a.Event) // reconnectNaming notes reconnect_<why>
		}
	}
	if f.p(0).State != PeerStale || !f.sink[0].has("connection.stale") {
		f.dump()
		t.Fatal("a plain reconnect refused quota_exceeded did not make the connection stale")
	}
}

// S12: held messages that expire are counted and audited.
func TestR29HeldExpiryAudited(t *testing.T) {
	f := demoted(t, nil)
	f.do(0, func(m *Manager, p *Peer) {
		m.sendWith(p, "test.note", json.RawMessage(`{"n":"e"}`), SendOptions{Exp: f.clk.Add(time.Minute)}, f.clk)
	})
	f.advance(time.Hour)
	f.tick(0)
	if !f.audited(0, "held_expired") {
		t.Fatal("an expired held message was not audited")
	}
}

// Code 2: the hold is by peer, not by mailbox: another record's deposit to
// the same mailbox (a new invitation's first contact) is not held behind
// a demoted connection's held messages.
func TestR29HoldIsByPeer(t *testing.T) {
	f := demoted(t, nil)
	f.note(0, "held")
	f.lose(0, 1, kAny)
	p := f.p(0)
	f.do(0, func(m *Manager, _ *Peer) {
		m.queueDeposit(&OutboxEntry{RelayURL: p.Relay.URL, Mailbox: p.Relay.Mailbox, Token: "v4.public.VEVTVA", Payload: []byte("first-contact")}, f.clk)
	})
	got := false
	f.d[0].relay.mu.Lock()
	for _, d := range f.d[0].relay.deposits {
		got = got || string(d.payload) == "first-contact"
	}
	f.d[0].relay.mu.Unlock()
	if !got {
		t.Fatal("another record's deposit to the mailbox waited behind the held messages")
	}
}

// A deposit refused quota_exceeded with 429 that is not a reconnect's
// hs.init is retried, never dropped (fdcc746 dropped it: an att.deliver
// lost on CI, the e2e TestAttachmentMaliciousPeer failure). With no
// `quota` it is first read as the token's (§8.6): it waits for a fresh
// token, asked for, and is tried again within the hour.
func TestR29QuotaRetryForOtherDeposits(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	r := f.d[0].relay
	r.mu.Lock()
	r.failMailbox = map[string]error{f.m(1).st.Relay.Mailbox: &relayclient.Error{Status: 429, Code: CodeQuotaExceeded}}
	r.mu.Unlock()
	f.note(0, "after-quota")
	r.mu.Lock()
	r.failMailbox = nil
	r.mu.Unlock()
	f.advance(time.Hour + time.Minute) // past the quota wait
	f.do(0, func(*Manager, *Peer) {})
	f.settle()
	if n := f.arrived(1, "after-quota"); n != 1 {
		t.Fatalf("a deposit refused quota_exceeded (429) arrived %d times: dropped", n)
	}
}

// §3.4.1 "Fork by ctx" (no exception for an epoch Q began): side 1's copy
// confirmed E1 at side 0 (the real side 1 never activated it) and also
// sent a message under E1, so side 0 shows the paused-connection feed item
// and suspends (fork_suspected, ref epoch), as the fork rule.
func TestR29CopyEpochSentUnderSuspends(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	f.rekey(0)
	f.deliver(0, 1, kHSInit)
	snap := f.snapshot(1)
	f.rotate(1)
	f.deliver(0, 1, kAny)
	f.deliver(1, 0, kHSResp)
	f.startCopy(1, snap)
	f.deliver(0, 2, kHSFin)
	f.deliver(2, 0, kConfirm)
	f.note(2, "copy-under-E1") // the copy sent a real message under E1
	f.deliver(2, 0, kNote)
	f.deliver(1, 0, kRotate)
	f.settle()
	f.advance(time.Hour)
	f.tick(0)
	f.tick(1)
	f.settle()
	if !f.suspendedRef(0, "epoch") {
		f.dump()
		t.Fatal("a copy's epoch P sent under: not the fork rule's suspension")
	}
	feed := false
	for _, a := range f.sink[0].got {
		feed = feed || a.Kind == "connection.fork_suspected" && a.Ref == "epoch" && a.Feed
	}
	if !feed {
		t.Fatal("no feed item")
	}
}
