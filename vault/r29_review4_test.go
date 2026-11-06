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
	"github.com/vettid/vettid-vault/vms/suite"
)

// The lead's Opus review of r29-step5 (batch 4): one test per fix.

// H1, §3.4.1 "Fork by ctx": the ancestors are those of the ik the
// message reaches. Q (side 1) has E0 and E1 (signer a, confirmed by P's
// message under it). A copy line of P (holding E0) rotates a→b and
// reconnects naming E0 with the link a→b: Q suspends (ref epoch), with or
// without the copy's identity.rotate first, toward a person and a
// service.
func TestR29ForkByCtxReachedIK(t *testing.T) {
	for _, service := range []bool{false, true} {
		for _, rotateFirst := range []bool{false, true} {
			t.Run(fmt.Sprintf("service=%v,rotateFirst=%v", service, rotateFirst), func(t *testing.T) {
				f := newR29Fx(t)
				f.longTokens()
				if service {
					f.p(1).PeerKind = "service"
				}
				snap := f.snapshot(0) // P's copy line: E0
				f.rekey(1)            // Q begins E1 with P
				f.settle()
				f.note(0, "under-E1") // P sends under E1: Q's confirmed epoch
				f.settle()
				f.startCopy(0, snap)
				f.rotate(2) // the copy line rotates a→b
				if rotateFirst {
					f.deliver(2, 1, kRotate)
				}
				f.lose(2, 1, kAny)
				if !rotateFirst {
					if f.p(1).suspended() {
						t.Fatal("setup: suspended early")
					}
				}
				if !f.p(1).suspended() {
					f.do(2, func(m *Manager, p *Peer) {
						for id, og := range m.st.Outgoing {
							if og.PeerID == p.ID {
								m.abandonOutgoing(id, f.clk)
							}
						}
						m.startReconnect(p, f.clk)
					})
					f.deliver(2, 1, kHSInit)
					f.deliver(1, 2, kHSResp)
					f.deliver(2, 1, kHSFin)
				}
				if !f.suspendedRef(1, "epoch") {
					f.dump()
					t.Fatal("Q did not suspend")
				}
			})
		}
	}
}

// H1 for a rekey: the copy line's rekey from E0 after its rotation a→b
// carries the link (S8); E0 is neither current nor confirmed at Q, and E1
// (signer a) is after it: fork evidence.
func TestR29ForkByCtxReachedIKRekey(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	snap := f.snapshot(0)
	f.rekey(1)
	f.settle()
	f.note(0, "under-E1")
	f.settle()
	f.startCopy(0, snap)
	f.rotate(2) // the copy's rekey from E0, with a→b, is queued
	f.lose(2, 1, kRotate)
	if f.deliver(2, 1, kHSInit) != 1 {
		t.Fatal("setup: no rekey from the copy")
	}
	if !f.suspendedRef(1, "epoch") {
		f.dump()
		t.Fatal("a rekey whose links reach past E1's signer was not fork evidence")
	}
}

// M1, Table B "Reached" for a reconnect: its links are applied, then H5.
// Q answered P's rekey (signer a); P rotates a→b and reconnects with the
// link; once Q finishes the reconnect, its old answer (pinned to a) is
// gone, so an old copy's hs.fin for it establishes nothing.
func TestR29ReconnectLinksRunH5(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	f.rekey(0)
	f.deliver(0, 1, kHSInit) // Q answers (signer a)
	f.startCopy(0, f.snapshot(0))
	if f.deliver(1, 2, kHSResp) != 1 { // the copy takes Q's answer; its hs.fin waits
		t.Fatal("setup: no hs.resp for the copy")
	}
	f.rotate(0)
	f.lose(0, 1, kAny)
	f.do(0, func(m *Manager, p *Peer) {
		for id, og := range m.st.Outgoing {
			if og.PeerID == p.ID {
				m.abandonOutgoing(id, f.clk)
			}
		}
		m.startReconnect(p, f.clk)
	})
	f.deliver(0, 1, kHSInit)
	f.deliver(1, 0, kHSResp)
	f.deliver(0, 1, kHSFin)
	rc := append([]byte(nil), f.cur(1)...)
	if !bytes.Equal(f.cur(0), rc) && f.p(0).Pending == nil {
		f.dump()
		t.Fatal("setup: the reconnect did not complete")
	}
	if f.answerCount(1) != 0 {
		t.Fatal("the answer pinned to the ancestor ik survived the reconnect's links")
	}
	f.deliver(2, 1, kHSFin)
	if !bytes.Equal(f.cur(1), rc) {
		f.dump()
		t.Fatal("an old copy's hs.fin for the dropped answer established an epoch")
	}
}

// takeKind removes from's deposits of kind k to to, as messages in
// deposit order, without delivering them.
func (f *r29Fx) takeKind(from, to, k int) []Message {
	f.t.Helper()
	fm := f.m(from)
	fm.mu.Lock()
	_ = fm.flushThenDrain(context.Background())
	fm.mu.Unlock()
	d, tod := f.d[from], f.d[to]
	toPK := tod.m.keys.relay.Public().(ed25519.PublicKey)
	var msgs []Message
	d.relay.mu.Lock()
	defer d.relay.mu.Unlock()
	kept := d.relay.deposits[:0]
	for i, dep := range d.relay.deposits {
		env, err := envelope.Parse(dep.payload)
		if err != nil || dep.mailbox != tod.m.st.Relay.Mailbox || f.kindOf(from, to, env) != k {
			kept = append(kept, dep)
			continue
		}
		jti := ""
		if c, err := relayauth.ParseToken(dep.token, toPK); err == nil {
			jti = c.Jti
		}
		msgs = append(msgs, Message{MsgID: fmt.Sprintf("take-%d-%d", len(msgs), i), Sender: relayauth.EncodeKey(f.pk(from)), JTI: jti,
			Payload: dep.payload})
	}
	d.relay.deposits = kept
	return msgs
}

func (f *r29Fx) process(to int, msg Message) {
	f.t.Helper()
	if err := f.m(to).ProcessBatch(context.Background(), &fakeCollector{}, []Message{msg}); err != nil {
		f.t.Fatal(err)
	}
}

// M2, honest: the signer must be the link's old_ik or an ancestor of it,
// not an ancestor of P's current ik. P rotates a→b (its identity.rotate M1,
// under E0, is delayed); Q learns a→b from P's hs.resp and E1 (signer b)
// goes pending; Q abandons E1; P had activated E1 and sent hs.confirm
// (E1's flag set at Q); P rotates b→c (Q follows it); then M1 arrives
// under E0. Its link a→b does not judge E1: Q neither suspends nor ends
// E1.
func TestR29OlderLinkDoesNotJudgeLaterSigner(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	f.rotate(0) // a→b
	m1 := f.takeKind(0, 1, kRotate)
	if len(m1) != 1 {
		t.Fatal("setup: no identity.rotate M1")
	}
	f.lose(0, 1, kAny)
	f.do(0, func(m *Manager, p *Peer) {
		for id, og := range m.st.Outgoing {
			if og.PeerID == p.ID {
				m.abandonOutgoing(id, f.clk)
			}
		}
	})
	f.rekey(1)
	f.deliver(1, 0, kHSInit)
	f.deliver(0, 1, kHSResp) // Q follows a→b at the hs.resp; E1 pending, signer b
	if f.p(1).Pending == nil || len(f.p(1).Chain) != 1 {
		f.dump()
		t.Fatal("setup: E1 not pending, or a→b not followed")
	}
	e1 := append([]byte(nil), f.p(1).Pending.ID...)
	f.do(1, func(m *Manager, p *Peer) { m.abandonPending(p, "test", false, f.clk) })
	f.deliver(1, 0, kHSFin) // P activates E1
	f.deliver(0, 1, kConfirm)
	if !f.flag(1, e1) {
		t.Fatal("setup: E1's flag not set")
	}
	f.rotate(0) // b→c, under E1
	f.deliver(0, 1, kRotate)
	f.lose(0, 1, kAny)
	if len(f.p(1).Chain) != 2 || f.p(1).suspended() {
		f.dump()
		t.Fatal("setup: b→c not followed, or suspended")
	}
	f.process(1, m1[0]) // M1, a→b, under E0
	if f.p(1).suspended() || f.ended(1, e1) {
		f.dump()
		t.Fatal("an older link judged an epoch signed by a later key")
	}
}

// M3, §6.3.1 rule E's last sentence: an epoch the vault began and
// abandoned while pending is not in rule E's destroyed set; a later
// message under it is processed (without confirming it), not fork
// evidence.
func TestR29RuleESparesOwnAbandoned(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	f.rekey(0)
	f.deliver(0, 1, kHSInit)
	f.deliver(1, 0, kHSResp)
	e1 := append([]byte(nil), f.p(0).Pending.ID...)
	f.deliver(0, 1, kHSFin) // P activates E1
	f.lose(1, 0, kConfirm)
	f.do(0, func(m *Manager, p *Peer) {
		m.abandonPending(p, "test", false, f.clk)
		m.ruleE(p, f.clk, f.clk) // as at a responder's establishment naming the confirmed E0
	})
	if e := f.p(0).epochMeta(e1); e == nil || e.Destroyed {
		t.Fatal("rule E destroyed the vault's own abandoned epoch")
	}
	f.advance(time.Minute)
	f.note(1, "under-abandoned-E1")
	f.deliver(1, 0, kNote)
	if f.p(0).suspended() || f.arrived(0, "under-abandoned-E1") != 1 {
		f.dump()
		t.Fatal("a message under the vault's own abandoned epoch was not processed")
	}
}

// L1: responderEstablish follows a rekey's links at hs.fin without
// restarting anything beside the epoch it establishes. Q (side 1) has its
// own reconnect open (pinned to P's ik a) and no reconnect token left; P
// rotates a→b and its rekey (with the link) is answered; at its hs.fin, H5
// must not restart Q's reconnect (which, without a reconnect token, would
// make the connection stale).
func TestR29FinLinksNoRestart(t *testing.T) {
	for try := 0; try < 50; try++ {
		f := newR29Fx(t)
		f.longTokens()
		f.rotate(0) // a→b; P's rekey from E0 carries the link
		f.lose(0, 1, kRotate)
		f.do(1, func(m *Manager, p *Peer) { m.startReconnect(p, f.clk) })
		f.lose(1, 0, kAny)
		var mine, theirs []byte
		for _, og := range f.m(1).st.Outgoing {
			mine = og.Th1
		}
		for _, og := range f.m(0).st.Outgoing {
			if og.Purpose == "rekey" {
				theirs = og.Th1
			}
		}
		if theirs == nil || bytes.Compare(mine, theirs) >= 0 {
			continue // want Q's reconnect lower: kept beside the answer
		}
		f.p(1).Reconnect.Token = ""
		f.deliver(0, 1, kHSInit)
		if f.answerCount(1) != 1 {
			t.Fatal("setup: P's rekey not answered")
		}
		f.deliver(1, 0, kHSResp)
		f.deliver(0, 1, kHSFin)
		if f.p(1).State == PeerStale || f.sink[1].has("connection.stale") {
			f.dump()
			t.Fatal("a restart at the hs.fin's links made the connection stale")
		}
		return
	}
	t.Skip("no th1 order found")
}

// L2: a reconnect naming an epoch does not start, and abandons nothing,
// while the vault's own reconnect is pending.
func TestR29ReconnectNamingKeepsPendingReconnect(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	f.do(0, func(m *Manager, p *Peer) { m.startReconnect(p, f.clk) })
	f.deliver(0, 1, kHSInit)
	f.deliver(1, 0, kHSResp)
	pe := f.p(0).Pending
	if pe == nil || pe.Purpose != "reconnect" {
		t.Fatal("setup: no pending reconnect")
	}
	started := true
	f.do(0, func(m *Manager, p *Peer) { started = m.reconnectNaming(p, p.LastEpochID, "f1", f.clk) })
	if started || f.p(0).Pending != pe {
		t.Fatal("a reconnect naming an epoch abandoned the pending reconnect")
	}
}

// L3: a strict F1 demotion is audited connection.fork_suspected (ref
// epoch) with no feed item and no suspension.
func TestR29StrictF1Audited(t *testing.T) {
	f := demoted(t, nil)
	if !f.activity(0, "connection.fork_suspected", "epoch") || f.forkFeed(0) || f.p(0).suspended() {
		f.dump()
		t.Fatal("a strict F1 demotion was not audited fork_suspected (epoch) without a feed item")
	}
}

// Recheck L-a: links followed beside the caller's own handshake
// (noLinkRestart) that demote the current epoch (by strict F1, and by
// position) start
// no reconnect after the demotion: no stale (here there is no reconnect token), no feed item,
// and the held entries survive.
func TestR29NoLinkRestartNoDemotionRestart(t *testing.T) {
	for _, byPosition := range []bool{false, true} {
		f := newR29Fx(t)
		f.longTokens()
		e0 := append([]byte(nil), f.cur(0)...)
		f.rekey(1)
		f.deliver(1, 0, kHSInit)
		f.deliver(0, 1, kHSResp)
		f.deliverAt(1, 0, kHSFin, "pump-z") // side 0 activates E1 (flag clear), with a position
		f.lose(0, 1, kConfirm)
		f.rotate(1) // side 1 abandons its pending E1; its link a→b
		f.lose(1, 0, kAny)
		r := f.d[0].relay
		r.mu.Lock()
		r.failMailbox = map[string]error{f.m(1).st.Relay.Mailbox: &relayclient.Error{Status: 503, Code: "unavailable"}}
		r.mu.Unlock()
		f.note(0, "sealed-before") // sealed under E1, not deposited
		f.p(0).Reconnect.Token = ""
		links := parseRotations(f.m(1).st.Rotations)
		f.do(0, func(m *Manager, p *Peer) {
			if byPosition {
				// the link's position before E1's establishing hs.fin
				e := p.epochMeta(p.LastEpochID)
				m.relayAt, m.msgID = e.EstAt.Add(-time.Second), "pos"
			}
			m.noLinkRestart = true
			m.followLinks(p, links, e0, f.clk) // E1 demoted (strict F1, or by position)
			m.noLinkRestart = false
			m.relayAt, m.msgID = time.Time{}, ""
		})
		if !f.m(0).currentDemoted(f.p(0)) {
			t.Fatal("setup: the current epoch is not demoted")
		}
		if f.p(0).State == PeerStale || f.sink[0].has("connection.stale") || f.forkFeed(0) {
			f.dump()
			t.Fatalf("position %v: a restart after the demotion made the connection stale, or showed a feed item", byPosition)
		}
		held := 0
		for _, e := range f.m(0).st.Outbox {
			if e.Held != nil && !e.Done {
				held++
			}
		}
		if held != 1 {
			t.Fatalf("held entries: %d", held)
		}
	}
}

// Recheck L-b: following a rekey's links at its hs.fin can suspend the
// connection (here "Epochs after an ik link" with the received flag set);
// the epoch the hs.fin would establish is then not established.
func TestR29FinLinksSuspendNoEstablish(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	snap := f.snapshot(0) // P's copy: ik a, E0
	f.rotate(0)           // the real P: a→b; its rekey from E0 carries the link
	f.lose(0, 1, kRotate)
	f.deliver(0, 1, kHSInit) // Q answers it under E0
	f.deliver(1, 0, kHSResp)
	fins := f.takeKind(0, 1, kHSFin) // the real P's hs.fin, held back
	if len(fins) != 1 {
		t.Fatal("setup: no hs.fin from P")
	}
	f.startCopy(0, snap)
	f.do(2, func(m *Manager, p *Peer) { m.startRekey(p, f.clk) })
	f.deliver(2, 1, kHSInit)
	f.deliver(1, 2, kHSResp)
	f.deliverAt(2, 1, kHSFin, "pump-z") // Q activates the copy's E1 (signer a)
	e1 := append([]byte(nil), f.cur(1)...)
	f.deliver(1, 2, kConfirm) // the copy's E1 is confirmed
	f.note(2, "copy-under-E1")
	f.deliver(2, 1, kNote) // E1's flag set
	if !f.flag(1, e1) || f.p(1).suspended() {
		f.dump()
		t.Fatalf("setup: flag %v suspended %v answers %d", f.flag(1, e1), f.p(1).suspended(), f.answerCount(1))
	}
	fin := fins[0]
	fin.MsgID, fin.DepositedAt = "pump-a-0", f.clk.UTC().Format(time.RFC3339Nano) // before E1's hs.fin
	f.process(1, fin)
	if !f.suspendedRef(1, "epoch") {
		f.dump()
		t.Fatal("setup: the links did not suspend")
	}
	if !bytes.Equal(f.cur(1), e1) {
		t.Fatal("the hs.fin established its epoch on a connection its links suspended")
	}
}

// Step 6 review L1: with the vault's own reconnect pending, a reconnect
// naming an epoch is not tried, so its lack of a reconnect token does not
// make the connection stale.
func TestR29ReconnectNamingPendingBeforeTokenCheck(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	f.do(0, func(m *Manager, p *Peer) { m.startReconnect(p, f.clk) })
	f.deliver(0, 1, kHSInit)
	f.deliver(1, 0, kHSResp)
	if f.p(0).Pending == nil {
		t.Fatal("setup: no pending reconnect")
	}
	f.do(0, func(m *Manager, p *Peer) {
		p.Reconnect.Token = ""
		m.reconnectNaming(p, p.LastEpochID, "f1", f.clk)
	})
	if f.p(0).State == PeerStale || f.p(0).Pending == nil {
		t.Fatal("a reconnect not tried (one pending) made the connection stale")
	}
}

// Step 6 review L2, Table B identity.rotate: a first unfollowed link whose
// old_ik is an ancestor (here the followed a→b again, with another kem:
// not a second successor, not followed) is refused unexpected, not
// rejected_ik.
func TestR29IdentityRotateAncestorFirstUnexpected(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	oldIK := f.m(1).keys.ik
	f.rotate(1)
	f.settle() // side 0 follows a→b
	newIK := f.m(1).keys.ik
	kem, err := suite.NewPrivateKey(bytes.Repeat([]byte{0x6e}, 32))
	if err != nil {
		t.Fatal(err)
	}
	r, err := handshake.NewRotation(oldIK, newIK, kem.Public())
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"rotation":` + string(r.Marshal()) + `}`)
	f.do(1, func(m *Manager, p *Peer) { m.sendTo(p, "identity.rotate", body, f.clk) })
	f.deliver(1, 0, kRotate)
	if !f.activity(0, "drop.peer_key", "unexpected") || f.activity(0, "drop.peer_key", "rejected_ik") {
		f.dump()
		t.Fatal("an ancestor first link was not refused unexpected")
	}
}

// Step 6 review L3, §3.4.1 "After a demotion": a held message that cannot
// be sealed under the new epoch is not dropped silently: the drop is
// audited (drop.held_unsealable).
func TestR29HeldUnsealableAudited(t *testing.T) {
	f := demoted(t, nil)
	f.do(0, func(m *Manager, p *Peer) {
		m.queueDeposit(&OutboxEntry{PeerID: p.ID, RelayURL: p.Relay.URL, Mailbox: p.Relay.Mailbox, Held: []byte("{")}, f.clk)
	})
	f.settle()
	f.advance(time.Hour)
	f.tick(0)
	f.tick(1)
	f.settle()
	if f.m(0).currentDemoted(f.p(0)) {
		f.dump()
		t.Fatal("setup: still demoted")
	}
	if !f.activity(0, "drop.held_unsealable", "") {
		f.dump()
		t.Fatal("a held message dropped at sealing was not audited")
	}
}

// depositsTo flushes side from and counts its deposits waiting for to.
func (f *r29Fx) depositsTo(from, to int) int {
	fm := f.m(from)
	fm.mu.Lock()
	_ = fm.flushThenDrain(context.Background())
	fm.mu.Unlock()
	d := f.d[from]
	d.relay.mu.Lock()
	defer d.relay.mu.Unlock()
	n := 0
	for _, dep := range d.relay.deposits {
		if dep.mailbox == f.m(to).st.Relay.Mailbox {
			n++
		}
	}
	return n
}

// Step 6 review L4: connection.removed goes under a usable current epoch;
// while the current epoch is demoted, or the vault's own reconnect is
// pending, it is not sent, and the removal's audit entry says so
// (ref notice_not_sent), never silently.
func TestR29ConnectionRemovedNotice(t *testing.T) {
	for _, c := range []string{"usable", "demoted", "pending"} {
		var f *r29Fx
		switch c {
		case "usable":
			f = newR29Fx(t)
		case "demoted":
			f = demoted(t, nil)
		case "pending":
			f = newR29Fx(t)
			f.longTokens()
			f.do(0, func(m *Manager, p *Peer) { m.startReconnect(p, f.clk) })
			f.deliver(0, 1, kHSInit)
			f.deliver(1, 0, kHSResp)
			if f.p(0).Pending == nil {
				t.Fatal("setup: no pending reconnect")
			}
		}
		f.lose(0, 1, kAny)
		id := f.id[0]
		f.do(0, func(m *Manager, p *Peer) { m.removeConnection(p, "out", f.clk) })
		n := f.depositsTo(0, 1)
		var removed *Activity
		for i := range f.sink[0].got {
			if a := &f.sink[0].got[i]; a.Kind == "connection.removed" && a.ConnectionID == id {
				removed = a
			}
		}
		if removed == nil {
			t.Fatalf("%s: no connection.removed", c)
		}
		switch c {
		case "usable":
			if n != 1 || removed.Ref != "" {
				t.Fatalf("usable: %d deposits, ref %q", n, removed.Ref)
			}
		default:
			if n != 0 || removed.Ref != "notice_not_sent" {
				t.Fatalf("%s: %d deposits, ref %q", c, n, removed.Ref)
			}
		}
	}
}
