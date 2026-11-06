package vault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"

	"github.com/vettid/vettid-vault/vms/envelope"
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
