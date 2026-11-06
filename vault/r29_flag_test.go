package vault

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
)

// §6.3.1 "The received flag" (R29-F3): set by any message from P that
// opens under the epoch and passes acceptFrom steps 1-4, except hs.fin; a
// message under one epoch never sets another's.

func (f *r29Fx) flag(s int, id []byte) bool {
	e := f.p(s).epochMeta(id)
	return e != nil && e.GotFromPeer
}

// hs.fin leaves the responder's flag for the new epoch clear; hs.confirm
// alone sets the initiator's.
func TestR29FlagSetByConfirmNotFin(t *testing.T) {
	f := newR29Fx(t)
	f.rekey(0)
	f.deliver(0, 1, kHSInit)
	f.deliver(1, 0, kHSResp)
	e1 := append([]byte(nil), f.p(0).Pending.ID...)
	f.deliver(0, 1, kHSFin)
	if !bytes.Equal(f.cur(1), e1) {
		t.Fatal("setup: the responder did not activate E1")
	}
	if f.flag(1, e1) {
		t.Fatal("hs.fin set the responder's flag for E1")
	}
	if f.flag(0, e1) {
		t.Fatal("setup: flag set before anything arrived under E1")
	}
	if f.deliver(1, 0, kConfirm) != 1 {
		t.Fatal("setup: no hs.confirm")
	}
	if !f.flag(0, e1) {
		t.Fatal("hs.confirm alone did not set the flag")
	}
	if f.flag(1, e1) {
		t.Fatal("the responder's flag was set without a message from the initiator")
	}
}

// A handshake message (an hs.init) under E0 sets E0's flag, never E1's.
func TestR29FlagPerEpoch(t *testing.T) {
	f := newR29Fx(t)
	e0 := append([]byte(nil), f.cur(1)...)
	f.rekey(0)
	f.deliver(0, 1, kHSInit)
	f.deliver(1, 0, kHSResp)
	f.deliver(0, 1, kHSFin) // side 1: E1 current, its flag clear
	e1 := append([]byte(nil), f.cur(1)...)
	f.lose(1, 0, kAny)
	f.do(1, func(_ *Manager, p *Peer) {
		if e := p.epochMeta(e0); e != nil {
			e.GotFromPeer = false
		}
	})
	f.do(0, func(m *Manager, p *Peer) { // side 0 is still on E0 (E1 pending)
		in := &envelope.Inner{ID: m.newID(f.clk), Type: handshake.TypeInit, TS: f.clk, Body: json.RawMessage(`{"purpose":"rekey"}`)}
		raw, err := m.sealFor(p, m.sessions[p.ID].Current(), in)
		if err != nil {
			t.Fatal(err)
		}
		m.queueDeposit(&OutboxEntry{PeerID: p.ID, RelayURL: p.Relay.URL, Mailbox: p.Relay.Mailbox, Payload: raw}, f.clk)
	})
	if f.deliver(0, 1, kHSInit) != 1 {
		t.Fatal("setup: no hs.init under E0")
	}
	if !f.flag(1, e0) {
		t.Fatal("an hs.init under E0 did not set E0's flag")
	}
	if f.flag(1, e1) {
		t.Fatal("a message under E0 set E1's flag")
	}
}

// P rekeys E0 to E1 and sends hs.fin, then rotates before any hs.confirm
// and sends identity.rotate under E0: Q's E1 has its flag clear, so Q ends
// demoted and reconnecting, not suspended.
func TestR29FinThenRotateDemotesNotSuspends(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	f.rekey(1)
	f.deliver(1, 0, kHSInit)
	f.deliver(0, 1, kHSResp)
	f.deliver(1, 0, kHSFin)
	e1 := append([]byte(nil), f.cur(0)...)
	f.lose(0, 1, kConfirm)
	f.rotate(1)
	f.deliver(1, 0, kRotate)
	if f.flag(0, e1) {
		t.Fatal("E1's flag set by hs.fin")
	}
	if e := f.p(0).epochMeta(e1); e == nil || !e.Demoted {
		f.dump()
		t.Fatal("E1 not demoted")
	}
	if f.p(0).suspended() || f.openReconnect(0) == nil {
		f.dump()
		t.Fatal("suspended, or not reconnecting")
	}
	f.settle()
	f.tick(0)
	f.tick(1)
	f.settle()
	if f.p(0).suspended() || !f.sameEpoch() {
		f.dump()
		t.Fatal("did not converge")
	}
}
