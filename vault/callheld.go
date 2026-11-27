package vault

import (
	"context"
	"errors"
	"time"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Call messages held in memory (0.97.0 §10.10 "Servers and credentials",
// owner decision b, GC #19349). A call.start answer and a V→D call.offer
// that carry a TURN credential never reach the vault's state: the message
// itself is kept here, in memory only, and the stored outbox holds only an
// empty marker (CallHeld, no payload) that keeps its place in the
// mailbox's order. At each attempt the marker's deposit seals the message
// from memory under the device's current epoch, with the same inner id
// and body, and wipes the sealed bytes once the attempt ends; the
// outbox's backoff, its terminal answers and its order (later deposits to
// the mailbox wait behind an undelivered one) apply as to any entry. A
// marker whose message is gone (dropped, or the vault stopped or locked
// since it was queued) ends at once, delivered nothing.
//
// The message is kept while the calls feature still holds the call
// (CallKeeper): a call.start answer while the call lasts, so that a
// retransmitted call.start gets it again (resendCached), and an offer
// only while its call rings and its exp has not passed, and no longer
// than its deposit.

// callMsg is one call message held in memory.
type callMsg struct {
	call  string // the call_id
	peer  string // the device it goes to
	offer bool   // a V→D call.offer (else a call.start answer)
	inner *envelope.Inner
}

// CallKeeper is implemented by the calls feature: whether a call's
// message carrying its TURN credential may still go (0.97.0 §10.10). For
// an offer, while the call rings and its exp has not passed; for a
// call.start answer, while the call lasts.
type CallKeeper interface {
	CallHeld(callID string, offer bool, now time.Time) bool
}

// errCallNoSession: the device has no usable epoch for a held call
// message now; the marker waits with the outbox's backoff.
var errCallNoSession = errors.New("vault: no session for a held call message")

// holdCallMsg keeps in, a message to p carrying a TURN credential, in
// memory for call, and queues its marker. It reports whether it is held.
func (m *Manager) holdCallMsg(p *Peer, in *envelope.Inner, call string, offer bool, wake string, now time.Time) bool {
	kr := m.sessions[p.ID]
	if kr == nil || kr.Current() == nil || p.Fork != nil || p.RelayConflict != nil || m.relayBlocked(p.ID) {
		return false
	}
	c := *in
	c.Body = append([]byte(nil), in.Body...)
	if m.callMsgs == nil {
		m.callMsgs = map[string]*callMsg{}
	}
	m.callMsgs[c.ID] = &callMsg{call: call, peer: p.ID, offer: offer, inner: &c}
	m.queueCallMarker(p, &c, wake, now)
	return true
}

// queueCallMarker queues the stored marker of a held call message: no
// payload, only its place in the mailbox's order.
func (m *Manager) queueCallMarker(p *Peer, in *envelope.Inner, wake string, now time.Time) {
	m.queueDeposit(&OutboxEntry{PeerID: p.ID, RelayURL: p.Relay.URL, Mailbox: p.Relay.Mailbox, Wake: wake,
		InnerID: in.ID, Type: in.Type, CallHeld: true}, now)
}

// callMsgLive reports whether cm may still go.
func (m *Manager) callMsgLive(cm *callMsg, now time.Time) bool {
	for _, f := range m.features {
		if k, ok := f.(CallKeeper); ok {
			return k.CallHeld(cm.call, cm.offer, now)
		}
	}
	return false
}

// dropCallMsg wipes and forgets the held message with that inner id.
func (m *Manager) dropCallMsg(id string) {
	if cm := m.callMsgs[id]; cm != nil {
		suite.Wipe(cm.inner.Body)
		cm.inner.Body = nil
		delete(m.callMsgs, id)
	}
}

// dropCallMsgs wipes every held call message: at a lock or stop they are
// dropped first, so that vault.locking never waits behind them (0.97.0
// §10.10 "Order", §10.2). Their markers then end at the next drain.
func (m *Manager) dropCallMsgs() {
	for id := range m.callMsgs {
		m.dropCallMsg(id)
	}
	m.callMsgs = nil
}

// sweepCallMsgs drops the held messages that may no longer go, and ends
// the markers whose message is gone, so that nothing waits behind them.
func (m *Manager) sweepCallMsgs(now time.Time) {
	for id, cm := range m.callMsgs {
		if !m.callMsgLive(cm, now) {
			m.dropCallMsg(id)
		}
	}
	for _, e := range m.st.Outbox {
		if e.CallHeld && !e.Done && m.callMsgs[e.InnerID] == nil {
			e.Done, m.dirty = true, true
		}
	}
}

// callMarkerPending reports whether a marker for the held message id is
// still undelivered in the outbox.
func (m *Manager) callMarkerPending(id string) bool {
	for _, e := range m.st.Outbox {
		if e.CallHeld && !e.Done && e.InnerID == id {
			return true
		}
	}
	return false
}

// depositCallMsg is one attempt at a held call message's marker e: the
// message is sealed from memory and deposited, and the sealed bytes are
// wiped. A message that is gone or may no longer go ends the marker
// (Done, nil). An offer is dropped from memory once its deposit ends.
func (m *Manager) depositCallMsg(ctx context.Context, e *OutboxEntry, now time.Time) error {
	cm := m.callMsgs[e.InnerID]
	if cm != nil && !m.callMsgLive(cm, now) {
		m.dropCallMsg(e.InnerID)
		cm = nil
	}
	p := m.peer(e.PeerID)
	if cm == nil || cm.peer != e.PeerID || p == nil {
		e.Done = true
		return nil
	}
	kr := m.sessions[p.ID]
	if kr == nil || kr.Current() == nil {
		return errCallNoSession
	}
	c := *cm.inner // sealFor sets the copy's features
	raw, err := m.sealFor(p, kr.Current(), &c)
	if err != nil {
		return err // demoted: it waits, with the backoff, for a new epoch
	}
	e.Payload = raw
	err = m.deposit(ctx, e, now)
	suite.Wipe(raw)
	e.Payload = nil
	if cm.offer && (err == nil || e.Done) {
		m.dropCallMsg(e.InnerID) // an offer is kept no longer than its deposit
	}
	return err
}

// rearmCallAnswer answers a retransmitted call.start from memory while the
// vault still holds the call (0.97.0 §10.10 "A lost call.start answer"):
// the live answer again, in the order of the mailbox (a new marker), or
// nothing new while its marker is still undelivered. It reports whether
// it did.
func (m *Manager) rearmCallAnswer(p *Peer, id string, now time.Time) bool {
	cm := m.callMsgs[id]
	if cm == nil || cm.offer || cm.peer != p.ID {
		return false
	}
	if !m.callMsgLive(cm, now) {
		m.dropCallMsg(id)
		return false
	}
	if !m.callMarkerPending(id) {
		m.queueCallMarker(p, cm.inner, "", now)
	}
	return true
}
