package calls

import (
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
)

// The ring timer (CALLS-PLAN V2) and call liveness (V3, decision D12),
// VAULT-MESSAGING §10.10 (C2).
const (
	// KeepaliveEvery is how often a watched call's device sends
	// call.keepalive; KeepaliveSilence the silence after which the vault
	// ends the call (judged at the end of each batch, so at the first
	// collect after the 90 s, at least every 25 s, §12.2).
	KeepaliveEvery   = 30 * time.Second
	KeepaliveSilence = 90 * time.Second
	// CollectGap: a longer time between two housekeepings is time the
	// vault was not collecting (a relay blip, a task swap). The device's
	// keep-alives may not have reached it, so the count starts again, as
	// at the unlock.
	CollectGap = 30 * time.Second
)

// Tick implements vault.TickObserver: housekeeping (every collect, at least
// every 25 s, §12.2, before the batch's messages) ends a ringing call at its
// exp. After a gap in collecting it starts the watched calls' count again.
func (f *Feature) Tick(s *vault.Session) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := s.Now()
	gap := !f.lastTick.IsZero() && now.Sub(f.lastTick) > CollectGap
	f.lastTick = now
	for _, id := range f.sorted() {
		c := f.calls[id]
		switch {
		case c.State == StateRinging && !now.Before(c.Exp):
			f.ringTimeout(s, c)
		case gap && c.State == StateActive && c.Watched:
			if t, ok := f.alive[c.ID]; !ok || t.Before(now) {
				f.alive[c.ID] = now
			}
		}
	}
}

// BatchEnd implements vault.BatchEndObserver: after the batch's messages
// (so its keep-alives count), a watched active call whose device has been
// silent more than 90 s ends failed; the peer vault and the owner devices
// are told.
func (f *Feature) BatchEnd(s *vault.Session) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := s.Now()
	for _, id := range f.sorted() {
		c := f.calls[id]
		if c.State == StateActive && c.Watched && now.Sub(f.lastAlive(c, now)) > KeepaliveSilence {
			f.finish(s, c, "failed")
			_ = s.SendToConnection(c.Conn, "call.end", endJSON(c.ID, "failed"))
			endToDevices(s, c, "failed", "")
		}
	}
}

// ringTimeout is the ring timer's end of an unanswered call: ended with
// reason timeout and call.end{timeout} to the owner devices; an outgoing
// call's peer vault is told too (an S10 peer records its missed call from
// it), an incoming one is a missed call and its caller's vault is told
// nothing (it ends its own record by its own timer).
func (f *Feature) ringTimeout(s *vault.Session, c *Call) {
	f.finish(s, c, "timeout")
	s.NotifyDevicesWith("call.end", endJSON(c.ID, "timeout"), "", vault.SendOptions{})
	if c.Dir == DirOut {
		_ = s.SendToConnection(c.Conn, "call.end", endJSON(c.ID, "timeout"))
		return
	}
	f.missed(s, c)
}

// lastAlive is when a watched call's device last showed it was alive: its
// last keep-alive, else the answer or, for a call already active when the
// vault was unlocked (memory only, so nothing of it is in the state), the
// first look after the unlock.
func (f *Feature) lastAlive(c *Call, now time.Time) time.Time {
	if t, ok := f.alive[c.ID]; ok {
		return t
	}
	f.alive[c.ID] = now
	return now
}

// keepalive: the call's device is alive (ephemeral; in memory only: no
// state is written, nothing forwarded or audited). One from another device
// is dropped; one for a call that is not active is answered
// call.end{unavailable} (ephemeral, as the keep-alive), so the device
// learns its vault no longer holds it; so is one for a call past the 12 h
// limit.
func (f *Feature) keepalive(s *vault.Session, body []byte) error {
	id, err := callIDOnly(body)
	if err != nil {
		return err
	}
	c := f.calls[id]
	if c != nil && c.Device != "" && c.Device != s.From().ID {
		return nil
	}
	if c == nil || c.State != StateActive || !c.live(s.Now()) {
		_ = s.SendCallSignal(s.From().ID, "call.end", endJSON(id, "unavailable"), eph(s.Now()))
		return nil
	}
	f.alive[id] = s.Now()
	return nil
}

// keepaliveFlag reads the optional keepalive member of call.start and a
// device's call.answer: absent (an app from before C2: the call is not
// watched) or true.
func keepaliveFlag(o strictjson.Object) (bool, error) {
	if !o.Has("keepalive") {
		return false, nil
	}
	v, err := o.Bool("keepalive")
	if err != nil || !v {
		return false, errBad
	}
	return true, nil
}
