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
	// ends the call (within one more housekeeping, so within 120 s of the
	// last keep-alive).
	KeepaliveEvery   = 30 * time.Second
	KeepaliveSilence = 90 * time.Second
)

// Tick implements vault.TickObserver: housekeeping (every collect, at least
// every 25 s, §12.2) ends a ringing call at its exp and a watched active
// call whose device has gone silent.
func (f *Feature) Tick(s *vault.Session) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := s.Now()
	for _, id := range f.sorted() {
		c := f.calls[id]
		switch {
		case c.State == StateRinging && !now.Before(c.Exp):
			f.ringTimeout(s, c)
		case c.State == StateActive && c.Watched && now.Sub(f.lastAlive(c, now)) > KeepaliveSilence:
			f.finish(s, c, "failed")
			_ = s.SendToConnection(c.Conn, "call.end", endJSON(c.ID, "failed"))
			s.NotifyDevicesWith("call.end", endJSON(c.ID, "failed"), "", vault.SendOptions{})
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
// call.end{unavailable}, so the device learns its vault no longer holds it.
func (f *Feature) keepalive(s *vault.Session, body []byte) error {
	id, err := callIDOnly(body)
	if err != nil {
		return err
	}
	c := f.calls[id]
	if c != nil && c.Device != "" && c.Device != s.From().ID {
		return nil
	}
	if c == nil || c.State != StateActive {
		return unavailable(s, id)
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
