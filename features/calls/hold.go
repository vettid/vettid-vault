package calls

import (
	"time"

	"github.com/vettid/vettid-vault/vault"
)

// The runtime interfaces the calls feature implements.
var (
	_ vault.CallGate              = (*Feature)(nil)
	_ vault.AccessEndedObserver   = (*Feature)(nil)
	_ vault.DeviceRemovedObserver = (*Feature)(nil)
	_ vault.BatchEndObserver      = (*Feature)(nil)
	_ vault.TickObserver          = (*Feature)(nil)
	_ vault.OwnerHoldObserver     = (*Feature)(nil)
)

// OwnerHoldStarted implements vault.OwnerHoldObserver: an incoming call
// ringing when the hold begins stops ringing on the devices
// (call.end{unavailable} to them only; the caller is not told and times
// out) and is recorded as missed, not counted toward the limits (the member
// couldn't have answered it). (0.88.13, owner decisions 2026-11-11) An
// outgoing call still ringing ends too: call.end{unavailable} to the peer
// vault, and the devices told once. A call answered before continues
// (§3.6.3, §10.10).
func (f *Feature) OwnerHoldStarted(s *vault.Session) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := s.Now()
	for _, id := range f.sorted() {
		c := f.calls[id]
		if c.State != StateRinging || !c.live(now) {
			continue
		}
		if c.Dir == DirOut {
			f.finish(s, c, "unavailable")
			_ = s.SendToConnection(c.Conn, "call.end", endJSON(c.ID, "unavailable"))
			endToDevices(s, c, "unavailable", "")
			continue
		}
		s.NotifyDevicesWith("call.end", endJSON(c.ID, "unavailable"), "", vault.SendOptions{})
		f.finish(s, c, "unavailable")
		recordMissed(s, c)
	}
}

// OwnerHoldEnded implements vault.OwnerHoldObserver.
func (f *Feature) OwnerHoldEnded(*vault.Session) {}

// CallAnsweredBefore implements vault.CallGate: callID is the device's
// active call, answered before t and still live at now (the 12 h limit: a
// stale record keeps nothing open through the hold).
func (f *Feature) CallAnsweredBefore(device, callID string, t, now time.Time) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.calls[callID]
	return c != nil && c.Device == device && c.State == StateActive && !c.Answered.IsZero() && c.Answered.Before(t) && c.live(now)
}

// CallActive implements vault.CallGate: callID is an active call of the
// device, still live at now.
func (f *Feature) CallActive(device, callID string, now time.Time) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.calls[callID]
	return c != nil && c.Device == device && c.State == StateActive && c.live(now)
}

// CallRingingOut implements vault.CallGate: callID is the device's own
// outgoing call, still ringing at now.
func (f *Feature) CallRingingOut(device, callID string, now time.Time) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.calls[callID]
	return c != nil && c.Device == device && c.Dir == DirOut && c.State == StateRinging && c.live(now)
}

// EndCallsAnsweredFrom implements vault.CallGate: when the hold begins, an
// active call answered at or after the deadline t (by a desktop while the
// check was due, or while hold_off_until held the hold off) ends unavailable at
// once, with the peer vault and the owner devices told, rather than by
// 90 s of silence (§3.6.3).
func (f *Feature) EndCallsAnsweredFrom(s *vault.Session, t time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := s.Now()
	for _, id := range f.sorted() {
		c := f.calls[id]
		if c.State != StateActive || !c.live(now) || c.Answered.Before(t) {
			continue
		}
		f.finish(s, c, "unavailable")
		_ = s.SendToConnection(c.Conn, "call.end", endJSON(c.ID, "unavailable"))
		endToDevices(s, c, "unavailable", "")
	}
}

// AccessEnded implements vault.AccessEndedObserver: a desktop whose access
// is ended on purpose (End access, "Deny and end access now", or its own
// device.session.end) loses its call too: ended unavailable, the peer
// vault and the owner devices told, the desktop included. A session that
// only expires keeps the call (§6.8, 0.88.13, owner decision 2026-11-11).
func (f *Feature) AccessEnded(s *vault.Session, device string) {
	f.endDeviceCalls(s, device)
}

// DeviceRemoved implements vault.DeviceRemovedObserver: a device unlinked,
// or an app a transfer or a recovery replaced, loses its call in progress
// as an access ended on purpose does (§6.8, §7.4, 0.88.13).
func (f *Feature) DeviceRemoved(s *vault.Session, device string) {
	f.endDeviceCalls(s, device)
}

// endDeviceCalls ends the device's live calls unavailable, the peer vault
// and the owner devices told.
func (f *Feature) endDeviceCalls(s *vault.Session, device string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := s.Now()
	for _, id := range f.sorted() {
		c := f.calls[id]
		if c.Device != device || c.State == StateEnded || !c.live(now) {
			continue
		}
		f.finish(s, c, "unavailable")
		_ = s.SendToConnection(c.Conn, "call.end", endJSON(c.ID, "unavailable"))
		endToDevices(s, c, "unavailable", "")
	}
}

// CallInProgress implements vault.CallActivity: a call is live (ringing or
// answered, not ended or timed out). The idle lock waits for it to end
// (VAULT-MESSAGING 0.29.0 §3.6.8, release L); a call ends within 12 hours
// (§10.10).
func (f *Feature) CallInProgress(now time.Time) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.busy(now)
}
