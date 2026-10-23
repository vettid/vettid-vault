package calls

import (
	"time"

	"github.com/vettid/vettid-vault/vault"
)

// OwnerHoldStarted implements vault.OwnerHoldObserver: an incoming call
// ringing when the hold begins stops ringing on the devices
// (call.end{unavailable} to them only; the caller is not told and times
// out) and is recorded as missed. A call answered before continues
// (§3.6.3, §10.10).
func (f *Feature) OwnerHoldStarted(s *vault.Session) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := s.Now()
	for _, id := range f.sorted() {
		c := f.calls[id]
		if c.Dir != DirIn || c.State != StateRinging || !c.live(now) {
			continue
		}
		s.NotifyDevicesWith("call.end", endJSON(c.ID, "unavailable"), "", vault.SendOptions{})
		f.finish(s, c, "unavailable")
		f.missed(s, c)
	}
}

// OwnerHoldEnded implements vault.OwnerHoldObserver.
func (f *Feature) OwnerHoldEnded(*vault.Session) {}

// CallAnsweredBefore implements vault.CallGate: the device is the call
// device of an active call answered before t.
func (f *Feature) CallAnsweredBefore(device string, t time.Time) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if c.Device == device && c.State == StateActive && !c.Answered.IsZero() && c.Answered.Before(t) {
			return true
		}
	}
	return false
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
