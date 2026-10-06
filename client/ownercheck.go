package client

import (
	"context"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// The daily owner check from the app's side (VAULT-MESSAGING 0.13.0,
// §3.6): the PIN and the credential password together, sealed to a UTK,
// with the blob; the CEK rotates. A check may also turn the hold off (with
// an optional end at most 30 days ahead) or on (§3.6.7).

// TypeOwnerCheck is the check's message type, as vault.TypeOwnerCheck.
const TypeOwnerCheck = "vault.owner-check"

// OwnerCheckResult is a successful check's answer (§3.6.1).
type OwnerCheckResult struct {
	Deadline     time.Time
	Interval     time.Duration
	Hold         bool
	HoldOffUntil time.Time // zero: none
}

// HoldOff turns the hold off within a check (until zero: until turned on).
type HoldOff struct{ Until time.Time }

// OwnerCheck sends the owner check (TypeOwnerCheck).
// hold is nil for no change, true to turn the hold on; holdOff, if
// non-nil, turns it off (hold must then be nil).
func (d *Device) OwnerCheck(ctx context.Context, pin, password string, hold *bool, holdOff *HoldOff) (*OwnerCheckResult, error) {
	payload := func() map[string]any {
		p := map[string]any{"pin": pin, "password": password}
		switch {
		case holdOff != nil:
			p["hold"] = false
			if !holdOff.Until.IsZero() {
				p["hold_off_until"] = envelope.FormatTS(holdOff.Until)
			}
		case hold != nil:
			p["hold"] = *hold
		}
		return p
	}
	o, _, _, err := d.credOpWith(ctx, TypeOwnerCheck, nil, payload, false)
	if err != nil {
		return nil, err
	}
	return parseOwnerCheck(o)
}

func parseOwnerCheck(o strictjson.Object) (*OwnerCheckResult, error) {
	r := &OwnerCheckResult{}
	s, err := o.String("deadline")
	if err != nil {
		return nil, ErrProtocol
	}
	if r.Deadline, err = envelope.ParseTS(s); err != nil {
		return nil, ErrProtocol
	}
	secs, err := o.Uint("interval_seconds", 1, strictjson.MaxSafeInteger)
	if err != nil {
		return nil, ErrProtocol
	}
	r.Interval = time.Duration(secs) * time.Second
	if r.Hold, err = o.Bool("hold"); err != nil {
		return nil, ErrProtocol
	}
	if s, ok, err := o.OptString("hold_off_until"); err != nil {
		return nil, ErrProtocol
	} else if ok {
		if r.HoldOffUntil, err = envelope.ParseTS(s); err != nil {
			return nil, ErrProtocol
		}
	}
	return r, nil
}

// OwnerCheckStatus is vault.status's owner_check member (§10.2).
type OwnerCheckStatus struct {
	State    string // ok, due or held
	Deadline time.Time
	Failures uint64
	Hold     bool
}

// OwnerCheckState reads vault.status's owner_check (§3.6.5: the app reads
// it after an unlock, and shows the failures left before the lock).
func (d *Device) OwnerCheckState(ctx context.Context) (*OwnerCheckStatus, error) {
	o, err := d.Op(ctx, "vault.status", nil)
	if err != nil {
		return nil, err
	}
	oc, err := o.Object("owner_check")
	if err != nil {
		return nil, ErrProtocol
	}
	st := &OwnerCheckStatus{}
	if st.State, err = oc.String("state"); err != nil {
		return nil, ErrProtocol
	}
	if s, ok, _ := oc.OptString("deadline"); ok {
		st.Deadline, _ = envelope.ParseTS(s)
	}
	st.Failures, _ = oc.Uint("failures", 0, strictjson.MaxSafeInteger)
	st.Hold, _ = oc.Bool("hold")
	return st, nil
}
