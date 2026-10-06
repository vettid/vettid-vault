package credential

import (
	"encoding/json"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
)

// The daily owner check (VAULT-MESSAGING 0.13.0, §3.6.1): the holder's
// vault.owner_check{credential, utk_id, sealed{pin, password, hold?,
// hold_off_until?}} verifies the PIN and the credential password
// together. It is a credential operation, so it rotates the CEK. The
// runtime keeps the record and the hold (vault.OwnerCheckHost).

// holdChange parses the payload's hold change (§3.6.7): hold_off_until
// only with hold false, RFC 3339, in the future and at most 30 days
// ahead. Anything else is bad_request, answered once the UTK is opened and
// before the PIN is tried, so it is not a failed check.
func holdChange(p *Payload, now time.Time) (*vault.HoldChange, error) {
	if !p.HasHold {
		if p.HoldOffUntil != "" {
			return nil, errBad
		}
		return nil, nil
	}
	if p.Hold {
		if p.HoldOffUntil != "" {
			return nil, errBad
		}
		return &vault.HoldChange{On: true}, nil
	}
	c := &vault.HoldChange{}
	if p.HoldOffUntil != "" {
		t, err := time.Parse(time.RFC3339Nano, p.HoldOffUntil)
		if err != nil || !t.After(now) || t.After(now.Add(vault.MaxHoldOff)) {
			return nil, errBad
		}
		c.Until = t.UTC()
	}
	return c, nil
}

// ownerCheck performs steps 2–8 of §3.6.1 (step 1, the alarm, is the
// gate; the UTK is spent and the payload opened by the caller).
func (f *Feature) ownerCheck(s *vault.Session, e *Envelope, p *Payload) (json.RawMessage, error) {
	change, err := holdChange(p, s.Now())
	if err != nil {
		return nil, err
	}
	// Step 3: the blob (stale_credential for the holder's own retry, a
	// clone otherwise).
	if err := f.checkBlob(s, e.Blob); err != nil {
		return nil, err
	}
	// Steps 4–5: the PIN under the §11.8 backoff.
	if err := s.VerifyPIN(string(p.PIN)); err != nil {
		if vault.IsCode(err, "bad_pin") {
			s.OwnerCheckFailed("pin")
		}
		return nil, err
	}
	// Steps 6–7: the password under its backoff.
	cek, inner, err := f.openChecked(s, e.Blob, p.Password)
	if err != nil {
		if err == errPassword {
			s.OwnerCheckFailed("password")
		}
		return nil, err
	}
	defer cek.Destroy()
	defer inner.Wipe()
	// Step 8, in one flush: the CEK rotates, the check is recorded, the
	// hold change applied and a hold ended.
	blob, err := f.rotateCEK(s, inner, p.Password)
	if err != nil {
		return nil, err
	}
	info, err := s.OwnerCheckPassed(change, true)
	if err != nil {
		return nil, err
	}
	b := strictjson.NewBuilder().Base64("credential", blob).Uint("version", f.st.Version).Raw("utks", f.replenish(s))
	info.Members(b)
	return b.Bytes(), nil
}

// OwnerHoldStarted implements vault.OwnerHoldObserver: the unlock window
// ends when the hold begins (§3.5.3, §3.6.3).
func (f *Feature) OwnerHoldStarted(_ *vault.Session) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.endWindow()
}

// OwnerHoldEnded implements vault.OwnerHoldObserver. It runs inside the
// credential's own handler (a check, a transfer's approval, a recovery):
// it must not take the lock.
func (f *Feature) OwnerHoldEnded(_ *vault.Session) {}

// AlarmState implements vault.CredentialAlarm.
func (f *Feature) AlarmState() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.st.Alarm == nil {
		return ""
	}
	return f.st.Alarm.State
}
