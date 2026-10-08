package credential

import (
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// A request of another feature that carries the vault PIN alone in a
// UTK-sealed payload, as the enrolling app's vault.delete does (§3.5.4;
// History's audit.export, §10.9, VAULT-MESSAGING 0.22.0). It is not a
// credential operation: no blob, no password, no CEK rotation and no
// UTKs in the answer. The caller checks the PIN with vault.Session
// .VerifyPIN under the §11.8 backoff.

// HolderGate answers forbidden unless the sender is the holder's app
// (not a recovering app, a desktop or an agent), then, while a clone alarm
// is open, the alarm's freeze code, credential_frozen or
// rotation_required (§3.5.9; owner decision of 2026-10-08). It spends
// nothing.
func (f *Feature) HolderGate(s *vault.Session) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.holderGate(s)
}

func (f *Feature) holderGate(s *vault.Session) error {
	from := s.From()
	if from.Kind != vault.KindApp || from.Recovering || f.st.Holder == "" || from.ID != f.st.Holder {
		return errForbidden
	}
	if f.st.Alarm != nil {
		return f.freezeErr()
	}
	return nil
}

// SpendPIN runs HolderGate (so that an alarm refuses the request before
// the UTK is spent), then spends the UTK utkID issued to the sender and
// opens sealed, bound to in's type and id, as {pin}: utk_invalid for an
// unknown, expired or spent UTK or a payload that does not open,
// bad_request for a PIN that is not 6–32 ASCII digits (the UTK stays
// spent). The caller owns the returned PIN and must wipe it.
func (f *Feature) SpendPIN(s *vault.Session, in *envelope.Inner, utkID string, sealed []byte) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pruneUTKs(s.Now())
	if err := f.holderGate(s); err != nil {
		return nil, err
	}
	if !ValidUTKID(utkID) {
		return nil, errBad
	}
	p, err := f.spendNeed(s, in, &Envelope{UTKID: utkID, Sealed: sealed}, needPIN)
	if err != nil {
		return nil, err
	}
	pin := p.PIN
	p.PIN = nil
	p.Wipe()
	return pin, nil
}
