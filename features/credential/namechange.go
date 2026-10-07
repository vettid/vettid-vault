package credential

import (
	"encoding/json"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// The account's name change from the app (VAULT-MESSAGING 0.18.0, §10.8;
// owner decisions of 2026-10-07): the holder's
// account.name.set{credential, utk_id, sealed{pin, password, first_name,
// last_name}} is checked as the daily owner check is (the same backoffs,
// counts and audit entries) and rotates the CEK, but it is not an owner
// check (the deadline does not move). The runtime stores the request and
// reports it to the host (vault.NameRequestHost); the member API applies
// it and the snapshot settles it.

var errTooSoon = func(allowed string) error {
	return &vault.HandlerError{Code: "too_soon", Body: strictjson.NewBuilder().String("allowed_after", allowed).Bytes()}
}

// nameSet performs §10.8 steps 2–6 (step 1, spending the UTK and opening
// the payload, is the caller's; the holder and the alarm are the gate,
// the hold is the runtime's).
func (f *Feature) nameSet(s *vault.Session, e *Envelope, p *Payload) (json.RawMessage, error) {
	// Step 2: the 30 days, from the snapshot; nothing is counted.
	if after := s.AccountAllowedAfter(); !after.IsZero() && after.After(s.Now()) {
		return nil, errTooSoon(envelope.FormatTS(after))
	}
	// Step 4, checked before the PIN and the password: a refusal after
	// step 3 would answer bad_request without the credential the CEK
	// rotation just sealed (spec issue reported with 0.18.0's
	// implementation). The names follow the registration rule and must
	// not both equal the current ones.
	first, ok1 := vault.NormalizeRequestedName(p.FirstName)
	last, ok2 := vault.NormalizeRequestedName(p.LastName)
	if !ok1 || !ok2 {
		return nil, errBad
	}
	if cf, cl, ok := s.AccountNames(); ok && cf == first && cl == last {
		return nil, errBad
	}
	// Step 3: the blob, the PIN and the password exactly as the owner
	// check (§3.6.1 steps 3–7), then the CEK rotates.
	if err := f.checkBlob(s, e.Blob); err != nil {
		return nil, err
	}
	if err := s.VerifyPIN(string(p.PIN)); err != nil {
		if vault.IsCode(err, "bad_pin") {
			s.OwnerCheckFailed("pin")
		}
		return nil, err
	}
	cek, inner, err := f.openChecked(s, e.Blob, p.Password)
	if err != nil {
		if err == errPassword {
			s.OwnerCheckFailed("password")
		}
		return nil, err
	}
	defer cek.Destroy()
	defer inner.Wipe()
	blob, err := f.rotateCEK(s, inner, p.Password)
	if err != nil {
		return nil, err
	}
	// Steps 5–6: the request, reported after this flush.
	req, err := s.RequestAccountName(first, last)
	if err != nil {
		return nil, err
	}
	return strictjson.NewBuilder().Base64("credential", blob).Uint("version", f.st.Version).Raw("utks", f.replenish(s)).
		Raw("request", req).Bytes(), nil
}
