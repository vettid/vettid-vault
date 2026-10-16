package altchan

import (
	"crypto/ed25519"
	"encoding/base64"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/recovery"
)

// The recovery open (VAULT-MESSAGING 0.33.0, release R, §11.14.6): the
// registered phone's attempt at the PIN and the password together.
const (
	TypeRecoveryOpen       = "vault.recovery.open"
	TypeRecoveryOpenResult = "vault.recovery.open.result"
)

// RecoveryOpenRequest is the vault.recovery.open body.
type RecoveryOpenRequest struct {
	UserGUID, VaultID, RequestID, RecoveryID string
	DeviceIK                                 ed25519.PublicKey
	PIN                                      string
	Password                                 []byte // wiped by the caller
	UnlockSecret                             []byte
	Token                                    string
	Assertion                                *DeviceAssertion
	ManifestSHA256                           string
	ManifestSerial                           uint64
	Sig                                      []byte
}

// Marshal encodes the body in §11.14.6 member order.
func (r *RecoveryOpenRequest) Marshal() ([]byte, error) {
	da, err := r.Assertion.Marshal()
	if err != nil {
		return nil, err
	}
	return strictjson.NewBuilder().String("user_guid", r.UserGUID).String("vault_id", r.VaultID).
		String("request_id", r.RequestID).String("recovery_id", r.RecoveryID).Base64("device_ik", r.DeviceIK).
		String("pin", r.PIN).String("password", string(r.Password)).Base64("unlock_secret", r.UnlockSecret).
		String("token", r.Token).Raw("device_assertion", da).String("manifest_sha256", r.ManifestSHA256).
		Uint("manifest_serial", r.ManifestSerial).Base64("sig", r.Sig).Bytes(), nil
}

// ParseRecoveryOpen parses the body strictly. A password longer than
// 1,024 bytes or a secret that is not 32 bytes is malformed.
func ParseRecoveryOpen(o strictjson.Object) (*RecoveryOpenRequest, error) {
	r := &RecoveryOpenRequest{}
	var err error
	for _, f := range []struct {
		n string
		d *string
	}{{"user_guid", &r.UserGUID}, {"vault_id", &r.VaultID}, {"request_id", &r.RequestID}, {"recovery_id", &r.RecoveryID},
		{"pin", &r.PIN}, {"token", &r.Token}} {
		if *f.d, err = o.String(f.n); err != nil {
			return nil, ErrMalformed
		}
	}
	pw, err := o.String("password")
	if err != nil {
		return nil, ErrMalformed
	}
	r.Password = []byte(pw)
	if !ValidPIN(r.PIN) || len(r.Password) == 0 || len(r.Password) > recovery.MaxPasswordBytes || r.Token == "" || len(r.Token) > 4096 ||
		!envelope.ValidULID(r.RecoveryID) {
		return nil, ErrMalformed
	}
	if r.DeviceIK, err = o.Base64("device_ik", ed25519.PublicKeySize); err != nil {
		return nil, ErrMalformed
	}
	if r.UnlockSecret, err = o.Base64("unlock_secret", UnlockSecretSize); err != nil {
		return nil, ErrMalformed
	}
	da, ok := o["device_assertion"]
	if !ok {
		return nil, ErrMalformed
	}
	if r.Assertion, err = ParseDeviceAssertion(da); err != nil {
		return nil, ErrMalformed
	}
	if r.ManifestSHA256, r.ManifestSerial, err = parseManifestRef(o); err != nil {
		return nil, err
	}
	if r.Sig, err = o.Base64("sig", ed25519.SignatureSize); err != nil {
		return nil, ErrMalformed
	}
	return r, nil
}

// RecoveryOpenResult is vault.recovery.open.result (§11.14.6).
type RecoveryOpenResult struct {
	OK            bool
	Code          string
	StateSeq      uint64
	HeaderSeq     uint64
	Token         string
	VaultBundle   []byte
	Release       string
	ReleaseNumber uint64
	UnlockID      string
	// Used is attempts.used, present when Counted is set (the counter
	// answered); RetryAt comes with quiet, wait, and a wrong or lost
	// attempt that began a wait.
	Counted bool
	Used    int
	RetryAt time.Time
	// AttemptUsed is attempt_used (0.34.0), in every result: this
	// request's Spend was answered spent or lost.
	AttemptUsed bool
}

// Marshal encodes the result.
func (r *RecoveryOpenResult) Marshal() []byte {
	b := strictjson.NewBuilder().Bool("ok", r.OK)
	if r.OK {
		b.Uint("state_seq", r.StateSeq).Uint("header_seq", r.HeaderSeq).String("token", r.Token).
			String("vault_bundle", base64.StdEncoding.EncodeToString(r.VaultBundle)).String("release", r.Release).
			Uint("release_number", r.ReleaseNumber).String("unlock_id", r.UnlockID)
	} else {
		b.String("code", r.Code)
	}
	b.Bool("attempt_used", r.AttemptUsed)
	if r.Counted {
		b.Raw("attempts", strictjson.NewBuilder().Uint("used", uint64(r.Used)).Uint("of", recovery.MaxAttempts).Bytes())
	}
	if !r.RetryAt.IsZero() {
		b.String("retry_at", envelope.FormatTS(r.RetryAt))
	}
	return b.Bytes()
}

// ParseRecoveryOpenResult parses a result (the reference client).
func ParseRecoveryOpenResult(o strictjson.Object) (*RecoveryOpenResult, error) {
	r := &RecoveryOpenResult{}
	var err error
	if r.OK, err = o.Bool("ok"); err != nil {
		return nil, ErrMalformed
	}
	if r.OK {
		if r.StateSeq, err = o.Uint("state_seq", 0, strictjson.MaxSafeInteger); err != nil {
			return nil, ErrMalformed
		}
		if r.HeaderSeq, err = o.Uint("header_seq", 0, strictjson.MaxSafeInteger); err != nil {
			return nil, ErrMalformed
		}
		if r.Token, err = o.String("token"); err != nil {
			return nil, ErrMalformed
		}
		s, err := o.String("vault_bundle")
		if err != nil {
			return nil, ErrMalformed
		}
		if r.VaultBundle, err = strictjson.DecodeStd(s, -1); err != nil {
			return nil, ErrMalformed
		}
		r.Release, _ = o.String("release")
		r.ReleaseNumber, _ = o.Uint("release_number", 0, strictjson.MaxSafeInteger)
		r.UnlockID, _ = o.String("unlock_id")
	} else if r.Code, err = o.String("code"); err != nil {
		return nil, ErrMalformed
	}
	if r.AttemptUsed, err = o.Bool("attempt_used"); err != nil {
		return nil, ErrMalformed
	}
	if a, err := o.Object("attempts"); err == nil {
		used, err := a.Uint("used", 0, recovery.MaxAttempts)
		if err != nil {
			return nil, ErrMalformed
		}
		r.Counted, r.Used = true, int(used)
	}
	if s, ok, err := o.OptString("retry_at"); err != nil {
		return nil, ErrMalformed
	} else if ok {
		if r.RetryAt, err = envelope.ParseTS(s); err != nil {
			return nil, ErrMalformed
		}
	}
	return r, nil
}
