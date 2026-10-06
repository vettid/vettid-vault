package enclave

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/altchan"
	"github.com/vettid/vettid-vault/vms/devattest"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Recovery (VAULT-MESSAGING §11.11). These jobs run in the vault's own
// process like enroll and unlock, but never derive the DEK: they work on
// the sealed header only.

func (c *Core) headerParams(j *Job, now func() time.Time) (vault.HeaderParams, *kmsSealer) {
	sealer := c.sealerFor("", c.meas.PCR0)
	o := c.vaultOptions(sealer)
	o.Now = now
	return vault.HeaderParams{Options: o, VaultID: j.VaultID, UserGUID: j.UserGUID}, sealer
}

// recoveryNow is the clock for the recovery's delay and expiry checks.
func (c *Core) recoveryNow() time.Time {
	if c.cfg.RecoveryNow != nil {
		return c.cfg.RecoveryNow()
	}
	return c.now()
}

// recoveryRequest mints the code, records it and returns it sealed to
// the member's browser key (§11.11.1, §11.11.2). A vault without a
// credential or without a backup copy of it (0.16.0) is refused, sealed
// too, and refused reports the clear marker recovery_unavailable. Any
// failure is answered with random bytes of the same size.
func (c *Core) recoveryRequest(ctx context.Context, j *Job) (res []byte, refused bool) {
	o, err := strictjson.ParseObject(j.Inner.Body)
	if err != nil {
		return opaque(), false
	}
	bk, err := o.Base64("browser_key", altchan.BrowserKeySize)
	if err != nil {
		return opaque(), false
	}
	p, sealer := c.headerParams(j, c.recoveryNow)
	defer sealer.Destroy()
	code, rec, err := vault.RecoveryRequest(ctx, p, j.RequestID, vault.RecoveryDelay)
	switch {
	case errors.Is(err, vault.ErrRecoveryNoCredential):
		return RefuseRecovery(bk, j.VaultID, j.RequestID, "no_credential")
	case errors.Is(err, vault.ErrRecoveryNoBackup):
		return RefuseRecovery(bk, j.VaultID, j.RequestID, "no_backup")
	case err != nil:
		return opaque(), false
	}
	sealed, err := altchan.SealRecoveryCode(bk, &altchan.RecoveryCode{VaultID: j.VaultID, RecoveryID: j.RequestID, Code: code,
		NotBefore: rec.NotBefore, Expires: rec.Expires})
	if err != nil {
		return opaque(), false
	}
	return sealed, false
}

// RefuseRecovery seals a recovery refusal to the member's browser key
// (§11.11.2: {"v":1,"vault_id","recovery_id","error"}): "no_credential"
// or "no_backup" (0.16.0). It carries no secret, so the instance can seal
// it for a running vault without opening anything.
func RefuseRecovery(browserKey []byte, vaultID, recoveryID, reason string) ([]byte, bool) {
	sealed, err := altchan.SealRecoveryCode(browserKey, &altchan.RecoveryCode{VaultID: vaultID, RecoveryID: recoveryID, Error: reason})
	if err != nil {
		return opaque(), false
	}
	return sealed, true
}

// recoveryCancel ends whatever recovery is in progress (the API keeps at
// most one per vault).
func (c *Core) recoveryCancel(ctx context.Context, j *Job) {
	p, sealer := c.headerParams(j, c.recoveryNow)
	defer sealer.Destroy()
	_ = vault.RecoveryCancel(ctx, p, "")
}

// recoveryRegister checks the code and the new app's device attestation
// and registers the app as an unlock key (§11.11.3). ok reports a sealed
// {"ok": true}: the answer then carries the clear marker (0.10.6).
func (c *Core) recoveryRegister(ctx context.Context, q *Job) (res []byte, ok bool) {
	inner := q.Inner
	o, err := strictjson.ParseObject(inner.Body)
	if err != nil {
		return opaque(), false
	}
	kem, err := altchan.EnrollKEM(o)
	if err != nil {
		return opaque(), false
	}
	answer := func(code string) ([]byte, bool) {
		r := &altchan.RecoveryResult{OK: code == "", Code: code}
		env, err := altchan.SealResult(kem, altchan.TypeRecoveryResult, q.RequestID, r.Marshal(), c.now())
		if err != nil {
			return opaque(), false
		}
		return env, r.OK
	}
	r, err := altchan.ParseRecoveryRegister(o)
	if err != nil || handshake.ValidateRelayAddr(handshake.RelayAddr{URL: r.Relay.URL, Mailbox: r.Relay.Mailbox, PK: r.Relay.PK}) != nil {
		return answer("bad_request")
	}
	if r.UserGUID != q.UserGUID || r.VaultID != q.VaultID || r.RequestID != q.RequestID || !suite.Equal(r.APIKey, q.AppKey) {
		return opaque(), false // redirected (§11.6); app.api_key bound like user_guid (§11.11.3, 0.15.0)
	}
	ch, err := altchan.DevattChallenge(q.RequestID, q.VaultID, envelope.FormatTS(inner.TS))
	if err != nil {
		return answer("bad_request")
	}
	p, sealer := c.headerParams(q, c.recoveryNow)
	defer sealer.Destroy()
	app := vault.RecoveryApp{IK: r.IK, KEM: r.KEM.Bytes(), RelayPK: r.Relay.PK, Name: r.Name, APIKey: r.APIKey}
	err = vault.RecoveryRegister(ctx, p, r.RecoveryID, r.Code, app, func() (json.RawMessage, error) {
		b, err := devattest.VerifyAttest(c.cfg.DeviceAttest, r.Attest, ch, c.now(), c.statusList())
		if err != nil {
			return nil, err
		}
		return json.Marshal(b)
	})
	return answer(vault.RecoveryCodeResult(err))
}
