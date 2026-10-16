package enclave

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/altchan"
	"github.com/vettid/vettid-vault/vms/devattest"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/recovery"
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

// recoveryRequest mints the code, records it and returns it sealed to
// the member's browser key (§11.11.1, §11.11.2). A vault without a
// credential or without a backup copy of it (0.16.0) is refused, sealed
// too, and refused reports the clear marker recovery_unavailable. Any
// failure is answered with random bytes of the same size.
func (c *Core) recoveryRequest(ctx context.Context, j *Job) (res []byte, mk Marker) {
	o, err := strictjson.ParseObject(j.Inner.Body)
	if err != nil {
		return opaque(), mk
	}
	bk, err := o.Base64("browser_key", altchan.BrowserKeySize)
	if err != nil {
		return opaque(), mk
	}
	refuse := func(why string) ([]byte, Marker) {
		r, ok := RefuseRecovery(bk, j.VaultID, j.RequestID, why)
		if !ok {
			return r, Marker{}
		}
		return r, Marker{Code: CodeRecoveryUnavailable, Reason: why}
	}
	if !c.cfg.Recovery.Offered {
		return refuse("not_offered") // §11.14.13
	}
	p, sealer := c.headerParams(j, c.recoveryNow)
	defer sealer.Destroy()
	code, rec, earliest, err := vault.RecoveryRequest(ctx, p, j.RequestID, vault.RecoveryDelay)
	switch {
	case errors.Is(err, vault.ErrRecoveryNoCredential):
		return refuse("no_credential")
	case errors.Is(err, vault.ErrRecoveryNoBackup):
		return refuse("no_backup")
	case err != nil:
		return opaque(), mk
	}
	sealed, err := altchan.SealRecoveryCode(bk, &altchan.RecoveryCode{VaultID: j.VaultID, RecoveryID: j.RequestID, Code: code,
		NotBefore: rec.NotBefore, Expires: rec.Expires})
	if err != nil {
		return opaque(), mk
	}
	// §11.14.5: the clear not_before, expires and earliest beside the code.
	return sealed, Marker{NotBefore: rec.NotBefore, Expires: rec.Expires, Earliest: earliest}
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
func (c *Core) recoveryRegister(ctx context.Context, q *Job) (res []byte, mk Marker) {
	res, ok := c.recoveryRegisterOK(ctx, q)
	if ok {
		mk.Code = CodeRecoveryRegistered
	}
	return res, mk
}

func (c *Core) recoveryRegisterOK(ctx context.Context, q *Job) (res []byte, ok bool) {
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
		// 0.27.0 (§11.11.3 check 6): the signer is recorded with the
		// registered key; it becomes the vault's binding only when the
		// recovery completes (§11.7.1).
		return c.marshalBinding(b)
	})
	return answer(vault.RecoveryCodeResult(err))
}

// recoveryOpen is vault.recovery.open (0.33.0, release R, §11.14.6): the
// binding (user_guid, vault_id, request_id and the queue's app_key, which
// must be the registered phone's), the signature and device assertion of
// the registered phone, the manifest, then the vault's steps 1 to 6. The
// result is sealed to the phone's kem recorded at register; a counted
// attempt carries the clear recovery_attempt marker.
func (c *Core) recoveryOpen(ctx context.Context, q *Job, started **vault.Manager) ([]byte, Marker) {
	inner := q.Inner
	now := c.now()
	o, err := strictjson.ParseObject(inner.Body)
	if err != nil {
		return opaque(), Marker{}
	}
	r, err := altchan.ParseRecoveryOpen(o)
	if err != nil {
		return opaque(), Marker{}
	}
	defer suite.Wipe(r.UnlockSecret)
	if r.UserGUID != q.UserGUID || r.VaultID != q.VaultID || r.RequestID != q.RequestID {
		return opaque(), Marker{} // redirected (§11.6)
	}
	ts := envelope.FormatTS(inner.TS)
	ch, err := altchan.DevattChallenge(q.RequestID, q.VaultID, ts)
	if err != nil {
		return opaque(), Marker{}
	}
	pw := r.Password
	defer suite.Wipe(pw)
	mh, err := hex.DecodeString(r.ManifestSHA256)
	if err != nil {
		return opaque(), Marker{}
	}
	secrets, err := recovery.Secrets(r.PIN, normalized(pw))
	if err != nil {
		return opaque(), Marker{}
	}
	signing, err := recovery.OpenSigningString(recovery.OpenFields{UserGUID: r.UserGUID, VaultID: r.VaultID, RequestID: r.RequestID,
		RecoveryID: r.RecoveryID, TS: ts, ETKKid: q.ETKKid.String(), Secrets: secrets, Token: []byte(r.Token), ManifestSHA256: mh,
		UnlockSecret: r.UnlockSecret})
	suite.Wipe(secrets)
	if err != nil {
		return opaque(), Marker{}
	}
	pol := c.cfg.DeviceAttest
	list := c.statusList()
	sealer := c.sealerFor("", c.meas.PCR0)
	p := vault.RecoveryOpenParams{Options: c.vaultOptions(sealer), VaultID: q.VaultID, UserGUID: q.UserGUID, RecoveryID: r.RecoveryID,
		DeviceIK: r.DeviceIK, PIN: r.PIN, Password: pw, UnlockSecret: r.UnlockSecret, DeviceToken: r.Token}
	p.RecoveryNow = c.recoveryNow
	p.VerifyDevice = func(app *vault.RecoveryApp) (json.RawMessage, error) {
		if !suite.Equal(app.APIKey, q.AppKey) {
			return nil, vault.ErrDeviceSig // the queue's app_key is the registered phone's (§11.11.7)
		}
		if !ed25519.Verify(ed25519.PublicKey(app.IK), []byte(signing), r.Sig) {
			return nil, vault.ErrDeviceSig
		}
		var b devattest.Binding
		if len(app.Attestation) == 0 || json.Unmarshal(app.Attestation, &b) != nil {
			return nil, vault.ErrDeviceAttestation
		}
		nb, err := devattest.VerifyAssertion(pol, &b, r.Assertion, devattest.ForChallenge(ch), b.Counter, now, list)
		if err != nil {
			return nil, vault.ErrDeviceAttestation
		}
		return json.Marshal(nb)
	}
	p.Manifest = func(seen uint64) (*vault.ManifestView, error) {
		_, own, err := c.verifyManifest(q.Manifest, r.ManifestSHA256, r.ManifestSerial, seen)
		if err != nil {
			return nil, err
		}
		return &vault.ManifestView{Serial: r.ManifestSerial, Own: entryOf(own), Lookup: func(string) (vault.ReleaseEntry, bool) {
			return vault.ReleaseEntry{}, false
		}}, nil
	}
	mgr, out := vault.RecoveryOpen(ctx, p)
	for _, ev := range out.Events {
		c.emit(ev)
	}
	if out.Drop || len(out.DeviceKEM) == 0 {
		sealer.Destroy()
		return opaque(), Marker{}
	}
	kem, err := suite.ParsePublicKey(out.DeviceKEM)
	if err != nil {
		sealer.Destroy()
		if mgr != nil {
			_ = mgr.Lock(ctx)
		}
		return opaque(), Marker{}
	}
	res := &altchan.RecoveryOpenResult{OK: out.OK, Code: out.Code, StateSeq: out.StateSeq, HeaderSeq: out.HeaderSeq, Token: out.Token,
		VaultBundle: out.VaultBundle, Release: c.meas.PCR0, ReleaseNumber: c.cfg.ReleaseNumber, Counted: out.HasUsed, Used: out.Used,
		RetryAt: out.RetryAt, AttemptUsed: out.AttemptUsed()}
	if mgr != nil {
		*started = mgr
	} else {
		sealer.Destroy()
	}
	env, err := altchan.SealResult(kem, altchan.TypeRecoveryOpenResult, q.RequestID, res.Marshal(), now)
	if err != nil {
		return opaque(), Marker{}
	}
	var mk Marker
	if out.Counted {
		mk = Marker{Code: CodeRecoveryAttempt, RetryAt: out.RetryAt, Expires: out.Expires}
	}
	return env, mk
}

// normalized is the password's NFC form (or the bytes, if not UTF-8; the
// vault refuses those).
func normalized(pw []byte) []byte {
	if n, ok := recovery.NormalizePassword(pw); ok {
		return n
	}
	return pw
}
