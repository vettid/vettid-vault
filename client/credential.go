package client

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/credwire"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/suite"
)

// The Protean Credential from the app's side (VAULT-MESSAGING §3.5): the
// app keeps the latest blob and a pool of UTKs; every operation seals its
// critical payload to a fresh UTK, stores the new blob the vault returns
// (the CEK rotated) and confirms it; critical values come back sealed to
// a one-time reply key.

// CredentialCopy is an app's copy of the Protean Credential.
type CredentialCopy struct {
	Blob    []byte `json:"blob"`
	Version uint64 `json:"version"`
}

// UTK is one issued transaction key (§3.5.4).
type UTK struct {
	ID      string    `json:"id"`
	EK      []byte    `json:"ek"`
	Expires time.Time `json:"expires"`
}

// ErrNoCredential: the device holds no credential.
var ErrNoCredential = errors.New("client: no credential on this device")

func (d *Device) credential() (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.st.Credential == nil {
		return "", ErrNoCredential
	}
	return base64.StdEncoding.EncodeToString(d.st.Credential.Blob), nil
}

// keep stores the UTKs and the blob a response carries, and confirms the
// blob to the vault (credential.ack, §3.5.3).
func (d *Device) keep(ctx context.Context, o strictjson.Object) error {
	if raw, ok := o["utks"]; ok {
		var us []struct {
			ID      string `json:"utk_id"`
			EK      []byte `json:"ek"`
			Expires string `json:"expires_at"`
		}
		if json.Unmarshal(raw, &us) != nil {
			return ErrProtocol
		}
		d.mu.Lock()
		for _, u := range us {
			exp, err := envelope.ParseTS(u.Expires)
			if err != nil || len(u.EK) != suite.EKSize {
				d.mu.Unlock()
				return ErrProtocol
			}
			d.st.UTKs = append(d.st.UTKs, UTK{ID: u.ID, EK: u.EK, Expires: exp})
		}
		d.mu.Unlock()
	}
	if !o.Has("credential") {
		return nil
	}
	blob, err := o.Base64("credential", -1)
	if err != nil {
		return ErrProtocol
	}
	// Item operations carry the item's version as `version` and the
	// credential's as `credential_version` (§10.6).
	vk := "version"
	if o.Has("credential_version") {
		vk = "credential_version"
	}
	v, err := o.Uint(vk, 1, strictjson.MaxSafeInteger)
	if err != nil {
		return ErrProtocol
	}
	d.mu.Lock()
	d.st.Credential = &CredentialCopy{Blob: blob, Version: v}
	d.mu.Unlock()
	_, err = d.Op(ctx, "credential.ack", map[string]any{"version": v})
	return err
}

// takeUTK returns an unexpired UTK, fetching a pool when empty.
func (d *Device) takeUTK(ctx context.Context) (UTK, error) {
	for attempt := 0; attempt < 2; attempt++ {
		now := d.cfg.Now()
		d.mu.Lock()
		for len(d.st.UTKs) > 0 {
			u := d.st.UTKs[0]
			d.st.UTKs = d.st.UTKs[1:]
			if now.Before(u.Expires) {
				d.mu.Unlock()
				return u, nil
			}
		}
		d.mu.Unlock()
		o, err := d.Op(ctx, "credential.utk.get", nil)
		if err != nil {
			return UTK{}, err
		}
		if err := d.keep(ctx, o); err != nil {
			return UTK{}, err
		}
	}
	return UTK{}, ErrProtocol
}

// sealedOp sends typ with the payload sealed to a fresh UTK, the blob if
// withBlob, and returns the response with its reply key (if any).
func (d *Device) sealedOp(ctx context.Context, typ string, withBlob bool, payload map[string]any, reply bool) (strictjson.Object, *suite.PrivateKey, string, error) {
	u, err := d.takeUTK(ctx)
	if err != nil {
		return nil, nil, "", err
	}
	d.mu.Lock()
	d.lastUTK = u
	d.mu.Unlock()
	return d.sealedWith(ctx, typ, u, nil, withBlob, payload, reply, nil)
}

// CredentialRaw sends a credential operation with an explicit UTK and
// blob (nil: none). It exists for tests of UTK reuse and stale blobs.
func (d *Device) CredentialRaw(ctx context.Context, typ string, u UTK, blob []byte, payload map[string]any) (strictjson.Object, error) {
	o, _, _, err := d.sealedWith(ctx, typ, u, blob, blob != nil, payload, false, nil)
	return o, err
}

// LastUTK returns the UTK the last credential operation spent (tests).
func (d *Device) LastUTK() UTK {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.lastUTK
}

// sealedWith sends typ with the payload sealed to u, the blob, and extra
// outer members (an item operation's item_id, version, tags, ...).
func (d *Device) sealedWith(ctx context.Context, typ string, u UTK, blob []byte, withBlob bool, payload map[string]any, reply bool,
	extra map[string]any) (strictjson.Object, *suite.PrivateKey, string, error) {
	var err error
	var rk *suite.PrivateKey
	if reply {
		if rk, err = suite.GeneratePrivateKey(); err != nil {
			return nil, nil, "", err
		}
		payload["reply_key"] = base64.StdEncoding.EncodeToString(rk.Public().Bytes())
	}
	pt, err := json.Marshal(payload)
	if err != nil {
		return nil, nil, "", err
	}
	defer suite.Wipe(pt)
	ek, err := suite.ParsePublicKey(u.EK)
	if err != nil {
		return nil, nil, "", ErrProtocol
	}
	id, err := envelope.NewULID(d.cfg.Now())
	if err != nil {
		return nil, nil, "", err
	}
	sealed, err := credwire.SealPayload(ek, d.VaultID(), u.ID, typ, id, pt)
	if err != nil {
		return nil, nil, "", err
	}
	body := map[string]any{}
	for k, v := range extra {
		body[k] = v
	}
	body["utk_id"], body["sealed"] = u.ID, base64.StdEncoding.EncodeToString(sealed)
	switch {
	case blob != nil:
		body["credential"] = base64.StdEncoding.EncodeToString(blob)
	case withBlob:
		c, err := d.credential()
		if err != nil {
			return nil, nil, "", err
		}
		body["credential"] = c
	}
	b, _ := json.Marshal(body)
	if _, err := d.SendWithID(ctx, id, typ, b); err != nil {
		return nil, nil, "", err
	}
	r, err := d.AwaitResponse(ctx, id)
	if err != nil {
		return nil, nil, "", err
	}
	if !r.OK() {
		return nil, nil, "", &OpError{Type: typ, Code: r.ErrorCode()}
	}
	o, err := strictjson.ParseObject(r.Body())
	if err != nil {
		return nil, nil, "", ErrProtocol
	}
	if err := d.keep(ctx, o); err != nil {
		return nil, nil, "", err
	}
	return o, rk, id, nil
}

// credOp is sealedOp with the blob; on stale_credential it fetches the
// latest blob once and retries (§3.5.3).
func (d *Device) credOp(ctx context.Context, typ string, payload func() map[string]any, reply bool) (strictjson.Object, *suite.PrivateKey, string, error) {
	return d.credOpWith(ctx, typ, nil, payload, reply)
}

// credOpWith is credOp with extra outer members.
func (d *Device) credOpWith(ctx context.Context, typ string, extra map[string]any, payload func() map[string]any, reply bool) (strictjson.Object, *suite.PrivateKey, string, error) {
	op := func() (strictjson.Object, *suite.PrivateKey, string, error) {
		u, err := d.takeUTK(ctx)
		if err != nil {
			return nil, nil, "", err
		}
		d.mu.Lock()
		d.lastUTK = u
		d.mu.Unlock()
		return d.sealedWith(ctx, typ, u, nil, true, payload(), reply, extra)
	}
	o, rk, id, err := op()
	if Code(err) == "stale_credential" {
		if ferr := d.CredentialFetch(ctx); ferr == nil {
			return op()
		}
	}
	return o, rk, id, err
}

// CredentialCreate creates the Protean Credential and keeps the blob.
func (d *Device) CredentialCreate(ctx context.Context, password string) error {
	_, _, _, err := d.sealedOp(ctx, "credential.create", false, map[string]any{"password": password}, false)
	return err
}

// CredentialFetch fetches the latest blob the vault holds.
func (d *Device) CredentialFetch(ctx context.Context) error {
	o, err := d.Op(ctx, "credential.get", nil)
	if err != nil {
		return err
	}
	return d.keep(ctx, o)
}

// CredentialVersion returns credential.version.
func (d *Device) CredentialVersion(ctx context.Context) (strictjson.Object, error) {
	return d.Op(ctx, "credential.version", nil)
}

// CredentialUnlock opens the unlock window and returns its expiry.
func (d *Device) CredentialUnlock(ctx context.Context, password string) (string, error) {
	o, _, _, err := d.credOp(ctx, "credential.unlock", func() map[string]any { return map[string]any{"password": password} }, false)
	if err != nil {
		return "", err
	}
	return o.String("expires_at")
}

// CredentialLock ends the unlock window.
func (d *Device) CredentialLock(ctx context.Context) error {
	_, err := d.Op(ctx, "credential.lock", nil)
	return err
}

// CredentialRotate rotates the credential key (and the vault's ik and kem).
func (d *Device) CredentialRotate(ctx context.Context, password string) error {
	_, _, _, err := d.credOp(ctx, "credential.rotate", func() map[string]any { return map[string]any{"password": password} }, false)
	return err
}

// CredentialChangePassword re-seals the credential under a new password.
func (d *Device) CredentialChangePassword(ctx context.Context, password, newPassword string) error {
	_, _, _, err := d.credOp(ctx, "credential.password.change", func() map[string]any {
		return map[string]any{"password": password, "new_password": newPassword}
	}, false)
	return err
}

// CredentialResetHolder replaces the holder's credential with a new one
// (VAULT-MESSAGING 0.15.2, §3.5.5): the current blob, the PIN and the
// current password, verified as an owner check, and the new password.
// Every critical item is destroyed; the app keeps the new blob. There is
// no credential deletion on its own.
func (d *Device) CredentialResetHolder(ctx context.Context, pin, password, newPassword string) error {
	_, _, _, err := d.credOp(ctx, "credential.reset", func() map[string]any {
		return map[string]any{"pin": pin, "password": password, "new_password": newPassword}
	}, false)
	return err
}

// CredentialRecover authenticates a recovering app with the credential
// password (§11.11.5) against the vault's copy of the latest blob and
// keeps the credential handed over; afterwards the app is the vault's one
// app. A vault without a backup copy is never recovered (0.16.0).
func (d *Device) CredentialRecover(ctx context.Context, password string) error {
	if _, _, _, err := d.sealedOp(ctx, "credential.recover", false, map[string]any{"password": password}, false); err != nil {
		return err
	}
	d.mu.Lock()
	d.st.Recovery = nil
	d.mu.Unlock()
	return nil
}

// CredentialAlarmConfirm answers a clone alarm (§3.5.9): mine is "that
// was me". It returns the alarm's new state (rotation_required).
func (d *Device) CredentialAlarmConfirm(ctx context.Context, alarmID string, mine bool) (string, error) {
	o, err := d.Op(ctx, "credential.alarm.confirm", map[string]any{"alarm_id": alarmID, "mine": mine})
	if err != nil {
		return "", err
	}
	return o.String("state")
}

// TransferCreate opens a direct transfer to a new phone (§6.7.1) and
// returns its id and the QR link the new app scans.
func (d *Device) TransferCreate(ctx context.Context) (id, link string, err error) {
	o, err := d.Op(ctx, "device.transfer.create", nil)
	if err != nil {
		return "", "", err
	}
	if id, err = o.String("transfer_id"); err != nil {
		return "", "", ErrProtocol
	}
	if link, err = o.String("link"); err != nil {
		return "", "", ErrProtocol
	}
	return id, link, nil
}

// TransferApprove approves the new app with the PIN and the credential
// password (§6.7.1). The vault rotates the CEK: this app's copy is dead
// and the new app fetches the credential.
func (d *Device) TransferApprove(ctx context.Context, id, pin, password string) error {
	_, _, _, err := d.credOpWith(ctx, "device.transfer.approve", map[string]any{"transfer_id": id},
		func() map[string]any { return map[string]any{"password": password, "pin": pin} }, false)
	return err
}

// VaultDelete deletes the vault (§12.5) with the confirmation phrase, the
// PIN and the credential password: from the holder with its blob; from a
// recovering app against the vault's own copy, or with the PIN only when
// the credential is lost (password ""). The vault answers, then tells
// every device and connection and erases itself.
func (d *Device) VaultDelete(ctx context.Context, pin, password string) error {
	payload := func() map[string]any {
		p := map[string]any{"pin": pin}
		if password != "" {
			p["password"] = password
		}
		return p
	}
	extra := map[string]any{"confirm": "delete my vault"}
	d.mu.Lock()
	holder := d.st.Credential != nil && d.st.Recovery == nil
	d.mu.Unlock()
	if holder {
		_, _, _, err := d.credOpWith(ctx, "vault.delete", extra, payload, false)
		return err
	}
	u, err := d.takeUTK(ctx)
	if err != nil {
		return err
	}
	_, _, _, err = d.sealedWith(ctx, "vault.delete", u, nil, false, payload(), false, extra)
	return err
}

// TransferReject ends a transfer (§6.7.1).
func (d *Device) TransferReject(ctx context.Context, id string) error {
	_, err := d.Op(ctx, "device.transfer.reject", map[string]any{"transfer_id": id})
	return err
}

// CredentialBlob returns this app's copy of the blob (the member's own
// backup when the vault keeps none, §3.5.6).
func (d *Device) CredentialBlob() []byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.st.Credential == nil {
		return nil
	}
	return append([]byte(nil), d.st.Credential.Blob...)
}

// UTKCount returns the number of UTKs the app holds (tests, tools).
func (d *Device) UTKCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.st.UTKs)
}

// TakeUTK takes an unused UTK from the pool (tests and tools).
func (d *Device) TakeUTK(ctx context.Context) (UTK, error) { return d.takeUTK(ctx) }
