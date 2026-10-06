package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"net/http"

	"github.com/vettid/vettid-vault/vms/altchan"
)

// The app key (VAULT-MESSAGING 0.15.0, §11.12.2): a per-app P-256 key that
// signs every app request to the member API. A real app keeps it in
// Android Keystore or the iOS Secure Enclave; this reference client keeps
// its scalar in the device state (development and tests).

// AppKey returns this app's app key and its SPKI DER, making it on first
// use.
func (d *Device) AppKey() (*ecdsa.PrivateKey, []byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.appKeyLocked()
}

func (d *Device) appKeyLocked() (*ecdsa.PrivateKey, []byte, error) {
	if d.st.AppKey == nil {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		b, err := k.Bytes()
		if err != nil {
			return nil, nil, err
		}
		d.st.AppKey = b
	}
	k, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), d.st.AppKey)
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	return k, der, nil
}

// AppKeyB64 returns the app key as the API takes it: standard base64 of
// the SPKI DER.
func (d *Device) AppKeyB64() (string, error) {
	_, der, err := d.AppKey()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(der), nil
}

// APIFor returns a member API client whose requests this app's key signs
// for its vault (§11.12.2): the app holds no member session.
func (d *Device) APIFor(base string, hc *http.Client) (*MemberAPI, error) {
	k, _, err := d.AppKey()
	if err != nil {
		return nil, err
	}
	return &MemberAPI{Base: base, HTTP: hc, AppKey: k, Vault: d.VaultID}, nil
}

// signApp adds X-VettID-App to req (body: the exact body bytes).
func (a *MemberAPI) signApp(req *http.Request, body []byte) error {
	k := a.AppKey
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		return err
	}
	nonce, err := altchan.NewAppNonce()
	if err != nil {
		return err
	}
	vault := ""
	if a.Vault != nil && !a.unbound {
		vault = a.Vault()
	}
	now := a.now()
	r := &altchan.AppRequest{Method: req.Method, Path: req.URL.EscapedPath(), Query: req.URL.RawQuery, VaultID: vault,
		KID: altchan.AppKeyID(der), TS: now.Unix(), Nonce: nonce, Body: body}
	h, err := r.Sign(k)
	if err != nil {
		return err
	}
	req.Header.Set(altchan.AppHeaderName, h)
	return nil
}

// RedeemResult is the redeem's answer (§11.12.1).
type RedeemResult struct {
	VaultID   string `json:"vault_id"`
	UserGUID  string `json:"user_guid"`
	EmailHint string `json:"email_hint"`
}

// Redeem redeems a setup code (§11.12.1): the QR secret (secret != ""),
// or the member's email with the typed code. The request is signed by the
// app key being registered, with an empty vault.
func (a *MemberAPI) Redeem(ctx context.Context, secret, email, code string) (*RedeemResult, error) {
	der, err := x509.MarshalPKIXPublicKey(&a.AppKey.PublicKey)
	if err != nil {
		return nil, err
	}
	body := map[string]string{"app_key": base64.StdEncoding.EncodeToString(der)}
	if secret != "" {
		body["secret"] = secret
	} else {
		body["email"], body["code"] = email, code
	}
	var out RedeemResult
	u := *a
	u.unbound = true
	if err := u.do(ctx, http.MethodPost, "/api/vault/enroll/redeem", body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// RecoveryClaim claims a recovery with the app key (§11.11.7): the QR's
// vault_id and recovery_id; the answer names the member.
func (a *MemberAPI) RecoveryClaim(ctx context.Context, vaultID, recoveryID string) (*RedeemResult, error) {
	der, err := x509.MarshalPKIXPublicKey(&a.AppKey.PublicKey)
	if err != nil {
		return nil, err
	}
	var out RedeemResult
	u := *a
	u.Vault = func() string { return vaultID }
	if err := u.do(ctx, http.MethodPost, "/api/vault/recovery/claim", map[string]string{"vault_id": vaultID, "recovery_id": recoveryID,
		"app_key": base64.StdEncoding.EncodeToString(der)}, &out); err != nil {
		return nil, err
	}
	out.VaultID = vaultID
	return &out, nil
}

// RedeemVia redeems a setup code with this app's key and records the
// vault id the API assigned, which then names the vault in the app key's
// requests (enclave, enroll, polls; §11.12.1).
func (d *Device) RedeemVia(ctx context.Context, api *MemberAPI, secret, email, code string) (*RedeemResult, error) {
	r, err := api.Redeem(ctx, secret, email, code)
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	if d.st.VaultID == "" {
		d.st.VaultID = r.VaultID
	}
	d.st.UserGUID = r.UserGUID
	d.mu.Unlock()
	return r, nil
}

// ClaimVia claims a recovery from its QR with this app's key and records
// the member's id (§11.11.7).
func (d *Device) ClaimVia(ctx context.Context, api *MemberAPI, qr *altchan.RecoveryCode) (*RedeemResult, error) {
	r, err := api.RecoveryClaim(ctx, qr.VaultID, qr.RecoveryID)
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	d.st.UserGUID = r.UserGUID
	if d.st.VaultID == "" {
		d.st.VaultID = qr.VaultID // names the vault in the claim key's requests
	}
	d.mu.Unlock()
	return r, nil
}

// UserGUID returns the member's id from the redeem or claim.
func (d *Device) UserGUID() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.st.UserGUID
}

// EnrollCode is a setup code the portal issued (§11.12.1).
type EnrollCode struct {
	Secret    string `json:"secret"`
	Code      string `json:"code"`
	ExpiresAt string `json:"expires_at"`
	API       string `json:"api"`
}

// IssueEnrollCode is the portal's POST /api/vault/enroll-code (a member
// session: Authorize).
func (a *MemberAPI) IssueEnrollCode(ctx context.Context) (*EnrollCode, error) {
	var out EnrollCode
	if err := a.do(ctx, http.MethodPost, "/api/vault/enroll-code", map[string]string{}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// QR is the code's QR payload (§11.12.1).
func (c *EnrollCode) QR() ([]byte, error) {
	s, err := altchan.ParseQRSecret(c.Secret)
	if err != nil {
		return nil, err
	}
	return (&altchan.EnrollQR{API: c.API, Secret: s}).Marshal(), nil
}
