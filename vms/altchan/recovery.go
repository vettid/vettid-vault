package altchan

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/json"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Recovery (VAULT-MESSAGING §11.11).
const (
	TypeRecoveryRequest  = "vault.recovery.request"
	TypeRecoveryCancel   = "vault.recovery.cancel"
	TypeRecoveryRegister = "vault.recovery.register"
	TypeRecoveryResult   = "vault.recovery.result"

	// BrowserKeySize is an uncompressed P-256 point.
	BrowserKeySize = 65
	// LabelRecoverySeal labels the sealed code (§11.11.2).
	LabelRecoverySeal = "vettid/vms/2/recovery-code-seal"
	sealedCodeVersion = 0x01
	sealedCodeHeader  = 1 + BrowserKeySize + 12
)

// SealedCodeSize is the sealed code's size: the size of every result in
// the response slot (§11.5).
const SealedCodeSize = ResultEnvelopeSize

// RecoveryCode is what the vault seals to the member's browser.
type RecoveryCode struct {
	VaultID    string
	RecoveryID string
	Code       string
	// API is the QR's member API origin (0.15.0, §11.11.2): an identifier
	// the app compares with its own, never an address. Empty: the 0.10.6
	// payload (the recovery.json vector).
	API       string
	NotBefore time.Time
	Expires   time.Time
	// Error is set instead of the code when the vault refused the request
	// ("no_credential", §11.11.1).
	Error string
}

func codeKey(shared, eph, browser []byte, vaultID, recoveryID string) ([]byte, error) {
	salt := append(append([]byte(nil), eph...), browser...)
	return hkdf.Key(sha256.New, shared, salt, LabelRecoverySeal+"\x00"+vaultID+"\x00"+recoveryID, 32)
}

// ephemeralP256 draws the seal's ephemeral key from the library's
// randomness source (the OS CSPRNG; scripted only in vmsvectors builds, for
// the §16 recovery vector): a 32-byte scalar, redrawn in the negligible
// case that it is 0 or not below the group order.
func ephemeralP256() (*ecdh.PrivateKey, error) {
	for range 8 {
		b, err := suite.RandomBytes(32)
		if err != nil {
			return nil, err
		}
		k, err := ecdh.P256().NewPrivateKey(b)
		suite.Wipe(b)
		if err == nil {
			return k, nil
		}
	}
	return nil, suite.ErrRandom
}

// SealRecoveryCode seals the code to the browser's P-256 key (§11.11.2):
//
//	out = 0x01 || eph (65) || nonce (12) || AES-256-GCM(k, nonce, aad = out[0:78], pt)
//	k   = HKDF-SHA-256(ECDH(eph, browser), salt = eph || browser,
//	                   info = label || 0x00 || vault_id || 0x00 || recovery_id)
//
// pt is the JSON {v, vault_id, recovery_id, code, not_before, expires_at}
// followed by zero bytes up to SealedCodeSize. Its random draws, in order:
// the ephemeral scalar (32 bytes), then the nonce (12).
func SealRecoveryCode(browserKey []byte, c *RecoveryCode) ([]byte, error) {
	pub, err := ecdh.P256().NewPublicKey(browserKey)
	if err != nil {
		return nil, ErrMalformed
	}
	eph, err := ephemeralP256()
	if err != nil {
		return nil, err
	}
	shared, err := eph.ECDH(pub)
	if err != nil {
		return nil, err
	}
	defer suite.Wipe(shared)
	ephPub := eph.PublicKey().Bytes()
	k, err := codeKey(shared, ephPub, browserKey, c.VaultID, c.RecoveryID)
	if err != nil {
		return nil, err
	}
	defer suite.Wipe(k)
	b := strictjson.NewBuilder().Uint("v", 1).String("vault_id", c.VaultID).String("recovery_id", c.RecoveryID)
	if c.Error != "" {
		b.String("error", c.Error)
	} else {
		b.String("code", c.Code).String("not_before", envelope.FormatTS(c.NotBefore)).String("expires_at", envelope.FormatTS(c.Expires))
	}
	pt := b.Bytes()
	n := SealedCodeSize - sealedCodeHeader - 16
	if len(pt) > n {
		return nil, ErrMalformed
	}
	pt = append(pt, make([]byte, n-len(pt))...)
	defer suite.Wipe(pt)
	nonce, err := suite.RandomBytes(12)
	if err != nil {
		return nil, err
	}
	blk, _ := aes.NewCipher(k)
	g, _ := cipher.NewGCM(blk)
	out := append(append([]byte{sealedCodeVersion}, ephPub...), nonce...)
	return g.Seal(out, nonce, pt, out[:sealedCodeHeader]), nil
}

// OpenRecoveryCode opens a sealed code with the browser's private key
// (what the portal does in WebCrypto; Go for tests and tools).
func OpenRecoveryCode(priv *ecdh.PrivateKey, sealed []byte, vaultID, recoveryID string) (*RecoveryCode, error) {
	if len(sealed) != SealedCodeSize || sealed[0] != sealedCodeVersion {
		return nil, ErrMalformed
	}
	eph, err := ecdh.P256().NewPublicKey(sealed[1 : 1+BrowserKeySize])
	if err != nil {
		return nil, ErrMalformed
	}
	shared, err := priv.ECDH(eph)
	if err != nil {
		return nil, ErrMalformed
	}
	defer suite.Wipe(shared)
	k, err := codeKey(shared, sealed[1:1+BrowserKeySize], priv.PublicKey().Bytes(), vaultID, recoveryID)
	if err != nil {
		return nil, err
	}
	defer suite.Wipe(k)
	blk, _ := aes.NewCipher(k)
	g, _ := cipher.NewGCM(blk)
	pt, err := g.Open(nil, sealed[1+BrowserKeySize:sealedCodeHeader], sealed[sealedCodeHeader:], sealed[:sealedCodeHeader])
	if err != nil {
		return nil, ErrMalformed
	}
	return parseCode(bytes.TrimRight(pt, "\x00"), vaultID, recoveryID)
}

func parseCode(b []byte, vaultID, recoveryID string) (*RecoveryCode, error) {
	o, err := strictjson.ParseObject(b)
	if err != nil {
		return nil, ErrMalformed
	}
	c := &RecoveryCode{}
	if v, err := o.Uint("v", 1, 1); err != nil || v != 1 {
		return nil, ErrMalformed
	}
	if c.VaultID, err = o.String("vault_id"); err != nil || c.VaultID != vaultID {
		return nil, ErrMalformed
	}
	if c.RecoveryID, err = o.String("recovery_id"); err != nil || c.RecoveryID != recoveryID {
		return nil, ErrMalformed
	}
	if e, present, err := o.OptString("error"); err != nil {
		return nil, ErrMalformed
	} else if present {
		if e == "" || len(e) > 64 {
			return nil, ErrMalformed
		}
		c.Error = e
		return c, nil
	}
	if c.Code, err = o.String("code"); err != nil {
		return nil, ErrMalformed
	}
	for _, f := range []struct {
		n string
		t *time.Time
	}{{"not_before", &c.NotBefore}, {"expires_at", &c.Expires}} {
		s, err := o.String(f.n)
		if err != nil {
			return nil, ErrMalformed
		}
		if *f.t, err = envelope.ParseTS(s); err != nil {
			return nil, ErrMalformed
		}
	}
	return c, nil
}

// RecoveryQR is the QR payload the portal shows and the new app scans
// (§11.11.2): compact JSON {"v":1,"t":"r","api","vault_id","recovery_id","code"}
// (api since 0.15.0; absent when c.API is empty, the 0.10.6 form).
func RecoveryQR(c *RecoveryCode) []byte {
	b := strictjson.NewBuilder().Uint("v", 1).String("t", "r")
	if c.API != "" {
		b.String("api", c.API)
	}
	return b.String("vault_id", c.VaultID).String("recovery_id", c.RecoveryID).String("code", c.Code).Bytes()
}

// ParseRecoveryQR parses the QR payload strictly.
func ParseRecoveryQR(b []byte) (*RecoveryCode, error) {
	o, err := strictjson.ParseObject(b)
	if err != nil {
		return nil, ErrMalformed
	}
	c := &RecoveryCode{}
	if v, err := o.Uint("v", 1, 1); err != nil || v != 1 {
		return nil, ErrMalformed
	}
	if t, err := o.String("t"); err != nil || t != "r" {
		return nil, ErrMalformed
	}
	if api, ok, err := o.OptString("api"); err != nil || ok && !validOrigin(api) {
		return nil, ErrMalformed
	} else if ok {
		c.API = api // an app of 0.15.0 requires it and compares it with its own (§11.11.2)
	}
	if c.VaultID, err = o.String("vault_id"); err != nil || !validVaultID(c.VaultID, false) {
		return nil, ErrMalformed
	}
	if c.RecoveryID, err = o.String("recovery_id"); err != nil || !envelope.ValidULID(c.RecoveryID) {
		return nil, ErrMalformed
	}
	if c.Code, err = o.String("code"); err != nil || len(c.Code) != 32 {
		return nil, ErrMalformed
	}
	return c, nil
}

// RecoveryRegisterRequest is the vault.recovery.register body (§11.11.3).
type RecoveryRegisterRequest struct {
	UserGUID, VaultID, RequestID, RecoveryID, Code string
	IK                                             ed25519.PublicKey
	KEM                                            *suite.PublicKey
	Relay                                          RelayAddr
	Name                                           string
	Attest                                         *DeviceAttest
	// APIKey is the new app's app key, SPKI DER (0.15.0, §11.11.3).
	APIKey []byte
}

// Marshal encodes the body.
func (r *RecoveryRegisterRequest) Marshal() ([]byte, error) {
	da, err := r.Attest.Marshal()
	if err != nil {
		return nil, err
	}
	app := strictjson.NewBuilder().Base64("ik", r.IK).Base64("kem", r.KEM.Bytes()).Raw("relay", r.Relay.marshal()).
		String("name", r.Name).Raw("device_attest", da).Base64("api_key", r.APIKey).Bytes()
	return strictjson.NewBuilder().String("user_guid", r.UserGUID).String("vault_id", r.VaultID).
		String("request_id", r.RequestID).String("recovery_id", r.RecoveryID).String("code", r.Code).Raw("app", app).Bytes(), nil
}

// ParseRecoveryRegister parses the body strictly. Its app.kem is parsed
// first (EnrollKEM), so that failures can be answered.
func ParseRecoveryRegister(o strictjson.Object) (*RecoveryRegisterRequest, error) {
	r := &RecoveryRegisterRequest{}
	var err error
	if r.KEM, err = EnrollKEM(o); err != nil {
		return nil, err
	}
	app, err := o.Object("app")
	if err != nil {
		return nil, ErrMalformed
	}
	for _, f := range []struct {
		n string
		d *string
	}{{"user_guid", &r.UserGUID}, {"vault_id", &r.VaultID}, {"request_id", &r.RequestID}, {"recovery_id", &r.RecoveryID}, {"code", &r.Code}} {
		if *f.d, err = o.String(f.n); err != nil || len(*f.d) > 128 {
			return nil, ErrMalformed
		}
	}
	if !envelope.ValidULID(r.RecoveryID) || len(r.Code) != 32 {
		return nil, ErrMalformed
	}
	if r.IK, err = app.Base64("ik", ed25519.PublicKeySize); err != nil {
		return nil, ErrMalformed
	}
	ro, err := app.Object("relay")
	if err != nil {
		return nil, ErrMalformed
	}
	if r.Relay.URL, err = ro.String("url"); err != nil {
		return nil, ErrMalformed
	}
	if r.Relay.Mailbox, err = ro.String("mailbox"); err != nil {
		return nil, ErrMalformed
	}
	if r.Relay.PK, err = ro.Base64("pk", ed25519.PublicKeySize); err != nil {
		return nil, ErrMalformed
	}
	if r.Name, err = app.String("name"); err != nil || len(r.Name) > 128 {
		return nil, ErrMalformed
	}
	da, ok := app["device_attest"]
	if !ok {
		return nil, ErrMalformed
	}
	if r.Attest, err = ParseDeviceAttest(da); err != nil {
		return nil, ErrMalformed
	}
	if r.APIKey, err = appAPIKey(app); err != nil {
		return nil, err
	}
	return r, nil
}

// RecoveryResult is the body of vault.recovery.result.
type RecoveryResult struct {
	OK   bool
	Code string
}

// Marshal encodes the body.
func (r *RecoveryResult) Marshal() []byte {
	b := strictjson.NewBuilder().Bool("ok", r.OK)
	if !r.OK {
		b.String("code", r.Code)
	}
	return b.Bytes()
}

// ParseRecoveryResult parses the body strictly.
func ParseRecoveryResult(raw json.RawMessage) (*RecoveryResult, error) {
	o, err := strictjson.ParseObject(raw)
	if err != nil {
		return nil, ErrMalformed
	}
	r := &RecoveryResult{}
	if r.OK, err = o.Bool("ok"); err != nil {
		return nil, ErrMalformed
	}
	if !r.OK {
		if r.Code, err = o.String("code"); err != nil {
			return nil, ErrMalformed
		}
	}
	return r, nil
}
