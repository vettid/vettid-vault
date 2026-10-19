//go:build vmsvectors

package vectors

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/crypto/argon2"

	"github.com/vettid/vettid-vault/vms/recovery"
)

// Release R (VAULT-MESSAGING 0.33.0 §11.14, §16): the same inputs as the
// specification's excerpts, but with every Argon2id output computed from
// its inputs: the unlock key's x at t = 3, m = 64 MiB and the recovery
// wrap's x at t = 3, m = 1 GiB. Nonces are scripted. The 1 GiB step runs
// only with VMS_HEAVY_VECTORS=1 (or when the checked-in file lacks it);
// otherwise its output is read back from testdata/vectors/recovery.json,
// and TestReleaseRVectors recomputes it under the same variable.

const (
	rPIN      = "123456"
	rPassword = "correct horse battery staple"
	rVaultID  = "test-vault-0001"
	rRecID    = "01JB2Z6V9K3M4N5P6Q7R8S9T30"
)

func heavyXFromFile() ([]byte, bool) {
	b, err := os.ReadFile(filepath.Join(Dir, "recovery.json"))
	if err != nil {
		return nil, false
	}
	var f struct {
		R struct {
			X string `json:"x_hex"`
		} `json:"release_r"`
	}
	if json.Unmarshal(b, &f) != nil || f.R.X == "" {
		return nil, false
	}
	x, err := hex.DecodeString(f.R.X)
	return x, err == nil && len(x) == 32
}

func sealScripted(nonce byte, f func() ([]byte, error)) ([]byte, error) {
	var out []byte
	err := with(newScript(rep(nonce, 24)), func() (err error) {
		out, err = f()
		return err
	})
	return out, err
}

func genRecoveryR() (obj, error) {
	pw, ok := recovery.NormalizePassword([]byte(rPassword))
	if !ok {
		return nil, errors.New("password")
	}
	secrets, err := recovery.Secrets(rPIN, pw)
	if err != nil {
		return nil, err
	}
	salt := rep(0x48, 16)
	x, cached := heavyXFromFile()
	if !cached || os.Getenv("VMS_HEAVY_VECTORS") == "1" {
		x = argon2.IDKey(secrets, salt, recovery.HeavyTime, recovery.HeavyMemoryKiB, 1, 32)
	}
	pepper := rep(0x32, 32)
	k, err := recovery.WrapKey(x, pepper, rVaultID, 1)
	if err != nil {
		return nil, err
	}
	wrap, err := sealScripted(0x34, func() ([]byte, error) { return recovery.WrapRecoveryKey(k, rep(0x33, 32), rVaultID, 1) })
	if err != nil {
		return nil, err
	}
	opener, err := sealScripted(0x36, func() ([]byte, error) { return recovery.MakeOpener(rep(0x33, 32), rep(0x35, 32), rVaultID, 1, 1) })
	if err != nil {
		return nil, err
	}
	tag, err := recovery.WrongTag(x, pepper, rVaultID, rRecID, rep(0x04, 32))
	if err != nil {
		return nil, err
	}
	n, err := recovery.NewNames(rep(0x51, 32), rVaultID)
	if err != nil {
		return nil, err
	}
	open, err := recovery.OpenSigningString(recovery.OpenFields{UserGUID: "test-user-guid", VaultID: rVaultID,
		RequestID: "01JB2Z6V9K3M4N5P6Q7R8S9T31", RecoveryID: rRecID, TS: "2026-10-15T12:00:00.000Z", ETKKid: "40d6c2c8471844a9",
		Secrets: secrets, Token: []byte("test-token"), Manifest: []byte("manifest"), UnlockSecret: rep(0x42, 32)})
	if err != nil {
		return nil, err
	}
	bk := append([]byte{4}, rep(0x61, 64)...)
	req, err := recovery.RequestSigningString(recovery.OpRecovery, rVaultID, "test-user-guid", "01JB2Z6V9K3M4N5P6Q7R8S9T32", "2026-10-15T12:00:00Z", bk, "")
	if err != nil {
		return nil, err
	}
	cancel, err := recovery.RequestSigningString(recovery.OpRecoveryCancel, rVaultID, "test-user-guid", "01JB2Z6V9K3M4N5P6Q7R8S9T33", "2026-10-15T12:00:00Z", nil, "")
	if err != nil {
		return nil, err
	}
	// 0.49.0: a cancel that names its recovery (the eighth line).
	cancelNamed, err := recovery.RequestSigningString(recovery.OpRecoveryCancel, rVaultID, "test-user-guid", "01JB2Z6V9K3M4N5P6Q7R8S9T33", "2026-10-15T12:00:00Z", nil,
		"01JB2Z6V9K3M4N5P6Q7R8S9T32")
	if err != nil {
		return nil, err
	}
	sh := sha256.Sum256(secrets)
	return obj{
		{"description", "VAULT-MESSAGING 0.33.0 §11.14.3, §11.14.6, §11.14.8 and VAULT-HOST-PROTOCOL 0.1.10 §8.1 (release R), the §16 inputs with x computed: x = Argon2id(secrets, salt, t = 3, m = 1,048,576 KiB, p = 1, 32). secrets = len(PIN) (2) || PIN || len(password) (2) || NFC(password). K = HKDF-SHA-256(x, salt = pepper, info = \"vettid/vms/2/recovery-wrap\" || 0x00 || vault_id || 0x00 || generation (8)); wrap = nonce || XChaCha20-Poly1305(K, nonce, aad = info, recovery_key); opener = nonce || XChaCha20-Poly1305(recovery_key, nonce, \"vettid/vms/2/recovery-opener\" || 0x00 || vault_id || 0x00 || generation (8) || dek_version (8), DEK). TEST ONLY."},
		{"vault_id", rVaultID},
		{"pin", rPIN},
		{"password", rPassword},
		{"secrets_hex", hx(secrets)},
		{"secrets_sha256_hex", hx(sh[:])},
		{"salt_hex", hx(salt)},
		{"kdf", obj{{"alg", "argon2id"}, {"t", recovery.HeavyTime}, {"m", recovery.HeavyMemoryKiB}, {"p", 1}}},
		{"x_hex", hx(x)},
		{"pepper_hex", hx(pepper)},
		{"generation", 1},
		{"k_hex", hx(k)},
		{"recovery_key_hex", hx(rep(0x33, 32))},
		{"wrap_hex", hx(wrap)},
		{"dek_hex", hx(rep(0x35, 32))},
		{"dek_version", 1},
		{"opener_hex", hx(opener)},
		{"recovery_id", rRecID},
		{"device_ik_hex", hx(rep(0x04, 32))},
		{"last_wrong_hex", hx(tag)},
		{"open_signing_string", open},
		{"request_signing_string", req},
		{"cancel_signing_string", cancel},
		{"cancel_named_signing_string", cancelNamed},
		{"counter", obj{
			{"counter_key_hex", hx(rep(0x51, 32))},
			{"generation", 1},
			{"vault_tag", n.VaultTag()},
			{"present", n.Present()},
			{"token_1", n.Token(1, 1)},
			{"wait_2", n.Wait(1, 2)},
			{"success_1", n.Success(1, 1)},
			{"close", n.Close(1)},
		}},
	}, nil
}

func genUnlockR() (obj, error) {
	salt := rep(0x47, 16)
	x := argon2.IDKey([]byte(rPIN), salt, recovery.UnlockTime, recovery.UnlockMemKiB, 1, 32)
	pepper, sec, sec2 := rep(0x32, 32), rep(0x42, 32), rep(0x45, 32)
	uk, err := recovery.UnlockKey(x, sec, pepper, rVaultID)
	if err != nil {
		return nil, err
	}
	wrap, err := sealScripted(0x43, func() ([]byte, error) { return recovery.WrapDEK(uk, rep(0x35, 32), rVaultID, 1) })
	if err != nil {
		return nil, err
	}
	sc, err := recovery.SecretCheck(pepper, rVaultID, sec)
	if err != nil {
		return nil, err
	}
	ukn, err := recovery.UnlockKey(x, sec2, pepper, rVaultID)
	if err != nil {
		return nil, err
	}
	next, err := sealScripted(0x46, func() ([]byte, error) { return recovery.WrapDEKNext(ukn, rep(0x35, 32), rep(0x37, 32), rVaultID, 2) })
	if err != nil {
		return nil, err
	}
	scn, err := recovery.SecretCheck(pepper, rVaultID, sec2)
	if err != nil {
		return nil, err
	}
	return obj{
		{"description", "VAULT-MESSAGING 0.33.0 §11.14.1 and §11.14.2 (release R), the §16 inputs with x computed: x = Argon2id(PIN, salt, t = 3, m = 65,536 KiB, p = 1, 32); unlock_key = HKDF-SHA-256(ikm = x || unlock_secret, salt = pepper, info = \"vettid/vms/2/unlock-key\" || 0x00 || vault_id); dek_wrap = nonce || XChaCha20-Poly1305(unlock_key, nonce, \"vettid/vms/2/dek-wrap\" || 0x00 || vault_id || 0x00 || dek_version (8), DEK); secret_check = HMAC-SHA-256(pepper, \"vettid/vms/2/unlock-secret-check\" || 0x00 || vault_id || 0x00 || unlock_secret); dek_wrap_next under the next secret's unlock key holds DEK_0 || DEK_1, aad label \"vettid/vms/2/dek-wrap-next\" with DEK_1's version. unlock_secret = HMAC-SHA-256(phone key, \"vettid/vms/2/unlock-secret\" || 0x00 || vault_id || 0x00 || epoch (8)). TEST ONLY."},
		{"vault_id", rVaultID},
		{"pin", rPIN},
		{"salt_hex", hx(salt)},
		{"kdf", obj{{"alg", "argon2id"}, {"t", recovery.UnlockTime}, {"m", recovery.UnlockMemKiB}, {"p", 1}}},
		{"x_hex", hx(x)},
		{"pepper_hex", hx(pepper)},
		{"unlock_secret_hex", hx(sec)},
		{"unlock_key_hex", hx(uk)},
		{"dek_hex", hx(rep(0x35, 32))},
		{"dek_version", 1},
		{"dek_wrap_hex", hx(wrap)},
		{"secret_check_hex", hx(sc)},
		{"next", obj{
			{"unlock_secret_hex", hx(sec2)},
			{"unlock_key_hex", hx(ukn)},
			{"dek1_hex", hx(rep(0x37, 32))},
			{"dek_version", 2},
			{"dek_wrap_next_hex", hx(next)},
			{"secret_check_next_hex", hx(scn)},
		}},
		{"phone", obj{
			{"phone_key_hex", hx(rep(0x44, 32))},
			{"epoch_1_hex", hx(recovery.PhoneUnlockSecret(rep(0x44, 32), rVaultID, 1))},
			{"epoch_2_hex", hx(recovery.PhoneUnlockSecret(rep(0x44, 32), rVaultID, 2))},
		}},
	}, nil
}
