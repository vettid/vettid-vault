package vectors

import (
	"bytes"
	"os"
	"testing"

	"golang.org/x/crypto/argon2"

	"github.com/vettid/vettid-vault/vms/recovery"
)

// TestReleaseRVectors checks unlock.json and recovery.json's release_r
// (VAULT-MESSAGING 0.33.0 §16) from their inputs: the 64 MiB Argon2id
// step always, the 1 GiB step with VMS_HEAVY_VECTORS=1; every key, wrap,
// opener, tag, name and signing string re-derived and opened.
func TestReleaseRVectors(t *testing.T) {
	u := load(t, Dir, "unlock.json")
	vid := u.str("vault_id")
	x := argon2.IDKey([]byte(u.str("pin")), u.hex("salt_hex"), 3, 64*1024, 1, 32)
	if !bytes.Equal(x, u.hex("x_hex")) {
		t.Fatal("unlock x")
	}
	pepper := u.hex("pepper_hex")
	uk, _ := recovery.UnlockKey(x, u.hex("unlock_secret_hex"), pepper, vid)
	if !bytes.Equal(uk, u.hex("unlock_key_hex")) {
		t.Error("unlock_key")
	}
	if d, err := recovery.OpenDEK(uk, u.hex("dek_wrap_hex"), vid, uint64(u.num("dek_version"))); err != nil || !bytes.Equal(d, u.hex("dek_hex")) {
		t.Error("dek_wrap")
	}
	if sc, _ := recovery.SecretCheck(pepper, vid, u.hex("unlock_secret_hex")); !bytes.Equal(sc, u.hex("secret_check_hex")) {
		t.Error("secret_check")
	}
	n := u.sub("next")
	ukn, _ := recovery.UnlockKey(x, n.hex("unlock_secret_hex"), pepper, vid)
	if !bytes.Equal(ukn, n.hex("unlock_key_hex")) {
		t.Error("unlock_key_next")
	}
	d0, d1, err := recovery.OpenDEKNext(ukn, n.hex("dek_wrap_next_hex"), vid, uint64(n.num("dek_version")))
	if err != nil || !bytes.Equal(d0, u.hex("dek_hex")) || !bytes.Equal(d1, n.hex("dek1_hex")) {
		t.Error("dek_wrap_next")
	}
	p := u.sub("phone")
	if !bytes.Equal(recovery.PhoneUnlockSecret(p.hex("phone_key_hex"), vid, 1), p.hex("epoch_1_hex")) ||
		!bytes.Equal(recovery.PhoneUnlockSecret(p.hex("phone_key_hex"), vid, 2), p.hex("epoch_2_hex")) {
		t.Error("phone unlock secret")
	}

	r := load(t, Dir, "recovery.json").sub("release_r")
	pw, _ := recovery.NormalizePassword([]byte(r.str("password")))
	secrets, _ := recovery.Secrets(r.str("pin"), pw)
	if !bytes.Equal(secrets, r.hex("secrets_hex")) {
		t.Fatal("secrets")
	}
	rx := r.hex("x_hex")
	if os.Getenv("VMS_HEAVY_VECTORS") == "1" {
		if !bytes.Equal(argon2.IDKey(secrets, r.hex("salt_hex"), 3, 1024*1024, 1, 32), rx) {
			t.Fatal("recovery x (1 GiB)")
		}
	}
	g := uint64(r.num("generation"))
	k, _ := recovery.WrapKey(rx, r.hex("pepper_hex"), vid, g)
	if !bytes.Equal(k, r.hex("k_hex")) {
		t.Error("K")
	}
	if rk, err := recovery.OpenRecoveryKey(k, r.hex("wrap_hex"), vid, g); err != nil || !bytes.Equal(rk, r.hex("recovery_key_hex")) {
		t.Error("wrap")
	}
	if d, err := recovery.OpenOpener(r.hex("recovery_key_hex"), r.hex("opener_hex"), vid, g, uint64(r.num("dek_version"))); err != nil || !bytes.Equal(d, r.hex("dek_hex")) {
		t.Error("opener")
	}
	if tag, _ := recovery.WrongTag(rx, r.hex("pepper_hex"), vid, r.str("recovery_id"), r.hex("device_ik_hex")); !bytes.Equal(tag, r.hex("last_wrong_hex")) {
		t.Error("last_wrong")
	}
	c := r.sub("counter")
	nm, _ := recovery.NewNames(c.hex("counter_key_hex"), vid)
	cg := uint64(c.num("generation"))
	for _, x := range []struct{ got, want string }{{nm.VaultTag(), c.str("vault_tag")}, {nm.Present(), c.str("present")},
		{nm.Token(cg, 1), c.str("token_1")}, {nm.Wait(cg, 2), c.str("wait_2")}, {nm.Success(cg, 1), c.str("success_1")}, {nm.Close(cg), c.str("close")}} {
		if x.got != x.want {
			t.Errorf("counter name %s != %s", x.got, x.want)
		}
	}
}
