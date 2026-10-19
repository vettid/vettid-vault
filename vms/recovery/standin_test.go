package recovery

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// The VAULT-MESSAGING 0.33.0 §16 "release R" excerpts, computed for the
// specification with a fixed stand-in for each Argon2id output. These
// tests reproduce them byte for byte; the real Argon2id steps are in
// testdata/vectors (unlock.json, recovery.json "release_r").

func rep(b byte, n int) []byte { return bytes.Repeat([]byte{b}, n) }

func eq(t *testing.T, name string, got []byte, want string) {
	t.Helper()
	if hex.EncodeToString(got) != want {
		t.Errorf("%s:\n got %x\nwant %s", name, got, want)
	}
}

const vid = "test-vault-0001"

func TestStandInRecoveryWrap(t *testing.T) {
	secrets, err := Secrets("123456", []byte("correct horse battery staple"))
	if err != nil {
		t.Fatal(err)
	}
	eq(t, "secrets", secrets, "0006313233343536001c636f727265637420686f727365206261747465727920737461706c65")
	h := sha256.Sum256(secrets)
	eq(t, "SHA-256(secrets)", h[:], "6286862e0e08397dc6b79b2b39f3e37ea03fd8a21ca6c1d09bf33fe9d89e5452")
	x, pepper := rep(0x31, 32), rep(0x32, 32)
	k, err := WrapKey(x, pepper, vid, 1)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, "K", k, "eed3b4582a8e58183008274885b713b80e054aba79d8c9c0fb9d50e04e9c13ac")
	wrap, err := sealNonce(k, rep(0x34, 24), wrapInfo(vid, 1), rep(0x33, 32))
	if err != nil {
		t.Fatal(err)
	}
	eq(t, "wrap", wrap, "343434343434343434343434343434343434343434343434"+
		"1e4e898261636a4818354295d8f18c80bb6f74cd32faf796a7dd51256e2c47965ef579b8096d083518f59a16f4c7b1ae")
	if rk, err := OpenRecoveryKey(k, wrap, vid, 1); err != nil || !bytes.Equal(rk, rep(0x33, 32)) {
		t.Error("wrap does not open")
	}
	if _, err := OpenRecoveryKey(k, wrap, vid, 2); err == nil {
		t.Error("wrap opened under another generation")
	}
	op, err := sealNonce(rep(0x33, 32), rep(0x36, 24), openerAAD(vid, 1, 1), rep(0x35, 32))
	if err != nil {
		t.Fatal(err)
	}
	eq(t, "opener", op, "363636363636363636363636363636363636363636363636"+
		"feb4842d8bba2e7ea8f663fedb68b5ed8dacb56c049b00c3d1f55fe742c578ff6978ebc27968acfcfbda3294b7c5077f")
	if d, err := OpenOpener(rep(0x33, 32), op, vid, 1, 1); err != nil || !bytes.Equal(d, rep(0x35, 32)) {
		t.Error("opener does not open")
	}
	if _, err := OpenOpener(rep(0x33, 32), op, vid, 1, 2); err == nil {
		t.Error("opener opened for another dek_version")
	}
}

func TestStandInWrongTag(t *testing.T) {
	x, pepper := rep(0x31, 32), rep(0x32, 32)
	tag, err := WrongTag(x, pepper, vid, "01JB2Z6V9K3M4N5P6Q7R8S9T30", rep(0x04, 32))
	if err != nil {
		t.Fatal(err)
	}
	eq(t, "last_wrong", tag, "2ea0aae12ca8f3f7102a8ee4efd2682d9a46cb3577c2c649a37c89ea48821d34")
}

func TestStandInSigningStrings(t *testing.T) {
	secrets, _ := Secrets("123456", []byte("correct horse battery staple"))
	s, err := OpenSigningString(OpenFields{UserGUID: "test-user-guid", VaultID: vid, RequestID: "01JB2Z6V9K3M4N5P6Q7R8S9T31",
		RecoveryID: "01JB2Z6V9K3M4N5P6Q7R8S9T30", TS: "2026-10-15T12:00:00.000Z", ETKKid: "40d6c2c8471844a9",
		Secrets: secrets, Token: []byte("test-token"), Manifest: []byte("manifest"), UnlockSecret: rep(0x42, 32)})
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256([]byte(s))
	eq(t, "open signing string", h[:], "82ff1eb1b573f3976fce3f6a1095e03ddfc59e42ca18bbc5be1cd9e0a2c58240")
	bk := append([]byte{4}, rep(0x61, 64)...)
	r, err := RequestSigningString(OpRecovery, vid, "test-user-guid", "01JB2Z6V9K3M4N5P6Q7R8S9T32", "2026-10-15T12:00:00Z", bk, "")
	if err != nil {
		t.Fatal(err)
	}
	h = sha256.Sum256([]byte(r))
	eq(t, "request signing string", h[:], "f2f13d600b7e4f438171e03451a91c0c1bd8d79a18342558a9f60b32297e89a1")
	c, err := RequestSigningString(OpRecoveryCancel, vid, "u", "r", "2026-10-15T12:00:00Z", nil, "")
	if err != nil || c[len(c)-1] != '\n' {
		t.Errorf("cancel string must end with an empty last line: %q", c)
	}
	// VAULT-MESSAGING 0.49.0 §16: recovery_cancel in seven lines (no
	// recovery_id, the last line empty) and in eight (recovery_id after
	// the empty seventh).
	c7, err := RequestSigningString(OpRecoveryCancel, vid, "test-user-guid", "01JB2Z6V9K3M4N5P6Q7R8S9T33", "2026-10-15T12:00:00Z", nil, "")
	if err != nil {
		t.Fatal(err)
	}
	h = sha256.Sum256([]byte(c7))
	eq(t, "seven-line cancel", h[:], "027c441758559d461017926a1bba3b56cb6fa320ead17987859236a1731ba2c1")
	c8, err := RequestSigningString(OpRecoveryCancel, vid, "test-user-guid", "01JB2Z6V9K3M4N5P6Q7R8S9T33", "2026-10-15T12:00:00Z", nil, "01JB2Z6V9K3M4N5P6Q7R8S9T32")
	if err != nil {
		t.Fatal(err)
	}
	if want := c7 + "\n01JB2Z6V9K3M4N5P6Q7R8S9T32"; c8 != want {
		t.Fatalf("eight-line cancel %q, want %q", c8, want)
	}
	h = sha256.Sum256([]byte(c8))
	eq(t, "eight-line cancel", h[:], "f62e0062d49f9459d738869c16bc04dbc7f65f5235099296384af9ce7a768ec5")
	// A recovery never carries recovery_id, a cancel never a browser key.
	if _, err := RequestSigningString(OpRecovery, vid, "u", "r", "2026-10-15T12:00:00Z", bk, "01JB2Z6V9K3M4N5P6Q7R8S9T32"); err == nil {
		t.Error("a recovery with recovery_id")
	}
	if _, err := RequestSigningString(OpRecoveryCancel, vid, "u", "r", "2026-10-15T12:00:00Z", bk, ""); err == nil {
		t.Error("a cancel with a browser key")
	}
	if _, err := RequestSigningString(OpRecoveryCancel, vid, "u", "r", "2026-10-15T12:00:00Z", nil, "a\nb"); err == nil {
		t.Error("a recovery_id with a newline")
	}
}

func TestStandInUnlock(t *testing.T) {
	x, sec, pepper := rep(0x41, 32), rep(0x42, 32), rep(0x32, 32)
	uk, err := UnlockKey(x, sec, pepper, vid)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, "unlock_key", uk, "bede45517cf0d7c4448b8c55eef6a33dd9c6b3da18c83c25c357bc45e48af952")
	w, _ := sealNonce(uk, rep(0x43, 24), dekWrapAAD(vid, 1), rep(0x35, 32))
	eq(t, "dek_wrap", w, "434343434343434343434343434343434343434343434343"+
		"d2aa6bac61e76d83925647254c77fd7a6a63148432cf511eb22c8bad1345a1ad8a9473e229eda25520fdfbdee0962796")
	sc, _ := SecretCheck(pepper, vid, sec)
	eq(t, "secret_check", sc, "89f9fa1389f2e7ecfd0521ab27b39207d867a8acd3f99cd23ba19b3c357ccfde")
	ukn, _ := UnlockKey(x, rep(0x45, 32), pepper, vid)
	eq(t, "unlock_key_next", ukn, "ee25462f13ed11e5da8edeaff79472f91670918da6fada8aab8f55975765c1a3")
	wn, _ := sealNonce(ukn, rep(0x46, 24), dekWrapNextAAD(vid, 2), append(rep(0x35, 32), rep(0x37, 32)...))
	eq(t, "dek_wrap_next", wn, "464646464646464646464646464646464646464646464646"+
		"449ad8681c2613fc6d0b9e6a5225f6117fa90c3aa415d9cacfba8c5824c4e9c973a8c8cb9bb4fcc5afa33d629c9268d1"+
		"53c83541056969d0c66680c201254038b517b7bb2c294d580f330b536bd4bcc4")
	d0, d1, err := OpenDEKNext(ukn, wn, vid, 2)
	if err != nil || !bytes.Equal(d0, rep(0x35, 32)) || !bytes.Equal(d1, rep(0x37, 32)) {
		t.Error("dek_wrap_next does not open")
	}
	eq(t, "phone epoch 1", PhoneUnlockSecret(rep(0x44, 32), vid, 1), "84ae0b66319d60524f6dcffa6fa3c540669caa0f13a2b1cc01c49305d4af7836")
	eq(t, "phone epoch 2", PhoneUnlockSecret(rep(0x44, 32), vid, 2), "03bbaea3348d1fdb182a3474faf655f7f444c74be38ab84423ec21f3a2587f07")
}

func TestStandInCounterNames(t *testing.T) {
	n, err := NewNames(rep(0x51, 32), vid)
	if err != nil {
		t.Fatal(err)
	}
	p := "recovery/v1/486f02bad2b24e6b020d1211ab3bb070/"
	for _, c := range []struct{ got, want string }{
		{n.VaultTag(), "486f02bad2b24e6b020d1211ab3bb070"},
		{n.Present(), p + "present-94b1a52264abd447e9becade916aab4f"},
		{n.Token(1, 1), p + "g0000000000000001/t01-2124cc9d1a43ea50ee44f20a1bbd6b5d"},
		{n.Wait(1, 2), p + "g0000000000000001/w02-b270c8be143728446662bd950cba5128"},
		{n.Success(1, 1), p + "g0000000000000001/s01-a6137b69bdad29e9324bb5a311cbbb8a"},
		{n.Close(1), p + "g0000000000000001/c-9959b12f3b2e807bac9851cd64d3fd9c"},
	} {
		if c.got != c.want {
			t.Errorf("got %s want %s", c.got, c.want)
		}
	}
}

func TestWaitSchedule(t *testing.T) {
	want := []uint64{0, 1, 2, 4, 8, 16, 30, 30, 30, 0}
	for k := 1; k <= 10; k++ {
		if WaitUnits(k) != want[k-1] {
			t.Errorf("W(%d) = %d", k, WaitUnits(k))
		}
	}
	// Earliest next from attempt 2, cumulative (the table's second row).
	cum, row := uint64(0), []uint64{1, 3, 7, 15, 31, 61, 91, 121}
	for k := 2; k <= 9; k++ {
		cum += WaitUnits(k)
		if cum != row[k-2] {
			t.Errorf("after attempt %d: %d days", k, cum)
		}
	}
}
