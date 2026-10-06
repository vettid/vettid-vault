package altchan

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/suite"
)

// testManifestSHA256 is hex(SHA-256("{}")).
const testManifestSHA256 = "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"

func testKEM(t testing.TB) *suite.PrivateKey {
	k, err := suite.NewPrivateKey(bytes.Repeat([]byte{5}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func sampleEnroll(t testing.TB) *EnrollRequest {
	_, ak := testAppKey(t, 0x41)
	return &EnrollRequest{APIKey: ak, UserGUID: "user-1", RequestID: "01JB2Z6V9K3M4N5P6Q7R8S9T20", Nonce: bytes.Repeat([]byte{9}, 32),
		PIN: "123456", IK: bytes.Repeat([]byte{1}, 32), KEM: testKEM(t).Public(),
		Relay:     RelayAddr{URL: "https://relay.example", Mailbox: "mb", PK: bytes.Repeat([]byte{2}, 32)},
		OpenToken: "v4.public.x", Name: "phone",
		Attest: &DeviceAttest{Platform: PlatformIOS, KeyID: []byte{1}, Attestation: []byte{2}}, ManifestSHA256: testManifestSHA256, ManifestSerial: 7}
}

func sampleUnlock() *UnlockRequest {
	return &UnlockRequest{UserGUID: "user-1", VaultID: "vault-1", RequestID: "01JB2Z6V9K3M4N5P6Q7R8S9T21",
		DeviceIK: bytes.Repeat([]byte{1}, 32), PIN: "123456", MinStateSeq: 3, MinHeaderSeq: 4, Token: "v4.public.y",
		Assertion: &DeviceAssertion{Platform: PlatformAndroid, Sig: []byte{3}}, ManifestSHA256: testManifestSHA256, ManifestSerial: 7,
		Update: &ReleaseUpdate{To: strings.Repeat("cd", 48), ToRelease: 4, Approval: &DeviceAssertion{Platform: PlatformAndroid, Sig: []byte{4}}},
		Sig:    bytes.Repeat([]byte{7}, ed25519.SignatureSize)}
}

func TestRequestRoundTrip(t *testing.T) {
	b, err := sampleEnroll(t).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	o, _ := strictjson.ParseObject(b)
	e, err := ParseEnrollRequest(o)
	if err != nil || e.Name != "phone" || e.Attest.Platform != PlatformIOS {
		t.Fatalf("%v %+v", err, e)
	}
	u := sampleUnlock()
	b, err = u.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	o, _ = strictjson.ParseObject(b)
	got, err := ParseUnlockRequest(o)
	if err != nil || got.Update == nil || got.Update.ToRelease != 4 || got.MinHeaderSeq != 4 {
		t.Fatalf("%v %+v", err, got)
	}
	for name, mut := range map[string]func(string) string{
		"pin letters": func(s string) string { return strings.Replace(s, `"pin":"123456"`, `"pin":"12a456"`, 1) },
		"short pin":   func(s string) string { return strings.Replace(s, `"pin":"123456"`, `"pin":"123"`, 1) },
		"upper to": func(s string) string {
			return strings.Replace(s, strings.Repeat("cd", 48), strings.Repeat("CD", 48), 1)
		},
		"to_release 0": func(s string) string {
			return strings.Replace(s, `"to_release":4`, `"to_release":0`, 1)
		},
		"no assertion": func(s string) string { return strings.Replace(s, `"device_assertion"`, `"device_assertionx"`, 1) },
		"dup":          func(s string) string { return strings.Replace(s, `"pin":"123456"`, `"pin":"123456","pin":"123456"`, 1) },
		"no manifest_sha256": func(s string) string {
			return strings.Replace(s, `"manifest_sha256"`, `"manifest_sha256x"`, 1)
		},
		"upper manifest_sha256": func(s string) string {
			return strings.Replace(s, testManifestSHA256, strings.ToUpper(testManifestSHA256), 1)
		},
		"manifest_serial 0":  func(s string) string { return strings.Replace(s, `"manifest_serial":7`, `"manifest_serial":0`, 1) },
		"no manifest_serial": func(s string) string { return strings.Replace(s, `"manifest_serial":7`, `"manifest_serialx":7`, 1) },
		"old manifest document": func(s string) string {
			return strings.Replace(s, `"manifest_sha256":"`+testManifestSHA256+`","manifest_serial":7`, `"manifest":{"manifest":"e30=","sig":"`+strings.Repeat("A", 86)+`==","key_id":"1edbb48b6669decd"}`, 1)
		},
	} {
		o, err := strictjson.ParseObject([]byte(mut(string(b))))
		if err != nil {
			continue
		}
		if _, err := ParseUnlockRequest(o); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestSealOpen(t *testing.T) {
	k := testKEM(t)
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	env, err := SealRequest(k.Public(), TypeUnlock, "01JB2Z6V9K3M4N5P6Q7R8S9T21", now, []byte(`{}`))
	if err != nil || len(env) != RequestEnvelopeSize {
		t.Fatalf("%v %d", err, len(env))
	}
	res := &UnlockResult{OK: false, Code: "bad_pin", HeaderSeq: 9, RetryAfter: 30}
	env, err = SealResult(k.Public(), TypeUnlockResult, "01JB2Z6V9K3M4N5P6Q7R8S9T21", res.Marshal(), now)
	if err != nil || len(env) != ResultEnvelopeSize {
		t.Fatal(err)
	}
	body, err := OpenResult(env, k, TypeUnlockResult, "01JB2Z6V9K3M4N5P6Q7R8S9T21")
	if err != nil {
		t.Fatal(err)
	}
	r, err := ParseUnlockResult(body)
	if err != nil || r.Code != "bad_pin" || r.RetryAfter != 30 {
		t.Fatalf("%v %+v", err, r)
	}
	if _, err := OpenResult(env, k, TypeUnlockResult, "01JB2Z6V9K3M4N5P6Q7R8S9T22"); err == nil {
		t.Fatal("result for another request accepted")
	}
	if _, err := OpenResult(env, k, TypeEnrollResult, "01JB2Z6V9K3M4N5P6Q7R8S9T21"); err == nil {
		t.Fatal("wrong type accepted")
	}
	ok := &UnlockResult{OK: true, StateSeq: 5, HeaderSeq: 6, Token: "t", Release: strings.Repeat("ab", 48), ReleaseNumber: 3,
		ReleaseStatus: "active", ManifestSerial: 7, Update: &UpdateResult{To: strings.Repeat("cd", 48), Result: "refused", Code: "downgrade"}}
	r, err = ParseUnlockResult(ok.Marshal())
	if err != nil || r.Update.Code != "downgrade" || r.ManifestSerial != 7 || r.CredentialBackup != nil {
		t.Fatalf("%v %+v", err, r)
	}
	// §11.11.5 step 1 (0.10.6): the recovered app's result carries
	// credential_backup after vault_bundle.
	for _, on := range []bool{true, false} {
		rec := &UnlockResult{OK: true, StateSeq: 5, HeaderSeq: 6, Token: "t", Release: strings.Repeat("ab", 48), ReleaseNumber: 3,
			ReleaseStatus: "active", VaultBundle: []byte(`{"v":1}`), CredentialBackup: &on}
		b := rec.Marshal()
		if want := fmt.Sprintf(`"vault_bundle":"eyJ2IjoxfQ==","credential_backup":%t}`, on); !strings.HasSuffix(string(b), want) {
			t.Fatalf("member order: %s", b)
		}
		r, err = ParseUnlockResult(b)
		if err != nil || r.CredentialBackup == nil || *r.CredentialBackup != on {
			t.Fatalf("%v %+v", err, r)
		}
		if _, err := ParseUnlockResult([]byte(strings.Replace(string(b), fmt.Sprint(on), `"yes"`, 1))); err == nil {
			t.Fatal("non-boolean credential_backup accepted")
		}
	}
}

func TestDescriptor(t *testing.T) {
	k := testKEM(t)
	na := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	d := MarshalDescriptor("i-1", k.Public(), strings.Repeat("ab", 48), na)
	p, err := ParseDescriptor(d)
	if err != nil || !p.NotAfter.Equal(na) || !p.Kid.Equal(k.Public().Kid()) {
		t.Fatal(err)
	}
	for _, bad := range []string{
		strings.Replace(string(d), `"suite":2`, `"suite":1`, 1),
		strings.Replace(string(d), strings.Repeat("ab", 48), strings.Repeat("00", 48), 1),
		strings.Replace(string(d), p.Kid.String(), "0000000000000000", 1),
		strings.Replace(string(d), "2026-10-03T12:00:00Z", "2026-10-03T12:00:00.5Z", 1),
		strings.Replace(string(d), `"i-1"`, `"i.1"`, 1),
		strings.Replace(string(d), `"i-1"`, `"i 1"`, 1),
		strings.Replace(string(d), `"i-1"`, `"`+strings.Repeat("a", 49)+`"`, 1),
		strings.Replace(string(d), `"i-1"`, `""`, 1),
	} {
		if _, err := ParseDescriptor([]byte(bad)); err == nil {
			t.Errorf("accepted %.60s", bad)
		}
	}
}

func FuzzParseEnrollRequest(f *testing.F) {
	b, _ := sampleEnroll(f).Marshal()
	f.Add(b)
	f.Fuzz(func(t *testing.T, b []byte) {
		o, err := strictjson.ParseObject(b)
		if err != nil {
			return
		}
		if r, err := ParseEnrollRequest(o); err == nil {
			if _, err := r.Marshal(); err != nil {
				t.Fatal("parsed request does not marshal")
			}
		}
	})
}

func FuzzParseUnlockRequest(f *testing.F) {
	b, _ := sampleUnlock().Marshal()
	f.Add(b)
	f.Fuzz(func(t *testing.T, b []byte) {
		o, err := strictjson.ParseObject(b)
		if err != nil {
			return
		}
		if r, err := ParseUnlockRequest(o); err == nil {
			if _, err := r.Marshal(); err != nil {
				t.Fatal("parsed request does not marshal")
			}
		}
	})
}

func FuzzParseResults(f *testing.F) {
	f.Add((&UnlockResult{OK: false, Code: "bad_pin", HeaderSeq: 9}).Marshal())
	f.Add((&UnlockResult{OK: true, Release: strings.Repeat("ab", 48), ReleaseNumber: 1, ReleaseStatus: "active",
		Update: &UpdateResult{To: "x", Result: "moved"}}).Marshal())
	backup := false
	f.Add((&UnlockResult{OK: true, Release: strings.Repeat("ab", 48), ReleaseNumber: 1, ReleaseStatus: "active",
		VaultBundle: []byte("{}"), CredentialBackup: &backup}).Marshal())
	f.Add((&EnrollResult{OK: true, VaultID: "v"}).Marshal())
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = ParseUnlockResult(b)
		_, _ = ParseEnrollResult(b)
	})
}

func TestValidInstanceID(t *testing.T) {
	for s, ok := range map[string]bool{"i-0abc_DEF": true, strings.Repeat("Z", 48): true, "": false,
		strings.Repeat("Z", 49): false, "i.1": false, "i/1": false, "é": false} {
		if ValidInstanceID(s) != ok {
			t.Errorf("%q", s)
		}
	}
}

func FuzzParseDescriptor(f *testing.F) {
	k, _ := suite.NewPrivateKey(bytes.Repeat([]byte{5}, 32))
	f.Add(MarshalDescriptor("i-1", k.Public(), strings.Repeat("ab", 48), time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)))
	f.Add(MarshalDescriptor("i-0123456789abcdef_ENC", k.Public(), strings.Repeat("ab", 48), time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = ParseDescriptor(b)
	})
}

func FuzzOpenResult(f *testing.F) {
	k, _ := suite.NewPrivateKey(bytes.Repeat([]byte{5}, 32))
	env, _ := SealResult(k.Public(), TypeUnlockResult, "01JB2Z6V9K3M4N5P6Q7R8S9T21", []byte(`{"ok":false}`), time.Now())
	f.Add(env)
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = OpenResult(b, k, TypeUnlockResult, "01JB2Z6V9K3M4N5P6Q7R8S9T21")
	})
}
