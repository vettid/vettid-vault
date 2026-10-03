package credential

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/featuretest"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/suite"
)

const pw = "correct horse battery"

type env struct {
	t   *testing.T
	f   *Feature
	h   *featuretest.Host
	clk featuretest.Clock
}

func newEnv(t *testing.T) *env {
	return &env{t: t, f: New(Options{KDF: MinKDF}), h: featuretest.NewHost(),
		clk: featuretest.Clock{T: time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)}}
}

func (e *env) call(kind, typ, body string) featuretest.Result {
	e.clk.Advance(time.Second)
	return featuretest.Call(e.f, e.h, e.clk.T, kind, typ, body)
}

func (e *env) ok(kind, typ, body string) featuretest.Result {
	e.t.Helper()
	r := e.call(kind, typ, body)
	if !r.OK() {
		e.t.Fatalf("%s: %s", typ, r.Code)
	}
	return r
}

func (e *env) create() string {
	e.t.Helper()
	r := e.ok("app", "credential.create", `{"password":"`+pw+`"}`)
	c, _ := r.Obj(e.t).String("credential")
	return c
}

func blobOf(t *testing.T, r featuretest.Result) string {
	t.Helper()
	c, err := r.Obj(t).String("credential")
	if err != nil {
		t.Fatal("no credential in response")
	}
	return c
}

func use(cred, password, extra string) string {
	b := `{"credential":"` + cred + `","password":"` + password + `"`
	if extra != "" {
		b += "," + extra
	}
	return b + "}"
}

func TestAuthorizationBySenderKind(t *testing.T) {
	e := newEnv(t)
	for _, k := range []string{"desktop", "agent", "connection:c1"} {
		if r := e.call(k, "credential.create", `{"password":"`+pw+`"}`); r.Code != "forbidden" {
			t.Fatalf("%s created a credential: %q", k, r.Code)
		}
	}
	cred := e.create()
	for _, typ := range []string{"credential.secret.get", "credential.unlock", "credential.rotate", "credential.delete", "credential.get"} {
		for _, k := range []string{"desktop", "agent"} {
			if r := e.call(k, typ, use(cred, pw, `"secret_id":"`+testID+`"`)); r.Code != "forbidden" {
				t.Fatalf("%s may send %s: %q", k, typ, r.Code)
			}
		}
	}
	// Desktops may see the version and the secrets' metadata.
	e.ok("desktop", "credential.version", `{}`)
	e.ok("desktop", "credential.secret.list", `{}`)
	if r := e.call("agent", "credential.secret.list", `{}`); r.Code != "forbidden" {
		t.Fatal("agent listed critical secrets")
	}
}

func TestCreateOnce(t *testing.T) {
	e := newEnv(t)
	r := e.ok("app", "credential.create", `{"password":"`+pw+`"}`)
	o := r.Obj(t)
	if v, _ := o.Uint("version", 1, 1); v != 1 {
		t.Fatal("version")
	}
	if _, err := o.Base64("key", 32); err != nil {
		t.Fatal("key")
	}
	if r := e.call("app", "credential.create", `{"password":"`+pw+`"}`); r.Code != "exists" {
		t.Fatalf("second create: %q", r.Code)
	}
	if !e.h.HasActivity("credential.created") || len(e.h.SentOfType("sync.event")) != 1 {
		t.Fatal("create not recorded or not synced")
	}
	if s := e.h.SentOfType("sync.event")[0]; s.To != "devices-except:dev-app" || !strings.Contains(string(s.Body), `"credential.changed"`) {
		t.Fatalf("sync.event %s to %s", s.Body, s.To)
	}
}

func TestSecretsRoundTripAndNoPlaintextAtRest(t *testing.T) {
	e := newEnv(t)
	cred := e.create()
	val := base64.StdEncoding.EncodeToString([]byte("abandon ability able about above absent"))
	r := e.ok("app", "credential.secret.add", use(cred, pw, `"name":"wallet seed","category":"seed_phrase","value":"`+val+`"`))
	id, _ := r.Obj(t).String("secret_id")
	cred2 := blobOf(t, r)
	if v, _ := r.Obj(t).Uint("version", 1, 100); v != 2 {
		t.Fatalf("version %d", v)
	}
	// The old blob is refused (§3.5.3 step 2).
	if r := e.call("app", "credential.secret.get", use(cred, pw, `"secret_id":"`+id+`"`)); r.Code != "stale_credential" {
		t.Fatalf("old blob: %q", r.Code)
	}
	g := e.ok("app", "credential.secret.get", use(cred2, pw, `"secret_id":"`+id+`"`)).Obj(t)
	if v, _ := g.String("value"); v != val {
		t.Fatal("value")
	}
	if !e.h.HasActivity("credential.secret.read") {
		t.Fatal("read not audited")
	}
	l := e.ok("desktop", "credential.secret.list", `{}`)
	if !strings.Contains(string(l.Body), `"wallet seed"`) || strings.Contains(string(l.Body), val) {
		t.Fatalf("list: %s", l.Body)
	}
	saved, _ := e.f.Save()
	for _, secret := range [][]byte{[]byte("abandon ability"), []byte(val), []byte(pw)} {
		if bytes.Contains(saved, secret) {
			t.Fatal("plaintext in saved state")
		}
	}
	d := e.ok("app", "credential.secret.delete", use(cred2, pw, `"secret_id":"`+id+`"`))
	cred3 := blobOf(t, d)
	if r := e.call("app", "credential.secret.get", use(cred3, pw, `"secret_id":"`+id+`"`)); r.Code != "not_found" {
		t.Fatalf("deleted secret: %q", r.Code)
	}
	if strings.Contains(string(e.ok("app", "credential.secret.list", `{}`).Body), "wallet seed") {
		t.Fatal("metadata kept after delete")
	}
	// The kept copy is the latest blob.
	gc := e.ok("app", "credential.get", `{}`)
	if blobOf(t, gc) != cred3 {
		t.Fatal("credential.get is not the latest blob")
	}
	// Load/Save round trip keeps working.
	g2 := New(Options{KDF: MinKDF})
	featuretest.RoundTrip(t, e.f, g2)
	e.f = g2
	e.ok("app", "credential.unlock", use(cred3, pw, ""))
}

func TestBadPasswordAndBackoff(t *testing.T) {
	e := newEnv(t)
	cred := e.create()
	for i := 0; i < BackoffAfter; i++ {
		if r := e.call("app", "credential.unlock", use(cred, "wrong password", "")); r.Code != "bad_password" {
			t.Fatalf("attempt %d: %q", i, r.Code)
		}
	}
	if !e.h.HasActivity("credential.password_failed") {
		t.Fatal("failure not recorded")
	}
	// In backoff even the right password is refused, without trying it.
	if r := e.call("app", "credential.unlock", use(cred, pw, "")); r.Code != "backoff" {
		t.Fatalf("in backoff: %q", r.Code)
	}
	e.clk.Advance(31 * time.Second)
	e.ok("app", "credential.unlock", use(cred, pw, ""))
	// A success resets the count.
	if r := e.call("app", "credential.unlock", use(cred, "wrong password", "")); r.Code != "bad_password" {
		t.Fatalf("after reset: %q", r.Code)
	}
	if r := e.call("app", "credential.unlock", use(cred, pw, "")); !r.OK() {
		t.Fatalf("count not reset: %q", r.Code)
	}
}

func TestPasswordChange(t *testing.T) {
	e := newEnv(t)
	cred := e.create()
	r := e.ok("app", "credential.password.change", use(cred, pw, `"new_password":"another passphrase"`))
	cred2 := blobOf(t, r)
	if r := e.call("app", "credential.unlock", use(cred2, pw, "")); r.Code != "bad_password" {
		t.Fatalf("old password: %q", r.Code)
	}
	e.ok("app", "credential.unlock", use(cred2, "another passphrase", ""))
	if !e.h.HasActivity("credential.password_changed") {
		t.Fatal("not audited")
	}
}

func TestRotateRotatesIdentityAndCEK(t *testing.T) {
	e := newEnv(t)
	cred := e.create()
	k1, _ := e.ok("app", "credential.version", `{}`).Obj(t).String("key")
	e.h.RotateErr = vault.NewError("internal", "")
	if r := e.call("app", "credential.rotate", use(cred, pw, "")); r.OK() {
		t.Fatal("rotate succeeded although the identity rotation failed")
	}
	e.ok("app", "credential.unlock", use(cred, pw, "")) // unchanged
	e.h.RotateErr = nil
	r := e.ok("app", "credential.rotate", use(cred, pw, ""))
	if e.h.Rotations != 1 {
		t.Fatal("ik/kem not rotated with the credential (§3.4)")
	}
	k2, _ := r.Obj(t).String("key")
	if k1 == k2 {
		t.Fatal("credential key not rotated")
	}
	if _, ok := e.f.UseKey(e.clk.T, time.Minute); ok {
		t.Fatal("unlock window survived rotation")
	}
	// The old blob is sealed to the destroyed CEK: refused.
	if r := e.call("app", "credential.unlock", use(cred, pw, "")); r.Code != "stale_credential" {
		t.Fatalf("old blob after rotation: %q", r.Code)
	}
	e.ok("app", "credential.unlock", use(blobOf(t, r), pw, ""))
}

func TestUnlockWindow(t *testing.T) {
	e := newEnv(t)
	cred := e.create()
	e.h.Set.CredentialUnlockTTL = 60
	e.ok("app", "credential.unlock", use(cred, pw, ""))
	if _, ok := e.f.UseKey(e.clk.T.Add(30*time.Second), time.Minute); !ok {
		t.Fatal("window closed early")
	}
	if _, ok := e.f.UseKey(e.clk.T.Add(200*time.Second), time.Minute); ok {
		t.Fatal("window open after expiry")
	}
	e.ok("app", "credential.unlock", use(cred, pw, ""))
	e.ok("app", "credential.lock", `{}`)
	if _, ok := e.f.UseKey(e.clk.T, time.Minute); ok {
		t.Fatal("window open after credential.lock")
	}
	e.ok("app", "credential.unlock", use(cred, pw, ""))
	e.f.Zeroize()
	if _, ok := e.f.UseKey(e.clk.T, time.Minute); ok {
		t.Fatal("window open after vault lock")
	}
}

func TestDelete(t *testing.T) {
	e := newEnv(t)
	cred := e.create()
	if r := e.call("app", "credential.delete", use(cred, "wrong password", "")); r.Code != "bad_password" {
		t.Fatal("delete without the password")
	}
	e.ok("app", "credential.delete", use(cred, pw, ""))
	if ex, _ := e.ok("app", "credential.version", `{}`).Obj(t).Bool("exists"); ex {
		t.Fatal("exists after delete")
	}
	if r := e.call("app", "credential.unlock", use(cred, pw, "")); r.Code != "not_found" {
		t.Fatalf("after delete: %q", r.Code)
	}
	if r := e.call("app", "credential.get", `{}`); r.Code != "not_found" {
		t.Fatal("copy kept after delete")
	}
	e.create() // a new credential may be created
}

func TestNoCopy(t *testing.T) {
	e := newEnv(t)
	e.h.Set.NoBackup = true
	e.create()
	if r := e.call("app", "credential.get", `{}`); r.Code != "not_found" {
		t.Fatal("copy kept although credential.backup is off")
	}
}

func TestBadBodies(t *testing.T) {
	e := newEnv(t)
	cred := e.create()
	val := base64.StdEncoding.EncodeToString([]byte("x"))
	for _, c := range []struct{ typ, body string }{
		{"credential.create", `{"password":"short"}`},
		{"credential.create", `{"password":"` + strings.Repeat("p", MaxPassword+1) + `"}`},
		{"credential.create", `{"password":12345678}`},
		{"credential.create", `{"password":"` + pw + `","password":"` + pw + `"}`},
		{"credential.unlock", `{"password":"` + pw + `"}`},
		{"credential.unlock", `{"credential":"!!!","password":"` + pw + `"}`},
		{"credential.unlock", `{"credential":"AAAA","password":"` + pw + `"}`},
		{"credential.secret.add", use(cred, pw, `"name":"n","category":"bitcoin","value":"`+val+`"`)},
		{"credential.secret.add", use(cred, pw, `"name":"","category":"other","value":"`+val+`"`)},
		{"credential.secret.add", use(cred, pw, `"name":"n","category":"other","value":""`)},
		{"credential.secret.add", use(cred, pw, `"name":"n","category":"other","value":"`+base64.StdEncoding.EncodeToString(make([]byte, MaxValue+1))+`"`)},
		{"credential.secret.get", use(cred, pw, `"secret_id":"nope"`)},
		{"credential.password.change", use(cred, pw, `"new_password":"short"`)},
	} {
		if r := e.call("app", c.typ, c.body); r.Code != "bad_request" {
			t.Errorf("%s %.80s: %q", c.typ, c.body, r.Code)
		}
	}
}

func TestSecretLimit(t *testing.T) {
	e := newEnv(t)
	cred := e.create()
	val := base64.StdEncoding.EncodeToString([]byte("v"))
	for i := 0; i < MaxSecrets; i++ {
		cred = blobOf(t, e.ok("app", "credential.secret.add", use(cred, pw, `"name":"n","category":"other","value":"`+val+`"`)))
	}
	if r := e.call("app", "credential.secret.add", use(cred, pw, `"name":"n","category":"other","value":"`+val+`"`)); r.Code != "limit" {
		t.Fatalf("over the limit: %q", r.Code)
	}
}

func TestBlobLayers(t *testing.T) {
	cek, err := suite.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	defer cek.Destroy()
	inner := []byte(`{"x":1}`)
	blob, err := Seal(cek.Public(), "v1", 7, []byte(pw), MinKDF, inner)
	if err != nil {
		t.Fatal(err)
	}
	if v, pt, err := Open(cek, "v1", blob, []byte(pw)); err != nil || v != 7 || !bytes.Equal(pt, inner) {
		t.Fatalf("open: %v", err)
	}
	if _, _, err := Open(cek, "v1", blob, []byte("wrong password")); err != ErrPassword {
		t.Fatalf("wrong password: %v", err)
	}
	if _, _, err := Open(cek, "v2", blob, []byte(pw)); err != ErrFormat {
		t.Fatalf("other vault: %v", err)
	}
	other, _ := suite.GeneratePrivateKey()
	defer other.Destroy()
	if _, _, err := Open(other, "v1", blob, []byte(pw)); err != ErrFormat {
		t.Fatalf("other CEK: %v", err)
	}
	for _, i := range []int{1, 10, HeaderSize + 5, len(blob) - 1} {
		bad := append([]byte(nil), blob...)
		bad[i] ^= 1
		if _, _, err := Open(cek, "v1", bad, []byte(pw)); err == nil {
			t.Fatalf("tampered byte %d accepted", i)
		}
	}
	if _, err := Seal(cek.Public(), "v1", 1, []byte(pw), KDF{Time: 1, MemoryKiB: 1024, Threads: 1}, inner); err != ErrKDF {
		t.Fatal("weak KDF accepted")
	}
}

func FuzzParseRequest(f *testing.F) {
	f.Add("credential.create", []byte(`{"password":"`+pw+`"}`))
	f.Add("credential.secret.add", []byte(`{"credential":"AAAA","password":"`+pw+`","name":"n","category":"other","value":"eA=="}`))
	f.Add("credential.secret.get", []byte(`{"credential":"AAAA","password":"`+pw+`","secret_id":"`+testID+`"}`))
	f.Fuzz(func(t *testing.T, typ string, b []byte) {
		r, err := ParseRequest(typ, b)
		if err != nil {
			return
		}
		if n := needs[typ]; n&needPassword != 0 && (len(r.Password) < MinPassword || len(r.Password) > MaxPassword) {
			t.Fatal("bad password accepted")
		}
		if len(r.Value) > MaxValue || len(r.Name) > MaxName {
			t.Fatal("oversized secret accepted")
		}
	})
}

func FuzzParseInner(f *testing.F) {
	in := &Inner{VaultID: "v", Version: 1, CreatedAt: time.Unix(0, 0), PasswordChangedAt: time.Unix(0, 0), Key: make([]byte, 32),
		Secrets: []Secret{{ID: "01JB2Z6V9K3M4N5P6Q7R8S9T0V", Name: "n", Category: "other", Value: []byte("v"), CreatedAt: time.Unix(0, 0)}}}
	f.Add(in.Marshal())
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := ParseInner(b)
		if err != nil {
			return
		}
		if len(p.Key) != 32 || len(p.Secrets) > MaxSecrets {
			t.Fatal("invalid plaintext accepted")
		}
		if _, err := ParseInner(p.Marshal()); err != nil {
			t.Fatal("re-encoding does not parse")
		}
	})
}

func FuzzOpen(f *testing.F) {
	cek, err := suite.NewPrivateKey(bytes.Repeat([]byte{9}, 32))
	if err != nil {
		f.Fatal(err)
	}
	blob, err := Seal(cek.Public(), "v", 1, []byte(pw), MinKDF, []byte(`{}`))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(blob)
	f.Fuzz(func(t *testing.T, b []byte) {
		// Only the header and the outer layer are reached for most inputs;
		// a forged outer layer is impossible without the CEK.
		_, _, _ = Open(cek, "v", b, []byte(pw))
	})
}

// testID is a fixed ULID for tests.
const testID = "01JB2Z6V9K3M4N5P6Q7R8S9T0V"

// §11.11.5: credential.recover from a recovering app only; the password
// against the kept copy (with the backoff); a fresh version is handed
// over, so copies on the lost devices go stale.
func TestRecover(t *testing.T) {
	e := newEnv(t)
	cred := e.create()
	if r := e.call("app", "credential.recover", `{"password":"`+pw+`"}`); r.Code != "forbidden" {
		t.Fatalf("ordinary app recovered: %q", r.Code)
	}
	if r := e.call("recovering-app", "credential.unlock", use(cred, pw, "")); r.Code != "forbidden" {
		t.Fatalf("recovering app used the credential: %q", r.Code)
	}
	if r := e.call("recovering-app", "credential.recover", `{"password":"wrong password"}`); r.Code != "bad_password" {
		t.Fatalf("wrong password: %q", r.Code)
	}
	if len(e.h.Completed) != 0 {
		t.Fatal("completed without the password")
	}
	r := e.ok("recovering-app", "credential.recover", `{"password":"`+pw+`"}`)
	got := blobOf(t, r)
	if got == cred || len(e.h.Completed) != 1 || !e.h.HasActivity("credential.recovered") {
		t.Fatal("recover did not re-seal or complete")
	}
	if r := e.call("app", "credential.unlock", use(cred, pw, "")); r.Code != "stale_credential" {
		t.Fatalf("lost device's copy still usable: %q", r.Code)
	}
	e.ok("app", "credential.unlock", use(got, pw, ""))
}

func TestRecoverBackoff(t *testing.T) {
	e := newEnv(t)
	e.create()
	for i := 0; i < BackoffAfter; i++ {
		e.call("recovering-app", "credential.recover", `{"password":"wrong password"}`)
	}
	if r := e.call("recovering-app", "credential.recover", `{"password":"`+pw+`"}`); r.Code != "backoff" {
		t.Fatalf("no backoff: %q", r.Code)
	}
}

// §3.5.6: with credential.backup off there is no copy; turning it off
// drops the copy at once; recovery then completes without a credential.
func TestBackupSetting(t *testing.T) {
	e := newEnv(t)
	e.create()
	e.ok("app", "credential.get", `{}`)
	e.h.Set.NoBackup = true
	e.f.SettingsChanged(nil, e.h.Set)
	if r := e.call("app", "credential.get", `{}`); r.Code != "not_found" {
		t.Fatal("copy kept after backup was turned off")
	}
	r := e.ok("recovering-app", "credential.recover", `{"password":"`+pw+`"}`)
	if string(r.Body) != `{}` || len(e.h.Completed) != 1 {
		t.Fatalf("recover without backup: %s", r.Body)
	}
}
