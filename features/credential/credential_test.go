package credential

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/featuretest"
	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/credwire"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/suite"
)

const pw = "correct horse battery"

// testID is a fixed ULID for tests.
const testID = "01JB2Z6V9K3M4N5P6Q7R8S9T0V"

type utk struct {
	id string
	ek *suite.PublicKey
}

type env struct {
	t     *testing.T
	f     *Feature
	h     *featuretest.Host
	clk   featuretest.Clock
	pools map[string][]utk
	reply *suite.PrivateKey // the last request's reply key
	lastI string            // the last request's inner id
	op    *opFeature
	extra string // extra top-level body members (callBody)
}

func newEnv(t *testing.T) *env {
	e := &env{t: t, f: New(Options{KDF: MinKDF}), h: featuretest.NewHost(),
		clk: featuretest.Clock{T: time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)}, pools: map[string][]utk{}}
	e.h.AddDevice("dev-app", vault.KindApp)
	return e
}

func (e *env) raw(kind, typ, body string) featuretest.Result {
	e.clk.Advance(time.Second)
	id, _ := envelope.NewULID(e.clk.T)
	e.lastI = id
	r := featuretest.CallID(e.f, e.h, e.clk.T, kind, typ, id, body)
	e.absorb(kind, r)
	return r
}

// absorb keeps the UTKs a response carries.
func (e *env) absorb(kind string, r featuretest.Result) {
	if !r.OK() || r.Body == nil {
		return
	}
	var out struct {
		UTKs []struct {
			ID string `json:"utk_id"`
			EK []byte `json:"ek"`
		} `json:"utks"`
	}
	if json.Unmarshal(r.Body, &out) != nil {
		return
	}
	for _, u := range out.UTKs {
		ek, err := suite.ParsePublicKey(u.EK)
		if err != nil {
			e.t.Fatal(err)
		}
		e.pools[kind] = append(e.pools[kind], utk{u.ID, ek})
	}
}

// take returns an unused UTK of kind, fetching a pool if needed.
func (e *env) take(kind string) utk {
	if len(e.pools[kind]) == 0 {
		if r := e.raw(kind, "credential.utk.get", `{}`); !r.OK() {
			e.t.Fatalf("utk.get: %s", r.Code)
		}
	}
	u := e.pools[kind][0]
	e.pools[kind] = e.pools[kind][1:]
	return u
}

// call sends typ with blob and the payload sealed to a fresh UTK.
func (e *env) call(kind, typ, blob string, payload map[string]any) featuretest.Result {
	e.t.Helper()
	return e.callWith(kind, typ, blob, payload, e.take(kind))
}

func (e *env) callWith(kind, typ, blob string, payload map[string]any, u utk) featuretest.Result {
	e.t.Helper()
	if payload == nil {
		payload = map[string]any{}
	}
	if typ == "test.op" && e.op != nil && e.op.reply {
		k, _ := suite.GeneratePrivateKey()
		e.reply = k
		payload["reply_key"] = base64.StdEncoding.EncodeToString(k.Public().Bytes())
	}
	pt, _ := json.Marshal(payload)
	e.clk.Advance(time.Second)
	id, _ := envelope.NewULID(e.clk.T)
	e.lastI = id
	sealed, err := credwire.SealPayload(u.ek, e.h.VaultID(), u.id, typ, id, pt)
	if err != nil {
		e.t.Fatal(err)
	}
	body := map[string]any{"utk_id": u.id, "sealed": base64.StdEncoding.EncodeToString(sealed)}
	if blob != "" {
		body["credential"] = blob
	}
	b, _ := json.Marshal(body)
	if e.extra != "" {
		b = append(append(b[:len(b)-1], ','), e.extra+"}"...)
	}
	var f vault.Feature = e.f
	if typ == "test.op" {
		f = e.op
	}
	r := featuretest.CallID(f, e.h, e.clk.T, kind, typ, id, string(b))
	e.absorb(kind, r)
	return r
}

// opFeature drives Operate, the credential operation of another feature
// (critical items, §10.7; critical-item use, §10.13), as type test.op.
type opFeature struct {
	cred  *Feature
	need  int
	reply bool
	check func(*Payload) error
	op    func(*Inner, *Payload) error
}

func (o *opFeature) Name() string { return "op" }
func (o *opFeature) Types() []vault.TypeSpec {
	return []vault.TypeSpec{{Type: "test.op", Request: true, From: []string{vault.KindApp, vault.KindDesktop}}}
}
func (o *opFeature) Load(json.RawMessage) error     { return nil }
func (o *opFeature) Save() (json.RawMessage, error) { return json.RawMessage(`{}`), nil }
func (o *opFeature) Handle(_ context.Context, s *vault.Session, in *envelope.Inner) (json.RawMessage, error) {
	r, err := o.cred.Operate(s, in, o.need, o.check, o.op)
	if err != nil {
		return nil, err
	}
	b := strictjson.NewBuilder()
	r.Members(b)
	return b.Bytes(), nil
}

func (e *env) ok(r featuretest.Result) featuretest.Result {
	e.t.Helper()
	if !r.OK() {
		e.t.Fatalf("error %s", r.Code)
	}
	return r
}

func (e *env) create() string {
	e.t.Helper()
	return blobOf(e.t, e.ok(e.call("app", "credential.create", "", map[string]any{"password": pw})))
}

func blobOf(t *testing.T, r featuretest.Result) string {
	t.Helper()
	c, err := r.Obj(t).String("credential")
	if err != nil {
		t.Fatal("no credential in response")
	}
	return c
}

func (e *env) unlock(blob, password string) featuretest.Result {
	return e.call("app", "credential.unlock", blob, map[string]any{"password": password})
}

func TestAuthorizationBySenderKind(t *testing.T) {
	e := newEnv(t)
	for _, k := range []string{"desktop", "agent", "connection:c1"} {
		if r := e.raw(k, "credential.utk.get", `{}`); r.Code != "forbidden" {
			t.Fatalf("%s got UTKs: %q", k, r.Code)
		}
	}
	e.create()
	for _, typ := range []string{"credential.unlock", "credential.rotate", "credential.reset", "credential.get", "credential.ack"} {
		for _, k := range []string{"desktop", "agent"} {
			if r := e.raw(k, typ, `{}`); r.Code != "forbidden" {
				t.Fatalf("%s may send %s: %q", k, typ, r.Code)
			}
		}
	}
	e.ok(e.raw("desktop", "credential.version", `{}`))
	for _, typ := range []string{"credential.secret.add", "credential.secret.get", "credential.secret.list", "credential.secret.delete", "credential.secret.catalog"} {
		if r := e.raw("app", typ, `{}`); r.Code != "unsupported_type" {
			t.Fatalf("%s (removed in 0.7.0): %q", typ, r.Code)
		}
	}
	// Another feature's operation is app-only.
	e.op = &opFeature{cred: e.f, op: func(*Inner, *Payload) error { return nil }}
	if r := e.callWith("desktop", "test.op", "", map[string]any{"password": pw}, e.take("app")); r.Code != "forbidden" {
		t.Fatalf("desktop operation: %q", r.Code)
	}
	if !e.f.CredentialReady() {
		t.Fatal("gate")
	}
}

// §3.5.4: a pool of 20, replenished by 10 when below 10; a UTK works once,
// only for the device it was issued to, bound to type and request, and
// expires.
func TestUTKPool(t *testing.T) {
	e := newEnv(t)
	e.ok(e.raw("app", "credential.utk.get", `{}`))
	if len(e.pools["app"]) != PoolSize || e.f.PoolSizeOf("dev-app") != PoolSize {
		t.Fatalf("pool %d", len(e.pools["app"]))
	}
	if r := e.raw("app", "credential.utk.get", `{}`); !strings.Contains(string(r.Body), `"utks":[]`) {
		t.Fatal("topped up beyond 20")
	}
	u := e.take("app")
	blob := blobOf(t, e.ok(e.callWith("app", "credential.create", "", map[string]any{"password": pw}, u)))
	// Reuse refused: the UTK was spent.
	if r := e.callWith("app", "credential.unlock", blob, map[string]any{"password": pw}, u); r.Code != "utk_invalid" {
		t.Fatalf("reused UTK: %q", r.Code)
	}
	// Another device cannot use this app's UTK.
	other := e.take("app")
	pt, _ := json.Marshal(map[string]any{"password": pw})
	id, _ := envelope.NewULID(e.clk.T.Add(time.Hour))
	sealed, _ := credwire.SealPayload(other.ek, e.h.VaultID(), other.id, "credential.recover", id, pt)
	body, _ := json.Marshal(map[string]any{"utk_id": other.id, "sealed": base64.StdEncoding.EncodeToString(sealed)})
	if r := featuretest.CallID(e.f, e.h, e.clk.T, "recovering-app", "credential.recover", id, string(body)); r.Code != "utk_invalid" {
		t.Fatalf("foreign UTK: %q", r.Code)
	}
	// Spend down: refills arrive with responses.
	for i := 0; i < 15; i++ {
		blob = blobOf(t, e.ok(e.unlock(blob, pw)))
	}
	if n := e.f.PoolSizeOf("dev-app"); n < PoolLow-1 || n > PoolSize {
		t.Fatalf("pool after refills: %d", n)
	}
	// A payload moved to another request does not open (bound to its id).
	u = e.take("app")
	sealed, _ = credwire.SealPayload(u.ek, e.h.VaultID(), u.id, "credential.unlock", testID, pt)
	body, _ = json.Marshal(map[string]any{"credential": blob, "utk_id": u.id, "sealed": base64.StdEncoding.EncodeToString(sealed)})
	if r := e.raw("app", "credential.unlock", string(body)); r.Code != "utk_invalid" {
		t.Fatalf("payload under another inner id: %q", r.Code)
	}
	// Expiry.
	u = e.take("app")
	e.clk.Advance(UTKLifetime + time.Hour)
	if r := e.callWith("app", "credential.unlock", blob, map[string]any{"password": pw}, u); r.Code != "utk_invalid" {
		t.Fatalf("expired UTK: %q", r.Code)
	}
}

// §3.5.3: every use rotates the CEK; the previous blob is undecryptable,
// not merely refused.
func TestCEKRotatesOnEveryUse(t *testing.T) {
	e := newEnv(t)
	b1 := e.create()
	seed1 := append([]byte(nil), e.f.st.CEKSeed...)
	b2 := blobOf(t, e.ok(e.unlock(b1, pw)))
	if b1 == b2 || bytes.Equal(seed1, e.f.st.CEKSeed) {
		t.Fatal("CEK not rotated by an unlock")
	}
	if v, _ := e.ok(e.raw("app", "credential.version", `{}`)).Obj(t).Uint("version", 1, 100); v != 2 {
		t.Fatalf("version %d", v)
	}
	// The old blob cannot be opened even with the vault's current CEK.
	cur, _ := suite.NewPrivateKey(e.f.st.CEKSeed)
	raw1, _ := base64.StdEncoding.DecodeString(b1)
	if _, _, err := Open(cur, e.h.VaultID(), raw1, []byte(pw)); err == nil || err == ErrPassword {
		t.Fatalf("old blob opened: %v", err)
	}
	if r := e.unlock(b1, pw); r.Code != "stale_credential" {
		t.Fatalf("old blob: %q", r.Code)
	}
	// A wrong password does not rotate.
	if r := e.unlock(b2, "wrong password"); r.Code != "bad_password" {
		t.Fatal("wrong password")
	}
	e.ok(e.unlock(b2, pw))
}

// §3.5.3, §3.5.4, §10.7: another feature's operation (a critical item)
// spends a UTK, opens the credential with the password, changes the
// plaintext and rotates the CEK; values return sealed to a reply key and
// never reach saved state.
func TestOperateAndReplyKey(t *testing.T) {
	e := newEnv(t)
	blob := e.create()
	val := []byte("abandon ability able about above absent")[:ItemKeySize]
	add := &opFeature{cred: e.f, need: NeedItem, op: func(in *Inner, p *Payload) error {
		in.Items = append(in.Items, Item{ID: testID, Gen: 1, Key: append([]byte(nil), val...)})
		return nil
	}}
	e.op = add
	r := e.ok(e.call("app", "test.op", blob, map[string]any{"password": pw, "item": map[string]any{"name": "seed"}}))
	if v, _ := r.Obj(t).Uint("credential_version", 1, 9); v != 2 {
		t.Fatal("not rotated")
	}
	old := blob
	blob = blobOf(t, r)
	// Read it back, sealed to a reply key.
	var got []byte
	e.op = &opFeature{cred: e.f, need: NeedItemID | NeedReply, reply: true,
		check: func(p *Payload) error {
			if p.ItemID != testID {
				return errBad
			}
			return nil
		},
		op: func(in *Inner, p *Payload) error {
			i := in.FindItem(p.ItemID)
			if i < 0 {
				return errNotFound
			}
			var err error
			got, err = credwire.SealValue(p.Reply, e.h.VaultID(), e.lastI, in.Items[i].Key)
			return err
		}}
	r = e.ok(e.call("app", "test.op", blob, map[string]any{"password": pw, "item_id": testID}))
	blob = blobOf(t, r)
	pt, err := credwire.OpenValue(e.reply, e.h.VaultID(), e.lastI, got)
	if err != nil || !bytes.Equal(pt, val) {
		t.Fatalf("reply-sealed values: %s %v", pt, err)
	}
	if bytes.Contains(r.Body, []byte("abandon")) {
		t.Fatal("value in the clear in the response")
	}
	// A failed binding check spends the UTK and changes nothing.
	before, _ := e.f.Save()
	if r := e.call("app", "test.op", blob, map[string]any{"password": pw, "item_id": "01JB2Z6V9K3M4N5P6Q7R8S9T0W"}); r.Code != "bad_request" {
		t.Fatalf("binding: %q", r.Code)
	}
	after, _ := e.f.Save()
	var b1, b2 struct {
		Version uint64 `json:"version"`
		Hash    []byte `json:"hash"`
	}
	_ = json.Unmarshal(before, &b1)
	_ = json.Unmarshal(after, &b2)
	if b1.Version != b2.Version || !bytes.Equal(b1.Hash, b2.Hash) {
		t.Fatal("a refused operation changed the credential")
	}
	saved, _ := e.f.Save()
	for _, secret := range [][]byte{[]byte("abandon"), []byte(pw)} {
		if bytes.Contains(saved, secret) {
			t.Fatal("plaintext in saved state")
		}
	}
	g2 := New(Options{KDF: MinKDF})
	featuretest.RoundTrip(t, e.f, g2)
	e.f = g2
	e.ok(e.unlock(blob, pw))
	// The old blob is dead: every use rotated the CEK. Presented two
	// versions late it is a clone (§3.5.9).
	if r := e.call("app", "test.op", old, map[string]any{"password": pw, "item_id": testID}); r.Code != "credential_frozen" {
		t.Fatalf("old blob: %q", r.Code)
	}
}

// §3.5.3: a lost response never loses the credential: the latest blob is
// kept until the app confirms it, even with backup off.
func TestLatestBlobKeptUntilAck(t *testing.T) {
	e := newEnv(t)
	e.h.Set.NoBackup = true
	b1 := e.create()
	b2 := blobOf(t, e.ok(e.unlock(b1, pw))) // "lost": the app still holds b1
	if r := e.unlock(b1, pw); r.Code != "stale_credential" {
		t.Fatal("stale")
	}
	if got := blobOf(t, e.ok(e.raw("app", "credential.get", `{}`))); got != b2 {
		t.Fatal("credential.get is not the latest blob")
	}
	if r := e.raw("app", "credential.ack", `{"version":1}`); r.Code != "stale_credential" {
		t.Fatal("ack of an old version")
	}
	e.ok(e.raw("app", "credential.ack", `{"version":2}`))
	if r := e.raw("app", "credential.get", `{}`); r.Code != "not_found" {
		t.Fatal("blob kept after the ack with backup off")
	}
	e.ok(e.unlock(b2, pw))
	// With backup on, the latest blob stays after the ack.
	e.h.Set.NoBackup = false
	b4 := blobOf(t, e.ok(e.raw("app", "credential.get", `{}`)))
	v, _ := e.ok(e.raw("app", "credential.version", `{}`)).Obj(t).Uint("version", 1, 100)
	e.ok(e.raw("app", "credential.ack", `{"version":`+itoa(v)+`}`))
	if blobOf(t, e.ok(e.raw("app", "credential.get", `{}`))) != b4 {
		t.Fatal("backup copy dropped")
	}
	// Turning backup off drops an acknowledged copy at once.
	e.h.Set.NoBackup = true
	e.f.SettingsChanged(nil, e.h.Set)
	if r := e.raw("app", "credential.get", `{}`); r.Code != "not_found" {
		t.Fatal("copy kept after backup was turned off")
	}
}

func itoa(v uint64) string { b, _ := json.Marshal(v); return string(b) }

func TestCreateOnce(t *testing.T) {
	e := newEnv(t)
	r := e.ok(e.call("app", "credential.create", "", map[string]any{"password": pw}))
	if _, err := r.Obj(t).Base64("key", 32); err != nil {
		t.Fatal("key")
	}
	if r := e.call("app", "credential.create", "", map[string]any{"password": pw}); r.Code != "exists" {
		t.Fatalf("second create: %q", r.Code)
	}
	if !e.h.HasActivity("credential.created") {
		t.Fatal("not recorded")
	}
	var syncs int
	for _, s := range e.h.SentOfType("sync.event") {
		if strings.Contains(string(s.Body), `"credential.changed"`) && s.To == "devices-except:dev-app" {
			syncs++
		}
	}
	if syncs != 1 {
		t.Fatalf("sync events %d", syncs)
	}
}

func TestBadPasswordAndBackoff(t *testing.T) {
	e := newEnv(t)
	blob := e.create()
	for i := 0; i < BackoffAfter; i++ {
		if r := e.unlock(blob, "wrong password"); r.Code != "bad_password" {
			t.Fatalf("attempt %d: %q", i, r.Code)
		}
	}
	if r := e.unlock(blob, pw); r.Code != "backoff" {
		t.Fatalf("in backoff: %q", r.Code)
	}
	e.clk.Advance(31 * time.Second)
	blob = blobOf(t, e.ok(e.unlock(blob, pw)))
	if r := e.unlock(blob, "wrong password"); r.Code != "bad_password" {
		t.Fatal("after reset")
	}
	e.ok(e.unlock(blob, pw))
}

func TestPasswordChange(t *testing.T) {
	e := newEnv(t)
	blob := e.create()
	blob = blobOf(t, e.ok(e.call("app", "credential.password.change", blob, map[string]any{"password": pw, "new_password": "another passphrase"})))
	if r := e.unlock(blob, pw); r.Code != "bad_password" {
		t.Fatalf("old password: %q", r.Code)
	}
	e.ok(e.unlock(blob, "another passphrase"))
}

func TestRotateRotatesIdentity(t *testing.T) {
	e := newEnv(t)
	blob := e.create()
	k1, _ := e.ok(e.raw("app", "credential.version", `{}`)).Obj(t).String("key")
	e.h.RotateErr = vault.NewError("internal", "")
	if r := e.call("app", "credential.rotate", blob, map[string]any{"password": pw}); r.OK() {
		t.Fatal("rotate succeeded although the identity rotation failed")
	}
	e.h.RotateErr = nil
	r := e.ok(e.call("app", "credential.rotate", blob, map[string]any{"password": pw}))
	if e.h.Rotations != 1 {
		t.Fatal("ik/kem not rotated (§3.4)")
	}
	if k2, _ := r.Obj(t).String("key"); k1 == k2 {
		t.Fatal("credential key not rotated")
	}
	e.ok(e.unlock(blobOf(t, r), pw))
}

func TestUnlockWindow(t *testing.T) {
	e := newEnv(t)
	blob := e.create()
	e.h.Set.CredentialUnlockTTL = 60
	blob = blobOf(t, e.ok(e.unlock(blob, pw)))
	if _, ok := e.f.UseKey(e.clk.T.Add(30*time.Second), time.Minute); !ok {
		t.Fatal("window closed early")
	}
	if _, ok := e.f.UseKey(e.clk.T.Add(200*time.Second), time.Minute); ok {
		t.Fatal("window open after expiry")
	}
	e.ok(e.unlock(blob, pw))
	e.ok(e.raw("app", "credential.lock", `{}`))
	if _, ok := e.f.UseKey(e.clk.T, time.Minute); ok {
		t.Fatal("window open after credential.lock")
	}
}

// §3.5.5, §10.6, §15 item 23 (0.15.2): there is no credential.delete; the
// holder's credential.reset{credential, utk_id, sealed{pin, password,
// new_password}} verifies the blob, the PIN and the current password as an
// owner check does (failed entries are failed checks), then replaces the
// credential in one step: version 1, a new key, the old blob dead, every
// critical item destroyed, the clock started fresh; refused during an
// alarm and to another app.
func TestHolderReset(t *testing.T) {
	e := newEnv(t)
	e.h.PIN = "246810"
	if f := (&Feature{}); len(f.Types()) > 0 {
		for _, ts := range f.Types() {
			if ts.Type == "credential.delete" {
				t.Fatal("credential.delete still registered")
			}
		}
	}
	if r := e.raw("app", "credential.delete", `{}`); r.Code != "unsupported_type" {
		t.Fatalf("credential.delete: %q", r.Code)
	}
	blob := e.create()
	reset := func(b, pin, cur string) featuretest.Result {
		return e.call("app", "credential.reset", b, map[string]any{"pin": pin, "password": cur, "new_password": "a brand new password"})
	}
	if r := e.call("app", "credential.reset", blob, map[string]any{"password": pw}); r.Code != "bad_request" {
		t.Fatalf("recovering form from the holder: %q", r.Code)
	}
	if r := reset(blob, "135791", pw); r.Code != "bad_pin" {
		t.Fatalf("wrong PIN: %q", r.Code)
	}
	if r := reset(blob, "246810", "wrong password"); r.Code != "bad_password" {
		t.Fatalf("wrong password: %q", r.Code)
	}
	if strings.Join(e.h.CheckFailed, ",") != "pin,password" {
		t.Fatalf("failed checks %v", e.h.CheckFailed)
	}
	key0, _ := e.ok(e.raw("app", "credential.version", `{}`)).Obj(t).String("key")
	r := e.ok(reset(blob, "246810", pw))
	o := r.Obj(t)
	if v, _ := o.Uint("version", 1, 10); v != 1 || !o.Has("key") || !o.Has("utks") {
		t.Fatalf("reset answer %s", r.Body)
	}
	if k, _ := o.String("key"); k == key0 {
		t.Fatal("same credential key")
	}
	if len(e.h.Passed) != 1 || e.h.Passed[0] != nil || e.h.PassedAudit[0] || !e.h.HasActivity("credential.reset") {
		t.Fatalf("clock not started fresh: %v", e.h.Passed)
	}
	if e.f.Holder() != "dev-app" {
		t.Fatal("holder changed")
	}
	nb := blobOf(t, r)
	e.ok(e.raw("app", "credential.ack", `{"version":1}`))
	e.ok(e.unlock(nb, "a brand new password"))
	if r := e.unlock(blob, pw); r.Code == "" {
		t.Fatal("the old blob still opens")
	}
	for _, a := range e.h.Activities {
		if a.Kind == "credential.deleted" {
			t.Fatal("credential.deleted recorded (removed in 0.15.2)")
		}
	}
	if len(e.h.SentOfType("sync.event")) > 0 {
		for _, s := range e.h.SentOfType("sync.event") {
			if strings.Contains(string(s.Body), "credential.deleted") {
				t.Fatal("credential.deleted sync.event")
			}
		}
	}
	// Another app may not reset.
	if r := e.call("app2", "credential.reset", nb, map[string]any{"pin": "246810", "password": "a brand new password", "new_password": pw}); r.Code != "forbidden" {
		t.Fatalf("another app: %q", r.Code)
	}
}

// §11.11.5: recover only from a recovering app, against the vault's copy;
// no credential → refused. The recovered app becomes the holder: the old
// app's copy is dead and, presented, a clone (§3.5.9).
func TestRecover(t *testing.T) {
	e := newEnv(t)
	if r := e.call("recovering-app", "credential.recover", "", map[string]any{"password": pw}); r.Code != "credential_required" {
		t.Fatalf("no credential: %q", r.Code)
	}
	blob := e.create()
	if r := e.call("app", "credential.recover", "", map[string]any{"password": pw}); r.Code != "forbidden" {
		t.Fatalf("ordinary app: %q", r.Code)
	}
	if r := e.call("recovering-app", "credential.unlock", blob, map[string]any{"password": pw}); r.Code != "forbidden" {
		t.Fatalf("recovering app used the credential: %q", r.Code)
	}
	if r := e.call("recovering-app", "credential.recover", "", map[string]any{"password": "wrong password"}); r.Code != "bad_password" {
		t.Fatalf("wrong password: %q", r.Code)
	}
	if len(e.h.Completed) != 0 {
		t.Fatal("completed without the password")
	}
	got := blobOf(t, e.ok(e.call("recovering-app", "credential.recover", "", map[string]any{"password": pw})))
	if got == blob || len(e.h.Completed) != 1 {
		t.Fatal("recover did not rotate or complete")
	}
	if e.f.Holder() != "dev-recovering" || e.f.PoolSizeOf("dev-app") != 0 {
		t.Fatal("the recovered app does not hold the credential alone")
	}
	e.pools["app"] = nil // its UTKs went with it
	if r := e.unlock(blob, pw); r.Code != "credential_frozen" || len(e.h.Alarms) != 1 {
		t.Fatalf("lost device's copy: %q %v", r.Code, e.h.Alarms)
	}
}

// §3.5.6, §11.11.5 (0.16.0): the vault has a backup copy only while the
// setting is on and the latest blob was sealed with it on; with it off a
// recovering app gets nothing (no reset, no deletion, no credential_lost:
// credential.recover is refused), and only the holder may reset.
func TestBackupCopyAndRecoveringApp(t *testing.T) {
	e := newEnv(t)
	blob := e.create()
	if !e.f.HasBackupCopy() {
		t.Fatal("no backup copy with the setting on")
	}
	e.h.Set.NoBackup = true
	e.f.SettingsChanged(nil, e.h.Set)
	if e.f.HasBackupCopy() {
		t.Fatal("backup copy with the setting off")
	}
	e.h.Set.NoBackup = false
	e.f.SettingsChanged(nil, e.h.Set)
	if e.f.HasBackupCopy() {
		t.Fatal("a copy before the next use")
	}
	nb := blobOf(t, e.ok(e.unlock(blob, pw)))
	if !e.f.HasBackupCopy() {
		t.Fatal("no copy after a use with the setting on")
	}
	_ = nb
	for _, typ := range []string{"credential.reset", "vault.delete", "credential.get", "credential.version"} {
		if r := e.call("recovering-app", typ, "", map[string]any{"password": pw, "pin": "246810"}); r.Code != "forbidden" {
			t.Fatalf("%s from a recovering app: %q", typ, r.Code)
		}
	}
	e.h.Set.NoBackup = true
	e.f.SettingsChanged(nil, e.h.Set)
	e.ok(e.raw("app", "credential.ack", `{"version":2}`))
	if r := e.call("recovering-app", "credential.recover", "", map[string]any{"password": pw}); r.Code != "forbidden" || r.Body != nil {
		t.Fatalf("recover without a copy: %q", r.Code)
	}
	if len(e.h.Completed) != 0 {
		t.Fatal("completed")
	}
}

func TestRecoverBackoff(t *testing.T) {
	e := newEnv(t)
	e.create()
	for i := 0; i < BackoffAfter; i++ {
		e.call("recovering-app", "credential.recover", "", map[string]any{"password": "wrong password"})
	}
	if r := e.call("recovering-app", "credential.recover", "", map[string]any{"password": pw}); r.Code != "backoff" {
		t.Fatalf("no backoff: %q", r.Code)
	}
}

func TestBadBodies(t *testing.T) {
	e := newEnv(t)
	blob := e.create()
	for _, c := range []struct {
		typ     string
		payload map[string]any
	}{
		{"credential.unlock", map[string]any{"password": "short"}},
		{"credential.unlock", map[string]any{"password": strings.Repeat("p", MaxPassword+1)}},
		{"credential.unlock", map[string]any{"password": 12345678}},
		{"credential.password.change", map[string]any{"password": pw, "new_password": "short"}},
	} {
		if r := e.call("app", c.typ, blob, c.payload); r.Code != "bad_request" {
			t.Errorf("%s %v: %q", c.typ, c.payload, r.Code)
		}
	}
	for _, body := range []string{`{}`, `{"credential":"!!!","utk_id":"0011223344556677","sealed":"AAAA"}`, `{"credential":"` + blob + `","utk_id":"XYZ","sealed":"AAAA"}`} {
		if r := e.raw("app", "credential.unlock", body); r.Code != "bad_request" {
			t.Errorf("%.60s: %q", body, r.Code)
		}
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
	if _, err := Seal(cek.Public(), "v1", 1, []byte(pw), KDF{Time: 1, MemoryKiB: 1024, Threads: 1}, inner); err != ErrKDF {
		t.Fatal("weak KDF accepted")
	}
}

func FuzzParseEnvelope(f *testing.F) {
	f.Add("credential.unlock", []byte(`{"credential":"AAAA","utk_id":"0011223344556677","sealed":"AAAA"}`))
	f.Add("credential.recover", []byte(`{"utk_id":"0011223344556677","sealed":"AAAA"}`))
	f.Add("device.transfer.approve", []byte(`{"transfer_id":"`+testID+`","credential":"AAAA","utk_id":"0011223344556677","sealed":"AAAA"}`))
	f.Fuzz(func(t *testing.T, typ string, b []byte) {
		e, err := ParseEnvelope(typ, b)
		if err != nil {
			return
		}
		if needs[typ]&needSealed != 0 && !ValidUTKID(e.UTKID) {
			t.Fatal("bad utk id accepted")
		}
	})
}

func FuzzParsePayload(f *testing.F) {
	f.Add("credential.unlock", []byte(`{"password":"`+pw+`"}`))
	f.Add("credential.password.change", []byte(`{"password":"`+pw+`","new_password":"`+pw+`"}`))
	f.Add("device.transfer.approve", []byte(`{"password":"`+pw+`","pin":"246810"}`))
	f.Add("vault.delete", []byte(`{"pin":"246810"}`))
	f.Add(vault.TypeOwnerCheck, []byte(`{"password":"`+pw+`","pin":"246810","hold":false,"hold_off_until":"2026-10-07T12:00:00.000Z"}`))
	f.Fuzz(func(t *testing.T, typ string, b []byte) {
		p, err := ParsePayload(typ, b)
		if err != nil {
			return
		}
		if n := needs[typ]; n&needPassword != 0 && (len(p.Password) < MinPassword || len(p.Password) > MaxPassword) {
			t.Fatal("bad password accepted")
		}
		if n := needs[typ]; n&needPIN != 0 && !validPIN(string(p.PIN)) {
			t.Fatal("bad PIN accepted")
		}
	})
}

func FuzzParseOpPayload(f *testing.F) {
	f.Add(NeedItem|NeedOptItemID, []byte(`{"password":"`+pw+`","item_id":"`+testID+`","item":{"name":"x"}}`))
	f.Add(NeedRequest, []byte(`{"password":"`+pw+`","request_id":"`+testID+`","payload_sha256":"`+strings.Repeat("A", 43)+`="}`))
	f.Add(NeedItemID|NeedReply, []byte(`{"password":"`+pw+`","item_id":"`+testID+`","reply_key":"AA=="}`))
	f.Fuzz(func(t *testing.T, need int, b []byte) {
		p, err := ParseOpPayload(need&(NeedItemID|NeedOptItemID|NeedItem|NeedReply|NeedRequest), b)
		if err != nil {
			return
		}
		if len(p.Password) < MinPassword || len(p.Password) > MaxPassword {
			t.Fatal("bad password accepted")
		}
		if need&NeedItem != 0 && (len(p.Item) == 0 || p.Item[0] != '{') {
			t.Fatal("item not an object")
		}
		if need&NeedItemID != 0 && !envelope.ValidULID(p.ItemID) {
			t.Fatal("bad item id accepted")
		}
	})
}

func FuzzParseInner(f *testing.F) {
	in := &Inner{VaultID: "v", Version: 1, CreatedAt: time.Unix(0, 0), PasswordChangedAt: time.Unix(0, 0), Key: make([]byte, 32),
		Items: []Item{{ID: testID, Gen: 3, Key: make([]byte, ItemKeySize)}}}
	f.Add(in.Marshal())
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := ParseInner(b)
		if err != nil {
			return
		}
		if len(p.Key) != 32 || len(p.Items) > MaxItems {
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
		_, _, _ = Open(cek, "v", b, []byte(pw))
	})
}

// §3.5.2: the credential holds only item keys (§10.7), so 1,000 critical
// items fit within the 131,072-byte plaintext; more are refused with
// limit and change nothing.
func TestInnerLimit(t *testing.T) {
	e := newEnv(t)
	blob := e.create()
	n := 0
	e.op = &opFeature{cred: e.f, op: func(in *Inner, _ *Payload) error {
		for len(in.Items) < n {
			id, _ := envelope.NewULID(time.Unix(int64(len(in.Items)+1), 0))
			in.Items = append(in.Items, Item{ID: id, Gen: 1 << 40, Key: bytes.Repeat([]byte{0xee}, ItemKeySize)})
		}
		return nil
	}}
	n = MaxItems
	blob = blobOf(t, e.ok(e.call("app", "test.op", blob, map[string]any{"password": pw})))
	n = MaxItems + 1
	if r := e.call("app", "test.op", blob, map[string]any{"password": pw}); r.Code != "limit" {
		t.Fatalf("over the limit: %q", r.Code)
	}
	e.ok(e.unlock(blob, pw))
}
