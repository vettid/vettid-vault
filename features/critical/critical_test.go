package critical

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/features/credential"
	"github.com/vettid/vettid-vault/internal/featuretest"
	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/credwire"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/sharewire"
	"github.com/vettid/vettid-vault/vms/suite"
)

const pw = "correct horse battery"

var b64 = base64.StdEncoding

type utk struct {
	id string
	ek *suite.PublicKey
}

// side is one vault: a credential, the critical feature and a fake host.
type side struct {
	t    *testing.T
	h    *featuretest.Host
	cred *credential.Feature
	f    *Feature
	clk  *featuretest.Clock
	pool []utk
	blob string
}

func newSide(t *testing.T, clk *featuretest.Clock, ikSeed byte) *side {
	s := &side{t: t, h: featuretest.NewHost(), clk: clk}
	s.h.SetIdentity(ikSeed)
	s.cred = credential.New(credential.Options{KDF: credential.MinKDF})
	s.f = New(s.cred)
	return s
}

func (s *side) call(f vault.Feature, kind, typ, body string) featuretest.Result {
	s.clk.Advance(time.Second)
	r := featuretest.Call(f, s.h, s.clk.T, kind, typ, body)
	s.absorb(r)
	return r
}

func (s *side) absorb(r featuretest.Result) {
	if !r.OK() || r.Body == nil {
		return
	}
	var out struct {
		UTKs []struct {
			ID string `json:"utk_id"`
			EK []byte `json:"ek"`
		} `json:"utks"`
		Credential string `json:"credential"`
	}
	if json.Unmarshal(r.Body, &out) != nil {
		return
	}
	for _, u := range out.UTKs {
		ek, err := suite.ParsePublicKey(u.EK)
		if err != nil {
			s.t.Fatal(err)
		}
		s.pool = append(s.pool, utk{u.ID, ek})
	}
	if out.Credential != "" {
		s.blob = out.Credential
	}
}

func (s *side) take() utk {
	if len(s.pool) == 0 {
		if r := s.call(s.cred, "app", "credential.utk.get", `{}`); !r.OK() {
			s.t.Fatalf("utk.get: %s", r.Code)
		}
	}
	u := s.pool[0]
	s.pool = s.pool[1:]
	return u
}

// sealed sends typ to f from kind with payload sealed to a fresh UTK and
// the outer members extra (plus the current blob when withBlob).
func (s *side) sealed(f vault.Feature, kind, typ string, payload, extra map[string]any, withBlob bool) featuretest.Result {
	s.t.Helper()
	u := s.take()
	pt, _ := json.Marshal(payload)
	s.clk.Advance(time.Second)
	id, _ := envelope.NewULID(s.clk.T)
	sealed, err := credwire.SealPayload(u.ek, s.h.VaultID(), u.id, typ, id, pt)
	if err != nil {
		s.t.Fatal(err)
	}
	body := map[string]any{"utk_id": u.id, "sealed": b64.EncodeToString(sealed)}
	for k, v := range extra {
		body[k] = v
	}
	if withBlob {
		body["credential"] = s.blob
	}
	b, _ := json.Marshal(body)
	r := featuretest.CallID(f, s.h, s.clk.T, kind, typ, id, string(b))
	s.absorb(r)
	return r
}

// setup creates the credential and a cataloged critical secret holding
// value; it returns the secret's id.
func (s *side) setup(value []byte, catalog bool) string {
	s.t.Helper()
	if r := s.sealed(s.cred, "app", "credential.create", map[string]any{"password": pw}, nil, false); !r.OK() {
		s.t.Fatalf("create: %s", r.Code)
	}
	r := s.sealed(s.cred, "app", "credential.secret.add", map[string]any{"password": pw, "name": "Signer",
		"category": "signing_key", "value": b64.EncodeToString(value)}, nil, true)
	if !r.OK() {
		s.t.Fatalf("secret.add: %s", r.Code)
	}
	id, _ := r.Obj(s.t).String("secret_id")
	if catalog {
		if r := s.call(s.cred, "app", "credential.secret.catalog", `{"secret_id":"`+id+`","cataloged":true}`); !r.OK() {
			s.t.Fatalf("catalog: %s", r.Code)
		}
	}
	return id
}

func (s *side) approve(reqID string, payload []byte, kind string) featuretest.Result {
	h := sha256.Sum256(payload)
	return s.sealed(s.f, kind, "critical-secret-use.approve",
		map[string]any{"password": pw, "request_id": reqID, "payload_sha256": b64.EncodeToString(h[:])},
		map[string]any{"request_id": reqID}, true)
}

func ulid(t time.Time) string {
	id, _ := envelope.NewULID(t)
	return id
}

func useBody(reqID, secretID, op string, payload []byte) string {
	b, _ := json.Marshal(map[string]any{"request_id": reqID, "secret_id": secretID, "operation": op,
		"payload": b64.EncodeToString(payload), "context": "invoice 7"})
	return string(b)
}

func lastSent(t *testing.T, h *featuretest.Host, typ string) featuretest.Sent {
	t.Helper()
	l := h.SentOfType(typ)
	if len(l) == 0 {
		t.Fatalf("nothing of type %s sent", typ)
	}
	return l[len(l)-1]
}

func field(t *testing.T, raw json.RawMessage, name string) string {
	t.Helper()
	o, err := strictjson.ParseObject(raw)
	if err != nil {
		t.Fatal(err)
	}
	v, _ := o.String(name)
	return v
}

func newClock() *featuretest.Clock {
	return &featuretest.Clock{T: time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)}
}

// Both vaults end to end: B asks, A's member approves with the password,
// A signs (sign and auth), B verifies and passes the result on.
func TestUseFlow(t *testing.T) {
	for _, op := range []string{OperationSign, OperationAuth} {
		t.Run(op, func(t *testing.T) {
			clk := newClock()
			a, b := newSide(t, clk, 0x0a), newSide(t, clk, 0x0b)
			a.h.Conns["conn-b"] = vault.PeerInfo{ID: "conn-b", Kind: vault.KindConnection, State: vault.PeerActive, IK: b.h.IK}
			b.h.Conns["conn-a"] = vault.PeerInfo{ID: "conn-a", Kind: vault.KindConnection, State: vault.PeerActive, IK: a.h.IK}
			seed := bytes.Repeat([]byte{0x33}, 32)
			sid := a.setup(seed, true)
			payload := []byte("tx 0xdeadbeef")

			req, _ := json.Marshal(map[string]any{"connection_id": "conn-a", "secret_id": sid, "operation": op,
				"payload": b64.EncodeToString(payload)})
			r := b.call(b.f, "app", "critical-secret-use.request", string(req))
			if !r.OK() {
				t.Fatalf("request: %s", r.Code)
			}
			reqID, _ := r.Obj(t).String("request_id")
			use := lastSent(t, b.h, "critical-secret.use")
			if use.To != "conn-a" || field(t, use.Body, "request_id") != reqID {
				t.Fatalf("use: %+v", use)
			}
			if !b.h.HasActivity("critical-secret.use.requested") {
				t.Fatal("asking side not audited")
			}

			if r := a.call(a.f, "connection:conn-b", "critical-secret.use", string(use.Body)); !r.OK() {
				t.Fatalf("incoming: %s", r.Code)
			}
			pend := lastSent(t, a.h, "critical-secret-use.pending")
			if pend.To != "devices" || field(t, pend.Body, "name") != "Signer" {
				t.Fatalf("pending: %+v", pend)
			}
			if !a.h.HasActivity("critical-secret.use.request") || !a.h.HasActivity("critical-secret.use.requested") {
				t.Fatal("feed or audit missing")
			}
			oldBlob := a.blob
			ver0, _ := a.call(a.cred, "app", "credential.version", `{}`).Obj(t).Uint("version", 0, 1<<40)

			ar := a.approve(reqID, payload, "app")
			if !ar.OK() {
				t.Fatalf("approve: %s", ar.Code)
			}
			if st, _ := ar.Obj(t).String("status"); st != StatusOK {
				t.Fatalf("status %q", st)
			}
			ver1, _ := a.call(a.cred, "app", "credential.version", `{}`).Obj(t).Uint("version", 0, 1<<40)
			if ver1 != ver0+1 || a.blob == oldBlob {
				t.Fatalf("CEK not rotated: %d -> %d", ver0, ver1)
			}
			// The old blob is dead (§3.5.3).
			r = a.sealed(a.cred, "app", "credential.unlock", map[string]any{"password": pw}, map[string]any{"credential": oldBlob}, false)
			if r.Code != "stale_credential" {
				t.Fatalf("old blob: %q", r.Code)
			}
			if len(a.f.Pending()) != 0 || !a.h.HasActivity("critical-secret.used") {
				t.Fatal("pending kept or not audited")
			}
			res := lastSent(t, a.h, "critical-secret.result")
			if res.To != "conn-b" {
				t.Fatal("result to wrong connection")
			}
			o, _ := strictjson.ParseObject(res.Body)
			sig, _ := o.Base64("signature", 64)
			pub, _ := o.Base64("public_key", 32)
			msg := payload
			if op == OperationAuth {
				msg = append([]byte(sharewire.LabelCriticalAuth), sharewire.AuthMessage(b.h.IK, a.h.IK, reqID, payload)...)
			}
			want := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
			if !bytes.Equal(pub, want) || !ed25519.Verify(pub, msg, sig) {
				t.Fatal("signature does not verify")
			}
			if op == OperationAuth && ed25519.Verify(pub, payload, sig) {
				t.Fatal("auth signature valid as a raw sign")
			}

			if r := b.call(b.f, "connection:conn-a", "critical-secret.result", string(res.Body)); !r.OK() {
				t.Fatalf("result: %s", r.Code)
			}
			out := lastSent(t, b.h, "critical-secret-use.result")
			if field(t, out.Body, "status") != StatusOK || field(t, out.Body, "connection_id") != "conn-a" {
				t.Fatalf("result to devices: %s", out.Body)
			}
			// A second result for the same request is dropped.
			b.h.Reset()
			b.call(b.f, "connection:conn-a", "critical-secret.result", string(res.Body))
			if len(b.h.SentOfType("critical-secret-use.result")) != 0 {
				t.Fatal("answered request forwarded twice")
			}
			// A repeated request id is ignored by the member's vault.
			a.h.Reset()
			a.call(a.f, "connection:conn-b", "critical-secret.use", string(use.Body))
			if len(a.h.Sent) != 0 {
				t.Fatal("repeated request_id asked again")
			}
		})
	}
}

// A forged signature (or one over another message) is dropped by the
// asking vault.
func TestForgedResultDropped(t *testing.T) {
	clk := newClock()
	b := newSide(t, clk, 0x0b)
	b.h.AddConnection("conn-a")
	req, _ := json.Marshal(map[string]any{"connection_id": "conn-a", "secret_id": ulid(clk.T), "operation": "sign",
		"payload": b64.EncodeToString([]byte("x"))})
	r := b.call(b.f, "app", "critical-secret-use.request", string(req))
	reqID, _ := r.Obj(t).String("request_id")
	k := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	body, _ := json.Marshal(map[string]any{"request_id": reqID, "status": "ok", "signature": ed25519.Sign(k, []byte("y")),
		"public_key": []byte(k.Public().(ed25519.PublicKey))})
	b.call(b.f, "connection:conn-a", "critical-secret.result", string(body))
	if len(b.h.SentOfType("critical-secret-use.result")) != 0 || !b.h.HasActivity("drop.critical_signature") {
		t.Fatal("forged signature passed on")
	}
	// Another connection cannot answer it.
	b.h.AddConnection("conn-x")
	b.call(b.f, "connection:conn-x", "critical-secret.result", `{"request_id":"`+reqID+`","status":"denied"}`)
	if len(b.h.SentOfType("critical-secret-use.result")) != 0 {
		t.Fatal("another connection answered")
	}
	b.call(b.f, "connection:conn-a", "critical-secret.result", `{"request_id":"`+reqID+`","status":"denied"}`)
	if field(t, lastSent(t, b.h, "critical-secret-use.result").Body, "status") != StatusDenied {
		t.Fatal("denial not passed on")
	}
}

func setupA(t *testing.T, value []byte, catalog bool) (*side, string) {
	clk := newClock()
	a := newSide(t, clk, 0x0a)
	a.h.AddConnection("conn-b")
	return a, a.setup(value, catalog)
}

func (s *side) ask(secretID string, payload []byte) string {
	id := ulid(s.clk.T.Add(time.Hour + time.Duration(len(s.h.Sent))*time.Millisecond))
	if r := s.call(s.f, "connection:conn-b", "critical-secret.use", useBody(id, secretID, "sign", payload)); !r.OK() {
		s.t.Fatalf("incoming: %s", r.Code)
	}
	return id
}

// Consent: only the app approves; the sealed payload must name this
// request and this payload; a wrong password keeps the request pending.
func TestConsent(t *testing.T) {
	seed := bytes.Repeat([]byte{0x44}, 32)
	a, sid := setupA(t, seed, true)
	payload := []byte("pay 5 EUR")
	id := a.ask(sid, payload)

	for _, kind := range []string{"desktop", "agent", "connection:conn-b"} {
		if r := a.approve(id, payload, kind); r.Code != "forbidden" {
			t.Errorf("approve from %s: %q", kind, r.Code)
		}
	}
	// Wrong request id or payload in the sealed payload: bad_request, the
	// UTK spent, nothing signed.
	other := ulid(a.clk.T)
	h := sha256.Sum256(payload)
	r := a.sealed(a.f, "app", "critical-secret-use.approve",
		map[string]any{"password": pw, "request_id": other, "payload_sha256": b64.EncodeToString(h[:])},
		map[string]any{"request_id": id}, true)
	if r.Code != "bad_request" {
		t.Fatalf("redirected consent: %q", r.Code)
	}
	if r := a.approve(id, []byte("pay 500 EUR"), "app"); r.Code != "bad_request" {
		t.Fatalf("other payload: %q", r.Code)
	}
	if len(a.h.SentOfType("critical-secret.result")) != 0 || len(a.f.Pending()) != 1 {
		t.Fatal("bad consent answered the request")
	}
	// The UTK of a refused consent cannot be reused.
	u := a.take()
	pt, _ := json.Marshal(map[string]any{"password": pw, "request_id": other, "payload_sha256": b64.EncodeToString(h[:])})
	a.clk.Advance(time.Second)
	iid := ulid(a.clk.T)
	sealed, _ := credwire.SealPayload(u.ek, a.h.VaultID(), u.id, "critical-secret-use.approve", iid, pt)
	body, _ := json.Marshal(map[string]any{"request_id": id, "credential": a.blob, "utk_id": u.id, "sealed": b64.EncodeToString(sealed)})
	featuretest.CallID(a.f, a.h, a.clk.T, "app", "critical-secret-use.approve", iid, string(body))
	if r := featuretest.CallID(a.f, a.h, a.clk.T, "app", "critical-secret-use.approve", iid, string(body)); r.Code != "utk_invalid" {
		t.Fatalf("UTK reuse: %q", r.Code)
	}
	// A wrong password: bad_password, still pending; five of them: backoff.
	for i := 0; i < 5; i++ {
		h := sha256.Sum256(payload)
		r := a.sealed(a.f, "app", "critical-secret-use.approve",
			map[string]any{"password": "wrong password!", "request_id": id, "payload_sha256": b64.EncodeToString(h[:])},
			map[string]any{"request_id": id}, true)
		if r.Code != "bad_password" {
			t.Fatalf("wrong password %d: %q", i, r.Code)
		}
	}
	if r := a.approve(id, payload, "app"); r.Code != "backoff" {
		t.Fatalf("backoff: %q", r.Code)
	}
	if len(a.f.Pending()) != 1 {
		t.Fatal("request dropped by a credential error")
	}
	a.clk.Advance(time.Minute)
	if r := a.approve(id, payload, "app"); !r.OK() {
		t.Fatalf("approve after backoff: %s", r.Code)
	}
	// The same approval again: the request is gone.
	if r := a.approve(id, payload, "app"); r.Code != "not_found" {
		t.Fatalf("second approval: %q", r.Code)
	}
}

// Deny from a desktop; uncataloged and unsuitable secrets; limits;
// expiry; removal.
func TestRefusals(t *testing.T) {
	a, sid := setupA(t, bytes.Repeat([]byte{0x55}, 32), true)
	id := a.ask(sid, []byte("p"))
	if r := a.call(a.f, "agent", "critical-secret-use.deny", `{"request_id":"`+id+`"}`); r.Code != "forbidden" {
		t.Fatalf("agent deny: %q", r.Code)
	}
	if r := a.call(a.f, "desktop", "critical-secret-use.deny", `{"request_id":"`+id+`"}`); !r.OK() {
		t.Fatalf("deny: %s", r.Code)
	}
	if field(t, lastSent(t, a.h, "critical-secret.result").Body, "status") != StatusDenied {
		t.Fatal("not denied")
	}
	if !a.h.HasActivity("critical-secret.use.denied") || len(a.h.SentOfType("sync.event")) == 0 {
		t.Fatal("deny not audited or synced")
	}

	// Not in the catalog: unavailable without asking.
	b, sid2 := setupA(t, bytes.Repeat([]byte{0x55}, 32), false)
	b.h.Reset()
	b.ask(sid2, []byte("p"))
	if field(t, lastSent(t, b.h, "critical-secret.result").Body, "status") != StatusUnavailable || len(b.h.SentOfType("critical-secret-use.pending")) != 0 {
		t.Fatal("uncataloged secret asked")
	}
	b.ask(ulid(b.clk.T), []byte("p")) // unknown: the same answer
	if field(t, lastSent(t, b.h, "critical-secret.result").Body, "status") != StatusUnavailable {
		t.Fatal("unknown secret")
	}

	// A value that is not an Ed25519 seed: unsuitable (the credential was
	// opened and rotated).
	c, sid3 := setupA(t, []byte("not a seed"), true)
	id = c.ask(sid3, []byte("p"))
	r := c.approve(id, []byte("p"), "app")
	if st, _ := r.Obj(t).String("status"); !r.OK() || st != StatusUnsuitable {
		t.Fatalf("unsuitable: %s %q", r.Code, st)
	}

	// At most 8 pending per connection.
	d, sid4 := setupA(t, bytes.Repeat([]byte{0x55}, 32), true)
	for i := 0; i < MaxPendingIn; i++ {
		d.ask(sid4, []byte{byte(i)})
	}
	d.h.Reset()
	d.ask(sid4, []byte("ninth"))
	if field(t, lastSent(t, d.h, "critical-secret.result").Body, "status") != StatusUnavailable || len(d.f.Pending()) != MaxPendingIn {
		t.Fatal("limit")
	}
	// Expiry after 24 h: answered expired.
	d.clk.Advance(RequestTTL + time.Hour)
	d.h.Reset()
	d.call(d.f, "app", "critical-secret-use.list", `{}`)
	if len(d.h.SentOfType("critical-secret.result")) != MaxPendingIn || len(d.f.Pending()) != 0 {
		t.Fatal("expiry")
	}
	if field(t, d.h.SentOfType("critical-secret.result")[0].Body, "status") != StatusExpired {
		t.Fatal("expired status")
	}
	// Removal drops a connection's requests without notice.
	id = d.ask(sid4, []byte("p"))
	d.h.Reset()
	d.f.ConnectionRemoved(nil, "conn-b")
	if len(d.f.Pending()) != 0 || len(d.h.Sent) != 0 {
		t.Fatal("removal")
	}
	_ = id
}

// Roles and bad bodies.
func TestAuthorizationAndBadBodies(t *testing.T) {
	clk := newClock()
	a := newSide(t, clk, 0x0a)
	a.h.AddConnection("conn-b")
	sid := ulid(clk.T)
	good := `{"connection_id":"conn-b","secret_id":"` + sid + `","operation":"sign","payload":"cA=="}`
	for kind, want := range map[string]string{"agent": "forbidden", "connection:conn-b": "forbidden", "desktop": "", "app": ""} {
		if r := a.call(a.f, kind, "critical-secret-use.request", good); r.Code != want {
			t.Errorf("request from %s: %q", kind, r.Code)
		}
	}
	for _, typ := range []string{"critical-secret.use", "critical-secret.result"} {
		if r := a.call(a.f, "app", typ, `{}`); r.Code != "forbidden" {
			t.Errorf("%s from an app: %q", typ, r.Code)
		}
	}
	if r := a.call(a.f, "agent", "critical-secret-use.list", `{}`); r.Code != "forbidden" {
		t.Error("agent list")
	}
	for _, body := range []string{`{}`, `[]`,
		`{"connection_id":"conn-b","secret_id":"x","operation":"sign","payload":"cA=="}`,
		`{"connection_id":"conn-b","secret_id":"` + sid + `","operation":"decrypt","payload":"cA=="}`,
		`{"connection_id":"conn-b","secret_id":"` + sid + `","operation":"sign","payload":""}`,
		`{"connection_id":"conn-b","secret_id":"` + sid + `","operation":"sign","payload":"cA"}`,
		`{"connection_id":"conn-b","secret_id":"` + sid + `","operation":"sign","payload":"` + b64.EncodeToString(make([]byte, MaxPayload+1)) + `"}`,
		`{"connection_id":"conn-b","secret_id":"` + sid + `","operation":"sign","payload":"cA==","context":"` + string(bytes.Repeat([]byte{'x'}, MaxContext+1)) + `"}`,
		`{"connection_id":"conn-b","secret_id":"` + sid + `","operation":"sign","payload":"cA==","payload":"cA=="}`,
	} {
		if r := a.call(a.f, "app", "critical-secret-use.request", body); r.Code != "bad_request" {
			t.Errorf("%s: %q", body, r.Code)
		}
	}
	if r := a.call(a.f, "app", "critical-secret-use.request", `{"connection_id":"nope","secret_id":"`+sid+`","operation":"sign","payload":"cA=="}`); r.Code != "not_found" {
		t.Errorf("unknown connection: %q", r.Code)
	}
	a.h.DownConns["conn-b"] = true
	if r := a.call(a.f, "app", "critical-secret-use.request", good); r.Code != "connection_unavailable" {
		t.Errorf("down connection: %q", r.Code)
	}
	if r := a.call(a.f, "app", "critical-secret-use.deny", `{"request_id":"`+sid+`"}`); r.Code != "not_found" {
		t.Errorf("deny unknown: %q", r.Code)
	}
	if r := a.call(a.f, "app", "critical-secret-use.approve", `{"request_id":"`+sid+`"}`); r.Code != "not_found" {
		t.Errorf("approve unknown: %q", r.Code)
	}
	// A malformed peer message is refused.
	if r := a.call(a.f, "connection:conn-b", "critical-secret.use", `{"request_id":"`+sid+`"}`); r.Code != "bad_request" {
		t.Errorf("bad use: %q", r.Code)
	}
	if r := a.call(a.f, "connection:conn-b", "critical-secret.result", `{"request_id":"`+sid+`","status":"maybe"}`); r.Code != "bad_request" {
		t.Errorf("bad result: %q", r.Code)
	}
}

// State survives a flush and an unlock; the list shows both directions.
func TestStateAndList(t *testing.T) {
	a, sid := setupA(t, bytes.Repeat([]byte{0x66}, 32), true)
	id := a.ask(sid, []byte("p"))
	a.call(a.f, "app", "critical-secret-use.request", `{"connection_id":"conn-b","secret_id":"`+sid+`","operation":"auth","payload":"cA=="}`)
	g := New(a.cred)
	featuretest.RoundTrip(t, a.f, g)
	r := a.call(g, "desktop", "critical-secret-use.list", `{}`)
	o := r.Obj(t)
	in, _ := o.Array("incoming")
	out, _ := o.Array("outgoing")
	if len(in) != 1 || len(out) != 1 || !bytes.Contains(in[0], []byte(id)) || bytes.Contains(in[0], []byte(`"payload"`)) {
		t.Fatalf("list: %s", r.Body)
	}
}

func FuzzParseRequest(f *testing.F) {
	f.Add([]byte(`{"connection_id":"c","secret_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V","operation":"sign","payload":"cA==","context":"x"}`))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = ParseRequest(b) })
}

func FuzzParseUse(f *testing.F) {
	f.Add([]byte(`{"request_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V","secret_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V","operation":"auth","payload":"cA=="}`))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = ParseUse(b) })
}

func FuzzParseResult(f *testing.F) {
	f.Add([]byte(`{"request_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V","status":"denied"}`))
	f.Add([]byte(`{"request_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V","status":"ok","signature":"` + b64.EncodeToString(make([]byte, 64)) +
		`","public_key":"` + b64.EncodeToString(make([]byte, 32)) + `"}`))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = ParseResult(b) })
}

func FuzzRequestID(f *testing.F) {
	f.Add([]byte(`{"request_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V","credential":"x"}`))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = RequestID(b) })
}
