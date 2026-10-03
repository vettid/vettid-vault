package items_test

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/features/all"
	"github.com/vettid/vettid-vault/features/credential"
	"github.com/vettid/vettid-vault/internal/featuretest"
	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/credwire"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/sharewire"
	"github.com/vettid/vettid-vault/vms/suite"
)

func openGrant(k *suite.PrivateKey, grantID, fetchID string, sealed []byte) ([]byte, error) {
	return sharewire.OpenValue(k, grantID, fetchID, sealed)
}

const pw = "correct horse battery"

// env is one vault's whole feature set on a fake host: requests are
// dispatched to the feature that registers the type, with the runtime's
// sender-kind authorization (featuretest.Call).
type env struct {
	t     *testing.T
	set   *all.Set
	h     *featuretest.Host
	clk   featuretest.Clock
	owner map[string]vault.Feature
	utks  []utk
	blob  string
	reply *suite.PrivateKey
	lastI string
}

type utk struct {
	id string
	ek *suite.PublicKey
}

func newEnv(t *testing.T) *env {
	e := &env{t: t, set: all.NewSet(all.Options{CredentialKDF: credential.MinKDF}), h: featuretest.NewHost(),
		clk: featuretest.Clock{T: time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)}, owner: map[string]vault.Feature{}}
	for _, f := range e.set.List() {
		for _, ts := range f.Types() {
			e.owner[ts.Type] = f
		}
	}
	e.h.AddDevice("dev-app", vault.KindApp)
	e.h.AddDevice("dev-desktop", vault.KindDesktop)
	e.h.AddDevice("dev-agent", vault.KindAgent)
	e.h.AddConnection("cA")
	e.h.AddConnection("cB")
	return e
}

// call sends typ from a principal of kind ("app", "desktop", "agent",
// "connection:<id>").
func (e *env) call(kind, typ, body string) featuretest.Result {
	e.t.Helper()
	e.clk.Advance(time.Second)
	id, _ := envelope.NewULID(e.clk.T)
	e.lastI = id
	f := e.owner[typ]
	if f == nil {
		return featuretest.Result{Code: "unsupported_type"}
	}
	r := featuretest.CallID(f, e.h, e.clk.T, kind, typ, id, body)
	e.absorb(r)
	return r
}

func (e *env) ok(r featuretest.Result) strictjson.Object {
	e.t.Helper()
	if !r.OK() {
		e.t.Fatalf("error %s", r.Code)
	}
	return r.Obj(e.t)
}

func (e *env) code(r featuretest.Result, want string) {
	e.t.Helper()
	if r.Code != want {
		e.t.Fatalf("code %q, want %q", r.Code, want)
	}
}

func js(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// absorb keeps the UTKs and the latest blob a response carries.
func (e *env) absorb(r featuretest.Result) {
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
			e.t.Fatal(err)
		}
		e.utks = append(e.utks, utk{u.ID, ek})
	}
	if out.Credential != "" {
		e.blob = out.Credential
	}
}

func (e *env) take() utk {
	e.t.Helper()
	if len(e.utks) == 0 {
		e.ok(e.call("app", "credential.utk.get", `{}`))
	}
	u := e.utks[0]
	e.utks = e.utks[1:]
	return u
}

// sealed sends typ from kind with outer members and the payload sealed to
// a fresh UTK, with the current blob (unless blob is false); reply adds a
// one-time reply key (kept in e.reply).
func (e *env) sealed(kind, typ string, outer, payload map[string]any, blob, reply bool) featuretest.Result {
	e.t.Helper()
	return e.sealedUTK(kind, typ, outer, payload, blob, reply, e.take())
}

func (e *env) sealedUTK(kind, typ string, outer, payload map[string]any, blob, reply bool, u utk) featuretest.Result {
	e.t.Helper()
	if payload == nil {
		payload = map[string]any{}
	}
	if reply {
		k, _ := suite.GeneratePrivateKey()
		e.reply = k
		payload["reply_key"] = base64.StdEncoding.EncodeToString(k.Public().Bytes())
	}
	pt, _ := json.Marshal(payload)
	e.clk.Advance(time.Second)
	id, _ := envelope.NewULID(e.clk.T)
	e.lastI = id
	s, err := credwire.SealPayload(u.ek, e.h.VaultID(), u.id, typ, id, pt)
	if err != nil {
		e.t.Fatal(err)
	}
	body := map[string]any{}
	for k, v := range outer {
		body[k] = v
	}
	body["utk_id"], body["sealed"] = u.id, base64.StdEncoding.EncodeToString(s)
	if blob {
		body["credential"] = e.blob
	}
	r := featuretest.CallID(e.owner[typ], e.h, e.clk.T, kind, typ, id, js(body))
	e.absorb(r)
	return r
}

func (e *env) createCredential() {
	e.t.Helper()
	e.ok(e.sealed("app", "credential.create", nil, map[string]any{"password": pw}, false, false))
}

func (e *env) unlock() {
	e.t.Helper()
	e.ok(e.sealed("app", "credential.unlock", nil, map[string]any{"password": pw}, true, false))
}

type field struct {
	ID    string `json:"field_id,omitempty"`
	Label string `json:"label"`
	Kind  string `json:"kind"`
	Value any    `json:"value"`
}

// put creates a data or secret item and returns its id.
func (e *env) put(sens, name string, tags []string, fields ...field) string {
	e.t.Helper()
	body := map[string]any{"name": name, "sensitivity": sens}
	if tags != nil {
		body["tags"] = tags
	}
	if fields != nil {
		body["fields"] = fields
	}
	o := e.ok(e.call("app", "item.put", js(body)))
	id, _ := o.String("item_id")
	return id
}

// putCritical creates a critical item and returns its id.
func (e *env) putCritical(name string, tags []string, fields ...field) string {
	e.t.Helper()
	item := map[string]any{"name": name}
	if fields != nil {
		item["fields"] = fields
	}
	outer := map[string]any{"sensitivity": "critical"}
	if tags != nil {
		outer["tags"] = tags
	}
	o := e.ok(e.sealed("app", "item.put", outer, map[string]any{"password": pw, "item": item}, true, false))
	id, _ := o.String("item_id")
	return id
}

func (e *env) item(id string) strictjson.Object {
	e.t.Helper()
	return e.ok(e.call("app", "item.get", js(map[string]any{"item_id": id})))
}

func (e *env) version(id string) uint64 {
	e.t.Helper()
	v, _ := e.item(id).Uint("version", 1, 1<<53)
	return v
}

func (e *env) retag(id string, tags ...string) {
	e.t.Helper()
	if tags == nil {
		tags = []string{}
	}
	e.ok(e.call("app", "item.tag", js(map[string]any{"item_id": id, "version": e.version(id), "tags": tags})))
}

// rule creates a share rule and returns its id.
func (e *env) rule(body map[string]any) string {
	e.t.Helper()
	o := e.ok(e.call("app", "share.rule.set", js(body)))
	id, _ := o.String("rule_id")
	return id
}

func conn(id string) map[string]any { return map[string]any{"connection_id": id} }

// sentTo returns the messages of typ sent to a principal ("devices" for
// the owner's devices) since the last reset.
func (e *env) sentTo(to, typ string) []featuretest.Sent {
	var out []featuretest.Sent
	for _, s := range e.h.Sent {
		if s.Type == typ && (s.To == to || to == "devices" && strings.HasPrefix(s.To, "devices")) {
			out = append(out, s)
		}
	}
	return out
}

func obj(t *testing.T, b []byte) strictjson.Object {
	t.Helper()
	o, err := strictjson.ParseObject(b)
	if err != nil {
		t.Fatalf("%v: %s", err, b)
	}
	return o
}

func strs(t *testing.T, o strictjson.Object, k string) []string {
	t.Helper()
	var out []string
	if raw, ok := o[k]; ok {
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatal(err)
		}
	}
	return out
}

// grantsShared returns the grant ids in the data.shared messages to conn.
func (e *env) grantsShared(conn string) []string {
	var out []string
	for _, s := range e.sentTo(conn, "data.shared") {
		var b struct {
			Grants []struct {
				ID string `json:"grant_id"`
			} `json:"grants"`
		}
		if err := json.Unmarshal(s.Body, &b); err != nil {
			e.t.Fatal(err)
		}
		for _, g := range b.Grants {
			out = append(out, g.ID)
		}
	}
	return out
}

// fetch makes conn fetch a grant and returns the data.value it answers:
// the error, or the content opened with the reply key.
func (e *env) fetch(conn, grantID string) (string, []byte) {
	e.t.Helper()
	k, _ := suite.GeneratePrivateKey()
	defer k.Destroy()
	fid, _ := envelope.NewULID(e.clk.T)
	e.h.Reset()
	e.call("connection:"+conn, "data.fetch", js(map[string]any{"fetch_id": fid, "grant_id": grantID,
		"reply_key": base64.StdEncoding.EncodeToString(k.Public().Bytes())}))
	vs := e.sentTo(conn, "data.value")
	if len(vs) != 1 {
		e.t.Fatalf("data.value: %d", len(vs))
	}
	o := obj(e.t, vs[0].Body)
	if er, ok, _ := o.OptString("error"); ok {
		return er, nil
	}
	sv, err := o.Base64("value_sealed", -1)
	if err != nil {
		e.t.Fatal(err)
	}
	pt, err := openGrant(k, grantID, fid, sv)
	if err != nil {
		e.t.Fatal(err)
	}
	return "", pt
}
