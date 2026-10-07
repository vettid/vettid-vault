package vault

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"

	"github.com/vettid/vettid-vault/vault/store"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// recSink is a feature that only records activity.
type recSink struct{ got []Activity }

func (r *recSink) Name() string                          { return "rec" }
func (r *recSink) Types() []TypeSpec                     { return nil }
func (r *recSink) Load(json.RawMessage) error            { return nil }
func (r *recSink) Save() (json.RawMessage, error)        { return nil, nil }
func (r *recSink) RecordActivity(_ *Session, a Activity) { r.got = append(r.got, a) }
func (r *recSink) Handle(context.Context, *Session, *envelope.Inner) (json.RawMessage, error) {
	return nil, nil
}
func (r *recSink) has(kind string) bool {
	for _, a := range r.got {
		if a.Kind == kind {
			return true
		}
	}
	return false
}

func one(t *testing.T, d *devFixture) *envelope.Inner {
	t.Helper()
	rs := d.responses(t)
	if len(rs) != 1 {
		t.Fatalf("%d responses", len(rs))
	}
	return rs[0]
}

// §10.8 settings: defaults, versions, validation, roles, and the core flag.
func TestSettings(t *testing.T) {
	d := newDevFixture(t)
	_ = d.send("settings.get", []byte(`{}`))
	r := one(t, d)
	if !strings.Contains(string(r.Body), `"connections.auto_approve_in_person":false`) ||
		!strings.Contains(string(r.Body), `"credential.unlock_ttl_seconds":300`) || !strings.Contains(string(r.Body), `"version":0`) {
		t.Fatalf("defaults: %s", r.Body)
	}
	if !strings.Contains(string(r.Body), `"credential.backup":true`) {
		t.Fatalf("backup default: %s", r.Body)
	}
	_ = d.send("settings.set", []byte(`{"version":0,"set":{"connections.auto_approve_in_person":true,"app.theme":"dark","feed.retention_days":7}}`))
	if r := one(t, d); r.Status != envelope.StatusOK || string(r.Body) != `{"version":1}` {
		t.Fatalf("set: %+v", r)
	}
	if !d.m.st.Settings.AutoApproveInPerson || d.m.st.Settings.App["app.theme"] != "dark" {
		t.Fatal("settings not applied")
	}
	for body, code := range map[string]string{
		`{"version":0,"set":{"app.theme":"light"}}`:               "conflict",
		`{"version":1,"set":{"unknown.key":true}}`:                "bad_request",
		`{"version":1,"set":{"credential.unlock_ttl_seconds":5}}`: "bad_request",
		`{"version":1,"set":{}}`:                                  "bad_request",
		`{"version":1,"set":{"app.x":1}}`:                         "bad_request",
		`{"version":1,"set":{"audit.retention_days":30}}`:         "bad_request", // fixed retention (§10.9)
	} {
		_ = d.send("settings.set", []byte(body))
		if r := one(t, d); r.Error == nil || r.Error.Code != code {
			t.Errorf("%s: %+v", body, r.Error)
		}
	}
	_ = d.send("settings.set", []byte(`{"version":1,"set":{"app.theme":null}}`))
	if r := one(t, d); r.Status != envelope.StatusOK || d.m.st.Settings.App["app.theme"] != "" {
		t.Fatal("app key not removed")
	}
	d.devPeer.Kind = KindAgent
	_ = d.send("settings.get", []byte(`{}`))
	if r := one(t, d); r.Error == nil || r.Error.Code != "forbidden" {
		t.Fatal("agent read settings")
	}
}

// Activity reaches ActivitySink features: runtime drops (drop.*), unlock
// and identity rotation (§10.9).
func TestActivitySinks(t *testing.T) {
	d := newDevFixture(t)
	s := &recSink{}
	d.m.addFeature(s)
	_ = d.send("connection.removed", []byte(`{}`)) // not allowed from a device
	if !s.has("drop.forbidden_type") {
		t.Fatalf("drop not recorded: %+v", s.got)
	}
	if err := d.m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !s.has("vault.unlocked") {
		t.Fatal("unlock not recorded")
	}
	if err := d.m.RotateIdentity(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !s.has("identity.rotated") {
		t.Fatal("rotation not recorded")
	}
	for _, a := range s.got {
		if !a.Audit && !a.Feed {
			t.Fatalf("activity for nobody: %+v", a)
		}
	}
}

func FuzzApplySettings(f *testing.F) {
	f.Add([]byte(`{"version":0,"set":{"connections.auto_approve_in_person":true,"app.a":"b","credential.backup":false}}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		s, err := ApplySettings(Settings{}, b)
		if err != nil {
			return
		}
		if s.Version != 1 || len(s.App) > MaxAppSettings {
			t.Fatal("invalid settings accepted")
		}
		if s.CredentialUnlockTTL != 0 && (s.CredentialUnlockTTL < 30 || s.CredentialUnlockTTL > 3600) {
			t.Fatal("ttl out of range")
		}
	})
}

type namer struct{ recSink }

func (namer) DisplayName() string { return "Bo" }

// §6.2, §6.4 (0.18.0): a vault's hs.init profile carries the account's
// names and its display name, if any; none without the names.
func TestHandshakeProfile(t *testing.T) {
	d := newDevFixture(t)
	d.m.st.Account = nil
	if p, ok := d.m.handshakeProfile(); ok || p != nil {
		t.Fatal("profile without the account's names")
	}
	d.m.applyAccount(snapshotNamed(time.Now(), "Ada", "King", `{"allowed_after":null,"last":null}`, ""), time.Now())
	if p, ok := d.m.handshakeProfile(); !ok || string(p) != `{"first_name":"Ada","last_name":"King"}` {
		t.Fatalf("hs.init profile %s", p)
	}
	d.m.addFeature(&namer{})
	if p, _ := d.m.handshakeProfile(); string(p) != `{"first_name":"Ada","last_name":"King","name":"Bo"}` {
		t.Fatalf("hs.init profile %s", p)
	}
	inv, _, err := d.m.createInvite(context.Background(), KindConnection, 10*time.Minute, "dev1", time.Now())
	if err != nil || inv == nil {
		t.Fatal(err)
	}
	if truncateUTF8("aé", 2) != "a" {
		t.Fatal("truncateUTF8 split a character")
	}
}

// secretFeature answers a volatile request with a secret value.
type secretFeature struct {
	recSink
	calls int
}

func (s *secretFeature) Types() []TypeSpec {
	return []TypeSpec{{Type: "test.secret", Request: true, Volatile: true, From: []string{KindApp}}}
}
func (s *secretFeature) Handle(context.Context, *Session, *envelope.Inner) (json.RawMessage, error) {
	s.calls++
	return json.RawMessage(`{"value":"TOPSECRETVALUE"}`), nil
}

// §8.2, §3.5.3: a response carrying a secret value is never cached or
// written to vault state, and a retransmission is executed again.
func TestVolatileResponses(t *testing.T) {
	d := newDevFixture(t)
	f := &secretFeature{}
	d.m.addFeature(f)
	id, _ := envelope.NewULID(time.Now())
	for i := 0; i < 2; i++ {
		raw, _ := d.ep.Seal(&envelope.Inner{ID: id, Type: "test.secret", TS: time.Now(), Body: []byte(`{}`)})
		msg := Message{MsgID: "v" + string(rune('0'+i)), Sender: relayauth.EncodeKey(d.devPeer.Relay.PK), Payload: raw}
		if err := d.m.ProcessBatch(context.Background(), &fakeCollector{}, []Message{msg}); err != nil {
			t.Fatal(err)
		}
		rs := d.responses(t)
		if len(rs) != 1 || !strings.Contains(string(rs[0].Body), "TOPSECRETVALUE") || rs[0].Re != id {
			t.Fatalf("attempt %d: %+v", i, rs)
		}
		for k := range d.m.st.Responses {
			if strings.HasSuffix(k, id) {
				t.Fatal("volatile response cached")
			}
		}
		if len(d.m.st.Outbox) != 0 || len(d.m.volatile) != 0 {
			t.Fatal("volatile response in the outbox")
		}
	}
	if f.calls != 2 {
		t.Fatalf("retransmission not executed again: %d", f.calls)
	}
	// Nothing of it in the stored state object.
	blob, _, err := d.store.Get(context.Background(), store.StateKey(d.m.st.VaultID))
	if err != nil {
		t.Fatal(err)
	}
	pt, _, err := decryptState(d.m.dek, d.m.st.VaultID, blob)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(pt), "TOPSECRETVALUE") {
		t.Fatal("secret value in vault state")
	}
}

// gateFeature is a credential gate under test control.
type gateFeature struct {
	recSink
	ready bool
}

func (g *gateFeature) CredentialReady() bool  { return g.ready }
func (g *gateFeature) CredentialExists() bool { return g.ready }

// §3.5.7: a vault without a credential answers credential_required to all
// but the listed types, stays provisional, and records has_credential.
func TestCredentialGate(t *testing.T) {
	d := newDevFixture(t)
	g := &gateFeature{}
	d.m.addFeature(g)
	for _, typ := range []string{"vault.enroll.confirm", "device.pair.create", "connection.invite.create", "settings.get"} {
		_ = d.send(typ, []byte(`{}`))
		if r := one(t, d); r.Error == nil || r.Error.Code != "credential_required" {
			t.Fatalf("%s on a restricted vault: %+v", typ, r)
		}
	}
	_ = d.send("vault.status", []byte(`{}`))
	if r := one(t, d); r.Status != envelope.StatusOK {
		t.Fatal("vault.status refused")
	}
	if err := d.m.persist(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if d.m.hdr.HasCredential {
		t.Fatal("has_credential without a credential")
	}
	g.ready = true
	_ = d.send("settings.get", []byte(`{}`))
	if r := one(t, d); r.Status != envelope.StatusOK {
		t.Fatal("settings.get refused with a credential")
	}
	if !d.m.hdr.HasCredential {
		t.Fatal("has_credential not recorded")
	}
}
