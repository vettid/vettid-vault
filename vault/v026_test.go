package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"

	"github.com/vettid/vettid-vault/vms/envelope"
)

// VAULT-MESSAGING 0.26.0 (§11.10.8, "Feature allowlist"): what the vault
// core does about an optional feature the image does not register. The
// per-feature tests with the real features are in e2e (allowlist_test.go)
// and features/all.

// namedFeature is a feature with a given name, one request type and a
// state entry.
type namedFeature struct {
	recSink
	name  string
	typ   string
	state json.RawMessage
	loads []string
}

func (n *namedFeature) Name() string { return n.name }
func (n *namedFeature) Types() []TypeSpec {
	if n.typ == "" {
		return nil
	}
	return []TypeSpec{{Type: n.typ, From: []string{KindApp, KindConnection}, Request: true}}
}
func (n *namedFeature) Load(raw json.RawMessage) error {
	n.loads = append(n.loads, string(raw))
	return nil
}
func (n *namedFeature) Save() (json.RawMessage, error) { return n.state, nil }
func (n *namedFeature) Handle(context.Context, *Session, *envelope.Inner) (json.RawMessage, error) {
	return json.RawMessage(`{}`), nil
}

// asConnection adds a peer with a real epoch and makes it a connection
// holding a standing token of the vault's (its deposits are collected
// with that token's jti, §7.1).
func (d *devFixture) asConnection(t testing.TB, id string, seed byte) *tdev {
	t.Helper()
	td := d.addDevice(t, id, KindApp, seed)
	d.m.mu.Lock()
	p := d.m.st.Devices[id]
	delete(d.m.st.Devices, id)
	p.Kind = KindConnection
	d.m.st.Connections[id] = p
	d.m.st.Issued = append(d.m.st.Issued, IssuedToken{JTI: "standing-" + id, Kind: TokStanding, Sub: relayauth.EncodeKey(p.Relay.PK),
		PeerID: id, Exp: time.Now().Add(20 * 24 * time.Hour)})
	d.m.mu.Unlock()
	return td
}

// sendRaw sends a message of typ from td: a request, or with re a
// response. A connection's deposit carries its standing token's jti.
func (d *devFixture) sendRaw(t testing.TB, td *tdev, typ, re string) string {
	t.Helper()
	d.seq++
	id, _ := envelope.NewULID(time.Now())
	in := &envelope.Inner{ID: id, Type: typ, TS: time.Now(), Body: []byte(`{}`)}
	if re != "" {
		in.Re, in.Status = re, envelope.StatusOK
	}
	raw, err := td.ep.Seal(in)
	if err != nil {
		t.Fatal(err)
	}
	msg := Message{MsgID: fmt.Sprintf("raw%d", d.seq), Sender: relayauth.EncodeKey(td.peer.Relay.PK), Payload: raw}
	if td.peer.Kind == KindConnection {
		msg.JTI = "standing-" + td.peer.ID
	}
	if err := d.m.ProcessBatch(context.Background(), &fakeCollector{}, []Message{msg}); err != nil {
		t.Fatal(err)
	}
	return id
}

// §5.3, §11.10.8: a type no registered feature declares is an unknown
// type, with one answer for every principal: a message without `re` is
// answered with `error` code unsupported_type, to an app and to a
// connection alike, and a response of such a type is dropped. A feature
// that is not registered contributes no type, so this is what each of its
// types meets; once it is registered the type is answered.
func TestUnregisteredTypeIsUnknown(t *testing.T) {
	d := newDevFixture(t)
	app := d.self()
	conn := d.asConnection(t, "c1", 0x70)
	const typ = "presence.ping" // a type of an optional feature this vault does not register
	if d.m.hasFeature("presence") || d.m.registry[typ] != nil {
		t.Fatal("the fixture registers presence")
	}
	for _, td := range []*tdev{app, conn} {
		id := d.sendRaw(t, td, typ, "")
		in := d.inbox(td)[td.peer.ID]
		r := find(in, reply(id))
		if len(in) != 1 || r == nil || r.Status != envelope.StatusError || errCode(r) != "unsupported_type" {
			t.Fatalf("%s: %s answered %d: %+v", td.peer.Kind, typ, len(in), r)
		}
		// A response of the type is dropped: no answer, no error.
		d.sendRaw(t, td, typ, id)
		if in := d.inbox(td)[td.peer.ID]; len(in) != 0 {
			t.Fatalf("%s: a response of %s was answered: %+v", td.peer.Kind, typ, in)
		}
	}
	// The same vault with the feature: the type is answered.
	d.m.addFeature(&namedFeature{name: "presence", typ: typ})
	for _, td := range []*tdev{app, conn} {
		id := d.sendRaw(t, td, typ, "")
		if r := find(d.inbox(td)[td.peer.ID], reply(id)); r == nil || r.Status != envelope.StatusOK {
			t.Fatalf("%s: %s with the feature: %+v", td.peer.Kind, typ, r)
		}
	}
}

// §11.10.8: without leash, device.pair.create{role:"agent"} is answered
// bad_request, as an unknown role is, and nothing is created; with it the
// pairing is created. A desktop pairing is a core operation and stays
// answered in both.
func TestPairCreateAgentNeedsLeash(t *testing.T) {
	d := newDevFixture(t)
	r, _ := d.request(t, "device.pair.create", `{"role":"agent"}`)
	if errCode(r) != "bad_request" || len(d.m.st.Invites) != 0 {
		t.Fatalf("agent pairing without leash: %+v, %d invites", r, len(d.m.st.Invites))
	}
	if u, _ := d.request(t, "device.pair.create", `{"role":"robot"}`); errCode(u) != errCode(r) {
		t.Fatalf("an unknown role is answered %q, an agent without leash %q", errCode(u), errCode(r))
	}
	if r, _ := d.request(t, "device.pair.create", `{"role":"desktop"}`); r.Status != envelope.StatusOK || len(d.m.st.Invites) != 1 {
		t.Fatalf("desktop pairing without leash: %+v", r)
	}
	d.m.addFeature(&namedFeature{name: "leash"})
	if r, _ := d.request(t, "device.pair.create", `{"role":"agent"}`); r.Status != envelope.StatusOK || len(d.m.st.Invites) != 2 {
		t.Fatalf("agent pairing with leash: %+v", r)
	}
}

// §11.10.8: without location, settings.set of a location.history.* member
// is answered bad_request and changes nothing, whatever else the request
// sets; settings.get is unchanged (it still reports the defaults). With
// location the members are set as before.
func TestLocationHistorySettingsNeedLocation(t *testing.T) {
	d := newDevFixture(t)
	get, _ := d.request(t, "settings.get", `{}`)
	for _, k := range []string{`"location.history.enabled":false`, `"location.history.interval_seconds":`, `"location.history.retention_days":`} {
		if !strings.Contains(string(get.Body), k) {
			t.Fatalf("settings.get without location lacks %s: %s", k, get.Body)
		}
	}
	for _, set := range []string{`"location.history.enabled":true`, `"location.history.retention_days":7`, `"location.history.interval_seconds":120`,
		`"app.theme":"dark","location.history.enabled":true`, `"location.history.unknown":1`} {
		r, _ := d.request(t, "settings.set", `{"version":0,"set":{`+set+`}}`)
		if errCode(r) != "bad_request" {
			t.Fatalf("settings.set{%s} without location: %+v", set, r)
		}
	}
	if s := d.m.st.Settings; s.Version != 0 || s.LocationHistory || s.LocationHistoryDays != 0 || s.LocationHistorySeconds != 0 || len(s.App) != 0 {
		t.Fatalf("a refused settings.set changed the settings: %+v", s)
	}
	// Other settings are unaffected.
	if r, _ := d.request(t, "settings.set", `{"version":0,"set":{"app.theme":"dark"}}`); r.Status != envelope.StatusOK {
		t.Fatalf("settings.set without location: %+v", r)
	}
	again, _ := d.request(t, "settings.get", `{}`)
	if !strings.Contains(string(again.Body), `"location.history.enabled":false`) {
		t.Fatalf("settings.get changed: %s", again.Body)
	}
	d.m.addFeature(&namedFeature{name: "location"})
	r, _ := d.request(t, "settings.set", `{"version":1,"set":{"location.history.enabled":true,"location.history.retention_days":7,"location.history.interval_seconds":120}}`)
	if r.Status != envelope.StatusOK || !d.m.st.Settings.LocationHistory || d.m.st.Settings.LocationHistoryDays != 7 {
		t.Fatalf("settings.set with location: %+v %+v", r, d.m.st.Settings)
	}
}

// featureEntry returns a copy of the state.s features.<name> entry as the
// unlock loaded it from the stored state.
func featureEntry(t *testing.T, m *Manager, name string) (json.RawMessage, bool) {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	raw, ok := m.st.Features[name]
	return append(json.RawMessage(nil), raw...), ok
}

// §11.10.8 ("Never off"): an image that meets a features.<name> entry of
// a feature it does not register carries the entry unchanged through
// every load, flush, lock and unlock, and never reads, migrates or
// deletes it; an image that registers no such feature creates no entry;
// and a vault that later runs an image with the feature gets its entry
// from that feature (it starts empty, as in a new vault).
func TestUnregisteredFeatureStateCarried(t *testing.T) {
	f := newFixture(t)
	// An entry with content an image could be tempted to normalize: key
	// order, an unknown version, characters JSON may escape, numbers.
	entry := json.RawMessage(`{"v":99,"zeta":[3,2,1],"alpha":{"k":"<&>é \"q\"","n":1.50,"big":18446744073709551615},"empty":{}}`)
	f.m.mu.Lock()
	f.m.st.Features["wallet"] = append(json.RawMessage(nil), entry...)
	f.m.mu.Unlock()
	if err := f.m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	stored := func() json.RawMessage {
		t.Helper()
		// A vault that registers a feature of another name; its Load must
		// never be given the wallet entry.
		other := &namedFeature{name: "presence"}
		o := f.opts
		o.Features = []Feature{other}
		m, _, err := Unlock(context.Background(), UnlockParams{Options: o, VaultID: f.vid, PIN: testPIN, UnlockSecret: testSecret})
		if err != nil {
			t.Fatal(err)
		}
		for _, l := range other.loads {
			if strings.Contains(l, "zeta") {
				t.Fatal("an unregistered feature's entry was read by another feature")
			}
		}
		raw, ok := featureEntry(t, m, "wallet")
		if !ok {
			t.Fatal("the entry of an unregistered feature was deleted")
		}
		if _, ok := featureEntry(t, m, "presence"); ok {
			t.Fatal("a feature without state got an entry")
		}
		// A flush in between (the state is rewritten), then the lock's.
		m.mu.Lock()
		err = m.persist(context.Background(), false)
		m.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		if err := m.Lock(context.Background()); err != nil {
			t.Fatal(err)
		}
		return raw
	}
	first := stored()
	for i := 0; i < 3; i++ {
		if got := stored(); !bytes.Equal(got, first) {
			t.Fatalf("round %d: the entry changed:\n%s\n%s", i, first, got)
		}
	}
	// What was carried is the entry as the feature's own image wrote it:
	// the same JSON value, member for member.
	var a, b any
	if json.Unmarshal(entry, &a) != nil || json.Unmarshal(first, &b) != nil || fmt.Sprint(a) != fmt.Sprint(b) {
		t.Fatalf("the carried entry is another value:\n%s\n%s", entry, first)
	}
	// No entry is created for a feature the image does not register, and
	// a later image with the feature loads nothing and writes its entry.
	g := newFixture(t)
	if err := g.m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	m, _, err := g.unlock(testPIN, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if n := m.FeatureEntries(); len(n) != 0 {
		t.Fatalf("entries without features: %v", n)
	}
	if err := m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	pres := &namedFeature{name: "presence", state: json.RawMessage(`{"v":1}`)}
	o := g.opts
	o.Features = []Feature{pres}
	m, _, err = Unlock(context.Background(), UnlockParams{Options: o, VaultID: g.vid, PIN: testPIN, UnlockSecret: testSecret})
	if err != nil {
		t.Fatal(err)
	}
	if len(pres.loads) != 0 {
		t.Fatalf("a feature turned on later was given state: %v", pres.loads)
	}
	if err := m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	if m, _, err = Unlock(context.Background(), UnlockParams{Options: g.opts, VaultID: g.vid, PIN: testPIN, UnlockSecret: testSecret}); err != nil {
		t.Fatal(err)
	}
	if raw, ok := featureEntry(t, m, "presence"); !ok || string(raw) != `{"v":1}` {
		t.Fatalf("the feature's entry after its first flush: %s %v", raw, ok)
	}
}
