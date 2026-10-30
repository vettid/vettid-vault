package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/peerwire"
)

// gateStub registers types as a feature would and counts what it handles.
type gateStub struct {
	specs []TypeSpec
	mu    sync.Mutex
	got   []string
}

func (g *gateStub) Name() string                   { return "gatestub" }
func (g *gateStub) Types() []TypeSpec              { return g.specs }
func (g *gateStub) Load(json.RawMessage) error     { return nil }
func (g *gateStub) Save() (json.RawMessage, error) { return nil, nil }
func (g *gateStub) Handle(_ context.Context, _ *Session, in *envelope.Inner) (json.RawMessage, error) {
	g.mu.Lock()
	g.got = append(g.got, in.Type)
	g.mu.Unlock()
	return json.RawMessage(`{}`), nil
}
func (g *gateStub) handled(typ string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, t := range g.got {
		if t == typ {
			return true
		}
	}
	return false
}

// Types a service may send, with the spec flags the real features carry.
var gateAllowed = []string{peerwire.TypeConnAuthChallenge, "connection.authenticate.withdraw", "profile.update", "vote.proposal"}

// Types that only a person connection or a device sends (a sample of §6.4's
// "everything else"), registered for connections.
var gateDisallowed = []string{"message.send", "message.receipt", "data.request", "location.requested", "intro.offer", "call.offer",
	"call.ice", "presence.ping", "action.invocation", "grant.value", "critical-secret.use", "leash.grant.updated"}

func gateFixture(t *testing.T) (*devFixture, *gateStub, *tdev, *tdev) {
	d := newDevFixture(t)
	st := &gateStub{}
	for _, typ := range gateAllowed {
		spec := TypeSpec{Type: typ, From: conns, Connections: PeersBoth}
		if strings.HasPrefix(typ, "vote.") {
			spec = TypeSpec{Type: typ, Request: true, From: conns, Connections: PeersService}
		}
		st.specs = append(st.specs, spec)
	}
	for _, typ := range gateDisallowed {
		st.specs = append(st.specs, TypeSpec{Type: typ, From: conns})
	}
	d.m.addFeature(st)
	sinkOf(d)
	svc := d.asConnection(t, "svc", 0x70)
	per := d.asConnection(t, "per", 0x74)
	d.m.st.Connections["svc"].PeerKind = "service"
	return d, st, svc, per
}

func challengeBody(t *testing.T, purpose string) string {
	t.Helper()
	id, _ := envelope.NewULID(time.Now())
	wc, err := peerwire.NewConnAuthChallenge(id, "")
	if err != nil {
		t.Fatal(err)
	}
	b := string(wc.Marshal())
	if purpose != "" {
		b = strings.TrimSuffix(b, "}") + `,"purpose":"` + purpose + `"}`
	}
	return b
}

// sendC sends a message from a connection with its standing token's jti.
func sendC(d *devFixture, td *tdev, typ, body string) string {
	d.seq++
	id, _ := envelope.NewULID(time.Now())
	raw, err := td.ep.Seal(&envelope.Inner{ID: id, Type: typ, TS: time.Now(), Body: []byte(body)})
	if err != nil {
		panic(err)
	}
	msg := Message{MsgID: fmt.Sprintf("g%d", d.seq), Sender: relayauth.EncodeKey(td.peer.Relay.PK), JTI: "standing-" + td.peer.ID, Payload: raw}
	_ = d.m.ProcessBatch(context.Background(), &fakeCollector{}, []Message{msg})
	return id
}

// answers are what the vault sent td besides its own token upkeep.
func answers(d *devFixture, td *tdev) []*envelope.Inner {
	var out []*envelope.Inner
	for _, in := range d.inbox(td)[td.peer.ID] {
		if in.Type != "relay.token.issued" {
			out = append(out, in)
		}
	}
	return out
}

func dropped(d *devFixture, kind string) []Activity { return d.audits(kind) }

func TestServiceInboundAllowed(t *testing.T) {
	d, st, svc, _ := gateFixture(t)
	for _, c := range []struct{ typ, body string }{
		{peerwire.TypeConnAuthChallenge, challengeBody(t, "signin")},
		{peerwire.TypeConnAuthChallenge, challengeBody(t, "approval")},
		{"connection.authenticate.withdraw", `{}`},
		{"profile.update", `{}`},
		{"relay.token.issued", `{}`},
		{"relay.address.update", `{}`},
		{"connection.approved", `{}`},
	} {
		sendC(d, svc, c.typ, c.body)
		if got := dropped(d, "drop.service_type"); len(got) != 0 {
			t.Fatalf("%s dropped: %+v", c.typ, got)
		}
	}
	for _, typ := range []string{peerwire.TypeConnAuthChallenge, "connection.authenticate.withdraw", "profile.update"} {
		if !st.handled(typ) {
			t.Fatalf("%s not handled", typ)
		}
	}
}

func TestServiceInboundDropped(t *testing.T) {
	d, st, svc, _ := gateFixture(t)
	n := 0
	types := append(append([]string{}, gateDisallowed...), "no.such.type", "vote.cast", "vote.status", "vote.other",
		"connection.update", "device.list", "settings.get", "relay.token.refresh.x")
	for _, typ := range types {
		sendC(d, svc, typ, `{}`)
		n++
		got := dropped(d, "drop.service_type")
		if len(got) != n || got[n-1].Ref != "svc "+typ || got[n-1].ConnectionID != "svc" || !got[n-1].Audit {
			t.Fatalf("%s: audit %+v", typ, got)
		}
		if st.handled(typ) {
			t.Fatalf("%s handled", typ)
		}
	}
	if in := answers(d, svc); len(in) != 0 {
		t.Fatalf("sent back to the service: %d %s", len(in), in[0].Type)
	}
}

func TestServiceChallengePurpose(t *testing.T) {
	d, st, svc, _ := gateFixture(t)
	for _, p := range []string{"", "bogus"} {
		sendC(d, svc, peerwire.TypeConnAuthChallenge, challengeBody(t, p))
	}
	sendC(d, svc, peerwire.TypeConnAuthChallenge, `{"request_id":"x"}`)
	if got := dropped(d, "drop.service_type"); len(got) != 3 || st.handled(peerwire.TypeConnAuthChallenge) {
		t.Fatalf("audits %+v, handled %v", got, st.got)
	}
	if in := answers(d, svc); len(in) != 0 {
		t.Fatalf("sent back: %d %s", len(in), in[0].Type)
	}
}

// §6.4 0.81.0: a vault without the feature answers a service's three vote
// requests unsupported_type and audits drop.service_type.
func TestServiceVoteWithoutFeature(t *testing.T) {
	d := newDevFixture(t)
	sinkOf(d)
	svc := d.asConnection(t, "svc", 0x70)
	d.m.st.Connections["svc"].PeerKind = "service"
	for i, typ := range []string{"vote.proposal", "vote.extended", "vote.closed"} {
		id := sendC(d, svc, typ, `{}`)
		r := find(d.inbox(svc)["svc"], reply(id))
		if r == nil || errCode(r) != "unsupported_type" {
			t.Fatalf("%s: %+v", typ, r)
		}
		if got := dropped(d, "drop.service_type"); len(got) != i+1 || got[i].Ref != "svc "+typ {
			t.Fatalf("%s audit %+v", typ, got)
		}
	}
	// Any other vote.* is dropped silently.
	sendC(d, svc, "vote.cast", `{}`)
	if in := d.inbox(svc)["svc"]; len(in) != 0 {
		t.Fatalf("answered: %+v", in)
	}
	if len(dropped(d, "drop.service_type")) != 4 {
		t.Fatal("vote.cast not audited")
	}
}

// With a registered service-only vote type (the feature), a service's vote
// is handled and a person's is not.
func TestVoteTypesServiceOnly(t *testing.T) {
	d, st, svc, per := gateFixture(t)
	sendC(d, svc, "vote.proposal", `{}`)
	if !st.handled("vote.proposal") || len(dropped(d, "drop.service_type")) != 0 {
		t.Fatal("service vote not handled")
	}
	for _, typ := range []string{"vote.proposal", "vote.cast", "vote.nonsense"} {
		id := sendC(d, per, typ, `{}`)
		r := find(d.inbox(per)["per"], reply(id))
		if r == nil || errCode(r) != "unsupported_type" {
			t.Fatalf("%s: %+v", typ, r)
		}
	}
	got := dropped(d, "drop.vote_not_service")
	if len(got) != 3 || got[0].Ref != "per" || got[0].ConnectionID != "per" {
		t.Fatalf("audit %+v", got)
	}
	if len(st.got) != 1 {
		t.Fatalf("handled %v", st.got)
	}
}

// Person connections are unchanged: the types a service may not send are
// handled, the unknown one is answered unsupported_type.
func TestPersonConnectionUnchanged(t *testing.T) {
	d, st, _, per := gateFixture(t)
	for _, typ := range append(append([]string{}, gateDisallowed...), "profile.update", peerwire.TypeConnAuthChallenge) {
		body := `{}`
		if typ == peerwire.TypeConnAuthChallenge {
			body = challengeBody(t, "")
		}
		sendC(d, per, typ, body)
		if !st.handled(typ) {
			t.Fatalf("%s not handled for a person", typ)
		}
	}
	id := sendC(d, per, "no.such.type", `{}`)
	if r := find(d.inbox(per)["per"], reply(id)); r == nil || errCode(r) != "unsupported_type" {
		t.Fatalf("unknown type: %+v", r)
	}
	if len(dropped(d, "drop.service_type"))+len(dropped(d, "drop.vote_not_service")) != 0 {
		t.Fatal("a person connection audited as a service")
	}
}

func TestServiceDeviceRequestsForbidden(t *testing.T) {
	d := newDevFixture(t)
	sinkOf(d)
	st := &gateStub{}
	for typ := range serviceForbidden {
		st.specs = append(st.specs, TypeSpec{Type: typ, Request: true, From: owners})
	}
	st.specs = append(st.specs, TypeSpec{Type: "message.attachment.get", Request: true, From: owners})
	d.m.addFeature(st)
	app := d.self()
	svc := d.asConnection(t, "svc", 0x70)
	d.asConnection(t, "per", 0x74)
	d.m.st.Connections["svc"].PeerKind = "service"
	bodies := []string{`{"connection_id":"svc"}`, `{"subject":{"connection_id":"svc"}}`, `{"a":"svc","c":"per"}`, `{"a":"per","c":"svc"}`}
	types := []string{"message.attachment.get"}
	for typ := range serviceForbidden {
		types = append(types, typ)
	}
	for _, typ := range types {
		for _, b := range bodies {
			id := d.sendAs(app, typ, b)
			r := find(d.inbox(app)["dev1"], reply(id))
			if r == nil || errCode(r) != "forbidden" {
				t.Fatalf("%s %s: %+v", typ, b, r)
			}
		}
		// A person connection (and a missing one) is the handler's business.
		for _, b := range []string{`{"connection_id":"per"}`, `{"subject":{"connection_id":"per"}}`, `{"a":"per","c":"none"}`} {
			id := d.sendAs(app, typ, b)
			if r := find(d.inbox(app)["dev1"], reply(id)); r == nil || r.Status != envelope.StatusOK {
				t.Fatalf("%s %s: %+v", typ, b, r)
			}
		}
	}
	if len(st.got) != len(types)*3 {
		t.Fatalf("handled %d, want %d", len(st.got), len(types)*3)
	}
	if in := d.inbox(svc)["svc"]; len(in) != 0 {
		t.Fatalf("a forbidden request sent: %+v", in)
	}
}

// Every automatic sender goes through sendWith: nothing but the allowed
// types reaches a service, whoever sends it; a person gets all of them.
func TestNoAutomaticSenderReachesService(t *testing.T) {
	d := newDevFixture(t)
	svc := d.asConnection(t, "svc", 0x70)
	per := d.asConnection(t, "per", 0x74)
	d.m.st.Connections["svc"].PeerKind = "service"
	auto := []string{"action.offered", "action.invocation", "action.result", "presence.ping", "presence.pong", "presence.result",
		"message.receipt", "message.deliver", "message.attachment.deliver", "message.attachment.status",
		"location.shared", "location.update", "location.stopped", "location.snapshot", "location.requested",
		"data.request", "data.decided", "data.shared", "data.revoked", "data.fetch", "data.value", "data.catalog.get", "data.catalog",
		"intro.offer", "intro.invite", "intro.link", "intro.connect", "intro.answer", "intro.closed",
		"call.offer", "call.answer", "call.end", "call.ice", "call.ringing",
		"critical-secret.use", "critical-secret.result", "connection.authenticate.challenge", "connection.authenticate.withdraw",
		"grant.value", "grant.catalog.result", "push.token.needed", "vault.held"}
	allowed := []string{"profile.update", "connection.authenticate.response", "connection.authenticate.rotated", "relay.token.issued",
		"relay.token.refresh", "relay.address.update", "identity.rotate", "connection.removed", "vote.cast", "vote.status"}
	d.withLock(func(m *Manager) {
		for _, typ := range append(append([]string{}, auto...), allowed...) {
			m.sendTo(m.st.Connections["svc"], typ, json.RawMessage(`{}`), time.Now())
			m.sendWith(m.st.Connections["svc"], typ, json.RawMessage(`{}`), SendOptions{MemoryOnly: true}, time.Now())
			m.sendTo(m.st.Connections["per"], typ, json.RawMessage(`{}`), time.Now())
		}
		m.drainOutbox(context.Background())
	})
	in := d.inbox(svc, per)
	seen := map[string]bool{}
	for _, e := range in["svc"] {
		seen[e.Type] = true
	}
	for _, typ := range auto {
		if seen[typ] {
			t.Fatalf("%s sent to a service", typ)
		}
	}
	for _, typ := range allowed {
		if !seen[typ] {
			t.Fatalf("%s not sent to a service", typ)
		}
	}
	if len(in["per"]) < len(auto)+len(allowed) {
		t.Fatalf("a person got %d of %d", len(in["per"]), len(auto)+len(allowed))
	}
}
