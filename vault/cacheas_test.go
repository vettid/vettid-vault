package vault

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/envelope"
)

// cacheAsFeature answers with a secret and caches a public answer instead (Session.CacheResponseAs).
type cacheAsFeature struct{ calls int }

func (f *cacheAsFeature) Name() string { return "cacheasstub" }
func (f *cacheAsFeature) Types() []TypeSpec {
	return []TypeSpec{{Type: "test.secret", Request: true, From: []string{KindApp}},
		{Type: "test.secretheld", Request: true, From: []string{KindApp, KindDesktop}, DesktopApproval: true}}
}
func (f *cacheAsFeature) Load(json.RawMessage) error     { return nil }
func (f *cacheAsFeature) Save() (json.RawMessage, error) { return nil, nil }
func (f *cacheAsFeature) Handle(_ context.Context, s *Session, _ *envelope.Inner) (json.RawMessage, error) {
	f.calls++
	s.CacheResponseAs(json.RawMessage(`{"v":"public"}`))
	return json.RawMessage(`{"v":"SECRET-TURN-CREDENTIAL"}`), nil
}

// §8.2 with §10.10 (0.90.15): an answer a handler caches as another body is sent once as it is; the vault's state
// (the response cache, and the state as a flush writes it) holds only the cached body, and a retransmission is
// answered with it without running the handler again.
func TestResponseCachedAsAnotherBody(t *testing.T) {
	d := newDevFixture(t)
	f := &cacheAsFeature{}
	d.m.addFeature(f)
	app := d.self()
	id := d.sendAs(app, "test.secret", `{}`)
	r := find(d.inbox(app)["dev1"], reply(id))
	if r == nil || r.Status != envelope.StatusOK || !strings.Contains(string(r.Body), "SECRET") {
		t.Fatalf("first answer: %+v", r)
	}
	c, ok := d.m.st.Responses["dev1|"+id]
	if !ok || strings.Contains(string(c.Inner), "SECRET") || !strings.Contains(string(c.Inner), "public") {
		t.Fatalf("cached: %s", c.Inner)
	}
	if st, err := json.Marshal(d.m.st); err != nil || strings.Contains(string(st), "SECRET") {
		t.Fatalf("the state holds the secret: %v", err)
	}
	d.sendID(app, id, "test.secret", `{}`)
	again := find(d.inbox(app)["dev1"], reply(id))
	if again == nil || string(again.Body) != `{"v":"public"}` || again.ID != r.ID || f.calls != 1 {
		t.Fatalf("retransmission: %+v (calls %d)", again, f.calls)
	}
}

// §10.10 (0.90.15): a message to a device is sealed when queued and never held unsealed in the outbox, even if the
// device's current epoch were demoted (links demote connections' epochs only): it is then not sent at all.
func TestDeviceMessagesNeverHeldUnsealed(t *testing.T) {
	d := newDevFixture(t)
	p := d.m.st.Devices[d.devPeer.ID]
	if p == nil || p.Kind == KindConnection {
		t.Fatal("no device peer")
	}
	// One message queued (sealed) before the demotion: rehold must leave it sealed.
	d.m.mu.Lock()
	d.m.sealAndQueue(p, &envelope.Inner{ID: "01JB2Z6V9K3M4N5P6Q7R8S9T31", Type: "call.offer", TS: time.Now(),
		Body: json.RawMessage(`{"ice_config":"SECRET-TURN-CREDENTIAL-2"}`)})
	d.m.mu.Unlock()
	sealed := 0
	for _, o := range d.m.st.Outbox {
		if o.PeerID == p.ID && !o.Done && len(o.Payload) > 0 {
			sealed++
		}
	}
	if sealed == 0 {
		t.Fatal("nothing sealed in the outbox to hold back")
	}
	id := d.m.sessions[p.ID].Current().ID()
	if e := p.epochMeta(id[:]); e != nil {
		e.Demoted = true
	} else {
		p.Epochs = append(p.Epochs, EpochMeta{ID: append([]byte(nil), id[:]...), Demoted: true})
	}
	d.m.mu.Lock()
	d.m.sealAndQueue(p, &envelope.Inner{ID: "01JB2Z6V9K3M4N5P6Q7R8S9T30", Type: "call.offer", TS: time.Now(),
		Body: json.RawMessage(`{"ice_config":"SECRET-TURN-CREDENTIAL"}`)})
	d.m.reholdAt(p, d.m.sessions[p.ID].Current(), false, time.Now())
	d.m.mu.Unlock()
	for _, o := range d.m.st.Outbox {
		if o.PeerID == p.ID && o.Held != nil {
			t.Fatalf("a device's message held unsealed: %s", o.Held)
		}
	}
	if st, _ := json.Marshal(d.m.st); strings.Contains(string(st), "SECRET") {
		t.Fatal("the state holds a device's message in the clear")
	}
}

// A request held for an app's approval (a desktop's step-up) and then run caches its answer as the handler named it
// too: the held path keeps no secret either.
func TestHeldResponseCachedAsAnotherBody(t *testing.T) {
	f := newOCFixture(t)
	st := &cacheAsFeature{}
	f.m.addFeature(st)
	id := f.sendAs(f.desk, "test.secretheld", `{}`)
	ap := find(f.inbox(f.app, f.desk)["dev1"], ofType("approval.pending"))
	if ap == nil || st.calls != 0 {
		t.Fatal("not held")
	}
	f.sendAs(f.app, "approval.decide", `{"approval_id":"`+bodyStr(t, ap, "approval_id")+`","approve":true}`)
	r := find(f.inbox(f.app, f.desk)["desk1"], reply(id))
	if r == nil || r.Status != envelope.StatusOK || !strings.Contains(string(r.Body), "SECRET") || st.calls != 1 {
		t.Fatalf("approved: %+v", r)
	}
	for k, c := range f.m.st.Responses {
		if strings.HasSuffix(k, "|"+id) && (strings.Contains(string(c.Inner), "SECRET") || !strings.Contains(string(c.Inner), "public")) {
			t.Fatalf("held answer cached as: %s", c.Inner)
		}
	}
	if !f.cached(id) {
		t.Fatal("held answer not cached")
	}
}
