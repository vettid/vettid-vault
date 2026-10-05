//go:build devenclave && e2e

package e2e

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/client"
	"github.com/vettid/vettid-vault/internal/relaytest"
)

// introWorld is B with two connections, A and C, that do not know each
// other.
type introWorld struct {
	a, b, c *testVault
	bA, bC  string // B's connection ids of A and C
	aB, cB  string // A's and C's connection ids of B
	cIK     string // C's vault ik (as B has it), base64
}

func newIntroWorld(t *testing.T) *introWorld {
	t.Helper()
	r := relaytest.Start(t, nil)
	w := &introWorld{a: newTestVault(t, r.URL, "a", nil), b: newTestVault(t, r.URL, "b", nil), c: newTestVault(t, r.URL, "c", nil)}
	w.bA, w.aB = connect(t, w.b, w.a, 600)
	w.bC, w.cB = connect(t, w.b, w.c, 600)
	g := mustOK(t, w.b.request(w.b.app, "connection.get", `{"connection_id":"`+w.bC+`"}`))
	w.cIK, _ = g.String("ik")
	return w
}

func (w *introWorld) create(t *testing.T) string {
	t.Helper()
	ctx := ctxT(t, 30*time.Second)
	id, err := w.b.app.IntroCreate(ctx, w.bA, w.bC, client.IntroPeer{Name: "Carol", Note: "my sister"}, client.IntroPeer{Name: "Alice"})
	if err != nil {
		t.Fatal(err)
	}
	pa := waitEvent(t, w.a.app, "intro.pending", has("intro_id", id))
	if field(t, pa.Body, "connection_id") != w.aB || !strings.Contains(string(pa.Body), `"name":"Carol"`) {
		t.Fatalf("A's offer: %s", pa.Body)
	}
	waitEvent(t, w.c.app, "intro.pending", has("intro_id", id))
	return id
}

// V4 batch 3, introductions (§10.15) through the real relay: B introduces
// A and C; both accept; A's vault makes an invitation bound to C's ik,
// relayed by B; C's vault accepts it; A's member approves the request
// (introduced_by B, with the SAS); A and C exchange a message.
func TestIntroductionAccepted(t *testing.T) {
	w := newIntroWorld(t)
	ctx := ctxT(t, 120*time.Second)
	id := w.create(t)
	if err := w.a.app.IntroAccept(ctx, id); err != nil {
		t.Fatal(err)
	}
	waitEvent(t, w.b.app, "intro.event", func(b json.RawMessage) bool {
		return has("event", "accepted")(b) && has("connection_id", w.bA)(b)
	})
	if err := w.c.app.IntroAccept(ctx, id); err != nil {
		t.Fatal(err)
	}
	waitEvent(t, w.b.app, "intro.event", has("event", "connecting"))
	pend := waitEvent(t, w.a.app, "connection.request.pending", has("introduced_by", w.aB))
	if sas := field(t, pend.Body, "sas"); len(sas) != 6 {
		t.Fatal("no SAS")
	}
	mustOK(t, w.a.request(w.a.app, "connection.approve", `{"pending_id":"`+field(t, pend.Body, "pending_id")+`"}`))
	// C's member approves C's outgoing request with the same SAS (0.10.2).
	out := waitEvent(t, w.c.app, "connection.request.outgoing", has("introduced_by", w.cB))
	if field(t, out.Body, "sas") != field(t, pend.Body, "sas") {
		t.Fatal("A and C see different codes")
	}
	mustOK(t, w.c.request(w.c.app, "connection.approve", `{"connection_id":"`+field(t, out.Body, "connection_id")+`"}`))
	notB := func(own string) func(json.RawMessage) bool {
		return func(b json.RawMessage) bool { return has("event", "added")(b) && !has("connection_id", own)(b) }
	}
	evA := waitEvent(t, w.a.app, "connection.event", notB(w.aB))
	evC := waitEvent(t, w.c.app, "connection.event", notB(w.cB))
	aC, cA := field(t, evA.Body, "connection_id"), field(t, evC.Body, "connection_id")
	mid := sendText(t, w.c, w.c.app, cA, "hello via Bob")
	waitEvent(t, w.a.app, "message.new", has("message_id", mid))
	g := mustOK(t, w.a.request(w.a.app, "connection.get", `{"connection_id":"`+aC+`"}`))
	if ik, _ := g.String("ik"); ik != w.cIK {
		t.Fatal("A connected to someone other than the C that B named")
	}
	waitEvent(t, w.a.app, "intro.event", has("event", "connecting"))
	au, err := w.b.app.AuditList(ctx, map[string]any{"kinds": []string{"intro"}}, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"intro.created", "intro.accepted", "intro.connecting"} {
		if !strings.Contains(string(au["entries"]), `"`+k+`"`) {
			t.Errorf("B's audit lacks %s", k)
		}
	}
}

// §10.15: C declines; A learns only that the introduction closed: no key,
// link or answer of C, and no connection.
func TestIntroductionDeclined(t *testing.T) {
	w := newIntroWorld(t)
	ctx := ctxT(t, 120*time.Second)
	id := w.create(t)
	if err := w.a.app.IntroAccept(ctx, id); err != nil {
		t.Fatal(err)
	}
	if err := w.c.app.IntroDecline(ctx, id); err != nil {
		t.Fatal(err)
	}
	waitEvent(t, w.b.app, "intro.event", has("event", "declined"))
	waitEvent(t, w.a.app, "intro.event", has("event", "closed"))
	for _, ev := range w.a.app.Events() {
		s := string(ev.Body)
		if strings.Contains(s, w.cIK) || strings.Contains(s, "link") || strings.Contains(s, "declin") ||
			ev.Type == "connection.request.pending" && strings.Contains(s, "introduced_by") {
			t.Fatalf("A learned something about C: %s %s", ev.Type, s)
		}
	}
	l, err := w.a.app.IntroList(ctx)
	if err != nil || !strings.Contains(string(l["received"]), `"state":"closed"`) {
		t.Fatalf("A's list: %v %s", err, l["received"])
	}
	cl := mustOK(t, w.a.request(w.a.app, "connection.list", `{}`))
	if n := strings.Count(string(cl["connections"]), `"kind":"connection"`); n != 1 {
		t.Fatalf("A has %d connections", n)
	}
}

// §10.15: a connection cannot see, list or ask for the member's other
// connections. A's member, through its own vault, can only name its own
// connections; there is no type to ask B; guessed ids lead nowhere; and
// nothing B's vault sends A names B's other connections.
func TestConnectionsCannotProbe(t *testing.T) {
	w := newIntroWorld(t)
	ctx := ctxT(t, 60*time.Second)
	// A names B's connection ids (which it does not know): not its own.
	if _, err := w.a.app.IntroCreate(ctx, w.bA, w.bC, client.IntroPeer{Name: "x"}, client.IntroPeer{Name: "y"}); client.Code(err) != "not_found" {
		t.Fatalf("intro.create with B's ids: %v", err)
	}
	// There is no request to be introduced: an unknown type.
	if rr := w.a.request(w.a.app, "intro.request", `{"connection_id":"`+w.aB+`"}`); rr.ErrorCode() != "unsupported_type" {
		t.Fatalf("intro.request: %q", rr.ErrorCode())
	}
	if err := w.a.app.IntroAccept(ctx, "01JB2Z6V9K3M4N5P6Q7R8S9T0V"); client.Code(err) != "not_found" {
		t.Fatalf("guessed intro id: %v", err)
	}
	l, err := w.a.app.IntroList(ctx)
	if err != nil || string(l["made"]) != "[]" || string(l["received"]) != "[]" {
		t.Fatalf("A's list: %v %s %s", err, l["made"], l["received"])
	}
	// Whatever B's vault sent A (profile, offers) names none of B's other
	// connections.
	for _, ev := range w.a.app.Events() {
		if s := string(ev.Body); strings.Contains(s, w.bC) || strings.Contains(s, w.cIK) {
			t.Fatalf("A saw B's other connection: %s %s", ev.Type, s)
		}
	}
}
