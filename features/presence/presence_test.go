package presence

import (
	"strings"
	"testing"
	"time"

	ft "github.com/vettid/vettid-vault/internal/featuretest"
	"github.com/vettid/vettid-vault/internal/strictjson"
)

var t0 = time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)

func setup() (*Feature, *ft.Host) {
	h := ft.NewHost()
	h.AddConnection("c1")
	h.AddConnection("c2")
	h.AddDevice("dev-app", "app")
	h.AddDevice("dev-desktop", "desktop")
	return New(), h
}

func TestQueryPingPong(t *testing.T) {
	asker, ha := setup()
	r := ft.Call(asker, ha, t0, "app", "presence.query", `{"connection_id":"c1"}`)
	if !r.OK() {
		t.Fatal(r.Code)
	}
	pingID, _ := r.Obj(t).String("ping_id")
	pings := ha.SentOfType("presence.ping")
	if len(pings) != 1 || pings[0].To != "c1" || !pings[0].Opt.MemoryOnly || !pings[0].Opt.Exp.Equal(t0.Add(PingTTL)) {
		t.Fatalf("ping: %+v", pings)
	}
	// The peer answers.
	peer, hp := setup()
	hp.LastActive = t0.Add(-7 * time.Minute)
	ft.CallExp(peer, hp, t0, t0.Add(PingTTL), "connection:c1", "presence.ping", string(pings[0].Body))
	pongs := hp.SentOfType("presence.pong")
	if len(pongs) != 1 || !pongs[0].Opt.MemoryOnly {
		t.Fatalf("pong: %+v", pongs)
	}
	o, _ := strictjson.ParseObject(pongs[0].Body)
	if st, _ := o.String("state"); st != Available {
		t.Fatal(st)
	}
	if la, _ := o.String("last_active"); la != "2026-10-03T11:50:00.000Z" {
		t.Fatalf("last_active not rounded: %s", la)
	}
	// A second ping within the minute is not answered.
	hp.Reset()
	ft.CallExp(peer, hp, t0.Add(10*time.Second), t0.Add(time.Minute), "connection:c1", "presence.ping", `{"ping_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V"}`)
	if len(hp.SentOfType("presence.pong")) != 0 {
		t.Fatal("rate not enforced")
	}
	// The asker gets the result on the asking device.
	ft.CallExp(asker, ha, t0.Add(time.Second), t0.Add(PingTTL), "connection:c1", "presence.pong", string(pongs[0].Body))
	res := ha.SentOfType("presence.result")
	if len(res) != 1 || res[0].To != "dev-app" || !strings.Contains(string(res[0].Body), `"ping_id":"`+pingID+`"`) {
		t.Fatalf("result: %+v", res)
	}
	// A pong from another connection, or a repeat, is ignored.
	ha.Reset()
	ft.CallExp(asker, ha, t0.Add(time.Second), t0.Add(PingTTL), "connection:c2", "presence.pong", string(pongs[0].Body))
	ft.CallExp(asker, ha, t0.Add(time.Second), t0.Add(PingTTL), "connection:c1", "presence.pong", string(pongs[0].Body))
	if len(ha.SentOfType("presence.result")) != 0 {
		t.Fatal("foreign or repeated pong used")
	}
	// A query within the minute reuses the ping and re-sends the result.
	r2 := ft.Call(asker, ha, t0.Add(20*time.Second), "desktop", "presence.query", `{"connection_id":"c1"}`)
	if id, _ := r2.Obj(t).String("ping_id"); id != pingID || len(ha.SentOfType("presence.ping")) != 0 {
		t.Fatal("ping not reused")
	}
	if res := ha.SentOfType("presence.result"); len(res) != 1 || res[0].To != "dev-desktop" {
		t.Fatalf("result not re-sent: %+v", res)
	}
	// After the minute, a new ping.
	ha.Reset()
	ft.Call(asker, ha, t0.Add(61*time.Second), "app", "presence.query", `{"connection_id":"c1"}`)
	if len(ha.SentOfType("presence.ping")) != 1 {
		t.Fatal("no new ping")
	}
}

func TestPolicy(t *testing.T) {
	f, h := setup()
	r := ft.Call(f, h, t0, "app", "presence.get", `{}`)
	if string(r.Body) != `{"version":0,"state":"available","share":"all","except":[]}` {
		t.Fatalf("default: %s", r.Body)
	}
	if r := ft.Call(f, h, t0, "app", "presence.set", `{"version":1,"state":"busy"}`); r.Code != "conflict" {
		t.Fatal(r.Code)
	}
	if r := ft.Call(f, h, t0, "app", "presence.set", `{"version":0,"state":"busy","except":["c1","c1"]}`); !r.OK() {
		t.Fatal(r.Code)
	}
	if len(h.SentOfType("sync.event")) != 1 {
		t.Fatal("no sync event")
	}
	ping := func(conn string) int {
		h.Reset()
		ft.CallExp(f, h, t0, t0.Add(PingTTL), "connection:"+conn, "presence.ping", `{"ping_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V"}`)
		return len(h.SentOfType("presence.pong"))
	}
	if ping("c1") != 0 {
		t.Fatal("excepted connection answered")
	}
	if ping("c2") != 1 || !strings.Contains(string(h.Sent[0].Body), `"state":"busy"`) {
		t.Fatal("c2 not answered busy")
	}
	ft.Call(f, h, t0, "app", "presence.set", `{"version":1,"share":"none"}`)
	f.ponged = map[string]time.Time{}
	if ping("c1") != 1 || ping("c2") != 0 {
		t.Fatal("none + except")
	}
	ft.Call(f, h, t0, "app", "presence.set", `{"version":2,"share":"all","except":[],"state":"invisible"}`)
	f.ponged = map[string]time.Time{}
	if ping("c2") != 0 {
		t.Fatal("invisible answered")
	}
	g := New()
	ft.RoundTrip(t, f, g)
	if r := ft.Call(g, h, t0, "app", "presence.get", `{}`); !strings.Contains(string(r.Body), `"version":3`) {
		t.Fatalf("reload: %s", r.Body)
	}
	if r := ft.Call(f, h, t0, "app", "presence.set", `{"version":3,"state":"gone"}`); r.Code != "bad_request" {
		t.Fatal(r.Code)
	}
	ft.Call(f, h, t0, "app", "presence.set", `{"version":3,"except":["c1"]}`)
	f.ConnectionRemoved(nil, "c1")
	if len(f.policy.Except) != 0 {
		t.Fatal("removed connection kept")
	}
}

func TestQueryErrors(t *testing.T) {
	f, h := setup()
	if r := ft.Call(f, h, t0, "app", "presence.query", `{"connection_id":"cx"}`); r.Code != "not_found" {
		t.Fatal(r.Code)
	}
	h.DownConns["c2"] = true
	if r := ft.Call(f, h, t0, "app", "presence.query", `{"connection_id":"c2"}`); r.Code != "connection_unavailable" {
		t.Fatal(r.Code)
	}
	if r := ft.Call(f, h, t0, "agent", "presence.query", `{"connection_id":"c1"}`); r.Code != "forbidden" {
		t.Fatal(r.Code)
	}
	// A pong with an invisible state, or a future last_active, is ignored.
	ft.Call(f, h, t0, "app", "presence.query", `{"connection_id":"c1"}`)
	id, _ := strictjson.ParseObject(h.SentOfType("presence.ping")[0].Body)
	pid, _ := id.String("ping_id")
	h.Reset()
	ft.CallExp(f, h, t0, t0.Add(PingTTL), "connection:c1", "presence.pong", `{"ping_id":"`+pid+`","state":"invisible"}`)
	ft.CallExp(f, h, t0, t0.Add(PingTTL), "connection:c1", "presence.pong", `{"ping_id":"`+pid+`","state":"away","last_active":"2026-10-03T13:00:00.000Z"}`)
	if len(h.SentOfType("presence.result")) != 0 {
		t.Fatal("bad pong used")
	}
	// After exp the pong is ignored.
	ft.CallExp(f, h, t0.Add(31*time.Second), t0.Add(time.Minute), "connection:c1", "presence.pong", `{"ping_id":"`+pid+`","state":"away"}`)
	if len(h.SentOfType("presence.result")) != 0 {
		t.Fatal("late pong used")
	}
}

func FuzzParseSet(f *testing.F) {
	f.Add([]byte(`{"version":0,"state":"busy","share":"none","except":["c1"]}`))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = ParseSet(b) })
}

func FuzzParseQuery(f *testing.F) {
	f.Add([]byte(`{"connection_id":"c1"}`))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = ParseQuery(b) })
}

func FuzzParsePing(f *testing.F) {
	f.Add([]byte(`{"ping_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V"}`))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = ParsePing(b) })
}

func FuzzParsePong(f *testing.F) {
	f.Add([]byte(`{"ping_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V","state":"away","last_active":"2026-10-03T11:55:00.000Z"}`))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = ParsePong(b) })
}

// §3.6.3, §10.17 (0.13.0): a held vault does not answer pings; with the
// hold off (due) it does.
func TestHeldVaultDoesNotAnswer(t *testing.T) {
	peer, hp := setup()
	hp.Hold = "held"
	ft.CallExp(peer, hp, t0, t0.Add(PingTTL), "connection:c1", "presence.ping", `{"ping_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V"}`)
	if len(hp.SentOfType("presence.pong")) != 0 {
		t.Fatal("a held vault answered")
	}
	hp.Hold = "due"
	ft.CallExp(peer, hp, t0.Add(time.Second), t0.Add(PingTTL), "connection:c1", "presence.ping", `{"ping_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0W"}`)
	if len(hp.SentOfType("presence.pong")) != 1 {
		t.Fatal("a due vault (hold off) did not answer")
	}
}
