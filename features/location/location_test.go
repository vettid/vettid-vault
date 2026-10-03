package location

import (
	"strings"
	"testing"
	"time"

	ft "github.com/vettid/vettid-vault/internal/featuretest"
	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/envelope"
)

var t0 = time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)

func sample(at time.Time) string {
	return `{"lat":52.520008,"lon":13.404954,"accuracy_m":8,"altitude_m":34.5,"speed_mps":1.2,"heading_deg":90,"at":"` + envelope.FormatTS(at) + `"}`
}

func setup() (*Feature, *ft.Host) {
	h := ft.NewHost()
	h.AddConnection("c1")
	h.AddConnection("c2")
	h.AddDevice("dev-app", "app")
	h.AddDevice("dev-desktop", "desktop")
	return New(), h
}

func start(t *testing.T, f *Feature, h *ft.Host, now time.Time, body string) string {
	t.Helper()
	r := ft.Call(f, h, now, "app", "location.share.start", body)
	if !r.OK() {
		t.Fatalf("start: %s", r.Code)
	}
	id, _ := r.Obj(t).String("share_id")
	return id
}

func TestContinuousShare(t *testing.T) {
	f, h := setup()
	id := start(t, f, h, t0, `{"connection_id":"c1","mode":"continuous","precision":"approximate","interval_seconds":30,"duration_seconds":600}`)
	sh := h.SentOfType("location.shared")
	if len(sh) != 1 || sh[0].To != "c1" || !strings.Contains(string(sh[0].Body), `"interval_seconds":30`) ||
		!strings.Contains(string(sh[0].Body), `"precision":"approximate"`) {
		t.Fatalf("shared: %+v", sh)
	}
	if !h.HasActivity("location.share.started") {
		t.Fatal("no audit")
	}
	h.Reset()
	ft.Call(f, h, t0, "app", "location.update", sample(t0))
	up := h.SentOfType("location.update")
	if len(up) != 1 || up[0].To != "c1" || !up[0].Opt.MemoryOnly || up[0].Opt.Exp.IsZero() {
		t.Fatalf("update: %+v", up)
	}
	o, _ := strictjson.ParseObject(up[0].Body)
	if s, _ := o.String("share_id"); s != id {
		t.Fatal("share id")
	}
	if string(o["lat"]) != "52.525" || string(o["lon"]) != "13.405" || string(o["accuracy_m"]) != "1000" || o.Has("altitude_m") || o.Has("speed_mps") {
		t.Fatalf("precision not applied: %s", up[0].Body)
	}
	// Cadence: too soon is skipped; after the interval it is forwarded.
	h.Reset()
	ft.Call(f, h, t0.Add(10*time.Second), "app", "location.update", sample(t0.Add(10*time.Second)))
	if len(h.SentOfType("location.update")) != 0 {
		t.Fatal("cadence not enforced")
	}
	ft.Call(f, h, t0.Add(30*time.Second), "app", "location.update", sample(t0.Add(30*time.Second)))
	if len(h.SentOfType("location.update")) != 1 {
		t.Fatal("not forwarded after the interval")
	}
	// Another device does not feed this share.
	h.Reset()
	ft.Call(f, h, t0.Add(2*time.Minute), "desktop", "location.update", sample(t0.Add(2*time.Minute)))
	if len(h.SentOfType("location.update")) != 0 {
		t.Fatal("other device fed the share")
	}
	// Expiry ends it.
	h.Reset()
	ft.Call(f, h, t0.Add(11*time.Minute), "app", "location.update", sample(t0.Add(11*time.Minute)))
	if len(h.SentOfType("location.update")) != 0 {
		t.Fatal("forwarded after expiry")
	}
	if out, _ := f.Shares(); len(out) != 0 {
		t.Fatal("expired share kept")
	}
}

func TestStartValidation(t *testing.T) {
	f, h := setup()
	for _, b := range []string{
		`{"connection_id":"c1","mode":"once","duration_seconds":600}`,
		`{"connection_id":"c1","mode":"once","interval_seconds":60}`,
		`{"connection_id":"c1","mode":"continuous","interval_seconds":5}`,
		`{"connection_id":"c1","mode":"continuous","duration_seconds":100}`,
		`{"connection_id":"c1","mode":"always"}`,
		`{"connection_id":"c1","mode":"once","precision":"street"}`,
	} {
		if r := ft.Call(f, h, t0, "app", "location.share.start", b); r.Code != "bad_request" {
			t.Fatalf("%s: %q", b, r.Code)
		}
	}
	if r := ft.Call(f, h, t0, "app", "location.share.start", `{"connection_id":"cx","mode":"once"}`); r.Code != "not_found" {
		t.Fatal(r.Code)
	}
	h.DownConns["c2"] = true
	if r := ft.Call(f, h, t0, "app", "location.share.start", `{"connection_id":"c2","mode":"once"}`); r.Code != "connection_unavailable" {
		t.Fatal(r.Code)
	}
	if r := ft.Call(f, h, t0, "connection:c1", "location.share.start", `{"connection_id":"c1","mode":"once"}`); r.Code != "forbidden" {
		t.Fatal(r.Code)
	}
}

func TestOnceAndReplace(t *testing.T) {
	f, h := setup()
	first := start(t, f, h, t0, `{"connection_id":"c1","mode":"continuous"}`)
	h.Reset()
	second := start(t, f, h, t0, `{"connection_id":"c1","mode":"once","precision":"city"}`)
	st := h.SentOfType("location.stopped")
	if len(st) != 1 || !strings.Contains(string(st[0].Body), first) {
		t.Fatalf("old share not stopped: %+v", st)
	}
	h.Reset()
	ft.Call(f, h, t0, "app", "location.update", sample(t0))
	up := h.SentOfType("location.update")
	if len(up) != 1 || !strings.Contains(string(up[0].Body), second) || !strings.Contains(string(up[0].Body), `"lat":52.55`) {
		t.Fatalf("once update: %+v", up)
	}
	if out, _ := f.Shares(); len(out) != 0 {
		t.Fatal("once share still active")
	}
}

func TestReceive(t *testing.T) {
	f, h := setup()
	exp := envelope.FormatTS(t0.Add(time.Hour))
	ft.Call(f, h, t0, "connection:c1", "location.shared", `{"share_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V","mode":"continuous","precision":"exact","interval_seconds":30,"history":true,"expires_at":"`+exp+`"}`)
	if ev := h.SentOfType("location.event"); len(ev) != 1 || !h.HasActivity("location.shared") {
		t.Fatalf("event: %+v", ev)
	}
	up := func(now time.Time, from string) {
		ft.CallExp(f, h, now, now.Add(time.Minute), from, "location.update", `{"share_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V","lat":1.5,"lon":2.5,"accuracy_m":5,"at":"`+envelope.FormatTS(now)+`"}`)
	}
	h.Reset()
	up(t0, "connection:c1")
	if fw := h.SentOfType("location.update"); len(fw) != 1 || fw[0].To != "devices" || !fw[0].Opt.MemoryOnly {
		t.Fatalf("forward: %+v", fw)
	}
	up(t0.Add(2*time.Second), "connection:c1")
	if !h.HasActivity("drop.location_rate") {
		t.Fatal("rate not enforced")
	}
	up(t0.Add(time.Minute), "connection:c2")
	if !h.HasActivity("drop.location") {
		t.Fatal("foreign connection accepted")
	}
	up(t0.Add(time.Minute), "connection:c1")
	r := ft.Call(f, h, t0.Add(time.Minute), "app", "location.get", `{"connection_id":"c1","history":true}`)
	if !r.OK() || !strings.Contains(string(r.Body), `"lat":1.5`) || !strings.Contains(string(r.Body), `"history":[{`) {
		t.Fatalf("get: %s %s", r.Code, r.Body)
	}
	if r := ft.Call(f, h, t0, "app", "location.get", `{"connection_id":"c2"}`); r.Code != "not_found" {
		t.Fatal(r.Code)
	}
	// Persisted and reloaded.
	g := New()
	ft.RoundTrip(t, f, g)
	if r := ft.Call(g, h, t0.Add(time.Minute), "app", "location.share.list", `{}`); !strings.Contains(string(r.Body), `"incoming":[{`) {
		t.Fatalf("list: %s", r.Body)
	}
	// The sharer stops: the share and its samples are gone.
	h.Reset()
	ft.Call(g, h, t0.Add(2*time.Minute), "connection:c1", "location.stopped", `{"share_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V"}`)
	if _, in := g.Shares(); len(in) != 0 || !h.HasActivity("location.share.ended") {
		t.Fatal("not stopped")
	}
	// A repeated location.shared does not revive it.
	ft.Call(g, h, t0.Add(3*time.Minute), "connection:c1", "location.shared", `{"share_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V","mode":"once","precision":"exact","history":false,"expires_at":"`+exp+`"}`)
	if _, in := g.Shares(); len(in) != 0 {
		t.Fatal("revived")
	}
}

func TestIncomingExpiryAndStop(t *testing.T) {
	f, h := setup()
	exp := envelope.FormatTS(t0.Add(10 * time.Minute))
	ft.Call(f, h, t0, "connection:c1", "location.shared", `{"share_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V","mode":"once","precision":"exact","history":false,"expires_at":"`+exp+`"}`)
	ft.Call(f, h, t0, "connection:c2", "location.shared", `{"share_id":"01JB2Z6V9K3M4N5P6Q7R8S9T1V","mode":"once","precision":"exact","history":false,"expires_at":"`+exp+`"}`)
	h.Reset()
	if r := ft.Call(f, h, t0, "app", "location.share.stop", `{"share_id":"01JB2Z6V9K3M4N5P6Q7R8S9T1V"}`); !r.OK() {
		t.Fatal(r.Code)
	}
	if st := h.SentOfType("location.stopped"); len(st) != 1 || st[0].To != "c2" {
		t.Fatalf("receiver stop: %+v", st)
	}
	ft.Call(f, h, t0.Add(11*time.Minute), "app", "location.share.list", `{}`)
	if _, in := f.Shares(); len(in) != 0 {
		t.Fatal("expired share kept")
	}
	// Too far in the future, or in the past: dropped.
	far := envelope.FormatTS(t0.Add(8 * 24 * time.Hour))
	ft.Call(f, h, t0, "connection:c1", "location.shared", `{"share_id":"01JB2Z6V9K3M4N5P6Q7R8S9T2V","mode":"once","precision":"exact","history":false,"expires_at":"`+far+`"}`)
	if _, in := f.Shares(); len(in) != 0 {
		t.Fatal("accepted a far expiry")
	}
	if r := ft.Call(f, h, t0, "app", "location.share.stop", `{"share_id":"01JB2Z6V9K3M4N5P6Q7R8S9T2V"}`); r.Code != "not_found" {
		t.Fatal(r.Code)
	}
}

func TestRequests(t *testing.T) {
	f, h := setup()
	r := ft.Call(f, h, t0, "app", "location.request", `{"connection_id":"c1","note":"where are you?"}`)
	if !r.OK() || len(h.SentOfType("location.requested")) != 1 {
		t.Fatal(r.Code)
	}
	if r := ft.Call(f, h, t0.Add(time.Minute), "app", "location.request", `{"connection_id":"c1"}`); r.Code != "limit" {
		t.Fatal(r.Code)
	}
	if r := ft.Call(f, h, t0, "app", "location.request", `{"connection_id":"c2","note":"a\nb"}`); r.Code != "bad_request" {
		t.Fatal(r.Code)
	}
	if r := ft.Call(f, h, t0.Add(11*time.Minute), "app", "location.request", `{"connection_id":"c1"}`); !r.OK() {
		t.Fatal(r.Code)
	}
	// Incoming.
	h.Reset()
	ft.Call(f, h, t0, "connection:c2", "location.requested", `{"request_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V","note":"hi"}`)
	if p := h.SentOfType("location.request.pending"); len(p) != 1 || !h.HasActivity("location.request") {
		t.Fatal("pending")
	}
	ft.Call(f, h, t0.Add(time.Minute), "connection:c2", "location.requested", `{"request_id":"01JB2Z6V9K3M4N5P6Q7R8S9T1V"}`)
	if !h.HasActivity("drop.location_rate") {
		t.Fatal("incoming rate")
	}
	// Answering it with a share closes it.
	start(t, f, h, t0.Add(2*time.Minute), `{"connection_id":"c2","mode":"once","request_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V"}`)
	if len(f.d.Requests) != 0 {
		t.Fatal("request not closed")
	}
}

func TestConnectionRemoved(t *testing.T) {
	f, h := setup()
	start(t, f, h, t0, `{"connection_id":"c1","mode":"continuous"}`)
	ft.Call(f, h, t0, "connection:c1", "location.shared", `{"share_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V","mode":"once","precision":"exact","history":false,"expires_at":"`+envelope.FormatTS(t0.Add(time.Hour))+`"}`)
	f.ConnectionRemoved(nil, "c1")
	if out, in := f.Shares(); len(out)+len(in) != 0 {
		t.Fatal("kept")
	}
}

func TestReduce(t *testing.T) {
	alt := 10.0
	sm := &Sample{Lat: -33.868819, Lon: 151.209295, Accuracy: 3, Altitude: &alt, At: t0}
	if r := Reduce(sm, Exact); r.Lat != -33.86882 || r.Lon != 151.2093 || r.Altitude == nil {
		t.Fatalf("exact %+v", r)
	}
	if r := Reduce(sm, Approximate); r.Lat != -33.865 || r.Lon != 151.205 || r.Accuracy != 1000 || r.Altitude != nil {
		t.Fatalf("approximate %+v", r)
	}
	if r := Reduce(sm, City); r.Lat != -33.85 || r.Lon != 151.25 || r.Accuracy != 10000 {
		t.Fatalf("city %+v", r)
	}
	edge := &Sample{Lat: 90, Lon: 180, At: t0}
	if r := Reduce(edge, City); r.Lat > 90 || r.Lon > 180 {
		t.Fatalf("clamp %+v", r)
	}
}

func TestSampleValidation(t *testing.T) {
	for _, b := range []string{
		`{"lat":91,"lon":0,"at":"2026-10-03T12:00:00.000Z"}`,
		`{"lat":0,"lon":-181,"at":"2026-10-03T12:00:00.000Z"}`,
		`{"lat":"1","lon":0,"at":"2026-10-03T12:00:00.000Z"}`,
		`{"lat":0,"lon":0,"heading_deg":360,"at":"2026-10-03T12:00:00.000Z"}`,
		`{"lat":0,"lon":0,"accuracy_m":-1,"at":"2026-10-03T12:00:00.000Z"}`,
		`{"lat":1e400,"lon":0,"at":"2026-10-03T12:00:00.000Z"}`,
		`{"lat":0,"lon":0}`,
	} {
		if _, _, err := ParseSample([]byte(b), false); err == nil {
			t.Fatalf("accepted %s", b)
		}
	}
	f, h := setup()
	start(t, f, h, t0, `{"connection_id":"c1","mode":"once"}`)
	h.Reset()
	ft.Call(f, h, t0, "app", "location.update", sample(t0.Add(-2*time.Hour)))
	if !h.HasActivity("drop.location_malformed") || len(h.SentOfType("location.update")) != 0 {
		t.Fatal("stale sample forwarded")
	}
}

func FuzzParseStart(f *testing.F) {
	f.Add([]byte(`{"connection_id":"c1","mode":"continuous","precision":"approximate","interval_seconds":30,"duration_seconds":600,"history":true}`))
	f.Add([]byte(`{"connection_id":"c1","mode":"once","request_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V"}`))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = ParseStart(b) })
}

func FuzzParseSample(f *testing.F) {
	f.Add([]byte(sample(t0)), false)
	f.Add([]byte(`{"share_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V","lat":-1.5,"lon":2,"accuracy_m":0,"at":"2026-10-03T12:00:00.000Z"}`), true)
	f.Fuzz(func(t *testing.T, b []byte, peer bool) {
		_, sm, err := ParseSample(b, peer)
		if err != nil {
			return
		}
		for _, p := range []string{Exact, Approximate, City} {
			r := Reduce(sm, p)
			if r.Lat < -90 || r.Lat > 90 || r.Lon < -180 || r.Lon > 180 {
				t.Fatalf("out of range %+v", r)
			}
			if _, _, err := ParseSample(r.json("", "01JB2Z6V9K3M4N5P6Q7R8S9T0V", false), true); err != nil {
				t.Fatalf("reduced sample does not parse: %s", r.json("", "01JB2Z6V9K3M4N5P6Q7R8S9T0V", false))
			}
		}
	})
}

func FuzzParseShared(f *testing.F) {
	f.Add([]byte(`{"share_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V","mode":"continuous","precision":"exact","interval_seconds":30,"history":true,"expires_at":"2026-10-03T13:00:00.000Z"}`))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = ParseShared(b) })
}

func FuzzParseShareID(f *testing.F) {
	f.Add([]byte(`{"share_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V"}`))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = ParseShareID(b) })
}

func FuzzParseRequest(f *testing.F) {
	f.Add([]byte(`{"connection_id":"c1","note":"hi"}`), false)
	f.Add([]byte(`{"request_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V","note":"hi"}`), true)
	f.Fuzz(func(t *testing.T, b []byte, peer bool) { _, _ = ParseRequest(b, peer) })
}

func FuzzParseGet(f *testing.F) {
	f.Add([]byte(`{"connection_id":"c1","history":true}`))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = ParseGet(b) })
}
