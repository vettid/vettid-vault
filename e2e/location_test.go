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

// V4 batch 4, location sharing (§10.16) through the real relay: B asks
// A to share; A shares continuously at approximate precision, answering
// the request; A's app sends a sample, which B receives reduced; B reads
// it (with the trail) and A stops; a one-off share ends after its single
// sample; B (the receiver) stops a share, which A ends.
func TestLocationShare(t *testing.T) {
	r := relaytest.Start(t, nil)
	a := newTestVault(t, r.URL, "a", nil)
	b := newTestVault(t, r.URL, "b", nil)
	ctx := ctxT(t, 180*time.Second)
	aConn, bConn := connect(t, a, b, 600)

	reqID, err := b.app.LocationRequest(ctx, bConn, "where are you?")
	if err != nil {
		t.Fatal(err)
	}
	p, err := a.app.LocationRequestPending(ctx, aConn)
	if err != nil {
		t.Fatal(err)
	}
	if id, _ := p.String("request_id"); id != reqID {
		t.Fatalf("request id %s != %s", id, reqID)
	}

	sid, exp, err := a.app.LocationShareStart(ctx, client.LocationShare{ConnectionID: aConn, Mode: "continuous", Precision: "approximate",
		Duration: 600, Interval: 10, History: true, RequestID: reqID})
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Until(exp); d < 9*time.Minute || d > 11*time.Minute {
		t.Fatalf("expiry %v", exp)
	}
	ev, err := b.app.LocationEvent(ctx, bConn, "started")
	if err != nil {
		t.Fatal(err)
	}
	if id, _ := ev.String("share_id"); id != sid {
		t.Fatal("started: share id")
	}
	alt := 34.5
	if err := a.app.LocationUpdate(ctx, client.LocationSample{Lat: 52.520008, Lon: 13.404954, Accuracy: 8, Altitude: &alt}); err != nil {
		t.Fatal(err)
	}
	up, err := b.app.LocationUpdateFrom(ctx, bConn)
	if err != nil {
		t.Fatal(err)
	}
	if string(up["lat"]) != "52.525" || string(up["lon"]) != "13.405" || string(up["accuracy_m"]) != "1000" || up.Has("altitude_m") {
		t.Fatalf("precision not applied: %v", up)
	}
	g, err := b.app.LocationGet(ctx, bConn, true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(g["last"]), `"lat":52.525`) || !strings.Contains(string(g["history"]), `"lat":52.525`) {
		t.Fatalf("get: %v", g)
	}
	if err := a.app.LocationShareStop(ctx, sid); err != nil {
		t.Fatal(err)
	}
	if _, err := b.app.LocationEvent(ctx, bConn, "stopped"); err != nil {
		t.Fatal(err)
	}
	if _, err := b.app.LocationGet(ctx, bConn, false); client.Code(err) != "not_found" {
		t.Fatalf("get after stop: %v", err)
	}

	// A one-off share at exact precision ends after its single sample.
	once, _, err := a.app.LocationShareStart(ctx, client.LocationShare{ConnectionID: aConn, Mode: "once", Precision: "exact"})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.app.LocationUpdate(ctx, client.LocationSample{Lat: 48.858370, Lon: 2.294481, Accuracy: 4}); err != nil {
		t.Fatal(err)
	}
	up, err = b.app.LocationUpdateFrom(ctx, bConn)
	if err != nil {
		t.Fatal(err)
	}
	if id, _ := up.String("share_id"); id != once || string(up["lat"]) != "48.85837" {
		t.Fatalf("once: %v", up)
	}
	l, err := a.app.LocationShareList(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if string(l["outgoing"]) != "[]" {
		t.Fatalf("once share still active: %s", l["outgoing"])
	}

	// The receiver stops a share: the sharer ends it.
	cont, _, err := a.app.LocationShareStart(ctx, client.LocationShare{ConnectionID: aConn, Mode: "continuous"})
	if err != nil {
		t.Fatal(err)
	}
	waitEvent(t, b.app, "location.event", has("share_id", cont))
	if err := b.app.LocationShareStop(ctx, cont); err != nil {
		t.Fatal(err)
	}
	ev, err = a.app.LocationEvent(ctx, aConn, "stopped")
	if err != nil {
		t.Fatal(err)
	}
	if d, _ := ev.String("direction"); d != "out" {
		t.Fatalf("stopped: %v", ev)
	}
	if l, _ := a.app.LocationShareList(ctx); string(l["outgoing"]) != "[]" {
		t.Fatalf("share kept after the receiver stopped it: %s", l["outgoing"])
	}
}

// The member's own location log (§10.16) through the real relay: off by
// default; enabled with a cadence; the app's positions recorded; listed
// by the owner; a snapshot sent through an active share and kept by the
// connection with it; deleted.
func TestLocationHistory(t *testing.T) {
	r := relaytest.Start(t, nil)
	a := newTestVault(t, r.URL, "a", nil)
	b := newTestVault(t, r.URL, "b", nil)
	ctx := ctxT(t, 180*time.Second)
	aConn, bConn := connect(t, a, b, 600)

	now := time.Now().UTC()
	if err := a.app.LocationUpdate(ctx, client.LocationSample{Lat: 48.8584, Lon: 2.2945, Accuracy: 5, At: now.Add(-10 * time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.app.SettingsSet(ctx, 0, map[string]any{"location.history.enabled": true, "location.history.interval_seconds": 60,
		"location.history.retention_days": 7}); err != nil {
		t.Fatal(err)
	}
	for i := 3; i >= 1; i-- {
		at := now.Add(-time.Duration(i) * 2 * time.Minute)
		if err := a.app.LocationUpdate(ctx, client.LocationSample{Lat: 48.8584 + float64(i)/1000, Lon: 2.2945, Accuracy: 5, At: at}); err != nil {
			t.Fatal(err)
		}
	}
	var l map[string]json.RawMessage
	deadline := time.Now().Add(20 * time.Second)
	for {
		o, err := a.app.LocationHistoryList(ctx, time.Time{}, time.Time{}, "", 0)
		if err != nil {
			t.Fatal(err)
		}
		if n, _ := o.Uint("count", 0, 1e6); n == 3 {
			l = o
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("log: %v", o)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if strings.Contains(string(l["points"]), "48.8584,") {
		t.Fatalf("recorded while off: %s", l["points"])
	}
	sid, _, err := a.app.LocationShareStart(ctx, client.LocationShare{ConnectionID: aConn, Mode: "continuous", Duration: 600})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.app.LocationEvent(ctx, bConn, "started"); err != nil {
		t.Fatal(err)
	}
	n, err := a.app.LocationHistoryShare(ctx, sid, now.Add(-time.Hour), now)
	if err != nil || n != 3 {
		t.Fatalf("share: %d %v", n, err)
	}
	if _, err := b.app.LocationEvent(ctx, bConn, "snapshot"); err != nil {
		t.Fatal(err)
	}
	g, err := b.app.LocationGet(ctx, bConn, false)
	if err != nil || !strings.Contains(string(g["snapshot"]), `"lat":48.865`) || strings.Contains(string(g["snapshot"]), "48.8614") {
		t.Fatalf("snapshot at the default precision (approximate): %v %v", g, err)
	}
	if n, err := a.app.LocationHistoryDelete(ctx, time.Time{}, time.Time{}); err != nil || n != 3 {
		t.Fatalf("delete: %d %v", n, err)
	}
}
