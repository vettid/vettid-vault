package grants

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/envelope"
)

// §10.12 (0.21.0): an available item entry of grant.pending, and of
// grant.list's pending (which now carries available), names the member's
// item, its category and the labels of the requested fields in the item's
// order; unavailable and category entries carry none of them.
func TestPendingEntryDetails(t *testing.T) {
	a, b := pair()
	ok(t, call(t, b, t0, "app", "grant.request", `{"connection_id":"cA","items":[`+
		`{"kind":"item","ref":"`+s1+`","fields":["f2","f1"],"label":"wifi"},{"kind":"item","ref":"`+s3+`"},`+
		`{"kind":"item","ref":"`+s2+`"},{"kind":"category","ref":"contact"}]}`))
	relay(t, b, a, t0, "data.request")
	type entry struct {
		Kind      string `json:"kind"`
		Ref       string `json:"ref"`
		Label     string `json:"label"`
		Available *bool  `json:"available"`
		Name      string `json:"name"`
		Category  string `json:"category"`
		Labels    []struct {
			ID, Label, Kind string
		} `json:"labels"`
	}
	check := func(where string, raw json.RawMessage) {
		t.Helper()
		var p struct {
			Items []entry `json:"items"`
		}
		if err := json.Unmarshal(raw, &p); err != nil || len(p.Items) != 4 {
			t.Fatalf("%s: %s", where, raw)
		}
		w := p.Items[0]
		if w.Available == nil || !*w.Available || w.Name != "Wi-Fi" || w.Category != "login" || w.Label != "wifi" ||
			len(w.Labels) != 2 || w.Labels[0].Label != "Password" || w.Labels[1].Label != "SSID" || w.Labels[0].Kind != "password" {
			t.Fatalf("%s: wi-fi entry %+v", where, w)
		}
		if ph := p.Items[1]; ph.Name != "Phone" || ph.Category != "contact" || len(ph.Labels) != 1 {
			t.Fatalf("%s: whole item %+v", where, ph)
		}
		if c := p.Items[2]; c.Available == nil || *c.Available || c.Name != "" || c.Labels != nil {
			t.Fatalf("%s: unavailable entry %+v", where, c)
		}
		if c := p.Items[3]; c.Available == nil || !*c.Available || c.Name != "" || c.Labels != nil {
			t.Fatalf("%s: category entry %+v", where, c)
		}
		if strings.Contains(string(raw), "hunter22") || strings.Contains(string(raw), "zz-home") {
			t.Fatalf("%s: a value or tag: %s", where, raw)
		}
	}
	check("grant.pending", last(t, a.h, "grant.pending").Body)
	l := ok(t, call(t, a, t0, "desktop", "grant.list", `{}`))
	var pend []json.RawMessage
	_ = json.Unmarshal(l["pending"], &pend)
	if len(pend) != 1 {
		t.Fatalf("list pending: %s", l["pending"])
	}
	check("grant.list", pend[0])
	// The entries stay the asker's on its side: no names, no availability,
	// exactly as sent; state pending.
	bl := ok(t, call(t, b, t0, "app", "grant.list", `{}`))
	var req []struct {
		Items []map[string]any `json:"items"`
		State string           `json:"state"`
	}
	if err := json.Unmarshal(bl["requested"], &req); err != nil || len(req) != 1 || req[0].State != "pending" {
		t.Fatalf("requested: %s", bl["requested"])
	}
	for _, it := range req[0].Items {
		for k := range it {
			if k != "kind" && k != "ref" && k != "fields" && k != "label" {
				t.Fatalf("requested entry member %s: %s", k, bl["requested"])
			}
		}
	}
	if f := req[0].Items[0]["fields"].([]any); len(f) != 2 || f[0] != "f2" {
		t.Fatalf("fields as sent: %v", f)
	}
}

// §10.12 (0.21.0): a received grant in grant.list carries its labels as
// the descriptor had them; a given grant carries none.
func TestReceivedLabels(t *testing.T) {
	a, b := pair()
	share(t, a, b, `{"request_id":"RID","approve":true}`)
	relay(t, a, b, t0, "data.decided")
	l := ok(t, call(t, b, t0, "app", "grant.list", `{}`))
	var rec []struct {
		Ref    string `json:"ref"`
		Labels []struct {
			ID    string `json:"field_id"`
			Label string `json:"label"`
			Kind  string `json:"kind"`
		} `json:"labels"`
	}
	if err := json.Unmarshal(l["received"], &rec); err != nil || len(rec) != 2 {
		t.Fatalf("received: %s", l["received"])
	}
	for _, g := range rec {
		switch g.Ref {
		case s1:
			if len(g.Labels) != 1 || g.Labels[0].ID != "f1" || g.Labels[0].Label != "Password" || g.Labels[0].Kind != "password" {
				t.Fatalf("wi-fi labels: %+v", g)
			}
		case s3:
			if len(g.Labels) != 1 || g.Labels[0].Label != "Number" {
				t.Fatalf("phone labels: %+v", g)
			}
		}
	}
	// Not refreshed: the member relabels; the received labels stay.
	a.it.items[s3].Fields[0].Label = "Mobile"
	l = ok(t, call(t, b, t0, "app", "grant.list", `{}`))
	if !strings.Contains(string(l["received"]), `"label":"Number"`) {
		t.Fatalf("labels refreshed: %s", l["received"])
	}
	al := ok(t, call(t, a, t0, "app", "grant.list", `{}`))
	if strings.Contains(string(al["given"]), `"labels"`) {
		t.Fatalf("given grant with labels: %s", al["given"])
	}
}

// §10.1 (0.21.0): the grants feature's limits name themselves.
func TestLimitNames(t *testing.T) {
	_, b := pair()
	for i := 0; i < MaxFetches; i++ {
		ok(t, call(t, b, t0, "app", "grant.catalog", `{"connection_id":"cA"}`))
	}
	r := call(t, b, t0, "app", "grant.catalog", `{"connection_id":"cA"}`)
	if r.Code != "limit" || string(r.Body) != `{"limit":"catalog_requests","max":64}` {
		t.Fatalf("catalog_requests: %q %s", r.Code, r.Body)
	}
	_, b = pair()
	for i := 0; i < MaxRequested; i++ {
		b.f.d.Requested[ulidAt(i)] = &Requested{ID: ulidAt(i), Conn: "cA", State: "pending", Created: t0}
	}
	r = call(t, b, t0, "app", "grant.request", `{"connection_id":"cA","items":[{"kind":"item","ref":"`+s3+`"}]}`)
	if r.Code != "limit" || string(r.Body) != `{"limit":"grant_requests","max":1000}` {
		t.Fatalf("grant_requests: %q %s", r.Code, r.Body)
	}
}

func ulidAt(i int) string {
	id, _ := envelope.NewULID(t0.Add(time.Duration(i) * time.Millisecond))
	return id
}
