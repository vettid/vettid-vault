package audit

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/featuretest"
	"github.com/vettid/vettid-vault/vault"
)

type fakeItems map[string]string

func (f fakeItems) ItemName(id string) (string, bool) {
	n, ok := f[id]
	return n, ok
}

type page struct {
	Entries []struct {
		Seq  uint64 `json:"seq"`
		Kind string `json:"kind"`
	} `json:"entries"`
	Seq        uint64  `json:"seq"`
	NextBefore *uint64 `json:"next_before_seq"`
	NextAfter  *uint64 `json:"next_after_seq"`
	Partial    *bool   `json:"partial"`
}

func list(t *testing.T, f *Feature, h *featuretest.Host, typ, body string) page {
	t.Helper()
	r := featuretest.Call(f, h, t0, "app", typ, body)
	if !r.OK() {
		t.Fatalf("%s %s: %s", typ, body, r.Code)
	}
	var p page
	if err := json.Unmarshal(r.Body, &p); err != nil {
		t.Fatal(err)
	}
	if p.Partial != nil && !*p.Partial {
		t.Fatalf("partial:false in %s", r.Body)
	}
	return p
}

func seqs(p page) string {
	var b []string
	for _, e := range p.Entries {
		b = append(b, strconv.FormatUint(e.Seq, 10))
	}
	return strings.Join(b, ",")
}

// searchFixture: a connection with a name, alias and profile, a device,
// items, and one entry of each kind of reference.
func searchFixture(t *testing.T) (*Feature, *featuretest.Host) {
	f, h := New(), featuretest.NewHost()
	f.SetItems(fakeItems{"it1": "Bank PIN", "w1": "Cold Storage", "it2": "Über Konto"})
	h.Conns["c1"] = vault.PeerInfo{ID: "c1", Kind: vault.KindConnection, State: vault.PeerActive, Name: "Bobcat", Alias: "Builder Bob",
		Profile: json.RawMessage(`{"version":2,"first_name":"Robert","last_name":"Tables","name":"Bobcat","ik":"AAAA",` +
			`"items":[{"item_id":"x","name":"Phone","fields":[{"label":"Number","value":"SECRETVALUE"}],"tags":["@profile","hiddentag"]}]}`)}
	h.Conns["c2"] = vault.PeerInfo{ID: "c2", Kind: vault.KindConnection, State: vault.PeerPending, Name: "Pendleton"}
	h.Devices["d1"] = vault.PeerInfo{ID: "d1", Kind: vault.KindDesktop, State: vault.PeerActive, Name: "Pixel Ten"}
	h.Devices["d2"] = vault.PeerInfo{ID: "d2", Kind: vault.KindApp, State: vault.PeerActive, Recovering: true, Name: "Recovering Phone"}
	for i, a := range []vault.Activity{
		{Kind: "credential.password_changed"},                                      // 1
		{Kind: "message.sent", ConnectionID: "c1", Ref: "m1"},                      // 2
		{Kind: "device.paired", DeviceID: "d1"},                                    // 3
		{Kind: "item.revealed", Ref: "it1"},                                        // 4
		{Kind: "wallet.address_issued", ConnectionID: "c1", Ref: "w1"},             // 5
		{Kind: "share.pending", Ref: "it1"},                                        // 6: ref is not an item_id
		{Kind: "message.sent", ConnectionID: "c-gone", Ref: "m2"},                  // 7: removed connection
		{Kind: "drop.suppressed", ConnectionID: "c-gone", Ref: "message.received"}, // 8: ref is a kind
		{Kind: "item.updated", Ref: "it-deleted"},                                  // 9: deleted item
		{Kind: "device.unlinked", DeviceID: "d-gone"},                              // 10: unlinked device
		{Kind: "item.added", Ref: "it2"},                                           // 11
		{Kind: "connection.added", ConnectionID: "c2"},                             // 12: a pending connection
		{Kind: "vault.unlocked", DeviceID: "d2"},                                   // 13: a recovering app
	} {
		a.Audit = true
		rec(f, h, t0.Add(time.Duration(i)*time.Second), a)
	}
	return f, h
}

// §10.9 (0.20.0): q matches the kind (also with ".", "_", "-" read as
// spaces) and the current names of the entry's connection (name, alias,
// first_name, last_name, display name, "First Last"), device and item
// (for the kinds whose ref is an item_id), case-insensitively, each field
// separately.
func TestSearchFields(t *testing.T) {
	f, h := searchFixture(t)
	for _, c := range []struct{ q, want string }{
		{"password changed", "1"}, {"PASSWORD_CHANGED", "1"}, {"credential.password", "1"}, {"Credential Password", "1"},
		{"message sent", "7,2"}, {"sent", "7,2"},
		{"bobcat", "5,2"}, {"builder", "5,2"}, {"ROBERT", "5,2"}, {"tables", "5,2"}, {"robert tables", "5,2"}, {"rt ta", "5,2"},
		{"pixel", "3"}, {"bank pin", "4"}, {"cold", "5"}, {"über", "11"}, {"ÜBER KONTO", "11"},
		{"pendleton", "12"}, {"recovering phone", "13"},
		{"address issued", "5"}, {"address_issued", "5"}, {"wallet address", "5"},
	} {
		if got := seqs(list(t, f, h, "audit.list", `{"q":`+strconv.Quote(c.q)+`}`)); got != c.want {
			t.Errorf("q %q: %s, want %s", c.q, got, c.want)
		}
	}
	// connection.audit.list takes q for its one connection.
	if got := seqs(list(t, f, h, "connection.audit.list", `{"connection_id":"c1","q":"cold"}`)); got != "5" {
		t.Errorf("connection.audit.list q: %s", got)
	}
	// q combines with kinds and connection_id.
	if got := seqs(list(t, f, h, "audit.list", `{"q":"bob","kinds":["message"]}`)); got != "2" {
		t.Errorf("q with kinds: %s", got)
	}
}

// §10.9 (0.20.0): never searched: field labels and values, tags, the
// profile's other members, ids, refs that are not item ids (a share.pending
// rule, a drop.suppressed kind, a message id), a match spanning two
// fields; a removed connection, unlinked device or deleted item adds no
// text (the entry is found by its kind only).
func TestSearchNeverSearched(t *testing.T) {
	f, h := searchFixture(t)
	for _, q := range []string{"secretvalue", "number", "hiddentag", "phone number", "AAAA", "c1", "d1", "it1", "m1",
		"message.received", "bobcat builder", "tables bob", "pin cold", "c-gone", "it-deleted", "d-gone", "2026"} {
		if p := list(t, f, h, "audit.list", `{"q":`+strconv.Quote(q)+`}`); len(p.Entries) != 0 {
			t.Errorf("q %q matched %s", q, seqs(p))
		}
	}
	// "bank" is the name of share.pending's ref too: only item.revealed.
	if got := seqs(list(t, f, h, "audit.list", `{"q":"bank"}`)); got != "4" {
		t.Errorf("bank: %s", got)
	}
	// The names are those held when the vault answers: a renamed item and
	// a removed connection.
	f.SetItems(fakeItems{"it1": "Brokerage PIN"})
	delete(h.Conns, "c1")
	if got := seqs(list(t, f, h, "audit.list", `{"q":"bank"}`)); got != "" {
		t.Errorf("old item name still found: %s", got)
	}
	if got := seqs(list(t, f, h, "audit.list", `{"q":"brokerage"}`)); got != "4" {
		t.Errorf("new item name: %s", got)
	}
	if got := seqs(list(t, f, h, "audit.list", `{"q":"robert"}`)); got != "" {
		t.Errorf("removed connection still found: %s", got)
	}
	// Without the items feature, entries are found by kind, connection
	// and device only.
	g, hg := New(), featuretest.NewHost()
	rec(g, hg, t0, vault.Activity{Kind: "item.revealed", Ref: "it1", Audit: true})
	if p := list(t, g, hg, "audit.list", `{"q":"bank"}`); len(p.Entries) != 0 {
		t.Error("item name without the items feature")
	}
	// The entries are unchanged by a search (same JSON as without q).
	plain := featuretest.Call(f, h, t0, "app", "audit.list", `{"kinds":["item.revealed"]}`)
	found := featuretest.Call(f, h, t0, "app", "audit.list", `{"q":"item revealed"}`)
	if string(plain.Body) != string(found.Body) {
		t.Errorf("search changed the entries:\n%s\n%s", plain.Body, found.Body)
	}
}

// §10.9 (0.20.0): with q at most 2,000 entries that pass the other filters
// are evaluated; a budget run out before limit matches answers the
// matches so far, partial and the cursor of the last evaluated entry; no
// cursor is the end; with limit matches and entries left the cursor is the
// last returned, without partial; without q the budget does not apply.
func TestSearchBudget(t *testing.T) {
	f, h := New(), featuretest.NewHost()
	for i := 1; i <= 2500; i++ {
		k := "noise.entry"
		if i == 1 || i == 2400 || i == 2499 {
			k = "needle.found"
		}
		rec(f, h, t0.Add(time.Duration(i)*time.Millisecond), vault.Activity{Kind: k, Audit: true})
	}
	// Newest first: 2500..501 evaluated, matches 2499 and 2400.
	p := list(t, f, h, "audit.list", `{"q":"needle","limit":10}`)
	if seqs(p) != "2499,2400" || p.Partial == nil || p.NextBefore == nil || *p.NextBefore != 501 || p.NextAfter != nil {
		t.Fatalf("first page: %s %+v", seqs(p), p)
	}
	p = list(t, f, h, "audit.list", `{"q":"needle","limit":10,"before_seq":501}`)
	if seqs(p) != "1" || p.Partial != nil || p.NextBefore != nil {
		t.Fatalf("continuation: %s %+v", seqs(p), p)
	}
	// Nothing matched before the budget ran out: an empty partial page.
	p = list(t, f, h, "audit.list", `{"q":"needle","before_seq":2399}`)
	if len(p.Entries) != 0 || p.Partial == nil || p.NextBefore == nil || *p.NextBefore != 399 {
		t.Fatalf("empty partial page: %s %+v", seqs(p), p)
	}
	// limit reached before the budget: the cursor of the last returned.
	p = list(t, f, h, "audit.list", `{"q":"needle","limit":1}`)
	if seqs(p) != "2499" || p.Partial != nil || p.NextBefore == nil || *p.NextBefore != 2499 {
		t.Fatalf("limit page: %s %+v", seqs(p), p)
	}
	// limit reached, then the budget runs out looking further: still the
	// last returned's cursor, not partial.
	p = list(t, f, h, "audit.list", `{"q":"needle","limit":2}`)
	if seqs(p) != "2499,2400" || p.Partial != nil || p.NextBefore == nil || *p.NextBefore != 2400 {
		t.Fatalf("limit then budget: %s %+v", seqs(p), p)
	}
	// Oldest first: next_after_seq is the last evaluated.
	p = list(t, f, h, "audit.list", `{"q":"needle","after_seq":0}`)
	if seqs(p) != "1" || p.Partial == nil || p.NextAfter == nil || *p.NextAfter != 2000 || p.NextBefore != nil {
		t.Fatalf("after_seq: %s %+v", seqs(p), p)
	}
	p = list(t, f, h, "audit.list", `{"q":"needle","after_seq":2000}`)
	if seqs(p) != "2400,2499" || p.Partial != nil || p.NextAfter != nil {
		t.Fatalf("after_seq continuation: %s %+v", seqs(p), p)
	}
	// Exactly 2,000 entries pass the other filters, none after: the end.
	p = list(t, f, h, "audit.list", `{"q":"needle","before_seq":2001}`)
	if seqs(p) != "1" || p.Partial != nil || p.NextBefore != nil {
		t.Fatalf("exactly the budget: %s %+v", seqs(p), p)
	}
	// Entries the other filters exclude do not count: kinds.
	p = list(t, f, h, "audit.list", `{"q":"found","kinds":["needle"]}`)
	if seqs(p) != "2499,2400,1" || p.Partial != nil || p.NextBefore != nil {
		t.Fatalf("kinds before the budget: %s %+v", seqs(p), p)
	}
	// ... and the time range.
	p = list(t, f, h, "audit.list", `{"q":"needle","until":"`+t0.Add(2*time.Millisecond).Format(time.RFC3339Nano)+`"}`)
	if seqs(p) != "1" || p.Partial != nil {
		t.Fatalf("until before the budget: %s %+v", seqs(p), p)
	}
	// Without q no budget: the whole log, paged by limit.
	p = list(t, f, h, "audit.list", `{"kinds":["needle"],"limit":500}`)
	if seqs(p) != "2499,2400,1" || p.Partial != nil {
		t.Fatalf("without q: %s", seqs(p))
	}
}

// §10.9 (0.20.0): since inclusive, until exclusive, compared in Unix
// milliseconds, any offset; a filter, not a cursor (at need not grow with
// seq); either alone.
func TestSinceUntil(t *testing.T) {
	f, h := New(), featuretest.NewHost()
	rec(f, h, t0, vault.Activity{Kind: "a", Audit: true})                                     // 1
	rec(f, h, t0.Add(time.Second), vault.Activity{Kind: "b", Audit: true})                    // 2
	rec(f, h, t0.Add(2*time.Second), vault.Activity{Kind: "c", Audit: true})                  // 3
	rec(f, h, t0.Add(-time.Hour), vault.Activity{Kind: "d", Audit: true})                     // 4: the clock stepped back
	rec(f, h, t0.Add(time.Second+5*time.Millisecond), vault.Activity{Kind: "e", Audit: true}) // 5
	ts := func(d time.Duration) string { return t0.Add(d).Format(time.RFC3339Nano) }
	for _, c := range []struct{ body, want string }{
		{`{"since":"` + ts(time.Second) + `","until":"` + ts(2*time.Second) + `"}`, "5,2"},
		{`{"since":"` + ts(time.Second) + `"}`, "5,3,2"},
		{`{"until":"` + ts(time.Second) + `"}`, "4,1"},
		{`{"since":"2026-10-02T14:00:01+02:00","until":"2026-10-02T08:00:02-04:00"}`, "5,2"},
		{`{"since":"` + ts(time.Second+900*time.Microsecond) + `"}`, "5,3,2"}, // sub-millisecond: compared in ms
		{`{"until":"` + ts(time.Second+5*time.Millisecond) + `","since":"` + ts(time.Second+4*time.Millisecond) + `"}`, ""},
		{`{"since":"` + ts(time.Second+5*time.Millisecond) + `","until":"` + ts(time.Second+6*time.Millisecond) + `"}`, "5"},
		{`{"since":"` + ts(time.Second) + `","q":"b"}`, "2"},
		{`{"since":"` + ts(time.Second) + `","after_seq":2}`, "3,5"},
		{`{"since":"` + ts(0) + `","limit":1}`, "5"},
	} {
		if got := seqs(list(t, f, h, "audit.list", c.body)); got != c.want {
			t.Errorf("%s: %s, want %s", c.body, got, c.want)
		}
	}
	if p := list(t, f, h, "audit.list", `{"since":"`+ts(0)+`","limit":1}`); p.NextBefore == nil || *p.NextBefore != 5 {
		t.Errorf("cursor with a range: %+v", p)
	}
	if got := seqs(list(t, f, h, "connection.audit.list", `{"connection_id":"c1","since":"`+ts(0)+`"}`)); got != "" {
		t.Errorf("connection.audit.list range: %s", got)
	}
}

// §10.9 (0.20.0): bad_request for a bad q, a time that is not RFC 3339
// and since ≥ until, on both types; the kinds limit stays 16.
func TestSearchErrors(t *testing.T) {
	f, h := New(), featuretest.NewHost()
	kinds := func(n int) string { return `{"kinds":[` + strings.TrimSuffix(strings.Repeat(`"a",`, n), ",") + `]}` }
	for _, b := range []string{
		`{"q":""}`, `{"q":"` + strings.Repeat("x", MaxQ+1) + `"}`, `{"q":"` + strings.Repeat("é", 64) + `x"}`,
		`{"q":" "}`, `{"q":"   "}`, `{"q":" 　"}`, `{"q":"a\tb"}`, `{"q":"a\nb"}`, `{"q":"a\u0000"}`, `{"q":"a\u007f"}`,
		`{"q":"a\u0085"}`, `{"q":"a\u009f"}`, `{"q":5}`, `{"q":null}`, `{"q":["a"]}`,
		`{"since":"yesterday"}`, `{"since":5}`, `{"until":"2026-10-02"}`, `{"until":"2026-10-02 12:00:00Z"}`, `{"since":null}`,
		`{"since":"2026-10-02T12:00:00Z","until":"2026-10-02T12:00:00Z"}`,
		`{"since":"2026-10-02T12:00:01Z","until":"2026-10-02T12:00:00Z"}`,
		`{"since":"2026-10-02T12:00:00.0001Z","until":"2026-10-02T12:00:00.0009Z"}`, // the same millisecond
		`{"since":"2026-10-02T14:00:00+02:00","until":"2026-10-02T12:00:00Z"}`,
		kinds(MaxKinds + 1),
	} {
		if r := featuretest.Call(f, h, t0, "app", "audit.list", b); r.Code != "bad_request" {
			t.Errorf("audit.list %s: %q", b, r.Code)
		}
		cb := `{"connection_id":"c1",` + strings.TrimPrefix(b, "{")
		if r := featuretest.Call(f, h, t0, "app", "connection.audit.list", cb); r.Code != "bad_request" {
			t.Errorf("connection.audit.list %s: %q", cb, r.Code)
		}
	}
	for _, b := range []string{`{"q":"a"}`, `{"q":"` + strings.Repeat("x", MaxQ) + `"}`, `{"q":"` + strings.Repeat("é", 64) + `"}`,
		`{"q":" a "}`, `{"q":"\ud800"}`, `{"since":"2026-10-02T12:00:00Z","until":"2026-10-02T12:00:00.001Z"}`, kinds(MaxKinds)} {
		if r := featuretest.Call(f, h, t0, "app", "audit.list", b); !r.OK() {
			t.Errorf("audit.list %s: %q", b, r.Code)
		}
	}
	for _, k := range []string{"agent", "connection:c1"} {
		if r := featuretest.Call(f, h, t0, k, "audit.list", `{"q":"a"}`); r.Code != "forbidden" {
			t.Errorf("%s searched the audit log", k)
		}
	}
}

func FuzzValidQ(f *testing.F) {
	f.Add("password changed")
	f.Fuzz(func(t *testing.T, s string) {
		if !ValidQ(s) {
			return
		}
		if len(s) == 0 || len(s) > MaxQ || strings.TrimSpace(s) == "" || strings.ContainsAny(s, "\x00\t\n\x7f\u0085") {
			t.Fatalf("accepted %q", s)
		}
	})
}

// §10.9 (0.21.0, stating 0.20.0's behaviour): the budget runs out only
// when a 2,001st entry passing the other filters would be evaluated; a
// request that found limit matches by the 2,000th is not partial.
func TestSearchBudgetEdge(t *testing.T) {
	f, h := New(), featuretest.NewHost()
	for i := 1; i <= 2001; i++ {
		k := "noise.entry"
		if i == 2 {
			k = "needle.found"
		}
		rec(f, h, t0.Add(time.Duration(i)*time.Millisecond), vault.Activity{Kind: k, Audit: true})
	}
	// Newest first, 2001..2 evaluated: the 2,000th evaluated is the match.
	p := list(t, f, h, "audit.list", `{"q":"needle","limit":1}`)
	if seqs(p) != "2" || p.Partial != nil || p.NextBefore == nil || *p.NextBefore != 2 {
		t.Fatalf("limit at the 2,000th: %s %+v", seqs(p), p)
	}
	// Without the limit reached: entry 1 would be the 2,001st: partial.
	p = list(t, f, h, "audit.list", `{"q":"needle","limit":2}`)
	if seqs(p) != "2" || p.Partial == nil || p.NextBefore == nil || *p.NextBefore != 2 {
		t.Fatalf("budget out at the 2,001st: %s %+v", seqs(p), p)
	}
	// connection.audit.list takes after_seq (oldest first).
	p = list(t, f, h, "connection.audit.list", `{"connection_id":"c1","after_seq":0}`)
	if p.NextBefore != nil {
		t.Fatalf("connection.audit.list after_seq: %+v", p)
	}
}
