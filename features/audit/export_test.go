package audit

import (
	"bytes"
	"encoding/base64"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/featuretest"
	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// fakeCred stands in for the credential feature: the holder, an open
// alarm's freeze code, and UTKs whose sealed payload opens to a PIN.
type fakeCred struct {
	holder string
	alarm  string
	utks   map[string]string // utk_id → the PIN its payload carries
	spent  []string
}

func (c *fakeCred) HolderGate(s *vault.Session) error {
	if from := s.From(); from.Kind != vault.KindApp || from.Recovering || from.ID != c.holder {
		return vault.NewError("forbidden", "")
	}
	if c.alarm != "" {
		return vault.NewError(c.alarm, "")
	}
	return nil
}

func (c *fakeCred) SpendPIN(s *vault.Session, _ *envelope.Inner, utkID string, _ []byte) ([]byte, error) {
	if err := c.HolderGate(s); err != nil {
		return nil, err
	}
	pin, ok := c.utks[utkID]
	if !ok {
		return nil, vault.NewError("utk_invalid", "")
	}
	delete(c.utks, utkID)
	c.spent = append(c.spent, utkID)
	if len(pin) < 6 || len(pin) > 32 || strings.Trim(pin, "0123456789") != "" {
		return nil, vault.NewError("bad_request", "")
	}
	return []byte(pin), nil
}

// exportFixture: the search fixture (13 entries, names for q), the
// fake credential with dev-app as the holder, and the feature as the
// host's sink so that audit.exported is appended.
func exportFixture(t *testing.T) (*Feature, *featuretest.Host, *fakeCred) {
	f, h := searchFixture(t)
	h.Sinks = append(h.Sinks, f)
	h.PIN = "246810"
	c := &fakeCred{holder: "dev-app", utks: map[string]string{}}
	f.SetCredential(c)
	return f, h, c
}

type preview struct {
	Count     uint64
	More      bool
	Upto      uint64
	UptoHash  string
	Oldest    uint64
	Newest    uint64
	OldestAt  string
	NewestAt  string
	HasRange  bool
	EntrySeq  uint64
	HasEntry  bool
	Raw       string
	Code      string
	ErrorBody string
}

func parsePreview(t *testing.T, r featuretest.Result) preview {
	t.Helper()
	if !r.OK() {
		return preview{Code: r.Code, ErrorBody: string(r.Body)}
	}
	o := r.Obj(t)
	p := preview{Raw: string(r.Body)}
	var err error
	if p.Count, err = o.Uint("count", 0, ExportMax); err != nil {
		t.Fatalf("count: %s", r.Body)
	}
	if p.More, err = o.Bool("more"); err != nil {
		t.Fatalf("more: %s", r.Body)
	}
	if p.Upto, err = o.Uint("upto_seq", 0, strictjson.MaxSafeInteger); err != nil {
		t.Fatalf("upto_seq: %s", r.Body)
	}
	if p.UptoHash, err = o.String("upto_hash"); err != nil {
		t.Fatalf("upto_hash: %s", r.Body)
	}
	if o.Has("oldest_seq") {
		p.HasRange = true
		p.Oldest, _ = o.Uint("oldest_seq", 1, strictjson.MaxSafeInteger)
		p.Newest, _ = o.Uint("newest_seq", 1, strictjson.MaxSafeInteger)
		p.OldestAt, _ = o.String("oldest_at")
		p.NewestAt, _ = o.String("newest_at")
		if p.OldestAt == "" || p.NewestAt == "" {
			t.Fatalf("range without times: %s", r.Body)
		}
	}
	if o.Has("entry_seq") {
		p.HasEntry = true
		p.EntrySeq, _ = o.Uint("entry_seq", 1, strictjson.MaxSafeInteger)
	}
	return p
}

func dryRun(t *testing.T, f *Feature, h *featuretest.Host, kind, filters string) preview {
	t.Helper()
	body := `{"dry_run":true` + filters + `}`
	return parsePreview(t, featuretest.Call(f, h, t0.Add(time.Hour), kind, "audit.export", body))
}

// export sends an export with a fresh UTK whose payload carries pin.
func export(t *testing.T, f *Feature, h *featuretest.Host, c *fakeCred, pin, members string) preview {
	t.Helper()
	id := "u" + strconv.Itoa(len(c.spent)+len(c.utks)+1)
	c.utks[id] = pin
	body := `{"utk_id":"` + id + `","sealed":"AAAA"` + members + `}`
	return parsePreview(t, featuretest.Call(f, h, t0.Add(time.Hour), "app", "audit.export", body))
}

func ts(sec int) string { return envelope.FormatTS(t0.Add(time.Duration(sec) * time.Second)) }

// §10.9 (0.22.0): the preview counts what audit.list's filters match
// (connection_id, kinds, q, since, until, and together), newest first,
// with the range and the bound (the log's newest seq and head); it needs
// no PIN, spends no UTK and writes no entry.
func TestExportPreviewFilters(t *testing.T) {
	f, h, c := exportFixture(t)
	head := f.Entries()[12].Hash
	for _, tc := range []struct {
		filters        string
		count          uint64
		oldest, newest uint64
	}{
		{"", 13, 1, 13},
		{`,"connection_id":"c1"`, 2, 2, 5},
		{`,"kinds":["message"]`, 2, 2, 7},
		{`,"kinds":["item","device"]`, 5, 3, 11},
		{`,"q":"bobcat"`, 2, 2, 5},
		{`,"q":"pixel"`, 1, 3, 3},
		{`,"since":"` + ts(10) + `"`, 3, 11, 13},
		{`,"until":"` + ts(3) + `"`, 3, 1, 3},
		{`,"since":"` + ts(1) + `","until":"` + ts(4) + `"`, 3, 2, 4},
		{`,"kinds":["message"],"q":"bob"`, 1, 2, 2},
		{`,"connection_id":"c1","since":"` + ts(3) + `"`, 1, 5, 5},
		{`,"format":"csv","kinds":["wallet"]`, 1, 5, 5},
	} {
		p := dryRun(t, f, h, "app", tc.filters)
		if p.Code != "" || p.Count != tc.count || p.More || p.Oldest != tc.oldest || p.Newest != tc.newest {
			t.Errorf("filters %s: %+v", tc.filters, p)
			continue
		}
		if p.Upto != 13 || p.UptoHash != base64.StdEncoding.EncodeToString(head) {
			t.Errorf("filters %s: bound %d %s", tc.filters, p.Upto, p.UptoHash)
		}
		if p.OldestAt != ts(int(tc.oldest)-1) || p.NewestAt != ts(int(tc.newest)-1) {
			t.Errorf("filters %s: times %s %s", tc.filters, p.OldestAt, p.NewestAt)
		}
	}
	// Nothing matches: count 0, no range, still the bound.
	if p := dryRun(t, f, h, "app", `,"kinds":["nothing"]`); p.Code != "" || p.Count != 0 || p.HasRange || p.Upto != 13 {
		t.Errorf("no match: %+v", p)
	}
	if len(f.Entries()) != 13 || len(c.spent) != 0 || h.HasActivity(KindExported) {
		t.Fatal("a preview wrote an entry or spent a UTK")
	}
	// audit.list's bad_request rules, and no cursor, limit, PIN or bound.
	for _, bad := range []string{
		`,"q":"  "`, `,"kinds":[]`, `,"connection_id":""`, `,"since":"yesterday"`,
		`,"since":"` + ts(5) + `","until":"` + ts(5) + `"`, `,"format":"xml"`, `,"format":1`,
		`,"before_seq":5`, `,"after_seq":0`, `,"limit":10`, `,"utk_id":"u1"`, `,"sealed":"AAAA"`, `,"upto_seq":13`,
	} {
		if p := dryRun(t, f, h, "app", bad); p.Code != "bad_request" {
			t.Errorf("dry run %s: %+v", bad, p)
		}
	}
	if r := featuretest.Call(f, h, t0, "app", "audit.export", `{"dry_run":"yes"}`); r.Code != "bad_request" {
		t.Errorf("dry_run not a boolean: %q", r.Code)
	}
}

// §10.9 (0.22.0): audit.export evaluates q over the whole log, without
// audit.list's 2,000-entry budget, so the count is exact; at most the cap,
// newest first, with more beyond it.
func TestExportWholeLogAndCap(t *testing.T) {
	f, h := New(), featuretest.NewHost()
	f.SetCredential(&fakeCred{holder: "dev-app"})
	for i := 1; i <= 2500; i++ {
		k := "noise.entry"
		if i == 1 || i == 2400 || i == 2499 {
			k = "needle.found"
		}
		rec(f, h, t0.Add(time.Duration(i)*time.Millisecond), vault.Activity{Kind: k, Audit: true})
	}
	if p := list(t, f, h, "audit.list", `{"q":"needle"}`); p.Partial == nil {
		t.Fatal("audit.list did not run out of its budget")
	}
	if p := dryRun(t, f, h, "app", `,"q":"needle"`); p.Count != 3 || p.More || p.Oldest != 1 || p.Newest != 2499 || p.Upto != 2500 {
		t.Fatalf("whole-log q: %+v", p)
	}
	f.exportMax = 2
	if p := dryRun(t, f, h, "app", `,"q":"needle"`); p.Count != 2 || !p.More || p.Oldest != 2400 || p.Newest != 2499 {
		t.Fatalf("cap: %+v", p)
	}
	if p := dryRun(t, f, h, "app", `,"q":"needle","until":"`+envelope.FormatTS(t0.Add(2400*time.Millisecond))+`"`); p.Count != 1 || p.More {
		t.Fatalf("under the cap: %+v", p)
	}
}

// §10.9 (0.22.0): the holder's app only: a desktop (at once), an agent,
// a recovering app and an app that is not the holder are forbidden.
func TestExportHolderOnly(t *testing.T) {
	f, h, c := exportFixture(t)
	for _, kind := range []string{"desktop", "agent", "recovering-app", "app2", "connection:c1"} {
		if r := featuretest.Call(f, h, t0, kind, "audit.export", `{"dry_run":true}`); r.Code != "forbidden" {
			t.Errorf("%s: %q", kind, r.Code)
		}
	}
	// Without the credential feature: forbidden.
	g, hg := New(), featuretest.NewHost()
	if r := featuretest.Call(g, hg, t0, "app", "audit.export", `{"dry_run":true}`); r.Code != "forbidden" {
		t.Errorf("no credential: %q", r.Code)
	}
	if len(c.spent) != 0 {
		t.Fatal("spent")
	}
}

// §10.9 (0.22.0) steps 1–6 in order: the clone alarm (preview included,
// the UTK unspent), the UTK, the shape, not_found, the PIN; a wrong PIN is
// bad_pin and not a failed owner check; the right PIN appends exactly one
// audit.exported and answers entry_seq.
func TestExportCheckOrder(t *testing.T) {
	f, h, c := exportFixture(t)
	all := `,"format":"json","upto_seq":13`
	// 1. A clone alarm refuses the preview and the export with its freeze
	// code before anything else: even a malformed body, the UTK unspent.
	for _, code := range []string{"credential_frozen", "rotation_required"} {
		c.alarm = code
		if p := dryRun(t, f, h, "app", ""); p.Code != code {
			t.Errorf("preview during %s: %+v", code, p)
		}
		if p := export(t, f, h, c, "246810", all); p.Code != code {
			t.Errorf("export during %s: %+v", code, p)
		}
		if r := featuretest.Call(f, h, t0, "app", "audit.export", `{"utk_id":7}`); r.Code != code {
			t.Errorf("malformed export during %s: %q", code, r.Code)
		}
	}
	if len(c.spent) != 0 || len(c.utks) != 2 {
		t.Fatalf("a UTK was spent during the alarm: %v", c.spent)
	}
	c.alarm, c.utks = "", map[string]string{}
	// The UTK: unknown or spent is utk_invalid; without utk_id or sealed
	// (no UTK to spend) bad_request.
	if r := featuretest.Call(f, h, t0, "app", "audit.export", `{"utk_id":"nope","sealed":"AAAA","format":"json","upto_seq":13}`); r.Code != "utk_invalid" {
		t.Errorf("unknown UTK: %q", r.Code)
	}
	for _, b := range []string{`{"format":"json","upto_seq":13}`, `{"utk_id":"u9","format":"json","upto_seq":13}`, `{"utk_id":"u9","sealed":"!!","upto_seq":13}`} {
		if r := featuretest.Call(f, h, t0, "app", "audit.export", b); r.Code != "bad_request" {
			t.Errorf("%s: %q", b, r.Code)
		}
	}
	// 2. The shape, after the UTK is spent: a bad filter, format, PIN or
	// upto_seq (0, above the newest seq, not an integer).
	before := len(c.spent)
	for _, m := range []string{
		`,"format":"json","upto_seq":13,"q":""`, `,"format":"json","upto_seq":13,"limit":5`,
		`,"format":"pdf","upto_seq":13`, `,"upto_seq":13`, `,"format":"csv"`,
		`,"format":"csv","upto_seq":0`, `,"format":"csv","upto_seq":14`, `,"format":"csv","upto_seq":"13"`, `,"format":"csv","upto_seq":1.5`,
	} {
		if p := export(t, f, h, c, "000000", m); p.Code != "bad_request" {
			t.Errorf("shape %s: %+v", m, p)
		}
	}
	if p := export(t, f, h, c, "12", all); p.Code != "bad_request" {
		t.Errorf("short PIN: %+v", p)
	}
	if len(c.spent) != before+10 {
		t.Fatalf("the shape was checked before the UTK was spent: %d", len(c.spent)-before)
	}
	// 3. Nothing matches: not_found before the PIN is tried (a wrong PIN
	// is not counted).
	if p := export(t, f, h, c, "999999", `,"format":"json","upto_seq":13,"kinds":["nothing"]`); p.Code != "not_found" {
		t.Errorf("no match: %+v", p)
	}
	if h.HasActivity("vault.pin_failed") {
		t.Fatal("PIN tried before not_found")
	}
	// 5. A wrong PIN: bad_pin, not a failed owner check (no failure count,
	// no owner_check.failed entry or feed item), no audit.exported.
	n := len(f.Entries())
	if p := export(t, f, h, c, "999999", all); p.Code != "bad_pin" {
		t.Errorf("wrong PIN: %+v", p)
	}
	if len(h.CheckFailed) != 0 || h.HasActivity("owner_check.failed") || h.HasActivity(KindExported) || len(f.Entries()) != n {
		t.Fatalf("a wrong export PIN was a failed owner check: %v %v", h.CheckFailed, h.Activities)
	}
	for _, a := range h.Activities {
		if a.Feed {
			t.Fatalf("feed item %+v", a)
		}
	}
	// 6. The right PIN: exactly one audit.exported (device_id = the app,
	// no connection), the preview's answer and entry_seq.
	p := export(t, f, h, c, "246810", `,"format":"json","upto_seq":13,"kinds":["message"]`)
	if p.Code != "" || p.Count != 2 || p.Oldest != 2 || p.Newest != 7 || p.Upto != 13 || p.More || !p.HasEntry {
		t.Fatalf("export: %+v", p)
	}
	es := f.Entries()
	if len(es) != n+1 {
		t.Fatalf("%d entries appended", len(es)-n)
	}
	e := es[len(es)-1]
	if e.Kind != KindExported || e.DeviceID != "dev-app" || e.ConnectionID != "" || e.Seq != p.EntrySeq ||
		e.Ref != "format=json;count=2;seqs=2-7;filters=kinds" {
		t.Fatalf("audit.exported %+v (entry_seq %d)", e, p.EntrySeq)
	}
	if p.UptoHash != base64.StdEncoding.EncodeToString(es[12].Hash) {
		t.Fatal("upto_hash is not the hash of upto_seq's entry")
	}
	for _, a := range h.Activities {
		if a.Kind == KindExported && a.Feed {
			t.Fatal("an export made a feed item")
		}
	}
}

// §10.9 (0.22.0): upto_seq bounds the export: entries written after the
// preview, audit.exported among them, are not counted; an earlier bound
// counts below it and answers its entry's hash.
func TestExportUptoBound(t *testing.T) {
	f, h, c := exportFixture(t)
	pre := dryRun(t, f, h, "app", `,"kinds":["message"]`)
	if pre.Count != 2 || pre.Upto != 13 {
		t.Fatalf("preview %+v", pre)
	}
	rec(f, h, t0.Add(20*time.Second), vault.Activity{Kind: "message.received", ConnectionID: "c1", Audit: true}) // 14
	p := export(t, f, h, c, "246810", `,"format":"csv","kinds":["message"],"upto_seq":13`)
	if p.Code != "" || p.Count != 2 || p.Newest != 7 || p.Upto != 13 || p.UptoHash != pre.UptoHash || p.EntrySeq != 15 {
		t.Fatalf("bounded export: %+v", p)
	}
	// The newest entry is now audit.exported (15): a fresh preview counts
	// it and the message written meanwhile; an export bounded at 14 does
	// not count the export.
	if q := dryRun(t, f, h, "app", ""); q.Count != 15 || q.Upto != 15 || q.Newest != 15 {
		t.Fatalf("fresh preview %+v", q)
	}
	p = export(t, f, h, c, "246810", `,"format":"json","upto_seq":14`)
	if p.Code != "" || p.Count != 14 || p.Newest != 14 || p.Upto != 14 ||
		p.UptoHash != base64.StdEncoding.EncodeToString(f.Entries()[13].Hash) {
		t.Fatalf("export at 14: %+v", p)
	}
	if r := f.Entries()[len(f.Entries())-1]; r.Ref != "format=json;count=14;seqs=1-14;filters=none" {
		t.Fatalf("summary %q", r.Ref)
	}
	// A bound below every match: not_found.
	if p := export(t, f, h, c, "246810", `,"format":"json","upto_seq":1,"kinds":["message"]`); p.Code != "not_found" {
		t.Fatalf("below every match: %+v", p)
	}
}

// §10.9 (0.22.0): audit.exported's ref, key=value pairs in order, the
// filters named (connection,kinds,q,dates) but never their values, and
// since/until as UTC in the ts format.
func TestExportSummary(t *testing.T) {
	f, h, c := exportFixture(t)
	for _, tc := range []struct{ members, want string }{
		{`,"format":"json"`, "format=json;count=13;seqs=1-13;filters=none"},
		{`,"format":"csv","kinds":["item","device"],"since":"2026-10-02T08:00:03-04:00","until":"` + ts(11) + `"`,
			"format=csv;count=4;seqs=4-11;filters=kinds,dates;since=2026-10-02T12:00:03.000Z;until=2026-10-02T12:00:11.000Z"},
		{`,"format":"json","connection_id":"c1","q":"Bobcat"`, "format=json;count=2;seqs=2-5;filters=connection,q"},
		{`,"format":"json","until":"` + ts(2) + `"`, "format=json;count=2;seqs=1-2;filters=dates;until=2026-10-02T12:00:02.000Z"},
		{`,"format":"csv","connection_id":"c1","kinds":["message"],"q":"sent","since":"` + ts(0) + `"`,
			"format=csv;count=1;seqs=2-2;filters=connection,kinds,q,dates;since=2026-10-02T12:00:00.000Z"},
	} {
		p := export(t, f, h, c, "246810", tc.members+`,"upto_seq":13`)
		if p.Code != "" {
			t.Errorf("%s: %+v", tc.members, p)
			continue
		}
		e := f.Entries()[len(f.Entries())-1]
		if e.Kind != KindExported || e.Ref != tc.want {
			t.Errorf("%s: ref %q, want %q", tc.members, e.Ref, tc.want)
		}
		for _, leak := range []string{"c1", "message", "Bobcat", "bobcat", "sent", "item"} {
			if strings.Contains(e.Ref, leak) {
				t.Errorf("summary names %q: %s", leak, e.Ref)
			}
		}
	}
	// The chain holds across the exports.
	prev := make([]byte, 32)
	for _, e := range f.Entries() {
		if !bytes.Equal(e.Prev, prev) || !bytes.Equal(e.Hash, Hash(prev, &e)) {
			t.Fatalf("entry %d does not chain", e.Seq)
		}
		prev = e.Hash
	}
}

// FuzzParseExport: audit.export's parser never panics; an accepted export
// (not a dry run) has a format, a bound, a UTK id and a sealed payload; a
// dry run has none of the export's members.
func FuzzParseExport(f *testing.F) {
	for _, s := range []string{`{"dry_run":true}`, `{"dry_run":true,"format":"csv","q":"bob"}`,
		`{"utk_id":"0011223344556677","sealed":"AAAA","format":"json","upto_seq":5,"kinds":["item"]}`,
		`{"utk_id":"x","sealed":"AAAA","since":"2026-10-01T00:00:00Z","until":"2026-10-02T00:00:00Z"}`, `[]`, `{"dry_run":1}`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := parseExport(b)
		if err != nil || r.shape != nil {
			return
		}
		if r.dryRun && (r.utkID != "" || r.sealed != nil || r.hasUpto) {
			t.Fatalf("dry run with export members: %s", b)
		}
		if !r.dryRun && (r.format == "" || !r.hasUpto || r.upto < 1 || r.utkID == "") {
			t.Fatalf("export without its members: %s", b)
		}
	})
}

// §10.9 Order of checks (0.23.0, errata to 0.22.0): the sender and the
// holder (forbidden) before the clone alarm; the alarm before anything
// about the body; then bad_request at once for a request without a
// spendable UTK (not a JSON object, dry_run not a boolean, a preview with
// utk_id, sealed or upto_seq, an export without a readable utk_id and
// sealed) — the UTK unspent; only then the export's steps (the spend
// first).
func TestExportErrataOrder(t *testing.T) {
	f, h, c := exportFixture(t)
	c.alarm = "credential_frozen"
	c.utks["u1"] = "246810"
	for _, kind := range []string{"desktop", "agent", "app2", "recovering-app"} {
		if r := featuretest.Call(f, h, t0, kind, "audit.export", `{"utk_id":"u1","sealed":"AAAA","format":"json","upto_seq":13}`); r.Code != "forbidden" {
			t.Errorf("%s during an alarm: %q (the holder check comes first)", kind, r.Code)
		}
	}
	for _, b := range []string{`[]`, `{"dry_run":"yes"}`, `{"dry_run":true,"utk_id":"u1"}`} {
		if r := featuretest.Call(f, h, t0, "app", "audit.export", b); r.Code != "credential_frozen" {
			t.Errorf("%s during an alarm: %q", b, r.Code)
		}
	}
	c.alarm = ""
	for _, b := range []string{`[]`, `{"dry_run":"yes"}`, `{"dry_run":1}`, `{"dry_run":true,"utk_id":"u1"}`, `{"dry_run":true,"sealed":"AAAA"}`,
		`{"dry_run":true,"upto_seq":3}`, `{"sealed":"AAAA","format":"json","upto_seq":13}`, `{"utk_id":"u1","format":"json","upto_seq":13}`,
		`{"utk_id":"u1","sealed":7,"format":"json","upto_seq":13}`, `{"utk_id":"","sealed":"AAAA","format":"json","upto_seq":13}`} {
		if r := featuretest.Call(f, h, t0, "app", "audit.export", b); r.Code != "bad_request" {
			t.Errorf("%s: %q", b, r.Code)
		}
	}
	if len(c.spent) != 0 || c.utks["u1"] == "" {
		t.Fatalf("a UTK was spent before the export's steps: %v", c.spent)
	}
	// With a spendable UTK, a bad filter costs it (the export's step 2).
	if r := featuretest.Call(f, h, t0, "app", "audit.export", `{"utk_id":"u1","sealed":"AAAA","format":"pdf","upto_seq":13}`); r.Code != "bad_request" || len(c.spent) != 1 {
		t.Fatalf("shape after the spend: %q %v", r.Code, c.spent)
	}
}

// §10.9 (0.23.0): the preview of an empty log answers count 0, upto_seq
// 0 and upto_hash 32 zero bytes (audit.list's head then); an export can
// then only be bad_request (upto_seq ≥ 1 is required).
func TestExportEmptyLog(t *testing.T) {
	f := New()
	h := featuretest.NewHost()
	c := &fakeCred{holder: "dev-app", utks: map[string]string{"u1": "246810"}}
	f.SetCredential(c)
	p := parsePreview(t, featuretest.Call(f, h, t0, "app", "audit.export", `{"dry_run":true}`))
	if p.Code != "" || p.Count != 0 || p.More || p.Upto != 0 || p.HasRange || p.UptoHash != base64.StdEncoding.EncodeToString(make([]byte, 32)) {
		t.Fatalf("empty preview %+v", p)
	}
	l := featuretest.Call(f, h, t0, "app", "audit.list", `{}`)
	if !l.OK() || !strings.Contains(string(l.Body), `"head":"`+base64.StdEncoding.EncodeToString(make([]byte, 32))+`"`) {
		t.Fatalf("audit.list head: %s", l.Body)
	}
	for _, upto := range []string{"0", "1"} {
		if r := featuretest.Call(f, h, t0, "app", "audit.export", `{"utk_id":"u1","sealed":"AAAA","format":"json","upto_seq":`+upto+`}`); r.Code != "bad_request" {
			t.Fatalf("export of an empty log (upto %s): %q", upto, r.Code)
		}
		c.utks["u1"] = "246810"
	}
}
