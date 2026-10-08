package itemspec

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
)

func TestNormalizeTag(t *testing.T) {
	ok := map[string]string{
		"Travel":                "travel",
		"  Dr  Lee  ":           "dr lee",
		"tax-2026":              "tax-2026",
		"a_b":                   "a_b",
		"0":                     "0",
		"MEDICAL  NOTES":        "medical notes",
		strings.Repeat("x", 32): strings.Repeat("x", 32),
	}
	for in, want := range ok {
		got, err := NormalizeTag(in, false)
		if err != nil || got != want {
			t.Errorf("NormalizeTag(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	bad := []string{"", "  ", "-a", "_a", " a!", "é", "a\tb", strings.Repeat("x", 33), "@profile", "@other", "a,b", "a.b"}
	for _, in := range bad {
		if got, err := NormalizeTag(in, false); err == nil {
			t.Errorf("NormalizeTag(%q) = %q, want an error", in, got)
		}
	}
	if got, err := NormalizeTag("@Profile", true); err != nil || got != ProfileTag {
		t.Errorf("reserved: %q %v", got, err)
	}
	if _, err := NormalizeTag("@other", true); err == nil {
		t.Error("only @profile is reserved")
	}
}

func raws(ss ...string) []json.RawMessage {
	var out []json.RawMessage
	for _, s := range ss {
		out = append(out, strictjson.MarshalString(s))
	}
	return out
}

func TestParseTags(t *testing.T) {
	got, err := ParseTags(raws("Travel", "identity", "travel", " ID  card "), 0, MaxTags, false)
	if err != nil || strings.Join(got, "|") != "id card|identity|travel" {
		t.Fatalf("%q %v", got, err)
	}
	if _, err := ParseTags(raws(), 1, MaxTags, false); err == nil {
		t.Error("min")
	}
	many := make([]string, 17)
	for i := range many {
		many[i] = "t" + strings.Repeat("x", i)
	}
	if _, err := ParseTags(raws(many...), 0, MaxTags, false); err == nil {
		t.Error("17 tags")
	}
	if _, err := ParseTags([]json.RawMessage{json.RawMessage(`1`)}, 0, MaxTags, false); err == nil {
		t.Error("not a string")
	}
}

func TestParseValue(t *testing.T) {
	good := map[string][]string{
		KindText:      {`""`, `"hello"`, `"tab-free text"`},
		KindMultiline: {`"a\nb\tc"`},
		KindPassword:  {`"p\tw\nd"`},
		KindNumber:    {`"42"`, `"-3.14"`, `"0.5"`},
		KindDate:      {`"2031-04-30"`, `"2031-04"`, `"2024-02-29"`},
		KindEmail:     {`"a@b.c"`, `"first.last+tag@example.org"`},
		KindPhone:     {`"+1 (555) 010-0100"`, `"112"`},
		KindURL:       {`"https://example.org/x?y=1"`, `"mailto:a@b.c"`},
		KindOTP:       {`"JBSWY3DPEHPK3PXP"`, `"jbswy3dpehpk3pxp"`, `"JBSWY3DPEHPK3PXP===="`, `"otpauth://totp/x?secret=JBSWY3DPEHPK3PXP"`},
		KindAddress:   {`{}`, `{"city":"Oslo","country":"NO"}`, `{"street":"1 Main St","street2":"","postal_code":"0150"}`},
	}
	for kind, vs := range good {
		for _, v := range vs {
			if _, err := ParseValue(kind, json.RawMessage(v)); err != nil {
				t.Errorf("%s %s: %v", kind, v, err)
			}
		}
	}
	bad := map[string][]string{
		KindText:     {`"a\nb"`, `"a\u0000"`, `1`, `null`},
		KindNumber:   {`"1e5"`, `"1."`, `"abc"`, `"--1"`},
		KindDate:     {`"2031-13-01"`, `"2023-02-29"`, `"31-04-2031"`, `"2031-4-30"`},
		KindEmail:    {`"no-at"`, `"a@"`, `"@b"`, `"a b@c"`, `"a@b@c"`},
		KindPhone:    {`"call me"`, `"+-()"`, `"` + strings.Repeat("1", 33) + `"`},
		KindURL:      {`"/relative"`, `"https://a b"`, `"example.org"`},
		KindOTP:      {`"SHORT"`, `"JBSWY3DPEHPK3PX1"`, `"otpauth://x y"`},
		KindAddress:  {`{"city":1}`, `{"planet":"Mars"}`, `{"country":"nor"}`, `{"city":"a\nb"}`, `"Oslo"`},
		KindFile:     {`"blob"`},
		"nonsense":   {`"x"`},
		KindPassword: {`"a\u0001"`},
	}
	for kind, vs := range bad {
		for _, v := range vs {
			if _, err := ParseValue(kind, json.RawMessage(v)); err == nil {
				t.Errorf("%s %s accepted", kind, v)
			}
		}
	}
	big := `"` + strings.Repeat("x", MaxValue+1) + `"`
	if _, err := ParseValue(KindMultiline, json.RawMessage(big)); err == nil {
		t.Error("value over 16 KiB")
	}
	// Canonical forms.
	v, _ := ParseValue(KindAddress, json.RawMessage(`{"country":"NO","city":"Oslo","street":""}`))
	if string(v) != `{"city":"Oslo","country":"NO"}` {
		t.Errorf("address canonical: %s", v)
	}
	v, _ = ParseValue(KindText, json.RawMessage(`"<&>"`))
	if string(v) != `"<&>"` {
		t.Errorf("string canonical: %s", v)
	}
}

func content(t *testing.T, body string) *ContentIn {
	t.Helper()
	o, err := strictjson.ParseObject([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseContent(o)
	if err != nil {
		t.Fatalf("ParseContent(%s): %v", body, err)
	}
	return c
}

func TestContentAndFieldIDs(t *testing.T) {
	c := content(t, `{"name":"Passport","category":"identity_document","template":"passport",
		"fields":[{"label":"Number","kind":"text","value":"X1"},{"label":"Expires","kind":"date","value":"2031-04-30"}],"notes":"n"}`)
	it := &Item{ID: "01JB2Z6V9K3M4N5P6Q7R8S9T0V", Sensitivity: Data, NextField: 1}
	if !c.Apply(it, nil) {
		t.Fatal("apply")
	}
	if it.Fields[0].ID != "f1" || it.Fields[1].ID != "f2" || it.NextField != 3 {
		t.Fatalf("ids: %+v", it.Fields)
	}
	cur := it.Clone()
	// Keep f2 (relabelled), drop f1, add a field: f3, never f1 again.
	c = content(t, `{"name":"Passport","fields":[{"field_id":"f2","label":"Expiry","kind":"date","value":"2031-05-01"},
		{"label":"Country","kind":"text","value":"NO"}]}`)
	if !c.Apply(it, cur) {
		t.Fatal("apply 2")
	}
	if it.Fields[0].ID != "f2" || it.Fields[0].Label != "Expiry" || it.Fields[1].ID != "f3" || it.Category != "other" {
		t.Fatalf("after: %+v", it)
	}
	// A field id the item does not have is refused.
	c = content(t, `{"name":"x","fields":[{"field_id":"f9","label":"L","kind":"text","value":""}]}`)
	if c.Apply(it.Clone(), it) {
		t.Error("unknown field id applied")
	}
	if c.Apply(&Item{NextField: 1}, nil) {
		t.Error("a new item cannot name field ids")
	}
	// Bad contents.
	for _, b := range []string{`{}`, `{"name":""}`, `{"name":"a\nb"}`, `{"name":"x","category":"Bad"}`, `{"name":"x","template":"T T"}`,
		`{"name":"x","fields":[{"label":"","kind":"text","value":""}]}`, `{"name":"x","fields":[{"label":"L","kind":"text"}]}`,
		`{"name":"x","fields":[{"label":"L","kind":"file","value":"b"}]}`,
		`{"name":"x","fields":[{"field_id":"f1","label":"L","kind":"text","value":""},{"field_id":"f1","label":"L","kind":"text","value":""}]}`,
		`{"name":"x","notes":"` + strings.Repeat("n", MaxNotes+1) + `"}`} {
		o, err := strictjson.ParseObject([]byte(b))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseContent(o); err == nil {
			t.Errorf("ParseContent(%.60s) accepted", b)
		}
	}
}

func TestEncodings(t *testing.T) {
	ts := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	it := &Item{ID: "01JB2Z6V9K3M4N5P6Q7R8S9T0V", Version: 2, Name: "Login", Category: "login", Sensitivity: Secret,
		Tags: []string{"work"}, Notes: "note", Created: ts, Updated: ts,
		Fields: []Field{{ID: "f1", Label: "User", Kind: KindText, Value: json.RawMessage(`"al"`)},
			{ID: "f2", Label: "Password", Kind: KindPassword, Value: json.RawMessage(`"pw"`)}}}
	with, without := string(it.JSON(true)), string(it.JSON(false))
	if !strings.Contains(with, `"value":"pw"`) || !strings.Contains(with, `"notes":"note"`) || !strings.Contains(with, `"tags":["work"]`) {
		t.Errorf("with values: %s", with)
	}
	if strings.Contains(without, `"value"`) || strings.Contains(without, "note\"") || !strings.Contains(without, `"has_notes":true`) {
		t.Errorf("without values: %s", without)
	}
	c := string(it.Content([]string{"f2"}))
	if c != `{"item_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V","version":2,"name":"Login","category":"login","fields":[{"field_id":"f2","label":"Password","kind":"password","value":"pw"}]}` {
		t.Errorf("content: %s", c)
	}
	if strings.Contains(string(it.Content(nil)), "work") || strings.Contains(string(MetaOf(it, nil).JSON()), "work") {
		t.Error("tags in shared content or metadata")
	}
	m := MetaOf(it, []string{"f1"})
	if len(m.Labels) != 1 || m.Labels[0].ID != "f1" || strings.Contains(string(m.JSON()), "al\"") {
		t.Errorf("meta: %+v", m)
	}
	ls, err := ParseLabels(LabelsJSON(MetaOf(it, nil).Labels))
	if err != nil || len(ls) != 2 {
		t.Fatalf("labels round trip: %v", err)
	}
}

func TestTermsAndMatching(t *testing.T) {
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	parse := func(b string) (*Terms, error) {
		o, err := strictjson.ParseObject([]byte(b))
		if err != nil {
			t.Fatal(err)
		}
		return ParseTerms(o, now)
	}
	tm, err := parse(`{"tags":["Medical","dr lee"]}`)
	if err != nil || tm.Match != MatchAny || tm.Mode != ModeAsk || tm.Access != AccessRead || !tm.IncludeExisting || tm.Uses != 0 {
		t.Fatalf("defaults: %+v %v", tm, err)
	}
	if !tm.TagsMatch([]string{"medical"}) || tm.TagsMatch([]string{"travel"}) {
		t.Error("any")
	}
	tm.Match = MatchAll
	if tm.TagsMatch([]string{"medical"}) || !tm.TagsMatch([]string{"dr lee", "medical", "x"}) {
		t.Error("all")
	}
	if !tm.GainedTag([]string{"medical"}, []string{"dr lee", "medical"}) || tm.GainedTag([]string{"medical"}, []string{"medical", "x"}) {
		t.Error("gained")
	}
	for _, b := range []string{`{}`, `{"tags":[]}`, `{"tags":["@profile"]}`, `{"tags":["a"],"match":"some"}`, `{"tags":["a"],"access":"write"}`,
		`{"tags":["a"],"mode":"always"}`, `{"tags":["a"],"uses":0}`, `{"tags":["a"],"uses":10001}`,
		`{"tags":["a"],"expires_at":"2026-10-03T11:00:00.000Z"}`, `{"tags":["a"],"expires_at":"2037-10-03T11:00:00.000Z"}`,
		`{"tags":["a"],"include_existing":"yes"}`} {
		if _, err := parse(b); err == nil {
			t.Errorf("ParseTerms(%s) accepted", b)
		}
	}
	tm, err = parse(`{"tags":["a"],"mode":"auto","uses":10,"expires_at":"2027-10-03T12:00:00.000Z","include_existing":false}`)
	if err != nil || tm.Mode != ModeAuto || tm.Uses != 10 || tm.IncludeExisting || !tm.InForce(now) || tm.InForce(now.AddDate(2, 0, 0)) {
		t.Fatalf("%+v %v", tm, err)
	}
	b := strictjson.NewBuilder()
	tm.JSONMembers(b)
	if got := string(b.Bytes()); got != `{"tags":["a"],"match":"any","access":"read","mode":"auto","uses":10,"expires_at":"2027-10-03T12:00:00.000Z","include_existing":false}` {
		t.Errorf("terms JSON: %s", got)
	}
}

func FuzzParseContent(f *testing.F) {
	f.Add([]byte(`{"name":"x","fields":[{"label":"L","kind":"address","value":{"city":"Oslo"}}],"notes":"n"}`))
	f.Add([]byte(`{"name":"x","category":"login","fields":[{"field_id":"f1","label":"L","kind":"otp","value":"JBSWY3DPEHPK3PXP"}]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		o, err := strictjson.ParseObject(b)
		if err != nil {
			return
		}
		c, err := ParseContent(o)
		if err != nil {
			return
		}
		it := &Item{NextField: 1}
		if c.Apply(it, nil) {
			// The encoding of an accepted item parses back as strict JSON.
			if _, err := strictjson.ParseObject(it.JSON(true)); err != nil {
				t.Fatalf("encoding does not parse: %v", err)
			}
		}
	})
}

func FuzzParseValue(f *testing.F) {
	f.Add("text", []byte(`"x"`))
	f.Add("address", []byte(`{"country":"NO"}`))
	f.Add("otp", []byte(`"otpauth://totp/a?secret=JBSWY3DPEHPK3PXP"`))
	f.Fuzz(func(t *testing.T, kind string, b []byte) {
		v, err := ParseValue(kind, b)
		if err != nil {
			return
		}
		// Canonical: parsing the canonical form gives the same bytes.
		v2, err := ParseValue(kind, v)
		if err != nil || string(v2) != string(v) {
			t.Fatalf("not canonical: %s -> %s (%v)", v, v2, err)
		}
	})
}

func FuzzNormalizeTag(f *testing.F) {
	f.Add("  Dr  Lee ")
	f.Add("@profile")
	f.Fuzz(func(t *testing.T, s string) {
		n, err := NormalizeTag(s, true)
		if err != nil {
			return
		}
		if n2, err := NormalizeTag(n, true); err != nil || n2 != n {
			t.Fatalf("not idempotent: %q -> %q", n, n2)
		}
	})
}

func FuzzParseTerms(f *testing.F) {
	f.Add([]byte(`{"tags":["a","b"],"match":"all","mode":"auto","uses":3}`))
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	f.Fuzz(func(t *testing.T, b []byte) {
		o, err := strictjson.ParseObject(b)
		if err != nil {
			return
		}
		tm, err := ParseTerms(o, now)
		if err != nil {
			return
		}
		if len(tm.Tags) == 0 || len(tm.Tags) > MaxTags {
			t.Fatalf("tags: %v", tm.Tags)
		}
	})
}

func FuzzParseLabels(f *testing.F) {
	f.Add([]byte(`[{"field_id":"f1","label":"L","kind":"text"}]`))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = ParseLabels(b)
	})
}

// docs/item-templates.json, the registry the apps share, must describe
// items the vault accepts (§10.7).
func TestTemplateRegistry(t *testing.T) {
	b, err := os.ReadFile("../../docs/item-templates.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := strictjson.ParseObject(b); err != nil {
		t.Fatalf("not strict JSON: %v", err)
	}
	var reg struct {
		Categories []struct {
			Category string `json:"category"`
		} `json:"categories"`
		Templates []struct {
			Template    string   `json:"template"`
			Name        string   `json:"name"`
			Category    string   `json:"category"`
			Sensitivity string   `json:"sensitivity"`
			Tags        []string `json:"tags"`
			Fields      []struct {
				Label string `json:"label"`
				Kind  string `json:"kind"`
			} `json:"fields"`
		} `json:"templates"`
	}
	if err := json.Unmarshal(b, &reg); err != nil {
		t.Fatal(err)
	}
	cats := map[string]bool{}
	for _, c := range reg.Categories {
		if !ValidCategory(c.Category) {
			t.Errorf("category %q", c.Category)
		}
		cats[c.Category] = true
	}
	for _, c := range RecommendedCategories {
		if !cats[c] {
			t.Errorf("recommended category %q missing", c)
		}
	}
	seen := map[string]bool{}
	for _, tp := range reg.Templates {
		if !templateRE.MatchString(tp.Template) || seen[tp.Template] || !ValidName(tp.Name) || !cats[tp.Category] || !ValidSensitivity(tp.Sensitivity) {
			t.Errorf("template %+v", tp)
		}
		seen[tp.Template] = true
		for _, tag := range tp.Tags {
			// No template carries a reserved tag: only the member puts an
			// item into the shared profile (owner decision 2026-10-08).
			n, err := NormalizeTag(tag, false)
			if err != nil || n != tag || strings.HasPrefix(tag, "@") {
				t.Errorf("%s: tag %q", tp.Template, tag)
			}
		}
		if len(tp.Fields) > MaxFields || tp.Sensitivity == Critical && len(tp.Fields) > MaxCritFields {
			t.Errorf("%s: %d fields", tp.Template, len(tp.Fields))
		}
		for _, f := range tp.Fields {
			if !ValidLabel(f.Label) || !ValidKind(f.Kind) {
				t.Errorf("%s: field %+v", tp.Template, f)
			}
		}
	}
}
