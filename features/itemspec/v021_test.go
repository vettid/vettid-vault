package itemspec

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/vettid/vettid-vault/internal/strictjson"
)

func parseC(t *testing.T, body string) (*ContentIn, error) {
	t.Helper()
	o, err := strictjson.ParseObject([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	return ParseContent(o)
}

// §10.7 (0.21.0): fields without value only with a field_id; keep_notes
// boolean, never with notes; file stays reserved.
func TestParseContentKept(t *testing.T) {
	c, err := parseC(t, `{"name":"x","keep_notes":true,"fields":[{"field_id":"f1","label":"L","kind":"text"},{"label":"N","kind":"text","value":"v"}]}`)
	if err != nil || !c.KeepNotes || !c.Fields[0].Keep || c.Fields[1].Keep || !c.Keeps() {
		t.Fatalf("%+v %v", c, err)
	}
	if c, _ := parseC(t, `{"name":"x","keep_notes":false}`); c.KeepNotes || c.Keeps() {
		t.Fatal("keep_notes false")
	}
	for _, b := range []string{
		`{"name":"x","fields":[{"label":"L","kind":"text"}]}`,
		`{"name":"x","notes":"n","keep_notes":true}`,
		`{"name":"x","keep_notes":1}`,
		`{"name":"x","fields":[{"label":"L","kind":"file","value":"x"}]}`,
		`{"name":"x","fields":[{"field_id":"f1","label":"L","kind":"file"}]}`,
		`{"name":"x","fields":[{"field_id":"f1","label":"L","kind":"text","value":null}]}`,
	} {
		if _, err := parseC(t, b); err == nil {
			t.Errorf("accepted %s", b)
		}
	}
	// notes "" with keep_notes is notes given: refused too.
	if _, err := parseC(t, `{"name":"x","notes":"","keep_notes":true}`); err == nil {
		t.Error("empty notes with keep_notes")
	}
}

// §10.7 (0.21.0): Apply takes kept values from cur (a copy), refuses a
// kind change, keeps nothing of a new item.
func TestApplyKept(t *testing.T) {
	cur := &Item{ID: "i", Name: "x", Notes: "old", NextField: 3, Fields: []Field{
		{ID: "f1", Label: "A", Kind: KindPassword, Value: json.RawMessage(`"s"`)},
		{ID: "f2", Label: "B", Kind: KindAddress}}}
	c, _ := parseC(t, `{"name":"y","keep_notes":true,"fields":[{"field_id":"f2","label":"B2","kind":"address"},{"field_id":"f1","label":"A","kind":"password"}]}`)
	it := cur.Clone()
	if !c.Apply(it, cur) || it.Notes != "old" || it.Fields[0].ID != "f2" || string(it.Fields[0].Value) != `{}` ||
		string(it.Fields[1].Value) != `"s"` || it.Fields[0].Label != "B2" {
		t.Fatalf("%+v", it)
	}
	it.Fields[1].Value[1] = 'X'
	if string(cur.Fields[0].Value) != `"s"` {
		t.Fatal("kept value aliased")
	}
	c, _ = parseC(t, `{"name":"y","fields":[{"field_id":"f1","label":"A","kind":"text"}]}`)
	if c.Apply(cur.Clone(), cur) {
		t.Fatal("kind change kept")
	}
	c, _ = parseC(t, `{"name":"y","keep_notes":true}`)
	if c.Apply(&Item{}, nil) {
		t.Fatal("keep_notes on a new item")
	}
}

// §10.7 Size (0.21.0): the content encoding without the vault's members.
func TestSizeEncoding(t *testing.T) {
	it := &Item{ID: "01JB2Z6V9K3M4N5P6Q7R8S9T0V", Version: 7, Name: "N", Category: "other", Sensitivity: Secret, NextField: 2,
		Fields: []Field{{ID: "f1", Label: "L", Kind: KindText, Value: json.RawMessage(strictjson.MarshalString("a\u2028<b>"))}}}
	want := `{"name":"N","category":"other","sensitivity":"secret","tags":[],"fields":[{"label":"L","kind":"text","value":"a\u2028<b>"}]}`
	if got := string(it.sizeEncoding()); got != want || it.Size() != len(want) {
		t.Fatalf("%s", got)
	}
	if strings.Contains(string(it.sizeEncoding()), "f1") || strings.Contains(string(it.sizeEncoding()), it.ID) {
		t.Fatal("vault-assigned members counted")
	}
	// Smaller than the full item.get encoding: everything accepted before
	// is accepted now.
	if it.Size() >= len(it.JSON(true)) {
		t.Fatal("not smaller")
	}
	it.Sensitivity = Critical
	it.RecordSize()
	it.Tags = []string{"abc"}
	if n, ok := it.CurrentSize(); !ok || n != it.Size() {
		t.Fatalf("recorded %d, now %d", n, it.Size())
	}
	if _, ok := (&Item{Sensitivity: Critical}).CurrentSize(); ok {
		t.Fatal("a critical item never opened has a size")
	}
}
