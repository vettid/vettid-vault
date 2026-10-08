package vault

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// roFeature has a step-up type with a read-only form (a dry run).
type roFeature struct{ handled int }

func (f *roFeature) Name() string { return "ro" }
func (f *roFeature) Types() []TypeSpec {
	return []TypeSpec{{Type: "test.ro", Request: true, From: []string{KindApp, KindDesktop}, DesktopApproval: true}}
}
func (f *roFeature) Handle(context.Context, *Session, *envelope.Inner) (json.RawMessage, error) {
	f.handled++
	return json.RawMessage(`{"dry":true}`), nil
}
func (f *roFeature) Load(json.RawMessage) error     { return nil }
func (f *roFeature) Save() (json.RawMessage, error) { return json.RawMessage(`{}`), nil }
func (f *roFeature) ReadOnly(_ string, b json.RawMessage) bool {
	o, err := strictjson.ParseObject(b)
	if err != nil {
		return false
	}
	d, _ := o.Bool("dry_run")
	return d
}

// §10.7, §6.8 (0.21.0): a desktop's read-only form of a step-up type is
// handled at once; the same type in its changing form is held. §10.1: the
// held-approvals limit names itself.
func TestReadOnlyFormsAndHeldLimit(t *testing.T) {
	f := newOCFixture(t)
	ro := &roFeature{}
	f.m.addFeature(ro)
	id := f.sendAs(f.desk, "test.ro", `{"dry_run":true}`)
	if ro.handled != 1 || len(f.m.st.Held) != 0 {
		t.Fatalf("dry run held: handled %d held %d", ro.handled, len(f.m.st.Held))
	}
	if r := find(f.inbox(f.desk)["desk1"], reply(id)); r == nil || errCode(r) != "" || string(r.Body) != `{"dry":true}` {
		t.Fatalf("dry run answer: %+v", r)
	}
	for i := 0; i < MaxHeldPerDevice; i++ {
		f.sendAs(f.desk, "test.ro", `{}`)
	}
	if ro.handled != 1 || len(f.m.st.Held) != MaxHeldPerDevice {
		t.Fatalf("not held: handled %d held %d", ro.handled, len(f.m.st.Held))
	}
	f.inbox(f.desk)
	id = f.sendAs(f.desk, "test.ro", `{}`)
	r := find(f.inbox(f.desk)["desk1"], reply(id))
	if errCode(r) != "limit" || string(r.Body) != `{"limit":"held_approvals","max":8}` {
		t.Fatalf("held limit: %+v", r)
	}
}

// §10.1 (0.21.0): the limit body.
func TestLimitBody(t *testing.T) {
	he := LimitError("items", 2000).(*HandlerError)
	if he.Code != "limit" || string(he.Body) != `{"limit":"items","max":2000}` {
		t.Fatalf("%s %s", he.Code, he.Body)
	}
	he = LimitSizeError("item_size", 65536, 70000).(*HandlerError)
	if string(he.Body) != `{"limit":"item_size","max":65536,"size":70000}` || LimitName(he) != "item_size" {
		t.Fatalf("%s", he.Body)
	}
	if LimitName(NewError("limit", "")) != "" || LimitName(errBadRequest) != "" || LimitName(nil) != "" {
		t.Fatal("LimitName of another error")
	}
}

// §10.8, §11.13 (0.21.0): the snapshot's email excludes C0, DEL, C1,
// U+2028 and U+2029; names exclude DEL too (both use the same set).
func TestAccountControlSet(t *testing.T) {
	for _, s := range []string{"m\u2028@example.org", "m\u2029@example.org", "m\u007f@example.org", "m\u0080@example.org",
		"m\u009f@example.org", "m\u001f@example.org"} {
		if ValidAccountEmail(s) {
			t.Errorf("email %q accepted", s)
		}
	}
	for _, s := range []string{"Ada\u007f", "A\u2028", "A\u2029", "A\u0085", "A\u0000"} {
		if ValidAccountName(s) {
			t.Errorf("name %q accepted", s)
		}
	}
	for _, s := range []string{"m @example.org", "ü@例え.jp", "a@b"} {
		if !ValidAccountEmail(s) {
			t.Errorf("email %q refused", s)
		}
	}
	for _, s := range []string{"Ada", "Zoë O’Brien-Smith", " x", strings.Repeat("é", 80)} {
		if !ValidAccountName(s) {
			t.Errorf("name %q refused", s)
		}
	}
}
