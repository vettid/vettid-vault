package items

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/vettid/vettid-vault/features/itemspec"
	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
)

// §10.8 (0.19.0): the 196,608-byte limit is checked with each name
// counted as a 322-byte JSON string (the encoder escapes only `"` and `\`
// in names), not with the current names.
func TestProfileSizeWorstCaseNames(t *testing.T) {
	if n := len(strictjson.MarshalString(worstName)); n != 322 {
		t.Fatalf("worst-case name encodes to %d bytes", n)
	}
	for _, s := range []string{strings.Repeat(`\`, 160), strings.Repeat("é", 80), strings.Repeat("<&>", 53) + "x"} {
		if !vault.ValidAccountName(s) || len(strictjson.MarshalString(s)) > 322 {
			t.Fatalf("%q encodes to %d bytes", s, len(strictjson.MarshalString(s)))
		}
	}
	f := New(nil)
	it := &itemspec.Item{ID: "01JB2Z6V9K3M4N5P6Q7R8S9T0V", Name: "Big", Category: "contact", Sensitivity: itemspec.Data,
		Tags: []string{itemspec.ProfileTag}}
	f.st.Items[it.ID] = it
	short := &Core{FirstName: "A", LastName: "B", IK: make([]byte, 32)}
	size := func(pad int) (int, error) {
		v, _ := json.Marshal(strings.Repeat("x", pad))
		it.Fields = []itemspec.Field{{ID: "f1", Label: "L", Kind: "text", Value: v}}
		return len(f.bodyWith(short, strictjson.MaxSafeInteger)), f.checkProfile()
	}
	base, _ := size(0)
	// Fits with the current (short) names, not with the longest ones.
	if n, err := size(MaxProfileUpdate - base - 100); n > MaxProfileUpdate || err != errLimit {
		t.Fatalf("near the limit: %d bytes, %v", n, err)
	}
	// 2 × (322 − 3) bytes of headroom: accepted.
	if _, err := size(MaxProfileUpdate - base - 2*(322-3)); err != nil {
		t.Fatalf("with room for the longest names: %v", err)
	}
	if _, err := size(MaxProfileUpdate - base - 2*(322-3) + 1); err != errLimit {
		t.Fatalf("one byte over with the longest names: %v", err)
	}
}
