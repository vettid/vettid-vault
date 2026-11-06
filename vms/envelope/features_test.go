package envelope

import (
	"strings"
	"testing"
	"time"
)

// 0.86.0 (§5.3, §10.8): the inner `features` member round-trips, sits
// before body, and a malformed list is refused like any malformed known
// member; a message without it is unchanged.
func TestInnerFeatures(t *testing.T) {
	id, _ := NewULID(time.Now())
	ts := time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC)
	in := &Inner{ID: id, Type: "hs.confirm", TS: ts, Features: []string{"hs_confirm", "vote"}}
	j, err := in.Marshal(ModeSealed)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(j), `"features":["hs_confirm","vote"],"body":{}`) {
		t.Fatalf("encoding %s", j)
	}
	out, err := ParseInner(j, ModeSealed)
	if err != nil || len(out.Features) != 2 || out.Features[0] != "hs_confirm" {
		t.Fatalf("parse %v %v", out, err)
	}
	plain := &Inner{ID: id, Type: "x.y", TS: ts}
	pj, _ := plain.Marshal(ModeSealed)
	if strings.Contains(string(pj), "features") {
		t.Fatal("an absent list was written")
	}
	if p, err := ParseInner(pj, ModeSealed); err != nil || p.Features != nil {
		t.Fatal("absent list not nil")
	}
	for _, bad := range []string{`[]`, `["b","a"]`, `["a","a"]`, `["A"]`, `["a-b"]`, `[1]`, `"a"`, `["` + strings.Repeat("a", 33) + `"]`} {
		raw := strings.Replace(string(pj), `"body":{}`, `"features":`+bad+`,"body":{}`, 1)
		if _, err := ParseInner([]byte(raw), ModeSealed); err == nil {
			t.Fatalf("accepted features %s", bad)
		}
	}
	for _, bad := range [][]string{{}, {"b", "a"}, {"x y"}} {
		in := &Inner{ID: id, Type: "x.y", TS: ts, Features: bad}
		if _, err := in.Marshal(ModeSealed); err == nil {
			t.Fatalf("marshalled features %v", bad)
		}
	}
}
