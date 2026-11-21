package envelope

import (
	"bytes"
	"runtime"
	"strings"
	"testing"

	"github.com/vettid/vettid-vault/vms/strictjson"
)

const wipeSecret = `{"secret":"s3cret-value","n":{"k":[1,"two"]}}`

func allZero(b []byte) bool { return bytes.Count(b, []byte{0}) == len(b) }

// ParseInner wipes every copy it makes of the input, on success and on
// each refusal, except the body it hands to the Inner; that body does not
// alias the input (which the caller wipes), and Inner.Wipe zeroes it.
func TestParseInnerWipesItsCopies(t *testing.T) {
	ok := `{"v":1,"id":"01HZZZZZZZZZZZZZZZZZZZZZZZ","type":"test.ping","ts":"2026-01-01T00:00:00.000Z","re":"01HZZZZZZZZZZZZZZZZZZZZZZY","status":"error","error":{"code":"not_found","message":"m","detail":` + wipeSecret + `},"features":["a"],"x":"unknown","body":` + wipeSecret + `}`
	cases := []struct {
		name, src string
		accept    bool
	}{
		{"accepted", ok, true},
		{"session seq missing in session mode", ok, false}, // parsed in ModeSession below
		{"body not an object", `{"v":1,"id":"01HZZZZZZZZZZZZZZZZZZZZZZZ","type":"test.ping","ts":"2026-01-01T00:00:00.000Z","x":` + wipeSecret + `,"body":[1]}`, false},
		{"bad features", `{"v":1,"id":"01HZZZZZZZZZZZZZZZZZZZZZZZ","type":"test.ping","ts":"2026-01-01T00:00:00.000Z","features":[1],"body":` + wipeSecret + `}`, false},
		{"validate refuses (empty type)", `{"v":1,"id":"01HZZZZZZZZZZZZZZZZZZZZZZZ","type":"","ts":"2026-01-01T00:00:00.000Z","body":` + wipeSecret + `}`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var seen strictjson.Object // the top level: the set that holds "v"
			var all []strictjson.Object
			testParsedHook = func(o strictjson.Object) {
				all = append(all, o)
				if o.Has("v") {
					seen = o
				}
			}
			defer func() { testParsedHook = nil }()
			mode := ModeSealed
			if c.name == "session seq missing in session mode" {
				mode = ModeSession
			}
			src := []byte(c.src)
			in, err := ParseInner(src, mode)
			if (err == nil) != c.accept {
				t.Fatalf("ParseInner error = %v, accept = %v", err, c.accept)
			}
			if seen == nil {
				t.Fatal("the parsed members were not seen")
			}
			for _, o := range all {
				for k, v := range o {
					if !allZero(v) {
						t.Fatalf("member %q kept its value: %q", k, v)
					}
				}
			}
			if c.name == "accepted" && len(all) != 3 {
				t.Fatalf("%d sets of members wiped, want 3 (top level, error, features)", len(all))
			}
			if !c.accept {
				// A refused message hands its body to nobody: its copy is
				// among the wiped members.
				if _, ok := seen["body"]; !ok {
					t.Fatal("a refused message's body was not among the wiped members")
				}
				return
			}
			if _, kept := seen["body"]; kept {
				t.Fatal("the body's copy stayed in the parsed members")
			}
			if string(in.Body) != wipeSecret {
				t.Fatalf("body = %q", in.Body)
			}
			i := bytes.Index(src, []byte(wipeSecret))
			if &in.Body[0] == &src[i] {
				t.Fatal("Body aliases the input")
			}
			in.Wipe()
			if !allZero(in.Body) || len(in.Body) != len(wipeSecret) {
				t.Fatal("Inner.Wipe left the body")
			}
		})
	}
	var nilIn *Inner
	nilIn.Wipe() // a nil Inner is a no-op
}

// ParseInner makes one copy of a body, the one the Inner owns: the bytes
// it allocates for a large body stay near that body's size. Checking the
// body by unmarshalling it, or copying it again, would add a copy each.
func TestParseInnerCopiesBodyOnce(t *testing.T) {
	head := `{"v":1,"id":"01HZZZZZZZZZZZZZZZZZZZZZZZ","type":"test.ping","ts":"2026-01-01T00:00:00.000Z","body":`
	small := []byte(head + `{"a":"x"}}`)
	const size = 1 << 16
	big := []byte(head + `{"a":"` + strings.Repeat("x", size) + `"}}`)
	alloc := func(b []byte) float64 {
		var m0, m1 runtime.MemStats
		runtime.ReadMemStats(&m0)
		for range 20 {
			if _, err := ParseInner(b, ModeSealed); err != nil {
				t.Fatal(err)
			}
		}
		runtime.ReadMemStats(&m1)
		return float64(m1.TotalAlloc-m0.TotalAlloc) / 20
	}
	extra := alloc(big) - alloc(small)
	if extra > 1.5*size {
		t.Fatalf("ParseInner allocates %.0f bytes more for a %d-byte body: more than one copy", extra, size)
	}
	t.Logf("%.0f extra bytes for a %d-byte body", extra, size)
}
