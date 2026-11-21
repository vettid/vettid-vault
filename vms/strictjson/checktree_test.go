package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"runtime"
	"strings"
	"testing"
)

// checkTreeDecoder is checkTree as it was before it stopped using a
// json.Decoder (whose buffer and value tokens are copies of the input that
// cannot be wiped). It is kept here as the reference the in-place walk is
// compared with.
func checkTreeDecoder(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var stack []frame
	first := true
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return ErrSyntax
		}
		if first {
			if d, ok := tok.(json.Delim); !ok || d != '{' {
				return ErrNotObject
			}
		} else if len(stack) == 0 {
			return ErrSyntax
		}
		first = false
		if len(stack) > 0 && stack[len(stack)-1].obj && stack[len(stack)-1].key {
			top := &stack[len(stack)-1]
			if d, ok := tok.(json.Delim); ok && d == '}' {
				stack = stack[:len(stack)-1]
				markValueDone(stack)
				continue
			}
			name, ok := tok.(string)
			if !ok {
				return ErrSyntax
			}
			if _, dup := top.names[name]; dup {
				return ErrDuplicate
			}
			top.names[name] = struct{}{}
			top.key = false
			continue
		}
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{':
				if len(stack) >= MaxDepth {
					return ErrDepth
				}
				stack = append(stack, frame{obj: true, names: map[string]struct{}{}, key: true})
			case '[':
				if len(stack) >= MaxDepth {
					return ErrDepth
				}
				stack = append(stack, frame{})
			case '}', ']':
				stack = stack[:len(stack)-1]
				markValueDone(stack)
			}
		default:
			markValueDone(stack)
		}
	}
	if first || len(stack) != 0 {
		return ErrSyntax
	}
	return nil
}

// sameAsDecoder fails t unless checkTree and checkTreeDecoder agree on b:
// both accept or both refuse, and with the same error whenever b is
// well-formed JSON. On malformed JSON with a second fault (a duplicate
// before the syntax error, say) the two may name different faults.
func sameAsDecoder(t *testing.T, b []byte) {
	t.Helper()
	got, want := checkTree(b), checkTreeDecoder(b)
	if (got == nil) != (want == nil) {
		t.Fatalf("checkTree(%q) = %v, the decoder's = %v", b, got, want)
	}
	if json.Valid(b) && !errors.Is(got, want) {
		t.Fatalf("checkTree(%q) = %v, the decoder's = %v (well-formed input)", b, got, want)
	}
}

// u is the start of a JSON \u escape, built so that no tool rewrites it.
var u = "\\" + "u"

var bs = "\\"

var treeCases = []string{
	// Escaped names are compared decoded (a = 0061, é = 00e9, a surrogate
	// pair for U+1F600 = d83d de00).
	`{"a":1,"` + u + `0061":2}`, `{"` + u + `0061":1,"a":2}`, `{"` + u + `0061":1,"` + u + `0061":2}`,
	`{"` + u + `00e9":1,"é":2}`, `{"` + u + `d83d` + u + `de00":1,"😀":2}`, `{"a":{"x":1,"` + u + `0078":2}}`,
	`{"` + u + `0061":1,"b":2}`, `{"` + u + `0022":1,"` + u + `0022":2}`, `{"` + u + `005c":1,"` + bs + bs + `":2}`,
	`{"a` + bs + `"b":1,"a` + u + `0022b":2}`, `{"` + u + `00":1}`, `{"` + u + `zzzz":1}`, `{"a":"` + u + `0061"}`,
	// Lone surrogates: the decoder makes each U+FFFD (ParseObject refuses
	// them earlier, but checkTree alone must agree).
	`{"` + u + `d800":1,"` + u + `fffd":2}`, `{"` + u + `dc00":1,"` + u + `d800":2}`, `{"` + u + `d800x":1,"` + u + `fffdx":2}`,
	`{"` + u + `d83d` + u + `0061":1,"` + u + `fffda":2}`, "{\"\xff" + bs + "u" + "d800\":1,\"" + u + "fffd" + u + "fffd\":2}",
	`{}`, ` { } `, `{"a":1}`, `{"a":1,"b":2}`, `{"a":1,"a":2}`,
	`{"a":{"b":1,"b":2}}`, `{"a":[{"b":1,"b":2}]}`, `{"a":[{"b":1},{"b":2}]}`,
	`{"a":{"b":1},"b":{"a":1}}`, `{"a":1,"a":2}`, `{"é":1,"é":2}`,
	`{"a\"b":1,"a\"b":2}`, `{"a\\":1,"a\\":2}`, `{"a":"\"}\"","b":"{\\"}`,
	`{"a":"x,\"a\":1"}`, `{"a":[1,"a",{"a":"a"}],"b":true,"c":null,"d":-1.5e3}`,
	`[]`, `"x"`, `null`, `1`, `true`, `x`, ``, ` `, `{} {}`, `{}x`, `{} `,
	`{"a":1,}`, `{"a" 1}`, `{"a":1 "b":2}`, `{,}`, `{,"a":1}`, `{"a"::1}`,
	`{"a":1:2}`, `{"a":[1,]}`, `{"a":[,1]}`, `{"a":]`, `{"a":[}`, `{"a":{]}`,
	`{1:2}`, `{[]:1}`, `{{}:1}`, `{"a":1`, `{"a":"x`, `{"a`, `{"a":tru}`,
	`{"a":nul}`, `{"a":01}`, `{"a":"\x"}`, `{"\x":1}`, `{"a":1}}`, `{"a":1}]`,
	"{\"\xff\":1,\"\xfe\":2}", "{\"\xff\":1,\"\xef\xbf\xbd\":2}", "{\"\xff\":1,\"" + bs + "ufffd\":2}",
	"{\"\xff" + bs + "/\":1,\"\xfe/\":2}", "{\"a\":\"\xff\",\"b\":1}", "{\"\xc3\":1,\"\xc3\xa9\":2}",
	`]`, `}`, `{]`, `[}`, "{\"a\":\"\t\"}", `{"a":1,"a":2`, `{"a":1 "a":2}`,
	strings.Repeat(`{"a":`, MaxDepth-1) + `1` + strings.Repeat(`}`, MaxDepth-1),
	strings.Repeat(`{"a":`, MaxDepth) + `1` + strings.Repeat(`}`, MaxDepth),
	strings.Repeat(`{"a":`, MaxDepth+1) + `1` + strings.Repeat(`}`, MaxDepth+1),
	`{"a":` + strings.Repeat(`[`, MaxDepth-1) + strings.Repeat(`]`, MaxDepth-1) + `}`,
	`{"a":` + strings.Repeat(`[`, MaxDepth) + strings.Repeat(`]`, MaxDepth) + `}`,
	`{"a":` + strings.Repeat(`[`, MaxDepth+5),
}

// TestCheckTreeMatchesDecoder compares the in-place walk with the decoder it
// replaced, over the edge cases and every prefix of each.
func TestCheckTreeMatchesDecoder(t *testing.T) {
	for _, c := range treeCases {
		for n := 0; n <= len(c); n++ {
			sameAsDecoder(t, []byte(c[:n]))
		}
	}
}

func FuzzCheckTreeMatchesDecoder(f *testing.F) {
	for _, c := range treeCases {
		f.Add([]byte(c))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		sameAsDecoder(t, b)
	})
}

// TestObjectWipe: Wipe zeroes every value ParseObject copied, and the
// copies do not alias the input.
func TestObjectWipe(t *testing.T) {
	in := []byte(`{"a":"secret","b":{"c":"secret2"},"d":[1,2]}`)
	keep := append([]byte(nil), in...)
	o, err := ParseObject(in)
	if err != nil {
		t.Fatal(err)
	}
	vals := make([]json.RawMessage, 0, len(o))
	for _, v := range o {
		vals = append(vals, v)
	}
	o.Wipe()
	for _, v := range vals {
		if len(v) == 0 || bytes.Count(v, []byte{0}) != len(v) {
			t.Fatalf("a value was not wiped: %q", v)
		}
	}
	if !bytes.Equal(in, keep) {
		t.Fatal("Wipe changed the input")
	}
}

func TestIsObjectMember(t *testing.T) {
	o, err := ParseObject([]byte(`{"o":{"x":1},"e":{},"a":[],"s":"{","n":null}`))
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]bool{"o": true, "e": true, "a": false, "s": false, "n": false, "missing": false} {
		if got := o.IsObjectMember(name); got != want {
			t.Errorf("IsObjectMember(%q) = %v, want %v", name, got, want)
		}
		_, err := o.Object(name)
		if (err == nil) != want {
			t.Errorf("Object(%q) and IsObjectMember disagree", name)
		}
	}
}

// TestCheckTreeAllocatesNoValues: the walk's allocations do not grow with
// the size of a value, as a decoder's copies of it would.
func TestCheckTreeAllocatesNoValues(t *testing.T) {
	small := []byte(`{"a":"x","b":12}`)
	big := []byte(`{"a":"` + strings.Repeat("x", 1<<16) + `","b":` + strings.Repeat("1", 1<<10) + `}`)
	bytesOf := func(b []byte) float64 {
		var ms [2]runtimeMem
		ms[0].read()
		for i := 0; i < 50; i++ {
			if err := checkTree(b); err != nil {
				t.Fatal(err)
			}
		}
		ms[1].read()
		return float64(ms[1].total-ms[0].total) / 50
	}
	s, b := bytesOf(small), bytesOf(big)
	if b > s+1024 {
		t.Fatalf("checkTree allocates %.0f bytes for a 64 KiB value, %.0f for a small one", b, s)
	}
}

type runtimeMem struct{ total uint64 }

func (m *runtimeMem) read() {
	var s runtime.MemStats
	runtime.ReadMemStats(&s)
	m.total = s.TotalAlloc
}

// validObject refuses exactly what ParseObject refuses, with the same
// error, on every hand-made and generated case.
func TestValidObjectMatchesParseObject(t *testing.T) {
	g := newJSONGen(7)
	inputs := append([]string(nil), treeCases...)
	for range 20000 {
		inputs = append(inputs, g.input())
	}
	for _, c := range inputs {
		b := []byte(c)
		_, perr := ParseObject(b)
		if verr := validObject(b); (verr == nil) != (perr == nil) || (perr != nil && verr != perr) {
			t.Fatalf("validObject(%q) = %v, ParseObject = %v", b, verr, perr)
		}
	}
}

// CompactObject copies its input once, into the result: validating makes
// no copy, and the output is sized up front.
func TestCompactObjectCopiesOnce(t *testing.T) {
	const size = 1 << 16
	in := []byte(`{ "a" : "` + strings.Repeat("x", size) + `" }`)
	var m0, m1 runtime.MemStats
	runtime.ReadMemStats(&m0)
	for range 20 {
		if _, err := CompactObject(in); err != nil {
			t.Fatal(err)
		}
	}
	runtime.ReadMemStats(&m1)
	if per := float64(m1.TotalAlloc-m0.TotalAlloc) / 20; per > 1.5*size {
		t.Fatalf("CompactObject allocates %.0f bytes for a %d-byte object: more than one copy", per, size)
	}
}
