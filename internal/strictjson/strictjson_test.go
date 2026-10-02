package strictjson

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestParseObject(t *testing.T) {
	good := []string{
		`{}`, ` { "a" : 1 } `, `{"a":{"a":1},"b":[{"a":1},{"a":2}]}`, `{"a":"é"}`,
	}
	for _, s := range good {
		if _, err := ParseObject([]byte(s)); err != nil {
			t.Errorf("%s: %v", s, err)
		}
	}
	bad := map[string]error{
		`{"a":1,"a":2}`:         ErrDuplicate,
		`{"a":{"b":1,"b":2}}`:   ErrDuplicate,
		`{"a":[{"b":1,"b":2}]}`: ErrDuplicate,
		`[]`:                    ErrNotObject,
		`"x"`:                   ErrNotObject,
		`null`:                  ErrNotObject,
		``:                      ErrSyntax,
		`{} {}`:                 ErrSyntax,
		`{}x`:                   ErrSyntax,
		`{"a":1,}`:              ErrSyntax,
		`{"a" 1}`:               ErrSyntax,
		"{\"a\":\"\xff\"}":      ErrUTF8,
		strings.Repeat(`{"a":`, 40) + `1` + strings.Repeat(`}`, 40): ErrDepth,
	}
	for s, want := range bad {
		if _, err := ParseObject([]byte(s)); !errors.Is(err, want) {
			t.Errorf("%q: err = %v, want %v", s, err, want)
		}
	}
}

func TestUint(t *testing.T) {
	o, _ := ParseObject([]byte(`{"a":1,"c":1.0,"d":-1,"e":1e3,"f":"1","g":9007199254740991,"h":9007199254740992,"i":0}`))
	if v, err := o.Uint("a", 1, 10); err != nil || v != 1 {
		t.Fatal("a")
	}
	if _, err := parseUint(json.RawMessage("01"), 0, 5); err == nil {
		t.Error("leading zero accepted")
	}
	for _, n := range []string{"c", "d", "e", "f"} {
		if _, err := o.Uint(n, 0, 1<<62); err == nil {
			t.Errorf("%s accepted", n)
		}
	}
	if _, err := o.Uint("g", 0, 1<<62); err != nil {
		t.Fatal("max safe integer rejected")
	}
	if _, err := o.Uint("h", 0, 1<<62); err == nil {
		t.Fatal("2^53 accepted")
	}
	if _, err := o.Uint("i", 1, 5); !errors.Is(err, ErrValue) {
		t.Fatal("range")
	}
	if _, err := o.Uint("missing", 0, 1); !errors.Is(err, ErrMissing) {
		t.Fatal("missing")
	}
}

func TestBase64Strict(t *testing.T) {
	if b, err := DecodeStd("AAEC", 3); err != nil || len(b) != 3 {
		t.Fatal("good")
	}
	for _, s := range []string{"AAE", "AAEC\n", "AA\r\nEC", "AAF=", "-_8=", "AAEC===="} {
		if _, err := DecodeStd(s, -1); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
	if _, err := DecodeStd("AAEC", 4); err == nil {
		t.Fatal("length not enforced")
	}
	if _, err := DecodeRawURL("-_8", 2); err != nil {
		t.Fatal("rawurl")
	}
	for _, s := range []string{"-_8=", "+/8", "-_9"} {
		if _, err := DecodeRawURL(s, -1); err == nil {
			t.Errorf("rawurl %q accepted", s)
		}
	}
}

func TestBuilderNoHTMLEscape(t *testing.T) {
	b := NewBuilder().String("a", "<&>").Uint("n", 3).Bool("t", true).Raw("o", []byte(`{}`)).Bytes()
	if string(b) != `{"a":"<&>","n":3,"t":true,"o":{}}` {
		t.Fatalf("%s", b)
	}
	if !json.Valid(b) {
		t.Fatal("invalid")
	}
}

func FuzzParseObject(f *testing.F) {
	f.Add([]byte(`{"a":[1,{"b":null}],"c":"d"}`))
	f.Add([]byte(`{"a":1,"a":2}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		o, err := ParseObject(b)
		if err != nil {
			return
		}
		if !json.Valid(b) {
			t.Fatal("accepted invalid JSON")
		}
		for k := range o {
			_ = o.Has(k)
		}
	})
}
