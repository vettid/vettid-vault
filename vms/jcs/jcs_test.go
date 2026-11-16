package jcs

import (
	"bytes"
	"testing"
)

func enc(t *testing.T, v any) string {
	t.Helper()
	var b bytes.Buffer
	if err := Append(&b, v); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// RFC 8785 for the documents' types: keys sorted by UTF-16 code units, the short escapes and lower-case \u00xx
// for the other controls, everything else (DEL, U+2028, '/', non-ASCII) as itself.
func TestAppend(t *testing.T) {
	// U+1F600 is a surrogate pair (D83D DE00), so it sorts before U+E000 by UTF-16 code units, after it by bytes.
	if got := enc(t, map[string]any{"\ue000": int64(1), "\U0001F600": int64(2)}); got != "{\"\U0001F600\":2,\"\ue000\":1}" {
		t.Fatalf("order: %s", got)
	}
	got := enc(t, []any{"a\u2028b", "/", "\x7f", "\x1f", "\b\f\n\r\t", "\"\\", "é", nil, true, false, int64(0), int64(9007199254740991)})
	want := "[\"a\u2028b\",\"/\",\"\x7f\",\"\\u001f\",\"\\b\\f\\n\\r\\t\",\"\\\"\\\\\",\"é\",null,true,false,0,9007199254740991]"
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	if err := Append(&bytes.Buffer{}, 1.5); err != ErrValue {
		t.Fatalf("a float: %v", err)
	}
}
