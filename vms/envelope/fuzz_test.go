package envelope

import (
	"bytes"
	"testing"

	"github.com/vettid/vettid-vault/vms/suite"
)

// §13.6: envelope and inner parsers MUST be fuzzed.

func FuzzParse(f *testing.F) {
	padded, _ := Pad([]byte(specInner))
	s, _ := SealSession(key32(8), suite.Kid{2}, suite.Kid{1}, padded)
	f.Add(s)
	k := testKey(f, 5)
	sl, _, _ := SealSealed(k.Public(), suite.Anonymous, padded)
	f.Add(sl)
	f.Add([]byte{2, 2, 1, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		e, err := Parse(b)
		if err != nil {
			return
		}
		if !bytes.Equal(e.Bytes(), b) || e.Len() != len(b) {
			t.Fatal("bytes changed")
		}
		if !ValidPaddedLen(e.PaddedLen()) || b[3] != 0 || b[0] != 2 || b[1] != 2 {
			t.Fatal("accepted non-canonical envelope")
		}
		// Decryption with a fixed key must fail cleanly, never panic.
		switch e.Mode() {
		case ModeSession:
			_, _ = OpenSession(e, key32(8))
		case ModeSealed:
			_, _, _ = OpenSealed(e, k)
		}
	})
}

func FuzzUnpad(f *testing.F) {
	p, _ := Pad([]byte(specInner))
	f.Add(p)
	f.Add(make([]byte, 512))
	f.Fuzz(func(t *testing.T, b []byte) {
		j, err := Unpad(b)
		if err != nil {
			return
		}
		again, err := Pad(j)
		if err != nil || !bytes.Equal(again, b) {
			t.Fatal("accepted padding is not canonical")
		}
	})
}

func FuzzPadRoundTrip(f *testing.F) {
	f.Add([]byte(specInner))
	f.Add([]byte{})
	f.Add([]byte{0x80, 0x00})
	f.Fuzz(func(t *testing.T, j []byte) {
		if len(j) > 0 && j[len(j)-1] == 0 {
			return // the marker scan cannot tell trailing zeros from padding; JSON never ends in 0x00
		}
		p, err := Pad(j)
		if err != nil {
			return
		}
		got, err := Unpad(p)
		if err != nil || !bytes.Equal(got, j) {
			t.Fatalf("round trip failed: %v", err)
		}
	})
}

func FuzzParseInner(f *testing.F) {
	f.Add([]byte(specInner), false)
	f.Add([]byte(`{"v":1,"id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V","type":"a.b","ts":"2026-10-01T12:00:00.000Z","seq":7,"re":"01JB2Z6V9K3M4N5P6Q7R8S9T0W","status":"error","error":{"code":"x","message":"m"},"body":{"k":[1,{"z":null}]}}`), true)
	f.Fuzz(func(t *testing.T, b []byte, session bool) {
		mode := ModeSealed
		if session {
			mode = ModeSession
		}
		in, err := ParseInner(b, mode)
		if err != nil {
			return
		}
		out, err := in.Marshal(mode)
		if err != nil {
			t.Fatalf("accepted inner does not re-marshal: %v", err)
		}
		in2, err := ParseInner(out, mode)
		if err != nil {
			t.Fatalf("re-marshalled inner rejected: %v", err)
		}
		out2, _ := in2.Marshal(mode)
		if !bytes.Equal(out, out2) {
			t.Fatal("marshal not stable")
		}
	})
}
