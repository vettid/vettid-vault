package vaultipc

import (
	"bytes"
	"net/http"
	"testing"
)

func TestHeadersRoundTrip(t *testing.T) {
	h := http.Header{"Content-Type": {"application/json"}, "X-Vettid-Key": {"abc"}, "Accept": {"a", "b"}}
	g, err := DecodeHeaders(EncodeHeaders(h))
	if err != nil || len(g) != 3 || len(g["Accept"]) != 2 || g.Get("X-Vettid-Key") != "abc" {
		t.Fatalf("%v %v", g, err)
	}
	for _, bad := range [][]byte{nil, {0}, {0, 1}, {0, 1, 0, 1, 'a'}, append(EncodeHeaders(h), 0),
		EncodeHeaders(http.Header{"Bad Name": {"x"}}), EncodeHeaders(http.Header{"A": {"x\ny"}})} {
		if _, err := DecodeHeaders(bad); err == nil {
			t.Errorf("accepted %x", bad)
		}
	}
}

func FuzzDecodeHeaders(f *testing.F) {
	f.Add(EncodeHeaders(http.Header{"A": {"b"}}))
	f.Add([]byte{0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		h, err := DecodeHeaders(b)
		if err != nil {
			return
		}
		h2, err := DecodeHeaders(EncodeHeaders(h))
		if err != nil || len(h2) != len(h) {
			t.Fatal("round trip")
		}
		_ = bytes.Equal
	})
}
