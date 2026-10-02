package altchan

import (
	"bytes"
	"testing"
)

func TestDeviceAttestRoundTrip(t *testing.T) {
	for _, d := range []*DeviceAttest{
		{Platform: PlatformAndroid, Chain: [][]byte{{1, 2}, {3}}},
		{Platform: PlatformIOS, KeyID: []byte{1}, Attestation: []byte{2, 3}},
	} {
		b, err := d.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		got, err := ParseDeviceAttest(b)
		if err != nil {
			t.Fatal(err)
		}
		b2, _ := got.Marshal()
		if !bytes.Equal(b, b2) {
			t.Fatal("not canonical")
		}
	}
	bad := []string{
		`{"platform":"web","chain":["AQ=="]}`,
		`{"platform":"android","chain":[]}`,
		`{"platform":"android","chain":["AQ"]}`,
		`{"platform":"android","chain":[1]}`,
		`{"platform":"android","chain":["AQ==","AQ==","AQ==","AQ==","AQ==","AQ==","AQ==","AQ==","AQ==","AQ==","AQ=="]}`,
		`{"platform":"ios","attestation":"AQ=="}`,
		`{"platform":"ios","key_id":"","attestation":"AQ=="}`,
		`{"chain":["AQ=="]}`,
		`{"platform":"android","platform":"android","chain":["AQ=="]}`,
	}
	for _, s := range bad {
		if _, err := ParseDeviceAttest([]byte(s)); err == nil {
			t.Errorf("%s accepted", s)
		}
	}
}

func TestDeviceAssertion(t *testing.T) {
	for _, s := range []string{`{"platform":"android","sig":"AQ=="}`, `{"platform":"ios","assertion":"AQ=="}`} {
		a, err := ParseDeviceAssertion([]byte(s))
		if err != nil {
			t.Fatal(err)
		}
		if b, _ := a.Marshal(); string(b) != s {
			t.Fatalf("%s", b)
		}
	}
	for _, s := range []string{`{"platform":"android"}`, `{"platform":"ios","sig":"AQ=="}`, `{"platform":"x","sig":"AQ=="}`} {
		if _, err := ParseDeviceAssertion([]byte(s)); err == nil {
			t.Errorf("%s accepted", s)
		}
	}
}

func FuzzParseDeviceAttest(f *testing.F) {
	f.Add([]byte(`{"platform":"android","chain":["AQ==","Ag=="]}`))
	f.Add([]byte(`{"platform":"ios","key_id":"AQ==","attestation":"Ag=="}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		d, err := ParseDeviceAttest(b)
		if err != nil {
			return
		}
		out, err := d.Marshal()
		if err != nil {
			t.Fatal("accepted object does not re-marshal")
		}
		if _, err := ParseDeviceAttest(out); err != nil {
			t.Fatal("re-marshalled object rejected")
		}
	})
}

func FuzzParseDeviceAssertion(f *testing.F) {
	f.Add([]byte(`{"platform":"android","sig":"AQ=="}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		a, err := ParseDeviceAssertion(b)
		if err != nil {
			return
		}
		if _, err := a.Marshal(); err != nil {
			t.Fatal("accepted object does not re-marshal")
		}
	})
}
