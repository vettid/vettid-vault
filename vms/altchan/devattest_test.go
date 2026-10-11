package altchan

import (
	"bytes"
	"strings"
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

// 0.27.0 (§11.7, §11.7.1): an Android device_assertion may carry the
// chain of its key, 1 to 10 certificates; absent stays absent; a present
// but malformed chain rejects the object; unknown members (and `chain` on
// iOS, which has none) are ignored.
func TestDeviceAssertionChain(t *testing.T) {
	a, err := ParseDeviceAssertion([]byte(`{"platform":"android","sig":"AQ==","chain":["AQ==","Ag==","Aw=="]}`))
	if err != nil || len(a.Chain) != 3 || string(a.Chain[2]) != "\x03" {
		t.Fatalf("%+v %v", a, err)
	}
	if b, _ := a.Marshal(); string(b) != `{"platform":"android","sig":"AQ==","chain":["AQ==","Ag==","Aw=="]}` {
		t.Fatalf("%s", b)
	}
	if a, err := ParseDeviceAssertion([]byte(`{"platform":"android","sig":"AQ=="}`)); err != nil || a.Chain != nil {
		t.Fatalf("no chain: %+v %v", a, err)
	}
	eleven := `"AQ=="` + strings.Repeat(`,"AQ=="`, 10)
	for _, s := range []string{
		`{"platform":"android","sig":"AQ==","chain":[]}`,
		`{"platform":"android","sig":"AQ==","chain":null}`,
		`{"platform":"android","sig":"AQ==","chain":"AQ=="}`,
		`{"platform":"android","sig":"AQ==","chain":[1]}`,
		`{"platform":"android","sig":"AQ==","chain":[""]}`,
		`{"platform":"android","sig":"AQ==","chain":["not base64!"]}`,
		`{"platform":"android","sig":"AQ==","chain":["AQ=="],"chain":["AQ=="]}`,
		`{"platform":"android","sig":"AQ==","chain":[` + eleven + `]}`,
		`{"platform":"android","chain":["AQ=="]}`,
	} {
		if _, err := ParseDeviceAssertion([]byte(s)); err == nil {
			t.Errorf("%s accepted", s)
		}
	}
	ten := `"AQ=="` + strings.Repeat(`,"AQ=="`, 9)
	if a, err := ParseDeviceAssertion([]byte(`{"platform":"android","sig":"AQ==","chain":[` + ten + `]}`)); err != nil || len(a.Chain) != 10 {
		t.Fatalf("ten certificates: %v", err)
	}
	// Unknown members are ignored, and iOS has no chain.
	if a, err := ParseDeviceAssertion([]byte(`{"platform":"android","sig":"AQ==","later":{"x":1}}`)); err != nil || a.Chain != nil {
		t.Fatalf("unknown member: %v", err)
	}
	if a, err := ParseDeviceAssertion([]byte(`{"platform":"ios","assertion":"AQ==","chain":["AQ=="]}`)); err != nil || a.Chain != nil {
		t.Fatalf("ios with a chain member: %+v %v", a, err)
	}
	if _, err := (&DeviceAssertion{Platform: PlatformAndroid, Sig: []byte{1}, Chain: [][]byte{}}).Marshal(); err == nil {
		t.Fatal("an empty chain marshalled")
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
	f.Add([]byte(`{"platform":"android","sig":"AQ==","chain":["AQ==","Ag=="]}`))
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
