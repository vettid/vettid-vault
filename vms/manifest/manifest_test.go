package manifest

import (
	"crypto/ecdsa"
	"errors"
	"strings"
	"testing"
)

func TestVerify(t *testing.T) {
	k := specKey(0x21)
	other := specKey(0x23)
	s, err := Sign(k, specManifest())
	if err != nil {
		t.Fatal(err)
	}
	served := s.Marshal()
	p, err := ParseServed(served)
	if err != nil {
		t.Fatal(err)
	}
	m, err := Verify(p, []*ecdsa.PublicKey{&other.PublicKey, &k.PublicKey})
	if err != nil {
		t.Fatal(err)
	}
	if m.Serial != 7 || len(m.Releases) != 2 || m.Releases[1].Status != StatusActive {
		t.Fatalf("%+v", m)
	}
	if r, ok := m.ByPCR0(strings.Repeat("ab", 48)); !ok || r.Number != 3 {
		t.Fatal("by pcr0")
	}
	if r, ok := m.Newest(); !ok || r.Number != 4 {
		t.Fatal("newest")
	}
	if m.CheckSerial(7) != nil || !errors.Is(m.CheckSerial(8), ErrSerial) {
		t.Fatal("serial")
	}
	if _, err := Verify(p, []*ecdsa.PublicKey{&other.PublicKey}); !errors.Is(err, ErrKey) {
		t.Fatal("unpinned key")
	}
	bad := *p
	bad.Sig = append([]byte(nil), p.Sig...)
	bad.Sig[5] ^= 1
	if _, err := Verify(&bad, []*ecdsa.PublicKey{&k.PublicKey}); !errors.Is(err, ErrSignature) {
		t.Fatal("bad sig")
	}
	bad = *p
	bad.Manifest = append([]byte(nil), p.Manifest...)
	bad.Manifest[20] ^= 1
	if _, err := Verify(&bad, []*ecdsa.PublicKey{&k.PublicKey}); !errors.Is(err, ErrSignature) {
		t.Fatal("modified bytes")
	}
	// A signature by another key under the pinned key's id.
	s2, _ := Sign(other, specManifest())
	s2.KeyID = s.KeyID
	if _, err := Verify(s2, []*ecdsa.PublicKey{&k.PublicKey}); !errors.Is(err, ErrSignature) {
		t.Fatal("wrong key")
	}
}

func TestParseRejects(t *testing.T) {
	good := string(specManifest())
	pcr := strings.Repeat("ab", 48)
	for name, f := range map[string]func(string) string{
		"not compact":     func(s string) string { return strings.Replace(s, `"v":1,`, `"v": 1,`, 1) },
		"v 2":             func(s string) string { return strings.Replace(s, `"v":1`, `"v":2`, 1) },
		"duplicate":       func(s string) string { return strings.Replace(s, `"v":1,`, `"v":1,"v":1,`, 1) },
		"serial 0":        func(s string) string { return strings.Replace(s, `"serial":7`, `"serial":0`, 1) },
		"serial float":    func(s string) string { return strings.Replace(s, `"serial":7`, `"serial":7.0`, 1) },
		"fractional time": func(s string) string { return strings.Replace(s, `12:00:00Z`, `12:00:00.5Z`, 1) },
		"offset time":     func(s string) string { return strings.Replace(s, `12:00:00Z`, `12:00:00+00:00`, 1) },
		"upper hex":       func(s string) string { return strings.Replace(s, pcr, strings.ToUpper(pcr), 1) },
		"short pcr":       func(s string) string { return strings.Replace(s, pcr, pcr[2:], 1) },
		"debug pcr":       func(s string) string { return strings.Replace(s, pcr, strings.Repeat("0", 96), 1) },
		"status":          func(s string) string { return strings.Replace(s, `"deprecated"`, `"beta"`, 1) },
		"http notes": func(s string) string {
			return strings.Replace(s, `https://vettid.org/releases/3`, `http://vettid.org/releases/3`, 1)
		},
		"unsorted":       func(s string) string { return strings.Replace(s, `"release":3`, `"release":5`, 1) },
		"same number":    func(s string) string { return strings.Replace(s, `"release":3`, `"release":4`, 1) },
		"duplicate pcr0": func(s string) string { return strings.Replace(s, strings.Repeat("cd", 48), pcr, 1) },
		"empty releases": func(s string) string { return s[:strings.Index(s, `"releases"`)] + `"releases":[]}` },
		"empty seal key": func(s string) string {
			return strings.Replace(s, `arn:aws:kms:us-east-1:000000000000:key/test-release-3`, ``, 1)
		},
		"space in seal key": func(s string) string { return strings.Replace(s, `key/test-release-3`, `key/test release-3`, 1) },
		"trailing":          func(s string) string { return s + " " },
		"too large":         func(s string) string { return s[:len(s)-2] + `,"x":"` + strings.Repeat("a", 4096) + `"}]}` },
	} {
		if _, err := Parse([]byte(f(good))); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := Parse([]byte(good)); err != nil {
		t.Fatal(err)
	}
	// Unknown members are ignored (§5.3).
	if _, err := Parse([]byte(strings.Replace(good, `"v":1,`, `"v":1,"future":true,`, 1))); err != nil {
		t.Fatal(err)
	}
	for name, s := range map[string]string{
		"sig length":  `{"manifest":"e30=","sig":"AAAA","key_id":"1edbb48b6669decd"}`,
		"key id hex":  `{"manifest":"e30=","sig":"` + strings.Repeat("A", 86) + `==","key_id":"1EDBB48B6669DECD"}`,
		"no manifest": `{"sig":"` + strings.Repeat("A", 86) + `==","key_id":"1edbb48b6669decd"}`,
	} {
		if _, err := ParseServed([]byte(s)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func FuzzParse(f *testing.F) {
	f.Add(specManifest())
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := Parse(b)
		if err != nil {
			return
		}
		if len(m.Releases) == 0 {
			t.Fatal("empty")
		}
	})
}

func FuzzVerifyServed(f *testing.F) {
	k := specKey(0x21)
	s, _ := Sign(k, specManifest())
	f.Add(s.Marshal())
	keys := []*ecdsa.PublicKey{&k.PublicKey}
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := ParseServed(b)
		if err != nil {
			return
		}
		_, _ = Verify(p, keys)
	})
}
