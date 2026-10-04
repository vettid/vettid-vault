package manifest

import (
	"bytes"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
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
		"too large":         func(s string) string { return s[:len(s)-2] + `,"x":"` + strings.Repeat("a", MaxBytes) + `"}]}` },
		"bad ends_at": func(s string) string {
			return strings.Replace(s, `,"notes":"https://vettid.org/releases/3"`, `,"ends_at":"2027-10-01","notes":"https://vettid.org/releases/3"`, 1)
		},
		"ends_at number": func(s string) string {
			return strings.Replace(s, `,"notes":"https://vettid.org/releases/3"`, `,"ends_at":1,"notes":"https://vettid.org/releases/3"`, 1)
		},
		"ends_at fraction": func(s string) string {
			return strings.Replace(s, `,"notes":"https://vettid.org/releases/3"`, `,"ends_at":"2027-10-01T00:00:00.000Z","notes":"https://vettid.org/releases/3"`, 1)
		},
		"status Removed": func(s string) string { return strings.Replace(s, `"deprecated"`, `"Removed"`, 1) },
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

// 0.10.0: the removed status, ends_at, and the 64 KiB limit.
func TestStatusesEndsAtAndSize(t *testing.T) {
	at := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	ends := time.Date(2027, 10, 1, 0, 0, 0, 0, time.UTC)
	var rs []Release
	for i := 1; i <= 30; i++ {
		st := StatusDeprecated
		switch {
		case i <= 10:
			st = StatusRemoved
		case i <= 20:
			st = StatusRetired
		case i == 30:
			st = StatusActive
		}
		r := Release{Number: uint64(i), PCR0: fmt.Sprintf("%096x", i), PCR1: strings.Repeat("11", 48), PCR2: strings.Repeat("22", 48),
			SealKey: fmt.Sprintf("arn:aws:kms:us-east-1:111122223333:key/%08x-1111-2222-3333-444455556666", i), Status: st,
			PublishedAt: at, Notes: fmt.Sprintf("https://vettid.org/security/releases/%d/", i)}
		if st != StatusActive {
			r.EndsAt = ends
		}
		rs = append(rs, r)
	}
	b := Build(99, at, rs)
	m, err := Parse(b)
	if err != nil {
		t.Fatalf("%d bytes: %v", len(b), err)
	}
	if len(m.Releases) != 30 || m.Releases[0].Status != StatusRemoved || !m.Releases[0].EndsAt.Equal(ends) || !m.Releases[29].EndsAt.IsZero() {
		t.Fatalf("%+v", m.Releases[0])
	}
	if n, ok := m.Newest(); !ok || n.Number != 30 {
		t.Fatal("newest")
	}
	// ends_at is in the member order after published_at.
	if !bytes.Contains(b, []byte(`"published_at":"2026-10-01T00:00:00Z","ends_at":"2027-10-01T00:00:00Z","notes"`)) {
		t.Fatal("member order")
	}
	// ends_at on an active entry is not refused (forward compatibility).
	if _, err := Parse(bytes.Replace(b, []byte(`"status":"active","published_at":"2026-10-01T00:00:00Z",`),
		[]byte(`"status":"active","published_at":"2026-10-01T00:00:00Z","ends_at":"2027-10-01T00:00:00Z",`), 1)); err != nil {
		t.Fatal(err)
	}
	// The largest manifest, signed, fits the served-document limit.
	big := append([]byte(nil), b[:len(b)-3]...)
	big = append(big, []byte(`,"pad":"`)...)
	for len(big) < MaxBytes-4 {
		big = append(big, 'a')
	}
	big = append(big, []byte(`"}]}`)...)
	if len(big) != MaxBytes {
		t.Fatalf("len %d", len(big))
	}
	if _, err := Parse(big); err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(append(big[:len(big)-4:len(big)-4], []byte(`a"}]}`)...)); !errors.Is(err, ErrFormat) {
		t.Fatal("over 64 KiB accepted")
	}
	sv, err := Sign(specKey(0x21), big)
	if err != nil {
		t.Fatal(err)
	}
	doc := sv.Marshal()
	if len(doc) > MaxServed {
		t.Fatalf("served %d > %d", len(doc), MaxServed)
	}
	if _, err := ParseServed(doc); err != nil {
		t.Fatal(err)
	}
}

func TestHashHelpers(t *testing.T) {
	h := SHA256Hex(specManifest())
	if h != "d3fc1be2ce9358815863eeae15bebf5c755f168a7ab161c8e5c66500be1288f1" || !ValidSHA256Hex(h) {
		t.Fatal(h)
	}
	if ObjectKey(h) != "manifests/"+h+".json" {
		t.Fatal("key")
	}
	for _, s := range []string{"", strings.ToUpper(h), h[:63], h + "0", h[:63] + "g"} {
		if ValidSHA256Hex(s) {
			t.Errorf("%q valid", s)
		}
	}
}

func TestVerifyByHash(t *testing.T) {
	k := specKey(0x21)
	keys := []*ecdsa.PublicKey{&k.PublicKey}
	s, _ := Sign(k, specManifest())
	doc := s.Marshal()
	h := SHA256Hex(s.Manifest)
	m, err := VerifyByHash(doc, h, 7, keys)
	if err != nil || m.Serial != 7 {
		t.Fatal(err)
	}
	other, _ := Sign(k, Build(8, m.IssuedAt, m.Releases))
	for name, tc := range map[string]struct {
		doc    []byte
		hash   string
		serial uint64
		want   error
	}{
		"missing":          {nil, h, 7, ErrMissing},
		"empty":            {[]byte{}, h, 7, ErrMissing},
		"garbage":          {[]byte("{"), h, 7, ErrFormat},
		"another manifest": {other.Marshal(), h, 7, ErrHash},
		"hash upper":       {doc, strings.ToUpper(h), 7, ErrHash},
		"serial differs":   {doc, h, 8, ErrHash},
		"too large":        {append(doc[:len(doc)-1:len(doc)-1], []byte(`,"x":"`+strings.Repeat("a", MaxServed)+`"}`)...), h, 7, ErrFormat},
	} {
		if _, err := VerifyByHash(tc.doc, tc.hash, tc.serial, keys); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := VerifyByHash(doc, h, 7, []*ecdsa.PublicKey{&specKey(0x23).PublicKey}); !errors.Is(err, ErrKey) {
		t.Fatal("unpinned")
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

func FuzzVerifyByHash(f *testing.F) {
	k := specKey(0x21)
	s, _ := Sign(k, specManifest())
	h := SHA256Hex(s.Manifest)
	f.Add(s.Marshal(), uint64(7))
	keys := []*ecdsa.PublicKey{&k.PublicKey}
	f.Fuzz(func(t *testing.T, b []byte, serial uint64) {
		m, err := VerifyByHash(b, h, serial, keys)
		if err == nil && (m.Serial != serial || SHA256Hex(m.Bytes) != h) {
			t.Fatal("accepted a document the request does not name")
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
