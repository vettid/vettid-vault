package eif

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash/crc32"
	"testing"
)

type sec struct {
	typ  uint16
	data []byte
}

// build writes an EIF the way nitro-cli's EIF builder does.
func build(secs []sec) []byte {
	hdr := make([]byte, headerLen)
	copy(hdr, magic)
	binary.BigEndian.PutUint16(hdr[4:], 4)
	binary.BigEndian.PutUint16(hdr[26:], uint16(len(secs)))
	var body []byte
	off := uint64(headerLen)
	for i, s := range secs {
		binary.BigEndian.PutUint64(hdr[28+8*i:], off)
		binary.BigEndian.PutUint64(hdr[28+8*maxSections+8*i:], uint64(len(s.data)))
		sh := make([]byte, sectionHdrLen)
		binary.BigEndian.PutUint16(sh[0:], s.typ)
		binary.BigEndian.PutUint64(sh[4:], uint64(len(s.data)))
		body = append(append(body, sh...), s.data...)
		off += sectionHdrLen + uint64(len(s.data))
	}
	c := crc32.NewIEEE()
	c.Write(hdr[:crcOffset])
	c.Write(body)
	binary.BigEndian.PutUint32(hdr[crcOffset:], c.Sum32())
	return append(hdr, body...)
}

func sample(buildTime string) []byte {
	return build([]sec{
		{SectionKernel, bytes.Repeat([]byte("K"), 1000)},
		{SectionCmdline, []byte("reboot=k panic=30 pci=off nomodules console=ttyS0 random.trust_cpu=on root=/dev/ram0")},
		{SectionMetadata, []byte(`{"ImageName":"x","BuildMetadata":{"BuildTime":"` + buildTime + `","BuildTool":"nitro-cli","BuildToolVersion":"1.5.0"},"DockerInfo":{"Id":"a"}}`)},
		{SectionRamdisk, bytes.Repeat([]byte("B"), 300)},
		{SectionRamdisk, bytes.Repeat([]byte("U"), 700)},
	})
}

func ext(parts ...[]byte) string {
	inner := sha512.Sum384(bytes.Join(parts, nil))
	outer := sha512.Sum384(append(make([]byte, 48), inner[:]...))
	return hex.EncodeToString(outer[:])
}

func TestPCRs(t *testing.T) {
	in, _, err := Describe(sample("2026-10-04T15:04:04.915054579+00:00"))
	if err != nil {
		t.Fatal(err)
	}
	k, c := bytes.Repeat([]byte("K"), 1000), []byte("reboot=k panic=30 pci=off nomodules console=ttyS0 random.trust_cpu=on root=/dev/ram0")
	b, u := bytes.Repeat([]byte("B"), 300), bytes.Repeat([]byte("U"), 700)
	if in.PCR0 != ext(k, c, b, u) || in.PCR1 != ext(k, c, b) || in.PCR2 != ext(u) {
		t.Fatalf("PCRs %+v", in)
	}
	if in.BuildTool != "nitro-cli" || in.BuildToolVer != "1.5.0" || len(in.Sections) != 5 {
		t.Fatalf("info %+v", in)
	}
}

// Two builds that differ only in the metadata (build time, docker info)
// compare equal and have the same measured hash; any measured byte
// differs, they do not.
func TestCompare(t *testing.T) {
	a, b := sample("2026-10-04T15:04:04.915054579+00:00"), sample("2026-10-04T15:09:01.1+00:00")
	diff, err := Compare(a, b)
	if err != nil {
		t.Fatal(err)
	}
	if len(diff) != 1 || diff[0] != "BuildMetadata.BuildTime" {
		t.Fatalf("diff %v", diff)
	}
	ia, _ := Parse(a)
	ib, _ := Parse(b)
	if ia.MeasuredSHA256() != ib.MeasuredSHA256() || bytes.Equal(a, b) {
		t.Fatal("measured hash")
	}
	c := build([]sec{
		{SectionKernel, bytes.Repeat([]byte("K"), 1000)},
		{SectionCmdline, []byte("x")},
		{SectionMetadata, []byte(`{}`)},
		{SectionRamdisk, bytes.Repeat([]byte("B"), 300)},
		{SectionRamdisk, bytes.Repeat([]byte("V"), 700)},
	})
	if _, err := Compare(a, c); err == nil {
		t.Fatal("different sections compared equal")
	}
}

func TestParseRefuses(t *testing.T) {
	good := sample("t")
	for name, f := range map[string]func([]byte) []byte{
		"magic":    func(b []byte) []byte { b[0] = 'x'; return b },
		"crc":      func(b []byte) []byte { b[len(b)-1] ^= 1; return b },
		"short":    func(b []byte) []byte { return b[:100] },
		"trailing": func(b []byte) []byte { return append(b, 0) },
	} {
		if _, err := Parse(f(bytes.Clone(good))); !errors.Is(err, ErrFormat) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Structural refusals with a valid CRC.
	for name, secs := range map[string][]sec{
		"no kernel":       {{SectionCmdline, []byte("c")}, {SectionRamdisk, []byte("a")}, {SectionRamdisk, []byte("b")}},
		"one ramdisk":     {{SectionKernel, []byte("k")}, {SectionCmdline, []byte("c")}, {SectionRamdisk, []byte("a")}},
		"unknown section": {{SectionKernel, []byte("k")}, {SectionCmdline, []byte("c")}, {9, nil}, {SectionRamdisk, []byte("a")}, {SectionRamdisk, []byte("b")}},
		"two kernels":     {{SectionKernel, []byte("k")}, {SectionKernel, []byte("k")}, {SectionCmdline, []byte("c")}, {SectionRamdisk, []byte("a")}, {SectionRamdisk, []byte("b")}},
	} {
		if _, err := Parse(build(secs)); !errors.Is(err, ErrFormat) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func FuzzParse(f *testing.F) {
	f.Add(sample("t"))
	f.Fuzz(func(t *testing.T, b []byte) {
		im, err := Parse(b)
		if err != nil {
			return
		}
		im.PCRs()
		_ = im.MeasuredSHA256()
	})
}
