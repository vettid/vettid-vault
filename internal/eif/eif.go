// Package eif reads an AWS Nitro Enclaves image file (EIF) as written by
// nitro-cli build-enclave, and recomputes its PCR0, PCR1 and PCR2
// independently of nitro-cli (VAULT-RELEASES §5.1, §5.3).
//
// An EIF is a 548-byte header followed by sections, each a 12-byte section
// header and its data: the kernel, the kernel command line, a metadata
// section (JSON), the ramdisks (the bootstrap ramdisk, then the user
// ramdisk built from the docker image) and, for signed images, a
// signature. The header's CRC-32 (IEEE) covers the header without the CRC
// field and everything after the header.
//
// The PCRs cover the kernel, the command line and the ramdisks, never the
// metadata:
//
//	PCR0 = SHA-384(0^48 || SHA-384(kernel || cmdline || ramdisk_1 || ... || ramdisk_n))
//	PCR1 = SHA-384(0^48 || SHA-384(kernel || cmdline || ramdisk_1))
//	PCR2 = SHA-384(0^48 || SHA-384(ramdisk_2 || ... || ramdisk_n))
//
// The metadata section is not measured and nitro-cli fills it from the
// build host: the build time and the docker daemon's description of the
// image (storage paths, tags). Two builds of the same commit therefore
// give EIFs that differ in that section (and the CRC) only; MeasuredSHA256
// hashes everything else and is what two builds must agree on, byte for
// byte, besides the PCRs.
package eif

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"sort"
)

// Section types.
const (
	SectionKernel    = 1
	SectionCmdline   = 2
	SectionRamdisk   = 3
	SectionSignature = 4
	SectionMetadata  = 5
)

const (
	headerLen     = 548
	crcOffset     = 544
	maxSections   = 32
	sectionHdrLen = 12
)

var magic = []byte{'.', 'e', 'i', 'f'}

// ErrFormat is returned for anything that is not a well-formed EIF.
var ErrFormat = errors.New("eif: malformed image")

// Section is one section of an EIF.
type Section struct {
	Type  uint16
	Flags uint16
	// Header is the 12-byte section header, Data the section's bytes.
	Header []byte
	Data   []byte
}

// Image is a parsed EIF.
type Image struct {
	Version  uint16
	Sections []Section
	CRC      uint32
}

// Parse parses an EIF and checks its layout and CRC: the sections are
// contiguous from the end of the header to the end of the file, each
// section header's size equals the header's size table, and exactly one
// kernel, one command line and at most one metadata section precede at
// least two ramdisks.
func Parse(b []byte) (*Image, error) {
	if len(b) < headerLen || !bytes.Equal(b[:4], magic) {
		return nil, ErrFormat
	}
	im := &Image{Version: binary.BigEndian.Uint16(b[4:6])}
	n := int(binary.BigEndian.Uint16(b[26:28]))
	if n == 0 || n > maxSections {
		return nil, ErrFormat
	}
	im.CRC = binary.BigEndian.Uint32(b[crcOffset:headerLen])
	c := crc32.NewIEEE()
	c.Write(b[:crcOffset])
	c.Write(b[headerLen:])
	if c.Sum32() != im.CRC {
		return nil, fmt.Errorf("%w: CRC mismatch", ErrFormat)
	}
	next := uint64(headerLen)
	for i := 0; i < n; i++ {
		off := binary.BigEndian.Uint64(b[28+8*i:])
		size := binary.BigEndian.Uint64(b[28+8*maxSections+8*i:])
		if off != next || off+sectionHdrLen < off || off+sectionHdrLen > uint64(len(b)) {
			return nil, ErrFormat
		}
		h := b[off : off+sectionHdrLen]
		if binary.BigEndian.Uint64(h[4:12]) != size {
			return nil, ErrFormat
		}
		end := off + sectionHdrLen + size
		if end < off || end > uint64(len(b)) {
			return nil, ErrFormat
		}
		im.Sections = append(im.Sections, Section{Type: binary.BigEndian.Uint16(h[0:2]), Flags: binary.BigEndian.Uint16(h[2:4]),
			Header: h, Data: b[off+sectionHdrLen : end]})
		next = end
	}
	if next != uint64(len(b)) {
		return nil, ErrFormat // trailing bytes
	}
	count := map[uint16]int{}
	for _, s := range im.Sections {
		switch s.Type {
		case SectionKernel, SectionCmdline, SectionRamdisk, SectionSignature, SectionMetadata:
		default:
			return nil, ErrFormat
		}
		count[s.Type]++
	}
	if count[SectionKernel] != 1 || count[SectionCmdline] != 1 || count[SectionMetadata] > 1 || count[SectionSignature] > 1 || count[SectionRamdisk] < 2 {
		return nil, ErrFormat
	}
	return im, nil
}

func (im *Image) data(t uint16) [][]byte {
	var out [][]byte
	for _, s := range im.Sections {
		if s.Type == t {
			out = append(out, s.Data)
		}
	}
	return out
}

func pcr(parts ...[]byte) string {
	h := sha512.New384()
	for _, p := range parts {
		h.Write(p)
	}
	ext := sha512.New384()
	ext.Write(make([]byte, 48))
	ext.Write(h.Sum(nil))
	return hex.EncodeToString(ext.Sum(nil))
}

// PCRs returns PCR0, PCR1 and PCR2 (lowercase hex), computed from the
// sections.
func (im *Image) PCRs() (pcr0, pcr1, pcr2 string) {
	k, c, r := im.data(SectionKernel)[0], im.data(SectionCmdline)[0], im.data(SectionRamdisk)
	all := append([][]byte{k, c}, r...)
	return pcr(all...), pcr(k, c, r[0]), pcr(r[1:]...)
}

// MeasuredSHA256 is SHA-256 over every section except the metadata
// section, each as its section header and data, in file order: the part
// of the file that two builds of the same commit must reproduce byte for
// byte.
func (im *Image) MeasuredSHA256() string {
	h := sha256.New()
	for _, s := range im.Sections {
		if s.Type == SectionMetadata {
			continue
		}
		h.Write(s.Header)
		h.Write(s.Data)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Metadata returns the metadata section's bytes (nil if there is none).
func (im *Image) Metadata() []byte {
	if m := im.data(SectionMetadata); len(m) == 1 {
		return m[0]
	}
	return nil
}

// Info summarises an EIF for measurements.json.
type Info struct {
	SHA256         string `json:"eif_sha256"`
	MeasuredSHA256 string `json:"eif_measured_sha256"`
	PCR0           string `json:"pcr0"`
	PCR1           string `json:"pcr1"`
	PCR2           string `json:"pcr2"`
	BuildTool      string `json:"build_tool,omitempty"`
	BuildToolVer   string `json:"build_tool_version,omitempty"`
	Sections       []struct {
		Type   uint16 `json:"type"`
		Size   int    `json:"size"`
		SHA256 string `json:"sha256"`
	} `json:"sections"`
}

// Describe parses b and summarises it.
func Describe(b []byte) (*Info, *Image, error) {
	im, err := Parse(b)
	if err != nil {
		return nil, nil, err
	}
	sum := sha256.Sum256(b)
	in := &Info{SHA256: hex.EncodeToString(sum[:]), MeasuredSHA256: im.MeasuredSHA256()}
	in.PCR0, in.PCR1, in.PCR2 = im.PCRs()
	for _, s := range im.Sections {
		h := sha256.Sum256(s.Data)
		in.Sections = append(in.Sections, struct {
			Type   uint16 `json:"type"`
			Size   int    `json:"size"`
			SHA256 string `json:"sha256"`
		}{s.Type, len(s.Data), hex.EncodeToString(h[:])})
	}
	if md := im.Metadata(); md != nil {
		var m struct {
			BuildMetadata struct {
				BuildTool        string
				BuildToolVersion string
			}
		}
		if json.Unmarshal(md, &m) == nil {
			in.BuildTool, in.BuildToolVer = m.BuildMetadata.BuildTool, m.BuildMetadata.BuildToolVersion
		}
	}
	return in, im, nil
}

// Compare reports how two EIFs of the same commit differ: nil if every
// measured section is byte-identical (same layout, same PCRs), otherwise
// an error naming the first difference. It also returns the top-level
// metadata members that differ, for the log (nitro-cli fills the metadata
// from the build host, so they are expected to differ).
func Compare(a, b []byte) ([]string, error) {
	ia, err := Parse(a)
	if err != nil {
		return nil, fmt.Errorf("first EIF: %w", err)
	}
	ib, err := Parse(b)
	if err != nil {
		return nil, fmt.Errorf("second EIF: %w", err)
	}
	if ia.Version != ib.Version || len(ia.Sections) != len(ib.Sections) {
		return nil, errors.New("eif: different version or section count")
	}
	for i := range ia.Sections {
		sa, sb := ia.Sections[i], ib.Sections[i]
		if sa.Type != sb.Type || sa.Flags != sb.Flags {
			return nil, fmt.Errorf("eif: section %d has a different type", i)
		}
		if sa.Type == SectionMetadata {
			continue
		}
		if !bytes.Equal(sa.Data, sb.Data) {
			return nil, fmt.Errorf("eif: section %d (type %d) differs", i, sa.Type)
		}
	}
	return metadataDiff(ia.Metadata(), ib.Metadata()), nil
}

// metadataDiff lists the metadata paths (to depth 2) whose values differ.
func metadataDiff(a, b []byte) []string {
	var ma, mb map[string]json.RawMessage
	if json.Unmarshal(a, &ma) != nil || json.Unmarshal(b, &mb) != nil {
		if bytes.Equal(a, b) {
			return nil
		}
		return []string{"(metadata)"}
	}
	var out []string
	keys := map[string]bool{}
	for k := range ma {
		keys[k] = true
	}
	for k := range mb {
		keys[k] = true
	}
	for _, k := range sortedKeys(keys) {
		if bytes.Equal(ma[k], mb[k]) {
			continue
		}
		var sa, sb map[string]json.RawMessage
		if json.Unmarshal(ma[k], &sa) == nil && json.Unmarshal(mb[k], &sb) == nil {
			sub := map[string]bool{}
			for s := range sa {
				sub[s] = true
			}
			for s := range sb {
				sub[s] = true
			}
			for _, s := range sortedKeys(sub) {
				if !bytes.Equal(sa[s], sb[s]) {
					out = append(out, k+"."+s)
				}
			}
			continue
		}
		out = append(out, k)
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
