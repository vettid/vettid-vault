// Package vectors generates and checks the VAULT-MESSAGING §16 test
// vectors, stored as JSON under testdata/vectors at the repository root.
//
// All keys are derived from fixed, public, TEST-ONLY seeds. Never use them
// for anything else.
//
// Two tests guard the vectors:
//
//   - TestVectors (always built) re-derives every value from the inputs in
//     the JSON and checks it byte for byte from the receiving side: keys
//     from seeds, HPKE values with an independent key schedule, every
//     envelope opened with the recipient's key, every transcript hash,
//     key, kid, SAS and signature.
//   - TestVectorsUpToDate (built only with -tags vmsvectors) regenerates
//     the files through the library's own sending code, with every random
//     draw scripted, and requires identical bytes.
//
// Regenerate with `go generate ./vms/vectors` (or `make vectors`).
package vectors

//go:generate go test -tags vmsvectors -run ^TestVectorsUpToDate$ -update .

import (
	"bytes"
	"encoding/json"
	"strconv"
)

// Dir is the vector directory relative to this package.
const Dir = "../../testdata/vectors"

// Files are the vector files, in generation order.
var Files = []string{"keys.json", "hpke.json", "envelope_sealed.json", "envelope_session.json", "handshake.json", "invite.json", "altchan.json"}

// obj is a JSON object that keeps member order.
type obj []member

type member struct {
	k string
	v any
}

func (o obj) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, m := range o {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.Quote(m.k))
		b.WriteByte(':')
		v, err := marshal(m.v)
		if err != nil {
			return nil, err
		}
		b.Write(v)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

func marshal(v any) ([]byte, error) {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if err := e.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), nil
}

// render produces the canonical file bytes: two-space indented JSON with a
// trailing newline.
func render(o obj) ([]byte, error) {
	raw, err := marshal(o)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err := json.Indent(&out, raw, "", "  "); err != nil {
		return nil, err
	}
	out.WriteByte('\n')
	return out.Bytes(), nil
}

// Fixed inputs shared by the generator and the checker (§16).
const (
	TS        = "2026-10-01T12:00:00.000Z"
	SpecInner = `{"v":1,"id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V","type":"test.ping","ts":"2026-10-01T12:00:00.000Z","body":{}}`
)
