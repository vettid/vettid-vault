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

// Dir is the vector directory relative to this package.
const Dir = "../../testdata/vectors"

// Files are the vector files, in generation order.
var Files = []string{"keys.json", "hpke.json", "envelope_sealed.json", "envelope_session.json", "handshake.json", "invite.json", "altchan.json"}

// Fixed inputs shared by the generator and the checker (§16).
const (
	TS        = "2026-10-01T12:00:00.000Z"
	SpecInner = `{"v":1,"id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V","type":"test.ping","ts":"2026-10-01T12:00:00.000Z","body":{}}`
)
