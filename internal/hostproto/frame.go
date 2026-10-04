// Package hostproto is the framing between the enclave and its parent
// (VAULT-PLAN V3: the vsock control connection; TCP in development).
//
// The parent is untrusted (VAULT-MESSAGING §13.3): it only moves opaque
// bytes (queue messages, sealed results, encrypted state objects) and
// answers the enclave's requests for storage and credentials. Nothing in a
// frame is authenticated; the enclave treats every answer as host input.
//
// A frame is
//
//	u32 length (big-endian) || kind (1) || id (8) || count (2) || count × (u32 length || bytes)
//
// where length covers everything after itself. Requests carry an id the
// peer echoes in its KindReply; notifications carry id 0 and get no reply.
// Writes go out in pieces of at most ChunkSize bytes: the Nitro vsock
// transport has lost data beyond 32 KiB in a single write.
package hostproto

import (
	"encoding/binary"
	"errors"
	"io"
)

// Limits.
const (
	// MaxFrame bounds a frame body (a vault state object plus overhead).
	MaxFrame = 64 << 20
	// MaxFields bounds the fields in one frame.
	MaxFields = 64
	// ChunkSize is the largest single write to the connection.
	ChunkSize = 16 << 10
	headerLen = 1 + 8 + 2
)

// Kind is a frame type.
type Kind uint8

// Frame kinds. Requests from the enclave to the parent:
const (
	// Hello: [release]; reply [status, instance_id].
	KindHello Kind = 0x01
	// StoreGet: [key]; reply [status, data, version].
	KindStoreGet Kind = 0x02
	// StorePut: [key, data, if_match] (if_match "" = create-only); reply
	// [status, version].
	KindStorePut Kind = 0x03
	// StoreDelete: [key, if_match]; reply [status].
	KindStoreDelete Kind = 0x04
	// Credentials: []; reply [status, access_key_id, secret_access_key,
	// session_token, expiration (RFC 3339 or "")].
	KindCredentials Kind = 0x05
)

// Requests from the parent to the enclave:
const (
	// Queue: [queue message bytes, manifest document]; reply [status,
	// response bytes] (empty response bytes: the message did not parse).
	// The manifest document is the served manifest an enroll or unlock
	// names by manifest_sha256, read by the parent from the vault data
	// bucket (VAULT-MESSAGING 0.10.0); empty for other ops or if missing.
	KindQueue Kind = 0x10
	// LeaseLost: [vault_id]; reply [status]. The enclave locks the vault
	// (§12.3 "Lease lost").
	KindLeaseLost Kind = 0x11
	// Ping: []; reply [status, running vault count].
	KindPing Kind = 0x12
	// Shutdown: []; reply [status] once every vault is locked (§12.3
	// "Enclave release or restart ... if signalled").
	KindShutdown Kind = 0x13
	// Selftest: [request JSON]; reply [status, report JSON]. Only after a
	// Hello answered "selftest" (the hardware smoke test, docs/SMOKE.md).
	KindSelftest Kind = 0x14
)

// Notifications from the enclave to the parent:
const (
	// Descriptor: [release, descriptor, attestation] (§11.2).
	KindDescriptor Kind = 0x20
	// Lifecycle: [event, vault_id, release, vault_version, state_version]
	// (§11.5).
	KindLifecycle Kind = 0x21
	// Stopped: [vault_id, reason]: a vault's run loop ended without a
	// lifecycle "locked" (split brain, errors).
	KindStopped Kind = 0x22
	// Log: [level, message, key, value, ...]: sanitized enclave logs.
	KindLog Kind = 0x23
)

// KindReply answers a request; its id is the request's.
const KindReply Kind = 0x7f

// Reply statuses (the first field of a reply).
const (
	StatusOK       = "ok"
	StatusNotFound = "not_found"
	StatusConflict = "conflict"
	StatusInvalid  = "invalid"
	StatusError    = "error"
)

// Errors.
var (
	ErrFrame  = errors.New("hostproto: malformed frame")
	ErrTooBig = errors.New("hostproto: frame too large")
)

// Frame is one decoded frame. Fields alias the read buffer.
type Frame struct {
	Kind   Kind
	ID     uint64
	Fields [][]byte
}

// Field returns field i, or nil.
func (f *Frame) Field(i int) []byte {
	if i < 0 || i >= len(f.Fields) {
		return nil
	}
	return f.Fields[i]
}

// Marshal encodes the frame including its length prefix.
func (f *Frame) Marshal() ([]byte, error) {
	if len(f.Fields) > MaxFields {
		return nil, ErrTooBig
	}
	n := headerLen
	for _, x := range f.Fields {
		n += 4 + len(x)
		if n > MaxFrame {
			return nil, ErrTooBig
		}
	}
	b := make([]byte, 0, 4+n)
	b = binary.BigEndian.AppendUint32(b, uint32(n))
	b = append(b, byte(f.Kind))
	b = binary.BigEndian.AppendUint64(b, f.ID)
	b = binary.BigEndian.AppendUint16(b, uint16(len(f.Fields)))
	for _, x := range f.Fields {
		b = binary.BigEndian.AppendUint32(b, uint32(len(x)))
		b = append(b, x...)
	}
	return b, nil
}

// Parse decodes a frame body (without the length prefix). It rejects
// truncated and trailing data.
func Parse(b []byte) (*Frame, error) {
	if len(b) < headerLen || len(b) > MaxFrame {
		return nil, ErrFrame
	}
	f := &Frame{Kind: Kind(b[0]), ID: binary.BigEndian.Uint64(b[1:9])}
	count := int(binary.BigEndian.Uint16(b[9:11]))
	if count > MaxFields {
		return nil, ErrFrame
	}
	b = b[headerLen:]
	f.Fields = make([][]byte, 0, count)
	for i := 0; i < count; i++ {
		if len(b) < 4 {
			return nil, ErrFrame
		}
		l := binary.BigEndian.Uint32(b[:4])
		b = b[4:]
		if uint64(l) > uint64(len(b)) {
			return nil, ErrFrame
		}
		f.Fields = append(f.Fields, b[:l:l])
		b = b[l:]
	}
	if len(b) != 0 {
		return nil, ErrFrame
	}
	return f, nil
}

// ReadFrame reads one frame.
func ReadFrame(r io.Reader) (*Frame, error) {
	var lb [4]byte
	if _, err := io.ReadFull(r, lb[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(lb[:])
	if n < headerLen || n > MaxFrame {
		return nil, ErrTooBig
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	return Parse(b)
}

// WriteChunked writes b in pieces of at most ChunkSize bytes.
func WriteChunked(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n := min(len(b), ChunkSize)
		if _, err := w.Write(b[:n]); err != nil {
			return err
		}
		b = b[n:]
	}
	return nil
}

// WriteFrame encodes and writes one frame (chunked).
func WriteFrame(w io.Writer, f *Frame) error {
	b, err := f.Marshal()
	if err != nil {
		return err
	}
	return WriteChunked(w, b)
}

// ChunkedWriter wraps a writer so that no single Write exceeds ChunkSize
// (the parent's TCP forwarder copies through it toward the enclave).
type ChunkedWriter struct{ W io.Writer }

// Write implements io.Writer.
func (c ChunkedWriter) Write(b []byte) (int, error) {
	n := 0
	for len(b) > 0 {
		k := min(len(b), ChunkSize)
		m, err := c.W.Write(b[:k])
		n += m
		if err != nil {
			return n, err
		}
		b = b[k:]
	}
	return n, nil
}

// Strings returns the fields as byte slices of the given strings.
func Strings(s ...string) [][]byte {
	out := make([][]byte, len(s))
	for i, x := range s {
		out[i] = []byte(x)
	}
	return out
}
