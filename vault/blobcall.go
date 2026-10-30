package vault

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/vettid/vettid-vault/vms/envelope"
)

// A request that travels as one §5.5 claim-check blob from the app to its
// own vault (VAULT-MESSAGING 0.81.2 §10.19.8, vote.site.sync): the request's
// body is {blob: {id, key, sha256, size}}, the vault fetches the blob from
// its own mailbox in the background, checks sha256 in constant time, then
// the size, decrypts it and handles the plaintext as the request body; the
// blob is deleted once it has been fetched, and also when it fails. The
// answer is sent when the handler of the plaintext has run.

// BlobCall handles the plaintext of a blob request as the request's body:
// it runs with the vault's lock held, like a handler, and returns the
// response body or an error response.
type BlobCall func(s *Session, plaintext []byte) (json.RawMessage, error)

// BlobHost is implemented by the Host of the Manager's sessions (and by the
// test host).
type BlobHost interface {
	// BlobLimit is the largest plaintext a blob call may carry: the relay's
	// attachment_max_bytes, 0 without relay blobs.
	BlobLimit() int
	// DeferBlob starts a blob call for the request being handled and
	// returns at once; the handler returns ErrDeferred.
	DeferBlob(s *Session, id string, key, sha256 []byte, size int, call BlobCall) error
}

// BlobLimit is the largest plaintext a blob call may carry; 0 without relay
// blobs.
func (s *Session) BlobLimit() int {
	if h, ok := s.host.(BlobHost); ok {
		return h.BlobLimit()
	}
	return 0
}

// DeferBlob answers the request being handled later, with the result of
// call on the plaintext of the blob. The handler returns ErrDeferred.
func (s *Session) DeferBlob(id string, key, sha256 []byte, size int, call BlobCall) error {
	h, ok := s.host.(BlobHost)
	if !ok || s.peer == nil && s.inner == nil {
		return NewError("payload_too_large", "")
	}
	return h.DeferBlob(s, id, key, sha256, size, call)
}

// blobCallBound is how long a blob call may take from its request.
const blobCallBound = 120 * time.Second

func (h managerHost) BlobLimit() int { return h.m.attMaxContent() }

func (h managerHost) DeferBlob(s *Session, id string, key, sum []byte, size int, call BlobCall) error {
	m := h.m
	max := m.attMaxContent()
	if max <= 0 || size > max || s.peer == nil || s.inner == nil || len(sum) != 32 {
		return NewError("payload_too_large", "")
	}
	p, req := s.peer, *s.inner
	rkey := p.ID + "|" + req.ID
	key = append([]byte(nil), key...)
	var want [32]byte
	copy(want[:], sum)
	maxBlob := m.attMaxBlob()
	go m.runBlobCall(p.ID, req, rkey, id, key, want, size, maxBlob, call)
	return nil
}

// runBlobCall fetches and opens the blob without the vault's lock, then
// takes it to run the call and answer.
func (m *Manager) runBlobCall(deviceID string, req envelope.Inner, rkey, blobID string, key []byte, sum [32]byte, size, maxBlob int, call BlobCall) {
	ctx, cancel := context.WithTimeout(context.Background(), blobCallBound)
	defer cancel()
	var plain []byte
	var code string
	data, err := m.relay.GetBlob(ctx, blobID)
	switch {
	case err != nil && (transient(err) || ctx.Err() != nil):
		code = "relay_error"
	case err != nil:
		code = "bad_request" // blob_unknown and anything else the relay refuses
	default:
		if maxBlob > 0 && len(data) > maxBlob {
			code = "bad_request"
		} else if plain, err = envelope.OpenBlob(data, key, sum, size); err != nil {
			code = "bad_request"
		}
		wipe(data)
		// The blob is deleted once fetched, and also when it fails (§5.5).
		_ = m.relay.DeleteBlob(ctx, blobID)
	}
	wipe(key)
	m.mu.Lock()
	defer m.mu.Unlock()
	defer wipe(plain)
	if m.locked || m.st == nil {
		return
	}
	p := m.st.Devices[deviceID]
	if p == nil {
		return
	}
	now := m.now()
	if code != "" {
		m.respondError(p, &req, rkey, code, "", now)
	} else {
		s := &Session{m: m, peer: p, host: managerHost{m}, from: info(p), ctx: ctx, now: now, inner: &req}
		body, herr := call(s, plain)
		var he *HandlerError
		switch {
		case herr == nil:
			m.respond(p, &req, rkey, body, now)
		case errors.As(herr, &he):
			m.respondErrorBody(p, &req, rkey, he.Code, he.Message, he.Body, now)
		default:
			m.respondError(p, &req, rkey, "internal", "", now)
		}
	}
	m.dirty = true
	_ = m.flushIfDirty(context.Background())
	m.drainOutbox(ctx)
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
