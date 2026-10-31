package vault

import (
	"context"
	"encoding/json"
	"errors"
	"runtime/debug"
	"time"

	"github.com/vettid/vettid-vault/vms/attwire"
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

// blobCallID names a blob call in the attachment runner's books; the
// "fetch:" prefix keeps it from the per-entry minimum gap.
func blobCallID(device string) string { return "fetch:blobcall|" + device }

func (h managerHost) BlobLimit() int { return h.m.attMaxContent() }

func (h managerHost) DeferBlob(s *Session, id string, key, sum []byte, size int, call BlobCall) error {
	m := h.m
	max := m.attMaxContent()
	if max <= 0 || size > max || s.peer == nil || s.inner == nil || len(sum) != 32 {
		return NewError("payload_too_large", "")
	}
	p, req := s.peer, *s.inner
	rkey := p.ID + "|" + req.ID
	// At most one blob call in flight per device; the same request again
	// (a retransmission) reuses the one running.
	if cur, ok := m.blobBusy[p.ID]; ok {
		if cur == req.ID {
			return nil
		}
		return NewError("busy", "")
	}
	r := m.att
	if r != nil {
		// A blob call is a transfer of the vault's: it takes one of its
		// attwire.VaultTransfers slots.
		if attwire.VaultTransfers-r.slots <= 0 {
			return NewError("busy", "")
		}
		r.slots++
		r.running[blobCallID(p.ID)] = true
	}
	if m.blobBusy == nil {
		m.blobBusy = map[string]string{}
	}
	m.blobBusy[p.ID] = req.ID
	key = append([]byte(nil), key...)
	var want [32]byte
	copy(want[:], sum)
	maxBlob := m.attMaxBlob()
	go m.runBlobCall(r, p.ID, req, rkey, id, key, want, size, maxBlob, call)
	return nil
}

// runBlobCall fetches and opens the blob without the vault's lock, then
// takes it to run the call and answer. The fetch is a transfer: the
// instance's admission at the owner-fetch priority first, memory returned
// afterwards when it was large.
func (m *Manager) runBlobCall(r *attRunner, deviceID string, req envelope.Inner, rkey, blobID string, key []byte, sum [32]byte, size, maxBlob int, call BlobCall) {
	var plain []byte
	var code string
	fetch := func(ctx context.Context) int {
		if ctx == nil {
			code = "busy" // not admitted in time
			return 0
		}
		ctx, cancel := context.WithTimeout(ctx, blobCallBound)
		defer cancel()
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
		}
		n := len(data)
		wipe(data)
		return n
	}
	if r != nil {
		m.transfer(r, PrioOwnerFetch, blobCallID(deviceID), time.Now().Add(OwnerFetchStart), fetch)
	} else {
		var n int
		if g := m.opt.Transfers; g != nil {
			actx, cancel := context.WithTimeout(context.Background(), OwnerFetchStart)
			release, err := g.Admit(actx, PrioOwnerFetch)
			cancel()
			if err != nil {
				fetch(nil)
			} else {
				n = fetch(context.Background())
				release()
			}
		} else {
			n = fetch(context.Background())
		}
		if n > 1<<20 {
			debug.FreeOSMemory()
		}
	}
	// The blob is deleted on every path (§5.5): after a failed or timed out
	// fetch too, with a context of its own.
	dctx, dcancel := context.WithTimeout(context.Background(), 15*time.Second)
	_ = m.relay.DeleteBlob(dctx, blobID)
	dcancel()
	wipe(key)
	m.mu.Lock()
	defer m.mu.Unlock()
	defer wipe(plain)
	if m.blobBusy[deviceID] == req.ID {
		delete(m.blobBusy, deviceID)
	}
	if m.locked || m.st == nil {
		return
	}
	p := m.st.Devices[deviceID]
	if p == nil {
		return
	}
	now := m.now()
	ctx := context.Background()
	if code == "" {
		// The hold and recovery are checked again as dispatch does: the
		// vault may have gone overdue or into recovery during the fetch.
		m.refreshOwnerCred()
		switch {
		case !m.credentialReady() && !(p.Recovering && m.credentialExists()):
			code = "credential_required"
		case !p.Recovering:
			if st := m.ownerCheckState(now); st != OwnerCheckOK && !m.holdAllows(p, req.Type, st) {
				code = "owner_check_required"
			}
		case !recoveryAllowed[req.Type]:
			code = "forbidden"
		}
	}
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
	_ = m.flushIfDirty(ctx)
	m.drainOutbox(ctx)
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
