package vault

import (
	"context"
	"crypto/ed25519"
	"errors"
	"math/rand/v2"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/vettid/vettid-relay/relayauth"
	"github.com/vettid/vettid-relay/relayclient"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Message is one collected relay message.
type Message = relayclient.Message

// Limits are the relay policy values advertised at registration (§1.2).
type Limits = relayclient.Limits

// Relay is everything the vault does on relays, as the holder of its relay
// key. All requests are signed inside the vault (§1.1 decision 5).
type Relay interface {
	// BaseURL is the vault's own relay (the audience of tokens it mints).
	BaseURL() string
	Register(ctx context.Context) (Limits, error)
	// Collector opens a collect session on the vault's mailbox (§12.2).
	Collector(ctx context.Context, websocket bool) (Collector, error)
	// Deposit deposits into a mailbox on any relay.
	Deposit(ctx context.Context, relayURL, mailbox, token string, payload []byte) (string, error)
	Revoke(ctx context.Context, kind, value string) error
	PutClaim(ctx context.Context, data []byte, ttl time.Duration) (string, time.Time, error)
	GetClaim(ctx context.Context, relayURL, claimID string) ([]byte, error)
	DeleteClaim(ctx context.Context, claimID string) error
	// DeleteMailbox deletes the vault's own mailbox and everything in it
	// (RELAY-PROTOCOL 0.5.0 §6.10; idempotent). A relay before 0.5.0
	// answers not_found.
	DeleteMailbox(ctx context.Context) error
	// MintToken mints a deposit token for sub. ownerDevice sets the
	// owner_device claim (RELAY-PROTOCOL 0.9.2 §5.2): only on the tokens
	// the vault mints for its own devices (§7.1, 0.32.0).
	MintToken(sub ed25519.PublicKey, ttl time.Duration, jti string, quota *relayauth.Quota, ownerDevice bool) (string, error)
	MintOpenToken(ttl time.Duration, jti string) (string, error)
	// Blob transfer (RELAY-PROTOCOL §6.8; VAULT-MESSAGING §5.5, §10.5.1).
	// PutBlob uploads to a mailbox on any relay under a deposit token;
	// GetBlob, DeleteBlob and ListBlobs act on the vault's own mailbox.
	PutBlob(ctx context.Context, relayURL, mailbox, token string, data []byte) (id string, expires time.Time, err error)
	GetBlob(ctx context.Context, id string) ([]byte, error)
	DeleteBlob(ctx context.Context, id string) error
	// ListBlobs lists the own mailbox's blobs (RELAY-PROTOCOL 0.9.2
	// POST /v1/blobs); a relay without the list answers not_found.
	ListBlobs(ctx context.Context) (BlobList, error)
}

// RelayRotator is what a Relay offers for the vault's own relay-key
// rotation (§3.4 "The order of a relay-key rotation"; RELAY-PROTOCOL §6.1,
// §6.7). Only with Options.RelayKeyRotation; a Relay without it rotates no
// relay key (the rotation's attempt is not made). Each call is one
// attempt: the vault retries on its own schedule.
type RelayRotator interface {
	// Rotate moves the mailbox of this Relay's key to newKey's, in a
	// request signed by this Relay's key; it returns the new mailbox id.
	Rotate(ctx context.Context, newKey ed25519.PrivateKey) (string, error)
	// RegisterCreated registers this Relay's key and reports whether the
	// relay created the mailbox (201) or already had it (200).
	RegisterCreated(ctx context.Context) (Limits, bool, error)
	// WithKey is a Relay on the same relay for another of the vault's own
	// relay keys (a pending one, or an old one kept for deposits).
	WithKey(key ed25519.PrivateKey) Relay
}

// BlobEntry is one blob of the own mailbox's list.
type BlobEntry = relayclient.BlobEntry

// BlobList is the own mailbox's blob list and its storage use.
type BlobList struct {
	Blobs     []BlobEntry
	UsedBytes int64
	MaxBytes  int64
}

// Collector is a collect session: long-poll or WebSocket.
type Collector interface {
	// Next returns the next batch (up to 32 messages), blocking up to the
	// long-poll wait.
	Next(ctx context.Context) ([]Message, error)
	Ack(ctx context.Context, msgID string) error
	Close() error
}

// Relay error codes the runtime acts on (RELAY-PROTOCOL §7.1, §8.6).
const (
	CodeTokenExpired   = "token_expired"
	CodeTokenRevoked   = "token_revoked"
	CodeTokenInvalid   = "token_invalid"
	CodeTokenUsed      = "token_used"
	CodeMailboxUnknown = "mailbox_unknown"
	CodeClaimUnknown   = "claim_unknown"
	CodeTimestampStale = "timestamp_stale"
	CodeReplayDetected = "replay_detected"
	CodeBlobUnknown    = "blob_unknown"
	CodeQuotaExceeded  = "quota_exceeded"
	CodeNotFound       = "not_found"
)

// RelayQuota returns the quota member of a quota_exceeded error (""
// otherwise, or from a relay before 0.9.2).
func RelayQuota(err error) string { return relayclient.QuotaOf(err) }

// RelayCode returns the relay error code of err, or "".
func RelayCode(err error) string {
	var e *relayclient.Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

// ClientRelay implements Relay with relayclient. HTTP is the transport
// (injectable: the enclave dials through the parent in phase V3).
type ClientRelay struct {
	base string
	key  ed25519.PrivateKey // its own copy, wiped by Close
	http *http.Client
	now  func() time.Time
	g    *relayGuard  // this relay's calls and its key copy
	fam  *relayFamily // the relays WithKey derives share it: Close closes them all

	mu      sync.Mutex
	clients map[string]*relayclient.Client
	// deposits are the clients the outbox's deposits go through
	// (withOneAttempt): one attempt each (0.88.7 §8.3, §8.6). The outbox
	// retries with its own backoff, and an in-client retry could hide that
	// an earlier attempt was stored (its answer lost) behind a later
	// attempt's refusal, so that the entry would not be marked as one that
	// may have reached the relay (Tried). Other deposits (volatile ones,
	// vault.locking), which judge no Tried, keep relayclient's retries.
	deposits map[string]*relayclient.Client
}

// NewClientRelay returns a Relay for the vault whose relay key is key and
// whose mailbox lives at baseURL. httpClient may be nil.
//
// It keeps its own copy of key, so that the vault's wipe of its keys never
// races a request in flight; Close ends the relay's requests and wipes the
// copy.
func NewClientRelay(baseURL string, key ed25519.PrivateKey, httpClient *http.Client, now func() time.Time) *ClientRelay {
	return newClientRelay(baseURL, key, httpClient, now, &relayFamily{})
}

func newClientRelay(baseURL string, key ed25519.PrivateKey, httpClient *http.Client, now func() time.Time, fam *relayFamily) *ClientRelay {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 60 * time.Second}
	}
	if now == nil {
		now = time.Now
	}
	own := append(ed25519.PrivateKey(nil), key...)
	g := newRelayGuard(own)
	fam.add(g)
	return &ClientRelay{base: strings.TrimRight(baseURL, "/"), key: own, http: httpClient, now: now, g: g, fam: fam,
		clients: map[string]*relayclient.Client{}, deposits: map[string]*relayclient.Client{}}
}

// Close ends the requests in flight of the relay and of every relay of its
// family (WithKey's), waits for them up to relayCloseWait, and then wipes
// all their key copies: also if the wait ran out, so that a request that
// does not end leaves no key behind (fail secure). An answer that arrives
// after Close is not used: the call returns ErrRelayClosed. Every later
// call returns ErrRelayClosed. Close is for the end of the vault's keys
// (zeroize); to drop one relay, use Release.
func (r *ClientRelay) Close() { r.cut()(time.Now().Add(relayCloseWait)) }

// cut is Close in two steps: it refuses new calls and cancels those in
// flight of the whole family now, and returns the wait and wipe, which the
// caller runs later against a deadline of its own (zeroize: one deadline
// for every family, after it has destroyed its other secrets).
func (r *ClientRelay) cut() func(deadline time.Time) {
	gs := r.fam.begin()
	return func(deadline time.Time) {
		for _, g := range gs {
			g.close(deadline)
		}
	}
}

// Release closes this relay alone, as Close does, and wipes its key copy:
// for a key the vault drops while its other relays go on (a pending key
// given up, a recovery's relays rebuilt). The family no longer holds it.
func (r *ClientRelay) Release() {
	r.fam.remove(r.g)
	r.g.close(time.Now().Add(relayCloseWait))
}

// relayCloseWait bounds how long a close waits for the requests in flight
// it has cancelled. Real transports end a cancelled request in
// milliseconds; the bound is for one that does not (the key copy is wiped
// at it anyway), and it is spent under the Manager's lock.
var relayCloseWait = 2 * time.Second

// ErrRelayClosed is returned by a relay call once the relay is closed
// (the vault zeroized).
var ErrRelayClosed = errors.New("vault: relay closed")

// relayFamily is the guards of a ClientRelay and the relays WithKey
// derived from it: close ends them all.
type relayFamily struct {
	mu     sync.Mutex
	guards []*relayGuard
	closed bool
}

func (f *relayFamily) add(g *relayGuard) {
	f.mu.Lock()
	closed := f.closed
	if !closed {
		f.guards = append(f.guards, g)
	}
	f.mu.Unlock()
	if closed {
		g.close(time.Now()) // a relay derived after Close: never usable
	}
}

// begin closes the family: it cancels every guard's calls at once and
// returns the guards, for the caller to wait for against one deadline (the
// bound is one wait, not one per relay). A second begin returns none.
func (f *relayFamily) begin() []*relayGuard {
	f.mu.Lock()
	f.closed = true
	gs := f.guards
	f.guards = nil
	f.mu.Unlock()
	for _, g := range gs {
		g.begin()
	}
	return gs
}

// remove takes a released relay's guard out of the family.
func (f *relayFamily) remove(g *relayGuard) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, x := range f.guards {
		if x == g {
			f.guards = append(f.guards[:i], f.guards[i+1:]...)
			return
		}
	}
}

// relayGuard ties one ClientRelay to its key copy: each call is counted
// and its context cut short by close; close waits for the calls, then
// wipes the copy.
type relayGuard struct {
	ctx    context.Context
	cancel context.CancelFunc

	mu       sync.Mutex
	idle     *sync.Cond // signalled as calls end, and when the wait runs out
	inflight int
	closed   bool
	key      ed25519.PrivateKey
}

func newRelayGuard(key ed25519.PrivateKey) *relayGuard {
	g := &relayGuard{key: key}
	g.ctx, g.cancel = context.WithCancel(context.Background())
	g.idle = sync.NewCond(&g.mu)
	return g
}

// enter begins a call: ctx, cut short by close, and done, which ends it.
func (g *relayGuard) enter(ctx context.Context) (context.Context, func(), error) {
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return nil, nil, ErrRelayClosed
	}
	g.inflight++
	g.mu.Unlock()
	c, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(g.ctx, cancel)
	return c, func() {
		stop()
		cancel()
		g.mu.Lock()
		g.inflight--
		g.idle.Broadcast()
		g.mu.Unlock()
	}, nil
}

func (g *relayGuard) isClosed() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.closed
}

// begin refuses new calls and cancels those in flight.
func (g *relayGuard) begin() {
	g.mu.Lock()
	g.closed = true
	g.mu.Unlock()
	g.cancel()
}

// close begins, waits for the calls in flight until deadline, and wipes
// the key whether or not they ended. It reports whether they all ended. A
// second close does nothing.
func (g *relayGuard) close(deadline time.Time) bool {
	g.begin()
	g.mu.Lock()
	if g.key == nil {
		g.mu.Unlock()
		return true // already wiped
	}
	g.mu.Unlock()
	timedOut := false
	t := time.AfterFunc(time.Until(deadline), func() {
		g.mu.Lock()
		timedOut = true
		g.idle.Broadcast()
		g.mu.Unlock()
	})
	defer t.Stop()
	g.mu.Lock()
	defer g.mu.Unlock()
	for g.inflight > 0 && !timedOut {
		g.idle.Wait()
	}
	if g.key == nil {
		return true // a concurrent close wiped it
	}
	if g.inflight == 0 {
		suite.Wipe(g.key)
	} else {
		// The timeout path: a call that ignored its cancel may still be
		// signing with the copy. Only the seed is wiped. Ed25519 signing
		// reads the seed and the public half separately and does not check
		// one against the other, so a real seed read with a zeroed public
		// half would sign with the true scalar under a wrong public key,
		// and two such signatures over one message give the scalar away.
		// With the public half (public) left, a torn read gives a seed, and
		// so a scalar and nonce, unrelated to the real ones: nothing leaks.
		// The call's answer is dropped (ErrRelayClosed).
		suite.Wipe(g.key[:ed25519.SeedSize])
	}
	g.key = nil
	if testRelayClosedHook != nil {
		testRelayClosedHook(g.inflight == 0)
	}
	return g.inflight == 0
}

// testRelayClosedHook, set only by tests, learns whether a relay's close
// saw every call end before it wiped.
var testRelayClosedHook func(allEnded bool)

// guarded runs a call of r under its guard: ctx is cut short by Close, and
// a result that arrives after Close is not used (ErrRelayClosed), since the
// key it was made with may be wiped.
func guarded[T any](r *ClientRelay, ctx context.Context, f func(context.Context) (T, error)) (T, error) {
	var zero T
	c, done, err := r.g.enter(ctx)
	if err != nil {
		return zero, err
	}
	defer done()
	v, err := f(c)
	if r.g.isClosed() {
		return zero, ErrRelayClosed
	}
	return v, err
}

// guardedErr is guarded for a call with no result.
func guardedErr(r *ClientRelay, ctx context.Context, f func(context.Context) error) error {
	_, err := guarded(r, ctx, func(c context.Context) (struct{}, error) { return struct{}{}, f(c) })
	return err
}

func (r *ClientRelay) client(url string) *relayclient.Client {
	url = strings.TrimRight(url, "/")
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.clients[url]
	if !ok {
		c = relayclient.New(url, r.key)
		c.HTTP, c.Now = r.http, r.now
		r.clients[url] = c
	}
	return c
}

// depositClient is client with one attempt per call (deposits).
func (r *ClientRelay) depositClient(url string) *relayclient.Client {
	url = strings.TrimRight(url, "/")
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.deposits[url]
	if !ok {
		c = relayclient.New(url, r.key)
		c.HTTP, c.Now, c.MaxAttempts = r.http, r.now, 1
		r.deposits[url] = c
	}
	return c
}

func (r *ClientRelay) BaseURL() string { return r.base }

func (r *ClientRelay) Register(ctx context.Context) (Limits, error) {
	reg, err := guarded(r, ctx, func(c context.Context) (relayclient.Registration, error) { return r.client(r.base).Register(c) })
	return reg.Limits, err
}

// once is the client for one attempt (RelayRotator).
func (r *ClientRelay) once() *relayclient.Client {
	c := relayclient.New(r.base, r.key)
	c.HTTP, c.Now, c.MaxAttempts = r.http, r.now, 1
	return c
}

func (r *ClientRelay) Rotate(ctx context.Context, newKey ed25519.PrivateKey) (string, error) {
	return guarded(r, ctx, func(c context.Context) (string, error) { return r.once().Rotate(c, newKey) })
}

func (r *ClientRelay) RegisterCreated(ctx context.Context) (Limits, bool, error) {
	reg, err := guarded(r, ctx, func(c context.Context) (relayclient.Registration, error) { return r.once().Register(c) })
	return reg.Limits, reg.Created, err
}

// WithKey is a relay for another of the vault's relay keys, of r's family:
// Close on any of them closes them all, Release only the one.
func (r *ClientRelay) WithKey(key ed25519.PrivateKey) Relay {
	return newClientRelay(r.base, key, r.http, r.now, r.fam)
}

func (r *ClientRelay) Deposit(ctx context.Context, relayURL, mailbox, token string, payload []byte) (string, error) {
	return guarded(r, ctx, func(c context.Context) (string, error) {
		if c.Value(oneAttemptKey{}) != nil {
			return r.depositClient(relayURL).Deposit(c, mailbox, token, payload)
		}
		return r.client(relayURL).Deposit(c, mailbox, token, payload)
	})
}

// oneAttemptKey marks a context whose deposit makes one attempt.
type oneAttemptKey struct{}

// withOneAttempt is ctx for an outbox deposit: one relayclient attempt
// (ClientRelay.depositClient), so that its answer is that attempt's.
func withOneAttempt(ctx context.Context) context.Context {
	return context.WithValue(ctx, oneAttemptKey{}, true)
}

func (r *ClientRelay) Revoke(ctx context.Context, kind, value string) error {
	return guardedErr(r, ctx, func(c context.Context) error {
		return r.client(r.base).Revoke(c, relayclient.Revocation{Kind: kind, Value: value})
	})
}

func (r *ClientRelay) PutClaim(ctx context.Context, data []byte, ttl time.Duration) (string, time.Time, error) {
	type claim struct {
		id  string
		exp time.Time
	}
	v, err := guarded(r, ctx, func(c context.Context) (claim, error) {
		id, exp, err := r.client(r.base).PutClaim(c, data, ttl)
		return claim{id, exp}, err
	})
	return v.id, v.exp, err
}

func (r *ClientRelay) GetClaim(ctx context.Context, relayURL, claimID string) ([]byte, error) {
	return guarded(r, ctx, func(c context.Context) ([]byte, error) { return r.client(relayURL).GetClaim(c, claimID) })
}

func (r *ClientRelay) DeleteClaim(ctx context.Context, claimID string) error {
	return guardedErr(r, ctx, func(c context.Context) error { return r.client(r.base).DeleteClaim(c, claimID) })
}

func (r *ClientRelay) DeleteMailbox(ctx context.Context) error {
	return guardedErr(r, ctx, func(c context.Context) error { return r.client(r.base).DeleteMailbox(c) })
}

func (r *ClientRelay) MintToken(sub ed25519.PublicKey, ttl time.Duration, jti string, quota *relayauth.Quota, ownerDevice bool) (string, error) {
	return guarded(r, context.Background(), func(context.Context) (string, error) {
		return r.client(r.base).MintToken(relayauth.EncodeKey(sub), r.base, relayclient.TokenOptions{TTL: ttl, JTI: jti, Quota: quota, OwnerDevice: ownerDevice})
	})
}

func (r *ClientRelay) PutBlob(ctx context.Context, relayURL, mailbox, token string, data []byte) (string, time.Time, error) {
	type put struct {
		id  string
		exp time.Time
	}
	v, err := guarded(r, ctx, func(c context.Context) (put, error) {
		id, exp, err := r.client(relayURL).PutBlob(c, mailbox, token, data)
		return put{id, exp}, err
	})
	return v.id, v.exp, err
}

func (r *ClientRelay) GetBlob(ctx context.Context, id string) ([]byte, error) {
	return guarded(r, ctx, func(c context.Context) ([]byte, error) { return r.client(r.base).GetBlob(c, id) })
}

func (r *ClientRelay) DeleteBlob(ctx context.Context, id string) error {
	return guardedErr(r, ctx, func(c context.Context) error { return r.client(r.base).DeleteBlob(c, id) })
}

// maxBlobPages bounds a listing (500 a page): a mailbox's blobs are bounded
// by the relay's per-sender counts; this only stops a relay that never
// ends its list.
const maxBlobPages = 64

func (r *ClientRelay) ListBlobs(ctx context.Context) (BlobList, error) {
	return guarded(r, ctx, r.listBlobs)
}

func (r *ClientRelay) listBlobs(ctx context.Context) (BlobList, error) {
	c := r.client(r.base)
	var out BlobList
	after := ""
	for range maxBlobPages {
		p, err := c.ListBlobs(ctx, after, 500)
		if err != nil {
			return BlobList{}, err
		}
		out.Blobs = append(out.Blobs, p.Blobs...)
		out.UsedBytes, out.MaxBytes = p.UsedBytes, p.MaxBytes
		if p.Next == "" || p.Next == after {
			return out, nil
		}
		after = p.Next
	}
	return out, nil
}

func (r *ClientRelay) MintOpenToken(ttl time.Duration, jti string) (string, error) {
	return guarded(r, context.Background(), func(context.Context) (string, error) {
		return r.client(r.base).MintOpenToken(r.base, ttl, jti)
	})
}

// MaxBatch is the collect batch size (§8.3).
const MaxBatch = 32

// LongPollWait is the longest long-poll wait (§12.2). Each poll asks for a
// random whole number of seconds from LongPollWait - LongPollSpread up to
// it: vaults the relay answered in the same instant (it does when a relay
// task stops) would otherwise poll in step from then on
// (VAULT-RELAY-SCALING §4.2).
const (
	LongPollWait   = 25 * time.Second
	LongPollSpread = 5 * time.Second
)

func (r *ClientRelay) Collector(ctx context.Context, websocket bool) (Collector, error) {
	c := r.client(r.base)
	if !websocket {
		return &pollCollector{r: r, c: c, wait: LongPollWait, spread: LongPollSpread}, nil
	}
	// Only the stream's opening is signed; its messages and acks are not.
	s, err := guarded(r, ctx, c.OpenStream)
	if err != nil {
		return nil, err
	}
	return &wsCollector{s: s}, nil
}

// NewPollCollector returns a long-poll collector with a custom wait (tests
// use short waits).
func (r *ClientRelay) NewPollCollector(wait time.Duration) Collector {
	return &pollCollector{r: r, c: r.client(r.base), wait: wait}
}

type pollCollector struct {
	r      *ClientRelay // its calls run under r's guard: Close ends a long poll
	c      *relayclient.Client
	wait   time.Duration
	spread time.Duration // 0: every poll waits the same
}

func (p *pollCollector) Next(ctx context.Context) ([]Message, error) {
	return guarded(p.r, ctx, func(c context.Context) ([]Message, error) {
		return p.c.Collect(c, pollWait(p.wait, p.spread), MaxBatch)
	})
}

// pollWait is one poll's wait: whole seconds, evenly from wait - spread
// to wait (not secret: math/rand).
func pollWait(wait, spread time.Duration) time.Duration {
	if spread < time.Second {
		return wait
	}
	return wait - time.Duration(rand.Int64N(int64(spread/time.Second)+1))*time.Second
}
func (p *pollCollector) Ack(ctx context.Context, id string) error {
	return guardedErr(p.r, ctx, func(c context.Context) error { return p.c.Ack(c, id) })
}
func (p *pollCollector) Close() error { return nil }

// wsCollector gathers pushed messages into batches: it blocks for the
// first, then takes whatever else arrives within a short window.
type wsCollector struct {
	s    *relayclient.Stream
	mu   sync.Mutex
	next chan wsItem
	once sync.Once
}

type wsItem struct {
	m   Message
	err error
}

func (w *wsCollector) start(ctx context.Context) {
	w.once.Do(func() {
		w.next = make(chan wsItem, MaxBatch)
		go func() {
			for {
				m, err := w.s.Next(context.Background())
				w.next <- wsItem{m, err}
				if err != nil {
					close(w.next)
					return
				}
			}
		}()
	})
}

var errStreamClosed = errors.New("vault: collect stream closed")

const wsBatchWindow = 50 * time.Millisecond

func (w *wsCollector) Next(ctx context.Context) ([]Message, error) {
	w.start(ctx)
	var batch []Message
	select {
	case it, ok := <-w.next:
		if !ok {
			return nil, errStreamClosed
		}
		if it.err != nil {
			return nil, it.err
		}
		batch = append(batch, it.m)
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(LongPollWait):
		return nil, nil
	}
	timer := time.NewTimer(wsBatchWindow)
	defer timer.Stop()
	for len(batch) < MaxBatch {
		select {
		case it, ok := <-w.next:
			if !ok || it.err != nil {
				return batch, nil
			}
			batch = append(batch, it.m)
		case <-timer.C:
			return batch, nil
		}
	}
	return batch, nil
}

func (w *wsCollector) Ack(ctx context.Context, id string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.s.Ack(ctx, id)
}

func (w *wsCollector) Close() error { return w.s.Close() }
