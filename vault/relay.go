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
	CodeTokenUsed      = "token_used"
	CodeMailboxUnknown = "mailbox_unknown"
	CodeClaimUnknown   = "claim_unknown"
	CodeTimestampStale = "timestamp_stale"
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
	key  ed25519.PrivateKey
	http *http.Client
	now  func() time.Time

	mu      sync.Mutex
	clients map[string]*relayclient.Client
}

// NewClientRelay returns a Relay for the vault whose relay key is key and
// whose mailbox lives at baseURL. httpClient may be nil.
func NewClientRelay(baseURL string, key ed25519.PrivateKey, httpClient *http.Client, now func() time.Time) *ClientRelay {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 60 * time.Second}
	}
	if now == nil {
		now = time.Now
	}
	return &ClientRelay{base: strings.TrimRight(baseURL, "/"), key: key, http: httpClient, now: now, clients: map[string]*relayclient.Client{}}
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

func (r *ClientRelay) BaseURL() string { return r.base }

func (r *ClientRelay) Register(ctx context.Context) (Limits, error) {
	reg, err := r.client(r.base).Register(ctx)
	return reg.Limits, err
}

func (r *ClientRelay) Deposit(ctx context.Context, relayURL, mailbox, token string, payload []byte) (string, error) {
	return r.client(relayURL).Deposit(ctx, mailbox, token, payload)
}

func (r *ClientRelay) Revoke(ctx context.Context, kind, value string) error {
	return r.client(r.base).Revoke(ctx, relayclient.Revocation{Kind: kind, Value: value})
}

func (r *ClientRelay) PutClaim(ctx context.Context, data []byte, ttl time.Duration) (string, time.Time, error) {
	return r.client(r.base).PutClaim(ctx, data, ttl)
}

func (r *ClientRelay) GetClaim(ctx context.Context, relayURL, claimID string) ([]byte, error) {
	return r.client(relayURL).GetClaim(ctx, claimID)
}

func (r *ClientRelay) DeleteClaim(ctx context.Context, claimID string) error {
	return r.client(r.base).DeleteClaim(ctx, claimID)
}

func (r *ClientRelay) DeleteMailbox(ctx context.Context) error {
	return r.client(r.base).DeleteMailbox(ctx)
}

func (r *ClientRelay) MintToken(sub ed25519.PublicKey, ttl time.Duration, jti string, quota *relayauth.Quota, ownerDevice bool) (string, error) {
	return r.client(r.base).MintToken(relayauth.EncodeKey(sub), r.base, relayclient.TokenOptions{TTL: ttl, JTI: jti, Quota: quota, OwnerDevice: ownerDevice})
}

func (r *ClientRelay) PutBlob(ctx context.Context, relayURL, mailbox, token string, data []byte) (string, time.Time, error) {
	return r.client(relayURL).PutBlob(ctx, mailbox, token, data)
}

func (r *ClientRelay) GetBlob(ctx context.Context, id string) ([]byte, error) {
	return r.client(r.base).GetBlob(ctx, id)
}

func (r *ClientRelay) DeleteBlob(ctx context.Context, id string) error {
	return r.client(r.base).DeleteBlob(ctx, id)
}

// maxBlobPages bounds a listing (500 a page): a mailbox's blobs are bounded
// by the relay's per-sender counts; this only stops a relay that never
// ends its list.
const maxBlobPages = 64

func (r *ClientRelay) ListBlobs(ctx context.Context) (BlobList, error) {
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
	return r.client(r.base).MintOpenToken(r.base, ttl, jti)
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
		return &pollCollector{c: c, wait: LongPollWait, spread: LongPollSpread}, nil
	}
	s, err := c.OpenStream(ctx)
	if err != nil {
		return nil, err
	}
	return &wsCollector{s: s}, nil
}

// NewPollCollector returns a long-poll collector with a custom wait (tests
// use short waits).
func (r *ClientRelay) NewPollCollector(wait time.Duration) Collector {
	return &pollCollector{c: r.client(r.base), wait: wait}
}

type pollCollector struct {
	c      *relayclient.Client
	wait   time.Duration
	spread time.Duration // 0: every poll waits the same
}

func (p *pollCollector) Next(ctx context.Context) ([]Message, error) {
	return p.c.Collect(ctx, pollWait(p.wait, p.spread), MaxBatch)
}

// pollWait is one poll's wait: whole seconds, evenly from wait - spread
// to wait (not secret: math/rand).
func pollWait(wait, spread time.Duration) time.Duration {
	if spread < time.Second {
		return wait
	}
	return wait - time.Duration(rand.Int64N(int64(spread/time.Second)+1))*time.Second
}
func (p *pollCollector) Ack(ctx context.Context, id string) error { return p.c.Ack(ctx, id) }
func (p *pollCollector) Close() error                             { return nil }

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
