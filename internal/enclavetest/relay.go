package enclavetest

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strconv"
	"sync"
	"time"

	"github.com/vettid/vettid-relay/relayauth"
	"github.com/vettid/vettid-relay/relayclient"

	"github.com/vettid/vettid-vault/vault"
)

// MemRelay is a TEST-ONLY in-memory stand-in for the relay, implementing
// the vault's Relay interface for one vault: it records deposits and signs
// tokens like a relay client, with no network.
type MemRelay struct {
	mu       sync.Mutex
	base     string
	key      ed25519.PrivateKey
	Deposits []Deposit
}

// Deposit is one recorded deposit.
type Deposit struct {
	RelayURL, Mailbox, Token string
	Payload                  []byte
	// Sender is the depositing vault's relay key (the collect sender).
	Sender ed25519.PublicKey
}

// MemRelays hands out MemRelays and keeps every deposit.
type MemRelays struct {
	mu  sync.Mutex
	all []*MemRelay
}

// New returns a relay for a vault (the shape of vault.Options.Relay).
func (rs *MemRelays) New(base string, key ed25519.PrivateKey) *MemRelay {
	r := &MemRelay{base: base, key: key}
	rs.mu.Lock()
	rs.all = append(rs.all, r)
	rs.mu.Unlock()
	return r
}

// DepositsTo returns every deposit into a mailbox.
func (rs *MemRelays) DepositsTo(mailbox string) []Deposit {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	var out []Deposit
	for _, r := range rs.all {
		r.mu.Lock()
		for _, d := range r.Deposits {
			if d.Mailbox == mailbox {
				out = append(out, d)
			}
		}
		r.mu.Unlock()
	}
	return out
}

// BaseURL implements vault.Relay.
func (r *MemRelay) BaseURL() string { return r.base }

// Register implements vault.Relay.
func (r *MemRelay) Register(context.Context) (relayclient.Limits, error) {
	return relayclient.Limits{MaxTokenLifetimeSeconds: 400 * 86400, OpenTokenMaxLifetimeSeconds: 7 * 86400, ClaimTTLSeconds: 7 * 86400}, nil
}

type idleCollector struct{}

func (idleCollector) Next(ctx context.Context) ([]relayclient.Message, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(20 * time.Millisecond):
		return nil, nil
	}
}
func (idleCollector) Ack(context.Context, string) error { return nil }
func (idleCollector) Close() error                      { return nil }

// Collector returns a collector that never has messages.
func (r *MemRelay) Collector(context.Context, bool) (vault.Collector, error) {
	return idleCollector{}, nil
}

var _ vault.Relay = (*MemRelay)(nil)

// Deposit implements vault.Relay.
func (r *MemRelay) Deposit(_ context.Context, relayURL, mailbox, token string, payload []byte) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Deposits = append(r.Deposits, Deposit{relayURL, mailbox, token, append([]byte(nil), payload...), r.key.Public().(ed25519.PublicKey)})
	return "m" + strconv.Itoa(len(r.Deposits)), nil
}

// Revoke implements vault.Relay.
func (r *MemRelay) Revoke(context.Context, string, string) error { return nil }

// PutClaim implements vault.Relay.
func (r *MemRelay) PutClaim(context.Context, []byte, time.Duration) (string, time.Time, error) {
	return "abcdefghijklmnopqrstuvwxyz", time.Now().Add(time.Hour), nil
}

// GetClaim implements vault.Relay.
func (r *MemRelay) GetClaim(context.Context, string, string) ([]byte, error) {
	return nil, errors.New("enclavetest: no claims")
}

// DeleteClaim implements vault.Relay.
func (r *MemRelay) DeleteClaim(context.Context, string) error { return nil }

// DeleteMailbox implements vault.Relay.
func (r *MemRelay) DeleteMailbox(context.Context) error { return nil }

func (r *MemRelay) client() *relayclient.Client { return relayclient.New(r.base, r.key) }

// MintToken implements vault.Relay.
func (r *MemRelay) MintToken(sub ed25519.PublicKey, ttl time.Duration, jti string, q *relayauth.Quota, ownerDevice bool) (string, error) {
	return r.client().MintToken(relayauth.EncodeKey(sub), r.base, relayclient.TokenOptions{TTL: ttl, JTI: jti, Quota: q, OwnerDevice: ownerDevice})
}

var errNoBlobs = &relayclient.Error{Status: 404, Code: "not_found"}

// PutBlob implements vault.Relay: this relay advertises no blobs.
func (r *MemRelay) PutBlob(context.Context, string, string, string, []byte) (string, time.Time, error) {
	return "", time.Time{}, errNoBlobs
}

// GetBlob implements vault.Relay.
func (r *MemRelay) GetBlob(context.Context, string) ([]byte, error) { return nil, errNoBlobs }

// DeleteBlob implements vault.Relay.
func (r *MemRelay) DeleteBlob(context.Context, string) error { return errNoBlobs }

// ListBlobs implements vault.Relay.
func (r *MemRelay) ListBlobs(context.Context) (vault.BlobList, error) {
	return vault.BlobList{}, errNoBlobs
}

// MintOpenToken implements vault.Relay.
func (r *MemRelay) MintOpenToken(ttl time.Duration, jti string) (string, error) {
	return r.client().MintOpenToken(r.base, ttl, jti)
}
