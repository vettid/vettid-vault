package callswire

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/vettid/vettid-relay/relayauth"
)

// Client calls the calling service's issuer (CALLING-SERVICE §5.2). Each request is signed (Relay Protocol §4.1)
// with an Ed25519 key made for that one request and dropped after it, never any other key of the vault
// (VAULT-MESSAGING §10.10). It makes one attempt per call: the pool's limits and waits are the vault's own.
type Client struct {
	// BaseURL is the issuer, https://host (no trailing slash): the release constant calls_url.
	BaseURL string
	HTTP    *http.Client
	Now     func() time.Time
	// Attest, if set, returns the Nitro attestation document for the request: public_key = the request's key,
	// user_data = the request's digest. Nil: the request leaves without the header and the enclave's supervisor
	// attaches it (the vault process cannot ask the NSM for arbitrary user_data).
	Attest func(publicKey ed25519.PublicKey, digest [32]byte) ([]byte, error)
}

// ErrTransport is an issuer that could not be reached or did not answer in time.
var ErrTransport = errors.New("callswire: issuer unreachable")

// ErrOversized is an answer longer than MaxAnswer: an answer the vault refuses, so errors.Is(ErrOversized,
// ErrResponse) (a failed attempt like any other refused answer).
var ErrOversized error = oversized{}

type oversized struct{}

func (oversized) Error() string        { return "callswire: issuer answer too large" }
func (oversized) Is(target error) bool { return target == ErrResponse }

// Credentials asks for count credentials (1..MaxCount) and returns the checked answer (ParseAnswer, against the
// client's clock). An issuer error is an *Error; an answer that fails the checks is ErrResponse; anything else
// that fails is ErrTransport.
func (c *Client) Credentials(ctx context.Context, count int) (*Answer, error) {
	if count < 1 || count > MaxCount {
		return nil, ErrResponse
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, ErrTransport
	}
	// The request's key is this request's alone (VAULT-MESSAGING §10.10): it is dropped when the call returns.
	defer clear(key)
	status, ans, err := c.do(ctx, key, PathCredentials, RequestBody(count))
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, ParseError(status, ans)
	}
	return ParseAnswer(ans, c.now())
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Client) do(ctx context.Context, key ed25519.PrivateKey, path string, body []byte) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(c.BaseURL, "/")+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, ErrTransport
	}
	req.Header.Set("Content-Type", "application/json")
	bh := relayauth.BodyHash(body)
	relayauth.SetHeaders(req.Header, key, http.MethodPost, path, c.now(), bh)
	if c.Attest != nil {
		d := relayauth.Digest(http.MethodPost, path, req.Header.Get(relayauth.HeaderTimestamp), bh)
		doc, err := c.Attest(key.Public().(ed25519.PublicKey), d)
		if err != nil {
			return 0, nil, ErrTransport
		}
		req.Header.Set(HeaderAttestation, base64.StdEncoding.EncodeToString(doc))
	}
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return 0, nil, ErrTransport
	}
	defer resp.Body.Close()
	ans, err := io.ReadAll(io.LimitReader(resp.Body, MaxAnswer+1))
	if err != nil {
		return 0, nil, ErrTransport
	}
	if len(ans) > MaxAnswer {
		return 0, nil, ErrOversized
	}
	return resp.StatusCode, ans, nil
}
