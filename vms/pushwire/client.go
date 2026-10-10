package pushwire

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/vettid/vettid-relay/relayauth"
)

// Client calls one push gateway (PUSH-GATEWAY §5) with requests signed by
// a wake key (Relay Protocol §4.1). It makes one attempt per call: the
// vault's retry rules are its own (VAULT-MESSAGING §14.1, §14.2).
type Client struct {
	// BaseURL is the gateway, https://host (no trailing slash).
	BaseURL string
	HTTP    *http.Client
	Now     func() time.Time
	// Attest, if set, returns the Nitro attestation document for a
	// registration: public_key = the wake public key, user_data = the
	// request's digest (PUSH-GATEWAY §5.1). Nil: the request leaves
	// without the header and the enclave's supervisor attaches it (the
	// vault process cannot ask the NSM for arbitrary user_data).
	Attest func(publicKey ed25519.PublicKey, digest [32]byte) ([]byte, error)
}

// ErrTransport is a gateway that could not be reached or did not answer
// in time (no connection, a timeout, an unreadable answer).
var ErrTransport = errors.New("pushwire: gateway unreachable")

const maxAnswer = 16 << 10

// Register sends POST /v1/register and returns the wake blob. A gateway
// error is an *Error; anything else that fails is ErrTransport (or
// ErrResponse for a 201 that does not parse).
func (c *Client) Register(ctx context.Context, key ed25519.PrivateKey, r Registration) (string, error) {
	body := r.Body()
	status, ans, err := c.do(ctx, key, PathRegister, body, true)
	if err != nil {
		return "", err
	}
	if status != http.StatusCreated {
		return "", ParseError(status, ans)
	}
	return ParseRegistered(ans)
}

// Wake sends POST /v1/wake {wake_blob, class: notify} and returns the
// answer's reseal, if any.
func (c *Client) Wake(ctx context.Context, key ed25519.PrivateKey, blob string) (string, error) {
	status, ans, err := c.do(ctx, key, PathWake, WakeBody(blob), false)
	if err != nil {
		return "", err
	}
	if status != http.StatusAccepted {
		return "", ParseError(status, ans)
	}
	return ParseWoken(ans)
}

func (c *Client) do(ctx context.Context, key ed25519.PrivateKey, path string, body []byte, attest bool) (int, []byte, error) {
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(c.BaseURL, "/")+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, ErrTransport
	}
	req.Header.Set("Content-Type", "application/json")
	bh := relayauth.BodyHash(body)
	relayauth.SetHeaders(req.Header, key, http.MethodPost, path, now(), bh)
	if attest && c.Attest != nil {
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
	ans, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswer+1))
	if err != nil || len(ans) > maxAnswer {
		return 0, nil, ErrTransport
	}
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
		// Relay §7.2: the header may carry retry_after when the body does not.
		e := ParseError(resp.StatusCode, ans)
		if e.RetryAfter == 0 {
			if v, err := parseRetryAfter(resp.Header.Get("Retry-After")); err == nil {
				e.RetryAfter = v
			}
		}
		return 0, nil, e
	}
	return resp.StatusCode, ans, nil
}

func parseRetryAfter(s string) (int, error) {
	if s == "" || len(s) > 6 {
		return 0, errors.New("none")
	}
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, errors.New("bad")
		}
		n = n*10 + int(s[i]-'0')
	}
	return min(n, MaxRetryAfter), nil
}
