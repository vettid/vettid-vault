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
// in time (no connection, a timeout, an answer cut off while read).
var ErrTransport = errors.New("pushwire: gateway unreachable")

// ErrOversized is a gateway answer longer than MaxAnswer: the gateway
// answered, but not with anything the vault reads.
var ErrOversized = errors.New("pushwire: gateway answer too large")

// MaxAnswer bounds a gateway answer's body. The enclave's supervisor
// passes at most MaxAnswer+1 bytes on, so an oversized answer is still
// recognised behind it.
const MaxAnswer = 16 << 10

// Answered reports whether err, from Register, Confirm or Wake, means the gateway
// answered over HTTP: an error answer (*Error), an answer that does not
// parse (ErrResponse) or one that is too large (ErrOversized). Such a
// registration counts toward push_registrations whatever the answer; a
// timeout or no connection does not (VAULT-MESSAGING 0.24.1 §14.1 check
// 5, owner decision 2026-10-10).
func Answered(err error) bool {
	var ge *Error
	return err == nil || errors.As(err, &ge) || errors.Is(err, ErrResponse) || errors.Is(err, ErrOversized)
}

// Register sends POST /v1/register, attested, and returns the pending
// registration of the gateway's 202 (PUSH-GATEWAY 0.5.0 §5.1); the gateway
// has sent the challenge code to the token. A gateway error is an *Error;
// anything else that fails is ErrTransport (or ErrResponse for a 202 that
// does not parse).
func (c *Client) Register(ctx context.Context, key ed25519.PrivateKey, r Registration) (string, error) {
	body := r.Body()
	status, ans, err := c.do(ctx, key, PathRegister, body, true)
	if err != nil {
		return "", err
	}
	if status != http.StatusAccepted {
		return "", ParseError(status, ans)
	}
	return ParsePending(ans)
}

// Confirm sends POST /v1/confirm {pending, code}, signed by the same wake
// key as the registration and without an attestation, and returns the
// wake blob of the gateway's 201 (PUSH-GATEWAY 0.5.0 §5.1). A wrong code,
// another key or a pending registration over 10 minutes old is 403
// challenge_invalid (*Error).
func (c *Client) Confirm(ctx context.Context, key ed25519.PrivateKey, pending, code string) (string, error) {
	status, ans, err := c.do(ctx, key, PathConfirm, ConfirmBody(pending, code), false)
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
	ans, err := io.ReadAll(io.LimitReader(resp.Body, MaxAnswer+1))
	if err != nil {
		return 0, nil, ErrTransport
	}
	if len(ans) > MaxAnswer {
		return 0, nil, ErrOversized
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
