package awskms

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
)

// CredentialSource supplies credentials (the parent, over the control
// connection). Refresh forces a new fetch.
type CredentialSource interface {
	Credentials(ctx context.Context, refresh bool) (Credentials, error)
}

// Errors. AWS error types are reported by name only (never the message,
// which can echo request data).
var (
	ErrTransport = errors.New("awskms: request failed")
	ErrResponse  = errors.New("awskms: malformed response")
	ErrNoCreds   = errors.New("awskms: no credentials")
)

// APIError is an error response from KMS.
type APIError struct {
	Status int
	Type   string
}

func (e *APIError) Error() string { return "awskms: " + e.Type }

// MaxResponse bounds a response body (a key policy is at most 32 KiB; a
// ListGrants page of 100 grants stays well under this).
const MaxResponse = 1 << 20

// Client calls KMS in one region.
type Client struct {
	HTTP   *http.Client
	Region string
	// Endpoint is https://kms.<region>.amazonaws.com (default).
	Endpoint string
	Creds    CredentialSource
	Now      func() time.Time
}

// NewClient returns a client for region over hc.
func NewClient(hc *http.Client, region string, creds CredentialSource) *Client {
	return &Client{HTTP: hc, Region: region, Endpoint: "https://kms." + region + ".amazonaws.com", Creds: creds, Now: time.Now}
}

func (c *Client) now() time.Time {
	if c.Now == nil {
		return time.Now()
	}
	return c.Now()
}

// call sends one signed request and returns the response body. Expired or
// unrecognized credentials are refreshed once.
func (c *Client) call(ctx context.Context, op string, body []byte) ([]byte, error) {
	if c.Creds == nil {
		return nil, ErrNoCreds
	}
	for attempt := 0; ; attempt++ {
		cr, err := c.Creds.Credentials(ctx, attempt > 0)
		if err != nil || !cr.Valid(c.now(), 0) {
			return nil, ErrNoCreds
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint+"/", bytes.NewReader(body))
		if err != nil {
			return nil, ErrTransport
		}
		req.Header.Set("Content-Type", "application/x-amz-json-1.1")
		req.Header.Set("X-Amz-Target", "TrentService."+op)
		Sign(req, sha256Hex(body), cr, c.Region, "kms", c.now())
		resp, err := c.HTTP.Do(req)
		if err != nil {
			return nil, ErrTransport
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponse+1))
		resp.Body.Close()
		if err != nil || len(b) > MaxResponse {
			return nil, ErrTransport
		}
		if resp.StatusCode == http.StatusOK {
			return b, nil
		}
		ae := &APIError{Status: resp.StatusCode, Type: errorType(b)}
		if attempt == 0 && (ae.Type == "ExpiredTokenException" || ae.Type == "UnrecognizedClientException" || ae.Type == "InvalidSignatureException") {
			continue
		}
		return nil, ae
	}
}

// errorType extracts __type ("prefix#Name" or "Name") from an error body.
func errorType(b []byte) string {
	o, err := strictjson.ParseObject(b)
	if err != nil {
		return "Unknown"
	}
	t, err := o.String("__type")
	if err != nil {
		return "Unknown"
	}
	if i := bytes.LastIndexByte([]byte(t), '#'); i >= 0 {
		t = t[i+1:]
	}
	if len(t) == 0 || len(t) > 64 {
		return "Unknown"
	}
	for i := 0; i < len(t); i++ {
		ch := t[i]
		if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '.' || ch == '_') {
			return "Unknown"
		}
	}
	return t
}

func recipient(att []byte) *strictjson.Builder {
	return strictjson.NewBuilder().String("KeyEncryptionAlgorithm", "RSAES_OAEP_SHA_256").Base64("AttestationDocument", att)
}

// GenerateDataKey requests an AES-256 data key for keyARN with the
// Recipient attestation att; it returns CiphertextBlob and
// CiphertextForRecipient (a CMS envelope to att's RSA key). A response
// that carries the plaintext key is refused.
func (c *Client) GenerateDataKey(ctx context.Context, keyARN string, att []byte) ([]byte, []byte, error) {
	body := strictjson.NewBuilder().String("KeyId", keyARN).String("KeySpec", "AES_256").Raw("Recipient", recipient(att).Bytes()).Bytes()
	b, err := c.call(ctx, "GenerateDataKey", body)
	if err != nil {
		return nil, nil, err
	}
	o, err := strictjson.ParseObject(b)
	if err != nil {
		return nil, nil, ErrResponse
	}
	if !noPlaintext(o) {
		return nil, nil, ErrResponse // a plaintext key outside the enclave's Recipient key
	}
	blob, err := o.Base64("CiphertextBlob", -1)
	if err != nil || len(blob) == 0 {
		return nil, nil, ErrResponse
	}
	cfr, err := o.Base64("CiphertextForRecipient", -1)
	if err != nil || len(cfr) == 0 {
		return nil, nil, ErrResponse
	}
	return blob, cfr, nil
}

// Decrypt decrypts blob under keyARN (KeyId pins the key) for the
// Recipient attestation att and returns CiphertextForRecipient.
func (c *Client) Decrypt(ctx context.Context, keyARN string, blob, att []byte) ([]byte, error) {
	body := strictjson.NewBuilder().String("KeyId", keyARN).Base64("CiphertextBlob", blob).Raw("Recipient", recipient(att).Bytes()).Bytes()
	b, err := c.call(ctx, "Decrypt", body)
	if err != nil {
		return nil, err
	}
	o, err := strictjson.ParseObject(b)
	if err != nil {
		return nil, ErrResponse
	}
	if !noPlaintext(o) {
		return nil, ErrResponse
	}
	if k, err := o.String("KeyId"); err != nil || k != keyARN {
		return nil, ErrResponse
	}
	cfr, err := o.Base64("CiphertextForRecipient", -1)
	if err != nil || len(cfr) == 0 {
		return nil, ErrResponse
	}
	return cfr, nil
}

// DescribeKey returns the raw DescribeKey response (checked by package
// keypolicy).
func (c *Client) DescribeKey(ctx context.Context, keyARN string) ([]byte, error) {
	return c.call(ctx, "DescribeKey", strictjson.NewBuilder().String("KeyId", keyARN).Bytes())
}

// GetKeyPolicy returns the raw GetKeyPolicy response for the policy named
// "default".
func (c *Client) GetKeyPolicy(ctx context.Context, keyARN string) ([]byte, error) {
	return c.call(ctx, "GetKeyPolicy", strictjson.NewBuilder().String("KeyId", keyARN).String("PolicyName", "default").Bytes())
}

// ListGrants returns the raw first page of ListGrants (Limit 100). A
// truncated listing fails the §11.10.7 check, so later pages are never
// needed.
func (c *Client) ListGrants(ctx context.Context, keyARN string) ([]byte, error) {
	return c.call(ctx, "ListGrants", strictjson.NewBuilder().String("KeyId", keyARN).Uint("Limit", 100).Bytes())
}

// CachedCredentials caches a CredentialSource's credentials until skew
// before they expire.
type CachedCredentials struct {
	Source func(ctx context.Context) (Credentials, error)
	Skew   time.Duration
	Now    func() time.Time

	mu  sync.Mutex
	cur Credentials
}

// Credentials implements CredentialSource.
func (c *CachedCredentials) Credentials(ctx context.Context, refresh bool) (Credentials, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	if c.Now != nil {
		now = c.Now()
	}
	if !refresh && c.cur.Valid(now, c.Skew) {
		return c.cur, nil
	}
	cr, err := c.Source(ctx)
	if err != nil {
		return Credentials{}, err
	}
	if !cr.Valid(now, 0) {
		return Credentials{}, ErrNoCreds
	}
	c.cur = cr
	return cr, nil
}

// noPlaintext reports that a Recipient response carries no plaintext
// (Plaintext absent, null or empty).
func noPlaintext(o strictjson.Object) bool {
	raw, ok := o["Plaintext"]
	if !ok {
		return true
	}
	s := string(bytes.TrimSpace(raw))
	return s == "null" || s == `""`
}
