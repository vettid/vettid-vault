// Package s3counter is the enclave's client for the recovery attempt
// counter's S3 bucket (VAULT-HOST-PROTOCOL 0.1.10 §8.1, P16-P18): five
// calls (PutObject, GetObjectRetention, GetObject by version,
// ListObjectVersions; PutObjectRetention is never needed because every
// write sets its lock), each to the bucket's virtual-hosted name pinned in
// the release, with x-amz-expected-bucket-owner set to the pinned account
// and signed, over the enclave's own TLS through the egress. It follows no
// redirect and refuses any key outside recovery/v1/. Request limits: 15 s
// to the answer's headers (the egress), 30 s in all.
package s3counter

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/vettid/vettid-vault/enclave/awskms"
	"github.com/vettid/vettid-vault/vault/counter"
	"github.com/vettid/vettid-vault/vms/recovery"
)

// Limits.
const (
	RequestTimeout = 30 * time.Second
	maxBody        = 1 << 20
	maxPages       = 64
	maxObjectBody  = 64
)

// ErrKey: a key outside the counter's prefix.
var ErrKey = errors.New("s3counter: key outside recovery/v1/")

// Client calls one pinned bucket.
type Client struct {
	HTTP    *http.Client
	Bucket  string
	Account string
	Region  string
	Creds   awskms.CredentialSource
	Now     func() time.Time
	// Endpoint overrides https://<bucket>.s3.<region>.amazonaws.com
	// (tests and the development stack only; the host keeps the bucket's
	// virtual-hosted name).
	Endpoint string
}

var _ counter.Bucket = (*Client)(nil)

func (c *Client) host() string { return c.Bucket + ".s3." + c.Region + ".amazonaws.com" }

func (c *Client) base() string {
	if c.Endpoint != "" {
		return c.Endpoint
	}
	return "https://" + c.host()
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func validKey(k string) bool {
	if !strings.HasPrefix(k, recovery.CounterPrefixRoot) || len(k) > 512 {
		return false
	}
	for i := 0; i < len(k); i++ {
		if ch := k[i]; !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '/' || ch == '-') {
			return false
		}
	}
	return true
}

type response struct {
	status int
	header http.Header
	body   []byte
}

// do signs and sends one request. Redirects are not followed (the http
// client must not follow them either: CheckRedirect is set by New).
func (c *Client) do(ctx context.Context, method, key string, q url.Values, hdr http.Header, body []byte) (*response, error) {
	if c.Creds == nil || c.HTTP == nil {
		return nil, counter.ErrUnknown
	}
	ctx, cancel := context.WithTimeout(ctx, RequestTimeout)
	defer cancel()
	cr, err := c.Creds.Credentials(ctx, false)
	if err != nil || !cr.Valid(c.now(), 0) {
		return nil, counter.ErrUnknown
	}
	u := c.base() + "/" + key
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(body))
	if err != nil {
		return nil, counter.ErrUnknown
	}
	req.Host = c.host()
	req.ContentLength = int64(len(body))
	for k, vs := range hdr {
		req.Header[k] = vs
	}
	req.Header.Set("X-Amz-Expected-Bucket-Owner", c.Account)
	h := sha256.Sum256(body)
	ph := hex.EncodeToString(h[:])
	req.Header.Set("X-Amz-Content-Sha256", ph)
	awskms.Sign(req, ph, cr, c.Region, "s3", c.now())
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, counter.ErrUnknown
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil || len(b) > maxBody {
		return nil, counter.ErrUnknown
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return nil, counter.ErrUnknown // no redirect is followed
	}
	return &response{status: resp.StatusCode, header: resp.Header, body: b}, nil
}

type listResult struct {
	XMLName             xml.Name `xml:"ListVersionsResult"`
	IsTruncated         bool     `xml:"IsTruncated"`
	NextKeyMarker       string   `xml:"NextKeyMarker"`
	NextVersionIDMarker string   `xml:"NextVersionIdMarker"`
	Versions            []struct {
		Key          string `xml:"Key"`
		VersionID    string `xml:"VersionId"`
		LastModified string `xml:"LastModified"`
	} `xml:"Version"`
	DeleteMarkers []struct {
		Key          string `xml:"Key"`
		VersionID    string `xml:"VersionId"`
		LastModified string `xml:"LastModified"`
	} `xml:"DeleteMarker"`
}

func parseTime(s string) (time.Time, error) { return time.Parse(time.RFC3339Nano, s) }

// List implements counter.Bucket: a complete versions listing, every page
// followed; Date is the last page's.
func (c *Client) List(ctx context.Context, prefix string) (counter.Listing, error) {
	if !validKey(prefix) {
		return counter.Listing{}, ErrKey
	}
	var out counter.Listing
	km, vm := "", ""
	for page := 0; page < maxPages; page++ {
		q := url.Values{"versions": {""}, "prefix": {prefix}}
		if km != "" {
			q.Set("key-marker", km)
			q.Set("version-id-marker", vm)
		}
		r, err := c.do(ctx, http.MethodGet, "", q, nil, nil)
		if err != nil || r.status != http.StatusOK {
			return counter.Listing{}, counter.ErrUnknown
		}
		var lr listResult
		if xml.Unmarshal(r.body, &lr) != nil {
			return counter.Listing{}, counter.ErrUnknown
		}
		date, err := http.ParseTime(r.header.Get("Date"))
		if err != nil {
			return counter.Listing{}, counter.ErrUnknown
		}
		out.Date = date.UTC()
		for _, v := range lr.Versions {
			t, err := parseTime(v.LastModified)
			if err != nil || !strings.HasPrefix(v.Key, prefix) {
				return counter.Listing{}, counter.ErrUnknown
			}
			out.Entries = append(out.Entries, counter.Entry{Key: v.Key, VersionID: v.VersionID, LastModified: t.UTC()})
		}
		for _, v := range lr.DeleteMarkers {
			t, err := parseTime(v.LastModified)
			if err != nil || !strings.HasPrefix(v.Key, prefix) {
				return counter.Listing{}, counter.ErrUnknown
			}
			out.Entries = append(out.Entries, counter.Entry{Key: v.Key, VersionID: v.VersionID, LastModified: t.UTC(), DeleteMarker: true})
		}
		if !lr.IsTruncated {
			return out, nil
		}
		if lr.NextKeyMarker == "" {
			return counter.Listing{}, counter.ErrUnknown
		}
		km, vm = lr.NextKeyMarker, lr.NextVersionIDMarker
	}
	return counter.Listing{}, counter.ErrUnknown // not complete: decide nothing from it
}

func lockHeaders(body []byte, until time.Time) http.Header {
	sum := md5.Sum(body) // S3 requires an integrity header on Object Lock writes
	return http.Header{
		"X-Amz-Object-Lock-Mode":              {counter.ModeCompliance},
		"X-Amz-Object-Lock-Retain-Until-Date": {until.UTC().Format("2006-01-02T15:04:05.000Z")},
		"Content-Md5":                         {base64.StdEncoding.EncodeToString(sum[:])},
	}
}

// PutCreate implements counter.Bucket.
func (c *Client) PutCreate(ctx context.Context, key string, body []byte, until time.Time) (int, string, error) {
	if !validKey(key) {
		return 0, "", ErrKey
	}
	h := lockHeaders(body, until)
	h.Set("If-None-Match", "*")
	r, err := c.do(ctx, http.MethodPut, key, nil, h, body)
	if err != nil {
		return 0, "", err
	}
	switch r.status {
	case http.StatusOK:
		v := r.header.Get("X-Amz-Version-Id")
		if v == "" {
			return 0, "", counter.ErrUnknown
		}
		return counter.PutOK, v, nil
	case http.StatusPreconditionFailed:
		return counter.PutPrecondition, "", nil
	}
	return 0, "", counter.ErrUnknown // 409 included: the outcome is unknown
}

// Put implements counter.Bucket.
func (c *Client) Put(ctx context.Context, key string, body []byte, until time.Time) (string, error) {
	if !validKey(key) {
		return "", ErrKey
	}
	r, err := c.do(ctx, http.MethodPut, key, nil, lockHeaders(body, until), body)
	if err != nil || r.status != http.StatusOK || r.header.Get("X-Amz-Version-Id") == "" {
		return "", counter.ErrUnknown
	}
	return r.header.Get("X-Amz-Version-Id"), nil
}

type retentionResult struct {
	XMLName         xml.Name `xml:"Retention"`
	Mode            string   `xml:"Mode"`
	RetainUntilDate string   `xml:"RetainUntilDate"`
}

// GetRetention implements counter.Bucket.
func (c *Client) GetRetention(ctx context.Context, key, versionID string) (counter.Retention, error) {
	if !validKey(key) || versionID == "" {
		return counter.Retention{}, ErrKey
	}
	r, err := c.do(ctx, http.MethodGet, key, url.Values{"retention": {""}, "versionId": {versionID}}, nil, nil)
	if err != nil || r.status != http.StatusOK {
		return counter.Retention{}, counter.ErrUnknown
	}
	var rr retentionResult
	if xml.Unmarshal(r.body, &rr) != nil {
		return counter.Retention{}, counter.ErrUnknown
	}
	t, err := parseTime(rr.RetainUntilDate)
	if err != nil {
		return counter.Retention{}, counter.ErrUnknown
	}
	return counter.Retention{Mode: rr.Mode, Until: t.UTC()}, nil
}

// GetVersion implements counter.Bucket.
func (c *Client) GetVersion(ctx context.Context, key, versionID string) ([]byte, error) {
	if !validKey(key) || versionID == "" {
		return nil, ErrKey
	}
	r, err := c.do(ctx, http.MethodGet, key, url.Values{"versionId": {versionID}}, nil, nil)
	if err != nil || r.status != http.StatusOK || len(r.body) > maxObjectBody {
		return nil, counter.ErrUnknown
	}
	return r.body, nil
}

// NoRedirect is the CheckRedirect an http.Client for the counter uses.
func NoRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
