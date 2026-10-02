// Package awskms is the enclave's AWS KMS client (VAULT-MESSAGING
// §11.10.2, §11.10.7): the JSON 1.1 API over the egress transport (TLS
// terminated in the enclave against the pinned Amazon roots), signed with
// AWS Signature Version 4 by code in this package, using temporary
// credentials of the host's instance role that the parent passes in.
//
// No AWS SDK is linked into the enclave. The credentials only authorize
// requests; the host cannot forge or alter a TLS-authenticated KMS
// response, and the data keys KMS returns are encrypted to the enclave's
// attested Recipient key.
package awskms

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Credentials are temporary AWS credentials.
type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	// Expires is zero for credentials without an expiry (development).
	Expires time.Time
}

// Valid reports whether the credentials are complete and not within skew
// of expiring.
func (c Credentials) Valid(now time.Time, skew time.Duration) bool {
	if c.AccessKeyID == "" || c.SecretAccessKey == "" {
		return false
	}
	return c.Expires.IsZero() || now.Add(skew).Before(c.Expires)
}

const (
	algorithm   = "AWS4-HMAC-SHA256"
	amzDateFmt  = "20060102T150405Z"
	shortDate   = "20060102"
	unsignedHdr = "authorization"
)

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// uriEncode is SigV4 URI encoding: unreserved characters stay, everything
// else is %XX (uppercase); '/' is kept when encoding a path.
func uriEncode(s string, path bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		case c == '/' && path:
			b.WriteByte(c)
		default:
			b.WriteString("%" + strings.ToUpper(hex.EncodeToString([]byte{c})))
		}
	}
	return b.String()
}

// canonicalPath double-encodes the escaped path (every service but S3).
func canonicalPath(u *url.URL) string {
	p := u.EscapedPath()
	if p == "" {
		return "/"
	}
	return uriEncode(p, true)
}

func canonicalQuery(u *url.URL) string {
	q := u.Query()
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		vs := append([]string(nil), q[k]...)
		sort.Strings(vs)
		for _, v := range vs {
			parts = append(parts, uriEncode(k, false)+"="+uriEncode(v, false))
		}
	}
	return strings.Join(parts, "&")
}

func trimSpaces(s string) string { return strings.Join(strings.Fields(s), " ") }

// Sign adds X-Amz-Date, X-Amz-Security-Token (if any) and Authorization
// to req, signing every header present, Host, Content-Length (when
// positive) and payloadHash (hex SHA-256 of the body), as the AWS SDKs do.
func Sign(req *http.Request, payloadHash string, c Credentials, region, service string, t time.Time) {
	t = t.UTC()
	amzDate := t.Format(amzDateFmt)
	req.Header.Set("X-Amz-Date", amzDate)
	if c.SessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", c.SessionToken)
	}
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	hdrs := map[string]string{"host": trimSpaces(host)}
	if req.ContentLength > 0 {
		hdrs["content-length"] = strconv.FormatInt(req.ContentLength, 10)
	}
	for k, vs := range req.Header {
		lk := strings.ToLower(k)
		if lk == unsignedHdr || lk == "user-agent" || lk == "content-length" {
			continue
		}
		vals := make([]string, len(vs))
		for i, v := range vs {
			vals[i] = trimSpaces(v)
		}
		hdrs[lk] = strings.Join(vals, ",")
	}
	names := make([]string, 0, len(hdrs))
	for k := range hdrs {
		names = append(names, k)
	}
	sort.Strings(names)
	var ch strings.Builder
	for _, k := range names {
		ch.WriteString(k + ":" + hdrs[k] + "\n")
	}
	signed := strings.Join(names, ";")
	creq := strings.Join([]string{req.Method, canonicalPath(req.URL), canonicalQuery(req.URL), ch.String(), signed, payloadHash}, "\n")
	scope := t.Format(shortDate) + "/" + region + "/" + service + "/aws4_request"
	sts := algorithm + "\n" + amzDate + "\n" + scope + "\n" + sha256Hex([]byte(creq))
	k := hmacSHA256([]byte("AWS4"+c.SecretAccessKey), t.Format(shortDate))
	k = hmacSHA256(k, region)
	k = hmacSHA256(k, service)
	k = hmacSHA256(k, "aws4_request")
	sig := hex.EncodeToString(hmacSHA256(k, sts))
	req.Header.Set("Authorization", algorithm+" Credential="+c.AccessKeyID+"/"+scope+", SignedHeaders="+signed+", Signature="+sig)
}
