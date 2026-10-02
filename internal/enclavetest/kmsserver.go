package enclavetest

import (
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/vettid/vettid-vault/enclave/awskms"
)

// TLS test PKI: a TEST-ONLY root that stands in for Amazon and Google
// Trust Services in development builds and integration tests.
var (
	tlsOnce sync.Once
	tlsCA   *CA
)

// TestTLSCA returns the shared TEST-ONLY TLS root (fixed seed).
func TestTLSCA() *CA {
	tlsOnce.Do(func() { tlsCA = NewRootCA("TEST VettID TLS root", TestKey(elliptic.P256(), 0x41)) })
	return tlsCA
}

// TLSRoots is a pool with the test TLS root.
func TLSRoots() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(TestTLSCA().Cert)
	return p
}

// ServerCert issues a TEST-ONLY server certificate for names under the
// test TLS root (valid one day around now).
func ServerCert(names ...string) tls.Certificate {
	k := TestKey(elliptic.P256(), 0x42)
	c := TestTLSCA().Issue(&x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: names[0]},
		DNSNames: names, NotBefore: time.Now().Add(-24 * time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}, k.Public())
	return tls.Certificate{Certificate: [][]byte{c.Raw, TestTLSCA().Cert.Raw}, PrivateKey: k, Leaf: c}
}

// KMSServer is a TEST-ONLY AWS KMS endpoint: the KMS JSON 1.1 API over
// HTTP(S), with SigV4 verification against known credentials, in front of
// a FakeKMS. It lets the enclave's real KMS client (SigV4, TLS, Recipient
// CMS) run unchanged in development and integration tests.
type KMSServer struct {
	KMS    *FakeKMS
	Region string
	Now    func() time.Time

	mu    sync.Mutex
	creds map[string]awskms.Credentials
	calls map[string]int
}

// NewKMSServer returns a server for region accepting the given
// credentials.
func NewKMSServer(k *FakeKMS, region string, creds ...awskms.Credentials) *KMSServer {
	s := &KMSServer{KMS: k, Region: region, Now: time.Now, creds: map[string]awskms.Credentials{}, calls: map[string]int{}}
	for _, c := range creds {
		s.creds[c.AccessKeyID] = c
	}
	return s
}

// Calls returns how many authenticated calls an operation received.
func (s *KMSServer) Calls(op string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls[op]
}

func kmsError(w http.ResponseWriter, status int, typ string) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.WriteHeader(status)
	b, _ := json.Marshal(map[string]string{"__type": typ, "message": "TEST " + typ})
	_, _ = w.Write(b)
}

// verify checks the SigV4 signature by re-signing the received request.
func (s *KMSServer) verify(r *http.Request, body []byte) bool {
	auth := r.Header.Get("Authorization")
	const pfx = "AWS4-HMAC-SHA256 Credential="
	if !strings.HasPrefix(auth, pfx) {
		return false
	}
	akid, rest, ok := strings.Cut(auth[len(pfx):], "/")
	if !ok {
		return false
	}
	s.mu.Lock()
	cr, ok := s.creds[akid]
	s.mu.Unlock()
	if !ok || !strings.Contains(rest, "/"+s.Region+"/kms/aws4_request") {
		return false
	}
	if r.Header.Get("X-Amz-Security-Token") != cr.SessionToken {
		return false
	}
	ts, err := time.Parse("20060102T150405Z", r.Header.Get("X-Amz-Date"))
	if err != nil || s.Now().Sub(ts).Abs() > 5*time.Minute {
		return false
	}
	_, signed, ok := strings.Cut(rest, "SignedHeaders=")
	if !ok {
		return false
	}
	signed, _, _ = strings.Cut(signed, ",")
	re, _ := http.NewRequest(r.Method, "https://"+r.Host+r.URL.RequestURI(), nil)
	re.ContentLength = int64(len(body))
	for _, h := range strings.Split(signed, ";") {
		if h == "host" || h == "content-length" || h == "x-amz-date" || h == "x-amz-security-token" {
			continue
		}
		re.Header[http.CanonicalHeaderKey(h)] = r.Header.Values(h)
	}
	if !cr.Expires.IsZero() && s.Now().After(cr.Expires) {
		return false
	}
	awskms.Sign(re, sha256Hex(body), cr, s.Region, "kms", ts)
	return subtle.ConstantTimeCompare([]byte(re.Header.Get("Authorization")), []byte(auth)) == 1
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

type kmsRequest struct {
	KeyId          string
	KeySpec        string
	PolicyName     string
	CiphertextBlob []byte
	Limit          int
	Recipient      *struct {
		KeyEncryptionAlgorithm string
		AttestationDocument    []byte
	}
}

// ServeHTTP implements the KMS JSON API subset the enclave uses.
func (s *KMSServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil || r.Method != http.MethodPost || r.URL.Path != "/" || r.Header.Get("Content-Type") != "application/x-amz-json-1.1" {
		kmsError(w, http.StatusBadRequest, "SerializationException")
		return
	}
	if !s.verify(r, body) {
		kmsError(w, http.StatusBadRequest, "InvalidSignatureException")
		return
	}
	op, ok := strings.CutPrefix(r.Header.Get("X-Amz-Target"), "TrentService.")
	if !ok {
		kmsError(w, http.StatusBadRequest, "UnknownOperationException")
		return
	}
	var req kmsRequest
	if err := json.Unmarshal(body, &req); err != nil || req.KeyId == "" {
		kmsError(w, http.StatusBadRequest, "ValidationException")
		return
	}
	s.mu.Lock()
	s.calls[op]++
	s.mu.Unlock()
	att := func() ([]byte, bool) {
		if req.Recipient == nil || req.Recipient.KeyEncryptionAlgorithm != "RSAES_OAEP_SHA_256" {
			return nil, false
		}
		return req.Recipient.AttestationDocument, true
	}
	var out any
	ctx := r.Context()
	switch op {
	case "GenerateDataKey":
		a, ok := att()
		if !ok || req.KeySpec != "AES_256" {
			kmsError(w, http.StatusBadRequest, "ValidationException")
			return
		}
		blob, cfr, err := s.KMS.GenerateDataKey(ctx, req.KeyId, a)
		if err != nil {
			s.fail(w, err)
			return
		}
		out = map[string]any{"CiphertextBlob": blob, "CiphertextForRecipient": cfr, "KeyId": req.KeyId}
	case "Decrypt":
		a, ok := att()
		if !ok {
			kmsError(w, http.StatusBadRequest, "ValidationException")
			return
		}
		cfr, err := s.KMS.Decrypt(ctx, req.KeyId, req.CiphertextBlob, a)
		if err != nil {
			s.fail(w, err)
			return
		}
		out = map[string]any{"CiphertextForRecipient": cfr, "KeyId": req.KeyId, "EncryptionAlgorithm": "SYMMETRIC_DEFAULT"}
	case "DescribeKey", "GetKeyPolicy", "ListGrants":
		var b []byte
		switch op {
		case "DescribeKey":
			b, err = s.KMS.DescribeKey(ctx, req.KeyId)
		case "GetKeyPolicy":
			if req.PolicyName != "default" {
				kmsError(w, http.StatusBadRequest, "ValidationException")
				return
			}
			b, err = s.KMS.GetKeyPolicy(ctx, req.KeyId)
		default:
			b, err = s.KMS.ListGrants(ctx, req.KeyId)
		}
		if err != nil {
			s.fail(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		_, _ = w.Write(b)
		return
	default:
		kmsError(w, http.StatusBadRequest, "UnknownOperationException")
		return
	}
	b, _ := json.Marshal(out) // []byte members encode as base64, as KMS sends blobs
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	_, _ = w.Write(b)
}

func (s *KMSServer) fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrKMSNotFound):
		kmsError(w, http.StatusBadRequest, "NotFoundException")
	case errors.Is(err, ErrKMSInvalid):
		kmsError(w, http.StatusBadRequest, "InvalidCiphertextException")
	default:
		kmsError(w, http.StatusBadRequest, "AccessDeniedException")
	}
}
