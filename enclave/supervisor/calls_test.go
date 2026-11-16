package supervisor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"

	"github.com/vettid/vettid-vault/enclave"
	"github.com/vettid/vettid-vault/internal/hostproto"
	"github.com/vettid/vettid-vault/internal/vaultipc"
	"github.com/vettid/vettid-vault/vms/callswire"
)

// VAULT-MESSAGING §10.10 "Servers and credentials", CALLING-SERVICE §5.2: a vault process reaches only its
// channel's issuer, only POST /v1/credentials, with a request signed by a key that is not its relay key; the
// supervisor attaches the attestation over the digest it computes and drops one the process sent.
func TestCallsChannel(t *testing.T) {
	var mu sync.Mutex
	var got []*http.Request
	is := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = append(got, r.Clone(context.Background()))
		mu.Unlock()
		w.Header().Set("Retry-After", "7")
		_, _ = w.Write([]byte(`{"stun":[],"turn":[],"credentials":[]}`))
	}))
	defer is.Close()
	nsm := &recNSM{}
	s := &Supervisor{encCfg: enclave.Config{CallsURL: is.URL}, cfg: Config{NSM: nsm}, relayHTTP: is.Client(), activity: map[string]time.Time{}}
	p := &vproc{h: &procHost{s: s}, vaultID: "aaaa"}
	_, key, _ := ed25519.GenerateKey(nil)
	_, relay, _ := ed25519.GenerateKey(nil)
	p.relayKey = relay.Public().(ed25519.PublicKey)
	body := callswire.RequestBody(4)
	signed := func(k ed25519.PrivateKey, path string, b []byte, at time.Time) []byte {
		h := http.Header{}
		relayauth.SetHeaders(h, k, http.MethodPost, path, at, relayauth.BodyHash(b))
		h.Set(callswire.HeaderAttestation, "Zm9yZ2Vk") // never passed on
		return vaultipc.EncodeHeaders(h)
	}
	call := func(f ...[]byte) [][]byte {
		return p.handle(context.Background(), &hostproto.Frame{Kind: vaultipc.KindCalls, ID: 1, Fields: f})
	}
	now := time.Now()
	path := []byte(callswire.PathCredentials)
	big := make([]byte, maxCallsBody+1)
	for name, f := range map[string][][]byte{
		"health":       {[]byte(callswire.PathHealth), signed(key, callswire.PathHealth, body, now), body},
		"other path":   {[]byte("/v1/credentials/"), signed(key, "/v1/credentials/", body, now), body},
		"unsigned":     {path, vaultipc.EncodeHeaders(http.Header{}), body},
		"wrong body":   {path, signed(key, callswire.PathCredentials, body, now), []byte(`{"count":1}`)},
		"stale":        {path, signed(key, callswire.PathCredentials, body, now.Add(-time.Hour)), body},
		"relay key":    {path, signed(relay, callswire.PathCredentials, body, now), body},
		"too large":    {path, signed(key, callswire.PathCredentials, big, now), big},
		"short frame":  {path, signed(key, callswire.PathCredentials, body, now)},
		"signed other": {path, signed(key, callswire.PathHealth, body, now), body},
		// Signed for /v1/credentials, asked for another path: refused by the path, not only by the signature.
		"health, signed for credentials": {[]byte(callswire.PathHealth), signed(key, callswire.PathCredentials, body, now), body},
	} {
		if r := call(f...); string(r[0]) != vaultipc.StatusDenied {
			t.Errorf("%s: %s", name, r[0])
		}
	}
	mu.Lock()
	if len(got) != 0 {
		t.Fatalf("%d denied requests reached the issuer", len(got))
	}
	mu.Unlock()
	r := call(path, signed(key, callswire.PathCredentials, body, now), body)
	if cap(p.egress) != maxVaultEgress || len(p.egress) != 0 {
		t.Errorf("calls request and the vault's limit: %d of %d places taken", len(p.egress), cap(p.egress))
	}
	if len(r) != 4 || string(r[0]) != "ok" || string(r[1]) != "200" {
		t.Fatalf("credentials: %q", r)
	}
	if rh, _ := vaultipc.DecodeHeaders(r[2]); rh.Get("Retry-After") != "7" {
		t.Fatal("Retry-After not passed back")
	}
	mu.Lock()
	req := got[0]
	mu.Unlock()
	ts := req.Header.Get(relayauth.HeaderTimestamp)
	d := relayauth.Digest(http.MethodPost, callswire.PathCredentials, ts, relayauth.BodyHash(body))
	if !bytes.Equal(nsm.ud, d[:]) || !bytes.Equal(nsm.pk, key.Public().(ed25519.PublicKey)) {
		t.Fatal("attestation not over the digest and the request's key")
	}
	if req.Header.Get(callswire.HeaderAttestation) != base64.StdEncoding.EncodeToString([]byte("doc")) || req.URL.Path != callswire.PathCredentials {
		t.Fatalf("forwarded %v %s", req.Header, req.URL.Path)
	}
	// Without an issuer in the release, nothing.
	s.encCfg.CallsURL = ""
	if r := call(path, signed(key, callswire.PathCredentials, body, now), body); string(r[0]) != vaultipc.StatusDenied {
		t.Fatal("no issuer: not denied")
	}
}

// An issuer that does not answer within the attempt's time is an error to the vault process, and an answer longer
// than callswire.MaxAnswer is passed on cut to MaxAnswer+1 bytes (the process refuses it as oversized).
func TestCallsTimeoutAndCap(t *testing.T) {
	slow := make(chan struct{})
	is := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Test") == "" {
			select {
			case <-slow:
			case <-r.Context().Done():
			case <-time.After(3 * time.Second): // an answer after the attempt's time must not be taken
				_, _ = w.Write([]byte(`{"stun":[],"turn":[],"credentials":[]}`))
			}
			return
		}
		_, _ = w.Write(bytes.Repeat([]byte("a"), callswire.MaxAnswer+100))
	}))
	defer is.Close()
	defer close(slow)
	old := callsAttempt
	callsAttempt = 200 * time.Millisecond
	defer func() { callsAttempt = old }()
	s := &Supervisor{encCfg: enclave.Config{CallsURL: is.URL}, cfg: Config{NSM: &recNSM{}}, relayHTTP: is.Client(), activity: map[string]time.Time{}}
	p := &vproc{h: &procHost{s: s}, vaultID: "aaaa"}
	_, key, _ := ed25519.GenerateKey(nil)
	body := callswire.RequestBody(1)
	h := http.Header{}
	relayauth.SetHeaders(h, key, http.MethodPost, callswire.PathCredentials, time.Now(), relayauth.BodyHash(body))
	call := func() [][]byte {
		return p.handle(context.Background(), &hostproto.Frame{Kind: vaultipc.KindCalls, ID: 1,
			Fields: [][]byte{[]byte(callswire.PathCredentials), vaultipc.EncodeHeaders(h), body}})
	}
	start := time.Now()
	if r := call(); string(r[0]) != hostproto.StatusError || time.Since(start) > 5*time.Second {
		t.Fatalf("slow issuer: %q after %v", r[0], time.Since(start))
	}
	// The test header is not one the supervisor forwards: send it through a client that adds it.
	is.Client().Transport.(*http.Transport).Proxy = nil
	s.relayHTTP = &http.Client{Transport: addHeader{is.Client().Transport}}
	r := call()
	if string(r[0]) != hostproto.StatusOK || len(r[3]) != callswire.MaxAnswer+1 {
		t.Fatalf("oversized answer: %q, %d bytes", r[0], len(r[3]))
	}
}

type addHeader struct{ rt http.RoundTripper }

func (a addHeader) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("X-Test", "1")
	return a.rt.RoundTrip(r)
}
