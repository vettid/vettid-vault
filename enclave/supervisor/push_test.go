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
	"github.com/vettid/vettid-vault/vms/nitro"
	"github.com/vettid/vettid-vault/vms/pushwire"
)

type recNSM struct {
	mu     sync.Mutex
	ud, pk []byte
}

func (n *recNSM) Attest(ud, nonce, pk []byte) ([]byte, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.ud, n.pk = append([]byte(nil), ud...), append([]byte(nil), pk...)
	return []byte("doc"), nil
}
func (n *recNSM) Measurements() (nitro.Measurements, error) { return nitro.Measurements{}, nil }

// VAULT-MESSAGING 0.24.0 §14.3, PUSH-GATEWAY §5.1: a vault process
// reaches only its channel's gateway, with requests signed by a key that
// is not its relay key; the supervisor attaches a registration's
// attestation over the digest it computes.
func TestPushChannel(t *testing.T) {
	var mu sync.Mutex
	var got []*http.Request
	gw := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = append(got, r.Clone(context.Background()))
		mu.Unlock()
		w.Header().Set("Retry-After", "9")
		w.WriteHeader(201)
		_, _ = w.Write([]byte(`{"wake_blob":"QUJD"}`))
	}))
	defer gw.Close()
	nsm := &recNSM{}
	s := &Supervisor{encCfg: enclave.Config{PushURL: gw.URL}, cfg: Config{NSM: nsm}, relayHTTP: gw.Client(), activity: map[string]time.Time{}}
	p := &vproc{h: &procHost{s: s}, vaultID: "aaaa"}
	_, wake, _ := ed25519.GenerateKey(nil)
	_, relay, _ := ed25519.GenerateKey(nil)
	p.relayKey = relay.Public().(ed25519.PublicKey)
	body := []byte(`{"platform":"fcm","token":"t","app_id":"a"}`)
	signed := func(k ed25519.PrivateKey, path string, b []byte, at time.Time) []byte {
		h := http.Header{}
		relayauth.SetHeaders(h, k, http.MethodPost, path, at, relayauth.BodyHash(b))
		h.Set(pushwire.HeaderAttestation, "Zm9yZ2Vk") // never passed on
		return vaultipc.EncodeHeaders(h)
	}
	call := func(f ...[]byte) [][]byte {
		return p.handle(context.Background(), &hostproto.Frame{Kind: vaultipc.KindPush, ID: 1, Fields: f})
	}
	now := time.Now()
	for name, f := range map[string][][]byte{
		"other path":   {[]byte("/v1/health"), signed(wake, "/v1/health", body, now), body},
		"unsigned":     {[]byte(pushwire.PathRegister), vaultipc.EncodeHeaders(http.Header{}), body},
		"wrong body":   {[]byte(pushwire.PathRegister), signed(wake, pushwire.PathRegister, body, now), []byte(`{}`)},
		"stale":        {[]byte(pushwire.PathRegister), signed(wake, pushwire.PathRegister, body, now.Add(-time.Hour)), body},
		"relay key":    {[]byte(pushwire.PathRegister), signed(relay, pushwire.PathRegister, body, now), body},
		"other path 2": {[]byte("/v1/register/../wake"), signed(wake, "/v1/register/../wake", body, now), body},
		"other path 3": {[]byte("/v1/confirm/"), signed(wake, "/v1/confirm/", body, now), body},
		// PUSH-GATEWAY 0.5.0: a confirmation gets the same checks.
		"confirm unsigned":            {[]byte(pushwire.PathConfirm), vaultipc.EncodeHeaders(http.Header{}), body},
		"confirm wrong body":          {[]byte(pushwire.PathConfirm), signed(wake, pushwire.PathConfirm, body, now), []byte(`{}`)},
		"confirm signed for register": {[]byte(pushwire.PathConfirm), signed(wake, pushwire.PathRegister, body, now), body},
		"confirm stale":               {[]byte(pushwire.PathConfirm), signed(wake, pushwire.PathConfirm, body, now.Add(-time.Hour)), body},
		"confirm relay key":           {[]byte(pushwire.PathConfirm), signed(relay, pushwire.PathConfirm, body, now), body},
		"confirm too large":           {[]byte(pushwire.PathConfirm), signed(wake, pushwire.PathConfirm, make([]byte, maxPushBody+1), now), make([]byte, maxPushBody+1)},
	} {
		if r := call(f...); string(r[0]) != vaultipc.StatusDenied {
			t.Errorf("%s: %s", name, r[0])
		}
	}
	r := call([]byte(pushwire.PathRegister), signed(wake, pushwire.PathRegister, body, now), body)
	// A push request takes one of the vault's places for requests in
	// flight, like a relay request (TestVaultEgressLimit), and gives it
	// back.
	if cap(p.egress) != maxVaultEgress || len(p.egress) != 0 {
		t.Errorf("push request and the vault's limit: %d of %d places taken", len(p.egress), cap(p.egress))
	}
	if len(r) != 4 || string(r[0]) != "ok" || string(r[1]) != "201" || string(r[3]) != `{"wake_blob":"QUJD"}` {
		t.Fatalf("register: %q", r)
	}
	if rh, _ := vaultipc.DecodeHeaders(r[2]); rh.Get("Retry-After") != "9" {
		t.Fatal("Retry-After not passed back")
	}
	mu.Lock()
	req := got[0]
	mu.Unlock()
	ts := req.Header.Get(relayauth.HeaderTimestamp)
	d := relayauth.Digest(http.MethodPost, pushwire.PathRegister, ts, relayauth.BodyHash(body))
	if !bytes.Equal(nsm.ud, d[:]) || !bytes.Equal(nsm.pk, wake.Public().(ed25519.PublicKey)) {
		t.Fatal("attestation not over the digest and the wake key")
	}
	if req.Header.Get(pushwire.HeaderAttestation) != base64.StdEncoding.EncodeToString([]byte("doc")) || req.URL.Path != pushwire.PathRegister {
		t.Fatalf("forwarded %v %s", req.Header, req.URL.Path)
	}
	// A wake carries no attestation.
	nsm.ud = nil
	wb := pushwire.WakeBody("QUJD")
	if r := call([]byte(pushwire.PathWake), signed(wake, pushwire.PathWake, wb, now), wb); string(r[0]) != "ok" {
		t.Fatalf("wake: %q", r[0])
	}
	mu.Lock()
	if got[1].Header.Get(pushwire.HeaderAttestation) != "" || nsm.ud != nil {
		t.Fatal("wake attested")
	}
	mu.Unlock()
	// PUSH-GATEWAY 0.5.0: a confirmation is forwarded, without an
	// attestation (the NSM document is for /v1/register only).
	cb := pushwire.ConfirmBody("cGVuZGluZw", "Y29kZQ")
	if r := call([]byte(pushwire.PathConfirm), signed(wake, pushwire.PathConfirm, cb, now), cb); string(r[0]) != "ok" || string(r[1]) != "201" {
		t.Fatalf("confirm: %q", r)
	}
	mu.Lock()
	if c := got[2]; c.URL.Path != pushwire.PathConfirm || c.Header.Get(pushwire.HeaderAttestation) != "" || nsm.ud != nil ||
		c.Header.Get(relayauth.HeaderKey) == "" {
		t.Fatalf("confirm forwarded %s %v (attested: %v)", c.URL.Path, c.Header, nsm.ud != nil)
	}
	mu.Unlock()
	// Without a gateway in the release, nothing.
	s.encCfg.PushURL = ""
	if r := call([]byte(pushwire.PathWake), signed(wake, pushwire.PathWake, wb, now), wb); string(r[0]) != vaultipc.StatusDenied {
		t.Fatal("no gateway: not denied")
	}
}

// VAULT-MESSAGING 0.24.1 §14.1 check 5 (owner decision 2026-10-10): an
// oversized gateway answer is passed on cut to pushwire.MaxAnswer+1 bytes,
// so the vault process sees that the gateway answered (it counts) and
// refuses the answer as oversized; it is never an IPC error.
func TestPushOversizedAnswer(t *testing.T) {
	gw := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(201)
		_, _ = w.Write(bytes.Repeat([]byte("A"), 4*pushwire.MaxAnswer))
	}))
	defer gw.Close()
	s := &Supervisor{encCfg: enclave.Config{PushURL: gw.URL}, cfg: Config{NSM: &recNSM{}}, relayHTTP: gw.Client(), activity: map[string]time.Time{}}
	p := &vproc{h: &procHost{s: s}, vaultID: "aaaa"}
	_, wake, _ := ed25519.GenerateKey(nil)
	body := []byte(`{"platform":"fcm","token":"t","app_id":"a"}`)
	h := http.Header{}
	relayauth.SetHeaders(h, wake, http.MethodPost, pushwire.PathRegister, time.Now(), relayauth.BodyHash(body))
	r := p.handle(context.Background(), &hostproto.Frame{Kind: vaultipc.KindPush, ID: 1,
		Fields: [][]byte{[]byte(pushwire.PathRegister), vaultipc.EncodeHeaders(h), body}})
	if len(r) != 4 || string(r[0]) != "ok" || string(r[1]) != "201" || len(r[3]) != pushwire.MaxAnswer+1 {
		t.Fatalf("oversized: %q %q len %d", r[0], r[1], len(r[3]))
	}
}
