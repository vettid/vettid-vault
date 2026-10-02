package supervisor

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/enclave"
	"github.com/vettid/vettid-vault/internal/hostproto"
	"github.com/vettid/vettid-vault/internal/selftest"
	"github.com/vettid/vettid-vault/internal/vaultipc"
	"github.com/vettid/vettid-vault/vms/nitro"
)

type stubNSM struct{ calls int }

func (n *stubNSM) Attest(ud, nonce, pk []byte) ([]byte, error) { n.calls++; return []byte("doc"), nil }
func (n *stubNSM) Measurements() (nitro.Measurements, error)   { return nitro.Measurements{}, nil }

// A vault process reaches only its own vault through the channel
// (VAULT-MESSAGING §12.4).
func TestChannelScope(t *testing.T) {
	l := fakeParent(t, func(f *hostproto.Frame) [][]byte {
		switch f.Kind {
		case hostproto.KindStoreGet:
			return hostproto.Strings("ok", "data", `"v"`)
		case hostproto.KindStorePut:
			return hostproto.Strings("ok", `"v2"`)
		}
		return hostproto.Strings("ok")
	})
	nsm := &stubNSM{}
	s := &Supervisor{st: &hostStore{l: l}, encCfg: enclave.Config{SealAccount: "111122223333", SealRegion: "us-east-1"},
		relays: map[string]bool{"relay.example": true}, cfg: Config{NSM: nsm}, activity: map[string]time.Time{}}
	h := &procHost{s: s}
	p := &vproc{h: h, vaultID: "aaaa", userGUID: "u1", prevRead: "vaults/prev/"}
	ctx := context.Background()
	call := func(k hostproto.Kind, f ...[]byte) string {
		r := p.handle(ctx, &hostproto.Frame{Kind: k, ID: 1, Fields: f})
		return string(r[0])
	}
	str := func(s ...string) [][]byte { return hostproto.Strings(s...) }
	for _, c := range []struct {
		name string
		k    hostproto.Kind
		f    [][]byte
		want string
	}{
		{"own state", vaultipc.KindStoreGet, str("vaults/aaaa/state"), "ok"},
		{"own header put", vaultipc.KindStorePut, str("vaults/aaaa/header/x", "d", ""), "ok"},
		{"own member index", vaultipc.KindStoreGet, str(enclave.UserIndexKey("u1")), "ok"},
		{"previous vault read", vaultipc.KindStoreGet, str("vaults/prev/state"), "ok"},
		{"previous vault write", vaultipc.KindStorePut, str("vaults/prev/state", "d", "v"), "denied"},
		{"another vault", vaultipc.KindStoreGet, str("vaults/bbbb/state"), "denied"},
		{"another vault write", vaultipc.KindStorePut, str("vaults/bbbb/state", "d", ""), "denied"},
		{"another member's index", vaultipc.KindStoreGet, str(enclave.UserIndexKey("u2")), "denied"},
		{"prefix trick", vaultipc.KindStoreGet, str("vaults/aaaa/../bbbb/state"), "denied"},
		{"vault id prefix", vaultipc.KindStoreGet, str("vaults/aaaab/state"), "denied"},
		{"not an RSA key", vaultipc.KindAttestRecipient, str("not a key"), "denied"},
		{"vault attestation outside enrollment", vaultipc.KindAttestVault, str("bundle", "nonce"), "denied"},
		{"KMS key outside the namespace", vaultipc.KindKMS, str("Decrypt", "arn:aws:kms:us-east-1:444455556666:key/x", "", ""), "denied"},
		{"KMS unknown op", vaultipc.KindKMS, str("Encrypt", "arn:aws:kms:us-east-1:111122223333:key/x", "", ""), "denied"},
		{"HTTP to KMS", vaultipc.KindHTTP, [][]byte{[]byte("POST"), []byte("https://kms.us-east-1.amazonaws.com/"), vaultipc.EncodeHeaders(nil), nil}, "denied"},
		{"plain HTTP", vaultipc.KindHTTP, [][]byte{[]byte("GET"), []byte("http://relay.example/x"), vaultipc.EncodeHeaders(nil), nil}, "denied"},
		{"other port", vaultipc.KindHTTP, [][]byte{[]byte("GET"), []byte("https://relay.example:8443/x"), vaultipc.EncodeHeaders(nil), nil}, "denied"},
		{"bad method", vaultipc.KindHTTP, [][]byte{[]byte("CONNECT"), []byte("https://relay.example/x"), vaultipc.EncodeHeaders(nil), nil}, "denied"},
		{"Open from the vault", vaultipc.KindOpen, nil, "denied"},
		{"Lock from the vault", vaultipc.KindLock, nil, "denied"},
		{"host protocol kind", hostproto.KindCredentials, nil, "denied"},
	} {
		if got := call(c.k, c.f...); got != c.want {
			t.Errorf("%s: %s", c.name, got)
		}
	}
	// A Recipient key is attested without user_data; vault attestations
	// only while enrolling.
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if got := call(vaultipc.KindAttestRecipient, der); got != "ok" {
		t.Fatalf("recipient attestation: %s", got)
	}
	p.enroll, p.opening = true, true
	if got := call(vaultipc.KindAttestVault, []byte("bundle"), []byte("nonce")); got != "ok" {
		t.Fatalf("vault attestation while enrolling: %s", got)
	}
	// Lifecycle events for another vault are dropped.
	p.notify(&hostproto.Frame{Kind: vaultipc.KindLifecycle, Fields: str("unlocked", "bbbb", "r", "r", "1")})
}

// A self-test attestation that does not verify is returned whole (public
// data) so it can be examined.
func TestSelftestKeepsUnverifiedDocument(t *testing.T) {
	s := &Supervisor{cfg: Config{NSM: &stubNSM{}, NitroRoots: x509.NewCertPool()}, now: time.Now}
	r := &selftest.Report{}
	s.selftestNSM(r)
	if string(r.AttestationDocument) != "doc" {
		t.Fatalf("document not kept: %q", r.AttestationDocument)
	}
}
