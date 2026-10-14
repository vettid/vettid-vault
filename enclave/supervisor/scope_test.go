package supervisor

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/enclave"
	"github.com/vettid/vettid-vault/internal/hostproto"
	"github.com/vettid/vettid-vault/internal/selftest"
	"github.com/vettid/vettid-vault/internal/vaultipc"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vault/store"
	"github.com/vettid/vettid-vault/vms/nitro"
)

type stubNSM struct{ calls int }

func (n *stubNSM) Attest(ud, nonce, pk []byte) ([]byte, error) { n.calls++; return []byte("doc"), nil }
func (n *stubNSM) Measurements() (nitro.Measurements, error)   { return nitro.Measurements{}, nil }

// memParent answers the supervisor's store requests from a memory store,
// as the parent would from the bucket.
func memParent(t *testing.T, m *store.Memory) *link {
	ctx := context.Background()
	return fakeParent(t, func(f *hostproto.Frame) [][]byte {
		switch f.Kind {
		case hostproto.KindStoreGet:
			b, v, err := m.Get(ctx, string(f.Fields[0]))
			return storeReply(err, func() [][]byte { return [][]byte{[]byte(hostproto.StatusOK), b, []byte(v)} })
		case hostproto.KindStorePut:
			v, err := m.Put(ctx, string(f.Fields[0]), f.Fields[1], store.Version(f.Fields[2]))
			return storeReply(err, func() [][]byte { return hostproto.Strings(hostproto.StatusOK, string(v)) })
		case hostproto.KindStoreDelete:
			err := m.Delete(ctx, string(f.Fields[0]), store.Version(f.Fields[1]))
			return storeReply(err, func() [][]byte { return hostproto.Strings(hostproto.StatusOK) })
		}
		return hostproto.Strings("ok")
	})
}

// channelStore is a vault process's view of the store: every call goes
// through the supervisor's channel handler, as vaultproc's does.
type channelStore struct{ p *vproc }

func (c channelStore) call(k hostproto.Kind, f ...[]byte) ([][]byte, error) {
	r := c.p.handle(context.Background(), &hostproto.Frame{Kind: k, ID: 1, Fields: f})
	switch string(r[0]) {
	case hostproto.StatusOK:
		return r, nil
	case hostproto.StatusNotFound:
		return nil, store.ErrNotFound
	case hostproto.StatusConflict:
		return nil, store.ErrConflict
	}
	return nil, errors.New(string(r[0]))
}

func (c channelStore) Get(_ context.Context, key string) ([]byte, store.Version, error) {
	r, err := c.call(vaultipc.KindStoreGet, []byte(key))
	if err != nil {
		return nil, "", err
	}
	return r[1], store.Version(r[2]), nil
}

func (c channelStore) Put(_ context.Context, key string, data []byte, ifMatch store.Version) (store.Version, error) {
	r, err := c.call(vaultipc.KindStorePut, []byte(key), data, []byte(ifMatch))
	if err != nil {
		return "", err
	}
	return store.Version(r[1]), nil
}

func (c channelStore) Delete(_ context.Context, key string, ifMatch store.Version) error {
	_, err := c.call(vaultipc.KindStoreDelete, []byte(key), []byte(ifMatch))
	return err
}

// A vault process reaches only its own vault through the channel
// (VAULT-MESSAGING §12.4).
func TestChannelScope(t *testing.T) {
	ctx := context.Background()
	m := store.NewMemory()
	nsm := &stubNSM{}
	s := &Supervisor{st: &hostStore{l: memParent(t, m)}, encCfg: enclave.Config{SealAccount: "111122223333", SealRegion: "us-east-1"},
		relays: map[string]bool{"relay.example": true}, cfg: Config{NSM: nsm}, activity: map[string]time.Time{}}
	h := &procHost{s: s}
	idx, idx2 := enclave.UserIndexKey("u1"), enclave.UserIndexKey("u2")
	put := func(k, v string) store.Version {
		t.Helper()
		_, old, _ := m.Get(ctx, k)
		ver, err := m.Put(ctx, k, []byte(v), old)
		if err != nil {
			t.Fatal(err)
		}
		return ver
	}
	for _, k := range []string{"vaults/aaaa/state", "vaults/aaaa/header/x", "vaults/prev/state", "vaults/prev/header/pcr",
		"vaults/prev/header/other", "vaults/prev/extra", "vaults/bbbb/state"} {
		put(k, "d")
	}
	put(idx2, "bbbb")
	str := func(s ...string) [][]byte { return hostproto.Strings(s...) }
	type phase int
	const (
		running         phase = iota // an unlocked vault (not opening)
		opening                      // a non-enrollment job while it opens
		enrolling                    // an enrollment while it opens
		enrolledRunning              // an enrollment after its open returned
	)
	newProc := func(ph phase) *vproc {
		p := &vproc{h: h, vaultID: "aaaa", userGUID: "u1"}
		p.enroll = ph == enrolling || ph == enrolledRunning
		p.opening = ph == opening || ph == enrolling
		if p.enroll {
			p.prevRead = previousVaultKeys("prev", "aaaa", "pcr")
		}
		if ph == enrolledRunning {
			p.prevRead = nil // as Open leaves it
		}
		return p
	}
	for _, c := range []struct {
		name  string
		ph    phase
		index string // the member's index content before the call ("": absent)
		k     hostproto.Kind
		f     func(ver string) [][]byte // ver: the index's current version
		want  string
	}{
		{name: "own state", k: vaultipc.KindStoreGet, f: func(string) [][]byte { return str("vaults/aaaa/state") }, want: "ok"},
		{name: "own header put", k: vaultipc.KindStorePut, f: func(string) [][]byte { return str("vaults/aaaa/header/y", "d", "") }, want: "ok"},
		{name: "own member index read", index: "aaaa", k: vaultipc.KindStoreGet, f: func(string) [][]byte { return str(idx) }, want: "ok"},
		{name: "another vault", k: vaultipc.KindStoreGet, f: func(string) [][]byte { return str("vaults/bbbb/state") }, want: "denied"},
		{name: "another vault write", k: vaultipc.KindStorePut, f: func(string) [][]byte { return str("vaults/bbbb/state", "d", "") }, want: "denied"},
		{name: "another vault delete", k: vaultipc.KindStoreDelete, f: func(string) [][]byte { return str("vaults/bbbb/state", "1") }, want: "denied"},
		{name: "another member's index", k: vaultipc.KindStoreGet, f: func(string) [][]byte { return str(idx2) }, want: "denied"},
		{name: "another member's index write while enrolling", ph: enrolling, k: vaultipc.KindStorePut, f: func(string) [][]byte { return str(idx2, "aaaa", "") }, want: "denied"},
		{name: "prefix trick", k: vaultipc.KindStoreGet, f: func(string) [][]byte { return str("vaults/aaaa/../bbbb/state") }, want: "denied"},
		{name: "vault id prefix", k: vaultipc.KindStoreGet, f: func(string) [][]byte { return str("vaults/aaaab/state") }, want: "denied"},

		// The member's index is written once, by an enrollment while it
		// opens, and only with the process's own vault id.
		{name: "index write with own id while enrolling", ph: enrolling, k: vaultipc.KindStorePut, f: func(string) [][]byte { return str(idx, "aaaa", "") }, want: "ok"},
		{name: "index rewrite with own id while enrolling", ph: enrolling, index: "prev", k: vaultipc.KindStorePut, f: func(v string) [][]byte { return str(idx, "aaaa", v) }, want: "ok"},
		{name: "index write with another id while enrolling", ph: enrolling, k: vaultipc.KindStorePut, f: func(string) [][]byte { return str(idx, "bbbb", "") }, want: "denied"},
		{name: "index rewrite with another id while enrolling", ph: enrolling, index: "aaaa", k: vaultipc.KindStorePut, f: func(v string) [][]byte { return str(idx, "bbbb", v) }, want: "denied"},
		{name: "index write with another id while running", ph: running, index: "aaaa", k: vaultipc.KindStorePut, f: func(v string) [][]byte { return str(idx, "bbbb", v) }, want: "denied"},
		{name: "index write with own id outside an enrollment", ph: opening, k: vaultipc.KindStorePut, f: func(string) [][]byte { return str(idx, "aaaa", "") }, want: "denied"},
		{name: "index write with own id while running", ph: running, index: "prev", k: vaultipc.KindStorePut, f: func(v string) [][]byte { return str(idx, "aaaa", v) }, want: "denied"},
		{name: "index write with own id after the enrollment's open", ph: enrolledRunning, k: vaultipc.KindStorePut, f: func(string) [][]byte { return str(idx, "aaaa", "") }, want: "denied"},
		{name: "index write with own id and padding", ph: enrolling, k: vaultipc.KindStorePut, f: func(string) [][]byte { return str(idx, "aaaa ", "") }, want: "denied"},

		// The member's index is deleted only while it names the process's
		// own vault, at the version the process read.
		{name: "index delete naming own vault", ph: running, index: "aaaa", k: vaultipc.KindStoreDelete, f: func(v string) [][]byte { return str(idx, v) }, want: "ok"},
		{name: "index delete naming another vault", ph: running, index: "bbbb", k: vaultipc.KindStoreDelete, f: func(v string) [][]byte { return str(idx, v) }, want: "denied"},
		{name: "index delete naming another vault while enrolling", ph: enrolling, index: "prev", k: vaultipc.KindStoreDelete, f: func(v string) [][]byte { return str(idx, v) }, want: "denied"},
		{name: "index delete at another version", ph: running, index: "aaaa", k: vaultipc.KindStoreDelete, f: func(string) [][]byte { return str(idx, "999") }, want: "conflict"},
		{name: "index delete without a version", ph: running, index: "aaaa", k: vaultipc.KindStoreDelete, f: func(string) [][]byte { return str(idx, "") }, want: "conflict"},
		{name: "index delete when absent", ph: running, k: vaultipc.KindStoreDelete, f: func(string) [][]byte { return str(idx, "1") }, want: "not_found"},

		// The member's previous vault: its state and its header sealed to
		// this release, read-only, while the enrollment opens.
		{name: "previous vault state while enrolling", ph: enrolling, k: vaultipc.KindStoreGet, f: func(string) [][]byte { return str("vaults/prev/state") }, want: "ok"},
		{name: "previous vault header while enrolling", ph: enrolling, k: vaultipc.KindStoreGet, f: func(string) [][]byte { return str("vaults/prev/header/pcr") }, want: "ok"},
		{name: "previous vault header of another release", ph: enrolling, k: vaultipc.KindStoreGet, f: func(string) [][]byte { return str("vaults/prev/header/other") }, want: "denied"},
		{name: "previous vault third object", ph: enrolling, k: vaultipc.KindStoreGet, f: func(string) [][]byte { return str("vaults/prev/extra") }, want: "denied"},
		{name: "previous vault write", ph: enrolling, k: vaultipc.KindStorePut, f: func(string) [][]byte { return str("vaults/prev/state", "d", "1") }, want: "denied"},
		{name: "previous vault delete", ph: enrolling, k: vaultipc.KindStoreDelete, f: func(string) [][]byte { return str("vaults/prev/state", "1") }, want: "denied"},
		{name: "previous vault after the open", ph: enrolledRunning, k: vaultipc.KindStoreGet, f: func(string) [][]byte { return str("vaults/prev/state") }, want: "denied"},
		{name: "previous vault outside an enrollment", ph: opening, k: vaultipc.KindStoreGet, f: func(string) [][]byte { return str("vaults/prev/state") }, want: "denied"},

		{name: "not an RSA key", k: vaultipc.KindAttestRecipient, f: func(string) [][]byte { return str("not a key") }, want: "denied"},
		{name: "vault attestation outside enrollment", k: vaultipc.KindAttestVault, f: func(string) [][]byte { return str("bundle", "nonce") }, want: "denied"},
		{name: "KMS key outside the namespace", k: vaultipc.KindKMS, f: func(string) [][]byte { return str("Decrypt", "arn:aws:kms:us-east-1:444455556666:key/x", "", "") }, want: "denied"},
		{name: "KMS unknown op", k: vaultipc.KindKMS, f: func(string) [][]byte { return str("Encrypt", "arn:aws:kms:us-east-1:111122223333:key/x", "", "") }, want: "denied"},
		{name: "HTTP to KMS", k: vaultipc.KindHTTP, f: func(string) [][]byte {
			return [][]byte{[]byte("POST"), []byte("https://kms.us-east-1.amazonaws.com/"), vaultipc.EncodeHeaders(nil), nil}
		}, want: "denied"},
		{name: "plain HTTP", k: vaultipc.KindHTTP, f: func(string) [][]byte {
			return [][]byte{[]byte("GET"), []byte("http://relay.example/x"), vaultipc.EncodeHeaders(nil), nil}
		}, want: "denied"},
		{name: "other port", k: vaultipc.KindHTTP, f: func(string) [][]byte {
			return [][]byte{[]byte("GET"), []byte("https://relay.example:8443/x"), vaultipc.EncodeHeaders(nil), nil}
		}, want: "denied"},
		{name: "bad method", k: vaultipc.KindHTTP, f: func(string) [][]byte {
			return [][]byte{[]byte("CONNECT"), []byte("https://relay.example/x"), vaultipc.EncodeHeaders(nil), nil}
		}, want: "denied"},
		{name: "Open from the vault", k: vaultipc.KindOpen, f: func(string) [][]byte { return nil }, want: "denied"},
		{name: "Lock from the vault", k: vaultipc.KindLock, f: func(string) [][]byte { return nil }, want: "denied"},
		{name: "host protocol kind", k: hostproto.KindCredentials, f: func(string) [][]byte { return nil }, want: "denied"},
	} {
		var ver string
		if c.index != "" {
			ver = string(put(idx, c.index))
		} else {
			_ = m.Delete(ctx, idx, func() store.Version { _, v, _ := m.Get(ctx, idx); return v }())
		}
		p := newProc(c.ph)
		r := p.handle(ctx, &hostproto.Frame{Kind: c.k, ID: 1, Fields: c.f(ver)})
		if got := string(r[0]); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
		// A refused index call leaves the index as it was.
		if c.want != "ok" && c.index != "" {
			if b, _, err := m.Get(ctx, idx); err != nil || string(b) != c.index {
				t.Errorf("%s: index now %q %v", c.name, b, err)
			}
		}
	}
	// A Recipient key is attested without user_data; vault attestations
	// only while enrolling.
	p := newProc(running)
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if r := p.handle(ctx, &hostproto.Frame{Kind: vaultipc.KindAttestRecipient, ID: 1, Fields: [][]byte{der}}); string(r[0]) != "ok" {
		t.Fatalf("recipient attestation: %s", r[0])
	}
	p = newProc(enrolling)
	if r := p.handle(ctx, &hostproto.Frame{Kind: vaultipc.KindAttestVault, ID: 1, Fields: str("bundle", "nonce")}); string(r[0]) != "ok" {
		t.Fatalf("vault attestation while enrolling: %s", r[0])
	}
	// Lifecycle events for another vault are dropped.
	p.notify(&hostproto.Frame{Kind: vaultipc.KindLifecycle, Fields: str("unlocked", "bbbb", "r", "r", "1")})
}

// The previous vault an enrollment may read is the one the member's index
// names, and only when that is another valid vault id.
func TestPreviousVaultKeys(t *testing.T) {
	if got := previousVaultKeys("prev", "aaaa", "pcr"); len(got) != 2 || got[0] != "vaults/prev/state" || got[1] != "vaults/prev/header/pcr" {
		t.Fatalf("keys %v", got)
	}
	for _, prev := range []string{"", "aaaa", "a/b", "..", "UPPER", "x y"} {
		if got := previousVaultKeys(prev, "aaaa", "pcr"); got != nil {
			t.Errorf("%q: %v", prev, got)
		}
	}
}

// The calls an honest vault process makes on the member's index go
// through: the enrollment's write (create, and replace on a conflict) and
// a deletion's erase, which deletes the index only while it names the
// vault (vault.EraseStored).
func TestChannelIndexHonestCalls(t *testing.T) {
	ctx := context.Background()
	m := store.NewMemory()
	s := &Supervisor{st: &hostStore{l: memParent(t, m)}, cfg: Config{NSM: &stubNSM{}}, activity: map[string]time.Time{}}
	h := &procHost{s: s}
	idx := enclave.UserIndexKey("u1")
	if _, err := m.Put(ctx, idx, []byte("prev"), ""); err != nil {
		t.Fatal(err)
	}
	// Enrollment of aaaa over prev (as enclave.Core.indexUser writes it).
	p := &vproc{h: h, vaultID: "aaaa", userGUID: "u1", enroll: true, opening: true, prevRead: previousVaultKeys("prev", "aaaa", "pcr")}
	cs := channelStore{p}
	if _, err := cs.Put(ctx, idx, []byte("aaaa"), ""); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("create over an existing index: %v", err)
	}
	_, v, err := cs.Get(ctx, idx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cs.Put(ctx, idx, []byte("aaaa"), v); err != nil {
		t.Fatalf("index replace: %v", err)
	}
	p.mu.Lock()
	p.opening, p.prevRead = false, nil
	p.mu.Unlock()
	// The vault's deletion erases its objects and the index naming it.
	for _, k := range []string{store.StateKey("aaaa"), store.HeaderKey("aaaa", "pcr")} {
		if _, err := m.Put(ctx, k, []byte("d"), ""); err != nil {
			t.Fatal(err)
		}
	}
	if err := vault.EraseStored(ctx, cs, "aaaa", "u1", []string{"pcr"}, "pcr", "", ""); err != nil {
		t.Fatalf("erase: %v", err)
	}
	for _, k := range []string{idx, store.StateKey("aaaa"), store.HeaderKey("aaaa", "pcr")} {
		if _, _, err := m.Get(ctx, k); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("%s left: %v", k, err)
		}
	}
	// An index that names another vault is left alone by the erase.
	if _, err := m.Put(ctx, idx, []byte("bbbb"), ""); err != nil {
		t.Fatal(err)
	}
	if err := vault.EraseStored(ctx, cs, "aaaa", "u1", []string{"pcr"}, "pcr", "", ""); err != nil {
		t.Fatalf("erase again: %v", err)
	}
	if b, _, err := m.Get(ctx, idx); err != nil || string(b) != "bbbb" {
		t.Fatalf("index now %q %v", b, err)
	}
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
