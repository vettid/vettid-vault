package parent_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/hostproto"
	"github.com/vettid/vettid-vault/internal/parenttest"
	"github.com/vettid/vettid-vault/internal/selftest"
	"github.com/vettid/vettid-vault/internal/vsock"
	"github.com/vettid/vettid-vault/parent"
)

// peerListener is a listener whose connections come from the addresses
// the test names (vsock is not available to a test; the parent sees the
// peer only through RemoteAddr).
type peerListener struct {
	conns chan net.Conn
	done  chan struct{}
	once  sync.Once
}

func newPeerListener() *peerListener {
	return &peerListener{conns: make(chan net.Conn), done: make(chan struct{})}
}

func (l *peerListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}
func (l *peerListener) Close() error   { l.once.Do(func() { close(l.done) }); return nil }
func (l *peerListener) Addr() net.Addr { return vsock.Addr{CID: vsock.CIDAny, Port: 5000} }

type peerConn struct {
	net.Conn
	remote net.Addr
}

func (c peerConn) RemoteAddr() net.Addr { return c.remote }

// dial connects as a peer with the given address and returns its end.
func (l *peerListener) dial(t *testing.T, from net.Addr) net.Conn {
	t.Helper()
	mine, theirs := net.Pipe()
	select {
	case l.conns <- peerConn{theirs, from}:
	case <-time.After(5 * time.Second):
		t.Fatal("the parent does not accept")
	}
	t.Cleanup(func() { mine.Close() })
	return mine
}

type otherAddr struct{}

func (otherAddr) Network() string { return "other" }
func (otherAddr) String() string  { return "other" }

var notEnclave = map[string]net.Addr{
	"the host's own context id": vsock.Addr{CID: vsock.CIDHost, Port: 40000},
	"the local context id":      vsock.Addr{CID: 1, Port: 40000},
	"another enclave":           vsock.Addr{CID: 17, Port: 40000},
	"no context id":             vsock.Addr{},
	"TCP from another host":     &net.TCPAddr{IP: net.IPv4(192, 0, 2, 7), Port: 40000},
	"another kind of address":   otherAddr{},
}

// call sends one request as the enclave would and returns the reply.
func call(c net.Conn, k hostproto.Kind, fields ...string) ([][]byte, error) {
	hc := hostproto.NewConn(c, func(context.Context, *hostproto.Frame) [][]byte { return nil }, nil)
	defer hc.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return hc.Call(ctx, k, hostproto.Strings(fields...)...)
}

// The control channel answers only the enclave: a connection from any
// other peer is closed with no answer, and so gets no session, no stored
// object and none of the instance role's credentials.
func TestControlRefusesOtherPeers(t *testing.T) {
	cl := newPeerListener()
	h := newHarness(t, func(c *parent.Config) { c.ControlListener.Close(); c.ControlListener = cl })
	h.objs.Put(context.Background(), "vaults/v1/state", []byte("sealed"), "")
	for name, from := range notEnclave {
		for _, req := range []struct {
			kind   hostproto.Kind
			fields []string
		}{{hostproto.KindHello, []string{pcr, "boot-x"}}, {hostproto.KindCredentials, nil}, {hostproto.KindStoreGet, []string{"vaults/v1/state"}}} {
			if r, err := call(cl.dial(t, from), req.kind, req.fields...); err == nil {
				t.Errorf("%s: request %#x answered: %q", name, req.kind, r)
			}
		}
	}
	if h.p.Health().Enclave {
		t.Fatal("a peer that is not the enclave became the session")
	}
	// The enclave (context id 16, the default) is served.
	enclave := vsock.Addr{CID: parent.DefaultEnclaveCID, Port: 40000}
	if r, err := call(cl.dial(t, enclave), hostproto.KindCredentials); err != nil || len(r) != 5 || string(r[1]) != "AK" {
		t.Fatalf("the enclave's credentials request: %v %q", err, r)
	}
	if r, err := call(cl.dial(t, enclave), hostproto.KindHello, pcr, "boot-1"); err != nil || string(r[0]) != hostproto.StatusOK {
		t.Fatalf("the enclave's hello: %v %q", err, r)
	}
	// Refusals are logged with the channel and the peer, not once each.
	h.logMu.Lock()
	logs := h.logs.String()
	h.logMu.Unlock()
	if n := strings.Count(logs, `"msg":"connection refused: the peer is not the enclave","channel":"control"`); n != 1 {
		t.Fatalf("refusals logged %d times:\n%s", n, logs)
	}
}

// A configured context id replaces the default.
func TestControlEnclaveCID(t *testing.T) {
	cl := newPeerListener()
	newHarness(t, func(c *parent.Config) {
		c.ControlListener.Close()
		c.ControlListener = parent.EnclaveOnly(cl, 21, "control", c.Logger)
	})
	if r, err := call(cl.dial(t, vsock.Addr{CID: parent.DefaultEnclaveCID, Port: 1}), hostproto.KindCredentials); err == nil {
		t.Fatalf("context id 16 answered when the enclave's is 21: %q", r)
	}
	if r, err := call(cl.dial(t, vsock.Addr{CID: 21, Port: 1}), hostproto.KindCredentials); err != nil || string(r[0]) != hostproto.StatusOK {
		t.Fatalf("the enclave: %v %q", err, r)
	}
}

// The egress channel connects only the enclave to the allowlist.
func TestEgressRefusesOtherPeers(t *testing.T) {
	el := newPeerListener()
	newHarness(t, func(c *parent.Config) { c.EgressListener.Close(); c.EgressListener = el })
	for name, from := range notEnclave {
		c := el.dial(t, from)
		err := hostproto.OpenEgress(c, "relay.example.org", 443)
		if err == nil || errors.Is(err, hostproto.ErrEgressRefused) || errors.Is(err, hostproto.ErrEgressFailed) {
			t.Errorf("%s: egress answered: %v", name, err)
		}
	}
	c := el.dial(t, vsock.Addr{CID: parent.DefaultEnclaveCID, Port: 40000})
	if err := hostproto.OpenEgress(c, "relay.example.org", 443); err != nil {
		t.Fatalf("the enclave's egress: %v", err)
	}
	go func() { _, _ = c.Write([]byte("ping")) }()
	got := make([]byte, 4)
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(c, got); err != nil || string(got) != "ping" {
		t.Fatalf("splice: %v %q", err, got)
	}
}

// The hardware self-test's parent hands out credentials too: it answers
// only the enclave as well.
func TestSelftestRefusesOtherPeers(t *testing.T) {
	cl, el := newPeerListener(), newPeerListener()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = parent.RunSelftest(ctx, parent.SelftestConfig{ControlListener: cl, EgressListener: el,
			Objects: parenttest.NewObjects(), Creds: parenttest.StaticCreds{AccessKeyID: "AK", SecretAccessKey: "SK"},
			Request: selftest.Request{RunID: "run-1", KeyARN: "arn:aws:kms:us-east-1:000000000000:key/k", Account: "000000000000", Region: "us-east-1"},
			Logger:  slog.New(slog.NewTextHandler(io.Discard, nil))})
	}()
	defer func() { cancel(); <-done }()
	for name, from := range notEnclave {
		if r, err := call(cl.dial(t, from), hostproto.KindCredentials); err == nil {
			t.Errorf("%s: credentials answered: %q", name, r)
		}
		c := el.dial(t, from)
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		h, _ := hostproto.EgressHeader("relay.example.org", 443)
		_, _ = c.Write(h)
		if n, err := c.Read(make([]byte, 1)); err == nil {
			t.Errorf("%s: egress answered %d byte(s)", name, n)
		}
	}
	if r, err := call(cl.dial(t, vsock.Addr{CID: parent.DefaultEnclaveCID, Port: 40000}), hostproto.KindCredentials); err != nil || string(r[1]) != "AK" {
		t.Fatalf("the enclave's credentials request: %v %q", err, r)
	}
}

// The context id is written in four places that must agree: the default
// here, the enclave's unit, the parent's unit and the smoke script.
func TestEnclaveCIDEverywhere(t *testing.T) {
	for file, re := range map[string]string{
		"../deploy/host/vault-enclave.service": `(?m)^ExecStart=/usr/bin/nitro-cli run-enclave .*--enclave-cid (\d+)$`,
		"../deploy/host/vault-parent.service":  `(?m)^    -enclave-cid (\d+) \\$`,
		"../scripts/smoke/run-on-host.sh":      `(?m)^CID=(\d+)$`,
	} {
		b, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		m := regexp.MustCompile(re).FindAllStringSubmatch(string(b), -1)
		if len(m) != 1 {
			t.Errorf("%s: %d context ids found, want one", file, len(m))
			continue
		}
		if m[0][1] != strconv.Itoa(parent.DefaultEnclaveCID) {
			t.Errorf("%s runs with context id %s; parent.DefaultEnclaveCID is %d", file, m[0][1], parent.DefaultEnclaveCID)
		}
	}
	// The smoke script's parent is told the id its enclave is started with.
	b, _ := os.ReadFile("../scripts/smoke/run-on-host.sh")
	if !strings.Contains(string(b), `-enclave-cid "$CID"`) || !strings.Contains(string(b), `--enclave-cid "$CID"`) {
		t.Error("scripts/smoke/run-on-host.sh does not pass $CID to both the parent and the enclave")
	}
}

// The rule itself, for each kind of address.
func TestPeerIsEnclave(t *testing.T) {
	for _, c := range []struct {
		a    net.Addr
		want bool
	}{
		{vsock.Addr{CID: 16, Port: 1}, true},
		{&vsock.Addr{CID: 16, Port: 1}, false}, // internal/vsock yields values
		{vsock.Addr{CID: vsock.CIDHost}, false},
		{vsock.Addr{CID: vsock.CIDAny}, false},
		{&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}, true},
		{&net.TCPAddr{IP: net.IPv6loopback, Port: 1}, true},
		{&net.TCPAddr{IP: net.IPv4(10, 0, 0, 16), Port: 1}, false},
		{&net.TCPAddr{Port: 1}, false},
		{(*net.TCPAddr)(nil), false},
		{&net.UnixAddr{Name: "/run/x", Net: "unix"}, false},
		{nil, false},
	} {
		if got := parent.PeerIsEnclaveForTest(c.a, 16); got != c.want {
			t.Errorf("%v: %v", c.a, got)
		}
	}
}
