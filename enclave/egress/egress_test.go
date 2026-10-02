package egress

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newCA(t *testing.T, name string) *testCA {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	p := x509.NewCertPool()
	p.AddCert(c)
	return &testCA{cert: c, key: k, pool: p}
}

func (ca *testCA) leaf(t *testing.T, names ...string) tls.Certificate {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &k.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

// server starts a TLS server for names; h2 enables HTTP/2.
func server(t *testing.T, ca *testCA, h2 bool, names ...string) *httptest.Server {
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.Proto)
	}))
	s.EnableHTTP2 = h2
	s.TLS = &tls.Config{Certificates: []tls.Certificate{ca.leaf(t, names...)}}
	s.StartTLS()
	t.Cleanup(s.Close)
	return s
}

// dialer maps every allowed host to addr and counts dials.
func dialer(addr string, n *atomic.Int32) Dialer {
	return DialerFunc(func(ctx context.Context, host string, port uint16) (net.Conn, error) {
		if port != 443 {
			return nil, ErrNotAllowed
		}
		n.Add(1)
		var d net.Dialer
		return d.DialContext(ctx, "tcp", addr)
	})
}

func get(c *http.Client, url string) (string, error) {
	r, err := c.Get(url)
	if err != nil {
		return "", err
	}
	defer r.Body.Close()
	b, err := io.ReadAll(r.Body)
	return string(b), err
}

func TestSharedHTTP2(t *testing.T) {
	ca := newCA(t, "test root")
	s := server(t, ca, true, "relay.example")
	var dials atomic.Int32
	tr, err := New(Config{Dialer: dialer(s.Listener.Addr().String(), &dials), Hosts: []Host{{Name: "relay.example", Roots: ca.pool, HTTP2: true}}})
	if err != nil {
		t.Fatal(err)
	}
	c := tr.Client(10 * time.Second)
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p, err := get(c, "https://relay.example/x")
			if err != nil || p != "HTTP/2.0" {
				t.Errorf("get: %q %v", p, err)
			}
		}()
	}
	wg.Wait()
	// 40 concurrent requests share at most one connection per pool (2),
	// plus at most one racing dial per pool.
	if n := dials.Load(); n > 4 {
		t.Fatalf("%d connections for 40 requests", n)
	}
}

func TestRefusals(t *testing.T) {
	ca := newCA(t, "test root")
	other := newCA(t, "other root")
	s := server(t, ca, true, "relay.example")
	h1 := server(t, ca, false, "relay.example")
	var dials atomic.Int32
	mk := func(addr string, h Host) *http.Client {
		tr, err := New(Config{Dialer: dialer(addr, &dials), Hosts: []Host{h}})
		if err != nil {
			t.Fatal(err)
		}
		return tr.Client(5 * time.Second)
	}
	good := mk(s.Listener.Addr().String(), Host{Name: "relay.example", Roots: ca.pool, HTTP2: true})
	for _, u := range []string{"http://relay.example/x", "https://relay.example:8443/x", "https://other.example/x", "https://user@relay.example/x"} {
		if _, err := get(good, u); err == nil {
			t.Errorf("%s allowed", u)
		}
	}
	// Another root does not verify the server.
	if _, err := get(mk(s.Listener.Addr().String(), Host{Name: "relay.example", Roots: other.pool, HTTP2: true}), "https://relay.example/"); err == nil {
		t.Error("unpinned root accepted")
	}
	// A certificate for another name does not verify.
	wrong := server(t, ca, true, "evil.example")
	if _, err := get(mk(wrong.Listener.Addr().String(), Host{Name: "relay.example", Roots: ca.pool, HTTP2: true}), "https://relay.example/"); err == nil {
		t.Error("wrong host name accepted")
	}
	// An HTTP/2 host must negotiate h2.
	if _, err := get(mk(h1.Listener.Addr().String(), Host{Name: "relay.example", Roots: ca.pool, HTTP2: true}), "https://relay.example/"); err == nil {
		t.Error("HTTP/1.1 accepted for an h2 host")
	}
	// An HTTP/1.1 host (KMS) works over HTTP/1.1, also against an h2-capable server.
	kms := mk(s.Listener.Addr().String(), Host{Name: "relay.example", Roots: ca.pool})
	if p, err := get(kms, "https://relay.example/"); err != nil || p != "HTTP/1.1" {
		t.Errorf("http/1.1 host: %q %v", p, err)
	}
	// TLS 1.2 servers are refused.
	old := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	old.TLS = &tls.Config{Certificates: []tls.Certificate{ca.leaf(t, "relay.example")}, MaxVersion: tls.VersionTLS12}
	old.StartTLS()
	defer old.Close()
	if _, err := get(mk(old.Listener.Addr().String(), Host{Name: "relay.example", Roots: ca.pool}), "https://relay.example/"); err == nil {
		t.Error("TLS 1.2 accepted")
	}
	// Redirects are not followed.
	redir := httptest.NewUnstartedServer(http.RedirectHandler("https://relay.example/elsewhere", http.StatusFound))
	redir.EnableHTTP2 = true
	redir.TLS = &tls.Config{Certificates: []tls.Certificate{ca.leaf(t, "relay.example")}}
	redir.StartTLS()
	defer redir.Close()
	r, err := mk(redir.Listener.Addr().String(), Host{Name: "relay.example", Roots: ca.pool, HTTP2: true}).Get("https://relay.example/")
	if err != nil || r.StatusCode != http.StatusFound {
		t.Errorf("redirect: %v", err)
	}
	if r != nil {
		r.Body.Close()
	}
}

func TestConfig(t *testing.T) {
	d := DialerFunc(func(context.Context, string, uint16) (net.Conn, error) { return nil, ErrNotAllowed })
	for _, c := range []Config{{}, {Dialer: d}, {Dialer: d, Hosts: []Host{{Name: "Upper.example", Roots: x509.NewCertPool()}}},
		{Dialer: d, Hosts: []Host{{Name: "a.example"}}}} {
		if _, err := New(c); err == nil {
			t.Errorf("accepted %+v", c)
		}
	}
}
