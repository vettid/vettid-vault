// Package egress is the enclave's only way out (VAULT-MESSAGING §12.2,
// VAULT-PLAN §5.2 decision D5): HTTPS to an allowlist of hosts, with TLS
// terminated inside the enclave against pinned roots, over connections
// that every vault shares. For an HTTP/2 host the enclave decides how many
// there are (h2pool.go): one until its streams are in use, then more, up
// to MaxConns.
//
// The parent forwards TCP bytes only, to the same allowlist on port 443
// (its own check). Here, a request is refused unless its URL is https, its
// host is listed and its port is 443; the TLS handshake is TLS 1.3 only,
// verifies the certificate chain against that host's pinned roots (and no
// others) and the host name, and, for HTTP/2 hosts, requires ALPN "h2" so
// that the host cannot split vault traffic onto per-vault connections.
// Redirects are not followed.
package egress

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// Dialer opens a byte stream to host:port through the parent's forwarder
// (vsock in release builds, TCP in development).
type Dialer interface {
	Dial(ctx context.Context, host string, port uint16) (net.Conn, error)
}

// DialerFunc adapts a function to Dialer.
type DialerFunc func(ctx context.Context, host string, port uint16) (net.Conn, error)

// Dial implements Dialer.
func (f DialerFunc) Dial(ctx context.Context, host string, port uint16) (net.Conn, error) {
	return f(ctx, host, port)
}

// Host is one allowlisted destination.
type Host struct {
	// Name is the exact DNS name (lowercase).
	Name string
	// Roots are the only trust anchors for this host.
	Roots *x509.CertPool
	// HTTP2 requires ALPN h2 and multiplexes requests on shared
	// connections; otherwise HTTP/1.1 with keep-alive (AWS KMS endpoints
	// do not offer h2, docs/V3-NOTES.md).
	HTTP2 bool
}

// Config configures a Transport.
type Config struct {
	Dialer Dialer
	Hosts  []Host
	// Conns is the number of connection pools per HTTP/1.1 host (default
	// 2), of at most 4 connections each; requests are spread over the
	// pools in turn. HTTP/2 hosts do not use it.
	Conns int
	// MaxConns is the most connections to one HTTP/2 host (default
	// DefaultMaxConns). When all are open and their streams in use,
	// requests wait. A connection the host is closing does not count
	// while its last requests end (at most MaxConns of those).
	MaxConns int
	// MinStreams is the fewest concurrent streams a host must announce
	// for a second connection to be opened (default DefaultMinStreams).
	// Below it requests wait for a stream instead: a host that announced
	// a limit of 1 would otherwise get a connection per request, and
	// could tell the vaults apart.
	MinStreams int
	// Now is the time certificates are verified at (default time.Now).
	Now func() time.Time
}

// Port is the only destination port.
const Port = 443

// The enclave's bounds on the connections to an HTTP/2 host
// (VAULT-RELAY-SCALING D3). 16 connections of 128 streams (the relay's
// load balancer) carry 2,048 requests, above the 1,024 vault processes a
// host runs at most.
const (
	DefaultMaxConns   = 16
	DefaultMinStreams = 32
)

// Errors.
var (
	ErrNotAllowed = errors.New("egress: destination not allowed")
	ErrALPN       = errors.New("egress: server did not negotiate h2")
	ErrConfig     = errors.New("egress: invalid configuration")
)

// Transport is an http.RoundTripper restricted to the allowlist.
type Transport struct {
	hosts map[string]*hostPool
}

// hostPool is one host's connections: h2 for an HTTP/2 host, otherwise
// the HTTP/1.1 pools.
type hostPool struct {
	h2    *h2Pool
	next  atomic.Uint64
	pools []*http.Transport
}

// New builds the transport.
func New(cfg Config) (*Transport, error) {
	if cfg.Dialer == nil || len(cfg.Hosts) == 0 {
		return nil, ErrConfig
	}
	if cfg.Conns <= 0 {
		cfg.Conns = 2
	}
	if cfg.MaxConns <= 0 {
		cfg.MaxConns = DefaultMaxConns
	}
	if cfg.MinStreams <= 0 {
		cfg.MinStreams = DefaultMinStreams
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	t := &Transport{hosts: map[string]*hostPool{}}
	for _, h := range cfg.Hosts {
		if h.Name == "" || h.Name != strings.ToLower(h.Name) || h.Roots == nil || t.hosts[h.Name] != nil {
			return nil, ErrConfig
		}
		hp := &hostPool{}
		if h.HTTP2 {
			hp.h2 = newH2Pool(newPool(cfg, h), h.Name, cfg.MaxConns, cfg.MinStreams)
		}
		for i := 0; i < cfg.Conns && !h.HTTP2; i++ {
			hp.pools = append(hp.pools, newPool(cfg, h))
		}
		t.hosts[h.Name] = hp
	}
	return t, nil
}

func newPool(cfg Config, h Host) *http.Transport {
	host := h
	proto := "http/1.1"
	if host.HTTP2 {
		proto = "h2"
	}
	tc := &tls.Config{
		RootCAs: host.Roots, ServerName: host.Name, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		NextProtos: []string{proto}, Time: cfg.Now,
	}
	dialTLS := func(ctx context.Context, network, addr string) (net.Conn, error) {
		hn, port, err := net.SplitHostPort(addr)
		if err != nil || hn != host.Name || port != "443" {
			return nil, ErrNotAllowed
		}
		raw, err := cfg.Dialer.Dial(ctx, host.Name, Port)
		if err != nil {
			return nil, err
		}
		c := tls.Client(raw, tc)
		if err := c.HandshakeContext(ctx); err != nil {
			raw.Close()
			return nil, err
		}
		if c.ConnectionState().NegotiatedProtocol != proto && (host.HTTP2 || c.ConnectionState().NegotiatedProtocol != "") {
			c.Close()
			return nil, ErrALPN
		}
		return c, nil
	}
	tr := &http.Transport{
		Proxy:                 nil,
		DialTLSContext:        dialTLS,
		DialContext:           func(context.Context, string, string) (net.Conn, error) { return nil, ErrNotAllowed },
		ForceAttemptHTTP2:     host.HTTP2,
		MaxIdleConns:          4,
		MaxIdleConnsPerHost:   2,
		IdleConnTimeout:       5 * time.Minute,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 0, // long-polls hold the response for up to 25 s
		ExpectContinueTimeout: time.Second,
	}
	if !host.HTTP2 {
		tr.MaxConnsPerHost = 4
		tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{} // never h2
	}
	return tr
}

// check validates a request's destination.
func (t *Transport) check(r *http.Request) (*hostPool, error) {
	u := r.URL
	if u == nil || u.Scheme != "https" || u.User != nil || u.Opaque != "" {
		return nil, ErrNotAllowed
	}
	if p := u.Port(); p != "" && p != "443" {
		return nil, ErrNotAllowed
	}
	hp := t.hosts[u.Hostname()]
	if hp == nil {
		return nil, ErrNotAllowed
	}
	return hp, nil
}

// RoundTrip implements http.RoundTripper.
func (t *Transport) RoundTrip(r *http.Request) (*http.Response, error) {
	hp, err := t.check(r)
	if err != nil {
		if r.Body != nil {
			r.Body.Close()
		}
		return nil, err
	}
	if hp.h2 != nil {
		return hp.h2.RoundTrip(r)
	}
	i := hp.next.Add(1) % uint64(len(hp.pools))
	return hp.pools[i].RoundTrip(r)
}

// Client returns an http.Client over the transport that never follows
// redirects.
func (t *Transport) Client(timeout time.Duration) *http.Client {
	return &http.Client{Transport: t, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

// CloseIdle closes idle connections.
func (t *Transport) CloseIdle() {
	for _, hp := range t.hosts {
		if hp.h2 != nil {
			hp.h2.closeIdle()
		}
		for _, p := range hp.pools {
			p.CloseIdleConnections()
		}
	}
}

// Allowed reports whether host is on the allowlist.
func (t *Transport) Allowed(host string) bool { return t.hosts[host] != nil }

// Stats returns the state of the shared HTTP/2 connections to host (the
// zero value for an HTTP/1.1 host or one not on the allowlist).
func (t *Transport) Stats(host string) Stats {
	if hp := t.hosts[host]; hp != nil && hp.h2 != nil {
		return hp.h2.stats()
	}
	return Stats{}
}
