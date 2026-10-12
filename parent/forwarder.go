package parent

import (
	"context"
	"io"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vettid/vettid-vault/internal/hostproto"
)

// forwarder accepts the enclave's outbound connections and splices them
// to allowlisted hosts on port 443. It never sees plaintext: TLS ends in
// the enclave.
type forwarder struct {
	l       net.Listener
	allow   map[string]bool
	resolve map[string]string
	log     func(msg string, kv ...any)
	dial    func(ctx context.Context, network, addr string) (net.Conn, error)

	relay string // the relay's host name (its class in the counts)

	mu    sync.Mutex
	open  map[string]int // by destination class
	total map[string]int
}

// Destination classes of egress connections (metrics; VAULT-RELAY-SCALING
// §6): the relay, the KMS endpoint, a push gateway, anything else (the
// attestation status list).
const (
	egressRelay = "relay"
	egressKMS   = "kms"
	egressPush  = "push"
	egressOther = "other"
)

var egressClasses = []string{egressRelay, egressKMS, egressPush, egressOther}

func (f *forwarder) class(host string) string {
	switch {
	case host == f.relay:
		return egressRelay
	case strings.HasPrefix(host, "kms.") && strings.HasSuffix(host, ".amazonaws.com"):
		return egressKMS
	case slices.Contains(PushHosts, host):
		return egressPush
	}
	return egressOther
}

func newForwarder(cfg *Config) *forwarder {
	f := &forwarder{l: cfg.EgressListener, allow: map[string]bool{}, resolve: cfg.Resolve, relay: cfg.RelayHost,
		open: map[string]int{}, total: map[string]int{},
		log: func(msg string, kv ...any) { cfg.Logger.Info(msg, kv...) }}
	for _, h := range cfg.Allow {
		f.allow[h] = true
	}
	d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	f.dial = d.DialContext
	return f
}

func (f *forwarder) serve(ctx context.Context) {
	for {
		c, err := f.l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			f.log("egress accept failed", "error", err.Error())
			time.Sleep(100 * time.Millisecond)
			continue
		}
		go f.handle(ctx, c)
	}
}

func (f *forwarder) handle(ctx context.Context, c net.Conn) {
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	host, port, err := hostproto.ReadEgressHeader(c)
	if err != nil {
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	if port != 443 || !f.allow[host] {
		f.log("egress refused", "host", host, "port", port)
		_, _ = c.Write([]byte{hostproto.EgressRefused})
		return
	}
	addr := net.JoinHostPort(host, strconv.Itoa(int(port)))
	if r, ok := f.resolve[host]; ok {
		addr = r
	}
	dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	up, err := f.dial(dctx, "tcp", addr)
	cancel()
	if err != nil {
		f.log("egress dial failed", "host", host)
		_, _ = c.Write([]byte{hostproto.EgressFailed})
		return
	}
	defer up.Close()
	if _, err := c.Write([]byte{hostproto.EgressOK}); err != nil {
		return
	}
	cl := f.class(host)
	f.mu.Lock()
	f.open[cl]++
	f.total[cl]++
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		f.open[cl]--
		f.mu.Unlock()
	}()
	splice(c, up)
}

type closeWriter interface{ CloseWrite() error }

// splice copies both ways until both directions end. Writes toward the
// enclave are chunked (hostproto.ChunkSize).
func splice(enclave, up net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(hostproto.ChunkedWriter{W: enclave}, up)
		if cw, ok := enclave.(closeWriter); ok {
			_ = cw.CloseWrite()
		} else {
			_ = enclave.Close()
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(up, enclave)
		if cw, ok := up.(closeWriter); ok {
			_ = cw.CloseWrite()
		} else {
			_ = up.Close()
		}
	}()
	wg.Wait()
}

// stats returns the connections open now and opened since the start.
func (f *forwarder) stats() (open, total int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, cl := range egressClasses {
		open, total = open+f.open[cl], total+f.total[cl]
	}
	return open, total
}

// classStats is stats for one destination class.
func (f *forwarder) classStats(cl string) (open, total int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.open[cl], f.total[cl]
}
