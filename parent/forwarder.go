package parent

import (
	"context"
	"io"
	"net"
	"strconv"
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

	mu    sync.Mutex
	open  int
	total int
}

func newForwarder(cfg *Config) *forwarder {
	f := &forwarder{l: cfg.EgressListener, allow: map[string]bool{}, resolve: cfg.Resolve,
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
	f.mu.Lock()
	f.open++
	f.total++
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		f.open--
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

func (f *forwarder) stats() (open, total int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.open, f.total
}
