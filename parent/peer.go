package parent

import (
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/vettid/vettid-vault/internal/vsock"
)

// DefaultEnclaveCID is the vsock context id the host runs the enclave
// with (deploy/host/vault-enclave.service and vault-parent.service,
// scripts/smoke/run-on-host.sh; a test compares them).
const DefaultEnclaveCID = 16

// peerIsEnclave reports whether a connection accepted on the control or
// the egress listener comes from the enclave.
//
//   - vsock: the peer's context id is the enclave's (internal/vsock gives
//     every accepted connection a vsock.Addr value). A process on the
//     host that connects to the same port has the host's or the local
//     context id. This does not stop root, or anyone who can start an
//     enclave with that context id or load a vsock transport for guests.
//   - TCP (development and tests, -control-tcp/-egress-tcp): there is no
//     enclave and no context id; the peer must be on the loopback
//     interface.
//
// Any other kind of address is refused.
func peerIsEnclave(a net.Addr, cid uint32) bool {
	switch a := a.(type) {
	case vsock.Addr:
		return a.CID == cid
	case *net.TCPAddr:
		return a != nil && a.IP.IsLoopback()
	}
	return false
}

// refusedPeerLogEvery is the least time between two log lines about
// refused peers on one listener (a variable for tests).
var refusedPeerLogEvery = 10 * time.Second

// peerListener accepts only the enclave's connections: any other is
// closed before a byte of it is read or answered.
type peerListener struct {
	net.Listener
	cid     uint32
	channel string // "control" or "egress"
	log     *slog.Logger

	mu      sync.Mutex
	refused int
	logged  time.Time
}

// EnclaveOnly returns a listener that accepts only the connections of the
// enclave with context id cid on l (channel, "control" or "egress", names
// it in the log). New and RunSelftest do this themselves with
// DefaultEnclaveCID for a listener that was not made here; cmd/vault-parent
// makes its listeners here with -enclave-cid.
func EnclaveOnly(l net.Listener, cid uint32, channel string, log *slog.Logger) net.Listener {
	if l == nil {
		return nil
	}
	if _, ok := l.(*peerListener); ok {
		return l
	}
	return &peerListener{Listener: l, cid: cid, channel: channel, log: log}
}

// Accept returns the next connection whose peer is the enclave.
func (l *peerListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		peer := c.RemoteAddr()
		if peerIsEnclave(peer, l.cid) {
			return c, nil
		}
		_ = c.Close()
		l.refuse(peer)
	}
}

// refuse counts a refused connection and logs it, at most one line every
// refusedPeerLogEvery (a process that keeps connecting must not fill the
// log).
func (l *peerListener) refuse(peer net.Addr) {
	l.mu.Lock()
	l.refused++
	n := l.refused
	now := time.Now()
	say := l.logged.IsZero() || now.Sub(l.logged) >= refusedPeerLogEvery
	if say {
		l.logged = now
	}
	l.mu.Unlock()
	if !say || l.log == nil {
		return
	}
	p := "unknown"
	if peer != nil {
		p = truncate(peer.String(), 64)
	}
	l.log.Warn("connection refused: the peer is not the enclave", "channel", l.channel, "peer", p, "refused", n)
}
