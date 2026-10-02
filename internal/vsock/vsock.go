// Package vsock is a minimal AF_VSOCK stream socket (Linux) for the
// enclave and its parent: Dial, Listen and a net.Conn over the socket that
// never writes more than hostproto.ChunkSize bytes at once (the Nitro vsock
// transport has lost data beyond 32 KiB in a single write).
//
// It uses golang.org/x/sys/unix and the runtime poller through os.File,
// instead of a third-party vsock package.
package vsock

import (
	"errors"
	"fmt"
)

// Well-known context ids.
const (
	// CIDHost is the parent instance as seen from an enclave.
	CIDHost = 3
	// CIDAny binds a listener to every local context id.
	CIDAny = 0xffffffff
)

// Addr is a vsock address.
type Addr struct {
	CID, Port uint32
}

// Network implements net.Addr.
func (Addr) Network() string { return "vsock" }

func (a Addr) String() string { return fmt.Sprintf("vsock:%d:%d", a.CID, a.Port) }

// ErrUnsupported is returned on platforms without AF_VSOCK.
var ErrUnsupported = errors.New("vsock: not supported on this platform")
