//go:build linux

package vsock

import (
	"context"
	"errors"
	"net"
	"os"
	"time"

	"golang.org/x/sys/unix"

	"github.com/vettid/vettid-vault/internal/hostproto"
)

// Dial connects to cid:port. The connect itself is bounded by the kernel's
// vsock connect timeout; ctx is checked before and after.
func Dial(ctx context.Context, cid, port uint32) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	for {
		err = unix.Connect(fd, &unix.SockaddrVM{CID: cid, Port: port})
		if !errors.Is(err, unix.EINTR) {
			break
		}
	}
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		unix.Close(fd)
		return nil, err
	}
	return newConn(fd, Addr{CID: cid, Port: port})
}

func newConn(fd int, remote Addr) (net.Conn, error) {
	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return nil, err
	}
	local := Addr{}
	if sa, err := unix.Getsockname(fd); err == nil {
		if vm, ok := sa.(*unix.SockaddrVM); ok {
			local = Addr{CID: vm.CID, Port: vm.Port}
		}
	}
	f := os.NewFile(uintptr(fd), "vsock")
	return &conn{f: f, local: local, remote: remote}, nil
}

// conn is a vsock stream. os.File gives it the runtime poller, deadlines
// and safe concurrent Read and Write.
type conn struct {
	f             *os.File
	local, remote Addr
}

func (c *conn) Read(b []byte) (int, error) { return c.f.Read(b) }

// Write writes b in pieces of at most hostproto.ChunkSize bytes.
func (c *conn) Write(b []byte) (int, error) { return hostproto.ChunkedWriter{W: c.f}.Write(b) }

func (c *conn) Close() error                       { return c.f.Close() }
func (c *conn) LocalAddr() net.Addr                { return c.local }
func (c *conn) RemoteAddr() net.Addr               { return c.remote }
func (c *conn) SetDeadline(t time.Time) error      { return c.f.SetDeadline(t) }
func (c *conn) SetReadDeadline(t time.Time) error  { return c.f.SetReadDeadline(t) }
func (c *conn) SetWriteDeadline(t time.Time) error { return c.f.SetWriteDeadline(t) }

// CloseWrite shuts down the sending side (half close).
func (c *conn) CloseWrite() error {
	rc, err := c.f.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	if err := rc.Control(func(fd uintptr) { serr = unix.Shutdown(int(fd), unix.SHUT_WR) }); err != nil {
		return err
	}
	return serr
}

// Listener accepts vsock connections.
type Listener struct {
	f    *os.File
	addr Addr
}

// Listen listens on port for any context id.
func Listen(port uint32) (*Listener, error) {
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	if err := unix.Bind(fd, &unix.SockaddrVM{CID: CIDAny, Port: port}); err != nil {
		unix.Close(fd)
		return nil, err
	}
	if err := unix.Listen(fd, 64); err != nil {
		unix.Close(fd)
		return nil, err
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return nil, err
	}
	return &Listener{f: os.NewFile(uintptr(fd), "vsock-listener"), addr: Addr{CID: CIDAny, Port: port}}, nil
}

// Accept waits for a connection (through the runtime poller).
func (l *Listener) Accept() (net.Conn, error) {
	rc, err := l.f.SyscallConn()
	if err != nil {
		return nil, err
	}
	var nfd int
	var sa unix.Sockaddr
	var aerr error
	err = rc.Read(func(fd uintptr) bool {
		nfd, sa, aerr = unix.Accept4(int(fd), unix.SOCK_CLOEXEC)
		return !errors.Is(aerr, unix.EAGAIN) && !errors.Is(aerr, unix.EINTR)
	})
	if err != nil {
		return nil, err
	}
	if aerr != nil {
		return nil, aerr
	}
	remote := Addr{}
	if vm, ok := sa.(*unix.SockaddrVM); ok {
		remote = Addr{CID: vm.CID, Port: vm.Port}
	}
	return newConn(nfd, remote)
}

// Close stops listening.
func (l *Listener) Close() error { return l.f.Close() }

// Addr implements net.Listener.
func (l *Listener) Addr() net.Addr { return l.addr }

var _ net.Listener = (*Listener)(nil)
