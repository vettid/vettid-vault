//go:build !linux

package vsock

import (
	"context"
	"net"
)

// Dial is not supported off Linux.
func Dial(context.Context, uint32, uint32) (net.Conn, error) { return nil, ErrUnsupported }

// Listener is not supported off Linux.
type Listener struct{}

// Listen is not supported off Linux.
func Listen(uint32) (*Listener, error) { return nil, ErrUnsupported }

// Accept is not supported off Linux.
func (*Listener) Accept() (net.Conn, error) { return nil, ErrUnsupported }

// Close is not supported off Linux.
func (*Listener) Close() error { return ErrUnsupported }

// Addr is not supported off Linux.
func (*Listener) Addr() net.Addr { return Addr{} }
