//go:build linux && amd64

package seccomp

import "golang.org/x/sys/unix"

// The x32 number of socket.
var archProbes = []probe{
	{name: "x32_socket", nr: x32Bit | unix.SYS_SOCKET, fd: true, a: [3]uintptr{unix.AF_UNIX, unix.SOCK_STREAM | unix.SOCK_CLOEXEC}},
}
