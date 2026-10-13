//go:build linux && amd64

package seccomp

import "golang.org/x/sys/unix"

// The x32 number of socket, and the x32-only ptrace, process_vm_readv
// and process_vm_writev called without the x32 bit (as the others: no
// process, nothing to read or write).
var archProbes = []probe{
	{name: "x32_socket", nr: x32Bit | unix.SYS_SOCKET, fd: true, a: [3]uintptr{unix.AF_UNIX, unix.SOCK_STREAM | unix.SOCK_CLOEXEC}},
	{name: "x32_only_ptrace", nr: 521, a: [3]uintptr{unix.PTRACE_ATTACH}},
	{name: "x32_only_process_vm_readv", nr: 539},
	{name: "x32_only_process_vm_writev", nr: 540},
}
