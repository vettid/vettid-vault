//go:build linux && (amd64 || arm64)

package seccomp

import (
	"errors"
	"fmt"
	"runtime"
	"slices"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Denied syscalls (EPERM). None of them is made by the Go runtime, the
// standard library or the vault's code: a vault process works on its
// inherited channel, its memory and a few /proc files.
var denied = []uint32{
	// No sockets but the inherited channel.
	unix.SYS_SOCKET, unix.SYS_SOCKETPAIR,
	// io_uring makes sockets (and every other kind of I/O) without the
	// calls above.
	unix.SYS_IO_URING_SETUP, unix.SYS_IO_URING_ENTER, unix.SYS_IO_URING_REGISTER,
	// No other process's execution, memory or descriptors.
	unix.SYS_PTRACE, unix.SYS_PROCESS_VM_READV, unix.SYS_PROCESS_VM_WRITEV, unix.SYS_PIDFD_GETFD,
	// Kernel interfaces a vault never uses. Refusing bpf closes the
	// bpf call (maps and programs of the extended kind); classic filters
	// are still accepted where they always were, by seccomp itself and
	// by SO_ATTACH_FILTER on the inherited channel.
	unix.SYS_BPF, unix.SYS_USERFAULTFD, unix.SYS_PERF_EVENT_OPEN,
}

// x32Bit marks a syscall number of the x32 ABI on amd64. Such a call
// reports the same architecture as a native one but has its own number
// (socket is x32Bit|41), so the list above would not match it. Nothing
// here is built for x32: every number from x32Bit up is refused.
//
// The calls that exist only for x32 have the numbers x32First to x32Last
// (rt_sigaction to pwritev2 in the kernel's syscall_64.tbl; ptrace is
// 521, process_vm_readv 539, process_vm_writev 540). Before Linux 5.4 a
// kernel with x32 ran them for a 64-bit process that called them without
// the bit, so that range is refused too. No 64-bit call has a number in
// it.
const (
	x32Bit   = 0x40000000
	x32First = 512
	x32Last  = 547
)

func arch() uint32 {
	if runtime.GOARCH == "arm64" {
		return unix.AUDIT_ARCH_AARCH64
	}
	return unix.AUDIT_ARCH_X86_64
}

// offsets in struct seccomp_data
const (
	offNR   = 0
	offArch = 4
)

// eperm is what a denied call returns.
const eperm = unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)

func stmt(code uint16, k uint32) unix.SockFilter { return unix.SockFilter{Code: code, K: k} }
func jump(code uint16, k uint32, jt, jf uint8) unix.SockFilter {
	return unix.SockFilter{Code: code, Jt: jt, Jf: jf, K: k}
}

// program builds the BPF filter: kill on a foreign architecture, deny
// (EPERM in the installed filter) for the denied syscalls, allow the
// rest.
func program(deny uint32) []unix.SockFilter {
	const (
		ldW = unix.BPF_LD | unix.BPF_W | unix.BPF_ABS
		jeq = unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K
		jge = unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K
		jgt = unix.BPF_JMP | unix.BPF_JGT | unix.BPF_K
		ret = unix.BPF_RET | unix.BPF_K
	)
	p := []unix.SockFilter{
		stmt(ldW, offArch),
		jump(jeq, arch(), 1, 0),
		stmt(ret, unix.SECCOMP_RET_KILL_PROCESS),
		stmt(ldW, offNR),
	}
	if runtime.GOARCH == "amd64" {
		p = append(p, jump(jge, x32Bit, 0, 1), stmt(ret, deny))
		// x32First <= number <= x32Last.
		p = append(p, jump(jge, x32First, 0, 2), jump(jgt, x32Last, 1, 0), stmt(ret, deny))
	}
	for _, nr := range denied {
		p = append(p, jump(jeq, nr, 0, 1), stmt(ret, deny))
	}
	return append(p, stmt(ret, unix.SECCOMP_RET_ALLOW))
}

// Install sets no_new_privs and installs the filter on every thread of
// the process (TSYNC). Threads and processes created later inherit both,
// and neither can be removed, also not by an exec.
func Install() error { return install(program(eperm)) }

func install(f []unix.SockFilter) error {
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return err
	}
	prog := unix.SockFprog{Len: uint16(len(f)), Filter: &f[0]}
	r, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_TSYNC, uintptr(unsafe.Pointer(&prog)))
	runtime.KeepAlive(f)
	if errno != 0 {
		return errno
	}
	// With TSYNC the call answers the id of a thread it could not bring
	// under the filter (one that has a filter of another origin), without
	// an error, and has then installed nothing.
	if r != 0 {
		return fmt.Errorf("seccomp: no filter installed: thread %d cannot take it", r)
	}
	return nil
}

// Refused reports whether err is what the filter answers.
func Refused(err error) bool { return errors.Is(err, unix.EPERM) }

// A probe makes one denied call with arguments that do nothing where the
// call is not refused: the kernel then answers with another error (no
// such process, bad descriptor, bad argument, no such call) or creates a
// descriptor, which the probe closes.
type probe struct {
	name string
	nr   uint32
	fd   bool // the call returns a descriptor
	a    [3]uintptr
}

const none = ^uintptr(0) // a descriptor that is not open

var probes = []probe{
	{name: "socket_vsock", nr: unix.SYS_SOCKET, fd: true, a: [3]uintptr{unix.AF_VSOCK, unix.SOCK_STREAM | unix.SOCK_CLOEXEC}},
	{name: "socket_inet", nr: unix.SYS_SOCKET, fd: true, a: [3]uintptr{unix.AF_INET, unix.SOCK_STREAM | unix.SOCK_CLOEXEC}},
	{name: "socketpair", nr: unix.SYS_SOCKETPAIR}, // see Probe
	{name: "io_uring_setup", nr: unix.SYS_IO_URING_SETUP, fd: true},
	{name: "io_uring_enter", nr: unix.SYS_IO_URING_ENTER, a: [3]uintptr{none}},
	{name: "io_uring_register", nr: unix.SYS_IO_URING_REGISTER, a: [3]uintptr{none}},
	// Attaching to process 0, which does not exist, and reading or
	// writing nothing of it.
	{name: "ptrace", nr: unix.SYS_PTRACE, a: [3]uintptr{unix.PTRACE_ATTACH}},
	{name: "process_vm_readv", nr: unix.SYS_PROCESS_VM_READV},
	{name: "process_vm_writev", nr: unix.SYS_PROCESS_VM_WRITEV},
	{name: "pidfd_getfd", nr: unix.SYS_PIDFD_GETFD, fd: true, a: [3]uintptr{none}},
	// A lookup (command 1) in no map.
	{name: "bpf", nr: unix.SYS_BPF, a: [3]uintptr{unix.BPF_MAP_LOOKUP_ELEM}},
	// Flags that do not exist.
	{name: "userfaultfd", nr: unix.SYS_USERFAULTFD, fd: true, a: [3]uintptr{none}},
	// No attributes.
	{name: "perf_event_open", nr: unix.SYS_PERF_EVENT_OPEN, fd: true},
}

// Names are the names of Probe's results, sorted.
func Names() []string {
	var n []string
	for _, p := range slices.Concat(probes, archProbes) {
		n = append(n, p.name)
	}
	slices.Sort(n)
	return n
}

// Probe makes every call the filter denies, harmlessly, and returns each
// one's error by name: Refused(err) under the filter, ErrNotRefused for a
// call that went through, the kernel's own error otherwise. It is what
// the hardware self-test and the tests ask (docs/SMOKE.md).
func Probe() map[string]error {
	out := map[string]error{}
	for _, p := range slices.Concat(probes, archProbes) {
		if p.nr == unix.SYS_SOCKETPAIR {
			if fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0); err != nil {
				out[p.name] = err
			} else {
				unix.Close(fds[0])
				unix.Close(fds[1])
				out[p.name] = ErrNotRefused
			}
			continue
		}
		r, _, errno := unix.Syscall6(uintptr(p.nr), p.a[0], p.a[1], p.a[2], 0, 0, 0)
		switch {
		case errno != 0:
			out[p.name] = errno
		default:
			if p.fd {
				unix.Close(int(r))
			}
			out[p.name] = ErrNotRefused
		}
	}
	return out
}
