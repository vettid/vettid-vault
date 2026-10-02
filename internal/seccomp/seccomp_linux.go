//go:build linux && (amd64 || arm64)

package seccomp

import (
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Denied syscalls (EPERM).
var denied = []uint32{
	unix.SYS_SOCKET, unix.SYS_SOCKETPAIR, unix.SYS_PTRACE,
	unix.SYS_PROCESS_VM_READV, unix.SYS_PROCESS_VM_WRITEV,
}

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

func stmt(code uint16, k uint32) unix.SockFilter { return unix.SockFilter{Code: code, K: k} }
func jump(code uint16, k uint32, jt, jf uint8) unix.SockFilter {
	return unix.SockFilter{Code: code, Jt: jt, Jf: jf, K: k}
}

// program builds the BPF filter: kill on a foreign architecture, EPERM
// for the denied syscalls, allow the rest.
func program() []unix.SockFilter {
	const (
		ldW  = unix.BPF_LD | unix.BPF_W | unix.BPF_ABS
		jeq  = unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K
		ret  = unix.BPF_RET | unix.BPF_K
		eprm = unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)
	)
	p := []unix.SockFilter{
		stmt(ldW, offArch),
		jump(jeq, arch(), 1, 0),
		stmt(ret, unix.SECCOMP_RET_KILL_PROCESS),
		stmt(ldW, offNR),
	}
	for _, nr := range denied {
		p = append(p, jump(jeq, nr, 0, 1), stmt(ret, eprm))
	}
	return append(p, stmt(ret, unix.SECCOMP_RET_ALLOW))
}

// Install sets no_new_privs and installs the filter on every thread of
// the process (TSYNC).
func Install() error {
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return err
	}
	f := program()
	prog := unix.SockFprog{Len: uint16(len(f)), Filter: &f[0]}
	_, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_TSYNC, uintptr(unsafe.Pointer(&prog)))
	runtime.KeepAlive(f)
	if errno != 0 {
		return errno
	}
	return nil
}
