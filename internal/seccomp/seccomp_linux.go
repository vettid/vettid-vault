//go:build linux && (amd64 || arm64)

package seccomp

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"slices"
	"unsafe"

	"golang.org/x/sys/unix"
)

// allowed are the system calls a vault process may make without a
// condition on their arguments. The list is what vault processes were
// measured to make once their filter is in place (the end-to-end suite,
// the self-test and the capacity run with every vault process under
// strace, a static CGO_ENABLED=0 build as in a release), plus the few the
// Go runtime makes only on paths a test run does not reach:
// restart_syscall (the kernel restarts an interrupted sleep with it),
// the clock calls (the vDSO falls back to them where the clock cannot
// be read in user space), sched_getaffinity and pread64 (GOMAXPROCS
// updates), munmap, and fstat, newfstatat and lseek (the standard
// library's file reads); and the two calls glibc's threads need in a
// build with cgo. Each acts on the calling process alone: its
// memory, threads, signals and own descriptors (the channel, /dev/null,
// the /proc files it reads).
//
// The names are the same on amd64 and arm64 (arm64 has none of the
// legacy calls such as open or stat, and none is listed); the numbers
// are each architecture's own. The most frequent calls come first: the
// filter compares in this order.
var allowed = []uint32{
	unix.SYS_FUTEX, unix.SYS_NANOSLEEP, unix.SYS_EPOLL_PWAIT, unix.SYS_READ, unix.SYS_WRITE,
	unix.SYS_GETPID, unix.SYS_RT_SIGRETURN, unix.SYS_FCNTL, unix.SYS_SCHED_YIELD, unix.SYS_CLOSE,
	unix.SYS_EPOLL_CTL, unix.SYS_MADVISE, unix.SYS_RT_SIGPROCMASK,
	unix.SYS_RT_SIGACTION, unix.SYS_GETRANDOM, unix.SYS_GETTID, unix.SYS_SIGALTSTACK,
	unix.SYS_GETRUSAGE, unix.SYS_GETDENTS64, unix.SYS_GETRLIMIT, unix.SYS_MUNMAP,
	unix.SYS_RESTART_SYSCALL, unix.SYS_CLOCK_GETTIME, unix.SYS_CLOCK_GETRES, unix.SYS_GETTIMEOFDAY,
	unix.SYS_SCHED_GETAFFINITY, unix.SYS_PREAD64, unix.SYS_FSTAT, unix.SYS_NEWFSTATAT, unix.SYS_LSEEK,
	unix.SYS_GETUID, unix.SYS_GETEUID, unix.SYS_GETGID, unix.SYS_GETEGID, unix.SYS_GETPPID,
	unix.SYS_EPOLL_CREATE1, unix.SYS_EVENTFD2, unix.SYS_EXIT, unix.SYS_EXIT_GROUP,
	// glibc's thread start, in builds with cgo only (tests and
	// development binaries; a release is CGO_ENABLED=0): a thread that
	// cannot register its rseq area where the first thread did ends the
	// process.
	unix.SYS_RSEQ, unix.SYS_SET_ROBUST_LIST,
}

// conditional are the calls allowed only with certain arguments (see
// program): files opened for reading only, new threads but no new
// processes, signals to itself only, no executable memory, two prctl
// options, rlimits read but not set.
var conditional = []uint32{
	unix.SYS_OPENAT, unix.SYS_CLONE, unix.SYS_TGKILL, unix.SYS_KILL, unix.SYS_MMAP, unix.SYS_MPROTECT,
	unix.SYS_PRCTL, unix.SYS_PRLIMIT64,
}

// nosys are refused with ENOSYS ("no such call") instead of EPERM:
// clone3, which callers use only where available and replace with clone
// when the kernel has none (glibc's threads do); and io_uring_setup,
// which makes io_uring look absent, as on a kernel built without it
// (and lets the self-test tell the filter's answer from that of
// kernel.io_uring_disabled=2, which is EPERM).
var nosys = []uint32{unix.SYS_CLONE3, unix.SYS_IO_URING_SETUP}

// lastKnown is the highest system-call number of Linux 6.6, the kernel
// the release image pins (map_shadow_stack, 453 on both architectures;
// arm64 does not implement it). A higher number is a call added after
// 6.6: the filter answers ENOSYS, as 6.6 itself does, so that a newer
// kernel offers a vault process nothing 6.6 did not, and a program that
// probes a new call falls back as it would on 6.6.
const lastKnown = unix.SYS_MAP_SHADOW_STACK

// Argument conditions.
const (
	// A thread shares memory, files and signal handlers with its process
	// (the Go runtime and glibc pass CLONE_THREAD); a clone without it is
	// a new process. No namespace flag is accepted.
	cloneNamespaces = unix.CLONE_NEWNS | unix.CLONE_NEWCGROUP | unix.CLONE_NEWUTS | unix.CLONE_NEWIPC |
		unix.CLONE_NEWUSER | unix.CLONE_NEWPID | unix.CLONE_NEWNET
	// A vault process reads files (/proc/self/..., /proc/meminfo) and
	// writes none: openat only read-only, without creating or truncating.
	// Writing /proc/self/mem would patch the process's own code whatever
	// the page protections (the kernel writes it with FOLL_FORCE), which
	// the PROT_EXEC rule below cannot stop. O_TMPFILE needs write access,
	// so it is refused too. (The legacy open and creat of amd64, and
	// openat2, are not allowed at all.)
	openWrite = unix.O_ACCMODE | unix.O_CREAT | unix.O_TRUNC
)

// x32Bit marks a syscall number of the x32 ABI on amd64. Such a call
// reports the same architecture as a native one but has its own number
// (socket is x32Bit|41). Nothing here is built for x32: every number
// from x32Bit up is refused.
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

// offsets in struct seccomp_data: the number, the architecture, and the
// six arguments, 64 bits each (both architectures are little-endian, so
// an argument's low 32 bits come first).
const (
	offNR   = 0
	offArch = 4
	offArgs = 16
)

func argLo(i int) uint32 { return offArgs + 8*uint32(i) }
func argHi(i int) uint32 { return offArgs + 8*uint32(i) + 4 }

// The filter's answers.
const (
	eperm  = unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)
	enosys = unix.SECCOMP_RET_ERRNO | uint32(unix.ENOSYS)
)

// asm builds a classic BPF program with forward jumps to labels.
type asm struct {
	p      []unix.SockFilter
	labels map[string]int
	fix    []fixup
}

type fixup struct {
	at     int
	jt, jf string // "" is the next instruction
}

const (
	ldW  = unix.BPF_LD | unix.BPF_W | unix.BPF_ABS
	jeq  = unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K
	jge  = unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K
	jgt  = unix.BPF_JMP | unix.BPF_JGT | unix.BPF_K
	jset = unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K
	ret  = unix.BPF_RET | unix.BPF_K
)

func (a *asm) stmt(code uint16, k uint32) { a.p = append(a.p, unix.SockFilter{Code: code, K: k}) }

func (a *asm) jump(code uint16, k uint32, jt, jf string) {
	a.fix = append(a.fix, fixup{at: len(a.p), jt: jt, jf: jf})
	a.p = append(a.p, unix.SockFilter{Code: code, K: k})
}

func (a *asm) label(l string) { a.labels[l] = len(a.p) }

func (a *asm) done() []unix.SockFilter {
	off := func(from int, l string) uint32 {
		if l == "" {
			return 0
		}
		to, ok := a.labels[l]
		if !ok || to <= from {
			panic("seccomp: bad label " + l)
		}
		return uint32(to - from - 1)
	}
	for _, f := range a.fix {
		jt, jf := off(f.at, f.jt), off(f.at, f.jf)
		if jt > 255 || jf > 255 {
			panic("seccomp: jump too far")
		}
		a.p[f.at].Jt, a.p[f.at].Jf = uint8(jt), uint8(jf)
	}
	return a.p
}

// program builds the filter for the process pid. On a foreign
// architecture it kills. On amd64 every x32 number is refused. The
// allowed calls pass, the conditional ones when their arguments qualify;
// the nosys calls and every number above lastKnown get notFound; every
// other call gets deny. The installed filter answers EPERM and ENOSYS;
// TestWorkload's strict copy kills instead.
func program(pid, deny, notFound uint32) []unix.SockFilter {
	a := &asm{labels: map[string]int{}}
	a.stmt(ldW, offArch)
	a.jump(jeq, arch(), "", "kill")
	a.stmt(ldW, offNR)
	if runtime.GOARCH == "amd64" {
		a.jump(jge, x32Bit, "deny", "")
		a.jump(jge, x32First, "", "native")
		a.jump(jgt, x32Last, "", "deny")
		a.label("native")
	}
	for _, nr := range allowed {
		a.jump(jeq, nr, "allow", "")
	}
	a.jump(jeq, unix.SYS_OPENAT, "readonly", "")
	a.jump(jeq, unix.SYS_CLONE, "clone", "")
	a.jump(jeq, unix.SYS_TGKILL, "self", "")
	a.jump(jeq, unix.SYS_KILL, "self", "")
	a.jump(jeq, unix.SYS_MMAP, "noexec", "")
	a.jump(jeq, unix.SYS_MPROTECT, "noexec", "")
	a.jump(jeq, unix.SYS_PRCTL, "prctl", "")
	a.jump(jeq, unix.SYS_PRLIMIT64, "prlimit", "")
	for _, nr := range nosys {
		a.jump(jeq, nr, "nosys", "")
	}
	a.jump(jgt, lastKnown, "nosys", "deny")

	// openat: flags (the third argument) neither ask for write access
	// nor create or truncate.
	a.label("readonly")
	a.stmt(ldW, argLo(2))
	a.jump(jset, openWrite, "deny", "allow")
	// clone: CLONE_THREAD and no namespace (flags are the first argument
	// on both architectures; the kernel uses their low 32 bits).
	a.label("clone")
	a.stmt(ldW, argLo(0))
	a.jump(jset, unix.CLONE_THREAD, "", "deny")
	a.jump(jset, cloneNamespaces, "deny", "allow")
	// kill and tgkill: the first argument (a pid_t) is this process.
	a.label("self")
	a.stmt(ldW, argLo(0))
	a.jump(jeq, pid, "allow", "deny")
	// mmap and mprotect: never PROT_EXEC (the third argument).
	a.label("noexec")
	a.stmt(ldW, argLo(2))
	a.jump(jset, unix.PROT_EXEC, "deny", "allow")
	// prctl: reading the dumpable flag (the self-test) and naming
	// anonymous memory (the Go runtime since 1.25).
	a.label("prctl")
	a.stmt(ldW, argLo(0))
	a.jump(jeq, unix.PR_GET_DUMPABLE, "allow", "")
	a.jump(jeq, unix.PR_SET_VMA, "allow", "deny")
	// prlimit64: this process (pid 0) and no new limit (third argument
	// NULL): reading only.
	a.label("prlimit")
	a.stmt(ldW, argLo(0))
	a.jump(jeq, 0, "", "deny")
	a.stmt(ldW, argLo(2))
	a.jump(jeq, 0, "", "deny")
	a.stmt(ldW, argHi(2))
	a.jump(jeq, 0, "allow", "deny")

	a.label("deny")
	a.stmt(ret, deny)
	a.label("nosys")
	a.stmt(ret, notFound)
	a.label("allow")
	a.stmt(ret, unix.SECCOMP_RET_ALLOW)
	a.label("kill")
	a.stmt(ret, unix.SECCOMP_RET_KILL_PROCESS)
	return a.done()
}

// Install sets no_new_privs and installs the filter on every thread of
// the process (TSYNC). Threads created later inherit both, and neither
// can be removed. (The filter refuses execve and new processes.)
func Install() error { return install(program(uint32(os.Getpid()), eperm, enosys)) }

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

// Allowed is the number of system calls the filter lets through, those
// with argument conditions included.
func Allowed() int { return len(allowed) + len(conditional) }

// Refused reports whether err is the filter's answer to the probe name:
// EPERM, or ENOSYS for clone3 and io_uring_setup.
func Refused(name string, err error) bool {
	for _, p := range slices.Concat(probes, archProbes) {
		if p.name == name {
			return errors.Is(err, p.want())
		}
	}
	return false
}

// A probe makes one call the filter refuses, with arguments that do
// nothing where the call is not refused: the kernel then answers with
// another error (no such process, bad descriptor, bad argument or
// address, no such call) or creates a descriptor, which the probe
// closes. No argument makes a call succeed in a way that changes the
// process: Probe also runs without the filter (the self-test's record of
// the kernel's own answers, and the tests).
type probe struct {
	name  string
	nr    uint32
	fd    bool // the call returns a descriptor
	a     [6]uintptr
	nosys bool // the filter answers ENOSYS
}

func (p probe) want() unix.Errno {
	if p.nosys {
		return unix.ENOSYS
	}
	return unix.EPERM
}

const (
	none = ^uintptr(0) // a descriptor that is not open; every flag bit
	bad  = uintptr(1)  // an address that is not mapped
)

var probes = []probe{
	// The calls the filter refused as a deny list, and still refuses.
	{name: "socket_vsock", nr: unix.SYS_SOCKET, fd: true, a: [6]uintptr{unix.AF_VSOCK, unix.SOCK_STREAM | unix.SOCK_CLOEXEC}},
	{name: "socket_inet", nr: unix.SYS_SOCKET, fd: true, a: [6]uintptr{unix.AF_INET, unix.SOCK_STREAM | unix.SOCK_CLOEXEC}},
	{name: "socketpair", nr: unix.SYS_SOCKETPAIR}, // see Probe
	// No parameters: EFAULT where io_uring is open, EPERM where
	// kernel.io_uring_disabled is 2, ENOSYS where the kernel has none
	// (4.14). The filter answers ENOSYS.
	{name: "io_uring_setup", nr: unix.SYS_IO_URING_SETUP, fd: true, nosys: true},
	{name: "io_uring_enter", nr: unix.SYS_IO_URING_ENTER, a: [6]uintptr{none}},
	{name: "io_uring_register", nr: unix.SYS_IO_URING_REGISTER, a: [6]uintptr{none}},
	// Attaching to process 0, which does not exist, and reading or
	// writing nothing of it.
	{name: "ptrace", nr: unix.SYS_PTRACE, a: [6]uintptr{unix.PTRACE_ATTACH}},
	{name: "process_vm_readv", nr: unix.SYS_PROCESS_VM_READV},
	{name: "process_vm_writev", nr: unix.SYS_PROCESS_VM_WRITEV},
	{name: "pidfd_getfd", nr: unix.SYS_PIDFD_GETFD, fd: true, a: [6]uintptr{none}},
	// A lookup (command 1) in no map.
	{name: "bpf", nr: unix.SYS_BPF, a: [6]uintptr{unix.BPF_MAP_LOOKUP_ELEM}},
	// Flags that do not exist.
	{name: "userfaultfd", nr: unix.SYS_USERFAULTFD, fd: true, a: [6]uintptr{none}},
	// No attributes.
	{name: "perf_event_open", nr: unix.SYS_PERF_EVENT_OPEN, fd: true},

	// Calls added after Linux 4.14, which a deny list let through on a
	// newer kernel (on 4.14 itself the kernel answers ENOSYS).
	{name: "pidfd_open", nr: unix.SYS_PIDFD_OPEN, fd: true}, // process 0: EINVAL; the os package probes it
	{name: "pidfd_send_signal", nr: unix.SYS_PIDFD_SEND_SIGNAL, a: [6]uintptr{none}},
	{name: "process_madvise", nr: unix.SYS_PROCESS_MADVISE, a: [6]uintptr{none}},
	{name: "process_mrelease", nr: unix.SYS_PROCESS_MRELEASE, a: [6]uintptr{none}},
	{name: "open_tree", nr: unix.SYS_OPEN_TREE, fd: true, a: [6]uintptr{none, 0, none}},
	{name: "fsconfig", nr: unix.SYS_FSCONFIG, a: [6]uintptr{none}},
	{name: "mount_setattr", nr: unix.SYS_MOUNT_SETATTR, a: [6]uintptr{none, 0, none}},
	{name: "memfd_secret", nr: unix.SYS_MEMFD_SECRET, fd: true, a: [6]uintptr{none}},
	{name: "landlock_create_ruleset", nr: unix.SYS_LANDLOCK_CREATE_RULESET, a: [6]uintptr{0, 0, none}},
	{name: "quotactl_fd", nr: unix.SYS_QUOTACTL_FD, a: [6]uintptr{none}},
	{name: "cachestat", nr: unix.SYS_CACHESTAT, a: [6]uintptr{none}},
	{name: "set_mempolicy_home_node", nr: unix.SYS_SET_MEMPOLICY_HOME_NODE, a: [6]uintptr{1, 0, 0, none}},
	{name: "io_pgetevents", nr: unix.SYS_IO_PGETEVENTS},
	{name: "futex_waitv", nr: unix.SYS_FUTEX_WAITV, a: [6]uintptr{0, 0, none}},
	// glibc's way to create a thread, which it replaces with clone on
	// ENOSYS (Go's os package uses it only once pidfd_open works, which
	// the filter refuses): the filter answers ENOSYS (the kernel: EINVAL
	// for no arguments, ENOSYS on 4.14).
	{name: "clone3", nr: unix.SYS_CLONE3, nosys: true},

	// Older calls a vault process never makes.
	{name: "execve", nr: unix.SYS_EXECVE}, // no program: EFAULT
	{name: "execveat", nr: unix.SYS_EXECVEAT, a: [6]uintptr{none}},
	// A new process (no CLONE_THREAD), with flags the kernel refuses
	// (EINVAL), so that nothing is created without the filter either.
	{name: "clone_process", nr: unix.SYS_CLONE, a: [6]uintptr{unix.CLONE_NEWNS | unix.CLONE_FS | uintptr(unix.SIGCHLD)}},
	{name: "unshare", nr: unix.SYS_UNSHARE, a: [6]uintptr{unix.CLONE_NEWUSER}}, // EINVAL in a process with threads
	{name: "setns", nr: unix.SYS_SETNS, a: [6]uintptr{none}},
	{name: "mount", nr: unix.SYS_MOUNT}, // no target: EFAULT
	{name: "umount2", nr: unix.SYS_UMOUNT2, a: [6]uintptr{0, none}},
	{name: "chroot", nr: unix.SYS_CHROOT}, // no path: EFAULT
	{name: "keyctl", nr: unix.SYS_KEYCTL, a: [6]uintptr{none}},
	{name: "memfd_create", nr: unix.SYS_MEMFD_CREATE, fd: true, a: [6]uintptr{0, none}},
	{name: "ioctl", nr: unix.SYS_IOCTL, a: [6]uintptr{none}},
	{name: "connect", nr: unix.SYS_CONNECT, a: [6]uintptr{none}},
	{name: "sendmsg", nr: unix.SYS_SENDMSG, a: [6]uintptr{none}},
	{name: "recvmsg", nr: unix.SYS_RECVMSG, a: [6]uintptr{none}},
	// The conditional calls with arguments outside their conditions:
	// signal 0 (no signal) to the process group, an option prctl does
	// not have, a new limit at an unmapped address (EFAULT before
	// anything is set), executable memory at no address (EINVAL).
	{name: "kill_other", nr: unix.SYS_KILL},
	{name: "prctl_other", nr: unix.SYS_PRCTL, a: [6]uintptr{0xffff}},
	{name: "prlimit_set", nr: unix.SYS_PRLIMIT64, a: [6]uintptr{0, unix.RLIMIT_NOFILE, bad}},
	{name: "mprotect_exec", nr: unix.SYS_MPROTECT, a: [6]uintptr{bad, 0, unix.PROT_READ | unix.PROT_EXEC}},
	// Opening for writing, at no path (EFAULT before anything is opened).
	{name: "openat_write", nr: unix.SYS_OPENAT, fd: true, a: [6]uintptr{none, 0, unix.O_WRONLY | unix.O_CLOEXEC}},
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

// Probe makes every probe's call, harmlessly, and returns each one's
// error by name: Refused(name, err) under the filter, ErrNotRefused for a
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
		r, _, errno := unix.Syscall6(uintptr(p.nr), p.a[0], p.a[1], p.a[2], p.a[3], p.a[4], p.a[5])
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
