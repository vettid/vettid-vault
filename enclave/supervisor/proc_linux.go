//go:build linux

package supervisor

import (
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func socketpair() ([2]int, error) {
	return unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
}

// procAttr: a new process group, SIGKILL when the supervisor dies, and,
// with uidBase, the vault's own uid and gid without supplementary groups.
func procAttr(uidBase, slot int) *syscall.SysProcAttr {
	a := &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	if uidBase > 0 {
		id := uint32(uidBase + slot)
		a.Credential = &syscall.Credential{Uid: id, Gid: id, Groups: []uint32{}}
	}
	return a
}

// setLimits applies the vault process's rlimits: address space, open
// files, no core files.
func setLimits(pid int, c ProcConfig) {
	_ = unix.Prlimit(pid, unix.RLIMIT_AS, &unix.Rlimit{Cur: c.AddressSpace, Max: c.AddressSpace}, nil)
	_ = unix.Prlimit(pid, unix.RLIMIT_NOFILE, &unix.Rlimit{Cur: c.OpenFiles, Max: c.OpenFiles}, nil)
	_ = unix.Prlimit(pid, unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}, nil)
}

// hardenSelf makes the supervisor non-dumpable and, where the kernel has
// Yama, forbids ptrace for everyone (scope 3); failures are reported.
func hardenSelf() []string {
	var notes []string
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		notes = append(notes, "PR_SET_DUMPABLE failed")
	}
	// Only root (the supervisor) may open the NSM: vault processes run
	// under their own uids and get attestations through the supervisor.
	if _, err := os.Stat("/dev/nsm"); err == nil {
		if err := os.Chmod("/dev/nsm", 0o600); err != nil {
			notes = append(notes, "chmod /dev/nsm failed")
		}
	}
	if err := os.WriteFile("/proc/sys/kernel/yama/ptrace_scope", []byte("3"), 0); err != nil {
		notes = append(notes, "Yama ptrace_scope unavailable")
	}
	return notes
}
