//go:build linux

package supervisor

import (
	"fmt"
	"os"
	"strings"
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

// Kernel settings of the whole machine (variables for the tests, which
// must not write the real ones).
var (
	// The number of user namespaces that may exist below the initial
	// one. Only a process with CAP_SYS_RESOURCE in the initial user
	// namespace may write it, so no vault process can raise it again.
	userNSLimitPath = "/proc/sys/user/max_user_namespaces"
	// Not 0: only privileged processes may call bpf. The kernel does not
	// let it be set back to 0.
	bpfDisabledPath = "/proc/sys/kernel/unprivileged_bpf_disabled"
)

func readSetting(path string) (string, error) {
	b, err := os.ReadFile(path)
	return strings.TrimSpace(string(b)), err
}

// closeUserNamespaces sets the limit of user namespaces to 0 and reads
// it back. No process, root included, can then create a user namespace
// (clone and unshare with CLONE_NEWUSER answer ENOSPC), and with it none
// of the namespaces, mounts and capabilities that an unprivileged process
// gets only inside one.
func closeUserNamespaces() error {
	if err := os.WriteFile(userNSLimitPath, []byte("0\n"), 0); err != nil {
		return err
	}
	return userNamespacesClosed()
}

func userNamespacesClosed() error {
	v, err := readSetting(userNSLimitPath)
	if err != nil {
		return err
	}
	if v != "0" {
		return fmt.Errorf("the limit of user namespaces is %q", v)
	}
	return nil
}

// disableUnprivilegedBPF closes the bpf call to unprivileged processes
// and reads the setting back.
func disableUnprivilegedBPF() error {
	if err := os.WriteFile(bpfDisabledPath, []byte("1\n"), 0); err != nil {
		return err
	}
	return unprivilegedBPFDisabled()
}

func unprivilegedBPFDisabled() error {
	v, err := readSetting(bpfDisabledPath)
	if err != nil {
		return err
	}
	if v != "1" && v != "2" {
		return fmt.Errorf("unprivileged_bpf_disabled is %q", v)
	}
	return nil
}

func supervisorDumpable() (int, error) { return unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0) }

// selfCPUMicros is the supervisor's user and system CPU time.
func selfCPUMicros() int64 {
	var ru unix.Rusage
	if unix.Getrusage(unix.RUSAGE_SELF, &ru) != nil {
		return 0
	}
	return (int64(ru.Utime.Sec)+int64(ru.Stime.Sec))*1e6 + int64(ru.Utime.Usec) + int64(ru.Stime.Usec)
}
