//go:build linux

package supervisor

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func socketpair() ([2]int, error) {
	return unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
}

// procAttr: a new process group, SIGKILL when the supervisor dies, and,
// with a uid, that uid as uid and gid without supplementary groups.
func procAttr(uid int) *syscall.SysProcAttr {
	a := &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	if uid > 0 {
		id := uint32(uid)
		a.Credential = &syscall.Credential{Uid: id, Gid: id, Groups: []uint32{}}
	}
	return a
}

// setLimits applies the vault process's rlimits: address space, open
// files, no core files, no file of any size; and, when it runs under a
// uid of its own (ownUID), the number of processes and threads of that
// uid, so that what it starts stays countable and the sweep at its end
// cannot be outrun. (RLIMIT_NPROC counts every task of the real uid on
// the machine: under a shared uid it would count unrelated processes.)
func setLimits(pid int, c ProcConfig, ownUID bool) {
	_ = unix.Prlimit(pid, unix.RLIMIT_AS, &unix.Rlimit{Cur: c.AddressSpace, Max: c.AddressSpace}, nil)
	_ = unix.Prlimit(pid, unix.RLIMIT_NOFILE, &unix.Rlimit{Cur: c.OpenFiles, Max: c.OpenFiles}, nil)
	_ = unix.Prlimit(pid, unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}, nil)
	_ = unix.Prlimit(pid, unix.RLIMIT_FSIZE, &unix.Rlimit{Cur: 0, Max: 0}, nil)
	if ownUID {
		_ = unix.Prlimit(pid, unix.RLIMIT_NPROC, &unix.Rlimit{Cur: c.Tasks, Max: c.Tasks}, nil)
	}
}

// procRoot is where the sweep reads processes (a variable for the tests).
var procRoot = "/proc"

// Sweep pacing: a killed process takes a moment to go; the sweep looks
// again every sweepPause, sweepRounds times at most.
var (
	sweepPause  = 10 * time.Millisecond
	sweepRounds = 500
)

// killAll is how the sweep ends a uid's processes (a variable for the
// tests).
var killAll = killUID

// sweepUID ends every process still running under uid: it kills the
// whole uid at once (killUID: no pid is involved, so a pid reused by
// another process can never be hit), then looks in /proc whether any is
// left, and repeats until none is. RLIMIT_NPROC bounds how many there can
// be, so a process that keeps starting new ones cannot outrun it. It
// fails, and the caller must not count the uid as clean, when /proc
// cannot be read or processes are still there after the last round.
func sweepUID(uid int) error {
	for round := 0; round < sweepRounds; round++ {
		pids, err := liveProcessesOf(uid)
		if err != nil {
			return err
		}
		if len(pids) == 0 {
			return nil
		}
		if err := killAll(uid); err != nil {
			return err
		}
		time.Sleep(sweepPause)
	}
	pids, err := liveProcessesOf(uid)
	if err != nil {
		return err
	}
	if len(pids) > 0 {
		return fmt.Errorf("%d processes of uid %d still running", len(pids), uid)
	}
	return nil
}

// liveProcessesOf lists the processes of uid (any of its real,
// effective, saved and file-system uids) that still run: at least one
// of their threads is not a zombie.
func liveProcessesOf(uid int) ([]int, error) {
	ents, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, err
	}
	var pids []int
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 0 || !e.IsDir() {
			continue
		}
		if hasUID(pid, uid) && running(pid) {
			pids = append(pids, pid)
		}
	}
	if len(pids) == 0 && !hasSelf(ents) {
		// Not /proc at all (nothing mounted there): no answer.
		return nil, errors.New("no processes listed in " + procRoot)
	}
	return pids, nil
}

// hasSelf reports whether a /proc listing has the supervisor's own entry.
func hasSelf(ents []os.DirEntry) bool {
	self := strconv.Itoa(os.Getpid())
	for _, e := range ents {
		if e.Name() == self || e.Name() == "self" {
			return true
		}
	}
	return false
}

// hasUID reports whether a process's status names uid among its uids.
func hasUID(pid, uid int) bool {
	b, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "status"))
	if err != nil {
		return false
	}
	want := strconv.Itoa(uid)
	for _, line := range strings.Split(string(b), "\n") {
		if rest, ok := strings.CutPrefix(line, "Uid:"); ok {
			for _, f := range strings.Fields(rest) {
				if f == want {
					return true
				}
			}
			return false
		}
	}
	return false
}

// running reports whether any thread of a process is alive (its state is
// not Z or X). A process whose first thread has ended shows that thread
// as a zombie while its other threads run.
func running(pid int) bool {
	dir := filepath.Join(procRoot, strconv.Itoa(pid), "task")
	tasks, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, t := range tasks {
		b, err := os.ReadFile(filepath.Join(dir, t.Name(), "stat"))
		if err != nil {
			continue
		}
		// "tid (comm) S ...": comm may hold spaces and parentheses.
		i := strings.LastIndexByte(string(b), ')')
		if i < 0 || i+2 >= len(b) {
			continue
		}
		if st := b[i+2]; st != 'Z' && st != 'X' {
			return true
		}
	}
	return false
}

// killUID sends SIGKILL to every process of uid, without naming any:
// on a thread of its own, locked to this goroutine, the supervisor sets
// that thread's real, effective and saved uid to uid (the raw system
// call changes only the calling thread; Go's Setresuid would change
// every thread) and calls kill(-1, SIGKILL). kill(-1) signals every
// process the caller may signal, except PID 1 and the caller's own
// thread group: with all its uids set to uid and, having left uid 0, no
// capabilities (CAP_KILL included), the thread may signal exactly the
// processes whose real or saved uid is uid, which is only what that
// vault process and its children run, since a uid is never given to a
// second process. The supervisor's other threads keep root and are not
// signalled (its own thread group is skipped). The goroutine then ends
// still locked, so the Go runtime ends that thread instead of reusing
// it. The kernel walks its process list for kill(-1) itself, so no pid
// read from /proc is ever used, and a pid reused meanwhile by another
// process cannot be hit.
func killUID(uid int) error {
	if uid <= 0 || os.Geteuid() != 0 || uid == os.Getuid() {
		// Only root, and never for its own or root's uid: kill(-1) as the
		// caller's own uid would signal all of its processes.
		return errors.New("killUID: needs root and another uid")
	}
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		// Never unlocked: the thread ends with the goroutine.
		if _, _, e := unix.RawSyscall(unix.SYS_SETRESUID, uintptr(uid), uintptr(uid), uintptr(uid)); e != 0 {
			done <- e
			return
		}
		_, _, e := unix.RawSyscall(unix.SYS_KILL, ^uintptr(0), uintptr(unix.SIGKILL), 0) // kill(-1, SIGKILL)
		if e != 0 && e != unix.ESRCH {                                                   // ESRCH: nothing left
			done <- e
			return
		}
		done <- nil
	}()
	return <-done
}

// hardenSelf makes the supervisor non-dumpable and, where the kernel has
// Yama, forbids ptrace for everyone (scope 3); failures are reported.
func hardenSelf() []string {
	var notes []string
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		notes = append(notes, "PR_SET_DUMPABLE failed")
	}
	if err := os.WriteFile("/proc/sys/kernel/yama/ptrace_scope", []byte("3"), 0); err != nil {
		notes = append(notes, "Yama ptrace_scope unavailable")
	}
	return notes
}

// Kernel settings of the whole machine (variables for the tests, which
// must not write the real ones).
var (
	// The NSM device: only root (the supervisor) may open it. Vault
	// processes run under their own uids and get attestations through
	// the supervisor.
	nsmPath = "/dev/nsm"
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

// pid1 describes the enclave's process tree for the self-test: this
// process's pid and parent, and PID 1's name.
func pid1() string {
	comm, err := os.ReadFile(filepath.Join(procRoot, "1", "comm"))
	name := strings.TrimSpace(string(comm))
	if err != nil {
		name = err.Error()
	}
	return fmt.Sprintf("supervisor pid=%d ppid=%d; pid 1 is %q", os.Getpid(), os.Getppid(), name)
}

// zombies counts the processes that have ended and not been reaped, and
// those whose parent is the supervisor.
func zombies() (all, ours int, err error) {
	ents, err := os.ReadDir(procRoot)
	if err != nil {
		return 0, 0, err
	}
	for _, e := range ents {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		b, err := os.ReadFile(filepath.Join(procRoot, e.Name(), "stat"))
		if err != nil {
			continue
		}
		i := strings.LastIndexByte(string(b), ')')
		if i < 0 || i+2 >= len(b) || b[i+2] != 'Z' {
			continue
		}
		all++
		if f := strings.Fields(string(b[i+2:])); len(f) > 1 && f[1] == strconv.Itoa(os.Getpid()) {
			ours++
		}
	}
	return all, ours, nil
}

// closeNSM sets the NSM device to mode 0600 and checks that it is now
// root's alone: owned by uid 0, no access for group or others.
func closeNSM() error {
	if err := os.Chmod(nsmPath, 0o600); err != nil {
		return err
	}
	return nsmClosedCheck()
}

func nsmClosedCheck() error {
	fi, err := os.Stat(nsmPath)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("no owner")
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 || st.Uid != 0 {
		return fmt.Errorf("mode %v owner %d", perm, st.Uid)
	}
	if fi.Mode().Type()&fs.ModeDevice == 0 {
		return fmt.Errorf("not a device: %v", fi.Mode().Type())
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
