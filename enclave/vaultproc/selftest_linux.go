//go:build linux

package vaultproc

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/vettid/vettid-vault/internal/selftest"
)

type limitResult struct {
	ok     bool
	detail string
}

// limits reports the rlimits the supervisor applied.
func limits() map[string]limitResult {
	out := map[string]limitResult{}
	for name, r := range map[string]int{"as": unix.RLIMIT_AS, "nofile": unix.RLIMIT_NOFILE, "core": unix.RLIMIT_CORE, "fsize": unix.RLIMIT_FSIZE} {
		var l unix.Rlimit
		if err := unix.Getrlimit(r, &l); err != nil {
			out[name] = limitResult{detail: err.Error()}
			continue
		}
		ok := l.Cur != unix.RLIM_INFINITY
		if name == "core" || name == "fsize" {
			ok = l.Cur == 0
		}
		out[name] = limitResult{ok: ok, detail: fmt.Sprintf("cur=%d max=%d", l.Cur, l.Max)}
	}
	return out
}

// nprocLimit reports RLIMIT_NPROC (set only where the process has a uid
// of its own).
func nprocLimit() (limitResult, bool) {
	var l unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NPROC, &l); err != nil {
		return limitResult{detail: err.Error()}, false
	}
	return limitResult{ok: l.Cur != unix.RLIM_INFINITY, detail: fmt.Sprintf("cur=%d max=%d", l.Cur, l.Max)}, true
}

// cpuMicros is this process's user and system CPU time.
func cpuMicros() int64 {
	var ru unix.Rusage
	if unix.Getrusage(unix.RUSAGE_SELF, &ru) != nil {
		return 0
	}
	return (int64(ru.Utime.Sec)+int64(ru.Stime.Sec))*1e6 + int64(ru.Utime.Usec) + int64(ru.Stime.Usec)
}

// TryUserNamespace tries to start a process in a new user namespace and
// says what happened (selftest.UserNamespaceRefused where the supervisor
// has set the limit of user namespaces to 0). The program it names does
// not exist, so nothing ever runs: where the namespace is refused the
// kernel creates no process (ENOSPC), and where it is not, the new
// process ends when the program is not found (ENOENT).
//
// unshare is not tried: it refuses CLONE_NEWUSER in any process with
// more than one thread (EINVAL), which a Go process always is, whatever
// the limit.
func TryUserNamespace() string {
	pid, err := syscall.ForkExec("/proc/self/no-such-program", []string{"no-such-program"},
		&syscall.ProcAttr{Sys: &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER}})
	switch {
	case errors.Is(err, syscall.ENOSPC):
		return selftest.UserNamespaceRefused
	case errors.Is(err, syscall.EINVAL) && !userNSFile():
		// CONFIG_USER_NS=n: the kernel has no user namespaces, and so no
		// /proc/self/ns/user either. With them built in, these clone
		// flags are valid.
		return selftest.UserNamespaceNotBuilt
	case errors.Is(err, syscall.ENOENT):
		return selftest.UserNamespaceCreated
	case err == nil:
		var ws syscall.WaitStatus
		_, _ = syscall.Wait4(pid, &ws, 0, nil)
		return selftest.UserNamespaceCreated
	}
	return err.Error()
}

// userNSFile says whether /proc/self/ns/user exists (it does wherever the
// kernel has user namespaces).
func userNSFile() bool {
	_, err := os.Lstat("/proc/self/ns/user")
	return !errors.Is(err, os.ErrNotExist)
}
