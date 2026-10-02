//go:build linux

package vaultproc

import "golang.org/x/sys/unix"

// Harden makes this process non-dumpable (no core dumps, no ptrace by
// other users, /proc/<pid>/mem closed to them) and disables core files.
// The supervisor also sets rlimits and a separate user id before and after
// starting the process.
func Harden() {
	_ = unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
	_ = unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0})
}

// Dumpable reports the process's dumpable flag (tests).
func Dumpable() (int, error) {
	r, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	return r, err
}
