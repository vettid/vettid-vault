//go:build linux

package vaultproc

import (
	"fmt"

	"golang.org/x/sys/unix"
)

var errEPERM error = unix.EPERM

// forbidden tries what the seccomp filter refuses.
func forbidden() map[string]error {
	out := map[string]error{}
	if fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM, 0); err != nil {
		out["socket_vsock"] = err
	} else {
		unix.Close(fd)
		out["socket_vsock"] = fmt.Errorf("socket created")
	}
	if fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0); err != nil {
		out["socket_inet"] = err
	} else {
		unix.Close(fd)
		out["socket_inet"] = fmt.Errorf("socket created")
	}
	if err := unix.PtraceAttach(1); err != nil {
		out["ptrace"] = err
	} else {
		out["ptrace"] = fmt.Errorf("attached")
	}
	return out
}

type limitResult struct {
	ok     bool
	detail string
}

// limits reports the rlimits the supervisor applied.
func limits() map[string]limitResult {
	out := map[string]limitResult{}
	for name, r := range map[string]int{"as": unix.RLIMIT_AS, "nofile": unix.RLIMIT_NOFILE, "core": unix.RLIMIT_CORE} {
		var l unix.Rlimit
		if err := unix.Getrlimit(r, &l); err != nil {
			out[name] = limitResult{detail: err.Error()}
			continue
		}
		ok := l.Cur != unix.RLIM_INFINITY
		if name == "core" {
			ok = l.Cur == 0
		}
		out[name] = limitResult{ok: ok, detail: fmt.Sprintf("cur=%d max=%d", l.Cur, l.Max)}
	}
	return out
}
