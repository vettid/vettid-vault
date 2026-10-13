//go:build linux

package vaultproc

import (
	"fmt"

	"golang.org/x/sys/unix"
)

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

// cpuMicros is this process's user and system CPU time.
func cpuMicros() int64 {
	var ru unix.Rusage
	if unix.Getrusage(unix.RUSAGE_SELF, &ru) != nil {
		return 0
	}
	return (int64(ru.Utime.Sec)+int64(ru.Stime.Sec))*1e6 + int64(ru.Utime.Usec) + int64(ru.Stime.Usec)
}
