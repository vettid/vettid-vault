// Package seccomp installs the vault processes' syscall filter
// (VAULT-MESSAGING §12.4). The filter is an allow list: a vault process
// may make the system calls the Go runtime and the vault's code need
// (its memory, threads, signals, clocks, random bytes and its own
// descriptors: the inherited channel and the /proc files it reads), some
// only with certain arguments (files opened for reading only, threads
// but no new process, signals to itself, no executable memory, rlimits
// read but not set). Every other
// call is refused with EPERM, so that it fails visibly instead of
// killing a member's vault; clone3, io_uring_setup and every number
// above the last call of Linux 6.6 are answered ENOSYS, "no such call",
// which is what callers that probe a call expect where it is missing.
//
// In particular a vault process cannot create sockets (no AF_VSOCK
// socket to the parent's control port, which no namespace would stop),
// by the socket calls or through io_uring, run a program or start a
// process, trace other processes, read their memory or take their
// descriptors, or reach the kernel interfaces it never needs and an
// attacker likes (bpf, userfaultfd, perf_event_open, mounts, keys,
// namespaces). A newer kernel adds no reachable call: the list names
// what is allowed, not what is refused.
package seccomp

import "errors"

// ErrUnsupported is returned where no filter can be installed.
var ErrUnsupported = errors.New("seccomp: unsupported platform")

// ErrNotRefused is Probe's result for a call that went through.
var ErrNotRefused = errors.New("not refused")
