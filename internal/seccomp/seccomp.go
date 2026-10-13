// Package seccomp installs the vault processes' syscall filter
// (VAULT-MESSAGING §12.4): a vault process talks to nothing but its
// inherited channel, so it may not create sockets (in particular AF_VSOCK
// sockets to the parent's control port, which no namespace would stop),
// by the socket calls or through io_uring, trace other processes, read
// their memory or take their descriptors, and it may not use the kernel
// interfaces a vault never needs and an attacker likes (bpf, userfaultfd,
// perf_event_open). Everything else is allowed; the filter is a deny
// list, kept small on purpose.
package seccomp

import "errors"

// ErrUnsupported is returned where no filter can be installed.
var ErrUnsupported = errors.New("seccomp: unsupported platform")

// ErrNotRefused is Probe's result for a call that went through.
var ErrNotRefused = errors.New("not refused")
