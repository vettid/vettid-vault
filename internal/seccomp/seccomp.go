// Package seccomp installs the vault processes' syscall filter
// (VAULT-MESSAGING §12.4): a vault process talks to nothing but its
// inherited channel, so it may not create sockets (in particular AF_VSOCK
// sockets to the parent's control port, which no namespace would stop),
// trace other processes or read their memory. Everything else is allowed;
// the filter is a deny list, kept small on purpose.
package seccomp

import "errors"

// ErrUnsupported is returned where no filter can be installed.
var ErrUnsupported = errors.New("seccomp: unsupported platform")
