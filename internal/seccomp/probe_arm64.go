//go:build linux && arm64

package seccomp

// arm64 has one syscall table for 64-bit processes.
var archProbes []probe
