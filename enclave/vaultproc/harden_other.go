//go:build !linux

package vaultproc

// Harden is a no-op off Linux (development only).
func Harden() {}

// Dumpable is not supported off Linux.
func Dumpable() (int, error) { return -1, nil }
