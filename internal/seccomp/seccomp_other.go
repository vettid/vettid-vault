//go:build !(linux && (amd64 || arm64))

package seccomp

// Install is not supported here.
func Install() error { return ErrUnsupported }

// Probe has nothing to try here.
func Probe() map[string]error { return map[string]error{"unsupported": ErrUnsupported} }

// Refused is always false here.
func Refused(error) bool { return false }
