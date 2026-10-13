//go:build !(linux && (amd64 || arm64))

package seccomp

// Install is not supported here.
func Install() error { return ErrUnsupported }

// Probe has nothing to try here.
func Probe() map[string]error { return map[string]error{"unsupported": ErrUnsupported} }

// Names are the names of Probe's results.
func Names() []string { return []string{"unsupported"} }

// Refused is always false here.
func Refused(error) bool { return false }
