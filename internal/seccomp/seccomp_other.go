//go:build !(linux && (amd64 || arm64))

package seccomp

// Install is not supported here.
func Install() error { return ErrUnsupported }
