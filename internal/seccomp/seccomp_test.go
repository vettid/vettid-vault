//go:build linux && (amd64 || arm64)

package seccomp

import (
	"errors"
	"os"
	"os/exec"
	"testing"

	"golang.org/x/sys/unix"
)

// The filter is installed in a child copy of the test binary (it cannot be
// undone), which then tries what it must not do.
func TestFilter(t *testing.T) {
	if os.Getenv("SECCOMP_CHILD") == "1" {
		if err := Install(); err != nil {
			os.Exit(2)
		}
		if _, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM, 0); !errors.Is(err, unix.EPERM) {
			os.Exit(3)
		}
		if _, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0); !errors.Is(err, unix.EPERM) {
			os.Exit(4)
		}
		if _, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0); !errors.Is(err, unix.EPERM) {
			os.Exit(5)
		}
		if err := unix.PtraceAttach(os.Getppid()); !errors.Is(err, unix.EPERM) {
			os.Exit(6)
		}
		// Ordinary work still runs.
		if _, err := os.ReadFile("/proc/self/status"); err != nil {
			os.Exit(7)
		}
		os.Exit(0)
	}
	cmd := exec.Command(os.Args[0], "-test.run", "^TestFilter$")
	cmd.Env = append(os.Environ(), "SECCOMP_CHILD=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child: %v\n%s", err, out)
	}
}
