//go:build linux

package supervisor

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// Paths of the kernel checks (variables for the tests).
var (
	securityfsPath = "/sys/kernel/security"
	modulesPaths   = []string{"/proc/modules", "/proc/sys/kernel/modules_disabled"}
	// kernelLog reads the kernel's log buffer (syslog(2) READ_ALL; root).
	kernelLog = func() ([]byte, error) {
		n, err := unix.Klogctl(unix.SYSLOG_ACTION_SIZE_BUFFER, nil)
		if err != nil {
			return nil, err
		}
		buf := make([]byte, n)
		m, err := unix.Klogctl(unix.SYSLOG_ACTION_READ_ALL, buf)
		if err != nil {
			return nil, err
		}
		return buf[:m], nil
	}
)

// lockdownMode reads the kernel's lockdown state ("[confidentiality]"
// and the like: the bracketed mode is the one in force). AWS's init does
// not mount securityfs; where the file is missing, securityfs is mounted
// read-only at its usual place first.
func lockdownMode() (string, error) {
	p := filepath.Join(securityfsPath, "lockdown")
	if _, err := os.Stat(p); errors.Is(err, fs.ErrNotExist) {
		if err := unix.Mount("securityfs", securityfsPath, "securityfs",
			unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil && !errors.Is(err, unix.EBUSY) {
			return "", errors.New("mount securityfs: " + err.Error())
		}
	}
	return readSetting(p)
}

// checkLockdown: the kernel is locked down in confidentiality mode.
func checkLockdown() error {
	mode, err := lockdownMode()
	if err != nil {
		return err
	}
	if !lockdownConfidentiality(mode) {
		return errors.New("lockdown is " + mode)
	}
	return nil
}

// lockdownConfidentiality says whether the kernel is locked down in
// confidentiality mode.
func lockdownConfidentiality(mode string) bool {
	return strings.Contains(mode, "[confidentiality]")
}

// modulesAbsent: the kernel has no module support at all (no
// /proc/modules, no kernel.modules_disabled).
func modulesAbsent() error {
	for _, p := range modulesPaths {
		if _, err := os.Stat(p); !errors.Is(err, fs.ErrNotExist) {
			return errors.New(p + " exists: the kernel can load modules")
		}
	}
	return nil
}

// kaslrStatus reports what the kernel logged about KASLR at boot
// ("KASLR enabled", "KASLR disabled due to lack of seed", ...).
func kaslrStatus() string {
	b, err := kernelLog()
	if err != nil {
		return "kernel log: " + err.Error()
	}
	for _, line := range bytes.Split(b, []byte("\n")) {
		if i := bytes.Index(line, []byte("KASLR")); i >= 0 {
			return strings.TrimSpace(string(line[i:]))
		}
	}
	return "no KASLR message in the kernel log"
}
