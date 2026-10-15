//go:build linux

package supervisor

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestLockdownConfidentiality(t *testing.T) {
	for mode, want := range map[string]bool{
		"none integrity [confidentiality]": true,
		"none [integrity] confidentiality": false,
		"[none] integrity confidentiality": false,
		"":                                 false,
	} {
		if got := lockdownConfidentiality(mode); got != want {
			t.Errorf("%q: %v", mode, got)
		}
	}
}

func TestModulesAbsent(t *testing.T) {
	d := t.TempDir()
	old := modulesPaths
	t.Cleanup(func() { modulesPaths = old })
	modulesPaths = []string{filepath.Join(d, "modules"), filepath.Join(d, "modules_disabled")}
	if err := modulesAbsent(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(modulesPaths[1], []byte("0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if modulesAbsent() == nil {
		t.Fatal("modules_disabled exists, yet no module support reported")
	}
}

func TestKaslrStatus(t *testing.T) {
	old := kernelLog
	t.Cleanup(func() { kernelLog = old })
	kernelLog = func() ([]byte, error) {
		return []byte("<6>[    0.000000] Booting Linux\n<4>[    0.000000] KASLR disabled due to lack of seed\n"), nil
	}
	if got := kaslrStatus(); got != "KASLR disabled due to lack of seed" {
		t.Fatalf("got %q", got)
	}
	kernelLog = func() ([]byte, error) { return nil, errors.New("EPERM") }
	if got := kaslrStatus(); got != "kernel log: EPERM" {
		t.Fatalf("got %q", got)
	}
}

// TestSpawnNeedsLockdown: on the hardened kernel no vault process starts
// unless closeKernel found lockdown in confidentiality mode.
func TestSpawnNeedsLockdown(t *testing.T) {
	old := securityfsPath
	t.Cleanup(func() { securityfsPath = old })
	securityfsPath = t.TempDir()
	write := func(v string) {
		if err := os.WriteFile(filepath.Join(securityfsPath, "lockdown"), []byte(v), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	s := &Supervisor{cfg: Config{KernelHardened: true}}
	h := newProcHost(s, ProcConfig{Exec: []string{"/bin/true"}, MaxProcs: 1})
	write("[none] integrity confidentiality\n")
	if checkLockdown() == nil {
		t.Fatal("lockdown none accepted")
	}
	if _, err := h.spawn("vault", "user", false); !errors.Is(err, errSpawn) {
		t.Fatalf("spawn without lockdown: %v", err)
	}
	write("none integrity [confidentiality]\n")
	if err := checkLockdown(); err != nil {
		t.Fatal(err)
	}
	// Without KernelHardened the gate does not apply.
	s2 := &Supervisor{cfg: Config{}}
	if s2.cfg.KernelHardened || s2.lockedDown.Load() {
		t.Fatal("unexpected state")
	}
}
