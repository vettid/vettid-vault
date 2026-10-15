//go:build linux

package supervisor

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/enclave/vaultproc"
	"github.com/vettid/vettid-vault/internal/selftest"
)

// settings points the kernel settings at files of the test. The real
// ones belong to the whole machine and are never written by a test,
// except by TestUserNamespaceLimit's child in a user namespace of its
// own.
func settings(t *testing.T, userNS, bpf string) {
	t.Helper()
	oldNS, oldBPF, oldNSM := userNSLimitPath, bpfDisabledPath, nsmPath
	t.Cleanup(func() { userNSLimitPath, bpfDisabledPath, nsmPath = oldNS, oldBPF, oldNSM })
	userNSLimitPath, bpfDisabledPath = userNS, bpf
	// No NSM device here: closing it fails and adds its note.
	nsmPath = filepath.Join(t.TempDir(), "absent", "nsm")
	fakeProcSys(t)
}

// fakeProcSys points the sysctls at a directory of the test holding
// every setting with its kernel default, and io_uring_setup at a stub
// that answers EPERM (as with io_uring_disabled 2). It returns the
// directory.
func fakeProcSys(t *testing.T) string {
	t.Helper()
	oldRoot, oldSetup, oldBPF, oldInfo, oldRemount := procSys, ioUringSetup, bpfCall, procMountinfo, remountProc
	t.Cleanup(func() {
		procSys, ioUringSetup, bpfCall, procMountinfo, remountProc = oldRoot, oldSetup, oldBPF, oldInfo, oldRemount
	})
	procSys = t.TempDir()
	procMountinfo = filepath.Join(procSys, "mountinfo")
	remountProc = func() error { return mountinfo(t, "rw,hidepid=invisible") }
	if err := mountinfo(t, "rw"); err != nil {
		t.Fatal(err)
	}
	ioUringSetup = func() error { return syscall.EPERM }
	bpfCall = func() error { return syscall.EINVAL } // a kernel with bpf
	for _, c := range sysctls {
		p := filepath.Join(procSys, c.path)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("1\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return procSys
}

// withNSMNote reports whether notes are kernel notes followed by the NSM's.
func withNSMNote(notes []string, kernel int) bool {
	if len(notes) != kernel+1 {
		return false
	}
	return strings.Contains(notes[kernel], "the NSM is not closed to vault processes, the enclave will not serve vaults")
}

func setting(t *testing.T, value string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "setting")
	if err := os.WriteFile(p, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestCloseKernel: the supervisor writes 0 and 1, believes only what it
// reads back, and starts no vault process while user namespaces are
// open.
func TestCloseKernel(t *testing.T) {
	spawn := func(s *Supervisor) error {
		h := newProcHost(s, ProcConfig{Exec: []string{filepath.Join(t.TempDir(), "no-such-program")}, MaxProcs: 2})
		_, err := h.spawn("vault", "user", false)
		for i, used := range h.slots {
			if used {
				t.Errorf("slot %d is still taken", i)
			}
		}
		return err
	}

	// Both settings can be made.
	ns, bpf := setting(t, "15000\n"), setting(t, "0\n")
	settings(t, ns, bpf)
	s := &Supervisor{cfg: Config{OwnKernel: true}}
	if notes := s.closeKernel(); !withNSMNote(notes, 0) || !s.userNSClosed.Load() || s.nsmClosed.Load() {
		t.Fatalf("notes %v, closed %v", notes, s.userNSClosed.Load())
	}
	if v, _ := readSetting(ns); v != "0" {
		t.Errorf("limit %q", v)
	}
	if v, _ := readSetting(bpf); v != "1" {
		t.Errorf("unprivileged_bpf_disabled %q", v)
	}
	if userNamespacesClosed() != nil || unprivilegedBPFDisabled() != nil {
		t.Error("not read back as closed")
	}

	// The limit cannot be written (the file's directory does not exist):
	// a note, and no vault process.
	settings(t, filepath.Join(t.TempDir(), "absent", "max_user_namespaces"), bpf)
	s = &Supervisor{cfg: Config{OwnKernel: true}}
	if notes := s.closeKernel(); !withNSMNote(notes, 1) || !strings.Contains(notes[0], "no vault process will be started") || s.userNSClosed.Load() {
		t.Fatalf("notes %v, closed %v", notes, s.userNSClosed.Load())
	}
	s.nsmClosed.Store(true) // the refusal is the user namespaces'
	if err := spawn(s); !errors.Is(err, errSpawn) {
		t.Fatalf("spawn: %v", err)
	}

	// The write is accepted but the value is not 0 afterwards (/dev/null
	// takes the write and reads back empty): not closed.
	settings(t, os.DevNull, os.DevNull)
	s = &Supervisor{cfg: Config{OwnKernel: true}}
	if notes := s.closeKernel(); !withNSMNote(notes, 2) || s.userNSClosed.Load() {
		t.Fatalf("notes %v, closed %v", notes, s.userNSClosed.Load())
	}
	for _, v := range []string{"1\n", "15000\n", "", "00x"} {
		settings(t, setting(t, v), setting(t, "0\n"))
		if userNamespacesClosed() == nil {
			t.Errorf("limit %q counts as closed", v)
		}
		if unprivilegedBPFDisabled() == nil {
			t.Error("unprivileged_bpf_disabled 0 counts as closed")
		}
	}
	settings(t, setting(t, "0\n"), setting(t, "2\n"))
	if userNamespacesClosed() != nil || unprivilegedBPFDisabled() != nil {
		t.Error("0 and 2 do not count as closed")
	}

}

// TestSpawnNeedsClosedUserNamespaces: with OwnKernel the refusal comes
// before anything is started, and goes away once the limit is 0.
func TestSpawnNeedsClosedUserNamespaces(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "started")
	script := filepath.Join(t.TempDir(), "program")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho started > "+marker+"\nexec sleep 30\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	s := &Supervisor{cfg: Config{OwnKernel: true}}
	h := newProcHost(s, ProcConfig{Exec: []string{script}, MaxProcs: 1})
	if _, err := h.spawn("vault", "user", false); !errors.Is(err, errSpawn) {
		t.Fatalf("spawn: %v", err)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the program was started")
	}
	s.userNSClosed.Store(true)
	// Nor while the NSM is open.
	if _, err := h.spawn("vault", "user", false); !errors.Is(err, errSpawn) {
		t.Fatalf("spawn with the NSM open: %v", err)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the program was started with the NSM open")
	}
	s.nsmClosed.Store(true)
	// Nor while a kernel setting is not made.
	if _, err := h.spawn("vault", "user", false); !errors.Is(err, errSpawn) {
		t.Fatalf("spawn with a kernel setting not made: %v", err)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the program was started with a kernel setting not made")
	}
	s.kernelSet.Store(true)
	p, err := h.spawn("vault", "user", false)
	if err != nil {
		t.Fatalf("spawn with user namespaces and the NSM closed and the settings made: %v", err)
	}
	p.mu.Lock()
	p.stopping = true // ended by the test: nothing to report
	p.mu.Unlock()
	for i := 0; ; i++ {
		if _, err := os.Stat(marker); err == nil {
			break
		}
		if i == 500 {
			t.Error("the program was not started")
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	_ = p.cmd.Process.Kill()
	<-p.exited
}

// mountinfo writes procMountinfo with /proc mounted with super options opts.
func mountinfo(t *testing.T, opts string) error {
	t.Helper()
	return os.WriteFile(procMountinfo, []byte("22 1 0:20 / /sys rw,nosuid - sysfs sysfs rw\n"+
		"53 45 0:25 / /proc rw,nosuid,nodev,noexec,relatime shared:13 - proc proc "+opts+"\n"), 0o600)
}

// TestHideProcesses: the supervisor remounts /proc with hidepid=2 and
// believes only the mount table; without it no vault process starts.
func TestHideProcesses(t *testing.T) {
	fakeProcSys(t)
	for opts, ok := range map[string]bool{"rw,hidepid=2": true, "rw,hidepid=invisible": true, "rw": false, "rw,hidepid=1": false,
		"rw,hidepid=noaccess": false, "rw,hidepid=2,gid=10": true} {
		if err := mountinfo(t, opts); err != nil {
			t.Fatal(err)
		}
		if err := processesHidden(); (err == nil) != ok {
			t.Errorf("%s: %v", opts, err)
		}
	}
	if err := os.WriteFile(procMountinfo, []byte("22 1 0:20 / /sys rw - sysfs sysfs rw\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if processesHidden() == nil {
		t.Error("no /proc mount counts as hidden")
	}

	settings(t, setting(t, "15000\n"), setting(t, "0\n"))
	s := &Supervisor{cfg: Config{OwnKernel: true}}
	if notes := s.closeKernel(); !withNSMNote(notes, 0) || !s.kernelSet.Load() || processesHidden() != nil {
		t.Fatalf("remounted: notes %v, set %v", notes, s.kernelSet.Load())
	}
	// The remount fails, or succeeds without the option taking.
	for _, remount := range []func() error{
		func() error { return syscall.EPERM },
		func() error { return mountinfo(t, "rw") },
	} {
		if err := mountinfo(t, "rw"); err != nil {
			t.Fatal(err)
		}
		remountProc = remount
		s = &Supervisor{cfg: Config{OwnKernel: true}}
		if notes := s.closeKernel(); !withNSMNote(notes, 1) || s.kernelSet.Load() || !strings.Contains(notes[0], "other processes are not hidden") {
			t.Fatalf("not remounted: notes %v, set %v", notes, s.kernelSet.Load())
		}
	}
}

// TestSysctls: every setting is written and read back; a setting an
// older kernel lacks is accepted (and reported as such), except where it
// matters: a missing required file, a missing io_uring_disabled on a
// kernel that has io_uring, a write that does not hold. Any failure
// leaves kernelSet false, so that no vault process starts.
func TestSysctls(t *testing.T) {
	root := fakeProcSys(t)
	statuses := func() map[string]sysctlStatus {
		m := map[string]sysctlStatus{}
		for _, st := range sysctlStatuses() {
			m[st.check] = st
		}
		return m
	}
	if notes := makeSysctls(); len(notes) != 0 {
		t.Fatalf("notes %v", notes)
	}
	want := map[string]string{
		"kernel/io_uring_disabled": "2", "kernel/kptr_restrict": "2", "kernel/dmesg_restrict": "1", "kernel/perf_event_paranoid": "3",
		"kernel/sysrq": "0", "kernel/kexec_load_disabled": "1", "kernel/modules_disabled": "1", "kernel/randomize_va_space": "2",
		"vm/unprivileged_userfaultfd": "0", "dev/tty/legacy_tiocsti": "0", "fs/protected_symlinks": "1", "fs/protected_hardlinks": "1",
		"fs/protected_fifos": "2", "fs/protected_regular": "2",
	}
	if len(sysctls) != len(want) {
		t.Fatalf("%d settings, %d reviewed", len(sysctls), len(want))
	}
	for path, v := range want {
		if got, _ := readSetting(filepath.Join(root, path)); got != v {
			t.Errorf("%s: %q, want %s", path, got, v)
		}
	}
	for name, st := range statuses() {
		if !st.ok || !st.provable || st.detail == "" {
			t.Errorf("%s: %+v", name, st)
		}
	}

	// Settings an older kernel does not have: accepted, informational.
	for _, path := range []string{"dev/tty/legacy_tiocsti", "vm/unprivileged_userfaultfd", "fs/protected_fifos", "fs/protected_regular",
		"kernel/kexec_load_disabled", "kernel/modules_disabled", "kernel/sysrq", "kernel/perf_event_paranoid"} {
		if err := os.Remove(filepath.Join(root, path)); err != nil {
			t.Fatal(err)
		}
	}
	if notes := makeSysctls(); len(notes) != 0 {
		t.Fatalf("absent optional settings: notes %v", notes)
	}
	st := statuses()
	for _, n := range []string{"kernel.legacy_tiocsti_off", "kernel.unprivileged_userfaultfd_off", "kernel.protected_fifos", "kernel.protected_regular",
		"kernel.kexec_load_disabled", "kernel.modules_disabled", "kernel.sysrq_off", "kernel.perf_event_paranoid"} {
		if !st[n].ok || st[n].provable || !strings.HasPrefix(st[n].detail, "absent: ") {
			t.Errorf("%s: %+v", n, st[n])
		}
	}

	// No io_uring_disabled: accepted only where the kernel has no
	// io_uring (4.14), which is then a proof, not a note.
	if err := os.Remove(filepath.Join(root, "kernel/io_uring_disabled")); err != nil {
		t.Fatal(err)
	}
	ioUringSetup = func() error { return syscall.ENOSYS }
	if notes := makeSysctls(); len(notes) != 0 {
		t.Fatalf("no io_uring: notes %v", notes)
	}
	if st := statuses()["kernel.io_uring_off"]; !st.ok || !st.provable || !strings.Contains(st.detail, "no io_uring in this kernel") {
		t.Errorf("no io_uring: %+v", st)
	}
	ioUringSetup = func() error { return syscall.EFAULT }
	if notes := makeSysctls(); len(notes) != 1 || !strings.Contains(notes[0], "kernel.io_uring_off is not set, no vault process will be started") {
		t.Fatalf("io_uring without the setting: notes %v", notes)
	}
	if st := statuses()["kernel.io_uring_off"]; st.ok || !st.provable {
		t.Errorf("io_uring without the setting: %+v", st)
	}

	// io_uring_disabled reads 2 but the kernel still sets up a ring.
	if err := os.WriteFile(filepath.Join(root, "kernel/io_uring_disabled"), []byte("2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if st := statuses()["kernel.io_uring_off"]; st.ok || !strings.Contains(st.detail, "io_uring_setup in the supervisor: bad address") {
		t.Errorf("setting without effect: %+v", st)
	}
	ioUringSetup = func() error { return syscall.EPERM }

	// A required setting that is missing, or does not hold when read
	// back (/dev/null takes the write and reads back empty).
	if err := os.Remove(filepath.Join(root, "kernel/kptr_restrict")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(os.DevNull, filepath.Join(root, "kernel/dmesg_restrict")+".tmp"); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(root, "kernel/dmesg_restrict")+".tmp", filepath.Join(root, "kernel/dmesg_restrict")); err != nil {
		t.Fatal(err)
	}
	notes := makeSysctls()
	if len(notes) != 2 || !strings.Contains(notes[0], "kernel.kptr_restrict is not set") || !strings.Contains(notes[1], "kernel.dmesg_restrict is not set") {
		t.Fatalf("notes %v", notes)
	}
	st = statuses()
	for _, n := range []string{"kernel.kptr_restrict", "kernel.dmesg_restrict"} {
		if st[n].ok || !st[n].provable {
			t.Errorf("%s: %+v", n, st[n])
		}
	}

	// closeKernel: kernelSet only when every setting and bpf are made.
	ns, bpf := setting(t, "15000\n"), setting(t, "0\n")
	settings(t, ns, bpf)
	s := &Supervisor{cfg: Config{OwnKernel: true}}
	if notes := s.closeKernel(); !withNSMNote(notes, 0) || !s.kernelSet.Load() {
		t.Fatalf("all made: notes %v, set %v", notes, s.kernelSet.Load())
	}
	if err := os.Remove(filepath.Join(procSys, "kernel/randomize_va_space")); err != nil {
		t.Fatal(err)
	}
	s = &Supervisor{cfg: Config{OwnKernel: true}}
	if notes := s.closeKernel(); !withNSMNote(notes, 1) || s.kernelSet.Load() || !s.userNSClosed.Load() {
		t.Fatalf("one missing: notes %v, set %v", notes, s.kernelSet.Load())
	}
	// No unprivileged_bpf_disabled: refused where the kernel has bpf,
	// accepted where it has none (built without the bpf call).
	settings(t, setting(t, "15000\n"), filepath.Join(t.TempDir(), "absent", "bpf"))
	s = &Supervisor{cfg: Config{OwnKernel: true}}
	if notes := s.closeKernel(); !withNSMNote(notes, 1) || s.kernelSet.Load() || !strings.Contains(notes[0], "bpf is not closed") {
		t.Fatalf("bpf: notes %v, set %v", notes, s.kernelSet.Load())
	}
	if unprivilegedBPFDisabled() == nil || !bpfSettingAbsent() {
		t.Error("absent setting with bpf counts as closed")
	}
	bpfCall = func() error { return syscall.ENOSYS }
	s = &Supervisor{cfg: Config{OwnKernel: true}}
	if notes := s.closeKernel(); !withNSMNote(notes, 0) || !s.kernelSet.Load() {
		t.Fatalf("no bpf in the kernel: notes %v, set %v", notes, s.kernelSet.Load())
	}
	if unprivilegedBPFDisabled() != nil {
		t.Error("no bpf in the kernel does not count as closed")
	}
}

const userNSChildEnv = "SUPERVISOR_USERNS_CHILD"

// Exit codes of TestUserNamespaceLimit's child.
const (
	childRefused    = 0
	childCannotTest = 77
	childNotRefused = 3
)

// The child runs as root of a user namespace of its own. The setting it
// writes is that namespace's (each user namespace has its own limit for
// the namespaces below it) and is gone with the child.
func TestUserNamespaceLimitChild(t *testing.T) {
	if os.Getenv(userNSChildEnv) != "1" {
		t.Skip("the child of TestUserNamespaceLimit")
	}
	// Never in the initial user namespace: there the identity mapping
	// covers every id.
	m, err := os.ReadFile("/proc/self/uid_map")
	if f := strings.Fields(string(m)); err != nil || len(f) != 3 || f[2] != "1" || os.Getuid() != 0 {
		fmt.Printf("not in a user namespace of its own: %q %v\n", m, err)
		os.Exit(childCannotTest)
	}
	if got := vaultproc.TryUserNamespace(); got != selftest.UserNamespaceCreated {
		fmt.Printf("before the limit: %s\n", got)
		os.Exit(childCannotTest)
	}
	if err := closeUserNamespaces(); err != nil {
		fmt.Printf("the limit cannot be written here: %v\n", err)
		os.Exit(childCannotTest)
	}
	if got := vaultproc.TryUserNamespace(); got != selftest.UserNamespaceRefused {
		fmt.Printf("after the limit: %s\n", got)
		os.Exit(childNotRefused)
	}
	os.Exit(childRefused)
}

// TestUserNamespaceLimit: on a real kernel, once the limit is 0 a
// process cannot start a process in a new user namespace, and the
// self-test's attempt says so. It runs in a child that is root of its
// own user namespace, where the limit it writes is its own; the
// machine's is not touched, which the test checks. Skipped where this
// machine does not let an unprivileged process have such a namespace.
func TestUserNamespaceLimit(t *testing.T) {
	const real = "/proc/sys/user/max_user_namespaces"
	before, err := os.ReadFile(real)
	if err != nil {
		t.Skip(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run", "^TestUserNamespaceLimitChild$")
	cmd.Env = append(os.Environ(), userNSChildEnv+"=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
	}
	out, err := cmd.CombinedOutput()
	after, _ := os.ReadFile(real)
	if string(after) != string(before) {
		t.Fatalf("the machine's limit changed from %q to %q", before, after)
	}
	var ee *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &ee) && ee.ExitCode() == childCannotTest:
		t.Skipf("cannot be tested on this machine: %s", out)
	case errors.As(err, &ee):
		t.Fatalf("child: %v\n%s", err, out)
	default:
		t.Skipf("no user namespace for the child: %v", err)
	}
}
