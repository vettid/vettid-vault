//go:build linux

package supervisor

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// procSys is where the kernel's settings are (a variable for the tests,
// which must not write the real ones).
var procSys = "/proc/sys"

// ioUringSetup makes an io_uring_setup call with no parameters and
// returns its error (a variable for the tests). In the supervisor, which
// has no filter, it shows what the kernel itself answers: EPERM where
// kernel.io_uring_disabled is 2, ENOSYS where the kernel has no io_uring
// (4.14), EFAULT where io_uring is open.
var ioUringSetup = func() error {
	r, _, errno := unix.Syscall(unix.SYS_IO_URING_SETUP, 0, 0, 0)
	if errno == 0 {
		unix.Close(int(r))
		return nil
	}
	return errno
}

// A sysctl is one kernel setting the supervisor makes on its own kernel
// (Config.OwnKernel), for the whole machine, before any vault process
// starts. Each one closes an interface that a vault process (or a
// process that got out of one) could use against the kernel or the
// other vaults, and none is used by the enclave.
type sysctl struct {
	check string // the self-test check: kernel.<check>
	path  string // under procSys
	value string // written, and expected when read back
	// absent says what holds where the kernel has no such file (an older
	// kernel, or a feature not built in): ok, and why. Nil: the file must
	// exist (every kernel the release can run has it).
	absent func() (ok bool, why string)
}

func notBuilt(what string) func() (bool, string) {
	return func() (bool, string) { return true, what }
}

// sysctls are the settings, in the order they are made.
var sysctls = []sysctl{
	// io_uring makes sockets and every other kind of I/O without the
	// system calls the vault filter refuses. 2: no process may set up a
	// ring, root included. Linux 6.6 has the setting; where it is absent
	// only a kernel without io_uring is accepted (4.14), which the call
	// itself shows.
	{check: "io_uring_off", path: "kernel/io_uring_disabled", value: "2", absent: func() (bool, string) {
		err := ioUringSetup()
		if errors.Is(err, unix.ENOSYS) {
			return true, "no io_uring in this kernel (io_uring_setup: ENOSYS)"
		}
		return false, "io_uring without io_uring_disabled (io_uring_setup: " + errOrNil(err) + ")"
	}},
	// Kernel addresses are hidden from everyone (2: also from root), and
	// the kernel log from unprivileged processes: both help an exploit.
	{check: "kptr_restrict", path: "kernel/kptr_restrict", value: "2"},
	{check: "dmesg_restrict", path: "kernel/dmesg_restrict", value: "1"},
	// No performance events for unprivileged processes (2 upstream; 3,
	// "none at all", where a kernel has that level).
	{check: "perf_event_paranoid", path: "kernel/perf_event_paranoid", value: "3", absent: notBuilt("no performance events in this kernel")},
	{check: "sysrq_off", path: "kernel/sysrq", value: "0", absent: notBuilt("no magic SysRq in this kernel")},
	// No other kernel can be loaded (one-way).
	{check: "kexec_load_disabled", path: "kernel/kexec_load_disabled", value: "1", absent: notBuilt("no kexec in this kernel")},
	// No module can be loaded or removed from now on (one-way; the
	// enclave's init has loaded the NSM driver before the supervisor
	// starts, and nothing loads one later).
	{check: "modules_disabled", path: "kernel/modules_disabled", value: "1", absent: notBuilt("no loadable modules in this kernel")},
	{check: "randomize_va_space", path: "kernel/randomize_va_space", value: "2"},
	// userfaultfd lets a process stall the kernel at a chosen point of a
	// copy; unprivileged use is off by default since 5.11 (the setting
	// exists from 5.2). The vault filter refuses the call as well.
	{check: "unprivileged_userfaultfd_off", path: "vm/unprivileged_userfaultfd", value: "0",
		absent: notBuilt("before Linux 5.2 there is no such setting; the vault filter refuses userfaultfd")},
	// No input pushed into a terminal (6.2+). Vault processes have no
	// terminal, and the filter refuses ioctl.
	{check: "legacy_tiocsti_off", path: "dev/tty/legacy_tiocsti", value: "0",
		absent: notBuilt("before Linux 6.2 there is no such setting; vault processes have no terminal and the filter refuses ioctl")},
	// Links, FIFOs and files in shared sticky directories (/tmp) are
	// followed or opened only where their owner matches.
	{check: "protected_symlinks", path: "fs/protected_symlinks", value: "1"},
	{check: "protected_hardlinks", path: "fs/protected_hardlinks", value: "1"},
	{check: "protected_fifos", path: "fs/protected_fifos", value: "2", absent: notBuilt("before Linux 4.19 there is no such setting")},
	{check: "protected_regular", path: "fs/protected_regular", value: "2", absent: notBuilt("before Linux 4.19 there is no such setting")},
}

func errOrNil(err error) string {
	if err == nil {
		return "no error"
	}
	return err.Error()
}

// set writes the setting and reads it back. An absent file is accepted
// only where absent says so.
func (c sysctl) set() error {
	p := filepath.Join(procSys, c.path)
	if _, err := os.Stat(p); errors.Is(err, fs.ErrNotExist) {
		if c.absent == nil {
			return err
		}
		if ok, why := c.absent(); !ok {
			return errors.New(why)
		}
		return nil
	}
	if err := os.WriteFile(p, []byte(c.value+"\n"), 0); err != nil {
		return err
	}
	return c.made()
}

// made reports whether the setting reads back as written.
func (c sysctl) made() error {
	v, err := readSetting(filepath.Join(procSys, c.path))
	if err != nil {
		return err
	}
	if v != c.value {
		return fmt.Errorf("%s is %q, not %s", c.path, v, c.value)
	}
	return nil
}

// status is the self-test's view of the setting: whether it holds,
// whether that is required (the file is there, or its absence is a
// proof), and what was found.
func (c sysctl) status() (ok, provable bool, detail string) {
	p := filepath.Join(procSys, c.path)
	if _, err := os.Stat(p); errors.Is(err, fs.ErrNotExist) && c.absent != nil {
		ok, why := c.absent()
		// io_uring's absence is shown by the call; the others are
		// informational where the kernel has no such setting.
		return ok, c.check == "io_uring_off", "absent: " + why
	}
	err := c.made()
	if err != nil {
		return false, true, err.Error()
	}
	detail = c.path + " = " + c.value
	if c.check == "io_uring_off" {
		// Where the setting is 2 the kernel refuses even the
		// supervisor, which has no filter.
		e := ioUringSetup()
		detail += "; io_uring_setup in the supervisor: " + errOrNil(e)
		if !errors.Is(e, unix.EPERM) {
			return false, true, detail
		}
	}
	return true, true, detail
}

// makeSysctls makes every setting and returns one note for each that
// could not be made.
func makeSysctls() []string {
	var notes []string
	for _, c := range sysctls {
		if err := c.set(); err != nil {
			notes = append(notes, fmt.Sprintf("kernel.%s is not set, no vault process will be started: %v", c.check, err))
		}
	}
	return notes
}

// sysctlStatus is one setting's self-test check.
type sysctlStatus struct {
	check, detail string
	ok, provable  bool
}

func sysctlStatuses() []sysctlStatus {
	var out []sysctlStatus
	for _, c := range sysctls {
		ok, provable, detail := c.status()
		out = append(out, sysctlStatus{check: "kernel." + c.check, detail: detail, ok: ok, provable: provable})
	}
	return out
}

// The /proc mount (variables for the tests).
var (
	procMountinfo = "/proc/self/mountinfo"
	// remountProc remounts /proc with hidepid=2, keeping its mount flags.
	remountProc = func() error {
		var st unix.Statfs_t
		if err := unix.Statfs("/proc", &st); err != nil {
			return err
		}
		keep := uintptr(st.Flags) & (unix.ST_RDONLY | unix.ST_NOSUID | unix.ST_NODEV | unix.ST_NOEXEC)
		return unix.Mount("proc", "/proc", "proc", unix.MS_REMOUNT|keep, "hidepid=2")
	}
)

// hideProcesses remounts /proc so that a process sees only its own
// processes' entries (hidepid=2, "invisible" from 5.8): a vault process
// then cannot read another vault's or the supervisor's /proc/<pid>
// (uids, command lines, CPU times) or even learn their pids. The
// supervisor, root, still sees every process (it sweeps them). Reads of
// /proc/self and /proc/meminfo are unaffected.
func hideProcesses() error {
	if err := remountProc(); err != nil {
		return err
	}
	return processesHidden()
}

// processesHidden reports whether /proc is mounted with hidepid=2.
func processesHidden() error {
	b, err := os.ReadFile(procMountinfo)
	if err != nil {
		return err
	}
	// The last proc mount on /proc is the visible one (a later mount
	// covers the earlier).
	opts := ""
	for _, line := range strings.Split(string(b), "\n") {
		// id parent major:minor root mountpoint options [optional...] - type source super-options
		pre, post, ok := strings.Cut(line, " - ")
		f, g := strings.Fields(pre), strings.Fields(post)
		if ok && len(f) >= 5 && len(g) >= 3 && f[4] == "/proc" && g[0] == "proc" {
			opts = g[2]
		}
	}
	if opts == "" {
		return errors.New("/proc is not mounted")
	}
	for _, o := range strings.Split(opts, ",") {
		if o == "hidepid=2" || o == "hidepid=invisible" {
			return nil
		}
	}
	return fmt.Errorf("/proc is mounted with %s", opts)
}
