//go:build linux && (amd64 || arm64)

package seccomp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/crypto/argon2"
	"golang.org/x/sys/unix"
)

// A filter cannot be removed, so every test that installs one does it in
// a child copy of the test binary: TestMain runs the child's part when
// SECCOMP_CHILD names one.
const childEnv = "SECCOMP_CHILD"

func TestMain(m *testing.M) {
	switch os.Getenv(childEnv) {
	case "":
		os.Exit(m.Run())
	case "probe":
		childProbe()
	case "tsync":
		childTsync()
	case "goprobes":
		childGoProbes()
	case "work":
		childWork(eperm, enosys, false)
	case "work-kill":
		childWork(unix.SECCOMP_RET_KILL_PROCESS, enosys, false)
	case "work-kill-denied":
		childWork(unix.SECCOMP_RET_KILL_PROCESS, enosys, true)
	}
	os.Exit(90)
}

// Exit codes of a child.
const (
	exitInstall = 2
	exitWork    = 3
	exitOutput  = 4
)

func child(t *testing.T, mode string, extra ...*os.File) (*exec.Cmd, *bytes.Buffer) {
	t.Helper()
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), childEnv+"="+mode)
	cmd.ExtraFiles = extra
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = os.Stderr
	return cmd, &out
}

// result is one Probe run as a child reports it.
type result map[string]string

func report(p map[string]error) result {
	r := result{}
	for name, err := range p {
		switch {
		case Refused(name, err):
			r[name] = "refused"
		default:
			r[name] = err.Error()
		}
	}
	return r
}

func (r result) notRefused() []string {
	var bad []string
	for _, n := range Names() {
		if r[n] != "refused" {
			bad = append(bad, fmt.Sprintf("%s: %q", n, r[n]))
		}
	}
	if len(r) != len(Names()) {
		bad = append(bad, fmt.Sprintf("%d results for %d probes", len(r), len(Names())))
	}
	return bad
}

// onNewThread runs f on an OS thread of its own.
func onNewThread(f func()) {
	done := make(chan struct{})
	go func() {
		runtime.LockOSThread() // never unlocked: the thread ends with the goroutine
		f()
		close(done)
	}()
	<-done
}

func emit(v any) {
	if err := json.NewEncoder(os.Stdout).Encode(v); err != nil {
		os.Exit(exitOutput)
	}
}

func childProbe() {
	// A thread that exists before the filter does (TSYNC must reach it).
	start, old := make(chan struct{}), make(chan map[string]error)
	go func() {
		runtime.LockOSThread()
		<-start
		old <- Probe()
	}()
	out := map[string]result{"before": report(Probe())}
	if err := Install(); err != nil {
		os.Exit(exitInstall)
	}
	out["after"] = report(Probe())
	close(start)
	out["earlier_thread"] = report(<-old)
	onNewThread(func() { out["later_thread"] = report(Probe()) })
	// The filter's own prctl rule refuses PR_GET_NO_NEW_PRIVS and
	// PR_GET_SECCOMP: /proc tells.
	st, _ := os.ReadFile("/proc/self/status")
	out["process"] = result{"no_new_privs": statusField(st, "NoNewPrivs"), "seccomp_mode": statusField(st, "Seccomp")}
	emit(out)
	os.Exit(0)
}

func statusField(st []byte, name string) string {
	for _, l := range strings.Split(string(st), "\n") {
		if v, ok := strings.CutPrefix(l, name+":"); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// TestFilter: under the filter every denied call is refused with EPERM,
// on the installing thread, on a thread that existed before and on one
// created after, and the process lives on.
func TestFilter(t *testing.T) {
	cmd, out := child(t, "probe")
	if err := cmd.Run(); err != nil {
		t.Fatalf("child: %v\n%s", err, out)
	}
	var got map[string]result
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	for _, where := range []string{"after", "earlier_thread", "later_thread"} {
		if bad := got[where].notRefused(); len(bad) != 0 {
			t.Errorf("%s: not refused: %s", where, strings.Join(bad, "; "))
		}
	}
	// Without the filter this kernel must answer every probe with
	// something else than the filter's answer: only then does "refused"
	// show the filter. (io_uring_setup is answered ENOSYS by the filter,
	// so that this holds also where kernel.io_uring_disabled is 2 and
	// the kernel itself answers EPERM.)
	for _, n := range Names() {
		t.Logf("without the filter: %-26s %s", n, got["before"][n])
		if a, ok := got["before"][n]; !ok || a == "refused" {
			t.Errorf("without the filter %s answers %q", n, a)
		}
	}
	// The filter is in filter mode with no_new_privs. (The filter's
	// survival across execve is moot: execve is refused.)
	if p := got["process"]; p["no_new_privs"] != "1" || p["seccomp_mode"] != fmt.Sprint(unix.SECCOMP_MODE_FILTER) {
		t.Errorf("process: %v", p)
	}
}

// childGoProbes: under the filter, what the Go runtime and the standard
// library probe or try is answered in a way they handle: starting a
// program fails with an error (pidfd_open refused, then clone without
// CLONE_THREAD refused), finding this process works (os falls back from
// pidfds), random bytes come, a process signal to itself (signal 0)
// goes through; and the process lives on.
func childGoProbes() {
	if err := Install(); err != nil {
		os.Exit(exitInstall)
	}
	out := map[string]string{}
	err := exec.Command("/proc/self/exe").Run()
	out["start_process"] = fmt.Sprint(err)
	if p, err := os.FindProcess(os.Getpid()); err != nil {
		out["find_process"] = err.Error()
	} else {
		out["find_process"] = fmt.Sprint(p.Signal(syscall.Signal(0)))
	}
	b := make([]byte, 32)
	_, err = rand.Read(b)
	out["random"] = fmt.Sprint(err)
	out["kill_self"] = fmt.Sprint(unix.Kill(os.Getpid(), 0))
	out["tgkill_self"] = fmt.Sprint(unix.Tgkill(os.Getpid(), unix.Gettid(), 0))
	out["kill_other"] = fmt.Sprint(unix.Kill(os.Getppid(), 0))
	_, err = unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	out["prctl_get_dumpable"] = fmt.Sprint(err)
	var l unix.Rlimit
	out["getrlimit"] = fmt.Sprint(unix.Getrlimit(unix.RLIMIT_NOFILE, &l))
	out["prlimit_read"] = fmt.Sprint(unix.Prlimit(0, unix.RLIMIT_NOFILE, nil, &l))
	out["prlimit_set"] = fmt.Sprint(unix.Prlimit(0, unix.RLIMIT_NOFILE, &l, nil))
	m, err := unix.Mmap(-1, 0, 4096, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANON)
	out["mmap"] = fmt.Sprint(err)
	if err == nil {
		out["mprotect_none"] = fmt.Sprint(unix.Mprotect(m, unix.PROT_NONE))
		out["mprotect_exec"] = fmt.Sprint(unix.Mprotect(m, unix.PROT_READ|unix.PROT_EXEC))
		_ = unix.Munmap(m)
	}
	_, err = unix.Mmap(-1, 0, 4096, unix.PROT_READ|unix.PROT_EXEC, unix.MAP_PRIVATE|unix.MAP_ANON)
	out["mmap_exec"] = fmt.Sprint(err)
	_, _, errno := unix.Syscall(lastKnown+1, 0, 0, 0)
	out["after_6_6"] = errno.Error()
	_, err = os.ReadFile("/proc/self/status")
	out["read_file"] = fmt.Sprint(err)
	_, err = os.OpenFile("/proc/self/mem", os.O_RDWR, 0)
	out["open_self_mem_rw"] = fmt.Sprint(err)
	_, err = os.Create(filepath.Join(os.Getenv("SECCOMP_TMP"), "created"))
	out["create_file"] = fmt.Sprint(err)
	emit(out)
	os.Exit(0)
}

// TestGoProbes: refused calls fail visibly with errors the caller
// handles, and the calls with argument conditions pass exactly when
// their arguments qualify.
func TestGoProbes(t *testing.T) {
	cmd, out := child(t, "goprobes")
	dir := t.TempDir()
	cmd.Env = append(cmd.Env, "SECCOMP_TMP="+dir)
	if err := cmd.Run(); err != nil {
		t.Fatalf("child: %v\n%s", err, out)
	}
	var got map[string]string
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	ok := "<nil>"
	want := map[string]string{
		"start_process": unix.EPERM.Error(), "find_process": ok, "random": ok, "kill_self": ok, "tgkill_self": ok,
		"kill_other": unix.EPERM.Error(), "prctl_get_dumpable": ok, "getrlimit": ok, "prlimit_read": ok,
		"prlimit_set": unix.EPERM.Error(), "mmap": ok, "mprotect_none": ok, "mprotect_exec": unix.EPERM.Error(),
		"mmap_exec": unix.EPERM.Error(), "after_6_6": unix.ENOSYS.Error(),
		"read_file": ok, "open_self_mem_rw": unix.EPERM.Error(), "create_file": unix.EPERM.Error(),
	}
	for k, w := range want {
		if !strings.Contains(got[k], w) || (w == ok && got[k] != ok) {
			t.Errorf("%s: %q, want %q", k, got[k], w)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "created")); err == nil {
		t.Error("a file was created under the filter")
	}
}

// childTsync gives one thread a filter of its own; the process's filter
// can then not be put on all threads.
func childTsync() {
	ready := make(chan struct{})
	go func() {
		runtime.LockOSThread()
		if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			os.Exit(exitWork)
		}
		f := []unix.SockFilter{{Code: ret, K: unix.SECCOMP_RET_ALLOW}}
		prog := unix.SockFprog{Len: 1, Filter: &f[0]}
		if _, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, 0, uintptr(unsafe.Pointer(&prog))); errno != 0 {
			os.Exit(exitWork)
		}
		close(ready)
		select {} // the thread stays, with its filter
	}()
	<-ready
	out := map[string]any{}
	onNewThread(func() {
		err := Install()
		out["install"] = fmt.Sprint(err)
		out["after"] = report(Probe())
	})
	emit(out)
	os.Exit(0)
}

// TestInstallFailsWithoutAllThreads: when the kernel cannot put the
// filter on every thread it installs none and answers a thread id, not
// an error. Install must report that, or a release build would run a
// vault process without its filter.
func TestInstallFailsWithoutAllThreads(t *testing.T) {
	cmd, out := child(t, "tsync")
	if err := cmd.Run(); err != nil {
		t.Fatalf("child: %v\n%s", err, out)
	}
	var got struct {
		Install string `json:"install"`
		After   result `json:"after"`
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if !strings.Contains(got.Install, "no filter installed") {
		t.Errorf("Install: %s", got.Install)
	}
	// The premise: nothing was installed.
	if got.After["socket_inet"] == "refused" {
		t.Errorf("a filter is in place after all: %v", got.After)
	}
}

// TestRefused: only the filter's answer for the probe counts: EPERM,
// ENOSYS for clone3 and io_uring_setup.
func TestRefused(t *testing.T) {
	for _, err := range []error{unix.EPERM, fmt.Errorf("probe: %w", unix.EPERM)} {
		if !Refused("socket_inet", err) {
			t.Errorf("%v not refused", err)
		}
	}
	for _, n := range []string{"clone3", "io_uring_setup"} {
		if !Refused(n, unix.ENOSYS) || Refused(n, unix.EPERM) {
			t.Errorf("%s: ENOSYS is the answer, EPERM is not", n)
		}
	}
	for _, err := range []error{nil, ErrNotRefused, ErrUnsupported, unix.ENOSYS, unix.EACCES, unix.ESRCH, unix.EBADF, unix.EINVAL, unix.EFAULT, errors.New("operation not permitted")} {
		if Refused("socket_inet", err) {
			t.Errorf("%v refused", err)
		}
	}
	if Refused("no-such-probe", unix.EPERM) {
		t.Error("an unknown probe refused")
	}
}

// workFD is the inherited connection in a "work" child, as a vault
// process's channel is (enclave/vaultproc.ChannelFD).
const workFD = 3

// childWork is a vault process in small: it takes its inherited
// connection, installs the filter, and then does what a vault process
// does to the kernel: serves the connection (with deadlines) from many
// goroutines, runs timers, grows and returns memory (one Argon2id at the
// release's 64 MiB), collects garbage, starts threads, draws random
// bytes, and reads the /proc files and limits the process reads.
func childWork(deny, notFound uint32, alsoDenied bool) {
	f := os.NewFile(workFD, "channel")
	c, err := net.FileConn(f)
	f.Close()
	if err != nil {
		os.Exit(exitWork)
	}
	if err := install(program(uint32(os.Getpid()), deny, notFound)); err != nil {
		os.Exit(exitInstall)
	}
	fail := func(what string, err error) {
		fmt.Fprintf(os.Stderr, "work: %s: %v\n", what, err)
		os.Exit(exitWork)
	}

	// The connection: echo each line back, a deadline on every read.
	echoed := make(chan int)
	go func() {
		buf, n := make([]byte, 4096), 0
		for {
			_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))
			k, err := c.Read(buf)
			if err == io.EOF {
				echoed <- n
				return
			}
			if err != nil {
				fail("read", err)
			}
			_ = c.SetWriteDeadline(time.Now().Add(30 * time.Second))
			if _, err := c.Write(buf[:k]); err != nil {
				fail("write", err)
			}
			n += k
		}
	}()

	var wg sync.WaitGroup
	// Goroutines, timers and contexts.
	for i := range 64 {
		wg.Go(func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(1+i%7)*time.Millisecond)
			defer cancel()
			tick := time.NewTicker(time.Millisecond)
			defer tick.Stop()
			for {
				select {
				case <-tick.C:
					_ = make([]byte, 64<<10)
				case <-ctx.Done():
					return
				}
			}
		})
	}
	// Threads of their own, each blocked in the kernel for a while.
	for range 8 {
		wg.Go(func() {
			onNewThread(func() {
				ts := unix.Timespec{Nsec: 2e6}
				_ = unix.Nanosleep(&ts, nil)
			})
		})
	}
	// Memory: an unlock's Argon2id, then garbage collection and the
	// return of the memory to the kernel.
	wg.Go(func() {
		salt := make([]byte, 16)
		if _, err := rand.Read(salt); err != nil {
			fail("random bytes", err)
		}
		_ = argon2.IDKey([]byte("not-a-pin"), salt, 1, 64<<10, 1, 32)
		runtime.GC()
		debug.FreeOSMemory()
	})
	// The files, limits and process settings a vault process reads.
	wg.Go(func() {
		if b, err := os.ReadFile("/proc/self/status"); err != nil || !bytes.Contains(b, []byte("Seccomp:\t2")) {
			fail("/proc/self/status", fmt.Errorf("%v (or not in filter mode)", err))
		}
		if _, err := os.ReadDir("/proc/self/fd"); err != nil {
			fail("/proc/self/fd", err)
		}
		if _, err := os.ReadFile("/proc/meminfo"); err != nil {
			fail("/proc/meminfo", err)
		}
		var l unix.Rlimit
		var ru unix.Rusage
		if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &l); err != nil {
			fail("getrlimit", err)
		}
		if err := unix.Getrusage(unix.RUSAGE_SELF, &ru); err != nil {
			fail("getrusage", err)
		}
		if _, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0); err != nil {
			fail("prctl", err)
		}
		_ = os.Getpid() + os.Getuid() + len(os.Environ())
	})
	wg.Wait()
	n := <-echoed
	if alsoDenied {
		// The control of TestWorkload's strict run: one denied call.
		_, _ = unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	}
	emit(map[string]int{"echoed": n})
	os.Exit(0)
}

func runWork(t *testing.T, mode string) (*bytes.Buffer, error) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	theirs := os.NewFile(uintptr(fds[1]), "theirs")
	mine := os.NewFile(uintptr(fds[0]), "mine")
	conn, err := net.FileConn(mine)
	mine.Close()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cmd, out := child(t, mode, theirs)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	theirs.Close()
	_ = conn.SetDeadline(time.Now().Add(60 * time.Second))
	msg, back := bytes.Repeat([]byte("frame "), 100), make([]byte, 600)
	for i := range 200 {
		if _, err := conn.Write(msg); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		if _, err := io.ReadFull(conn, back); err != nil || !bytes.Equal(back, msg) {
			t.Fatalf("echo %d: %v", i, err)
		}
	}
	if err := conn.(*net.UnixConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	return out, cmd.Wait()
}

// TestWorkload: a vault-like workload runs under the filter. It also
// runs under a strict copy of the filter that kills the process on a
// denied call instead of refusing it, which shows that the workload (the
// Go runtime's own calls among it) makes none of them; the control shows
// that the strict copy does kill.
func TestWorkload(t *testing.T) {
	for _, mode := range []string{"work", "work-kill"} {
		out, err := runWork(t, mode)
		if err != nil {
			t.Fatalf("%s: %v\n%s", mode, err, out)
		}
		var got map[string]int
		if err := json.Unmarshal(out.Bytes(), &got); err != nil || got["echoed"] != 200*600 {
			t.Fatalf("%s: %v: %s", mode, err, out)
		}
	}
	_, err := runWork(t, "work-kill-denied")
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("control: %v", err)
	}
	if ws, ok := ee.Sys().(syscall.WaitStatus); !ok || !ws.Signaled() || ws.Signal() != syscall.SIGSYS {
		t.Fatalf("control: %v, want SIGSYS", err)
	}
}

// run interprets the filter for one call with its arguments.
func run(t *testing.T, p []unix.SockFilter, arch, nr uint32, args ...uint64) uint32 {
	t.Helper()
	var data [64]byte
	binary.LittleEndian.PutUint32(data[offNR:], nr)
	binary.LittleEndian.PutUint32(data[offArch:], arch)
	for i, v := range args {
		binary.LittleEndian.PutUint64(data[offArgs+8*i:], v)
	}
	var a uint32
	for pc := 0; pc < len(p); pc++ {
		switch in := p[pc]; in.Code {
		case ldW:
			if in.K%4 != 0 || in.K >= offArgs+48 || (in.K > offArch && in.K < offArgs) {
				t.Fatalf("instruction %d loads offset %d", pc, in.K)
			}
			a = binary.LittleEndian.Uint32(data[in.K:])
		case jeq, jgt, jge, jset:
			var c bool
			switch in.Code {
			case jeq:
				c = a == in.K
			case jgt:
				c = a > in.K
			case jge:
				c = a >= in.K
			case jset:
				c = a&in.K != 0
			}
			if c {
				pc += int(in.Jt)
			} else {
				pc += int(in.Jf)
			}
		case ret:
			return in.K
		default:
			t.Fatalf("instruction %d: code %#x", pc, in.Code)
		}
	}
	t.Fatal("the filter ends without a return")
	return 0
}

// reviewed is the allow list by name, as reviewed: a change to the list
// must change this too.
var reviewed = map[string]uint32{
	"futex": unix.SYS_FUTEX, "nanosleep": unix.SYS_NANOSLEEP, "epoll_pwait": unix.SYS_EPOLL_PWAIT, "read": unix.SYS_READ,
	"write": unix.SYS_WRITE, "getpid": unix.SYS_GETPID, "rt_sigreturn": unix.SYS_RT_SIGRETURN, "fcntl": unix.SYS_FCNTL,
	"sched_yield": unix.SYS_SCHED_YIELD, "close": unix.SYS_CLOSE, "epoll_ctl": unix.SYS_EPOLL_CTL,
	"madvise": unix.SYS_MADVISE, "rt_sigprocmask": unix.SYS_RT_SIGPROCMASK, "rt_sigaction": unix.SYS_RT_SIGACTION,
	"getrandom": unix.SYS_GETRANDOM, "gettid": unix.SYS_GETTID, "sigaltstack": unix.SYS_SIGALTSTACK,
	"getrusage": unix.SYS_GETRUSAGE, "getdents64": unix.SYS_GETDENTS64, "getrlimit": unix.SYS_GETRLIMIT,
	"munmap": unix.SYS_MUNMAP, "restart_syscall": unix.SYS_RESTART_SYSCALL, "clock_gettime": unix.SYS_CLOCK_GETTIME,
	"clock_getres": unix.SYS_CLOCK_GETRES, "gettimeofday": unix.SYS_GETTIMEOFDAY, "sched_getaffinity": unix.SYS_SCHED_GETAFFINITY,
	"pread64": unix.SYS_PREAD64, "fstat": unix.SYS_FSTAT, "newfstatat": unix.SYS_NEWFSTATAT, "lseek": unix.SYS_LSEEK,
	"getuid": unix.SYS_GETUID, "geteuid": unix.SYS_GETEUID, "getgid": unix.SYS_GETGID, "getegid": unix.SYS_GETEGID,
	"getppid": unix.SYS_GETPPID, "epoll_create1": unix.SYS_EPOLL_CREATE1, "eventfd2": unix.SYS_EVENTFD2,
	"exit": unix.SYS_EXIT, "exit_group": unix.SYS_EXIT_GROUP, "rseq": unix.SYS_RSEQ, "set_robust_list": unix.SYS_SET_ROBUST_LIST,
}

var reviewedConditional = map[string]uint32{
	"openat": unix.SYS_OPENAT, "clone": unix.SYS_CLONE, "tgkill": unix.SYS_TGKILL, "kill": unix.SYS_KILL, "mmap": unix.SYS_MMAP,
	"mprotect": unix.SYS_MPROTECT, "prctl": unix.SYS_PRCTL, "prlimit64": unix.SYS_PRLIMIT64,
}

// TestProgram: the filter, interpreted, kills on another architecture;
// passes exactly the reviewed calls, the conditional ones only with
// qualifying arguments; answers ENOSYS for clone3, io_uring_setup and
// every number above Linux 6.6's last; refuses every other number (and
// every x32 number on amd64) with EPERM; and answers every probe as
// Refused expects.
func TestProgram(t *testing.T) {
	if got, w := slices.Sorted(slices.Values(allowed)), slices.Sorted(maps.Values(reviewed)); !slices.Equal(got, w) {
		t.Fatalf("allowed %v, want %v", got, w)
	}
	if got, w := slices.Sorted(slices.Values(conditional)), slices.Sorted(maps.Values(reviewedConditional)); !slices.Equal(got, w) {
		t.Fatalf("conditional %v, want %v", got, w)
	}
	if n := Allowed(); n != len(reviewed)+len(reviewedConditional) || len(slices.Compact(slices.Sorted(slices.Values(slices.Concat(allowed, conditional))))) != n {
		t.Fatalf("Allowed %d", n)
	}
	t.Logf("%s: %d calls allowed (%d with conditions on their arguments)", runtime.GOARCH, Allowed(), len(conditional))

	const pid = 4242
	p := program(pid, eperm, enosys)
	if len(p) > 128 {
		t.Fatalf("%d instructions", len(p))
	}
	other := uint32(unix.AUDIT_ARCH_AARCH64)
	compat := uint32(unix.AUDIT_ARCH_I386)
	if runtime.GOARCH == "arm64" {
		other, compat = unix.AUDIT_ARCH_X86_64, unix.AUDIT_ARCH_ARM
	}
	amd64 := runtime.GOARCH == "amd64"
	allow := uint32(unix.SECCOMP_RET_ALLOW)
	for nr := range uint32(1024) {
		for _, a := range []uint32{other, compat} {
			if got := run(t, p, a, nr); got != unix.SECCOMP_RET_KILL_PROCESS {
				t.Fatalf("architecture %#x, call %d: %#x", a, nr, got)
			}
		}
		// No arguments: of the conditional calls, openat (read-only),
		// mmap, mprotect (no PROT_EXEC) and prlimit64 (pid 0, no new
		// limit) qualify.
		w := eperm
		switch {
		case slices.Contains(allowed, nr), nr == unix.SYS_OPENAT, nr == unix.SYS_MMAP, nr == unix.SYS_MPROTECT, nr == unix.SYS_PRLIMIT64:
			w = allow
		case amd64 && nr >= x32First && nr <= x32Last:
			w = eperm
		case nr == unix.SYS_CLONE3, nr == unix.SYS_IO_URING_SETUP, nr > lastKnown:
			w = enosys
		}
		if got := run(t, p, arch(), nr); got != w {
			t.Errorf("call %d: %#x, want %#x", nr, got, w)
		}
	}
	for _, nr := range []uint32{x32Bit, x32Bit | unix.SYS_SOCKET, x32Bit | unix.SYS_READ, 1<<32 - 1} {
		w := enosys
		if amd64 {
			w = eperm
		}
		if got := run(t, p, arch(), nr); got != w {
			t.Errorf("call %#x: %#x, want %#x", nr, got, w)
		}
	}

	// The argument conditions.
	const at = 1<<32 - 100 // AT_FDCWD as the kernel reads an int
	thread := uint64(unix.CLONE_VM | unix.CLONE_FS | unix.CLONE_FILES | unix.CLONE_SIGHAND | unix.CLONE_THREAD | unix.CLONE_SYSVSEM | unix.CLONE_SETTLS)
	glibc := thread | unix.CLONE_PARENT_SETTID | unix.CLONE_CHILD_CLEARTID
	for _, c := range []struct {
		name string
		nr   uint32
		args []uint64
		want uint32
	}{
		{"openat read", unix.SYS_OPENAT, []uint64{at, 1 << 20, unix.O_RDONLY | unix.O_CLOEXEC}, allow},
		{"openat directory", unix.SYS_OPENAT, []uint64{at, 1 << 20, unix.O_RDONLY | unix.O_CLOEXEC | unix.O_DIRECTORY | unix.O_NONBLOCK}, allow},
		{"openat write", unix.SYS_OPENAT, []uint64{at, 1 << 20, unix.O_WRONLY}, eperm},
		{"openat read-write (/proc/self/mem)", unix.SYS_OPENAT, []uint64{at, 1 << 20, unix.O_RDWR | unix.O_CLOEXEC}, eperm},
		{"openat create", unix.SYS_OPENAT, []uint64{at, 1 << 20, unix.O_RDONLY | unix.O_CREAT, 0o600}, eperm},
		{"openat truncate", unix.SYS_OPENAT, []uint64{at, 1 << 20, unix.O_RDONLY | unix.O_TRUNC}, eperm},
		{"openat tmpfile", unix.SYS_OPENAT, []uint64{at, 1 << 20, unix.O_TMPFILE | unix.O_RDWR, 0o600}, eperm},
		{"openat invalid access mode 3", unix.SYS_OPENAT, []uint64{at, 1 << 20, 3}, eperm},
		{"openat2", unix.SYS_OPENAT2, []uint64{at, 1 << 20, 1 << 21, 24}, eperm},
		{"go thread", unix.SYS_CLONE, []uint64{thread}, allow},
		{"glibc thread", unix.SYS_CLONE, []uint64{glibc}, allow},
		{"thread, high bits", unix.SYS_CLONE, []uint64{thread | 1<<40}, allow},
		{"fork", unix.SYS_CLONE, []uint64{uint64(unix.SIGCHLD)}, eperm},
		{"vfork", unix.SYS_CLONE, []uint64{unix.CLONE_VM | unix.CLONE_VFORK | uint64(unix.SIGCHLD)}, eperm},
		{"new user namespace", unix.SYS_CLONE, []uint64{unix.CLONE_NEWUSER | uint64(unix.SIGCHLD)}, eperm},
		{"thread in a new network namespace", unix.SYS_CLONE, []uint64{thread | unix.CLONE_NEWNET}, eperm},
		{"thread in a new pid namespace", unix.SYS_CLONE, []uint64{thread | unix.CLONE_NEWPID}, eperm},
		{"kill self", unix.SYS_KILL, []uint64{pid, 9}, allow},
		{"kill other", unix.SYS_KILL, []uint64{pid + 1, 9}, eperm},
		{"kill group", unix.SYS_KILL, []uint64{0, 9}, eperm},
		{"kill everyone", unix.SYS_KILL, []uint64{1<<64 - 1, 9}, eperm},
		{"tgkill self", unix.SYS_TGKILL, []uint64{pid, pid + 3, 23}, allow},
		{"tgkill other", unix.SYS_TGKILL, []uint64{pid + 1, pid + 1, 23}, eperm},
		{"mmap rw", unix.SYS_MMAP, []uint64{0, 4096, unix.PROT_READ | unix.PROT_WRITE, unix.MAP_PRIVATE | unix.MAP_ANON}, allow},
		{"mmap exec", unix.SYS_MMAP, []uint64{0, 4096, unix.PROT_READ | unix.PROT_EXEC, unix.MAP_PRIVATE | unix.MAP_ANON}, eperm},
		{"mprotect none", unix.SYS_MPROTECT, []uint64{1 << 20, 4096, unix.PROT_NONE}, allow},
		{"mprotect exec", unix.SYS_MPROTECT, []uint64{1 << 20, 4096, unix.PROT_EXEC}, eperm},
		{"prctl get dumpable", unix.SYS_PRCTL, []uint64{unix.PR_GET_DUMPABLE}, allow},
		{"prctl name memory", unix.SYS_PRCTL, []uint64{unix.PR_SET_VMA, unix.PR_SET_VMA_ANON_NAME, 1 << 20, 4096, 1 << 21}, allow},
		{"prctl set dumpable", unix.SYS_PRCTL, []uint64{unix.PR_SET_DUMPABLE, 1}, eperm},
		{"prctl seccomp", unix.SYS_PRCTL, []uint64{unix.PR_SET_SECCOMP, 2}, eperm},
		{"prctl no_new_privs", unix.SYS_PRCTL, []uint64{unix.PR_SET_NO_NEW_PRIVS, 1}, eperm},
		{"prlimit read", unix.SYS_PRLIMIT64, []uint64{0, unix.RLIMIT_NOFILE, 0, 1 << 20}, allow},
		{"prlimit set", unix.SYS_PRLIMIT64, []uint64{0, unix.RLIMIT_NOFILE, 1 << 20, 0}, eperm},
		{"prlimit set, high address", unix.SYS_PRLIMIT64, []uint64{0, unix.RLIMIT_NOFILE, 1 << 40, 0}, eperm},
		{"prlimit of another", unix.SYS_PRLIMIT64, []uint64{pid + 1, unix.RLIMIT_NOFILE, 0, 1 << 20}, eperm},
	} {
		if got := run(t, p, arch(), c.nr, c.args...); got != c.want {
			t.Errorf("%s: %#x, want %#x", c.name, got, c.want)
		}
	}

	// amd64's legacy open and creat are not allowed (2 and 85; arm64 has
	// neither).
	if amd64 {
		for _, nr := range []uint32{2, 85} {
			if got := run(t, p, arch(), nr, 1<<20, unix.O_RDONLY); got != eperm {
				t.Errorf("legacy call %d: %#x", nr, got)
			}
		}
	}

	// Every probe, with its arguments, gets the answer Refused expects;
	// the 13 calls of the earlier deny list are among them.
	for _, pr := range slices.Concat(probes, archProbes) {
		args := make([]uint64, 6)
		for i, v := range pr.a {
			args[i] = uint64(v)
		}
		if got, w := run(t, p, arch(), pr.nr, args...), unix.SECCOMP_RET_ERRNO|uint32(pr.want()); got != w {
			t.Errorf("probe %s: %#x, want %#x", pr.name, got, w)
		}
	}
	for _, n := range []string{"socket_vsock", "socket_inet", "socketpair", "io_uring_setup", "io_uring_enter", "io_uring_register",
		"ptrace", "process_vm_readv", "process_vm_writev", "pidfd_getfd", "bpf", "userfaultfd", "perf_event_open"} {
		if !slices.Contains(Names(), n) {
			t.Errorf("no probe %s", n)
		}
	}
	if len(Names()) != len(slices.Compact(Names())) {
		t.Error("two probes of one name")
	}
}
