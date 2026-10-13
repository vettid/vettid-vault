//go:build linux && (amd64 || arm64)

package seccomp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"os"
	"os/exec"
	"runtime"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

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
	case "exec":
		childExec()
	case "after-exec":
		childAfterExec()
	case "work":
		childWork(program(eperm), false)
	case "work-kill":
		childWork(program(unix.SECCOMP_RET_KILL_PROCESS), false)
	case "work-kill-denied":
		childWork(program(unix.SECCOMP_RET_KILL_PROCESS), true)
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

// names are the probes' names: what the filter must refuse.
func names() []string {
	var n []string
	for _, p := range slices.Concat(probes, archProbes) {
		n = append(n, p.name)
	}
	slices.Sort(n)
	return n
}

// result is one Probe run as a child reports it.
type result map[string]string

func report(p map[string]error) result {
	r := result{}
	for name, err := range p {
		switch {
		case Refused(err):
			r[name] = "refused"
		default:
			r[name] = err.Error()
		}
	}
	return r
}

func (r result) notRefused() []string {
	var bad []string
	for _, n := range names() {
		if r[n] != "refused" {
			bad = append(bad, fmt.Sprintf("%s: %q", n, r[n]))
		}
	}
	if len(r) != len(names()) {
		bad = append(bad, fmt.Sprintf("%d results for %d probes", len(r), len(names())))
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
	emit(out)
	os.Exit(0)
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
	// What this kernel answers without the filter (the test proves the
	// most where that is not "refused").
	for _, n := range names() {
		t.Logf("without the filter: %-18s %s", n, got["before"][n])
	}
}

func childExec() {
	if err := Install(); err != nil {
		os.Exit(exitInstall)
	}
	env := append(slices.DeleteFunc(os.Environ(), func(s string) bool { return strings.HasPrefix(s, childEnv+"=") }), childEnv+"=after-exec")
	_ = syscall.Exec("/proc/self/exe", os.Args[:1], env)
	os.Exit(exitWork)
}

func childAfterExec() {
	nnp, _ := unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
	mode, _ := unix.PrctlRetInt(unix.PR_GET_SECCOMP, 0, 0, 0, 0)
	emit(map[string]any{"probes": report(Probe()), "no_new_privs": nnp, "seccomp_mode": mode})
	os.Exit(0)
}

// TestFilterSurvivesExec: a program the process executes runs under the
// same filter and with no_new_privs.
func TestFilterSurvivesExec(t *testing.T) {
	cmd, out := child(t, "exec")
	if err := cmd.Run(); err != nil {
		t.Fatalf("child: %v\n%s", err, out)
	}
	var got struct {
		Probes      result `json:"probes"`
		NoNewPrivs  int    `json:"no_new_privs"`
		SeccompMode int    `json:"seccomp_mode"`
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if bad := got.Probes.notRefused(); len(bad) != 0 {
		t.Errorf("after exec: not refused: %s", strings.Join(bad, "; "))
	}
	if got.NoNewPrivs != 1 || got.SeccompMode != unix.SECCOMP_MODE_FILTER {
		t.Errorf("after exec: no_new_privs %d, seccomp mode %d", got.NoNewPrivs, got.SeccompMode)
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
func childWork(filter []unix.SockFilter, alsoDenied bool) {
	f := os.NewFile(workFD, "channel")
	c, err := net.FileConn(f)
	f.Close()
	if err != nil {
		os.Exit(exitWork)
	}
	if err := install(filter); err != nil {
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

// run interprets the filter for one call.
func run(t *testing.T, p []unix.SockFilter, arch, nr uint32) uint32 {
	t.Helper()
	var a uint32
	for pc := 0; pc < len(p); pc++ {
		switch in := p[pc]; in.Code {
		case unix.BPF_LD | unix.BPF_W | unix.BPF_ABS:
			switch in.K {
			case offNR:
				a = nr
			case offArch:
				a = arch
			default:
				t.Fatalf("instruction %d loads offset %d", pc, in.K)
			}
		case unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K:
			if a == in.K {
				pc += int(in.Jt)
			} else {
				pc += int(in.Jf)
			}
		case unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K:
			if a >= in.K {
				pc += int(in.Jt)
			} else {
				pc += int(in.Jf)
			}
		case unix.BPF_RET | unix.BPF_K:
			return in.K
		default:
			t.Fatalf("instruction %d: code %#x", pc, in.Code)
		}
	}
	t.Fatal("the filter ends without a return")
	return 0
}

// TestProgram: the filter, interpreted, kills on another architecture,
// refuses exactly the denied numbers (and every x32 number on amd64) and
// allows every other; and the deny list is the reviewed one, with a
// probe for each entry.
func TestProgram(t *testing.T) {
	want := map[string]uint32{
		"socket": unix.SYS_SOCKET, "socketpair": unix.SYS_SOCKETPAIR,
		"io_uring_setup": unix.SYS_IO_URING_SETUP, "io_uring_enter": unix.SYS_IO_URING_ENTER, "io_uring_register": unix.SYS_IO_URING_REGISTER,
		"ptrace": unix.SYS_PTRACE, "process_vm_readv": unix.SYS_PROCESS_VM_READV, "process_vm_writev": unix.SYS_PROCESS_VM_WRITEV,
		"pidfd_getfd": unix.SYS_PIDFD_GETFD,
		"bpf":         unix.SYS_BPF, "userfaultfd": unix.SYS_USERFAULTFD, "perf_event_open": unix.SYS_PERF_EVENT_OPEN,
	}
	if got, w := slices.Sorted(slices.Values(denied)), slices.Sorted(maps.Values(want)); !slices.Equal(got, w) {
		t.Fatalf("denied %v, want %v", got, w)
	}
	probed := map[uint32]bool{}
	for _, p := range probes {
		probed[p.nr] = true
	}
	for name, nr := range want {
		if !probed[nr] {
			t.Errorf("no probe for %s", name)
		}
	}
	if len(probed) != len(denied) {
		t.Errorf("probes for %d numbers, %d denied", len(probed), len(denied))
	}

	p := program(eperm)
	if len(p) > unix.BPF_MAXINSNS {
		t.Fatalf("%d instructions", len(p))
	}
	other := uint32(unix.AUDIT_ARCH_AARCH64)
	compat := uint32(unix.AUDIT_ARCH_I386)
	if runtime.GOARCH == "arm64" {
		other, compat = unix.AUDIT_ARCH_X86_64, unix.AUDIT_ARCH_ARM
	}
	for nr := range uint32(1024) {
		for _, a := range []uint32{other, compat} {
			if got := run(t, p, a, nr); got != unix.SECCOMP_RET_KILL_PROCESS {
				t.Fatalf("architecture %#x, call %d: %#x", a, nr, got)
			}
		}
		w := uint32(unix.SECCOMP_RET_ALLOW)
		if slices.Contains(denied, nr) {
			w = eperm
		}
		if got := run(t, p, arch(), nr); got != w {
			t.Errorf("call %d: %#x, want %#x", nr, got, w)
		}
	}
	// What the Go runtime and standard library call near the denied
	// numbers stays allowed: pidfd_send_signal, pidfd_open, openat2.
	for _, nr := range []uint32{unix.SYS_PIDFD_SEND_SIGNAL, unix.SYS_PIDFD_OPEN, unix.SYS_OPENAT2, unix.SYS_CLONE, unix.SYS_CLONE3, unix.SYS_FUTEX, unix.SYS_MMAP, unix.SYS_SENDMSG, unix.SYS_RECVMSG} {
		if got := run(t, p, arch(), nr); got != unix.SECCOMP_RET_ALLOW {
			t.Errorf("call %d: %#x", nr, got)
		}
	}
	for _, nr := range []uint32{x32Bit, x32Bit | unix.SYS_SOCKET, x32Bit | unix.SYS_READ, 1<<32 - 1} {
		w := uint32(unix.SECCOMP_RET_ALLOW)
		if runtime.GOARCH == "amd64" {
			w = eperm
		}
		if got := run(t, p, arch(), nr); got != w {
			t.Errorf("call %#x: %#x, want %#x", nr, got, w)
		}
	}
}
