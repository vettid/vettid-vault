//go:build linux

package supervisor

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Every vault process gets a uid of its own: the counter only grows, is
// shared by every process host of the supervisor, and refuses to start a
// process once it has run out.
func TestTakeUID(t *testing.T) {
	s := &Supervisor{}
	for want := 200000; want < 200003; want++ {
		if got, err := s.takeUID(200000); err != nil || got != want {
			t.Fatalf("uid %d %v, want %d", got, err, want)
		}
	}
	// Another process host (the self-test's, the capacity test's) draws
	// from the same counter.
	h1, h2 := newProcHost(s, ProcConfig{UIDBase: 200000}), newProcHost(s, ProcConfig{UIDBase: 200000})
	a, _ := h1.s.takeUID(h1.cfg.UIDBase)
	b, _ := h2.s.takeUID(h2.cfg.UIDBase)
	if a != 200003 || b != 200004 {
		t.Fatalf("uids %d %d", a, b)
	}
	if _, err := s.takeUID(0); !errors.Is(err, errNoUID) {
		t.Fatalf("base 0: %v", err)
	}
	// The last uid there is, then none.
	s = &Supervisor{}
	s.uidNext.Store(maxVaultUID - 200000)
	if got, err := s.takeUID(200000); err != nil || got != maxVaultUID {
		t.Fatalf("last uid %d %v", got, err)
	}
	for range 2 {
		if _, err := s.takeUID(200000); !errors.Is(err, errNoUID) {
			t.Fatalf("after the last uid: %v", err)
		}
	}
}

// A uid goes into the process's credentials as uid and gid, with no
// supplementary groups; without one the supervisor's ids are kept.
func TestProcAttrUID(t *testing.T) {
	a := procAttr(200007)
	if c := a.Credential; c == nil || c.Uid != 200007 || c.Gid != 200007 || c.Groups == nil || len(c.Groups) != 0 {
		t.Fatalf("credential %+v", a.Credential)
	}
	if !a.Setpgid || a.Pdeathsig != syscall.SIGKILL {
		t.Fatalf("attributes %+v", a)
	}
	if procAttr(0).Credential != nil {
		t.Fatal("credential without a uid")
	}
}

// fakeProcEntry writes a process into a fake /proc: its uids and the states
// of its threads.
func fakeProcEntry(t *testing.T, root string, pid int, uids string, states ...byte) {
	t.Helper()
	dir := filepath.Join(root, strconv.Itoa(pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	status := fmt.Sprintf("Name:\tx\nState:\tS (sleeping)\nPid:\t%d\nUid:\t%s\nGid:\t1\t1\t1\t1\n", pid, uids)
	if err := os.WriteFile(filepath.Join(dir, "status"), []byte(status), 0o644); err != nil {
		t.Fatal(err)
	}
	for i, st := range states {
		td := filepath.Join(dir, "task", strconv.Itoa(pid+i))
		if err := os.MkdirAll(td, 0o755); err != nil {
			t.Fatal(err)
		}
		stat := fmt.Sprintf("%d (a) b) c) %c 1 2 3", pid+i, st)
		if err := os.WriteFile(filepath.Join(td, "stat"), []byte(stat), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func fakeSweep(t *testing.T, rounds int, kill func(uid int) error) string {
	t.Helper()
	root := t.TempDir()
	oldRoot, oldKill, oldPause, oldRounds := procRoot, killAll, sweepPause, sweepRounds
	t.Cleanup(func() { procRoot, killAll, sweepPause, sweepRounds = oldRoot, oldKill, oldPause, oldRounds })
	procRoot, killAll, sweepPause, sweepRounds = root, kill, 0, rounds
	// The supervisor's own entry, as in a real /proc.
	if err := os.MkdirAll(filepath.Join(root, "self"), 0o755); err != nil {
		t.Fatal(err)
	}
	return root
}

// removeUID plays kill(-1) under uid in a fake /proc: every process with
// uid among its uids goes.
func removeUID(t *testing.T, root string, uid int) {
	t.Helper()
	ents, _ := os.ReadDir(root)
	for _, e := range ents {
		if pid, err := strconv.Atoi(e.Name()); err == nil && hasUID(pid, uid) {
			_ = os.RemoveAll(filepath.Join(root, e.Name()))
		}
	}
}

// The sweep kills the uid as a whole until /proc shows none of its
// processes running (by any of the four uids), including one that
// appeared meanwhile; zombies do not count, and other uids are never
// named.
func TestSweepUID(t *testing.T) {
	var root string
	kills := 0
	root = fakeSweep(t, 50, func(uid int) error {
		if uid != 200001 {
			t.Errorf("kill for uid %d", uid)
		}
		kills++
		removeUID(t, root, uid)
		if kills == 1 {
			// A child started just before the kill.
			fakeProcEntry(t, root, 300, "200001\t200001\t200001\t200001", 'R')
		}
		return nil
	})
	fakeProcEntry(t, root, 100, "200001\t200001\t200001\t200001", 'S')
	fakeProcEntry(t, root, 101, "5\t5\t200001\t5", 'Z', 'R') // first thread gone, another runs
	fakeProcEntry(t, root, 104, "200002\t200002\t200002\t200002", 'S')
	fakeProcEntry(t, root, 105, "2000010\t2000010\t2000010\t2000010", 'S')
	_ = os.WriteFile(filepath.Join(root, "106"), nil, 0o644)

	if got, err := liveProcessesOf(200001); err != nil || !slices.Equal(got, []int{100, 101}) {
		t.Fatalf("live %v %v", got, err)
	}
	if err := sweepUID(200001); err != nil {
		t.Fatal(err)
	}
	if kills != 2 {
		t.Fatalf("%d kills", kills)
	}
	for _, pid := range []int{104, 105} {
		if _, err := os.Stat(filepath.Join(root, strconv.Itoa(pid))); err != nil {
			t.Errorf("%d: %v", pid, err)
		}
	}
	// Only zombies of the uid left: nothing to do.
	fakeProcEntry(t, root, 103, "200001\t200001\t200001\t200001", 'Z')
	kills = 0
	if err := sweepUID(200001); err != nil || kills != 0 {
		t.Fatalf("zombie: %v, %d kills", err, kills)
	}
}

// The sweep fails secure: processes that do not go, a kill that fails,
// and a /proc that cannot be read or lists nothing are errors, never
// "none left".
func TestSweepUIDFails(t *testing.T) {
	kills := 0
	root := fakeSweep(t, 3, func(int) error { kills++; return nil })
	fakeProcEntry(t, root, 100, "200001\t200001\t200001\t200001", 'D')
	if err := sweepUID(200001); err == nil || !strings.Contains(err.Error(), "1 processes of uid 200001") {
		t.Fatalf("err %v", err)
	}
	if kills != 3 {
		t.Fatalf("%d kills", kills)
	}
	killAll = func(int) error { return errors.New("kill failed") }
	if err := sweepUID(200001); err == nil {
		t.Fatal("a failed kill counts as swept")
	}
	procRoot = filepath.Join(root, "absent")
	if err := sweepUID(200001); err == nil {
		t.Fatal("an unreadable /proc counts as swept")
	}
	procRoot = t.TempDir() // not a /proc: no entry of the supervisor's
	if err := sweepUID(200001); err == nil {
		t.Fatal("an empty /proc counts as swept")
	}
}

// A failed sweep holds back only that vault's next process, until a
// sweep of the uid succeeds.
func TestSweepPendingHoldsTheVault(t *testing.T) {
	var root string
	stuck := true
	root = fakeSweep(t, 2, func(uid int) error {
		if !stuck {
			removeUID(t, root, uid)
		}
		return nil
	})
	fakeProcEntry(t, root, 100, "200001\t200001\t200001\t200001", 'S')
	s := &Supervisor{log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	s.sweepAfter("vault-a", 200001)
	if s.sweepPending("vault-a") {
		t.Fatal("vault-a may start while its last process's child runs")
	}
	if !s.sweepPending("vault-b") {
		t.Fatal("another vault is held back")
	}
	h := newProcHost(s, ProcConfig{Exec: []string{filepath.Join(t.TempDir(), "no-such-program")}, MaxProcs: 1})
	if _, err := h.spawn("vault-a", "user", false); !errors.Is(err, errSpawn) {
		t.Fatalf("spawn of the held vault: %v", err)
	}
	stuck = false
	if !s.sweepPending("vault-a") || len(s.unswept) != 0 {
		t.Fatalf("not released after a successful sweep: %v", s.unswept)
	}
}

// killUID refuses without root, for uid 0 and for the caller's own uid
// (kill(-1) as itself would signal all its processes).
func TestKillUIDRefuses(t *testing.T) {
	if err := killUID(0); err == nil {
		t.Fatal("uid 0")
	}
	if err := killUID(os.Getuid()); err == nil {
		t.Fatal("own uid")
	}
	if os.Geteuid() != 0 {
		if err := killUID(os.Getuid() + 12345); err == nil {
			t.Fatal("without root")
		}
	}
}

// TestKillUID (root only; CI job root): two processes under two uids;
// killing one uid ends its process only, the supervisor's threads keep
// root, and the thread that switched uid is not reused.
func TestKillUID(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root (CI job root)")
	}
	start := func(uid uint32) *exec.Cmd {
		c := exec.Command("/bin/sleep", "60")
		c.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: uid, Groups: []uint32{}}}
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		return c
	}
	a, b := start(320000), start(320001)
	defer func() { _ = b.Process.Kill(); _ = b.Wait() }()
	for range 20 {
		if err := killUID(320000); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.Wait(); err == nil {
		t.Fatal("the process of uid 320000 was not killed")
	}
	if !running(b.Process.Pid) {
		t.Fatal("the process of another uid was killed")
	}
	// Nothing left of uid 320000; the switched threads are gone: every
	// thread a goroutine gets is still root.
	if left, err := liveProcessesOf(320000); err != nil || len(left) != 0 {
		t.Fatalf("left %v %v", left, err)
	}
	// The process as /proc shows it (its main thread) is still root's.
	if hasUID(os.Getpid(), 320000) {
		t.Fatal("the supervisor shows uid 320000")
	}
	errs := make(chan error, 64)
	for range 64 {
		go func() {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			if u := syscall.Geteuid(); u != 0 {
				errs <- fmt.Errorf("a thread runs as uid %d", u)
				return
			}
			errs <- nil
		}()
	}
	for range 64 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
}

// The NSM counts as closed only when it is a device owned by root with no
// access for group or others; the supervisor believes only what it reads
// back.
func TestNSMClosed(t *testing.T) {
	old := nsmPath
	t.Cleanup(func() { nsmPath = old })
	nsmPath = filepath.Join(t.TempDir(), "absent")
	if closeNSM() == nil || nsmClosedCheck() == nil {
		t.Fatal("an absent device counts as closed")
	}
	f := filepath.Join(t.TempDir(), "nsm")
	if err := os.WriteFile(f, nil, 0o666); err != nil {
		t.Fatal(err)
	}
	nsmPath = f
	if err := closeNSM(); err == nil {
		t.Fatal("a regular file counts as closed")
	}
	nsmPath = os.DevNull // a device open to everyone
	if nsmClosedCheck() == nil {
		t.Fatal("/dev/null counts as closed")
	}
}

// --- as root: real processes under real uids ---

const sweepHelperArg = "supervisor-sweep-helper"

// TestSweepHelper is the program of TestVaultProcessUIDs's vault
// processes (the test binary, re-executed under the vault uid). With
// "child" it starts a child of its own that outlives it, in a session of
// its own, and then waits for its channel (fd 3) to close.
func TestSweepHelper(t *testing.T) {
	args := flagArgs()
	if len(args) == 0 || args[0] != sweepHelperArg {
		t.Skip("the vault process of TestVaultProcessUIDs")
	}
	if len(args) > 1 && args[1] == "sleep" {
		time.Sleep(10 * time.Minute)
		os.Exit(0)
	}
	if len(args) > 1 && args[1] == "child" {
		c := exec.Command(os.Args[0], "-test.run=^TestSweepHelper$", "--", sweepHelperArg, "sleep")
		c.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if err := c.Start(); err != nil {
			os.Exit(5)
		}
	}
	_, _ = io.Copy(io.Discard, os.NewFile(3, "channel"))
	os.Exit(0)
}

// flagArgs is what follows "--" on the test binary's command line.
func flagArgs() []string {
	for i, a := range os.Args {
		if a == "--" {
			return os.Args[i+1:]
		}
	}
	return nil
}

// TestVaultProcessUIDs (root only; CI runs it in the job "root"): two
// vault processes one after the other in the same slot. The first starts
// a child that outlives it; when the first ends, the child is gone before
// the process counts as ended, and the second runs under another uid.
func TestVaultProcessUIDs(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root (CI job root)")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// The re-executed test binary must be reachable by the vault uids.
	for d := filepath.Dir(exe); d != "/"; d = filepath.Dir(d) {
		if fi, err := os.Stat(d); err != nil || fi.Mode().Perm()&0o001 == 0 {
			t.Skipf("%s is not open to other users: build the test binary where it is (go test -c)", d)
		}
	}
	const base = 310000
	s := &Supervisor{log: slog.New(slog.NewTextHandler(io.Discard, nil)), link: &link{}, activity: map[string]time.Time{}}
	// One slot: the second process can only start once the first has
	// ended, and gets its slot.
	h := newProcHost(s, ProcConfig{Exec: []string{exe, "-test.run=^TestSweepHelper$", "--", sweepHelperArg}, UIDBase: base, MaxProcs: 1})
	start := func(mode string) *vproc {
		p, err := h.spawn("vault", "user", false, mode)
		if err != nil {
			t.Fatalf("spawn: %v", err)
		}
		p.mu.Lock()
		p.stopping = true // ended by the test: nothing to report
		p.mu.Unlock()
		return p
	}

	p1 := start("child")
	if p1.uid != base || p1.slot != 0 {
		t.Fatalf("first process: uid %d slot %d", p1.uid, p1.slot)
	}
	var child int
	waitFor := func(what string, ok func() bool) {
		t.Helper()
		for i := 0; !ok(); i++ {
			if i == 1000 {
				t.Fatalf("timed out waiting for %s", what)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	waitFor("the first process's child", func() bool {
		pids, _ := liveProcessesOf(base)
		for _, pid := range pids {
			if pid != p1.cmd.Process.Pid {
				child = pid
				return true
			}
		}
		return false
	})
	if !hasUID(p1.cmd.Process.Pid, base) {
		t.Fatal("the first process does not run under its uid")
	}
	p1.conn.Close() // as a lock does: the process exits
	select {
	case <-p1.exited:
	case <-time.After(30 * time.Second):
		t.Fatal("the first process did not end")
	}
	// Ended before the process counted as ended.
	if hasUID(child, base) && running(child) {
		_ = syscall.Kill(child, syscall.SIGKILL)
		t.Fatalf("the child %d of the first process outlived it", child)
	}
	if left, err := liveProcessesOf(base); err != nil || len(left) != 0 {
		t.Fatalf("processes of uid %d left: %v", base, left)
	}

	p2 := start("plain")
	if p2.slot != 0 || p2.uid == p1.uid || p2.uid != base+1 {
		t.Fatalf("second process: uid %d slot %d (first uid %d)", p2.uid, p2.slot, p1.uid)
	}
	waitFor("the second process's uid", func() bool { return hasUID(p2.cmd.Process.Pid, base+1) })
	p2.conn.Close()
	<-p2.exited
}

// endThreadAfter runs f on a goroutine locked to its thread and lets the
// goroutine end still locked, so the runtime ends that thread (as the
// sweep's goroutine does).
func endThreadAfter(f func()) {
	done := make(chan struct{})
	go func() {
		runtime.LockOSThread()
		f()
		close(done)
	}()
	<-done
}

// The kernel sends a child's parent-death signal when the thread that
// forked it ends. Vault processes, which have Pdeathsig SIGKILL, are
// forked on the spawner thread, which never ends: started from threads
// that then end, and with sweeps of another uid ending more threads, they
// keep running. The first part shows the hazard is real on this kernel.
func TestSpawnSurvivesThreadExit(t *testing.T) {
	// The hazard: a process forked on a thread that ends gets SIGKILL.
	var direct *exec.Cmd
	endThreadAfter(func() {
		direct = exec.Command("/bin/sleep", "60")
		direct.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
		if err := direct.Start(); err != nil {
			direct = nil
		}
	})
	if direct == nil {
		t.Skip("no /bin/sleep")
	}
	if err := direct.Wait(); err == nil {
		t.Fatal("this kernel did not kill a child whose forking thread ended: the test shows nothing")
	}

	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	base := 0
	if os.Geteuid() == 0 {
		base = 330000 // as root, also under their own uids, with sweeps
	}
	s := &Supervisor{log: slog.New(slog.NewTextHandler(io.Discard, nil)), link: &link{}, activity: map[string]time.Time{}}
	h := newProcHost(s, ProcConfig{Exec: []string{exe, "-test.run=^TestSweepHelper$", "--", sweepHelperArg}, UIDBase: base, MaxProcs: 8})
	var procs []*vproc
	for i := range 4 {
		var p *vproc
		var err error
		endThreadAfter(func() { p, err = h.spawn("vault-"+strconv.Itoa(i), "user", false, "plain") })
		if err != nil {
			t.Fatalf("spawn %d: %v", i, err)
		}
		p.mu.Lock()
		p.stopping = true // ended by the test: nothing to report
		p.mu.Unlock()
		procs = append(procs, p)
	}
	defer func() {
		for _, p := range procs {
			p.conn.Close()
			<-p.exited
		}
	}()
	if base > 0 {
		for range 20 {
			if err := killUID(base + 1000); err != nil { // another uid: ends a thread each time
				t.Fatal(err)
			}
		}
	}
	time.Sleep(200 * time.Millisecond)
	for i, p := range procs {
		select {
		case <-p.exited:
			t.Fatalf("vault process %d ended (code %d) when a thread ended", i, p.exitCode)
		default:
		}
	}
}
