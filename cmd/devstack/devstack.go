//go:build devenclave

// Command devstack runs a long-lived local DEVELOPMENT stack of the vault
// side, for app development (vettid-android's devStack build, its
// instrumented tests) against a phone over `adb reverse`:
//
//   - the real vettid-relay binary, at the version go.mod requires;
//   - LocalStack (S3, SQS, DynamoDB, SSM): integration/docker-compose.yml
//     started and stopped by devstack, or an external one (-localstack);
//   - vault-parent (release build) in TCP mode;
//   - vault-enclave (dev build: fake NSM and KMS, TEST-ONLY roots, test
//     release 3), optionally with a -dev-device-policy;
//   - the member API stand-in (internal/memberapitest);
//   - a vaultctl peer vault (a second member), driven through the control
//     port.
//
// Everything listens on 127.0.0.1:
//
//	-relay-port (18080)  the relay, plain HTTP; tokens name it https://relay.vettid.test
//	-api-port   (18081)  the member API stand-in ("Authorization: Bearer <user_guid>")
//	-ctl-port   (18082)  dev control: GET /dev/health, GET /dev/info, GET /dev/trust,
//	                     POST /dev/peer/request, POST /dev/peer/event
//
// Run it from a checkout or by module version:
//
//	go run -tags devenclave ./cmd/devstack
//	go run -tags devenclave github.com/vettid/vettid-vault/cmd/devstack@<commit>
//
// It stops on SIGINT or SIGTERM (to devstack itself; under `go run`, also
// when the go command exits). Every key in the stack is TEST-ONLY
// (fixed public seeds); nothing persists across restarts. The command
// exists only in devenclave builds (release.go; `make check-tcb`).
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/vettid/vettid-vault/internal/enclavetest"
)

const modulePath = "github.com/vettid/vettid-vault"

// options are the command-line settings.
type options struct {
	relayPort, apiPort, ctlPort int
	devicePolicy                string
	dataDir                     string
	localstack                  string
	compose                     string
	src                         string
	minFreeGB                   int
	memWait                     time.Duration
}

func parseFlags(args []string) (*options, error) {
	fs := flag.NewFlagSet("devstack", flag.ContinueOnError)
	o := &options{}
	cache, err := os.UserCacheDir()
	if err != nil {
		cache = os.TempDir()
	}
	fs.IntVar(&o.relayPort, "relay-port", 18080, "relay port (plain HTTP, 127.0.0.1)")
	fs.IntVar(&o.apiPort, "api-port", 18081, "member API stand-in port (127.0.0.1)")
	fs.IntVar(&o.ctlPort, "ctl-port", 18082, "dev control port (127.0.0.1)")
	fs.StringVar(&o.devicePolicy, "dev-device-policy", "", "JSON file extending the dev enclave's TEST device-attestation policy (passed to vault-enclave)")
	fs.StringVar(&o.dataDir, "data", filepath.Join(cache, "vettid-devstack"), "data directory (binaries in bin/, this run in run/: logs, ready.json)")
	fs.StringVar(&o.localstack, "localstack", "", "external LocalStack endpoint (e.g. http://127.0.0.1:4566); empty: start integration/docker-compose.yml and stop it on exit")
	fs.StringVar(&o.compose, "compose", "", "compose command for LocalStack (default: \"podman compose\" if podman is installed, else \"docker compose\")")
	fs.StringVar(&o.src, "src", "", "vettid-vault source tree to build the binaries from (default: this command's own module)")
	fs.IntVar(&o.minFreeGB, "wait-free-mem", 8, "refuse to start unless this many GB of memory are available (0: no check)")
	fs.DurationVar(&o.memWait, "mem-wait", 0, "with -wait-free-mem: keep re-checking (every 30 s) this long before refusing")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() != 0 {
		return nil, fmt.Errorf("unexpected arguments %q", fs.Args())
	}
	ports := map[int]bool{}
	for _, p := range []int{o.relayPort, o.apiPort, o.ctlPort} {
		if p < 0 || p > 65535 {
			return nil, fmt.Errorf("port %d out of range", p)
		}
		if p != 0 && ports[p] {
			return nil, fmt.Errorf("port %d used twice", p)
		}
		ports[p] = true
	}
	if o.minFreeGB < 0 || o.memWait < 0 {
		return nil, errors.New("-wait-free-mem and -mem-wait must not be negative")
	}
	if o.localstack != "" && !strings.HasPrefix(o.localstack, "http://") && !strings.HasPrefix(o.localstack, "https://") {
		return nil, errors.New("-localstack must be an http(s) URL")
	}
	return o, nil
}

func main() {
	o, err := parseFlags(os.Args[1:])
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		fmt.Fprintln(os.Stderr, "devstack:", err)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, o, nil); err != nil {
		fmt.Fprintln(os.Stderr, "devstack:", err)
		os.Exit(1)
	}
}

// run starts the stack, calls ready (if set) with its info once it is up,
// and runs until ctx ends or a stack process exits.
func run(ctx context.Context, o *options, ready func(map[string]any)) (err error) {
	if err := memCheck(ctx, o.minFreeGB, o.memWait); err != nil {
		return err
	}
	var dp *enclavetest.DevDevicePolicy
	if o.devicePolicy != "" {
		abs, err := filepath.Abs(o.devicePolicy)
		if err != nil {
			return err
		}
		o.devicePolicy = abs
		b, err := os.ReadFile(abs)
		if err != nil {
			return fmt.Errorf("-dev-device-policy: %w", err)
		}
		if dp, err = enclavetest.ParseDevDevicePolicy(b); err != nil {
			return fmt.Errorf("-dev-device-policy: %w", err)
		}
	}
	src := o.src
	if src == "" {
		if src, err = findSource(); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(o.dataDir, 0o700); err != nil {
		return err
	}
	unlock, err := lockDir(o.dataDir)
	if err != nil {
		return err
	}
	defer unlock()
	s := &stack{opts: o, src: src, policy: dp, binDir: filepath.Join(o.dataDir, "bin"), runDir: filepath.Join(o.dataDir, "run")}
	defer s.close()
	if err := s.start(ctx); err != nil {
		return err
	}
	info := s.info()
	b, _ := json.MarshalIndent(info, "", "  ")
	if err := os.WriteFile(filepath.Join(s.runDir, "ready.json"), append(b, '\n'), 0o600); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "devstack ready (%s):\n%s\n", filepath.Join(s.runDir, "ready.json"), b)
	if ready != nil {
		ready(info)
	}
	select {
	case <-ctx.Done():
		s.logf("stopping")
		return nil
	case e := <-s.died:
		return e
	case <-goRunGone(ctx):
		s.logf("go run exited; stopping")
		return nil
	}
}

// goRunGone is closed when this process was started by `go run` and that
// go process is gone: `go run` does not pass SIGTERM on to its child, so
// a stack started with `go run ... &` and stopped with `kill` would
// otherwise keep running. Started any other way, it never closes.
func goRunGone(ctx context.Context) <-chan struct{} {
	ch := make(chan struct{})
	ppid := os.Getppid()
	comm, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", ppid))
	if err != nil || strings.TrimSpace(string(comm)) != "go" {
		return ch
	}
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
			if os.Getppid() != ppid {
				close(ch)
				return
			}
		}
	}()
	return ch
}

// memCheck refuses to start unless minGB of memory are available (Linux
// MemAvailable), re-checking every 30 s for up to wait.
func memCheck(ctx context.Context, minGB int, wait time.Duration) error {
	if minGB == 0 {
		return nil
	}
	deadline := time.Now().Add(wait)
	for {
		avail, err := memAvailable("/proc/meminfo")
		if err != nil {
			fmt.Fprintf(os.Stderr, "devstack: cannot read available memory (%v); skipping the -wait-free-mem check\n", err)
			return nil
		}
		if avail >= uint64(minGB)<<30 {
			return nil
		}
		msg := fmt.Sprintf("only %.1f GB of memory available, need %d (-wait-free-mem)", float64(avail)/(1<<30), minGB)
		if !time.Now().Before(deadline) {
			return errors.New(msg)
		}
		fmt.Fprintf(os.Stderr, "devstack: %s; re-checking in 30 s\n", msg)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(30 * time.Second):
		}
	}
}

// memAvailable reads MemAvailable (bytes) from a meminfo file.
func memAvailable(path string) (uint64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if rest, ok := strings.CutPrefix(sc.Text(), "MemAvailable:"); ok {
			kb, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimSpace(rest), " kB"), 10, 64)
			if err != nil {
				return 0, errors.New("malformed MemAvailable")
			}
			return kb << 10, nil
		}
	}
	return 0, errors.New("no MemAvailable")
}

// findSource locates the vettid-vault source tree this command was built
// from: the directory of its own source file (a checkout, or the module
// cache for `go run ...@version`), else the module cache entry of the
// version in the build info.
func findSource() (string, error) {
	if _, file, _, ok := runtime.Caller(0); ok && filepath.IsAbs(file) {
		root := filepath.Dir(filepath.Dir(filepath.Dir(file)))
		if isVaultModule(root) {
			return root, nil
		}
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Path == modulePath && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		out, err := exec.Command("go", "mod", "download", "-json", modulePath+"@"+bi.Main.Version).Output()
		if err == nil {
			var m struct{ Dir string }
			if json.Unmarshal(out, &m) == nil && isVaultModule(m.Dir) {
				return m.Dir, nil
			}
		}
	}
	return "", errors.New("cannot find the vettid-vault source tree; pass -src DIR")
}

func isVaultModule(dir string) bool {
	b, err := os.ReadFile(filepath.Join(dir, "go.mod"))
	if err != nil {
		return false
	}
	first, _, _ := strings.Cut(string(b), "\n")
	return strings.TrimSpace(first) == "module "+modulePath
}

// lockDir holds an exclusive lock on dir/lock: one stack per data dir.
func lockDir(dir string) (func(), error) {
	f, err := os.OpenFile(filepath.Join(dir, "lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("another devstack is using %s", dir)
	}
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil
}

// healthy reports whether url answers 200.
func healthy(url string) bool {
	c := &http.Client{Timeout: 2 * time.Second}
	r, err := c.Get(url)
	if err != nil {
		return false
	}
	r.Body.Close()
	return r.StatusCode == http.StatusOK
}
