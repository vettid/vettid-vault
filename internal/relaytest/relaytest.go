// Package relaytest builds and runs the real vettid-relay binary for
// integration tests, at exactly the version this module depends on. The
// binary is built with `go install <module>/cmd/relay@<version>` (outside
// this module, so the relay's own dependencies never enter go.mod) into a
// per-version cache directory.
package relaytest

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const module = "github.com/vettid/vettid-relay"

var (
	buildOnce sync.Once
	binPath   string
	buildErr  error
)

// moduleRoot finds the directory holding go.mod, from the test's cwd.
func moduleRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("relaytest: go.mod not found")
		}
		dir = parent
	}
}

// Binary returns the path of the relay binary, building it once.
func Binary(t testing.TB) string {
	t.Helper()
	buildOnce.Do(func() {
		root, err := moduleRoot()
		if err != nil {
			buildErr = err
			return
		}
		binPath, buildErr = BuildBinary(root)
	})
	if buildErr != nil {
		t.Fatal(buildErr)
	}
	return binPath
}

// BuildBinary builds (or finds in the per-version cache) the relay binary
// at the version the module in root (a vettid-vault source tree) requires.
func BuildBinary(root string) (string, error) {
	out, err := exec.Command("go", "list", "-C", root, "-m", "-f", "{{.Version}}", module).Output()
	if err != nil {
		return "", fmt.Errorf("relaytest: go list: %w", err)
	}
	version := strings.TrimSpace(string(out))
	cache, err := os.UserCacheDir()
	if err != nil {
		cache = os.TempDir()
	}
	dir := filepath.Join(cache, "vettid-vault-test", "relay-"+version)
	bin := filepath.Join(dir, "relay")
	if _, err := os.Stat(bin); err == nil {
		return bin, nil
	}
	cmd := exec.Command("go", "install", module+"/cmd/relay@"+version)
	cmd.Env = append(os.Environ(), "GOBIN="+dir, "CGO_ENABLED=0", "GOFLAGS=")
	cmd.Dir = os.TempDir()
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("relaytest: building relay %s: %v: %s", version, err, stderr.String())
	}
	return bin, nil
}

// Relay is a running relay.
type Relay struct {
	URL      string
	cmd      *exec.Cmd
	logs     *syncBuffer
	stopOnce sync.Once
}

// Options override relay settings (environment variable → value).
type Options map[string]string

func freePort() (string, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	defer l.Close()
	return l.Addr().String(), nil
}

// Start runs a fresh relay with a temporary database. It is stopped when
// the test ends. Defaults suit tests: short visibility timeout (2 s), 7-day
// open tokens and claims, 400-day token lifetimes, relaxed rate limits.
func Start(t testing.TB, opts Options) *Relay {
	t.Helper()
	r, err := Run(Binary(t), filepath.Join(t.TempDir(), "relay.db"), nil, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		r.Stop()
		if t.Failed() {
			t.Logf("relay output:\n%s", r.logs.String())
		}
	})
	return r
}

// Run starts bin with its database at dbPath and the test defaults of
// Start, overridden by opts, and waits until it is healthy. Its output
// goes to logs (nil: kept in memory, see Logs). The caller stops it.
func Run(bin, dbPath string, logs io.Writer, opts Options) (*Relay, error) {
	addr, err := freePort()
	if err != nil {
		return nil, err
	}
	url := "http://" + addr
	env := map[string]string{
		"RELAY_LISTEN_ADDR":                addr,
		"RELAY_BASE_URL":                   url,
		"RELAY_DB_PATH":                    dbPath,
		"RELAY_METRICS_ADDR":               "",
		"RELAY_LOG_LEVEL":                  "warn",
		"RELAY_VISIBILITY_TIMEOUT":         "2s",
		"RELAY_OPEN_TOKEN_MAX_LIFETIME":    "168h",
		"RELAY_CLAIM_TTL":                  "168h",
		"RELAY_MAX_TOKEN_LIFETIME":         "9600h",
		"RELAY_RATE_IP_RPS":                "10000",
		"RELAY_RATE_IP_BURST":              "10000",
		"RELAY_RATE_SENDER_RPS":            "10000",
		"RELAY_RATE_SENDER_BURST":          "10000",
		"RELAY_RATE_CLAIM_GET_RPS":         "10000",
		"RELAY_RATE_CLAIM_GET_BURST":       "10000",
		"RELAY_MAX_COLLECTORS_PER_MAILBOX": "16",
	}
	for k, v := range opts {
		env[k] = v
	}
	cmd := exec.Command(bin)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	buf := &syncBuffer{}
	var w io.Writer = buf
	if logs != nil {
		w = io.MultiWriter(buf, logs)
	}
	cmd.Stdout, cmd.Stderr = w, w
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	r := &Relay{URL: url, cmd: cmd, logs: buf}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for {
		resp, err := http.Get(url + "/healthz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return r, nil
			}
		}
		select {
		case <-ctx.Done():
			r.Stop()
			return nil, fmt.Errorf("relaytest: relay did not start: %s", buf.String())
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// Stop kills the relay and waits for it.
func (r *Relay) Stop() {
	r.stopOnce.Do(func() {
		_ = r.cmd.Process.Kill()
		_ = r.cmd.Wait()
	})
}

// Logs returns the relay's output so far (the last 1 MiB).
func (r *Relay) Logs() string { return r.logs.String() }

// syncBuffer keeps the last 1 MiB written.
type syncBuffer struct {
	mu sync.Mutex
	b  []byte
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.b = append(s.b, p...)
	if over := len(s.b) - 1<<20; over > 0 {
		s.b = append(s.b[:0], s.b[over:]...)
	}
	return len(p), nil
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return string(s.b)
}
