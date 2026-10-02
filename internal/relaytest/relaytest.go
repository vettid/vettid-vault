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
		out, err := exec.Command("go", "list", "-C", root, "-m", "-f", "{{.Version}}", module).Output()
		if err != nil {
			buildErr = fmt.Errorf("relaytest: go list: %w", err)
			return
		}
		version := strings.TrimSpace(string(out))
		cache, err := os.UserCacheDir()
		if err != nil {
			cache = os.TempDir()
		}
		dir := filepath.Join(cache, "vettid-vault-test", "relay-"+version)
		binPath = filepath.Join(dir, "relay")
		if _, err := os.Stat(binPath); err == nil {
			return
		}
		cmd := exec.Command("go", "install", module+"/cmd/relay@"+version)
		cmd.Env = append(os.Environ(), "GOBIN="+dir, "CGO_ENABLED=0", "GOFLAGS=")
		cmd.Dir = os.TempDir()
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			buildErr = fmt.Errorf("relaytest: building relay %s: %v: %s", version, err, stderr.String())
		}
	})
	if buildErr != nil {
		t.Fatal(buildErr)
	}
	return binPath
}

// Relay is a running relay.
type Relay struct {
	URL  string
	cmd  *exec.Cmd
	logs *bytes.Buffer
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
	bin := Binary(t)
	addr, err := freePort()
	if err != nil {
		t.Fatal(err)
	}
	url := "http://" + addr
	env := map[string]string{
		"RELAY_LISTEN_ADDR":                addr,
		"RELAY_BASE_URL":                   url,
		"RELAY_DB_PATH":                    filepath.Join(t.TempDir(), "relay.db"),
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
	logs := &bytes.Buffer{}
	cmd.Stdout, cmd.Stderr = logs, logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	r := &Relay{URL: url, cmd: cmd, logs: logs}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if t.Failed() {
			t.Logf("relay output:\n%s", logs.String())
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for {
		resp, err := http.Get(url + "/healthz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return r
			}
		}
		select {
		case <-ctx.Done():
			t.Fatalf("relay did not start: %s", logs.String())
		case <-time.After(50 * time.Millisecond):
		}
	}
}
