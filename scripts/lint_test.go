// Package scripts holds the checks of the enclave image build and the
// smoke-test scripts (docs/SMOKE.md); there is no Go code here.
package scripts

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func arg(t *testing.T, s, name string) string {
	t.Helper()
	m := regexp.MustCompile(`(?m)^\s*(?:ARG\s+)?` + name + `=([0-9a-f.]+)\s*$`).FindStringSubmatch(s)
	if m == nil {
		t.Fatalf("%s not set", name)
	}
	return m[1]
}

// The enclave image is reproducible and minimal (VAULT-PLAN D3).
func TestDockerfileEnclave(t *testing.T) {
	d := read(t, "../Dockerfile.enclave")
	for _, line := range regexp.MustCompile(`(?m)^FROM\s+(\S+)`).FindAllStringSubmatch(d, -1) {
		if line[1] != "scratch" && !regexp.MustCompile(`@sha256:[0-9a-f]{64}$`).MatchString(line[1]) {
			t.Errorf("base image not pinned by digest: %s", line[1])
		}
	}
	if !strings.Contains(d, "FROM scratch") {
		t.Error("the final image is not empty (FROM scratch)")
	}
	for _, want := range []string{"CGO_ENABLED=0", "-trimpath", "-buildvcs=false", "-buildid=", "GOTOOLCHAIN=local", "-mod=readonly",
		"sha256sum -c", "go mod verify", "SOURCE_DATE_EPOCH", `CMD ["/vault-enclave"]`} {
		if !strings.Contains(d, want) {
			t.Errorf("Dockerfile.enclave lacks %q", want)
		}
	}
	if n := strings.Count(d, "COPY --from=build"); n != 1 {
		t.Errorf("the final image copies %d files; only the enclave binary belongs there", n)
	}
	// The host script pins the same toolchain.
	h := read(t, "smoke/run-on-host.sh")
	for _, n := range []string{"GO_VERSION", "GO_SHA256_ARM64", "GO_SHA256_AMD64"} {
		if a, b := arg(t, d, n), arg(t, h, n); a != b {
			t.Errorf("%s differs: Dockerfile %s, run-on-host %s", n, a, b)
		}
	}
}

func TestScripts(t *testing.T) {
	for _, p := range []string{"build-eif.sh", "smoke/run-on-host.sh"} {
		s := read(t, p)
		if !strings.HasPrefix(s, "#!/usr/bin/env bash\n") || !strings.Contains(s, "set -euo pipefail") {
			t.Errorf("%s: missing shebang or set -euo pipefail", p)
		}
		if strings.Contains(s, "--debug-mode") {
			t.Errorf("%s runs the enclave in debug mode", p)
		}
		if regexp.MustCompile(`AKIA[0-9A-Z]{16}|aws_secret_access_key`).MatchString(s) {
			t.Errorf("%s contains credentials", p)
		}
		if st, err := os.Stat(p); err != nil || st.Mode()&0o111 == 0 {
			t.Errorf("%s is not executable", p)
		}
	}
}
