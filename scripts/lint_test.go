// Package scripts holds the checks of the enclave image build, the
// smoke-test scripts (docs/SMOKE.md) and the host files (deploy/host);
// there is no Go code here.
package scripts

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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
	stages := map[string]bool{}
	for _, line := range regexp.MustCompile(`(?m)^FROM\s+(\S+)(?:\s+AS\s+(\S+))?`).FindAllStringSubmatch(d, -1) {
		if line[1] != "scratch" && !stages[line[1]] && !regexp.MustCompile(`@sha256:[0-9a-f]{64}$`).MatchString(line[1]) {
			t.Errorf("base image not pinned by digest: %s", line[1])
		}
		if line[2] != "" {
			stages[line[2]] = true
		}
	}
	// The enclave image is the default (last) stage.
	if !regexp.MustCompile(`FROM scratch\nCOPY --from=build /out/vault-enclave /vault-enclave\n# The supervisor re-executes this binary for every vault process \(D4\).\nCMD \["/vault-enclave"\]\n$`).MatchString(d) {
		t.Error("the enclave image is not the last stage of Dockerfile.enclave")
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
	for _, p := range []string{"build-eif.sh", "smoke/run-on-host.sh", "compat-matrix.sh", "../release/rebuild.sh"} {
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

// The host files (deploy/host): SHA256SUMS lists every other file with its
// current hash (vettid.org pins SHA256SUMS per release; `make host-sums`),
// the scripts parse, nothing runs the enclave in debug mode, and the
// scripts call no AWS service beyond the host's DNS allowlist.
func TestHostFiles(t *testing.T) {
	const dir = "../deploy/host"
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, e := range ents {
		if e.IsDir() {
			t.Errorf("deploy/host/%s: no subdirectories (the AMI build fetches a flat list)", e.Name())
			continue
		}
		b := []byte(read(t, filepath.Join(dir, e.Name())))
		if strings.Contains(string(b), "debug-mode") {
			t.Errorf("deploy/host/%s mentions debug-mode", e.Name())
		}
		if regexp.MustCompile(`AKIA[0-9A-Z]{16}|aws_secret_access_key`).Match(b) {
			t.Errorf("deploy/host/%s contains credentials", e.Name())
		}
		if e.Name() == "SHA256SUMS" {
			continue
		}
		want = append(want, fmt.Sprintf("%x  %s", sha256.Sum256(b), e.Name()))
	}
	// os.ReadDir sorts by name (byte order, as LC_ALL=C sort does).
	if got := read(t, filepath.Join(dir, "SHA256SUMS")); got != strings.Join(want, "\n")+"\n" {
		t.Errorf("deploy/host/SHA256SUMS is stale (make host-sums):\n%s\nwant:\n%s", got, strings.Join(want, "\n"))
	}

	for _, s := range []string{"install.sh", "vault-host-config", "vault-lifecycle"} {
		p := filepath.Join(dir, s)
		src := read(t, p)
		if !strings.HasPrefix(src, "#!/usr/bin/env bash\n") || !strings.Contains(src, "set -euo pipefail") {
			t.Errorf("%s: missing shebang or set -euo pipefail", s)
		}
		if st, err := os.Stat(p); err != nil || st.Mode()&0o111 == 0 {
			t.Errorf("%s is not executable", s)
		}
		// jq is not on the host; STS is not on the DNS allowlist.
		if regexp.MustCompile(`\bjq\b|\bsts\b`).MatchString(src) {
			t.Errorf("%s uses jq or STS", s)
		}
		if out, err := exec.Command("bash", "-n", p).CombinedOutput(); err != nil {
			t.Errorf("bash -n %s: %v\n%s", s, err, out)
		}
	}

	// The units run what install.sh installs, the enclave in production
	// mode with the allocator's resources.
	enc := read(t, filepath.Join(dir, "vault-enclave.service"))
	if !strings.Contains(enc, "ExecStart=/usr/bin/nitro-cli run-enclave --eif-path /opt/vettid/vault-enclave.eif --cpu-count 1 --memory 5120 --enclave-cid 16\n") {
		t.Error("vault-enclave.service: unexpected run-enclave command")
	}
	alloc := read(t, filepath.Join(dir, "allocator.yaml"))
	if !strings.Contains(alloc, "\nmemory_mib: 5120\n") || !strings.Contains(alloc, "\ncpu_count: 1\n") {
		t.Error("allocator.yaml does not match the enclave's resources")
	}
	par := read(t, filepath.Join(dir, "vault-parent.service"))
	for _, f := range []string{"-instance-id", "-region", "-bucket", "-table-vaults", "-table-instances", "-table-requests",
		"-queue-prefix", "-dlq-arn", "-relay-host", "-queue-policy-param"} {
		if !strings.Contains(par, "    "+f+" ${VAULT_") {
			t.Errorf("vault-parent.service lacks %s", f)
		}
	}
	env := read(t, filepath.Join(dir, "vault-host-config"))
	for _, v := range regexp.MustCompile(`\$\{(VAULT_[A-Z_]+)\}`).FindAllStringSubmatch(par, -1) {
		if !strings.Contains(env, "\n"+v[1]+"=") {
			t.Errorf("vault-host-config does not write %s", v[1])
		}
	}
}

// The EIF toolchain (VAULT-RELEASES §5.1): the builder's base image is the
// lock's, pinned by digest; the lock pins the nitro-cli packages and every
// blob by SHA-256; the release workflow pins every action by commit.
func TestEIFToolchain(t *testing.T) {
	lock := read(t, "../release/eif-toolchain.lock")
	val := func(k string) string {
		m := regexp.MustCompile(`(?m)^` + k + `=(\S+)$`).FindStringSubmatch(lock)
		if m == nil {
			t.Fatalf("lock lacks %s", k)
		}
		return m[1]
	}
	d := read(t, "../release/Dockerfile.eif-builder")
	froms := regexp.MustCompile(`(?m)^FROM\s+(\S+)`).FindAllStringSubmatch(d, -1)
	if len(froms) != 1 || froms[0][1] != val("base_image") || !regexp.MustCompile(`@sha256:[0-9a-f]{64}$`).MatchString(froms[0][1]) {
		t.Errorf("builder base image %v, lock %s", froms, val("base_image"))
	}
	if val("arch") != "aarch64" || !regexp.MustCompile(`^2023\.\d+\.\d{8}$`).MatchString(val("releasever")) {
		t.Error("lock arch or releasever")
	}
	ver := val("nitro_cli_version")
	for _, f := range []string{
		"/toolchain/aws-nitro-enclaves-cli-" + ver + ".aarch64.rpm", "/toolchain/aws-nitro-enclaves-cli-devel-" + ver + ".aarch64.rpm",
		"/usr/share/nitro_enclaves/blobs/Image", "/usr/share/nitro_enclaves/blobs/Image.config", "/usr/share/nitro_enclaves/blobs/cmdline",
		"/usr/share/nitro_enclaves/blobs/init", "/usr/share/nitro_enclaves/blobs/linuxkit", "/usr/share/nitro_enclaves/blobs/nsm.ko",
	} {
		if !regexp.MustCompile(`(?m)^[0-9a-f]{64}  ` + regexp.QuoteMeta(f) + `$`).MatchString(lock) {
			t.Errorf("lock does not pin %s", f)
		}
	}
	for _, want := range []string{"sha256sum -c", "--releasever", "dnf -q --releasever=\"$rv\" download"} {
		if !strings.Contains(d, want) {
			t.Errorf("builder lacks %q", want)
		}
	}
	for _, wf := range []string{"../.github/workflows/release.yml", "../.github/workflows/compat.yml", "../.github/workflows/ci.yml"} {
		w := read(t, wf)
		for _, m := range regexp.MustCompile(`(?m)^\s*-?\s*uses:\s*(\S+)`).FindAllStringSubmatch(w, -1) {
			if !regexp.MustCompile(`@[0-9a-f]{40}$`).MatchString(m[1]) {
				t.Errorf("%s: action not pinned by commit: %s", wf, m[1])
			}
		}
	}
}
