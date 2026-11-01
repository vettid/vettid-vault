// Package scripts holds the checks of the enclave image build, the
// smoke-test scripts (docs/SMOKE.md) and the host files (deploy/host);
// there is no Go code here.
package scripts

import (
	"crypto/sha256"
	"errors"
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
	// go.mod's toolchain line names the same release, so that CI's
	// setup-go (go-version-file: go.mod) runs the tests on it too.
	m := regexp.MustCompile(`(?m)^toolchain\s+go(\S+)\s*$`).FindStringSubmatch(read(t, "../go.mod"))
	if m == nil {
		t.Error("go.mod has no toolchain line")
	} else if v := arg(t, d, "GO_VERSION"); m[1] != v {
		t.Errorf("go.mod's toolchain is go%s, Dockerfile's GO_VERSION is %s", m[1], v)
	}
}

func TestScripts(t *testing.T) {
	for _, p := range []string{"build-eif.sh", "smoke/run-on-host.sh", "compat-matrix.sh", "../release/rebuild.sh",
		"../release/kernel/build.sh", "../release/kernel/check-config.sh", "../release/kernel/check-current.sh", "../release/kernel/eif-with-blobs.sh", "../release/kernel/rebuild-check.sh"} {
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
	// The kernel the binary expects (release/enclave-kernel, embedded)
	// matches the blobs the lock pins: AWS's release, or vettid-vault's
	// own build of release/kernel/kernel.lock.
	ek := read(t, "../release/enclave-kernel")
	ekv := func(k string) string {
		m := regexp.MustCompile(`(?m)^` + k + `=(\S+)$`).FindStringSubmatch(ek)
		if m == nil {
			t.Fatalf("release/enclave-kernel lacks %s", k)
		}
		return m[1]
	}
	krel, khard := ekv("kernel_release"), ekv("kernel_hardened")
	// blobs_version names release assets and files: a plain name.
	if !regexp.MustCompile(`^[A-Za-z0-9._-]+$`).MatchString(val("blobs_version")) {
		t.Errorf("blobs_version %q", val("blobs_version"))
	}
	if regexp.MustCompile(`(?m)^kernel_(release|hardened)=`).MatchString(lock) {
		t.Error("the lock names the kernel itself; it belongs in release/enclave-kernel")
	}
	switch khard {
	case "false":
		if val("blobs_version") != "v"+krel {
			t.Errorf("kernel_release %s does not match blobs_version %s", krel, val("blobs_version"))
		}
		if !strings.HasPrefix(val("blobs_url"), "https://github.com/aws/") {
			t.Errorf("kernel_hardened=false but blobs_url %s is not AWS's", val("blobs_url"))
		}
	case "true":
		if !strings.Contains(read(t, "../release/kernel/kernel.lock"), "\nkernel_version="+krel+"\n") {
			t.Errorf("kernel_release %s is not release/kernel/kernel.lock's kernel_version", krel)
		}
		if !strings.HasPrefix(val("blobs_url"), "https://github.com/vettid/vettid-vault/releases/download/") || val("blobs_dir") != "vettid-enclave-blobs/aarch64" {
			t.Errorf("kernel_hardened=true but blobs_url %s / blobs_dir %s are not vettid-vault's release", val("blobs_url"), val("blobs_dir"))
		}
		// The set was built from the committed kernel inputs, and its six
		// files are the ones release/kernel/SHA256SUMS records.
		kl, err := os.ReadFile("../release/kernel/kernel.lock")
		if err != nil {
			t.Fatal(err)
		}
		if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(val("kernel_source_sha256")) {
			t.Error("kernel_source_sha256: the recipe source archive's SHA-256")
		}
		if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(val("kernel_commit")) {
			t.Errorf("kernel_commit %q is not a full commit id", val("kernel_commit"))
		} else if err := kernelCommitInHistory("..", val("kernel_commit")); err != nil {
			if os.Getenv("GITHUB_ACTIONS") != "true" && errors.Is(err, errNoHistory) {
				t.Logf("kernel_commit ancestry not checked: %v", err)
			} else {
				t.Error(err)
			}
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(kl)); val("kernel_lock_sha256") != got {
			t.Errorf("kernel_lock_sha256 %s, release/kernel/kernel.lock is %s", val("kernel_lock_sha256"), got)
		}
		for _, line := range strings.Split(strings.TrimSpace(read(t, "../release/kernel/SHA256SUMS")), "\n") {
			f := strings.Fields(line)
			if len(f) != 2 || !regexp.MustCompile(`(?m)^`+f[0]+`  /usr/share/nitro_enclaves/blobs/`+regexp.QuoteMeta(f[1])+`$`).MatchString(lock) {
				t.Errorf("the lock does not pin %s as release/kernel/SHA256SUMS does", line)
			}
		}
	default:
		t.Errorf("kernel_hardened %q is not true or false", khard)
	}
	ver := val("nitro_cli_version")
	for _, f := range []string{
		"/toolchain/aws-nitro-enclaves-cli-" + ver + ".aarch64.rpm", "/toolchain/aws-nitro-enclaves-cli-devel-" + ver + ".aarch64.rpm", "/toolchain/enclaves-blobs.txz",
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
	for _, wf := range []string{"../.github/workflows/release.yml", "../.github/workflows/compat.yml", "../.github/workflows/ci.yml",
		"../.github/workflows/enclave-kernel.yml", "../.github/workflows/kernel-freshness.yml"} {
		w := read(t, wf)
		for _, m := range regexp.MustCompile(`(?m)^\s*-?\s*uses:\s*(\S+)`).FindAllStringSubmatch(w, -1) {
			if !regexp.MustCompile(`@[0-9a-f]{40}$`).MatchString(m[1]) {
				t.Errorf("%s: action not pinned by commit: %s", wf, m[1])
			}
		}
	}
}

// The enclave kernel built from source (docs/KERNEL.md): every input is
// pinned in release/kernel/kernel.lock (source by SHA-256 and signer
// fingerprint, the Nix image by digest, nixpkgs by hash), the files
// copied from AWS's recipe are unchanged (aws/SHA256SUMS), and the config
// fragment keeps module loading off with the NSM driver built in.
func TestEnclaveKernel(t *testing.T) {
	const dir = "../release/kernel"
	lock := read(t, dir+"/kernel.lock")
	val := func(k string) string {
		m := regexp.MustCompile(`(?m)^` + k + `=(\S+)$`).FindStringSubmatch(lock)
		if m == nil {
			t.Fatalf("kernel.lock lacks %s", k)
		}
		return m[1]
	}
	v := val("kernel_version")
	if !regexp.MustCompile(`^6\.6\.\d+$`).MatchString(v) {
		t.Errorf("kernel_version %s is not a 6.6.y release", v)
	}
	if want := "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-" + v + ".tar.xz"; val("kernel_url") != want {
		t.Errorf("kernel_url %s, want %s", val("kernel_url"), want)
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(val("kernel_sha256")) {
		t.Error("kernel_sha256")
	}
	if !regexp.MustCompile(`^[0-9A-F]{40}(,[0-9A-F]{40})*$`).MatchString(val("kernel_signers")) {
		t.Error("kernel_signers: full fingerprints, comma separated")
	}
	if !regexp.MustCompile(`@sha256:[0-9a-f]{64}$`).MatchString(val("nix_image")) {
		t.Errorf("nix_image %s is not pinned by digest", val("nix_image"))
	}
	if !regexp.MustCompile(`^[0-9a-z]{52}$`).MatchString(val("nixpkgs_sha256")) || !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(val("aws_bootstrap_commit")) {
		t.Error("nixpkgs_sha256 or aws_bootstrap_commit")
	}
	if val("arch") != "aarch64" {
		t.Error("arch")
	}
	tc := regexp.MustCompile(`(?m)^toolchain=(\w+) /nix/store/[0-9a-z]{32}-\S+ sha256:[0-9a-z]{52}$`).FindAllStringSubmatch(lock, -1)
	if !regexp.MustCompile(`(?m)^toolchain_closure_sha256=[0-9a-f]{64}$`).MatchString(lock) {
		t.Error("kernel.lock lacks toolchain_closure_sha256")
	}
	if names := len(tc); names != 5 {
		t.Errorf("kernel.lock pins %d toolchain paths, want 5 (gcc, binutils, muslGcc, musl, go)", names)
	}
	sums := read(t, dir+"/aws/SHA256SUMS")
	n := 0
	for _, line := range strings.Split(strings.TrimSpace(sums), "\n") {
		f := strings.Fields(line)
		if len(f) != 2 {
			t.Fatalf("aws/SHA256SUMS: %q", line)
		}
		b, err := os.ReadFile(filepath.Join(dir, "aws", f[1]))
		if err != nil {
			t.Error(err)
			continue
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(b)); got != f[0] {
			t.Errorf("aws/%s changed: AWS's files stay as copied; changes go in patches/ or config/", f[1])
		}
		n++
	}
	if n < 9 {
		t.Errorf("aws/SHA256SUMS lists %d files", n)
	}
	frag := read(t, dir+"/config/hardening.config")
	for _, want := range []string{"# CONFIG_MODULES is not set\n", "CONFIG_NSM=y\n", "CONFIG_SECURITY_YAMA=y\n", "CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY=y\n"} {
		if !strings.Contains(frag, want) {
			t.Errorf("hardening.config lacks %q", want)
		}
	}
	if c := read(t, dir+"/cmdline"); strings.Contains(c, "\n") || strings.Contains(c, "nomodule") {
		t.Errorf("cmdline %q: one line, no newline, no module options (the kernel has no modules)", c)
	}
}

// errNoHistory: the checkout cannot answer whether a commit is in HEAD's
// history (not a git work tree, or a shallow clone). CI fails on it; a
// local run without the history only logs it.
var errNoHistory = errors.New("no full git history")

// kernelCommitInHistory reports whether commit, the recipe commit the
// pinned blob set was built and tagged at (release/eif-toolchain.lock
// kernel_commit), is an ancestor of HEAD in the repository at dir. The
// kernel pull request is merged with a merge commit (docs/KERNEL.md §6) so
// that it is; a squash would leave it reachable only from its tag.
func kernelCommitInHistory(dir, commit string) error {
	git := func(args ...string) (string, error) {
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = gitFreeEnv()
		out, err := cmd.CombinedOutput()
		return strings.TrimSpace(string(out)), err
	}
	if _, err := exec.LookPath("git"); err != nil {
		return fmt.Errorf("%w: %v", errNoHistory, err)
	}
	if out, err := git("rev-parse", "--is-shallow-repository"); err != nil {
		return fmt.Errorf("%w: %v: %s", errNoHistory, err, out)
	} else if out == "true" {
		return fmt.Errorf("%w: a shallow clone (fetch-depth: 0 is needed)", errNoHistory)
	}
	if _, err := git("cat-file", "-e", commit+"^{commit}"); err != nil {
		return fmt.Errorf("kernel_commit %s is not in this repository (was the kernel pull request squashed or rebased, or its kernel/<version>-<n> tag not fetched?)", commit)
	}
	if _, err := git("merge-base", "--is-ancestor", commit, "HEAD"); err != nil {
		return fmt.Errorf("kernel_commit %s is not in HEAD's history: merge the kernel pull request with a merge commit, not a squash or a rebase (docs/KERNEL.md §6)", commit)
	}
	return nil
}

// gitFreeEnv is the environment without the GIT_ variables a git hook
// exports (GIT_DIR, GIT_INDEX_FILE, GIT_WORK_TREE, ...), so that a git run
// here acts on the directory it is given and never on the repository of a
// hook that runs the tests.
func gitFreeEnv() []string {
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "GIT_") {
			env = append(env, kv)
		}
	}
	return env
}

// A merge commit keeps the recipe commit in the history; a squash of the
// same pull request does not, though a tag still holds it.
func TestKernelCommitInHistory(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	// No user or system git config, and none of a hook's GIT_ variables.
	gitEnv := func() []string {
		return append(gitFreeEnv(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
	}
	dir := t.TempDir()
	git := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(gitEnv(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.org", "GIT_COMMITTER_NAME=t",
			"GIT_COMMITTER_EMAIL=t@example.org")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	commit := func(file, msg string) string {
		if err := os.WriteFile(filepath.Join(dir, file), []byte(msg), 0o644); err != nil {
			t.Fatal(err)
		}
		git("add", file)
		git("commit", "-q", "-m", msg)
		return git("rev-parse", "HEAD")
	}
	git("init", "-q", "-b", "main")
	// A GIT_DIR or GIT_INDEX_FILE from a hook running the tests is not used.
	t.Setenv("GIT_DIR", filepath.Join(t.TempDir(), "not-this"))
	t.Setenv("GIT_INDEX_FILE", filepath.Join(t.TempDir(), "not-this-index"))
	commit("a", "base")
	git("checkout", "-q", "-b", "kernel")
	recipe := commit("kernel.lock", "recipe")
	commit("eif-toolchain.lock", "pin")
	git("tag", "kernel/x-1", recipe)
	git("checkout", "-q", "main")
	commit("b", "another change on main")

	git("checkout", "-q", "-b", "merged", "main")
	git("merge", "-q", "--no-ff", "-m", "merge", "kernel")
	if err := kernelCommitInHistory(dir, recipe); err != nil {
		t.Errorf("merge commit: %v", err)
	}

	git("checkout", "-q", "-b", "squashed", "main")
	git("merge", "-q", "--squash", "kernel")
	git("commit", "-q", "-m", "squash")
	if err := kernelCommitInHistory(dir, recipe); err == nil || errors.Is(err, errNoHistory) {
		t.Errorf("squash: %v, want not in history", err)
	}
	if err := kernelCommitInHistory(dir, strings.Repeat("0", 40)); err == nil {
		t.Error("an unknown commit passed")
	}

	shallow := t.TempDir()
	clone := exec.Command("git", "clone", "-q", "--depth", "1", "--branch", "merged", "file://"+dir, shallow)
	clone.Env = gitEnv()
	if out, err := clone.CombinedOutput(); err != nil {
		t.Fatalf("shallow clone: %v\n%s", err, out)
	}
	if err := kernelCommitInHistory(shallow, recipe); !errors.Is(err, errNoHistory) {
		t.Errorf("shallow clone: %v, want errNoHistory", err)
	}
}
