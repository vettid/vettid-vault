package buildnames

import (
	"bufio"
	"go/build/constraint"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// knownOS and knownArch are go/build's lists (internal/syslist): every word
// that a file name's suffix turns into a build constraint, including the
// ones `go tool dist list` does not name.
var knownOS = words("aix android darwin dragonfly freebsd hurd illumos ios js linux nacl netbsd openbsd plan9 solaris wasip1 windows zos")

var knownArch = words("386 amd64 amd64p32 arm armbe arm64 arm64be loong64 mips mipsle mips64 mips64le mips64p32 mips64p32le " +
	"ppc ppc64 ppc64le riscv riscv64 s390 s390x sparc sparc64 wasm")

func words(s string) map[string]bool {
	m := map[string]bool{}
	for _, w := range strings.Fields(s) {
		m[w] = true
	}
	return m
}

// nameTags returns the GOOS and GOARCH words a file name limits the file
// to, as go/build's goodOSArchFile reads the name: up to the first dot,
// after the first underscore, without a final _test; a GOOS_GOARCH pair,
// else one GOOS or GOARCH word.
func nameTags(file string) []string {
	name, _, _ := strings.Cut(file, ".")
	i := strings.Index(name, "_")
	if i < 0 {
		return nil
	}
	l := strings.Split(name[i:], "_")
	if n := len(l); n > 0 && l[n-1] == "test" {
		l = l[:n-1]
	}
	n := len(l)
	if n >= 2 && knownOS[l[n-2]] && knownArch[l[n-1]] {
		return []string{l[n-2], l[n-1]}
	}
	if n >= 1 && (knownOS[l[n-1]] || knownArch[l[n-1]]) {
		return []string{l[n-1]}
	}
	return nil
}

// positive reports whether tag appears in e outside any negation.
func positive(e constraint.Expr, tag string, negated bool) bool {
	switch x := e.(type) {
	case *constraint.TagExpr:
		return x.Tag == tag && !negated
	case *constraint.NotExpr:
		return positive(x.X, tag, !negated)
	case *constraint.AndExpr:
		return positive(x.X, tag, negated) || positive(x.Y, tag, negated)
	case *constraint.OrExpr:
		return positive(x.X, tag, negated) || positive(x.Y, tag, negated)
	}
	return false
}

// goBuild returns the file's //go:build expression, read up to its package
// clause, or nil.
func goBuild(t *testing.T, path string) constraint.Expr {
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "package ") {
			return nil
		}
		if constraint.IsGoBuild(line) {
			e, err := constraint.Parse(line)
			if err != nil {
				t.Fatalf("%s: %v", path, err)
			}
			return e
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return nil
}

// Every .go file whose name limits it to a platform names that platform,
// un-negated, in its //go:build line. Otherwise the name alone decides where
// it builds, which is how real_ios_test.go dropped a test from every build
// but iOS's.
func TestPlatformNamesAreDeclared(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if n := d.Name(); path != root && (strings.HasPrefix(n, ".") || strings.HasPrefix(n, "_") || n == "testdata" || n == "vendor") {
				return filepath.SkipDir // as the go command does
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		tags := nameTags(d.Name())
		if tags == nil {
			return nil
		}
		checked++
		rel, _ := filepath.Rel(root, path)
		e := goBuild(t, path)
		for _, tag := range tags {
			if e == nil || !positive(e, tag, false) {
				t.Errorf("%s: its name limits it to %s, but its //go:build line does not say so", rel, tag)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked == 0 {
		t.Fatal("no platform-named file found: the walk is not reading the repository")
	}
}

// The lists here are go/build's: every word the toolchain's
// internal/syslist names is in them (a new GOOS or GOARCH must be added).
func TestListsMatchTheToolchain(t *testing.T) {
	goroot, err := exec.Command("go", "env", "GOROOT").Output()
	if err != nil {
		t.Fatalf("go env GOROOT: %v", err)
	}
	src, err := os.ReadFile(filepath.Join(strings.TrimSpace(string(goroot)), "src", "internal", "syslist", "syslist.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, list := range []struct {
		name string
		ours map[string]bool
	}{{"KnownOS", knownOS}, {"KnownArch", knownArch}} {
		_, body, ok := strings.Cut(string(src), "var "+list.name+" = map[string]bool{")
		body, _, ok2 := strings.Cut(body, "}")
		if !ok || !ok2 {
			t.Fatalf("syslist.go has no %s", list.name)
		}
		theirs := regexp.MustCompile(`"([a-z0-9]+)":\s*true`).FindAllStringSubmatch(body, -1)
		if len(theirs) < 10 {
			t.Fatalf("%s: read %d words", list.name, len(theirs))
		}
		for _, m := range theirs {
			if !list.ours[m[1]] {
				t.Errorf("%s names %q, which this test's list lacks", list.name, m[1])
			}
		}
		if len(theirs) != len(list.ours) {
			t.Errorf("%s: %d words in the toolchain, %d here", list.name, len(theirs), len(list.ours))
		}
	}
}

// go/build's reading of names, and a negated tag.
func TestNameTagsAndPositive(t *testing.T) {
	for name, want := range map[string]string{
		"real_ios_test.go":         "ios",
		"real_iphone_test.go":      "",
		"ios_ext_test.go":          "",
		"linux.go":                 "",
		"x_linux_extra.go":         "",
		"x_linux_amd64.go":         "linux amd64",
		"x_darwin_arm64_test.go":   "darwin arm64",
		"x_zos_test.go":            "zos",
		"x_sparc64.go":             "sparc64",
		"x_amd64_linux.go":         "linux",
		"wipekey_race.go":          "",
		"probe_amd64.pb.go":        "amd64",
		"seccomp_linux_amd64.s.go": "linux amd64",
	} {
		if got := strings.Join(nameTags(name), " "); got != want {
			t.Errorf("%s: %q, want %q", name, got, want)
		}
	}
	for line, want := range map[string]bool{
		"//go:build ios":                     true,
		"//go:build !ios":                    false,
		"//go:build !(ios || linux)":         false,
		"//go:build linux && (ios || arm64)": true,
		"//go:build linux":                   false,
	} {
		e, err := constraint.Parse(line)
		if err != nil {
			t.Fatal(err)
		}
		if got := positive(e, "ios", false); got != want {
			t.Errorf("%s: %v, want %v", line, got, want)
		}
	}
}
