package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The release gate as the build runs it (VAULT-MESSAGING 0.26.0 §11.10.8,
// "The release check"): rule 1 on the committed files, and rule 2 against
// the channel file of the channel's previous release (-previous).
func TestCheckCommand(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	check := func(args ...string) (int, string) {
		var out, errb bytes.Buffer
		code := run(append([]string{"check"}, args...), &out, &errb)
		return code, out.String() + errb.String()
	}
	b, err := os.ReadFile("../../enclave/releasecfg/staging.json")
	if err != nil {
		t.Fatal(err)
	}
	// Release R's minimum app version is open until it is known
	// (VAULT-RELEASES 0.1.28): the committed file with a test value in its
	// place. The staging recovery request key is pinned.
	if bytes.Contains(b, []byte("TODO-recovery-request-key")) {
		t.Fatal("staging.json: the recovery request key is not pinned")
	}
	b = bytes.Replace(b, []byte(`"android_min_version_code": 0`), []byte(`"android_min_version_code": 100`), 1)
	stagingFile := filepath.Join(t.TempDir(), "staging.json")
	if err := os.WriteFile(stagingFile, b, 0o644); err != nil {
		t.Fatal(err)
	}
	staging := string(b)
	// The committed staging file passes rule 1 and names what it pins.
	code, out := check("staging", stagingFile)
	if code != 0 || !strings.Contains(out, "android package com.vettid.app.staging") ||
		!strings.Contains(out, "optional features: actions calls intro leash location presence wallet") {
		t.Fatalf("staging: %d %s", code, out)
	}
	// Rule 2 against a previous file from before 0.26.0 (as tagged at
	// release/staging/1 to 9: no features member): all seven are owed.
	cut := func(s, from, to string) string {
		t.Helper()
		i, j := strings.Index(s, from), strings.Index(s, to)
		if i < 0 || j < i {
			t.Fatalf("cannot cut %q..%q", from, to)
		}
		return s[:i] + s[j:]
	}
	old := write("s9.json", cut(staging, ",\n  \"android_package\"", "\n}"))
	if strings.Contains(old, "features") {
		t.Fatal("the pre-0.26.0 fixture still has a list")
	}
	if code, out := check("-previous", old, "staging", stagingFile); code != 0 || !strings.Contains(out, "no feature of the previous release (7) dropped") {
		t.Fatalf("staging after a pre-0.26.0 release: %d %s", code, out)
	}
	// A list that dropped a name is refused, with the name.
	i := strings.Index(staging, `"features": [`)
	j := i + strings.Index(staging[i:], `]`)
	dropped := write("dropped.json", staging[:i]+`"features": ["actions", "calls", "intro", "leash", "location", "presence"`+staging[j:])
	if code, out := check("staging", dropped); code != 0 {
		t.Fatalf("rule 1 alone refused a shorter list: %s", out)
	}
	if code, out := check("-previous", old, "staging", dropped); code != 1 || !strings.Contains(out, "wallet") || !strings.Contains(out, "refusing to build") {
		t.Fatalf("dropped feature: %d %s", code, out)
	}
	if code, out := check("-previous", stagingFile, "staging", dropped); code != 1 || !strings.Contains(out, "wallet") {
		t.Fatalf("dropped feature after a 0.26.0 file: %d %s", code, out)
	}
	// A name added passes.
	if code, out := check("-previous", dropped, "staging", stagingFile); code != 0 {
		t.Fatalf("a name added: %d %s", code, out)
	}
	// Rule 1 through the command: out of order, an always-registered
	// name, the other channel's package.
	for name, content := range map[string]string{
		"order":   staging[:i] + `"features": ["calls", "actions"` + staging[j:],
		"always":  staging[:i] + `"features": ["audit"` + staging[j:],
		"package": strings.Replace(staging, `"com.vettid.app.staging"`, `"com.vettid.app"`, 1),
	} {
		if code, out := check("staging", write(name+".json", content)); code != 1 || !strings.Contains(out, "malformed") {
			t.Errorf("%s: %d %s", name, code, out)
		}
	}
	// A previous file of another channel, a missing one, bad usage.
	if code, _ := check("-previous", "../../enclave/releasecfg/prod.json", "staging", stagingFile); code != 1 {
		t.Fatal("another channel's previous file accepted")
	}
	if code, _ := check("-previous", filepath.Join(dir, "missing.json"), "staging", stagingFile); code != 1 {
		t.Fatal("a missing previous file accepted")
	}
	for _, bad := range [][]string{{}, {"dev"}, {"staging", "a", "b"}, {"-unknown", "staging"}} {
		if code, _ := check(bad...); code != 2 {
			t.Errorf("%v: exit %d", bad, code)
		}
	}
	var out2, err2 bytes.Buffer
	if code := run([]string{"build"}, &out2, &err2); code != 2 {
		t.Fatal("unknown subcommand")
	}
}
