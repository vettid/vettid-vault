package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
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
	// The staging recovery request key and release R's minimum app
	// version (101) are pinned: the committed file as it is.
	if bytes.Contains(b, []byte("TODO-recovery-request-key")) || !bytes.Contains(b, []byte(`"android_min_version_code": 101`)) {
		t.Fatal("staging.json: the recovery request key or the minimum app version is not pinned")
	}
	stagingFile := filepath.Join(t.TempDir(), "staging.json")
	if err := os.WriteFile(stagingFile, b, 0o644); err != nil {
		t.Fatal(err)
	}
	staging := string(b)
	// The committed staging file passes rule 1 and names what it pins.
	code, out := check("staging", stagingFile)
	if code != 0 || !strings.Contains(out, "android package com.vettid.app.staging") || !strings.Contains(out, "iOS App ID 3X25CJ86MV.com.vettid.app.staging") ||
		!strings.Contains(out, "optional features: actions calls intro leash location presence wallet") ||
		!strings.Contains(out, "release log: Time scale: 1 day = 1 hour (staging)") {
		t.Fatalf("staging: %d %s", code, out)
	}
	// 0.43.0 (VAULT-RELEASES 0.1.32 §5.2): staging accepts only 1 or 24,
	// with the quiet period tied to it; at 1 the log says real time.
	realTime := strings.Replace(strings.Replace(staging, `"time_scale": 24`, `"time_scale": 1`, 1), `"recovery_quiet_seconds": 10800`, `"recovery_quiet_seconds": 259200`, 1)
	if code, out := check("staging", write("s-real.json", realTime)); code != 0 || !strings.Contains(out, "release log: Time scale: real time") {
		t.Fatalf("staging at 1: %d %s", code, out)
	}
	for name, bad := range map[string]string{
		"scale 12":            strings.Replace(staging, `"time_scale": 24`, `"time_scale": 12`, 1),
		"scale 0":             strings.Replace(staging, `"time_scale": 24`, `"time_scale": 0`, 1),
		"scale 24, quiet 72h": strings.Replace(staging, `"recovery_quiet_seconds": 10800`, `"recovery_quiet_seconds": 259200`, 1),
		"scale 1, quiet 3h":   strings.Replace(staging, `"time_scale": 24`, `"time_scale": 1`, 1),
		"no scale":            strings.Replace(staging, ",\n  \"time_scale\": 24", "", 1),
	} {
		if code, out := check("staging", write("s-bad.json", bad)); code != 1 {
			t.Errorf("staging %s: %d %s", name, code, out)
		}
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

// STAGING-DEVELOPMENT-PLAN §2.5.5, VAULT-RELEASES §3.1: the staging
// file's automation attestation switch has an end date; the gate refuses
// the file after it, judged at SOURCE_DATE_EPOCH when set (an image build
// and a rebuild from a tag) and at the current time otherwise.
func TestCheckAutomationEndDate(t *testing.T) {
	b, err := os.ReadFile("../../enclave/releasecfg/staging.json")
	if err != nil {
		t.Fatal(err)
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	until := now.AddDate(0, 0, 10)
	end := time.Date(until.Year(), until.Month(), until.Day(), 23, 0, 0, 0, time.UTC)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "TEST staging automation attestation CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: end, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	s := strings.TrimSuffix(strings.TrimSpace(string(b)), "}")
	s += `,"automation_attestation":{"android_roots":["` + base64.StdEncoding.EncodeToString(der) + `"],"until":"` + until.Format(time.DateOnly) + `"}}`
	p := filepath.Join(t.TempDir(), "staging.json")
	if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
	check := func(epoch string) (int, string) {
		t.Setenv("SOURCE_DATE_EPOCH", epoch)
		var out, errb bytes.Buffer
		code := run([]string{"check", "staging", p}, &out, &errb)
		return code, out.String() + errb.String()
	}
	if code, out := check(""); code != 0 || !strings.Contains(out, "staging automation attestation: 1 root(s), until "+until.Format(time.DateOnly)) {
		t.Fatalf("today: %d %s", code, out)
	}
	if code, out := check("0"); code != 0 { // the Dockerfile's default: today
		t.Fatalf("epoch 0: %d %s", code, out)
	}
	last := time.Date(until.Year(), until.Month(), until.Day(), 23, 59, 59, 0, time.UTC)
	if code, out := check(strconv.FormatInt(last.Unix(), 10)); code != 0 {
		t.Fatalf("last day: %d %s", code, out)
	}
	if code, out := check(strconv.FormatInt(last.Unix()+1, 10)); code != 1 || !strings.Contains(out, "past its end date") {
		t.Fatalf("the day after: %d %s", code, out)
	}
	// The same file for production is malformed.
	pp := filepath.Join(t.TempDir(), "prod.json")
	pb, err := os.ReadFile("../../enclave/releasecfg/prod.json")
	if err != nil {
		t.Fatal(err)
	}
	ps := strings.TrimSuffix(strings.TrimSpace(string(pb)), "}") + `,"automation_attestation":{"android_roots":["` + base64.StdEncoding.EncodeToString(der) + `"],"until":"` + until.Format(time.DateOnly) + `"}}`
	if err := os.WriteFile(pp, []byte(ps), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"check", "prod", pp}, &out, &errb); code != 1 || !strings.Contains(errb.String(), "malformed") {
		t.Fatalf("prod with automation: %d %s", code, errb.String())
	}
}
