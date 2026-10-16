package releasecfg

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func spki(t *testing.T, seed byte) string {
	k, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), bytes.Repeat([]byte{seed}, 32))
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

// complete is a filled-in production file (test values only).
func complete(t *testing.T) string {
	return `{"channel":"prod","release":1,"manifest_keys":["` + spki(t, 0x21) + `","` + spki(t, 0x23) + `"],` +
		`"seal_account":"111122223333","seal_region":"us-east-1",` +
		`"retirement_principal":"arn:aws:iam::111122223333:role/vettid-org-vault-key-retirement","retirement_window_days":30,` +
		`"android_signers":[{"digest":"` + strings.Repeat("ab", 32) + `","class":"vettid"}],"relay_url":"https://relay.vettid.org","push_url":"https://push.vettid.org",` +
		`"android_package":"com.vettid.app","features":[]` + recoveryMembers(t, "111122223333", 86400) + `}`
}

// recoveryMembers are release R's members (VAULT-MESSAGING 0.33.0
// §11.10.8) of a test file: the account's counter bucket, one request key.
func recoveryMembers(t *testing.T, account string, unit int) string {
	return `,"recovery_counter":{"bucket":"vettid-org-vault-recovery-` + account + `","account":"` + account + `","region":"us-east-1"},` +
		`"recovery_request_keys":[{"key_id":"test-key-1","spki":"` + spki(t, 0x25) + `"}],"recovery_wait_unit_seconds":` + strconv.Itoa(unit) +
		`,"recovery_quiet_seconds":259200,"recovery_offered":true,"android_min_version_code":100`
}

// releaseROpen are release R's members still open in production's file:
// its recovery request key until it exists, and its minimum app version
// until production's first app version of release R is known (staging's
// file has both: the staging key and app version 101).
var releaseROpen = map[string]bool{"recovery_request_keys": true, "android_min_version_code": true}

// fillReleaseR replaces those placeholders with test values.
func fillReleaseR(t *testing.T, b []byte) []byte {
	b = bytes.Replace(b, []byte(`"TODO-recovery-request-key-id"`), []byte(`"test-key-1"`), 1)
	b = bytes.Replace(b, []byte(`"TODO-recovery-request-key-spki"`), []byte(`"`+spki(t, 0x25)+`"`), 1)
	return bytes.Replace(b, []byte(`"android_min_version_code": 0`), []byte(`"android_min_version_code": 100`), 1)
}

// staging turns a production test file into a staging one.
func staging(s string) string {
	return strings.NewReplacer(`"channel":"prod"`, `"channel":"staging"`, `"retirement_window_days":30`, `"retirement_window_days":7`,
		`"push_url":"https://push.vettid.org"`, `"push_url":"https://push.staging.vettid.org"`,
		`"android_package":"com.vettid.app"`, `"android_package":"com.vettid.app.staging"`).Replace(s)
}

// withFeatures replaces the test file's (empty) feature list.
func withFeatures(s, list string) string {
	return strings.Replace(s, `"features":[]`, `"features":`+list, 1)
}

const allSeven = `["actions","calls","intro","leash","location","presence","wallet"]`

// The committed channel files parse, are their channel's, and are
// refused by the release gate while they hold placeholders.
func TestCommittedFiles(t *testing.T) {
	for _, ch := range []string{ChannelProd, ChannelStaging} {
		b, err := os.ReadFile(ch + ".json")
		if err != nil {
			t.Fatal(err)
		}
		f, err := Parse(b)
		if err != nil {
			t.Fatalf("%s: %v", ch, err)
		}
		if f.Config.Channel != ch || f.Config.SealRegion != "us-east-1" || f.Config.RelayURL != "https://relay.vettid.org" || f.Config.PushURL != PushURLs[ch] {
			t.Fatalf("%s: %+v", ch, f.Config)
		}
		// 0.26.0 (§11.10.8): staging registers all seven optional
		// features and accepts com.vettid.app.staging; production
		// registers none and accepts com.vettid.app.
		wantPkg, wantFeatures := "com.vettid.app", []string{}
		if ch == ChannelStaging {
			wantPkg, wantFeatures = "com.vettid.app.staging", OptionalFeatures()
		}
		if f.Config.AndroidPackage != wantPkg || f.Config.AndroidPackage != AndroidPackages[ch] || f.Config.Features == nil ||
			strings.Join(f.Config.Features, ",") != strings.Join(wantFeatures, ",") {
			t.Fatalf("%s: package %q, features %v", ch, f.Config.AndroidPackage, f.Config.Features)
		}
		// A placeholder is always reported missing; a value can also be
		// missing without one (release 0 before the first release).
		if bytes.Contains(b, []byte(Placeholder)) && len(f.Missing) == 0 {
			t.Fatalf("%s: placeholders %v", ch, f.Missing)
		}
		if len(f.Missing) > 0 {
			if _, err := Check(ch, b); !errors.Is(err, ErrIncomplete) {
				t.Fatalf("%s: release gate passed a file with placeholders: %v", ch, err)
			}
		}
		other := ChannelStaging
		if ch == ChannelStaging {
			other = ChannelProd
		}
		if _, err := Check(other, b); err == nil {
			t.Fatalf("%s file accepted as %s", ch, other)
		}
	}
}

// The binary's embedded file is the committed file of its channel (run
// with -tags vettid_channel_prod / vettid_channel_staging in CI), and an
// incomplete file pins nothing.
func TestEmbedded(t *testing.T) {
	ch, c := Embedded()
	if ch != channel {
		t.Fatal("channel")
	}
	if ch == "" {
		if c != nil || embedded != nil {
			t.Fatal("a build without a channel embeds constants")
		}
		return
	}
	b, err := os.ReadFile(ch + ".json")
	if err != nil || !bytes.Equal(b, embedded) {
		t.Fatal("embedded file differs from the committed file")
	}
	if _, err := Check(ch, b); (err == nil) != (c != nil) {
		t.Fatalf("embedded constants despite %v", err)
	}
}

func TestCompletePasses(t *testing.T) {
	c, err := Check(ChannelProd, []byte(complete(t)))
	if err != nil {
		t.Fatal(err)
	}
	if c.Release != 1 || len(c.ManifestKeys) != 2 || c.SealAccount != "111122223333" || c.RetirementWindowDays != 30 ||
		len(c.AndroidSigners) != 1 || len(c.AndroidSigners[0].Digest) != 32 || c.AndroidSigners[0].Class != "vettid" {
		t.Fatalf("%+v", c)
	}
	if c.AndroidPackage != "com.vettid.app" || c.Features == nil || len(c.Features) != 0 {
		t.Fatalf("%+v", c)
	}
	st := staging(complete(t))
	if _, err := Check(ChannelStaging, []byte(st)); err != nil {
		t.Fatal(err)
	}
}

func TestRefusals(t *testing.T) {
	base := complete(t)
	for name, tc := range map[string]struct {
		edit func(string) string
		want error
	}{
		"placeholder key": {func(s string) string { return strings.Replace(s, spki(t, 0x23), "TODO-O3", 1) }, ErrIncomplete},
		"placeholder account": {func(s string) string {
			return strings.Replace(s, `"seal_account":"111122223333"`, `"seal_account":"TODO-O1"`, 1)
		}, ErrIncomplete},
		"placeholder signer": {func(s string) string { return strings.Replace(s, strings.Repeat("ab", 32), "TODO-O8", 1) }, ErrIncomplete},
		"bare signer list (before 0.27.0)": {func(s string) string {
			return strings.Replace(s, `[{"digest":"`+strings.Repeat("ab", 32)+`","class":"vettid"}]`, `["`+strings.Repeat("ab", 32)+`"]`, 1)
		}, ErrFormat},
		"placeholder principal": {func(s string) string {
			return strings.Replace(s, "arn:aws:iam::111122223333:role/vettid-org-vault-key-retirement", "TODO-O1", 1)
		}, ErrIncomplete},
		"placeholder relay": {func(s string) string { return strings.Replace(s, "https://relay.vettid.org", "TODO-x", 1) }, ErrIncomplete},
		"placeholder push":  {func(s string) string { return strings.Replace(s, "https://push.vettid.org", "TODO-x", 1) }, ErrIncomplete},
		"other channel's push": {func(s string) string {
			return strings.Replace(s, "https://push.vettid.org", "https://push.staging.vettid.org", 1)
		}, ErrFormat},
		"push with a path": {func(s string) string {
			return strings.Replace(s, "https://push.vettid.org", "https://push.vettid.org/v1", 1)
		}, ErrFormat},
		"release 0":       {func(s string) string { return strings.Replace(s, `"release":1`, `"release":0`, 1) }, ErrIncomplete},
		"wrong channel":   {func(s string) string { return strings.Replace(s, `"channel":"prod"`, `"channel":"staging"`, 1) }, ErrFormat},
		"unknown channel": {func(s string) string { return strings.Replace(s, `"channel":"prod"`, `"channel":"dev"`, 1) }, ErrFormat},
		"prod window 7": {func(s string) string {
			return strings.Replace(s, `"retirement_window_days":30`, `"retirement_window_days":7`, 1)
		}, ErrFormat},
		"unknown member":   {func(s string) string { return strings.Replace(s, `"release":1`, `"release":1,"extra":1`, 1) }, ErrFormat},
		"missing member":   {func(s string) string { return strings.Replace(s, `"seal_region":"us-east-1",`, ``, 1) }, ErrFormat},
		"duplicate member": {func(s string) string { return strings.Replace(s, `"release":1`, `"release":1,"release":1`, 1) }, ErrFormat},
		"three keys": {func(s string) string {
			return strings.Replace(s, `"]`+`,"seal_account"`, `","`+spki(t, 0x24)+`"],"seal_account"`, 1)
		}, ErrFormat},
		"same key twice": {func(s string) string { return strings.Replace(s, spki(t, 0x23), spki(t, 0x21), 1) }, ErrFormat},
		"key not base64": {func(s string) string { return strings.Replace(s, spki(t, 0x23), "not base64!", 1) }, ErrFormat},
		"no keys":        {func(s string) string { return strings.Replace(s, `["`+spki(t, 0x21)+`","`+spki(t, 0x23)+`"]`, `[]`, 1) }, ErrFormat},
		"account short": {func(s string) string {
			return strings.Replace(s, `"seal_account":"111122223333"`, `"seal_account":"11112222333"`, 1)
		}, ErrFormat},
		"root principal": {func(s string) string { return strings.Replace(s, "role/vettid-org-vault-key-retirement", "root", 1) }, ErrFormat},
		"principal other account": {func(s string) string {
			return strings.Replace(s, "arn:aws:iam::111122223333:role", "arn:aws:iam::444455556666:role", 1)
		}, ErrFormat},
		"signer upper hex": {func(s string) string {
			return strings.Replace(s, strings.Repeat("ab", 32), strings.Repeat("AB", 32), 1)
		}, ErrFormat},
		"signer short": {func(s string) string {
			return strings.Replace(s, strings.Repeat("ab", 32), strings.Repeat("ab", 31), 1)
		}, ErrFormat},
		"relay http": {func(s string) string {
			return strings.Replace(s, "https://relay.vettid.org", "http://relay.vettid.org", 1)
		}, ErrFormat},
		"relay with path": {func(s string) string {
			return strings.Replace(s, "https://relay.vettid.org", "https://relay.vettid.org/x", 1)
		}, ErrFormat},
		"relay with port": {func(s string) string {
			return strings.Replace(s, "https://relay.vettid.org", "https://relay.vettid.org:444", 1)
		}, ErrFormat},
		// 0.26.0, android_package: missing, a placeholder, another
		// channel's value, anything else.
		"package missing": {func(s string) string { return strings.Replace(s, `"android_package":"com.vettid.app",`, ``, 1) }, ErrFormat},
		"package placeholder": {func(s string) string {
			return strings.Replace(s, `"android_package":"com.vettid.app"`, `"android_package":"TODO-D5"`, 1)
		}, ErrIncomplete},
		"other channel's package": {func(s string) string {
			return strings.Replace(s, `"android_package":"com.vettid.app"`, `"android_package":"com.vettid.app.staging"`, 1)
		}, ErrFormat},
		"another package": {func(s string) string {
			return strings.Replace(s, `"android_package":"com.vettid.app"`, `"android_package":"com.example.app"`, 1)
		}, ErrFormat},
		"package empty": {func(s string) string {
			return strings.Replace(s, `"android_package":"com.vettid.app"`, `"android_package":""`, 1)
		}, ErrFormat},
		"package as a list": {func(s string) string {
			return strings.Replace(s, `"android_package":"com.vettid.app"`, `"android_package":["com.vettid.app"]`, 1)
		}, ErrFormat},
		// 0.26.0, features, the release check's rule 1.
		"features missing":       {func(s string) string { return strings.Replace(s, `,"features":[]`, ``, 1) }, ErrFormat},
		"features null":          {func(s string) string { return withFeatures(s, `null`) }, ErrFormat},
		"features a string":      {func(s string) string { return withFeatures(s, `"calls"`) }, ErrFormat},
		"features an object":     {func(s string) string { return withFeatures(s, `{"calls":true}`) }, ErrFormat},
		"features not strings":   {func(s string) string { return withFeatures(s, `["calls",1]`) }, ErrFormat},
		"features a nested list": {func(s string) string { return withFeatures(s, `[["calls"]]`) }, ErrFormat},
		"features placeholder":   {func(s string) string { return withFeatures(s, `["TODO-D4"]`) }, ErrFormat},
		"features unknown name":  {func(s string) string { return withFeatures(s, `["calls","teleport"]`) }, ErrFormat},
		"features empty name":    {func(s string) string { return withFeatures(s, `[""]`) }, ErrFormat},
		"features upper case":    {func(s string) string { return withFeatures(s, `["Calls"]`) }, ErrFormat},
		"features repeated":      {func(s string) string { return withFeatures(s, `["calls","calls"]`) }, ErrFormat},
		"features out of order":  {func(s string) string { return withFeatures(s, `["leash","calls"]`) }, ErrFormat},
		"features eight":         {func(s string) string { return withFeatures(s, strings.Replace(allSeven, `]`, `,"wallet"]`, 1)) }, ErrFormat},
		"release negative":       {func(s string) string { return strings.Replace(s, `"release":1`, `"release":-1`, 1) }, ErrFormat},
		"release as string":      {func(s string) string { return strings.Replace(s, `"release":1`, `"release":"1"`, 1) }, ErrFormat},
	} {
		if _, err := Check(ChannelProd, []byte(tc.edit(base))); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// 0.26.0 (§11.10.8): the always-registered features are not names of the
// list, so no file can name one (and none can be switched off by leaving
// it out); every one of the seven optional names, alone and together, is
// accepted.
func TestFeatureNames(t *testing.T) {
	for _, n := range []string{"audit", "feed", "messaging", "credential", "items", "grants", "critical", "connauth"} {
		if _, err := Check(ChannelProd, []byte(withFeatures(complete(t), `["`+n+`"]`))); !errors.Is(err, ErrFormat) {
			t.Errorf("always-registered feature %s accepted in the list: %v", n, err)
		}
	}
	opt := OptionalFeatures()
	if strings.Join(opt, ",") != "actions,calls,intro,leash,location,presence,wallet" {
		t.Fatalf("optional features %v", opt)
	}
	for _, n := range opt {
		c, err := Check(ChannelProd, []byte(withFeatures(complete(t), `["`+n+`"]`)))
		if err != nil || len(c.Features) != 1 || c.Features[0] != n {
			t.Errorf("%s: %v", n, err)
		}
	}
	c, err := Check(ChannelStaging, []byte(withFeatures(staging(complete(t)), allSeven)))
	if err != nil || strings.Join(c.Features, ",") != strings.Join(opt, ",") {
		t.Fatalf("all seven: %v %v", c, err)
	}
	// The returned list is a copy: a caller cannot change the package's.
	opt[0] = "x"
	if OptionalFeatures()[0] != "actions" {
		t.Fatal("OptionalFeatures returned the package's own slice")
	}
}

// pre026 is a channel file as releases before 0.26.0 had it: no
// android_package, no features, bare signer digests.
func pre026(t *testing.T, channel string) string {
	s := strings.Replace(complete(t), `,"android_package":"com.vettid.app","features":[]`, ``, 1)
	s = strings.Replace(s, `[{"digest":"`+strings.Repeat("ab", 32)+`","class":"vettid"}]`, `["`+strings.Repeat("ab", 32)+`"]`, 1)
	if channel == ChannelStaging {
		s = staging(s)
	}
	return s
}

// 0.26.0 (§11.10.8), the release check's rule 2: a channel's list only
// grows. A name the previous release listed and this file lacks is
// refused; a name added passes; a previous file from before 0.26.0 counts
// as listing all seven.
func TestFeaturesOnlyGrow(t *testing.T) {
	cfg := func(list string) *Config {
		t.Helper()
		c, err := Check(ChannelStaging, []byte(withFeatures(staging(complete(t)), list)))
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	prev := func(list string) []string {
		t.Helper()
		p, err := PreviousFeatures(ChannelStaging, []byte(withFeatures(staging(complete(t)), list)))
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	// A name dropped is refused, and the error names it.
	err := CheckGrows(cfg(`["calls"]`), prev(`["calls","leash"]`))
	if !errors.Is(err, ErrFeatureRemoved) || !strings.Contains(err.Error(), "leash") || strings.Contains(err.Error(), "calls") {
		t.Fatalf("dropped name: %v", err)
	}
	if err := CheckGrows(cfg(`[]`), prev(`["wallet"]`)); !errors.Is(err, ErrFeatureRemoved) {
		t.Fatalf("emptied list: %v", err)
	}
	// A name added passes; so does the same list, and the first list.
	for _, tc := range [][2]string{{`["calls","leash"]`, `["calls"]`}, {`["calls"]`, `["calls"]`}, {`[]`, `[]`}, {allSeven, `[]`}, {allSeven, allSeven}} {
		if err := CheckGrows(cfg(tc[0]), prev(tc[1])); err != nil {
			t.Errorf("%s after %s: %v", tc[0], tc[1], err)
		}
	}
	// A previous file from before 0.26.0 counts as all seven: only the
	// full list passes after it.
	old, err := PreviousFeatures(ChannelStaging, []byte(pre026(t, ChannelStaging)))
	if err != nil || strings.Join(old, ",") != strings.Join(OptionalFeatures(), ",") {
		t.Fatalf("previous file from before 0.26.0: %v %v", old, err)
	}
	if err := CheckGrows(cfg(allSeven), old); err != nil {
		t.Fatalf("all seven after a pre-0.26.0 file: %v", err)
	}
	for _, list := range []string{`[]`, `["calls"]`, `["actions","calls","intro","leash","location","presence"]`} {
		if err := CheckGrows(cfg(list), old); !errors.Is(err, ErrFeatureRemoved) {
			t.Errorf("%s after a pre-0.26.0 file: %v", list, err)
		}
	}
	// The pre-0.26.0 file itself is no longer a valid channel file.
	if _, err := Parse([]byte(pre026(t, ChannelStaging))); !errors.Is(err, ErrFormat) {
		t.Fatalf("a file without features and android_package parsed: %v", err)
	}
	// The previous file is read leniently (its own release's format),
	// but it must be the channel's, and a list it has must be well-formed.
	if _, err := PreviousFeatures(ChannelProd, []byte(pre026(t, ChannelStaging))); !errors.Is(err, ErrChannel) {
		t.Fatalf("another channel's previous file: %v", err)
	}
	for _, bad := range []string{``, `[]`, `{"features":[]}`, `{"channel":"dev"}`, withFeatures(staging(complete(t)), `["leash","calls"]`),
		withFeatures(staging(complete(t)), `"all"`), withFeatures(staging(complete(t)), `["audit"]`)} {
		if _, err := PreviousFeatures(ChannelStaging, []byte(bad)); !errors.Is(err, ErrFormat) {
			t.Errorf("previous file %q: %v", bad, err)
		}
	}
	// The committed staging file after the last tagged format (S1 to S9
	// had no list): it must list all seven, and does.
	b, err := os.ReadFile("staging.json")
	if err != nil {
		t.Fatal(err)
	}
	f, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckGrows(&f.Config, old); err != nil {
		t.Fatalf("staging.json after a pre-0.26.0 release: %v", err)
	}
}

// withSigners replaces the test file's signer list.
func withSigners(s, list string) string {
	return strings.Replace(s, `[{"digest":"`+strings.Repeat("ab", 32)+`","class":"vettid"}]`, list, 1)
}

func signer(hexByte, class string) string {
	return `{"digest":"` + strings.Repeat(hexByte, 32) + `","class":"` + class + `"}`
}

// VAULT-MESSAGING 0.27.0 §11.10.8, VAULT-RELEASES 0.1.12 §5.2:
// android_signers is 1 to 4 entries {digest, class} with distinct
// digests. The release build refuses an entry without a class, an unknown
// class, a duplicate digest, the bare-string form and, in the production
// file, class development.
func TestAndroidSigners(t *testing.T) {
	prod, stg := complete(t), staging(complete(t))
	ok := func(channel, file string, classes ...string) {
		t.Helper()
		c, err := Check(channel, []byte(file))
		if err != nil {
			t.Fatalf("%v", err)
		}
		if len(c.AndroidSigners) != len(classes) {
			t.Fatalf("signers %+v", c.AndroidSigners)
		}
		for i, cl := range classes {
			if c.AndroidSigners[i].Class != cl || len(c.AndroidSigners[i].Digest) != 32 {
				t.Fatalf("signer %d: %+v", i, c.AndroidSigners[i])
			}
		}
	}
	ok(ChannelProd, prod, "vettid")
	ok(ChannelProd, withSigners(prod, `[`+signer("ab", "vettid")+`,`+signer("cd", "google_play")+`]`), "vettid", "google_play")
	ok(ChannelStaging, withSigners(stg, `[`+signer("ab", "vettid")+`,`+signer("cd", "development")+`]`), "vettid", "development")
	ok(ChannelStaging, withSigners(stg, `[`+signer("a1", "vettid")+`,`+signer("a2", "google_play")+`,`+signer("a3", "development")+`,`+signer("a4", "development")+`]`),
		"vettid", "google_play", "development", "development")
	for name, tc := range map[string]struct {
		channel, list string
		want          error
	}{
		"bare string":             {ChannelProd, `["` + strings.Repeat("ab", 32) + `"]`, ErrFormat},
		"bare string beside one":  {ChannelProd, `[` + signer("ab", "vettid") + `,"` + strings.Repeat("cd", 32) + `"]`, ErrFormat},
		"no class":                {ChannelProd, `[{"digest":"` + strings.Repeat("ab", 32) + `"}]`, ErrFormat},
		"no digest":               {ChannelProd, `[{"class":"vettid"}]`, ErrFormat},
		"unknown class":           {ChannelProd, `[` + signer("ab", "play") + `]`, ErrFormat},
		"empty class":             {ChannelProd, `[` + signer("ab", "") + `]`, ErrFormat},
		"class upper case":        {ChannelProd, `[` + signer("ab", "Vettid") + `]`, ErrFormat},
		"class not a string":      {ChannelProd, `[{"digest":"` + strings.Repeat("ab", 32) + `","class":1}]`, ErrFormat},
		"extra member":            {ChannelProd, `[{"digest":"` + strings.Repeat("ab", 32) + `","class":"vettid","note":"x"}]`, ErrFormat},
		"duplicate digest":        {ChannelProd, `[` + signer("ab", "vettid") + `,` + signer("ab", "google_play") + `]`, ErrFormat},
		"duplicate entry":         {ChannelProd, `[` + signer("ab", "vettid") + `,` + signer("ab", "vettid") + `]`, ErrFormat},
		"development in prod":     {ChannelProd, `[` + signer("ab", "development") + `]`, ErrFormat},
		"development beside prod": {ChannelProd, `[` + signer("ab", "vettid") + `,` + signer("cd", "development") + `]`, ErrFormat},
		"no entries":              {ChannelProd, `[]`, ErrFormat},
		"five entries":            {ChannelStaging, `[` + signer("a1", "vettid") + `,` + signer("a2", "vettid") + `,` + signer("a3", "vettid") + `,` + signer("a4", "vettid") + `,` + signer("a5", "vettid") + `]`, ErrFormat},
		"digest upper hex":        {ChannelProd, `[` + signer("AB", "vettid") + `]`, ErrFormat},
		"digest short":            {ChannelProd, `[{"digest":"` + strings.Repeat("ab", 31) + `","class":"vettid"}]`, ErrFormat},
		"not an array":            {ChannelProd, signer("ab", "vettid"), ErrFormat},
		"entry an array":          {ChannelProd, `[["` + strings.Repeat("ab", 32) + `","vettid"]]`, ErrFormat},
		"placeholder digest":      {ChannelProd, `[{"digest":"TODO-O8","class":"google_play"}]`, ErrIncomplete},
		"placeholder entry":       {ChannelProd, `["TODO-O8: the Play app signing certificate",` + signer("ab", "vettid") + `]`, ErrFormat},
	} {
		file := withSigners(prod, tc.list)
		if tc.channel == ChannelStaging {
			file = withSigners(stg, tc.list)
		}
		if _, err := Check(tc.channel, []byte(file)); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// development is a staging class: the same entry passes there.
	ok(ChannelStaging, withSigners(stg, `[`+signer("ab", "development")+`]`), "development")
}

// The committed files (0.27.0 §11.10.8; VAULT-RELEASES 0.1.12 §5.2;
// W10-READINESS 0.1.7): production pins exactly VettID's own release
// certificate, class vettid, with no placeholder left for the Play
// certificate (O8 as amended), so the gate refuses production only for
// its release number; staging pins its signing certificate (vettid) and
// the automation certificate (development).
func TestCommittedSigners(t *testing.T) {
	read := func(ch string) (*File, []byte) {
		t.Helper()
		b, err := os.ReadFile(ch + ".json")
		if err != nil {
			t.Fatal(err)
		}
		f, err := Parse(b)
		if err != nil {
			t.Fatalf("%s: %v", ch, err)
		}
		return f, b
	}
	hexOf := func(s Signer) string { return hex.EncodeToString(s.Digest) }
	p, pb := read(ChannelProd)
	if len(p.Config.AndroidSigners) != 1 || p.Config.AndroidSigners[0].Class != "vettid" ||
		hexOf(p.Config.AndroidSigners[0]) != "31a19613aa10f209e08945f947f94f7ce3e6e5ac342457ff9969a67986928e65" {
		t.Fatalf("prod signers %+v", p.Config.AndroidSigners)
	}
	if bytes.Contains(fillReleaseR(t, pb), []byte(Placeholder)) {
		t.Fatal("prod.json still holds a placeholder")
	}
	pb = fillReleaseR(t, pb)
	for _, m := range p.Missing {
		if m != "release" && !releaseROpen[m] {
			t.Fatalf("prod.json is refused for %q; only the release number may be open", m)
		}
	}
	// With its release number set, production's file passes the gate.
	one := bytes.Replace(pb, []byte(`"release": 0`), []byte(`"release": 1`), 1)
	c, err := Check(ChannelProd, one)
	if err != nil {
		t.Fatalf("prod.json with release 1: %v", err)
	}
	if c.AcceptsUnbound() {
		t.Fatal("production accepts unbound vaults")
	}
	s, _ := read(ChannelStaging)
	if len(s.Config.AndroidSigners) != 2 ||
		hexOf(s.Config.AndroidSigners[0]) != "bd83a0753faa6af6f8d81b9f76a04ac1a499ea6c7f46c6f1113d4b5787ecb2c4" || s.Config.AndroidSigners[0].Class != "vettid" ||
		hexOf(s.Config.AndroidSigners[1]) != "2fed27b72746797a931fd414ff3dac4cd969fa0c2ff36209ae05365f580014f2" || s.Config.AndroidSigners[1].Class != "development" {
		t.Fatalf("staging signers %+v", s.Config.AndroidSigners)
	}
}

// §11.7.1, "Vaults enrolled before 0.27.0": a key without a recorded
// signer unlocks unbound only in the staging channel and only up to S10
// (StagingUnboundThrough); from the staging release after it, and in
// every production release whatever its number, it is refused. The
// exception is a function of the measured channel and release number: no
// member of a channel file can turn it on.
func TestAcceptsUnbound(t *testing.T) {
	at := func(file string, channel string, release uint64) bool {
		t.Helper()
		c, err := Check(channel, []byte(strings.Replace(file, `"release":1`, `"release":`+strconv.FormatUint(release, 10), 1)))
		if err != nil {
			t.Fatal(err)
		}
		return c.AcceptsUnbound()
	}
	if StagingUnboundThrough != 10 {
		t.Fatalf("the staging exception ends at release %d, the spec says S10", StagingUnboundThrough)
	}
	for _, n := range []uint64{1, 9, 10} {
		if !at(staging(complete(t)), ChannelStaging, n) {
			t.Errorf("staging release %d refuses unbound vaults", n)
		}
	}
	for _, n := range []uint64{11, 12, 100} {
		if at(staging(complete(t)), ChannelStaging, n) {
			t.Errorf("staging release %d accepts unbound vaults", n)
		}
	}
	for _, n := range []uint64{1, 2, 9, 10, 11} {
		if at(complete(t), ChannelProd, n) {
			t.Errorf("production release %d accepts unbound vaults", n)
		}
	}
	var none *Config
	if none.AcceptsUnbound() {
		t.Fatal("no configuration accepts unbound vaults")
	}
	// No member of the file expresses it.
	for _, member := range []string{`"accept_unbound":true`, `"android_accept_unbound":true`, `"unbound":true`} {
		file := strings.Replace(complete(t), `"release":1`, `"release":1,`+member, 1)
		if _, err := Check(ChannelProd, []byte(file)); !errors.Is(err, ErrFormat) {
			t.Errorf("%s accepted in a production file: %v", member, err)
		}
	}
}

// VAULT-MESSAGING 0.33.2 §11.14.4: the counter's token, success and
// close records are locked for one day on staging and 100 years in
// production. The period is a function of the measured channel alone: no
// member of a channel file sets it, and anything but the staging channel
// (no configuration included) gets the long one.
func TestCounterLock(t *testing.T) {
	year := 365 * 24 * time.Hour
	if ProdCounterLock != 100*year || StagingCounterLock != 24*time.Hour {
		t.Fatalf("periods %v / %v", ProdCounterLock, StagingCounterLock)
	}
	p, err := Check(ChannelProd, []byte(complete(t)))
	if err != nil {
		t.Fatal(err)
	}
	s, err := Check(ChannelStaging, []byte(staging(complete(t))))
	if err != nil {
		t.Fatal(err)
	}
	if p.CounterLock() != ProdCounterLock || s.CounterLock() != StagingCounterLock {
		t.Fatalf("production %v, staging %v", p.CounterLock(), s.CounterLock())
	}
	var none *Config
	if none.CounterLock() != ProdCounterLock || (&Config{}).CounterLock() != ProdCounterLock {
		t.Fatal("no channel: not the long lock")
	}
	for _, member := range []string{`"counter_lock_seconds":86400`, `"recovery_counter_lock_seconds":86400`, `"recovery_lock_days":1`} {
		for _, ch := range []string{ChannelProd, ChannelStaging} {
			file := complete(t)
			if ch == ChannelStaging {
				file = staging(file)
			}
			file = strings.Replace(file, `"release":1`, `"release":1,`+member, 1)
			if _, err := Check(ch, []byte(file)); !errors.Is(err, ErrFormat) {
				t.Errorf("%s accepted in a %s file: %v", member, ch, err)
			}
		}
	}
}

func FuzzParse(f *testing.F) {
	for _, ch := range []string{ChannelProd, ChannelStaging} {
		if b, err := os.ReadFile(ch + ".json"); err == nil {
			f.Add(b)
		}
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := Parse(b)
		if err != nil {
			return
		}
		if c, err := p.Complete(); err == nil && (c.Release == 0 || len(c.ManifestKeys) == 0 || c.SealAccount == "" ||
			c.AndroidPackage != AndroidPackages[c.Channel] || c.Features == nil || len(c.AndroidSigners) == 0) {
			t.Fatal("complete without values")
		}
		seen := map[string]bool{}
		for _, sg := range p.Config.AndroidSigners {
			if len(sg.Digest) != 32 || seen[string(sg.Digest)] || sg.Class != "vettid" && sg.Class != "google_play" && sg.Class != "development" ||
				p.Config.Channel == ChannelProd && sg.Class == "development" {
				t.Fatalf("signers %+v", p.Config.AndroidSigners)
			}
			seen[string(sg.Digest)] = true
		}
		if p.Config.Channel == ChannelProd && p.Config.AcceptsUnbound() {
			t.Fatal("a production file accepts unbound vaults")
		}
		for i, n := range p.Config.Features {
			if !isOptional(n) || i > 0 && p.Config.Features[i-1] >= n {
				t.Fatalf("features %v", p.Config.Features)
			}
		}
		// The previous-file reader never panics on a parsed file.
		if _, err := PreviousFeatures(p.Config.Channel, b); err != nil {
			t.Fatalf("PreviousFeatures on a valid file: %v", err)
		}
	})
}

// FuzzPreviousFeatures fuzzes the reader of a previous release's channel
// file, which reads files this release's parser would refuse: whatever it
// returns is a list of optional feature names, each once, ascending, for
// the channel asked for; and a file the strict parser accepts is read.
func FuzzPreviousFeatures(f *testing.F) {
	for _, ch := range []string{ChannelProd, ChannelStaging} {
		if b, err := os.ReadFile(ch + ".json"); err == nil {
			f.Add(b, ch == ChannelStaging)
		}
	}
	for _, s := range []string{
		`{"channel":"staging"}`,
		`{"channel":"prod","features":[]}`,
		`{"channel":"staging","features":["calls","wallet"]}`,
		`{"channel":"staging","features":["wallet","calls"]}`,
		`{"channel":"staging","features":["calls","calls"]}`,
		`{"channel":"staging","features":["messaging"]}`,
		`{"channel":"staging","features":"calls"}`,
		`{"channel":"staging","features":[1]}`,
		`{"channel":"dev","features":[]}`,
		`{"channel":"staging","channel":"prod"}`,
		`{"features":[]}`,
		`[]`,
	} {
		f.Add([]byte(s), true)
		f.Add([]byte(s), false)
	}
	f.Fuzz(func(t *testing.T, b []byte, stagingChannel bool) {
		channel := ChannelProd
		if stagingChannel {
			channel = ChannelStaging
		}
		got, err := PreviousFeatures(channel, b)
		if p, perr := Parse(b); perr == nil && p.Config.Channel == channel && err != nil {
			t.Fatalf("a file the parser accepts is not read: %v", err)
		}
		if err != nil {
			if got != nil || !errors.Is(err, ErrFormat) && !errors.Is(err, ErrChannel) {
				t.Fatalf("%v with %v", err, got)
			}
			return
		}
		if got == nil {
			t.Fatal("no list and no error")
		}
		for i, n := range got {
			if !isOptional(n) || i > 0 && got[i-1] >= n {
				t.Fatalf("features %v", got)
			}
		}
		// The list read back is one this release's rule 2 can compare.
		if err := CheckGrows(&Config{Channel: channel, Features: got}, got); err != nil {
			t.Fatalf("a list does not contain itself: %v", err)
		}
	})
}
