package releasecfg

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"testing"
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
		`"android_signers":["` + strings.Repeat("ab", 32) + `"],"relay_url":"https://relay.vettid.org"}`
}

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
		if f.Config.Channel != ch || f.Config.SealRegion != "us-east-1" || f.Config.RelayURL != "https://relay.vettid.org" {
			t.Fatalf("%s: %+v", ch, f.Config)
		}
		if bytes.Contains(b, []byte(Placeholder)) != (len(f.Missing) > 0) {
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
		len(c.AndroidSigners) != 1 || len(c.AndroidSigners[0]) != 32 {
		t.Fatalf("%+v", c)
	}
	st := strings.NewReplacer(`"channel":"prod"`, `"channel":"staging"`, `"retirement_window_days":30`, `"retirement_window_days":7`).Replace(complete(t))
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
		"placeholder principal": {func(s string) string {
			return strings.Replace(s, "arn:aws:iam::111122223333:role/vettid-org-vault-key-retirement", "TODO-O1", 1)
		}, ErrIncomplete},
		"placeholder relay": {func(s string) string { return strings.Replace(s, "https://relay.vettid.org", "TODO-x", 1) }, ErrIncomplete},
		"release 0":         {func(s string) string { return strings.Replace(s, `"release":1`, `"release":0`, 1) }, ErrIncomplete},
		"wrong channel":     {func(s string) string { return strings.Replace(s, `"channel":"prod"`, `"channel":"staging"`, 1) }, ErrFormat},
		"unknown channel":   {func(s string) string { return strings.Replace(s, `"channel":"prod"`, `"channel":"dev"`, 1) }, ErrFormat},
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
		"release negative":  {func(s string) string { return strings.Replace(s, `"release":1`, `"release":-1`, 1) }, ErrFormat},
		"release as string": {func(s string) string { return strings.Replace(s, `"release":1`, `"release":"1"`, 1) }, ErrFormat},
	} {
		if _, err := Check(ChannelProd, []byte(tc.edit(base))); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v", name, err)
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
		if c, err := p.Complete(); err == nil && (c.Release == 0 || len(c.ManifestKeys) == 0 || c.SealAccount == "") {
			t.Fatal("complete without values")
		}
	})
}
