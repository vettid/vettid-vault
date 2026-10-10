package pushwire

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/vettid/vettid-relay/relayauth"
)

// PUSH-GATEWAY 0.4.0 §15: the signed registration request.
func TestVector(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, 32))
	if got := base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)); got != "7UkoxijRwsbq6QM4kFmVYSlZJzpcY/k2NsFGFKyHN9E=" {
		t.Fatalf("pubkey %s", got)
	}
	r := Registration{Platform: PlatformAPNs, Token: "740f4707bebcf74f9b7c25d48e3358945f6aa01da5ddb387462c7eaf61bb78ad",
		Environment: EnvProduction, AppID: "com.vettid.app"}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	body := r.Body()
	want := `{"platform":"apns","token":"740f4707bebcf74f9b7c25d48e3358945f6aa01da5ddb387462c7eaf61bb78ad","environment":"production","app_id":"com.vettid.app"}`
	if string(body) != want {
		t.Fatalf("body %s", body)
	}
	bh := relayauth.BodyHash(body)
	if hex.EncodeToString(bh[:]) != "b7c8170d637df5d636f997d15ac1e16f5900c18f6271f838d7f9e6c8a722881b" {
		t.Fatalf("body hash %x", bh)
	}
	c := relayauth.Canonical("POST", PathRegister, "2026-06-10T12:00:00Z", bh)
	if string(c) != "POST\n/v1/register\n2026-06-10T12:00:00Z\nb7c8170d637df5d636f997d15ac1e16f5900c18f6271f838d7f9e6c8a722881b" {
		t.Fatalf("canonical %q", c)
	}
	sig := relayauth.SignRequest(key, "POST", PathRegister, "2026-06-10T12:00:00Z", bh)
	if got := base64.StdEncoding.EncodeToString(sig); got != "3K+q6jDs868+0XetrLQXlddh8iZtKYeu5GRq6RZajyxRPIdDVh0dCYlkX59qFgL/wEhxs+sSzsOyH02gpsBQDA==" {
		t.Fatalf("sig %s", got)
	}
	// The registration parses back to itself.
	p, err := ParseRegistration(body)
	if err != nil || p != r {
		t.Fatalf("parse %+v %v", p, err)
	}
}

func TestValidate(t *testing.T) {
	hex64 := strings.Repeat("ab", 32)
	ok := []Registration{
		{Platform: "fcm", Token: "x", AppID: "a"},
		{Platform: "fcm", Token: strings.Repeat("~", MaxFCMToken), AppID: strings.Repeat("a", 255)},
		{Platform: "apns", Token: hex64, AppID: "com.vettid.app", Environment: "sandbox"},
		{Platform: "apns", Token: strings.Repeat("0f", 100), AppID: "A-b_c.9", Environment: "production"},
	}
	for _, r := range ok {
		if err := r.Validate(); err != nil {
			t.Errorf("%+v: %v", r, err)
		}
	}
	bad := map[string]Registration{
		"platform":        {Platform: "unifiedpush", Token: "x", AppID: "a"},
		"fcm empty token": {Platform: "fcm", Token: "", AppID: "a"},
		"fcm long token":  {Platform: "fcm", Token: strings.Repeat("a", MaxFCMToken+1), AppID: "a"},
		"fcm space":       {Platform: "fcm", Token: "a b", AppID: "a"},
		"fcm non-ascii":   {Platform: "fcm", Token: "é", AppID: "a"},
		"fcm env":         {Platform: "fcm", Token: "x", AppID: "a", Environment: "production"},
		"apns no env":     {Platform: "apns", Token: hex64, AppID: "a"},
		"apns bad env":    {Platform: "apns", Token: hex64, AppID: "a", Environment: "dev"},
		"apns upper":      {Platform: "apns", Token: strings.ToUpper(hex64), AppID: "a", Environment: "sandbox"},
		"apns short":      {Platform: "apns", Token: hex64[:62], AppID: "a", Environment: "sandbox"},
		"apns odd":        {Platform: "apns", Token: hex64 + "a", AppID: "a", Environment: "sandbox"},
		"apns long":       {Platform: "apns", Token: strings.Repeat("ab", 101), AppID: "a", Environment: "sandbox"},
		"app empty":       {Platform: "fcm", Token: "x", AppID: ""},
		"app long":        {Platform: "fcm", Token: "x", AppID: strings.Repeat("a", 256)},
		"app leading dot": {Platform: "fcm", Token: "x", AppID: ".a"},
		"app bad char":    {Platform: "fcm", Token: "x", AppID: "a/b"},
	}
	for name, r := range bad {
		if r.Validate() == nil {
			t.Errorf("%s accepted", name)
		}
	}
	for _, b := range []string{`{"platform":"fcm","token":"x","app_id":"a","extra":1}`, `{"platform":"fcm","token":"x"}`,
		`{"platform":"fcm","token":"x","app_id":"a","environment":""}`, `[]`, `{"platform":"fcm","token":1,"app_id":"a"}`} {
		if _, err := ParseRegistration([]byte(b)); err == nil {
			t.Errorf("parsed %s", b)
		}
	}
}

// §14.1 check 4: the hash's construction, and that every member counts.
func TestTokenHash(t *testing.T) {
	r := Registration{Platform: "apns", Token: strings.Repeat("ab", 32), AppID: "com.vettid.app", Environment: "sandbox"}
	h := sha256.New()
	h.Write([]byte("vettid/vms/2/push-token"))
	for _, s := range []string{r.Platform, r.AppID, r.Environment, r.Token} {
		h.Write(binary.BigEndian.AppendUint16(nil, uint16(len(s))))
		h.Write([]byte(s))
	}
	got := r.TokenHash()
	if !bytes.Equal(got[:], h.Sum(nil)) {
		t.Fatal("token hash")
	}
	f := Registration{Platform: "fcm", Token: "t", AppID: "a"}
	fh := f.TokenHash()
	for _, o := range []Registration{{Platform: "fcm", Token: "u", AppID: "a"}, {Platform: "fcm", Token: "t", AppID: "b"},
		{Platform: "apns", Token: "t", AppID: "a"}, {Platform: "fcm", Token: "t", AppID: "a", Environment: "sandbox"}} {
		oh := o.TokenHash()
		if EqualHash(fh[:], oh[:]) {
			t.Errorf("%+v hashes like %+v", o, f)
		}
	}
	if !EqualHash(fh[:], fh[:]) || EqualHash(fh[:], fh[:31]) {
		t.Fatal("EqualHash")
	}
}

func TestErrors(t *testing.T) {
	e := ParseError(429, []byte(`{"code":"rate_limited","retry_after":99999}`))
	if e.Code != CodeRateLimited || e.RetryAfter != MaxRetryAfter {
		t.Fatalf("%+v", e)
	}
	if e := ParseError(502, []byte(`<html>`)); e.Code != "http_502" || e.RetryAfter != 0 {
		t.Fatalf("%+v", e)
	}
	for _, c := range []struct {
		status int
		code   string
		gone   bool
	}{{410, CodeTokenGone, true}, {410, CodeBlobInvalid, true}, {400, CodeTokenInvalid, true}, {400, CodeBadRequest, false},
		{410, CodeTokenInvalid, false}, {429, CodeRateLimited, false}, {502, CodeProviderUnavailable, false}} {
		if (&Error{Status: c.status, Code: c.code}).Gone() != c.gone {
			t.Errorf("%d %s", c.status, c.code)
		}
	}
	if b := string(ErrorBody("rate_limited", 5)); b != `{"code":"rate_limited","retry_after":5}` {
		t.Fatal(b)
	}
}

func TestBlobsAndAnswers(t *testing.T) {
	if !ValidBlob("AQID_-x") || ValidBlob("") || ValidBlob("a=") || ValidBlob("a+b") || ValidBlob(strings.Repeat("a", MaxBlob+1)) {
		t.Fatal("ValidBlob")
	}
	if b, err := ParseRegistered([]byte(`{"wake_blob":"AQID"}`)); err != nil || b != "AQID" {
		t.Fatal(b, err)
	}
	if _, err := ParseRegistered([]byte(`{"wake_blob":"a b"}`)); err == nil {
		t.Fatal("bad blob accepted")
	}
	if r, err := ParseWoken([]byte(`{}`)); err != nil || r != "" {
		t.Fatal(r, err)
	}
	if r, err := ParseWoken([]byte(`{"reseal":"QUJD"}`)); err != nil || r != "QUJD" {
		t.Fatal(r, err)
	}
	if string(WakeBody("QUJD")) != `{"wake_blob":"QUJD","class":"notify"}` {
		t.Fatal("wake body")
	}
	if b, c, err := ParseWake(WakeBody("QUJD")); err != nil || b != "QUJD" || c != ClassNotify {
		t.Fatal(b, c, err)
	}
}
