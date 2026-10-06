package vectors

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"

	"github.com/vettid/vettid-vault/vms/altchan"
)

func TestAppKeyVectors(t *testing.T) { checkAppKeyVectors(t, Dir) }

// checkAppKeyVectors re-derives appkey.json (0.15.0 §11.12) independently
// of altchan where it can, and through altchan's parsers.
func checkAppKeyVectors(t *testing.T, dir string) {
	d := load(t, dir, "appkey.json")
	k, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), d.hex("app_key_scalar_hex"))
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	eq(t, "spki", der, d.b64("app_key_spki_b64"))
	h := sha256.Sum256(der)
	if d.str("akid") != hex.EncodeToString(h[:16]) || altchan.AppKeyID(der) != d.str("akid") {
		t.Error("akid")
	}
	if d.str("label") != "vettid/member-api/app/1" {
		t.Error("label")
	}
	for _, name := range []string{"unlock_request", "redeem_request", "enclave_request"} {
		r := d.sub(name)
		bh := sha256.Sum256([]byte(r.str("body")))
		if r.str("body_sha256_hex") != hex.EncodeToString(bh[:]) {
			t.Errorf("%s body hash", name)
		}
		want := strings.Join([]string{"vettid/member-api/app/1", r.str("method"), r.str("path"), r.str("query"), r.str("vault_id"),
			d.str("akid"), strconv.Itoa(r.num("ts")), r.str("nonce"), hex.EncodeToString(bh[:])}, "\n")
		if r.str("signing_string") != want {
			t.Errorf("%s signing string:\n%q\nwant\n%q", name, r.str("signing_string"), want)
		}
		sig, err := base64.RawURLEncoding.DecodeString(r.str("sig_b64url"))
		sh := sha256.Sum256([]byte(want))
		if err != nil || !ecdsa.VerifyASN1(&k.PublicKey, sh[:], sig) {
			t.Errorf("%s signature", name)
		}
		hdr := "v=1; vault=" + r.str("vault_id") + "; kid=" + d.str("akid") + "; ts=" + strconv.Itoa(r.num("ts")) + "; nonce=" +
			r.str("nonce") + "; sig=" + r.str("sig_b64url")
		if r.str("header") != hdr {
			t.Errorf("%s header", name)
		}
		p, psig, err := altchan.ParseAppHeader(hdr)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		p.Method, p.Path, p.Query, p.Body = r.str("method"), r.str("path"), r.str("query"), []byte(r.str("body"))
		if !p.Verify(&k.PublicKey, der, psig) {
			t.Errorf("%s: altchan does not verify", name)
		}
	}
	// The typed code: rejection sampling over the alphabet.
	alpha := d.str("code_alphabet")
	if alpha != "23456789ABCDEFGHJKMNPQRSTUVWXYZ" || altchan.CodeAlphabet != "23456789ABCDEFGHJKMNPQRSTUVWXYZ" {
		t.Error("alphabet")
	}
	var code []byte
	used := 0
	for _, c := range d.hex("code_random_hex") {
		if len(code) == 8 {
			break
		}
		used++
		if c < 248 {
			code = append(code, alpha[int(c)%31])
		}
	}
	if d.str("code") != string(code) || d.num("code_bytes_used") != used || d.str("code_display") != string(code[:4])+"-"+string(code[4:]) {
		t.Errorf("code %q (%d)", code, used)
	}
	mac := func(parts ...string) string {
		m := hmac.New(sha256.New, d.hex("k_code_hex"))
		m.Write([]byte(strings.Join(parts, "\x00")))
		return hex.EncodeToString(m.Sum(nil))
	}
	if d.str("qr_lookup_hex") != mac("qr", d.str("qr_secret")) || d.str("code_mac_hex") != mac("code", d.str("user_guid"), d.str("code")) {
		t.Error("MACs")
	}
	qs := d.str("qr_secret")
	want := `{"v":1,"t":"e","api":"https://account.vettid.org","s":"` + qs + `"}`
	if d.str("enroll_qr") != want || d.str("enroll_app_link") != "https://account.vettid.org/vault/enroll/#s="+qs {
		t.Error("enrollment QR")
	}
	if q, err := altchan.ParseEnrollQR([]byte(want)); err != nil || base64.RawURLEncoding.EncodeToString(q.Secret) != qs {
		t.Error("enrollment QR parse")
	}
	rq := `{"v":1,"t":"r","api":"https://account.vettid.org","vault_id":"test-vault-0001","recovery_id":"01JB2Z6V9K3M4N5P6Q7R8S9T30","code":"50M2GA1850M2GA1850M2GA1850M2GA18"}`
	if d.str("recovery_qr") != rq {
		t.Error("recovery QR")
	}
	if c, err := altchan.ParseRecoveryQR([]byte(rq)); err != nil || c.API != "https://account.vettid.org" {
		t.Error("recovery QR parse")
	}
	if d.str("email_hint") != "m***@example.com" {
		t.Error("email hint")
	}
}
