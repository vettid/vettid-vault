package manifesttool

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms"

	"github.com/vettid/vettid-vault/vms/manifest"
)

func key(t testing.TB) *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func pcr(b string) string { return strings.Repeat(b, 48) }

var list = strings.NewReplacer("P0-2", pcr("cd"), "P1-2", pcr("33"), "P2-2", pcr("44"), "P0-1", pcr("ab"), "P1-1", pcr("11"), "P2-1", pcr("22"),
	"P0-3", pcr("ef"), "P1-3", pcr("55"), "P2-3", pcr("66")).Replace(`{"releases":[
 {"release":2,"tag":"release/prod/2","pcr0":"P0-2","pcr1":"P1-2","pcr2":"P2-2","seal_key":"arn:aws:kms:us-east-1:111122223333:key/2","status":"active","published_at":"2026-11-15T00:00:00Z","notes":"https://vettid.org/security/releases/2"},
 {"release":1,"pcr0":"P0-1","pcr1":"P1-1","pcr2":"P2-1","seal_key":"arn:aws:kms:us-east-1:111122223333:key/1","status":"deprecated","published_at":"2026-10-15T00:00:00Z","ends_at":"2027-11-15T00:00:00Z","notes":"https://vettid.org/security/releases/1","instances":{"min":0}},
 {"release":3,"pcr0":"P0-3","pcr1":"P1-3","pcr2":"P2-3","seal_key":"arn:aws:kms:us-east-1:111122223333:key/3","status":"candidate","published_at":"2026-12-15T00:00:00Z","notes":"https://vettid.org/security/releases/3"}
]}`)

var at = time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)

func render(t *testing.T, serial uint64) *manifest.Manifest {
	t.Helper()
	l, err := ParseList([]byte(list))
	if err != nil {
		t.Fatal(err)
	}
	_, m, err := Render(l, serial, at)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestRender(t *testing.T) {
	m := render(t, 5)
	if m.Serial != 5 || len(m.Releases) != 2 || m.Releases[0].Number != 1 || m.Releases[1].Number != 2 || m.Releases[0].EndsAt.IsZero() {
		t.Fatalf("rendered %+v", m)
	}
	if !Canonical(m) {
		t.Fatal("not canonical")
	}
	if strings.Contains(string(m.Bytes), "candidate") || strings.Contains(string(m.Bytes), "tag") || strings.Contains(string(m.Bytes), "instances") {
		t.Fatal("candidate or unknown members in the manifest")
	}
	s := Summarize(m)
	h := sha256.Sum256(m.Bytes)
	if s.SHA256 != hex.EncodeToString(h[:]) || s.Object != "manifests/"+s.SHA256+".json" || s.Bytes != len(m.Bytes) {
		t.Fatalf("summary %+v", s)
	}
	// Non-canonical: a member order other than §11.10.1's.
	swapped := strings.Replace(string(m.Bytes), `{"v":1,"serial":5,`, `{"serial":5,"v":1,`, 1)
	if mm, err := manifest.Parse([]byte(swapped)); err != nil || Canonical(mm) {
		t.Fatalf("swapped order: %v", err)
	}
	for name, bad := range map[string]string{
		"status":    strings.Replace(list, `"status":"active"`, `"status":"live"`, 1),
		"time":      strings.Replace(list, `"2026-11-15T00:00:00Z"`, `"2026-11-15T00:00:00.5Z"`, 1),
		"duplicate": strings.Replace(list, `"release":1,`, `"release":2,`, 1),
		"debug pcr": strings.Replace(list, pcr("ab"), pcr("00"), 1),
	} {
		l, err := ParseList([]byte(bad))
		if err == nil {
			_, _, err = Render(l, 5, at)
		}
		if err == nil {
			t.Errorf("%s: rendered", name)
		}
	}
	l, _ := ParseList([]byte(list))
	if _, _, err := Render(l, 0, at); err == nil {
		t.Error("serial 0")
	}
}

func TestCheckSuccessor(t *testing.T) {
	prev := render(t, 5)
	if err := CheckSuccessor(prev, render(t, 6)); err != nil {
		t.Fatal(err)
	}
	if err := CheckSuccessor(prev, render(t, 5)); err == nil {
		t.Fatal("same serial")
	}
	mod := func(f func(rs []manifest.Release) []manifest.Release) *manifest.Manifest {
		rs := f(append([]manifest.Release(nil), prev.Releases...))
		m, err := manifest.Parse(manifest.Build(6, at, rs))
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	for name, next := range map[string]*manifest.Manifest{
		"dropped while deprecated": mod(func(rs []manifest.Release) []manifest.Release { return rs[1:] }),
		"status backwards":         mod(func(rs []manifest.Release) []manifest.Release { rs[0].Status = manifest.StatusActive; return rs }),
		"pcr changed":              mod(func(rs []manifest.Release) []manifest.Release { rs[0].PCR1 = pcr("77"); return rs }),
		"key changed":              mod(func(rs []manifest.Release) []manifest.Release { rs[1].SealKey = "arn:x"; return rs }),
	} {
		if err := CheckSuccessor(prev, next); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	retired := mod(func(rs []manifest.Release) []manifest.Release { rs[0].Status = manifest.StatusRemoved; return rs })
	if err := CheckSuccessor(prev, retired); err != nil {
		t.Fatal(err)
	}
	dropped, _ := manifest.Parse(manifest.Build(7, at, retired.Releases[1:]))
	if err := CheckSuccessor(retired, dropped); err != nil {
		t.Fatalf("dropping a removed release: %v", err)
	}
}

func TestSignFileAndImport(t *testing.T) {
	a, b, other := key(t), key(t), key(t)
	pinned := []*ecdsa.PublicKey{&a.PublicKey, &b.PublicKey}
	m := render(t, 5)
	ctx := context.Background()
	s, err := Sign(ctx, FileSigner{Key: a}, m.Bytes, pinned)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manifest.VerifyByHash(s.Marshal(), manifest.SHA256Hex(m.Bytes), 5, pinned); err != nil {
		t.Fatal(err)
	}
	if _, err := Sign(ctx, FileSigner{Key: other}, m.Bytes, pinned); err == nil {
		t.Fatal("signed with an unpinned key")
	}
	// Key B signs offline (here: DER, as tokens return it) and the
	// signature is imported, in every text encoding.
	d := manifest.Digest(m.Bytes)
	der, err := ecdsa.SignASN1(rand.Reader, b, d[:])
	if err != nil {
		t.Fatal(err)
	}
	for name, enc := range map[string][]byte{
		"der":    der,
		"hex":    []byte(hex.EncodeToString(der) + "\n"),
		"base64": []byte(base64.StdEncoding.EncodeToString(der)),
		"pem":    pem.EncodeToMemory(&pem.Block{Type: "SIGNATURE", Bytes: der}),
	} {
		s, err := Assemble(m.Bytes, DecodeBytes(enc), &b.PublicKey, pinned)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if id, _ := manifest.KeyID(&b.PublicKey); s.KeyID != id {
			t.Fatalf("%s: key id", name)
		}
	}
	raw, _ := RawSignature(der)
	if _, err := Assemble(m.Bytes, raw, &b.PublicKey, pinned); err != nil {
		t.Fatalf("raw: %v", err)
	}
	// A signature over other bytes, or claimed for the other pinned key.
	if _, err := Assemble(render(t, 6).Bytes, der, &b.PublicKey, pinned); err == nil {
		t.Fatal("signature over other bytes")
	}
	if _, err := Assemble(m.Bytes, der, &a.PublicKey, pinned); err == nil {
		t.Fatal("signature attributed to the wrong key")
	}
	if _, err := RawSignature([]byte("short")); err == nil {
		t.Fatal("junk signature")
	}
	// Keys round-trip through the file formats.
	spki, _ := x509.MarshalPKIXPublicKey(&b.PublicKey)
	for _, f := range [][]byte{pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki}), []byte(base64.StdEncoding.EncodeToString(spki))} {
		if k, err := ParsePublicKey(f); err != nil || !k.Equal(&b.PublicKey) {
			t.Fatalf("public key: %v", err)
		}
	}
	ec, _ := x509.MarshalECPrivateKey(a)
	if k, err := ParsePrivateKey(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ec})); err != nil || !k.Equal(a) {
		t.Fatalf("private key: %v", err)
	}
}

// fakeKMS answers GetPublicKey and Sign (JSON 1.1) for one generated key.
func fakeKMS(t *testing.T, k *ecdsa.PrivateKey, spec string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var in map[string]any
		_ = json.Unmarshal(body, &in)
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
			w.WriteHeader(400)
			return
		}
		switch r.Header.Get("X-Amz-Target") {
		case "TrentService.GetPublicKey":
			spki, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
			_ = json.NewEncoder(w).Encode(map[string]any{"KeyId": in["KeyId"], "KeySpec": spec, "KeyUsage": "SIGN_VERIFY",
				"PublicKey": base64.StdEncoding.EncodeToString(spki), "SigningAlgorithms": []string{"ECDSA_SHA_256"}})
		case "TrentService.Sign":
			if in["MessageType"] != "DIGEST" || in["SigningAlgorithm"] != "ECDSA_SHA_256" {
				w.WriteHeader(400)
				return
			}
			msg, _ := base64.StdEncoding.DecodeString(in["Message"].(string))
			der, _ := ecdsa.SignASN1(rand.Reader, k, msg)
			_ = json.NewEncoder(w).Encode(map[string]any{"KeyId": in["KeyId"], "Signature": base64.StdEncoding.EncodeToString(der), "SigningAlgorithm": "ECDSA_SHA_256"})
		default:
			w.WriteHeader(400)
		}
	}))
}

func kmsClient(url string) *kms.Client {
	return kms.New(kms.Options{Region: "us-east-1", BaseEndpoint: aws.String(url),
		Credentials: credentials.NewStaticCredentialsProvider("AKIDTEST", "test", "")})
}

func TestKMSSigner(t *testing.T) {
	a := key(t)
	srv := fakeKMS(t, a, "ECC_NIST_P256")
	defer srv.Close()
	m := render(t, 5)
	s, err := Sign(context.Background(), KMSSigner{API: kmsClient(srv.URL), KeyID: "arn:aws:kms:us-east-1:111122223333:key/a"}, m.Bytes, []*ecdsa.PublicKey{&a.PublicKey})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manifest.Verify(s, []*ecdsa.PublicKey{&a.PublicKey}); err != nil {
		t.Fatal(err)
	}
	// A key of another spec is refused before signing.
	bad := fakeKMS(t, a, "ECC_SECG_P256K1")
	defer bad.Close()
	if _, err := Sign(context.Background(), KMSSigner{API: kmsClient(bad.URL), KeyID: "k"}, m.Bytes, []*ecdsa.PublicKey{&a.PublicKey}); err == nil {
		t.Fatal("secp256k1 key accepted")
	}
}
