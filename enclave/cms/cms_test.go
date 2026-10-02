package cms_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"sync"
	"testing"

	"github.com/vettid/vettid-vault/enclave/cms"
	"github.com/vettid/vettid-vault/internal/enclavetest"
)

var (
	keyOnce sync.Once
	key     *rsa.PrivateKey
)

func testKey() *rsa.PrivateKey {
	keyOnce.Do(func() {
		var err error
		if key, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			panic(err)
		}
	})
	return key
}

func TestUnwrap(t *testing.T) {
	k := testKey()
	content := bytes.Repeat([]byte{0x5a}, 32)
	for _, o := range []enclavetest.CMSOptions{{}, {Indefinite: true}} {
		got, err := cms.Unwrap(enclavetest.WrapCMS(&k.PublicKey, content, o), k)
		if err != nil || !bytes.Equal(got, content) {
			t.Fatalf("%+v: %v", o, err)
		}
	}
	// Refusals.
	if _, err := cms.Unwrap(enclavetest.WrapCMS(&k.PublicKey, content, enclavetest.CMSOptions{DefaultOAEPParams: true}), k); !errors.Is(err, cms.ErrFormat) {
		t.Errorf("SHA-1 OAEP defaults: %v", err)
	}
	if _, err := cms.Unwrap(enclavetest.WrapCMS(&k.PublicKey, content, enclavetest.CMSOptions{PKCS1v15: true}), k); !errors.Is(err, cms.ErrDecrypt) {
		t.Errorf("PKCS#1 v1.5: %v", err)
	}
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	if _, err := cms.Unwrap(enclavetest.WrapCMS(&other.PublicKey, content, enclavetest.CMSOptions{}), k); !errors.Is(err, cms.ErrDecrypt) {
		t.Errorf("other key: %v", err)
	}
	env := enclavetest.WrapCMS(&k.PublicKey, content, enclavetest.CMSOptions{})
	if _, err := cms.Unwrap(append(env, 0), k); err == nil {
		t.Error("trailing data")
	}
	bad := append([]byte(nil), env...)
	bad[len(bad)-1] ^= 1 // last ciphertext block: padding breaks
	if _, err := cms.Unwrap(bad, k); err == nil {
		t.Error("modified ciphertext accepted")
	}
}

func FuzzUnwrap(f *testing.F) {
	k := testKey()
	f.Add(enclavetest.WrapCMS(&k.PublicKey, []byte("data key"), enclavetest.CMSOptions{}))
	f.Add(enclavetest.WrapCMS(&k.PublicKey, []byte("data key"), enclavetest.CMSOptions{Indefinite: true}))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = cms.Unwrap(b, k)
	})
}
