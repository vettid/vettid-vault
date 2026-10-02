package suite

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hpke"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func seed(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

// §3.2/§4.3: ek 1,216 bytes, enc 1,120 bytes, codepoint 0x647a, and the
// ciphersuite is exactly HPKE(0x647a, 0x0001, 0x0003).
func TestSuite2Parameters(t *testing.T) {
	if hpke.MLKEM768X25519().ID() != KEMID || hpke.HKDFSHA256().ID() != KDFID || hpke.ChaCha20Poly1305().ID() != AEADID {
		t.Fatal("algorithm ids")
	}
	k, err := NewPrivateKey(seed(5))
	if err != nil {
		t.Fatal(err)
	}
	if len(k.Public().Bytes()) != EKSize {
		t.Fatalf("ek %d", len(k.Public().Bytes()))
	}
	enc, s, err := SetupSender(k.Public(), InfoSealed)
	if err != nil || len(enc) != EncSize {
		t.Fatalf("enc %d %v", len(enc), err)
	}
	ct, err := s.Seal([]byte("aad"), []byte("pt"))
	if err != nil {
		t.Fatal(err)
	}
	r, err := SetupRecipient(enc, k, InfoSealed)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := r.Open([]byte("aad"), ct)
	if err != nil || string(pt) != "pt" {
		t.Fatal("open")
	}
}

// §4.1: the info binds the label; a different info cannot open.
func TestInfoBindsLabel(t *testing.T) {
	k, _ := NewPrivateKey(seed(5))
	enc, s, _ := SetupSender(k.Public(), InfoSealed)
	ct, _ := s.Seal(nil, []byte("x"))
	r, err := SetupRecipient(enc, k, "vettid/vms/3/sealed")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Open(nil, ct); !errors.Is(err, ErrDecrypt) {
		t.Fatal("opened under another info")
	}
}

// §4.3: a context MUST NOT be reused for a second message.
func TestContextSingleUse(t *testing.T) {
	k, _ := NewPrivateKey(seed(5))
	enc, s, _ := SetupSender(k.Public(), InfoSealed)
	ct, err := s.Seal(nil, []byte("one"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Seal(nil, []byte("two")); !errors.Is(err, ErrContextUsed) {
		t.Fatal("sender sealed twice")
	}
	r, _ := SetupRecipient(enc, k, InfoSealed)
	if _, err := r.Open(nil, ct); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Open(nil, ct); !errors.Is(err, ErrContextUsed) {
		t.Fatal("recipient opened twice")
	}
	// Export stays available on both sides and agrees.
	a, _ := s.Export(LabelHsKs, 32)
	b, _ := r.Export(LabelHsKs, 32)
	if !bytes.Equal(a, b) {
		t.Fatal("exports differ")
	}
}

// §4.4 kid derivation.
func TestKidOf(t *testing.T) {
	k, _ := NewPrivateKey(seed(5))
	ek := k.Public().Bytes()
	h := LabeledHash("vettid/vms/2/kid", ek)
	kid := k.Public().Kid()
	if !bytes.Equal(kid[:], h[:8]) {
		t.Fatal("kid")
	}
	if Anonymous != (Kid{}) || !Anonymous.IsAnonymous() || k.Public().Kid().IsAnonymous() {
		t.Fatal("anonymous kid")
	}
	if kk, err := ParseKidHex(k.Public().Kid().String()); err != nil || kk != k.Public().Kid() {
		t.Fatal("hex round trip")
	}
	for _, s := range []string{"", "00", strings.Repeat("A", 16), strings.Repeat("g", 16)} {
		if _, err := ParseKidHex(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
}

func TestKeyParsing(t *testing.T) {
	if _, err := ParsePublicKey(make([]byte, EKSize-1)); !errors.Is(err, ErrKeySize) {
		t.Fatal("short ek")
	}
	// An ML-KEM part with an out-of-range coefficient is rejected.
	bad := bytes.Repeat([]byte{0xff}, EKSize)
	if _, err := ParsePublicKey(bad); err == nil {
		t.Fatal("invalid ML-KEM key accepted")
	}
	if _, err := NewPrivateKey(seed(1)[:31]); !errors.Is(err, ErrKeySize) {
		t.Fatal("short seed")
	}
	k, _ := NewPrivateKey(seed(5))
	s, err := k.Seed()
	if err != nil || !bytes.Equal(s, seed(5)) {
		t.Fatal("seed")
	}
	k.Destroy()
	if _, err := k.Seed(); !errors.Is(err, ErrDestroyed) {
		t.Fatal("seed after destroy")
	}
	if _, err := SetupRecipient(make([]byte, EncSize), k, InfoSealed); !errors.Is(err, ErrDestroyed) {
		t.Fatal("use after destroy")
	}
}

// §4.1: suite 1 MUST NOT be sent or accepted; §13.4 pinning.
func TestSuite1NeverAccepted(t *testing.T) {
	if err := Check(1, 0); !errors.Is(err, ErrSuite1) {
		t.Fatal("Check(1)")
	}
	if err := ValidateOffer([]int{1, 2}); !errors.Is(err, ErrSuite1) {
		t.Fatal("offer with 1")
	}
	if _, err := Negotiate([]int{1}, 0); err == nil {
		t.Fatal("negotiated 1")
	}
	var p Pin
	if err := p.Raise(1); err == nil {
		t.Fatal("pinned 1")
	}
}

func TestDowngradePin(t *testing.T) {
	p := NewPin(0)
	if err := p.Raise(2); err != nil {
		t.Fatal(err)
	}
	if p.Accept(2) != nil {
		t.Fatal("pinned suite rejected")
	}
	// A record pinned at 3 rejects 2.
	p3 := NewPin(3)
	if err := p3.Accept(2); !errors.Is(err, ErrDowngrade) {
		t.Fatalf("Accept(2) under pin 3: %v", err)
	}
	if err := p3.Raise(2); err == nil && p3.Value() != 3 {
		t.Fatal("pin decreased")
	}
	if s, err := Negotiate([]int{2, 3, 7}, 0); err != nil || s != 2 {
		t.Fatalf("negotiate: %d %v", s, err)
	}
	if _, err := Negotiate([]int{2}, 3); !errors.Is(err, ErrNoCommonSuite) {
		t.Fatal("negotiated below pin")
	}
	for _, o := range [][]int{nil, {}, {0}, {2, 2}, {3, 2}, {256}, {2, 3, 4, 5, 6, 7, 8, 9, 10}} {
		if ValidateOffer(o) == nil {
			t.Errorf("offer %v accepted", o)
		}
	}
}

func TestXChaCha(t *testing.T) {
	key, nonce := seed(8), bytes.Repeat([]byte{9}, 24)
	ct, err := SealX(key, nonce, []byte("aad"), []byte("pt"))
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := OpenX(key, nonce, []byte("aad"), ct); err != nil || string(pt) != "pt" {
		t.Fatal("open")
	}
	ct[0] ^= 1
	if _, err := OpenX(key, nonce, []byte("aad"), ct); !errors.Is(err, ErrDecrypt) {
		t.Fatal("tampered accepted")
	}
	if _, err := SealX(key[:31], nonce, nil, nil); err == nil {
		t.Fatal("short key")
	}
	n1, _ := NewNonce()
	n2, _ := NewNonce()
	if len(n1) != 24 || bytes.Equal(n1, n2) {
		t.Fatal("nonce")
	}
}

func TestSignLabels(t *testing.T) {
	k := ed25519.NewKeyFromSeed(seed(4))
	pub := k.Public().(ed25519.PublicKey)
	sig, _ := Sign(k, LabelSigResp, []byte("th"))
	if Verify(pub, LabelSigResp, []byte("th"), sig) != nil {
		t.Fatal("verify")
	}
	// Signatures are domain-separated by label (sig-resp vs sig-fin).
	if Verify(pub, LabelSigFin, []byte("th"), sig) == nil {
		t.Fatal("cross-label verify")
	}
	if Verify(pub[:31], LabelSigResp, []byte("th"), sig) == nil || Verify(pub, LabelSigResp, []byte("th"), sig[:63]) == nil {
		t.Fatal("bad sizes accepted")
	}
}

// §13.4: every label embeds the suite number.
func TestLabelsEmbedSuite(t *testing.T) {
	for _, l := range []string{LabelKid, InfoSealed, LabelHsKs, LabelHsKe, LabelTh1, LabelTh, LabelSession, LabelI2R,
		LabelR2I, LabelKidI2R, LabelKidR2I, LabelRK, LabelEpoch, LabelSigResp, LabelSigFin, LabelSAS, LabelBundle,
		LabelETK, LabelVault, LabelDevatt, LabelUnlock, InfoCall, LabelCallKey, LabelRotate, LabelBlob} {
		if !strings.HasPrefix(l, labelPrefix) || len(l) == len(labelPrefix) {
			t.Errorf("label %q", l)
		}
	}
}

func TestRedaction(t *testing.T) {
	k, _ := NewPrivateKey(seed(5))
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%x", "%q"} {
		if got := sprintf(verb, k); got != "[redacted]" {
			t.Errorf("%s -> %q", verb, got)
		}
	}
}

func sprintf(verb string, v any) string { return fmt.Sprintf(verb, v) }
