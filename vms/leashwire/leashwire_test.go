package leashwire

import (
	"bytes"
	"crypto/ed25519"
	"testing"
	"time"
)

func key(b byte) ed25519.PrivateKey { return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{b}, 32)) }

func sample() *Delegation {
	iat := time.Unix(1790000000, 0).UTC()
	return &Delegation{VaultIK: key(1).Public().(ed25519.PublicKey), AgentIK: key(2).Public().(ed25519.PublicKey),
		GrantID: "01JB2Z6V9K3M4N5P6Q7R8S9T0V", Version: 3, Scope: "secrets.get", Approval: "auto",
		Secrets: []string{"01JB2Z6V9K3M4N5P6Q7R8S9T0W"}, IssuedAt: iat, Expires: iat.Add(time.Hour)}
}

// §10.11: canonical bytes, signature by the credential key, expiry.
func TestDelegationRoundTrip(t *testing.T) {
	d := sample()
	b := d.Marshal()
	want := `{"v":1,"vault_ik":"` // members in the order of §10.11
	if !bytes.HasPrefix(b, []byte(want)) || bytes.Contains(b, []byte(" ")) || bytes.Contains(b, []byte("connections")) {
		t.Fatalf("not canonical: %s", b)
	}
	sig, err := Sign(key(9), b)
	if err != nil {
		t.Fatal(err)
	}
	pub := key(9).Public().(ed25519.PublicKey)
	got, err := Verify(pub, b, sig, d.IssuedAt.Add(time.Minute))
	if err != nil || got.GrantID != d.GrantID || got.Version != 3 || len(got.Secrets) != 1 {
		t.Fatalf("verify: %v %+v", err, got)
	}
	if _, err := Verify(key(8).Public().(ed25519.PublicKey), b, sig, d.IssuedAt); err == nil {
		t.Fatal("verified under another key")
	}
	if _, err := Verify(pub, b, sig, d.Expires); err == nil {
		t.Fatal("expired delegation accepted")
	}
	tampered := bytes.Replace(b, []byte(`"auto"`), []byte(`"ask"`), 1)
	if _, err := Verify(pub, tampered, sig, d.IssuedAt); err == nil {
		t.Fatal("tampered delegation accepted")
	}
}

func TestDelegationStrict(t *testing.T) {
	d := sample()
	good := d.Marshal()
	for name, b := range map[string][]byte{
		"whitespace":    bytes.Replace(good, []byte(`,"scope"`), []byte(`, "scope"`), 1),
		"reordered":     bytes.Replace(bytes.Replace(good, []byte(`"version":3,`), nil, 1), []byte(`"iat"`), []byte(`"version":3,"iat"`), 1),
		"bad approval":  bytes.Replace(good, []byte(`"auto"`), []byte(`"always"`), 1),
		"exp at iat":    func() []byte { e := *d; e.Expires = e.IssuedAt; return e.Marshal() }(),
		"exp before":    func() []byte { e := *d; e.Expires = e.IssuedAt.Add(-time.Second); return e.Marshal() }(),
		"empty secrets": bytes.Replace(good, []byte(`["01JB2Z6V9K3M4N5P6Q7R8S9T0W"]`), []byte(`[]`), 1),
		"bad id":        bytes.Replace(good, []byte(`01JB2Z6V9K3M4N5P6Q7R8S9T0V`), []byte(`not-a-ulid`), 1),
		"version 2":     bytes.Replace(good, []byte(`{"v":1`), []byte(`{"v":2`), 1),
	} {
		if _, err := Parse(b); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := Parse(good); err != nil {
		t.Fatal(err)
	}
	// Without an expiry (LEASH §3.2: the contract's expiry is optional).
	open := *d
	open.Expires = time.Time{}
	ob := open.Marshal()
	if bytes.Contains(ob, []byte(`"exp"`)) {
		t.Fatalf("exp written: %s", ob)
	}
	sig, _ := Sign(key(9), ob)
	if got, err := Verify(key(9).Public().(ed25519.PublicKey), ob, sig, d.IssuedAt.Add(400*24*time.Hour)); err != nil || !got.Expires.IsZero() {
		t.Fatalf("open-ended delegation: %v", err)
	}
	if _, err := Sign(key(9), []byte(`{}`)); err == nil {
		t.Fatal("signed a non-delegation")
	}
}

func FuzzParseDelegation(f *testing.F) {
	f.Add(sample().Marshal())
	f.Add([]byte(`{"v":1}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		d, err := Parse(b)
		if err != nil {
			return
		}
		if !bytes.Equal(d.Marshal(), b) {
			t.Fatal("accepted non-canonical bytes")
		}
	})
}
