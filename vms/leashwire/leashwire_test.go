package leashwire

import (
	"bytes"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/suite"
)

func key(b byte) ed25519.PrivateKey { return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{b}, 32)) }

func sample() *Delegation {
	iat := time.Unix(1790000000, 0).UTC()
	return &Delegation{VaultIK: key(1).Public().(ed25519.PublicKey), AgentIK: key(2).Public().(ed25519.PublicKey),
		GrantID: "01JB2Z6V9K3M4N5P6Q7R8S9T0V", Version: 3, Scope: "message.send", Approval: "auto",
		Connections: []string{"01JB2Z6V9K3M4N5P6Q7R8S9T0W"}, IssuedAt: iat, Expires: iat.Add(time.Hour), StatusTTL: DefaultStatusTTL}
}

// itemsSample is an agent share rule's delegation (§10.11).
func itemsSample() *Delegation {
	iat := time.Unix(1790000000, 0).UTC()
	return &Delegation{VaultIK: key(1).Public().(ed25519.PublicKey), AgentIK: key(2).Public().(ed25519.PublicKey),
		GrantID: "01JB2Z6V9K3M4N5P6Q7R8S9T0V", Version: 1, Scope: ScopeItems, Approval: "ask",
		Tags: []string{"agent ok", "work"}, Match: "all", Access: "read", Uses: 10, PerHour: 60, PerDay: 1000,
		IssuedAt: iat, StatusTTL: DefaultStatusTTL}
}

// §10.11: an items.read delegation carries its share rule.
func TestItemsDelegation(t *testing.T) {
	d := itemsSample()
	b := d.Marshal()
	want := `"scope":"items.read","approval":"ask","tags":["agent ok","work"],"match":"all","access":"read","uses":10,"per_hour":60,"per_day":1000,"status_ttl":900`
	if !bytes.Contains(b, []byte(want)) {
		t.Fatalf("canonical: %s", b)
	}
	got, err := Parse(b)
	if err != nil || got.Match != "all" || len(got.Tags) != 2 || got.Uses != 10 {
		t.Fatalf("parse: %+v %v", got, err)
	}
	noUses := *d
	noUses.Uses = 0
	if bytes.Contains(noUses.Marshal(), []byte(`"uses"`)) {
		t.Fatal("uses written without a limit")
	}
	if _, err := Parse(noUses.Marshal()); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string][]byte{
		"no tags":    func() []byte { e := *d; e.Tags = nil; return e.Marshal() }(),
		"bad tag":    bytes.Replace(b, []byte(`"work"`), []byte(`"Work"`), 1),
		"bad match":  bytes.Replace(b, []byte(`"all"`), []byte(`"some"`), 1),
		"bad access": bytes.Replace(b, []byte(`"read"`), []byte(`"write"`), 1),
		"tags on send": func() []byte {
			e := *sample()
			e.Tags, e.Match, e.Access, e.PerHour, e.PerDay = d.Tags, "any", "read", 1, 1
			return e.Marshal()
		}(),
		"connections": func() []byte { e := *d; e.Connections = []string{"01JB2Z6V9K3M4N5P6Q7R8S9T0W"}; return e.Marshal() }(),
		"no per_day":  bytes.Replace(b, []byte(`,"per_day":1000`), nil, 1),
	} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// §10.11: canonical bytes, signature by the credential key, expiry.
func TestDelegationRoundTrip(t *testing.T) {
	d := sample()
	b := d.Marshal()
	want := `{"v":1,"vault_ik":"` // members in the order of §10.11
	if !bytes.HasPrefix(b, []byte(want)) || bytes.Contains(b, []byte(" ")) || bytes.Contains(b, []byte("tags")) {
		t.Fatalf("not canonical: %s", b)
	}
	sig, err := Sign(key(9), b)
	if err != nil {
		t.Fatal(err)
	}
	pub := key(9).Public().(ed25519.PublicKey)
	got, err := Verify(pub, b, sig, d.IssuedAt.Add(time.Minute))
	if err != nil || got.GrantID != d.GrantID || got.Version != 3 || len(got.Connections) != 1 {
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
		"whitespace":   bytes.Replace(good, []byte(`,"scope"`), []byte(`, "scope"`), 1),
		"reordered":    bytes.Replace(bytes.Replace(good, []byte(`"version":3,`), nil, 1), []byte(`"iat"`), []byte(`"version":3,"iat"`), 1),
		"bad approval": bytes.Replace(good, []byte(`"auto"`), []byte(`"always"`), 1),
		"exp at iat":   func() []byte { e := *d; e.Expires = e.IssuedAt; return e.Marshal() }(),
		"exp before":   func() []byte { e := *d; e.Expires = e.IssuedAt.Add(-time.Second); return e.Marshal() }(),
		"empty conns":  bytes.Replace(good, []byte(`["01JB2Z6V9K3M4N5P6Q7R8S9T0W"]`), []byte(`[]`), 1),
		"bad id":       bytes.Replace(good, []byte(`01JB2Z6V9K3M4N5P6Q7R8S9T0V`), []byte(`not-a-ulid`), 1),
		"version 2":    bytes.Replace(good, []byte(`{"v":1`), []byte(`{"v":2`), 1),
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
	f.Add(itemsSample().Marshal())
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

// presented builds what an agent shows: a delegation signed by member key
// 9 naming vault key 1, and a status statement signed by signer.
func presented(t *testing.T, d *Delegation, signer ed25519.PrivateKey, chain []*handshake.Rotation, now time.Time) *Presented {
	t.Helper()
	b := d.Marshal()
	sig, err := Sign(key(9), b)
	if err != nil {
		t.Fatal(err)
	}
	st, err := NewStatus(b, now)
	if err != nil {
		t.Fatal(err)
	}
	sb := st.Marshal()
	ss, err := SignStatus(signer, sb)
	if err != nil {
		t.Fatal(err)
	}
	return &Presented{Delegation: b, DelegationSig: sig, Status: sb, StatusSig: ss, Rotations: chain}
}

// §10.11 status statements: verifiable offline with only the delegation
// and the statement; signer = the named status issuer (through its
// rotation chain); stale, forged, wrong-issuer or wrong-delegation
// statements rejected.
func TestStatusStatements(t *testing.T) {
	d := sample()
	now := d.IssuedAt.Add(time.Minute)
	member := key(9).Public().(ed25519.PublicKey)
	p := presented(t, d, key(1), nil, now)
	if _, err := VerifyPresented(member, p, now.Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	st, _ := ParseStatus(p.Status)
	if st.NotAfter.Sub(st.IssuedAt) != DefaultStatusTTL {
		t.Fatalf("ttl %v", st.NotAfter.Sub(st.IssuedAt))
	}
	// Stale: past not_after (+ skew).
	if _, err := VerifyPresented(member, p, st.NotAfter.Add(StatusSkew+time.Second)); err == nil {
		t.Fatal("stale statement accepted")
	}
	// Signed by another key than the status issuer.
	if _, err := VerifyPresented(member, presented(t, d, key(2), nil, now), now); err == nil {
		t.Fatal("wrong issuer accepted")
	}
	// Forged: a statement altered after signing.
	f := *p
	f.Status = bytes.Replace(p.Status, []byte(`"not_after":`), []byte(`"not_after":1`), 1)
	if _, err := VerifyPresented(member, &f, now); err == nil {
		t.Fatal("forged statement accepted")
	}
	// A statement for another delegation.
	other := *d
	other.Version = 4
	q := presented(t, &other, key(1), nil, now)
	mixed := *p
	mixed.Status, mixed.StatusSig = q.Status, q.StatusSig
	if _, err := VerifyPresented(member, &mixed, now); err == nil {
		t.Fatal("statement of another delegation accepted")
	}
	// The member's signature still matters.
	if _, err := VerifyPresented(key(8).Public().(ed25519.PublicKey), p, now); err == nil {
		t.Fatal("delegation under another member key accepted")
	}
	// Never past the delegation's own exp.
	short := *d
	short.Expires = short.IssuedAt.Add(5 * time.Minute)
	sp := presented(t, &short, key(1), nil, now)
	if s2, _ := ParseStatus(sp.Status); !s2.NotAfter.Equal(short.Expires) {
		t.Fatalf("not_after past exp: %v", s2.NotAfter)
	}
	// After the vault's ik rotated: the statement is signed by the new key
	// and carries the chain from the delegation's vault_ik.
	newIK := key(3)
	kem, _ := suite.NewPrivateKey(bytes.Repeat([]byte{4}, 32))
	rot, err := handshake.NewRotation(key(1), newIK, kem.Public())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyPresented(member, presented(t, d, newIK, []*handshake.Rotation{rot}, now), now); err != nil {
		t.Fatalf("rotated issuer: %v", err)
	}
	if _, err := VerifyPresented(member, presented(t, d, newIK, nil, now), now); err == nil {
		t.Fatal("new key accepted without the chain")
	}
}

func FuzzParseStatus(f *testing.F) {
	st, _ := NewStatus(sample().Marshal(), sample().IssuedAt)
	f.Add(st.Marshal())
	f.Fuzz(func(t *testing.T, b []byte) {
		s, err := ParseStatus(b)
		if err == nil && !bytes.Equal(s.Marshal(), b) {
			t.Fatal("non-canonical status accepted")
		}
	})
}
