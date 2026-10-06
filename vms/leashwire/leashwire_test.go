package leashwire

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/suite"
)

func key(b byte) ed25519.PrivateKey { return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{b}, 32)) }
func pub(b byte) ed25519.PublicKey  { return key(b).Public().(ed25519.PublicKey) }

// member is the credential key (iss) of the samples; vault key 1 is the
// status issuer, agent key 2 the sub.
const member = 9

func sample() *Delegation {
	iat := time.Unix(1790000000, 0).UTC()
	return &Delegation{Iss: pub(member), Sub: pub(2), StatusIssuer: pub(1),
		GrantID: "01JB2Z6V9K3M4N5P6Q7R8S9T0V", Version: 3, Approval: "auto",
		Scope:  Scope{Op: "message.send", Connections: []string{"01JB2Z6V9K3M4N5P6Q7R8S9T0W"}},
		Limits: &Limits{PerHour: 60, PerDay: 1000}, Nonce: bytes.Repeat([]byte{7}, NonceSize),
		IssuedAt: iat, Expires: iat.Add(time.Hour), StatusTTL: DefaultStatusTTL}
}

// itemsSample is an agent share rule's delegation (§10.11).
func itemsSample() *Delegation {
	iat := time.Unix(1790000000, 0).UTC()
	return &Delegation{Iss: pub(member), Sub: pub(2), StatusIssuer: pub(1),
		GrantID: "01JB2Z6V9K3M4N5P6Q7R8S9T0V", Version: 1, Approval: "ask",
		Scope:  Scope{Op: ScopeItems, Tags: []string{"agent ok", "work"}, Match: "all", Access: "read", Uses: 10},
		Limits: &Limits{PerHour: 60, PerDay: 1000}, Nonce: bytes.Repeat([]byte{8}, NonceSize),
		IssuedAt: iat, StatusTTL: DefaultStatusTTL}
}

// The §16 leash.json vectors (VAULT-MESSAGING 0.12.0), as the spec prints
// them; vms/vectors checks that the file reproduces them too.
var specVectors = []struct {
	name                         string
	d                            *Delegation
	delegation, sha, sig, status string
	statusSig                    string
	from, to                     int64
}{
	{
		name: "A",
		d: &Delegation{Iss: pub(0x30), Sub: pub(0x31), StatusIssuer: pub(0x04), GrantID: "01JB2Z6V9K3M4N5P6Q7R8S9T41",
			Version: 1, Approval: "auto", Scope: Scope{Op: ScopeItems, Tags: []string{"api-keys", "work"}, Match: "any", Access: "read", Uses: 10},
			Limits: &Limits{PerHour: 60, PerDay: 1000}, StatusTTL: 900 * time.Second, Nonce: bytes.Repeat([]byte{0x32}, 16),
			IssuedAt: time.Unix(1790856000, 0).UTC(), Expires: time.Unix(1798632000, 0).UTC()},
		delegation: `{"approval":"auto","exp":1798632000,"grant_id":"01JB2Z6V9K3M4N5P6Q7R8S9T41",` +
			`"iat":1790856000,"iss":"G6QHW3fJ4/s+zeFc2vUiHzwQNz5iP3sOHvdjZrCvcTc=",` +
			`"limits":{"per_day":1000,"per_hour":60},"nonce":"MjIyMjIyMjIyMjIyMjIyMg==",` +
			`"scope":{"access":"read","match":"any","op":"items.read","tags":["api-keys","work"],` +
			`"uses":10},"status_issuer":"ypOsFwUYcHHWe4PH/w7+gQjo7EUwV113JoeTM9vavnw=",` +
			`"status_ttl":900,"sub":"SAdaWX5yGhVuLgeZ3lzAxTJNxufq8c3UYlCGjsUyFd0=","v":1,"version":1}`,
		sha: "82403562f0a1b62c520c468d46f58a473eefc0cae0ac6a0d8d8bdaef225ea436",
		sig: "xGYxdD9lhE27/4NjTmDl1L+9/UJRv3cdRdWp3yOVxCOPgicdwrL+lv9A7lP4RNkE47XVEpAjAvh7Dc0z9dBKCw==",
		status: `{"delegation":"gkA1YvChtixSDEaNRvWKRz7vwMrgrGoNjYva7yJepDY=",` +
			`"grant_id":"01JB2Z6V9K3M4N5P6Q7R8S9T41","issued_at":1790856060,"not_after":1790856960,` +
			`"status":"valid","v":1}`,
		statusSig: "aSkNJrcIZmkYLzpX5Z7jb/1tHXkwrcNHBZURMycInB9vWdwEpGJB3RDzPmzUscKL6H3tRaOSyZID653kpcgACg==",
		from:      1790856000, to: 1790857020,
	},
	{
		name: "B",
		d: &Delegation{Iss: pub(0x30), Sub: pub(0x31), StatusIssuer: pub(0x04), GrantID: "01JB2Z6V9K3M4N5P6Q7R8S9T42",
			Version: 2, Approval: "ask", Scope: Scope{Op: "message.send", Connections: []string{"01JB2Z6V9K3M4N5P6Q7R8S9T43"}},
			StatusTTL: 300 * time.Second, Nonce: bytes.Repeat([]byte{0x33}, 16), IssuedAt: time.Unix(1790856000, 0).UTC()},
		delegation: `{"approval":"ask","grant_id":"01JB2Z6V9K3M4N5P6Q7R8S9T42","iat":1790856000,` +
			`"iss":"G6QHW3fJ4/s+zeFc2vUiHzwQNz5iP3sOHvdjZrCvcTc=","nonce":"MzMzMzMzMzMzMzMzMzMzMw==",` +
			`"scope":{"connections":["01JB2Z6V9K3M4N5P6Q7R8S9T43"],"op":"message.send"},` +
			`"status_issuer":"ypOsFwUYcHHWe4PH/w7+gQjo7EUwV113JoeTM9vavnw=","status_ttl":300,` +
			`"sub":"SAdaWX5yGhVuLgeZ3lzAxTJNxufq8c3UYlCGjsUyFd0=","v":1,"version":2}`,
		sha: "36ce9294e797cf1eecff1c61b8a21647e45a20eedd6acdb2abe2a591e322bacc",
		sig: "PS1c/aT/OAMyYaPhSudMMJX7TjCaXVrkjk6zOmjoFfZR9ZxjkzjTgfMg6smbq6KCDRoqh4AmXwUAtnJivESDBw==",
		status: `{"delegation":"Ns6SlOeXzx7s/xxhuKIWR+RaIO7das2yq+KlkeMiusw=",` +
			`"grant_id":"01JB2Z6V9K3M4N5P6Q7R8S9T42","issued_at":1790856060,"not_after":1790856360,` +
			`"status":"valid","v":1}`,
		statusSig: "AcQTmAdY8UpkeDssy4iHgHo8hKPZxwq1FJI8YHOwSUOgHRlCEc+SV4VVZr7fTn/jzKrFo9EilExC3XwKJKW1Bw==",
		from:      1790856000, to: 1790856420,
	},
}

// §16 leash.json: the library reproduces the spec's two vectors byte for
// byte, and the reference verifier accepts them exactly in their window.
func TestSpecVectors(t *testing.T) {
	for _, v := range specVectors {
		t.Run(v.name, func(t *testing.T) {
			b := v.d.Marshal()
			if string(b) != v.delegation {
				t.Fatalf("delegation:\n got %s\nwant %s", b, v.delegation)
			}
			if h := sha256.Sum256(b); hex.EncodeToString(h[:]) != v.sha {
				t.Fatal("sha-256")
			}
			sig, err := Sign(key(0x30), b)
			if err != nil || base64.StdEncoding.EncodeToString(sig) != v.sig {
				t.Fatalf("sig: %v", err)
			}
			st, err := NewStatus(b, v.d.IssuedAt.Add(time.Minute))
			if err != nil || string(st.Marshal()) != v.status {
				t.Fatalf("status: %v\n got %s\nwant %s", err, st.Marshal(), v.status)
			}
			ss, err := SignStatus(key(0x04), st.Marshal())
			if err != nil || base64.StdEncoding.EncodeToString(ss) != v.statusSig {
				t.Fatalf("status sig: %v", err)
			}
			got, err := ParseCanonical(b)
			if err != nil || !bytes.Equal(got.Marshal(), b) {
				t.Fatalf("parse: %v", err)
			}
			p := &Presented{Delegation: b, Sig: sig, Status: st.Marshal(), StatusSig: ss}
			for _, now := range []int64{v.from, v.to, (v.from + v.to) / 2} {
				if _, err := VerifyPresented(pub(0x30), p, time.Unix(now, 0)); err != nil {
					t.Fatalf("rejected at %d: %v", now, err)
				}
			}
			for _, now := range []int64{v.from - 1, v.to + 1} {
				if _, err := VerifyPresented(pub(0x30), p, time.Unix(now, 0)); err == nil {
					t.Fatalf("accepted at %d", now)
				}
			}
		})
	}
}

// §10.11: an items.read delegation carries its share rule in scope.
func TestItemsDelegation(t *testing.T) {
	d := itemsSample()
	b := d.Marshal()
	want := `"scope":{"access":"read","match":"all","op":"items.read","tags":["agent ok","work"],"uses":10}`
	if !bytes.Contains(b, []byte(want)) || !bytes.Contains(b, []byte(`"limits":{"per_day":1000,"per_hour":60}`)) {
		t.Fatalf("jcs: %s", b)
	}
	got, err := ParseCanonical(b)
	if err != nil || got.Scope.Match != "all" || len(got.Scope.Tags) != 2 || got.Scope.Uses != 10 || got.Limits.PerDay != 1000 {
		t.Fatalf("parse: %+v %v", got, err)
	}
	noUses := *d
	noUses.Scope.Uses = 0
	if bytes.Contains(noUses.Marshal(), []byte(`"uses"`)) {
		t.Fatal("uses written without a limit")
	}
	if _, err := ParseCanonical(noUses.Marshal()); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string][]byte{
		"no tags":    func() []byte { e := *d; e.Scope.Tags = nil; return e.Marshal() }(),
		"bad tag":    bytes.Replace(b, []byte(`"work"`), []byte(`"Work"`), 1),
		"bad match":  bytes.Replace(b, []byte(`"all"`), []byte(`"some"`), 1),
		"bad access": bytes.Replace(b, []byte(`"read"`), []byte(`"write"`), 1),
		"tags on send": func() []byte {
			e := *sample()
			e.Scope.Tags, e.Scope.Match, e.Scope.Access = d.Scope.Tags, "any", "read"
			return e.Marshal()
		}(),
		"uses on send": func() []byte { e := *sample(); e.Scope.Uses = 3; return e.Marshal() }(),
		"connections": func() []byte {
			e := *d
			e.Scope.Connections = []string{"01JB2Z6V9K3M4N5P6Q7R8S9T0W"}
			return e.Marshal()
		}(),
		"no limits":       func() []byte { e := *d; e.Limits = nil; return e.Marshal() }(),
		"no per_day":      bytes.Replace(b, []byte(`"per_day":1000,`), nil, 1),
		"unknown limit":   bytes.Replace(b, []byte(`"per_day":1000,`), []byte(`"per_day":1000,"per_min":1,`), 1),
		"unknown in rule": bytes.Replace(b, []byte(`"access":"read",`), []byte(`"access":"read","fields":"all",`), 1),
	} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// §10.11: JCS bytes, signature by the credential key (iss), expiry.
func TestDelegationRoundTrip(t *testing.T) {
	d := sample()
	b := d.Marshal()
	if !bytes.HasPrefix(b, []byte(`{"approval":"auto","exp":`)) || bytes.Contains(b, []byte(" ")) || bytes.Contains(b, []byte("tags")) {
		t.Fatalf("not JCS: %s", b)
	}
	sig, err := Sign(key(member), b)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Sign(key(8), b); err == nil {
		t.Fatal("signed by a key other than iss")
	}
	got, err := Verify(pub(member), b, sig, d.IssuedAt.Add(time.Minute))
	if err != nil || got.GrantID != d.GrantID || got.Version != 3 || len(got.Scope.Connections) != 1 {
		t.Fatalf("verify: %v %+v", err, got)
	}
	// Owner decision 9: no iat check (the statement's issued_at bounds
	// freshness).
	if _, err := Verify(pub(member), b, sig, d.IssuedAt.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(pub(8), b, sig, d.IssuedAt); err == nil {
		t.Fatal("iss not the trusted member key accepted")
	}
	if _, err := Verify(pub(member), b, sig, d.Expires); err == nil {
		t.Fatal("expired delegation accepted")
	}
	tampered := bytes.Replace(b, []byte(`"auto"`), []byte(`"ask"`), 1)
	if _, err := Verify(pub(member), tampered, sig, d.IssuedAt); err == nil {
		t.Fatal("tampered delegation accepted")
	}
}

func TestDelegationStrict(t *testing.T) {
	d := sample()
	good := d.Marshal()
	if !bytes.Contains(good, []byte(`"nonce":"BwcHBwcHBwcHBwcHBwcHBw==",`)) {
		t.Fatalf("test nonce: %s", good)
	}
	for name, b := range map[string][]byte{
		"bad approval":  bytes.Replace(good, []byte(`"auto"`), []byte(`"always"`), 1),
		"exp at iat":    func() []byte { e := *d; e.Expires = e.IssuedAt; return e.Marshal() }(),
		"exp before":    func() []byte { e := *d; e.Expires = e.IssuedAt.Add(-time.Second); return e.Marshal() }(),
		"empty conns":   bytes.Replace(good, []byte(`["01JB2Z6V9K3M4N5P6Q7R8S9T0W"]`), []byte(`[]`), 1),
		"bad id":        bytes.Replace(good, []byte(`01JB2Z6V9K3M4N5P6Q7R8S9T0V`), []byte(`not-a-ulid`), 1),
		"version 2":     bytes.Replace(good, []byte(`"v":1`), []byte(`"v":2`), 1),
		"unknown":       bytes.Replace(good, []byte(`{"approval"`), []byte(`{"aud":"x","approval"`), 1),
		"auto no limit": func() []byte { e := *d; e.Limits = nil; return e.Marshal() }(),
		"ask limit":     func() []byte { e := *d; e.Approval = "ask"; return e.Marshal() }(),
		"short nonce":   func() []byte { e := *d; e.Nonce = e.Nonce[:15]; return e.Marshal() }(),
		"no nonce":      bytes.Replace(good, []byte(`"nonce":"BwcHBwcHBwcHBwcHBwcHBw==",`), nil, 1),
		"url nonce":     bytes.Replace(good, []byte(`"BwcHBwcHBwcHBwcHBwcHBw=="`), []byte(`"BwcHBwcHBwcHBwcHBwcHBw"`), 1),
		"ttl 59":        func() []byte { e := *d; e.StatusTTL = 59 * time.Second; return e.Marshal() }(),
		"ttl 3601":      func() []byte { e := *d; e.StatusTTL = 3601 * time.Second; return e.Marshal() }(),
		"scope string": bytes.Replace(good, []byte(`"scope":{"connections":["01JB2Z6V9K3M4N5P6Q7R8S9T0W"],"op":"message.send"}`),
			[]byte(`"scope":"message.send"`), 1),
		"old format": []byte(`{"v":1,"vault_ik":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","agent_ik":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",` +
			`"grant_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V","version":1,"scope":"message.send","approval":"ask","status_ttl":900,"iat":1790000000}`),
		"duplicate": bytes.Replace(good, []byte(`"v":1`), []byte(`"v":1,"v":1`), 1),
	} {
		if _, err := Parse(b); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// Not JCS: a verifier accepts the bytes as received; the vault does not.
	spaced := bytes.Replace(good, []byte(`,"scope"`), []byte(`, "scope"`), 1)
	if _, err := Parse(spaced); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseCanonical(spaced); err == nil {
		t.Fatal("non-JCS bytes accepted as the vault's")
	}
	if _, err := Sign(key(member), spaced); err == nil {
		t.Fatal("signed non-JCS bytes")
	}
	// Without an expiry (LEASH §3.2: the contract's expiry is optional).
	open := *d
	open.Expires = time.Time{}
	ob := open.Marshal()
	if bytes.Contains(ob, []byte(`"exp"`)) {
		t.Fatalf("exp written: %s", ob)
	}
	sig, _ := Sign(key(member), ob)
	if got, err := Verify(pub(member), ob, sig, d.IssuedAt.Add(400*24*time.Hour)); err != nil || !got.Expires.IsZero() {
		t.Fatalf("open-ended delegation: %v", err)
	}
	if _, err := Sign(key(member), []byte(`{}`)); err == nil {
		t.Fatal("signed a non-delegation")
	}
}

func TestNonce(t *testing.T) {
	a, err := NewNonce()
	if err != nil || len(a) != NonceSize {
		t.Fatal(err)
	}
	b, _ := NewNonce()
	if bytes.Equal(a, b) {
		t.Fatal("nonce repeated")
	}
}

func FuzzParseDelegation(f *testing.F) {
	f.Add(sample().Marshal())
	f.Add(itemsSample().Marshal())
	f.Add([]byte(specVectors[0].delegation))
	f.Add([]byte(`{"v":1}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		d, err := ParseCanonical(b)
		if err != nil {
			if d, err := Parse(b); err == nil {
				// Accepted as received: its JCS form is the vault's.
				if _, err := ParseCanonical(d.Marshal()); err != nil {
					t.Fatal("parsed delegation does not re-encode")
				}
			}
			return
		}
		if !bytes.Equal(d.Marshal(), b) {
			t.Fatal("accepted non-canonical bytes")
		}
	})
}

// presented builds what an agent shows: a delegation signed by the member
// key, and a status statement signed by signer.
func presented(t *testing.T, d *Delegation, signer ed25519.PrivateKey, chain []*handshake.Rotation, now time.Time) *Presented {
	t.Helper()
	b := d.Marshal()
	sig, err := Sign(key(member), b)
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
	return &Presented{Delegation: b, Sig: sig, Status: sb, StatusSig: ss, Rotations: chain}
}

// §10.11 status statements: verifiable offline with only the delegation
// and the statement; signer = the named status issuer (through its
// rotation chain); stale, forged, wrong-issuer or wrong-delegation
// statements rejected; the revocation bound is status_ttl + 60 s.
func TestStatusStatements(t *testing.T) {
	d := sample()
	now := d.IssuedAt.Add(time.Minute)
	m := pub(member)
	p := presented(t, d, key(1), nil, now)
	if _, err := VerifyPresented(m, p, now.Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	st, _ := ParseStatus(p.Status)
	if st.NotAfter.Sub(st.IssuedAt) != DefaultStatusTTL {
		t.Fatalf("ttl %v", st.NotAfter.Sub(st.IssuedAt))
	}
	// The bound: accepted until not_after + 60 s, never after.
	if _, err := VerifyPresented(m, p, st.NotAfter.Add(StatusSkew)); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyPresented(m, p, st.NotAfter.Add(StatusSkew+time.Second)); err == nil {
		t.Fatal("stale statement accepted")
	}
	// issued_at - 60 s.
	if _, err := VerifyPresented(m, p, st.IssuedAt.Add(-StatusSkew-time.Second)); err == nil {
		t.Fatal("statement from the future accepted")
	}
	// A status statement is required.
	if _, err := VerifyPresented(m, &Presented{Delegation: p.Delegation, Sig: p.Sig}, now); err == nil {
		t.Fatal("delegation without a statement accepted")
	}
	// Signed by another key than the status issuer.
	if _, err := VerifyPresented(m, presented(t, d, key(2), nil, now), now); err == nil {
		t.Fatal("wrong issuer accepted")
	}
	// Forged: a statement altered after signing.
	f := *p
	f.Status = bytes.Replace(p.Status, []byte(`"not_after":`), []byte(`"not_after":1`), 1)
	if _, err := VerifyPresented(m, &f, now); err == nil {
		t.Fatal("forged statement accepted")
	}
	// A statement longer-lived than the delegation's status_ttl, though
	// signed by the issuer.
	long := &Status{Delegation: st.Delegation, GrantID: st.GrantID, IssuedAt: st.IssuedAt, NotAfter: st.IssuedAt.Add(DefaultStatusTTL + time.Second)}
	lb := long.Marshal()
	ls, _ := SignStatus(key(1), lb)
	if _, err := VerifyPresented(m, &Presented{Delegation: p.Delegation, Sig: p.Sig, Status: lb, StatusSig: ls}, now); err == nil {
		t.Fatal("statement past status_ttl accepted")
	}
	// Unknown members in the statement.
	ub := bytes.Replace(p.Status, []byte(`"v":1}`), []byte(`"v":1,"x":1}`), 1)
	us, _ := suite.Sign(key(1), LabelStatus, ub)
	if _, err := VerifyPresented(m, &Presented{Delegation: p.Delegation, Sig: p.Sig, Status: ub, StatusSig: us}, now); err == nil {
		t.Fatal("unknown status member accepted")
	}
	// A statement for another delegation.
	other := *d
	other.Version = 4
	q := presented(t, &other, key(1), nil, now)
	mixed := *p
	mixed.Status, mixed.StatusSig = q.Status, q.StatusSig
	if _, err := VerifyPresented(m, &mixed, now); err == nil {
		t.Fatal("statement of another delegation accepted")
	}
	// The member's signature still matters.
	if _, err := VerifyPresented(pub(8), p, now); err == nil {
		t.Fatal("delegation under another member key accepted")
	}
	// Trust may follow the member's earlier credential keys (§3.5.5).
	trustBoth := func(k ed25519.PublicKey) bool {
		return suite.EqualPublic(k, pub(8)) || suite.EqualPublic(k, pub(member))
	}
	if _, err := VerifyPresentedTrust(trustBoth, p, now); err != nil {
		t.Fatal(err)
	}
	// Never past the delegation's own exp.
	short := *d
	short.Expires = short.IssuedAt.Add(5 * time.Minute)
	sp := presented(t, &short, key(1), nil, now)
	if s2, _ := ParseStatus(sp.Status); !s2.NotAfter.Equal(short.Expires) {
		t.Fatalf("not_after past exp: %v", s2.NotAfter)
	}
	// After the vault's ik rotated: the statement is signed by the new key
	// and carries the chain from the delegation's status_issuer.
	newIK := key(3)
	kem, _ := suite.NewPrivateKey(bytes.Repeat([]byte{4}, 32))
	rot, err := handshake.NewRotation(key(1), newIK, kem.Public())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyPresented(m, presented(t, d, newIK, []*handshake.Rotation{rot}, now), now); err != nil {
		t.Fatalf("rotated issuer: %v", err)
	}
	if _, err := VerifyPresented(m, presented(t, d, newIK, nil, now), now); err == nil {
		t.Fatal("new key accepted without the chain")
	}
}

func FuzzParseStatus(f *testing.F) {
	st, _ := NewStatus(sample().Marshal(), sample().IssuedAt)
	f.Add(st.Marshal())
	f.Fuzz(func(t *testing.T, b []byte) {
		s, err := ParseStatusCanonical(b)
		if err == nil && !bytes.Equal(s.Marshal(), b) {
			t.Fatal("non-canonical status accepted")
		}
	})
}
