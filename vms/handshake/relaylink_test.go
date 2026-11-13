package handshake

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/vettid/vettid-vault/vms/suite"
)

func relayKey(b byte) ed25519.PrivateKey { return ed25519.NewKeyFromSeed(seed(b)) }

func pubOf(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }

// relayChain signs links k[0]->k[1]->...->k[n].
func relayChain(t testing.TB, ks ...ed25519.PrivateKey) []*RelayLink {
	t.Helper()
	var out []*RelayLink
	for i := 1; i < len(ks); i++ {
		l, err := NewRelayLink(ks[i-1], ks[i])
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, l)
	}
	return out
}

// The signed bytes are exactly "vettid/vms/2/relay-rotate" || old || new
// (rule U), signed by both keys with plain Ed25519.
func TestRelayLinkSignedBytes(t *testing.T) {
	a, b := relayKey(0x61), relayKey(0x62)
	l, err := NewRelayLink(a, b)
	if err != nil {
		t.Fatal(err)
	}
	m := append(append([]byte("vettid/vms/2/relay-rotate"), pubOf(a)...), pubOf(b)...)
	if !bytes.Equal(RelayLinkSigned(pubOf(a), pubOf(b)), m) || len(m) != 25+64 {
		t.Fatal("signed bytes")
	}
	if !ed25519.Verify(pubOf(a), m, l.SigOld) || !ed25519.Verify(pubOf(b), m, l.SigNew) {
		t.Fatal("signatures are not plain Ed25519 over m")
	}
	if !bytes.Equal(ed25519.Sign(a, m), l.SigOld) {
		t.Fatal("sig_old is not deterministic Ed25519(old, m)")
	}
	if err := l.Verify(); err != nil {
		t.Fatal(err)
	}
}

func TestRelayLinkVerifyRefuses(t *testing.T) {
	a, b, c := relayKey(0x61), relayKey(0x62), relayKey(0x63)
	l, _ := NewRelayLink(a, b)
	bad := *l
	bad.SigOld = bytes.Clone(l.SigOld)
	bad.SigOld[0] ^= 1
	if bad.Verify() == nil {
		t.Fatal("wrong sig_old accepted")
	}
	bad = *l
	bad.SigNew = l.SigOld // the old key's signature in sig_new
	if bad.Verify() == nil {
		t.Fatal("sig_old in sig_new accepted")
	}
	bad = *l
	bad.New = pubOf(c) // signed for b
	if bad.Verify() == nil {
		t.Fatal("a link re-pointed to another key accepted")
	}
	sw := &RelayLink{Old: l.New, New: l.Old, SigOld: l.SigNew, SigNew: l.SigOld}
	if sw.Verify() == nil {
		t.Fatal("a reversed link accepted")
	}
	if _, err := NewRelayLink(a, a); err == nil {
		t.Fatal("a link from a key to itself signed")
	}
	m := RelayLinkSigned(pubOf(a), pubOf(a))
	self := &RelayLink{Old: pubOf(a), New: pubOf(a), SigOld: ed25519.Sign(a, m), SigNew: ed25519.Sign(a, m)}
	if !errors.Is(self.Verify(), ErrRelayLink) {
		t.Fatal("a link from a key to itself accepted")
	}
	if p, err := ParseRelayLink(self.Marshal()); err != nil || !errors.Is(VerifyRelayChain(pubOf(a), pubOf(a), []*RelayLink{p}), ErrRelayLink) {
		t.Fatal("a parsed link from a key to itself verified")
	}
	// The identity link's label does not verify a relay link.
	idm := append([]byte(suite.LabelRotate), pubOf(a)...)
	idm = append(idm, pubOf(b)...)
	other := &RelayLink{Old: pubOf(a), New: pubOf(b), SigOld: ed25519.Sign(a, idm), SigNew: ed25519.Sign(b, idm)}
	if other.Verify() == nil {
		t.Fatal("a signature under the identity link's label accepted")
	}
}

func TestVerifyRelayChain(t *testing.T) {
	ks := []ed25519.PrivateKey{relayKey(0x61), relayKey(0x62), relayKey(0x63), relayKey(0x64)}
	ch := relayChain(t, ks...)
	first, last := pubOf(ks[0]), pubOf(ks[3])
	if err := VerifyRelayChain(first, last, ch); err != nil {
		t.Fatal(err)
	}
	if err := VerifyRelayChain(first, pubOf(ks[1]), ch[:1]); err != nil {
		t.Fatal("single link:", err)
	}
	cases := map[string]func() error{
		"empty":            func() error { return VerifyRelayChain(first, first, nil) },
		"first not sender": func() error { return VerifyRelayChain(pubOf(ks[1]), last, ch) },
		"last not announced": func() error {
			return VerifyRelayChain(first, pubOf(ks[2]), ch)
		},
		"broken chain": func() error {
			return VerifyRelayChain(first, last, []*RelayLink{ch[0], ch[2]})
		},
		"reordered": func() error {
			return VerifyRelayChain(first, last, []*RelayLink{ch[1], ch[0], ch[2]})
		},
		"short key": func() error { return VerifyRelayChain(first[:31], last, ch) },
		"repeated key A->B->A": func() error {
			return VerifyRelayChain(first, first, relayChain(t, ks[0], ks[1], ks[0]))
		},
		"repeated key A->B->C->B": func() error {
			return VerifyRelayChain(first, pubOf(ks[1]), relayChain(t, ks[0], ks[1], ks[2], ks[1]))
		},
	}
	for name, f := range cases {
		if f() == nil {
			t.Errorf("%s accepted", name)
		}
	}
	var long []ed25519.PrivateKey
	for i := 0; i <= MaxRelayLinks+1; i++ {
		long = append(long, relayKey(byte(0x80+i)))
	}
	lc := relayChain(t, long...) // 33 links
	if VerifyRelayChain(pubOf(long[0]), pubOf(long[33]), lc) == nil {
		t.Fatal("33 links accepted")
	}
	if err := VerifyRelayChain(pubOf(long[0]), pubOf(long[32]), lc[:32]); err != nil {
		t.Fatal("32 links:", err)
	}
}

func TestRelayLinkParse(t *testing.T) {
	l, _ := NewRelayLink(relayKey(0x61), relayKey(0x62))
	b := l.Marshal()
	want := `{"v":1,"suite":2,"old":"` + base64.StdEncoding.EncodeToString(l.Old) + `","new":"` + base64.StdEncoding.EncodeToString(l.New) +
		`","sig_old":"` + base64.StdEncoding.EncodeToString(l.SigOld) + `","sig_new":"` + base64.StdEncoding.EncodeToString(l.SigNew) + `"}`
	if string(b) != want {
		t.Fatalf("marshal:\n %s\n %s", b, want)
	}
	p, err := ParseRelayLink(b)
	if err != nil || p.Verify() != nil || !bytes.Equal(p.Marshal(), b) {
		t.Fatal("round trip")
	}
	if _, err := ParseRelayLink(replaceMember(t, b, "x_unknown", 1)); err != nil {
		t.Fatal("an unknown member refused (§10.1: ignored)")
	}
	// 0.90.3: v = 1 and suite = 2, nothing else (relay_unlinked).
	for name, raw := range map[string][]byte{
		"v 2":            replaceMember(t, b, "v", 2),
		"v 0":            replaceMember(t, b, "v", 0),
		"v string":       replaceMember(t, b, "v", "1"),
		"no v":           replaceMember(t, b, "v", nil),
		"suite 1":        replaceMember(t, b, "suite", 1),
		"suite 3":        replaceMember(t, b, "suite", 3),
		"suite string":   replaceMember(t, b, "suite", "2"),
		"no suite":       replaceMember(t, b, "suite", nil),
		"v 1.0":          []byte(strings.Replace(string(b), `"v":1`, `"v":1.0`, 1)),
		"suite negative": replaceMember(t, b, "suite", -2),
	} {
		if _, err := ParseRelayLink(raw); !errors.Is(err, ErrRelayLink) {
			t.Errorf("%s: %v, want ErrRelayLink", name, err)
		}
	}
	k32 := base64.StdEncoding.EncodeToString(l.Old)
	bad := map[string][]byte{
		"duplicate old":        []byte(strings.Replace(string(b), `,"old"`, `,"old":"`+k32+`","old"`, 1)),
		"short old":            replaceMember(t, b, "old", base64.StdEncoding.EncodeToString(l.Old[:31])),
		"long new":             replaceMember(t, b, "new", base64.StdEncoding.EncodeToString(append(bytes.Clone(l.New), 0))),
		"short sig_old":        replaceMember(t, b, "sig_old", base64.StdEncoding.EncodeToString(l.SigOld[:63])),
		"unpadded":             replaceMember(t, b, "old", base64.RawStdEncoding.EncodeToString(l.Old)),
		"url alphabet":         replaceMember(t, b, "sig_new", base64.URLEncoding.EncodeToString(l.SigNew)),
		"number":               replaceMember(t, b, "old", 7),
		"missing sig_new":      replaceMember(t, b, "sig_new", nil),
		"not an object":        []byte(`[]`),
		"trailing data":        append(bytes.Clone(b), ' ', '{', '}'),
		"non-canonical base64": replaceMember(t, b, "old", nonCanonical(t, l.Old)),
	}
	for name, raw := range bad {
		if _, err := ParseRelayLink(raw); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	arr := func(n int) []json.RawMessage {
		var out []json.RawMessage
		for i := 0; i < n; i++ {
			out = append(out, b)
		}
		return out
	}
	if _, err := ParseRelayLinks(arr(0)); err == nil {
		t.Error("0 links accepted")
	}
	if _, err := ParseRelayLinks(arr(33)); err == nil {
		t.Error("33 links accepted")
	}
	if ls, err := ParseRelayLinks(arr(32)); err != nil || len(ls) != 32 {
		t.Error("32 links refused")
	}
}

// nonCanonical is a base64 of v whose last character carries non-zero
// padding bits.
func nonCanonical(t testing.TB, v []byte) string {
	t.Helper()
	s := base64.StdEncoding.EncodeToString(v) // 32 bytes: 43 chars + "="
	last := strings.IndexByte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", s[42])
	alt := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[last|1]
	if alt == s[42] {
		alt = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[last|2]
	}
	return s[:42] + string(alt) + s[43:]
}

// §6.2: relay_links in a reconnect hs.init, ending at from.relay.pk.
func TestInitRelayLinks(t *testing.T) {
	in := sampleInit(t, PurposeReconnect)
	k := relayKey(0x71)
	in.RelayLinks = relayChain(t, k, ed25519.NewKeyFromSeed(seed(0x10+2))) // to the initiator's relay key
	b, err := in.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte(`"relay_links":[{"v":1,"suite":2,"old":`)) {
		t.Fatal("relay_links not encoded")
	}
	got, err := ParseInit(b)
	if err != nil || len(got.RelayLinks) != 1 || !suite.EqualPublic(got.RelayLinks[0].Old, pubOf(k)) {
		t.Fatalf("round trip: %v", err)
	}
	if err := VerifyRelayChain(pubOf(k), got.From.Relay.PK, got.RelayLinks); err != nil {
		t.Fatal(err)
	}
	// Absent: the encoding is the one without the member.
	plain, _ := sampleInit(t, PurposeReconnect).Marshal()
	if bytes.Contains(plain, []byte("relay_links")) {
		t.Fatal("relay_links encoded when absent")
	}
	links, _ := json.Marshal([]json.RawMessage{in.RelayLinks[0].Marshal()})
	for _, p := range []Purpose{PurposeRekey, PurposeConnection, PurposeApp} {
		raw, _ := sampleInit(t, p).Marshal()
		if _, err := ParseInit(replaceMember(t, raw, "relay_links", json.RawMessage(links))); err == nil {
			t.Errorf("relay_links accepted for %s", p)
		}
	}
	wrong := sampleInit(t, PurposeReconnect)
	wrong.RelayLinks = relayChain(t, relayKey(0x71), relayKey(0x72)) // ends elsewhere
	if _, err := wrong.Marshal(); err == nil {
		t.Fatal("relay_links not ending at from.relay.pk marshalled")
	}
	if _, err := ParseInit(replaceMember(t, plain, "relay_links", []any{})); err == nil {
		t.Fatal("empty relay_links accepted")
	}
}

// §6.2: an hs.resp carries relay and relay_links together, a reconnect's
// only, relay.pk the last link's new.
func TestRespRelayLinks(t *testing.T) {
	k1, k2 := relayKey(0x71), relayKey(0x72)
	addr := RelayAddr{URL: "https://relay.example.org", Mailbox: MailboxID(pubOf(k2)), PK: pubOf(k2)}
	r := &Resp{Token: tokC, ReconnectToken: tokD, Suite: 2, Sig: make([]byte, 64), Relay: &addr, RelayLinks: relayChain(t, k1, k2)}
	b, err := r.Marshal(PurposeReconnect)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseResp(b, PurposeReconnect)
	if err != nil || got.Relay == nil || !suite.EqualPublic(got.Relay.PK, pubOf(k2)) || len(got.RelayLinks) != 1 {
		t.Fatalf("round trip: %v", err)
	}
	if err := VerifyRelayChain(pubOf(k1), got.Relay.PK, got.RelayLinks); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseResp(b, PurposeRekey); err == nil {
		t.Fatal("relay accepted for a rekey")
	}
	plain := &Resp{Token: tokC, ReconnectToken: tokD, Suite: 2, Sig: make([]byte, 64)}
	pb, _ := plain.Marshal(PurposeReconnect)
	if bytes.Contains(pb, []byte("relay")) {
		t.Fatal("relay encoded when absent")
	}
	links, _ := json.Marshal([]json.RawMessage{r.RelayLinks[0].Marshal()})
	if _, err := ParseResp(replaceMember(t, pb, "relay_links", json.RawMessage(links)), PurposeReconnect); err == nil {
		t.Fatal("relay_links without relay accepted")
	}
	if _, err := ParseResp(replaceMember(t, pb, "relay", json.RawMessage(MarshalRelayAddr(addr))), PurposeReconnect); err == nil {
		t.Fatal("relay without relay_links accepted")
	}
	other := RelayAddr{URL: addr.URL, Mailbox: MailboxID(pubOf(k1)), PK: pubOf(k1)}
	if _, err := ParseResp(replaceMember(t, b, "relay", json.RawMessage(MarshalRelayAddr(other))), PurposeReconnect); err == nil {
		t.Fatal("relay.pk other than the last link's new accepted")
	}
	badMbx := RelayAddr{URL: addr.URL, Mailbox: MailboxID(pubOf(k1)), PK: pubOf(k2)}
	if _, err := ParseResp(replaceMember(t, b, "relay", json.RawMessage(MarshalRelayAddr(badMbx))), PurposeReconnect); err == nil {
		t.Fatal("relay.mailbox not derived from relay.pk accepted")
	}
	badURL := RelayAddr{URL: "ftp://relay.example.org", Mailbox: addr.Mailbox, PK: addr.PK}
	if _, err := ParseResp(replaceMember(t, b, "relay", json.RawMessage(MarshalRelayAddr(badURL))), PurposeReconnect); err == nil {
		t.Fatal("a non-https relay.url accepted")
	}
}
