package handshake

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/vettid/vettid-vault/vms/altchan"
	"github.com/vettid/vettid-vault/vms/suite"
)

func sampleInit(t testing.TB, purpose Purpose) *Init {
	t.Helper()
	i := newParty(t, 0x10)
	eph, err := suite.NewPrivateKey(seed(0x0c))
	if err != nil {
		t.Fatal(err)
	}
	in := &Init{
		Purpose: purpose, Ctx: testInviteID,
		From: Principal{IK: i.pub(), KEM: i.kem.Public(), Relay: i.addr},
		Eph:  eph.Public(), Token: tokA, Suites: []int{2},
	}
	if purpose == PurposeReconnect {
		in.ReconnectToken = tokB
	}
	if purpose == PurposeRekey {
		in.Token = ""
	}
	if purpose.HasSAS() {
		c := SASCommit(bytes.Repeat([]byte{0x16}, 32))
		in.SASCommit = c[:]
	}
	return in
}

func TestInitRoundTrip(t *testing.T) {
	for _, p := range []Purpose{PurposeApp, PurposeDesktop, PurposeAgent, PurposeConnection, PurposeRekey, PurposeReconnect} {
		in := sampleInit(t, p)
		if p == PurposeApp {
			in.DeviceAttest = &altchan.DeviceAttest{Platform: "android", Chain: [][]byte{{0x30, 0x82}, {0x30, 0x81}}}
		}
		if p == PurposeConnection {
			in.Profile = json.RawMessage(`{"name":"A <b>"}`)
		}
		b, err := in.Marshal()
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		out, err := ParseInit(b)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		b2, err := out.Marshal()
		if err != nil || !bytes.Equal(b, b2) {
			t.Fatalf("%s: not canonical", p)
		}
	}
}

// replaceMember rewrites one member of a JSON object.
func replaceMember(t testing.TB, b []byte, name string, val any) []byte {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if val == nil {
		delete(m, name)
	} else {
		v, _ := json.Marshal(val)
		m[name] = v
	}
	out, _ := json.Marshal(m)
	return out
}

func TestInitFieldRules(t *testing.T) {
	good, err := sampleInit(t, PurposeConnection).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	app, _ := sampleInit(t, PurposeApp).Marshal()
	cases := []struct {
		name string
		b    []byte
	}{
		{"unknown purpose", replaceMember(t, good, "purpose", "vote")},
		{"empty ctx", replaceMember(t, good, "ctx", "")},
		{"ctx with space", replaceMember(t, good, "ctx", "a b")},
		{"missing token", replaceMember(t, good, "token", nil)},
		{"bad token", replaceMember(t, good, "token", "v3.local.x")},
		{"connection with reconnect_token (0.10.3)", replaceMember(t, good, "reconnect_token", tokB)},
		{"connection without sas_commit", replaceMember(t, good, "sas_commit", nil)},
		{"sas_commit wrong size", replaceMember(t, good, "sas_commit", "AAAA")},
		{"pairing without sas_commit", replaceMember(t, app, "sas_commit", nil)},
		{"pairing with reconnect_token", replaceMember(t, app, "reconnect_token", tokB)},
		{"suite 1 offered", replaceMember(t, good, "suites", []int{1, 2})},
		{"suites unsorted", replaceMember(t, good, "suites", []int{3, 2})},
		{"suites duplicate", replaceMember(t, good, "suites", []int{2, 2})},
		{"suites empty", replaceMember(t, good, "suites", []int{})},
		{"suites float", []byte(strings.Replace(string(good), `"suites":[2]`, `"suites":[2.0]`, 1))},
		{"rotations outside reconnect", replaceMember(t, good, "rotations", []any{})},
		{"device_attest outside app", replaceMember(t, good, "device_attest", map[string]any{"platform": "ios", "key_id": "AA==", "attestation": "AA=="})},
		{"device_attest bad platform", replaceMember(t, app, "device_attest", map[string]any{"platform": "web", "chain": []string{"AA=="}})},
		{"device_attest empty chain", replaceMember(t, app, "device_attest", map[string]any{"platform": "android", "chain": []string{}})},
		{"device_attest ios missing key_id", replaceMember(t, app, "device_attest", map[string]any{"platform": "ios", "attestation": "AA=="})},
		{"profile not object", replaceMember(t, good, "profile", "x")},
		{"api_key outside app (0.15.0)", replaceMember(t, good, "api_key", testAPIKeyB64(t))},
		{"api_key not P-256 SPKI", replaceMember(t, app, "api_key", "AAAA")},
		{"eph wrong size", replaceMember(t, good, "eph", "AAAA")},
		{"duplicate member", append(bytes.TrimSuffix(bytes.Clone(good), []byte("}")), []byte(`,"ctx":"x"}`)...)},
		{"case-variant member", []byte(strings.Replace(string(good), `"purpose"`, `"Purpose"`, 1))},
		{"trailing data", append(append([]byte{}, good...), []byte(` {}`)...)},
	}
	for _, c := range cases {
		if _, err := ParseInit(c.b); err == nil {
			t.Errorf("%s: accepted", c.name)
		}
	}
	if _, err := ParseInit(good); err != nil {
		t.Fatal(err)
	}
}

func TestInitEphMustDifferFromStatic(t *testing.T) {
	in := sampleInit(t, PurposeConnection)
	in.Eph = in.From.KEM
	if _, err := in.Marshal(); !errors.Is(err, ErrBody) {
		t.Fatal("eph == from.kem accepted")
	}
}

func TestRelayAddrRules(t *testing.T) {
	i := newParty(t, 0x10)
	ok := i.addr
	if ValidateRelayAddr(ok) != nil {
		t.Fatal("good addr rejected")
	}
	bad := []RelayAddr{
		{URL: ok.URL, Mailbox: "aaaaaaaaaaaaaaaaaaaaaaaaaa", PK: ok.PK},
		{URL: "http://relay.example.org", Mailbox: ok.Mailbox, PK: ok.PK},
		{URL: "https://u@relay.example.org", Mailbox: ok.Mailbox, PK: ok.PK},
		{URL: "https://relay.example.org/?q", Mailbox: ok.Mailbox, PK: ok.PK},
		{URL: "https://relay.example.org/#f", Mailbox: ok.Mailbox, PK: ok.PK},
		{URL: "ftp://relay.example.org", Mailbox: ok.Mailbox, PK: ok.PK},
		{URL: "relay.example.org", Mailbox: ok.Mailbox, PK: ok.PK},
		{URL: ok.URL, Mailbox: ok.Mailbox, PK: ok.PK[:31]},
	}
	for n, a := range bad {
		if ValidateRelayAddr(a) == nil {
			t.Errorf("case %d accepted", n)
		}
	}
	for _, u := range []string{"http://localhost:8080", "http://127.0.0.1:8080", "http://[::1]:8080"} {
		if ValidateRelayURL(u) != nil {
			t.Errorf("%s rejected", u)
		}
	}
}

func TestMailboxIDMatchesRelayVector(t *testing.T) {
	// RELAY-PROTOCOL §9.1 (test-only seed 32 x 0x01).
	pk := []byte{0x8a, 0x88, 0xe3, 0xdd, 0x74, 0x09, 0xf1, 0x95, 0xfd, 0x52, 0xdb, 0x2d, 0x3c, 0xba, 0x5d, 0x72,
		0xca, 0x67, 0x09, 0xbf, 0x1d, 0x94, 0x12, 0x1b, 0xf3, 0x74, 0x88, 0x01, 0xb4, 0x0f, 0x6f, 0x5c}
	if got := MailboxID(pk); got != "gr2q7gf5lh6pzfdnurnkvputhp" {
		t.Fatalf("mailbox = %s", got)
	}
}

func TestRespFieldRules(t *testing.T) {
	nR := bytes.Repeat([]byte{0x17}, 32)
	r := &Resp{Token: tokC, Suite: 2, SASNonce: nR, Sig: make([]byte, 64)}
	b, err := r.Marshal(PurposeConnection)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseResp(b, PurposeConnection); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseResp(replaceMember(t, b, "reconnect_token", tokD), PurposeConnection); err == nil {
		t.Fatal("reconnect_token accepted for a connection (0.10.3)")
	}
	if _, err := ParseResp(replaceMember(t, b, "reconnect_token", tokD), PurposeApp); err == nil {
		t.Fatal("reconnect_token accepted for pairing")
	}
	if _, err := ParseResp(b, PurposeReconnect); err == nil {
		t.Fatal("sas_nonce accepted for a reconnect")
	}
	if _, err := ParseResp(replaceMember(t, b, "sas_nonce", "AAAA"), PurposeConnection); err == nil {
		t.Fatal("short sas_nonce accepted")
	}
	r.SASNonce = nil
	if _, err := r.Marshal(PurposeConnection); err == nil {
		t.Fatal("missing sas_nonce marshalled")
	}
	if _, err := ParseResp(replaceMember(t, b, "rotations", []any{}), PurposeConnection); err == nil {
		t.Fatal("rotations accepted outside reconnect")
	}
	if _, err := ParseResp(replaceMember(t, b, "sig", "AAAA"), PurposeConnection); err == nil {
		t.Fatal("short sig accepted")
	}
	if _, err := ParseResp(replaceMember(t, b, "suite", "2"), PurposeConnection); err == nil {
		t.Fatal("string suite accepted")
	}
	if _, err := ParseFin([]byte(`{"sig":"`+strings.Repeat("A", 86)+`=="}`), PurposeRekey); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseFin([]byte(`{"sig":"`+strings.Repeat("A", 86)+`=="}`), PurposeConnection); err == nil {
		t.Fatal("hs.fin without sas_nonce accepted for a connection")
	}
	nonce := `,"sas_nonce":"` + strings.Repeat("A", 43) + `="`
	if _, err := ParseFin([]byte(`{"sig":"`+strings.Repeat("A", 86)+`=="`+nonce+`}`), PurposeConnection); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseFin([]byte(`{"sig":"`+strings.Repeat("A", 86)+`=="`+nonce+`}`), PurposeReconnect); err == nil {
		t.Fatal("sas_nonce accepted for a reconnect")
	}
	if _, err := ParseFin([]byte(`{"sig":"`+strings.Repeat("A", 86)+"\n"+`=="}`), PurposeRekey); err == nil {
		t.Fatal("base64 with newline accepted")
	}
}

func testAPIKeyB64(t testing.TB) string {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	return base64.StdEncoding.EncodeToString(der)
}

// §6.2 (0.15.0): a transfer's hs.init carries the new app's api_key, for
// purpose app only, and it round-trips.
func TestInitAPIKey(t *testing.T) {
	app, _ := sampleInit(t, PurposeApp).Marshal()
	b := replaceMember(t, app, "api_key", testAPIKeyB64(t))
	in, err := ParseInit(b)
	if err != nil || len(in.APIKey) == 0 {
		t.Fatal(err)
	}
	again, err := in.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseInit(again); err != nil {
		t.Fatal(err)
	}
}
