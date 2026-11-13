package peerwire

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/vettid/vettid-vault/vms/handshake"
)

const (
	rrTok  = "v4.public.dGVzdC1zdGFuZGluZw"
	rrRTok = "v4.public.dGVzdC1yZWNvbm5lY3Q"
)

func rrKey(b byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{b}, 32))
}

func b64(v []byte) string { return base64.StdEncoding.EncodeToString(v) }

func rrPub(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }

// sampleUpdate moves from relay key 0x61 through 0x62 to 0x63.
func sampleUpdate(t testing.TB) (*AddressUpdate, ed25519.PublicKey) {
	t.Helper()
	a, b, c := rrKey(0x61), rrKey(0x62), rrKey(0x63)
	l1, err := handshake.NewRelayLink(a, b)
	if err != nil {
		t.Fatal(err)
	}
	l2, err := handshake.NewRelayLink(b, c)
	if err != nil {
		t.Fatal(err)
	}
	pk := rrPub(c)
	return &AddressUpdate{
		Relay: handshake.RelayAddr{URL: "https://relay.example.org", Mailbox: handshake.MailboxID(pk), PK: pk},
		Token: rrTok, ReconnectToken: rrRTok, Links: []*handshake.RelayLink{l1, l2},
	}, rrPub(a)
}

func setMember(t testing.TB, b []byte, name string, v any) []byte {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if v == nil {
		delete(m, name)
	} else {
		raw, _ := json.Marshal(v)
		m[name] = raw
	}
	out, _ := json.Marshal(m)
	return out
}

func TestAddressUpdateRoundTripAndVerify(t *testing.T) {
	u, sender := sampleUpdate(t)
	b, err := u.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(b), `{"relay":{"url":"https://relay.example.org","mailbox":"`) || !strings.Contains(string(b), `,"relay_links":[{"v":1,"suite":2,"old":"`) {
		t.Fatalf("member order: %s", b)
	}
	got, err := ParseAddressUpdate(b)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := got.Marshal()
	if !bytes.Equal(again, b) || got.ReconnectToken != rrRTok || len(got.Links) != 2 {
		t.Fatal("round trip")
	}
	if err := got.Verify(sender); err != nil {
		t.Fatal(err)
	}
	if got.Verify(rrPub(rrKey(0x62))) == nil {
		t.Fatal("a sender other than the first link's old verified")
	}
	// rule U: the last new is relay.pk
	moved := *got
	pk := rrPub(rrKey(0x62))
	moved.Relay = handshake.RelayAddr{URL: got.Relay.URL, Mailbox: handshake.MailboxID(pk), PK: pk}
	if moved.Verify(sender) == nil {
		t.Fatal("links not ending at relay.pk verified")
	}
	// optional members
	u.ReconnectToken = ""
	nb, _ := u.Marshal()
	if strings.Contains(string(nb), "reconnect_token") || strings.Contains(string(nb), "rotations") {
		t.Fatal("absent members encoded")
	}
	if _, err := ParseAddressUpdate(nb); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseAddressUpdate(setMember(t, b, "x_unknown", true)); err != nil {
		t.Fatal("an unknown member refused (§10.1: ignored)")
	}
}

func TestAddressUpdateRotations(t *testing.T) {
	u, _ := sampleUpdate(t)
	b, _ := u.Marshal()
	got, err := ParseAddressUpdate(setMember(t, b, "rotations", []any{}))
	if err != nil {
		t.Fatal("empty rotations refused:", err)
	}
	if got.Rotations != nil {
		t.Fatal("an empty rotations not read as absent (0.90.3)")
	}
	if out, _ := got.Marshal(); !bytes.Equal(out, b) {
		t.Fatal("an empty rotations re-encoded")
	}
	if _, err := ParseAddressUpdate(setMember(t, b, "rotations", []any{map[string]any{"v": 1}})); err == nil {
		t.Fatal("a malformed rotation accepted")
	}
	if _, err := ParseAddressUpdate(setMember(t, b, "rotations", "x")); err == nil {
		t.Fatal("rotations not an array accepted")
	}
}

func TestAddressUpdateRefused(t *testing.T) {
	u, _ := sampleUpdate(t)
	b, _ := u.Marshal()
	var m map[string]json.RawMessage
	_ = json.Unmarshal(b, &m)
	var links []json.RawMessage
	_ = json.Unmarshal(m["relay_links"], &links)
	many := make([]json.RawMessage, 33)
	for i := range many {
		many[i] = links[0]
	}
	otherPK := rrPub(rrKey(0x70))
	cases := map[string][]byte{
		"duplicate token":   []byte(strings.Replace(string(b), `"token":`, `"token":"`+rrTok+`","token":`, 1)),
		"no relay_links":    setMember(t, b, "relay_links", nil),
		"only the old name": setMember(t, setMember(t, b, "links", json.RawMessage(m["relay_links"])), "relay_links", nil),
		"empty links":       setMember(t, b, "relay_links", []any{}),
		"33 links":          setMember(t, b, "relay_links", many),
		"no token":          setMember(t, b, "token", nil),
		"bad token":         setMember(t, b, "token", "not-a-paseto"),
		"empty reconnect":   setMember(t, b, "reconnect_token", ""),
		"no relay":          setMember(t, b, "relay", nil),
		"mailbox mismatch":  setMember(t, b, "relay", map[string]string{"url": "https://relay.example.org", "mailbox": handshake.MailboxID(otherPK), "pk": b64(u.Relay.PK)}),
		"short pk":          setMember(t, b, "relay", map[string]string{"url": "https://relay.example.org", "mailbox": u.Relay.Mailbox, "pk": b64(u.Relay.PK[:31])}),
		"http url":          setMember(t, b, "relay", map[string]string{"url": "http://relay.example.org", "mailbox": u.Relay.Mailbox, "pk": b64(u.Relay.PK)}),
		"short link sig":    setMember(t, b, "relay_links", []any{map[string]any{"v": 1, "suite": 2, "old": b64(u.Links[0].Old), "new": b64(u.Links[0].New), "sig_old": b64(u.Links[0].SigOld[:63]), "sig_new": b64(u.Links[0].SigNew)}}),
		"not an object":     []byte(`[]`),
	}
	for name, raw := range cases {
		if _, err := ParseAddressUpdate(raw); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// A link-level failure keeps handshake.ErrRelayLink (relay_unlinked)
	// inside ErrRelayBody; a missing relay_links is a plain malformed body.
	link := func(v, s any) map[string]any {
		var l map[string]any
		_ = json.Unmarshal(u.Links[0].Marshal(), &l)
		l["v"], l["suite"] = v, s
		return l
	}
	for name, raw := range map[string][]byte{
		"suite 1":     setMember(t, b, "relay_links", []any{link(1, 1)}),
		"suite 3":     setMember(t, b, "relay_links", []any{link(1, 3)}),
		"v 2":         setMember(t, b, "relay_links", []any{link(2, 2)}),
		"0 links":     setMember(t, b, "relay_links", []any{}),
		"33 links":    setMember(t, b, "relay_links", many),
		"later bad v": setMember(t, b, "relay_links", []any{link(1, 2), link(7, 2)}),
	} {
		_, err := ParseAddressUpdate(raw)
		if !errors.Is(err, handshake.ErrRelayLink) || !errors.Is(err, ErrRelayBody) {
			t.Errorf("%s: %v, want ErrRelayBody wrapping ErrRelayLink", name, err)
		}
	}
	if _, err := ParseAddressUpdate(setMember(t, b, "relay_links", nil)); !errors.Is(err, ErrRelayBody) || errors.Is(err, handshake.ErrRelayLink) {
		t.Errorf("missing relay_links: %v, want a plain ErrRelayBody", err)
	}
	for name, v := range map[string]any{"a string": "x", "an object": json.RawMessage(links[0]), "a number": 1} {
		if _, err := ParseAddressUpdate(setMember(t, b, "relay_links", v)); !errors.Is(err, ErrRelayBody) || errors.Is(err, handshake.ErrRelayLink) {
			t.Errorf("relay_links as %s: %v, want a plain ErrRelayBody", name, err)
		}
	}
}

func TestMailboxClosed(t *testing.T) {
	mbx := handshake.MailboxID(rrPub(rrKey(0x61)))
	for _, c := range []MailboxClosed{{Mailbox: mbx, LastMsgID: "01JB2Z6V9K3M4N5P6Q7R8S9T0V"}, {Mailbox: mbx}} {
		b, err := c.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		got, err := ParseMailboxClosed(b)
		if err != nil || *got != c {
			t.Fatalf("round trip %s: %v", b, err)
		}
	}
	null := `{"mailbox":"` + mbx + `","last_msg_id":null}`
	if c, err := ParseMailboxClosed([]byte(null)); err != nil || c.LastMsgID != "" {
		t.Fatal("null last_msg_id refused")
	}
	if b, _ := (&MailboxClosed{Mailbox: mbx}).Marshal(); string(b) != null {
		t.Fatalf("null encoding: %s", b)
	}
	if _, err := ParseMailboxClosed([]byte(`{"mailbox":"` + mbx + `","last_msg_id":null,"x":1}`)); err != nil {
		t.Fatal("an unknown member refused (§10.1: ignored)")
	}
	bad := []string{
		`{"mailbox":"` + mbx + `"}`, // last_msg_id is required (null when none)
		`{"mailbox":"` + mbx + `","last_msg_id":"01jb2z6v9k3m4n5p6q7r8s9t0v"}`, // lower case
		`{"mailbox":"` + mbx + `","last_msg_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0"}`,  // 25 chars
		`{"mailbox":"` + mbx + `","last_msg_id":"81JB2Z6V9K3M4N5P6Q7R8S9T0V"}`, // over 128 bits
		`{"mailbox":"` + mbx + `","last_msg_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0I"}`, // not Crockford
		`{"mailbox":"` + mbx + `","last_msg_id":""}`,                           // empty is not null
		`{"mailbox":"` + mbx + `","last_msg_id":7}`,                            // not a string
		`{"mailbox":"` + strings.ToUpper(mbx) + `","last_msg_id":null}`,        // mailbox upper case
		`{"mailbox":"` + mbx[:25] + `","last_msg_id":null}`,                    // short mailbox
		`{"mailbox":"` + mbx + `","mailbox":"` + mbx + `","last_msg_id":null}`, // duplicate
		`{"last_msg_id":null}`,
		`[]`,
	}
	for _, s := range bad {
		if _, err := ParseMailboxClosed([]byte(s)); err == nil {
			t.Errorf("accepted: %s", s)
		}
	}
	if _, err := ParseMailboxClosed([]byte(`{"mailbox":"` + mbx + `"}`)); !errors.Is(err, ErrRelayBody) {
		t.Fatalf("missing last_msg_id: %v, want ErrRelayBody (0.90.3: required, null allowed)", err)
	}
	if _, err := (&MailboxClosed{Mailbox: "x"}).Marshal(); err == nil {
		t.Fatal("a bad mailbox marshalled")
	}
}

func FuzzParseAddressUpdate(f *testing.F) {
	u, _ := sampleUpdate(f)
	b, _ := u.Marshal()
	f.Add(b)
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		u, err := ParseAddressUpdate(b)
		if err != nil {
			return
		}
		out, err := u.Marshal()
		if err != nil {
			t.Fatalf("accepted body does not re-marshal: %v", err)
		}
		u2, err := ParseAddressUpdate(out)
		if err != nil {
			t.Fatalf("re-marshalled body rejected: %v", err)
		}
		out2, _ := u2.Marshal()
		if !bytes.Equal(out, out2) {
			t.Fatal("marshal not stable")
		}
	})
}

func FuzzParseMailboxClosed(f *testing.F) {
	f.Add([]byte(`{"mailbox":"gr2q7gf5lh6pzfdnurnkvputhp","last_msg_id":null}`))
	f.Add([]byte(`{"mailbox":"gr2q7gf5lh6pzfdnurnkvputhp","last_msg_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V"}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		c, err := ParseMailboxClosed(b)
		if err != nil {
			return
		}
		out, err := c.Marshal()
		if err != nil {
			t.Fatalf("accepted body does not re-marshal: %v", err)
		}
		if c2, err := ParseMailboxClosed(out); err != nil || *c2 != *c {
			t.Fatal("round trip")
		}
	})
}

// Malformed wins (0.90.3): a link refused for its form is relay_unlinked
// only when every other member is well formed.
func TestAddressUpdateMalformedWins(t *testing.T) {
	u, _ := sampleUpdate(t)
	b, _ := u.Marshal()
	var l map[string]any
	_ = json.Unmarshal(u.Links[0].Marshal(), &l)
	l["v"] = 2
	bad := setMember(t, b, "relay_links", []any{l})
	if _, err := ParseAddressUpdate(bad); !errors.Is(err, ErrRelayBody) || !errors.Is(err, handshake.ErrRelayLink) {
		t.Fatalf("a bad-form link alone: %v, want relay_unlinked", err)
	}
	otherPK := rrPub(rrKey(0x70))
	for name, raw := range map[string][]byte{
		"bad token":          setMember(t, bad, "token", "not-a-paseto"),
		"no token":           setMember(t, bad, "token", nil),
		"empty reconnect":    setMember(t, bad, "reconnect_token", ""),
		"mailbox mismatch":   setMember(t, bad, "relay", map[string]string{"url": "https://relay.example.org", "mailbox": handshake.MailboxID(otherPK), "pk": b64(u.Relay.PK)}),
		"bad rotations":      setMember(t, bad, "rotations", []any{map[string]any{"v": 1}}),
		"rotations string":   setMember(t, bad, "rotations", "x"),
		"0 links, bad token": setMember(t, setMember(t, b, "relay_links", []any{}), "token", "not-a-paseto"),
	} {
		if _, err := ParseAddressUpdate(raw); !errors.Is(err, ErrRelayBody) || errors.Is(err, handshake.ErrRelayLink) {
			t.Errorf("bad-form link with %s: %v, want a plain ErrRelayBody", name, err)
		}
	}
}
