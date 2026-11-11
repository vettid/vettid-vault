package callwire

import (
	"bytes"
	"testing"
)

// TestValidShareMessage: a vault vouches only for a share's signed bytes
// exactly as the four forms write them.
func TestValidShareMessage(t *testing.T) {
	const id = "01JABCDEFGHJKMNPQRSTVWXYZ0"
	ek, enc := bytes.Repeat([]byte{0}, EKSize), bytes.Repeat([]byte{7}, EncSize)            // shares may hold 0x00
	pp := Parties{Caller: bytes.Repeat([]byte{0}, 32), Callee: bytes.Repeat([]byte{9}, 32)} // keys may hold 0x00 too
	for name, m := range map[string][]byte{
		"offer":   ShareMessage(RoleOffer, id, "audio", ek),
		"video":   ShareMessage(RoleOffer, id, "video", ek),
		"answer":  ShareMessage(RoleAnswer, id, "", enc),
		"offer2":  OfferMessage2(id, "audio", []int{2, 1}, pp, ek),
		"answer2": AnswerMessage2(id, 1, []int{2, 1}, pp, enc),
		"max":     AnswerMessage2(id, MaxSuite, []int{MaxSuite, 1, 2, 3, 4, 5, 6, 7}, pp, enc),
	} {
		if !ValidShareMessage(m) {
			t.Errorf("%s refused", name)
		}
	}
	bad := map[string][]byte{
		"empty":             nil,
		"role only":         []byte("offer"),
		"unknown role":      ShareMessage("offer3", id, "audio", ek),
		"bad call_id":       ShareMessage(RoleOffer, id[:25], "audio", ek),
		"lower call_id":     ShareMessage(RoleOffer, "01jabcdefghjkmnpqrstvwxyz0", "audio", ek),
		"offer no media":    ShareMessage(RoleOffer, id, "", ek),
		"offer bad media":   ShareMessage(RoleOffer, id, "text", ek),
		"answer media":      ShareMessage(RoleAnswer, id, "audio", enc),
		"offer enc size":    ShareMessage(RoleOffer, id, "audio", enc),
		"answer ek size":    ShareMessage(RoleAnswer, id, "", ek),
		"short share":       ShareMessage(RoleOffer, id, "audio", ek[1:]),
		"long share":        ShareMessage(RoleOffer, id, "audio", append(ek, 0)),
		"form 1 as 2":       ShareMessage(RoleOffer2, id, "audio", ek),
		"answer 1 as 2":     ShareMessage(RoleAnswer2, id, "", enc),
		"no suites":         m2(RoleOffer2, id, "audio", "", pp, ek),
		"leading zero":      m2(RoleOffer2, id, "audio", "02 1", pp, ek),
		"zero":              m2(RoleOffer2, id, "audio", "0", pp, ek),
		"too big":           m2(RoleOffer2, id, "audio", "65536", pp, ek),
		"sign":              m2(RoleOffer2, id, "audio", "+1", pp, ek),
		"repeated":          m2(RoleOffer2, id, "audio", "1 1", pp, ek),
		"two spaces":        m2(RoleOffer2, id, "audio", "2  1", pp, ek),
		"trailing space":    m2(RoleOffer2, id, "audio", "1 ", pp, ek),
		"comma":             m2(RoleOffer2, id, "audio", "2,1", pp, ek),
		"nine":              m2(RoleOffer2, id, "audio", "1 2 3 4 5 6 7 8 9", pp, ek),
		"chosen empty":      m2(RoleAnswer2, id, "", "\x002 1", pp, enc),
		"chosen zero":       m2(RoleAnswer2, id, "", "0\x002 1", pp, enc),
		"chosen leading 0":  m2(RoleAnswer2, id, "", "01\x002 1", pp, enc),
		"chosen too big":    m2(RoleAnswer2, id, "", "65536\x002 1", pp, enc),
		"answer2 media":     m2(RoleAnswer2, id, "audio", "1\x002 1", pp, enc),
		"answer2 no list":   m2(RoleAnswer2, id, "", "1\x00", pp, enc),
		"offer2 enc":        m2(RoleOffer2, id, "audio", "1", pp, enc),
		"offer2 no parties": append([]byte(RoleOffer2+"\x00"+id+"\x00audio\x001\x00"), ek...),
		"offer2 one party":  m2(RoleOffer2, id, "audio", "1", Parties{Caller: pp.Caller}, ek),
		"answer2 short":     m2(RoleAnswer2, id, "", "1\x001", Parties{Caller: pp.Caller, Callee: pp.Callee[:31]}, enc),
	}
	for name, m := range bad {
		if ValidShareMessage(m) {
			t.Errorf("%s accepted", name)
		}
	}
}

// VouchingParty: the caller's key in an offer, the callee's in an answer;
// nil for form 1. Confirm names both parties, in order.
func TestParties(t *testing.T) {
	const id = "01JABCDEFGHJKMNPQRSTVWXYZ0"
	ek, enc := bytes.Repeat([]byte{0}, EKSize), bytes.Repeat([]byte{7}, EncSize)
	a, b := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	pp := Parties{Caller: a, Callee: b}
	if v := VouchingParty(OfferMessage2(id, "audio", []int{1}, pp, ek)); !bytes.Equal(v, a) {
		t.Errorf("offer: %x", v)
	}
	if v := VouchingParty(AnswerMessage2(id, 1, []int{1}, pp, enc)); !bytes.Equal(v, b) {
		t.Errorf("answer: %x", v)
	}
	if VouchingParty(ShareMessage(RoleOffer, id, "audio", ek)) != nil || VouchingParty([]byte("junk")) != nil {
		t.Error("form 1 or junk")
	}
	k := bytes.Repeat([]byte{3}, 32)
	c := Confirm(k, 1, []int{1}, id, pp)
	if !VerifyConfirm(k, 1, []int{1}, id, pp, c) || VerifyConfirm(k, 1, []int{1}, id, Parties{Caller: b, Callee: a}, c) ||
		VerifyConfirm(k, 1, []int{1}, id, Parties{Caller: a}, c) {
		t.Error("confirm not bound to the parties in order")
	}
	// Keys of the wrong length never verify, even when their bytes run
	// together into the same HMAC input (a‖b with nothing after it).
	if VerifyConfirm(k, 1, []int{1}, id, pp, nil) || VerifyConfirm(k, 1, []int{1}, id, pp, []byte{}) || VerifyConfirm(k, 1, []int{1}, id, pp, c[:31]) {
		t.Error("an empty or truncated confirm verifies")
	}
	if VerifyConfirm(k, 1, []int{1}, id, Parties{}, nil) || VerifyConfirm(k, 1, []int{1}, id, Parties{}, []byte{}) {
		t.Error("no parties and an empty confirm verify") // Confirm is nil for invalid parties
	}
	if VerifyConfirm(k, 1, []int{1}, id, Parties{Caller: append(bytes.Clone(a), b...)}, c) {
		t.Error("confirm not bound to the parties in order")
	}
}

// (0.88.16) Form 2's k_call names both members: both devices derive the
// same key, which differs from form 1's and from another pair's.
func TestAnswer2(t *testing.T) {
	const id = "01JABCDEFGHJKMNPQRSTVWXYZ0"
	sk, err := NewOfferKey()
	if err != nil {
		t.Fatal(err)
	}
	a, b, c := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{3}, 32)
	pp := Parties{Caller: a, Callee: b}
	enc, k2, err := Answer2(sk.Public().Bytes(), id, pp)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Accept2(sk, enc, id, pp)
	if err != nil || !bytes.Equal(got, k2) {
		t.Fatalf("the two sides differ: %v", err)
	}
	k1, _ := Accept(sk, enc, id)
	other, _ := Accept2(sk, enc, id, Parties{Caller: c, Callee: b})
	swapped, _ := Accept2(sk, enc, id, Parties{Caller: b, Callee: a})
	if bytes.Equal(k1, k2) || bytes.Equal(other, k2) || bytes.Equal(swapped, k2) {
		t.Fatal("k_call not bound to the parties")
	}
	if _, _, err := Answer2(sk.Public().Bytes(), id, Parties{Caller: a}); err == nil {
		t.Fatal("Answer2 with one party")
	}
	if _, err := Accept2(sk, enc, id, Parties{Caller: a, Callee: b[:31]}); err == nil {
		t.Fatal("Accept2 with a short key")
	}
	// A message or confirm naming a short or missing key is never built.
	ek := sk.Public().Bytes()
	if OfferMessage2(id, "audio", []int{1}, Parties{Caller: a}, ek) != nil ||
		AnswerMessage2(id, 1, []int{1}, Parties{Caller: a, Callee: b[:31]}, enc) != nil ||
		Confirm(bytes.Repeat([]byte{9}, 32), 1, []int{1}, id, Parties{Callee: b}) != nil {
		t.Fatal("built with a short or missing key")
	}
}
