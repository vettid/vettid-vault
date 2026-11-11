package callwire

import (
	"bytes"
	"testing"
)

// TestValidShareMessage: a vault vouches only for a share's signed bytes
// exactly as the four forms write them.
func TestValidShareMessage(t *testing.T) {
	const id = "01JABCDEFGHJKMNPQRSTVWXYZ0"
	ek, enc := bytes.Repeat([]byte{0}, EKSize), bytes.Repeat([]byte{7}, EncSize) // shares may hold 0x00
	for name, m := range map[string][]byte{
		"offer":   ShareMessage(RoleOffer, id, "audio", ek),
		"video":   ShareMessage(RoleOffer, id, "video", ek),
		"answer":  ShareMessage(RoleAnswer, id, "", enc),
		"offer2":  OfferMessage2(id, "audio", []int{2, 1}, ek),
		"answer2": AnswerMessage2(id, 1, []int{2, 1}, enc),
		"max":     AnswerMessage2(id, MaxSuite, []int{MaxSuite, 1, 2, 3, 4, 5, 6, 7}, enc),
	} {
		if !ValidShareMessage(m) {
			t.Errorf("%s refused", name)
		}
	}
	bad := map[string][]byte{
		"empty":            nil,
		"role only":        []byte("offer"),
		"unknown role":     ShareMessage("offer3", id, "audio", ek),
		"bad call_id":      ShareMessage(RoleOffer, id[:25], "audio", ek),
		"lower call_id":    ShareMessage(RoleOffer, "01jabcdefghjkmnpqrstvwxyz0", "audio", ek),
		"offer no media":   ShareMessage(RoleOffer, id, "", ek),
		"offer bad media":  ShareMessage(RoleOffer, id, "text", ek),
		"answer media":     ShareMessage(RoleAnswer, id, "audio", enc),
		"offer enc size":   ShareMessage(RoleOffer, id, "audio", enc),
		"answer ek size":   ShareMessage(RoleAnswer, id, "", ek),
		"short share":      ShareMessage(RoleOffer, id, "audio", ek[1:]),
		"long share":       ShareMessage(RoleOffer, id, "audio", append(ek, 0)),
		"form 1 as 2":      ShareMessage(RoleOffer2, id, "audio", ek),
		"answer 1 as 2":    ShareMessage(RoleAnswer2, id, "", enc),
		"no suites":        m2(RoleOffer2, id, "audio", "", ek),
		"leading zero":     m2(RoleOffer2, id, "audio", "02 1", ek),
		"zero":             m2(RoleOffer2, id, "audio", "0", ek),
		"too big":          m2(RoleOffer2, id, "audio", "65536", ek),
		"sign":             m2(RoleOffer2, id, "audio", "+1", ek),
		"repeated":         m2(RoleOffer2, id, "audio", "1 1", ek),
		"two spaces":       m2(RoleOffer2, id, "audio", "2  1", ek),
		"trailing space":   m2(RoleOffer2, id, "audio", "1 ", ek),
		"comma":            m2(RoleOffer2, id, "audio", "2,1", ek),
		"nine":             m2(RoleOffer2, id, "audio", "1 2 3 4 5 6 7 8 9", ek),
		"chosen empty":     m2(RoleAnswer2, id, "", "\x002 1", enc),
		"chosen zero":      m2(RoleAnswer2, id, "", "0\x002 1", enc),
		"chosen leading 0": m2(RoleAnswer2, id, "", "01\x002 1", enc),
		"chosen too big":   m2(RoleAnswer2, id, "", "65536\x002 1", enc),
		"answer2 media":    m2(RoleAnswer2, id, "audio", "1\x002 1", enc),
		"answer2 no list":  m2(RoleAnswer2, id, "", "1\x00", enc),
		"offer2 enc":       m2(RoleOffer2, id, "audio", "1", enc),
	}
	for name, m := range bad {
		if ValidShareMessage(m) {
			t.Errorf("%s accepted", name)
		}
	}
}
