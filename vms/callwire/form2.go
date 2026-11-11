package callwire

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"strconv"
	"strings"
)

// Form 2 of the signed key-exchange shares and key confirmation
// (VAULT-MESSAGING §10.10 "Signed key-exchange shares", "Call forms",
// "Key confirmation"; C2, CALLS-PLAN §12.3, §13.2).
const (
	RoleOffer2  = "offer2"
	RoleAnswer2 = "answer2"
	// MaxSuites bounds a suites or offered list; a suite is 1–65,535.
	MaxSuites = 8
	MaxSuite  = 65535
	// LabelConfirm is the salt of k_confirm.
	LabelConfirm = "vettid/vms/2/call-confirm"
	// ConfirmSize is the length of confirm.
	ConfirmSize = 32
)

// ErrSuites is a suites or offered list outside its limits.
var ErrSuites = errors.New("callwire: invalid media suite list")

// ValidSuites checks a suites or offered list: 1 to MaxSuites suites, each
// 1–MaxSuite, none repeated.
func ValidSuites(list []int) error {
	if len(list) == 0 || len(list) > MaxSuites {
		return ErrSuites
	}
	seen := map[int]bool{}
	for _, s := range list {
		if s < 1 || s > MaxSuite || seen[s] {
			return ErrSuites
		}
		seen[s] = true
	}
	return nil
}

// SuiteList is list(x): the numbers of x in decimal without leading
// zeros, joined by one space ("2 1").
func SuiteList(list []int) string {
	parts := make([]string, len(list))
	for i, s := range list {
		parts[i] = strconv.Itoa(s)
	}
	return strings.Join(parts, " ")
}

func m2(role, callID, media, suites string, share []byte) []byte {
	m := make([]byte, 0, len(role)+len(callID)+len(media)+len(suites)+4+len(share))
	m = append(append(m, role...), 0)
	m = append(append(m, callID...), 0)
	m = append(append(m, media...), 0)
	m = append(append(m, suites...), 0)
	return append(m, share...)
}

// OfferMessage2 is a form 2 offer's signed bytes:
//
//	"offer2" || 0x00 || call_id || 0x00 || media || 0x00 || list(offered) || 0x00 || ek
func OfferMessage2(callID, media string, offered []int, ek []byte) []byte {
	return m2(RoleOffer2, callID, media, SuiteList(offered), ek)
}

// AnswerMessage2 is a form 2 answer's signed bytes:
//
//	"answer2" || 0x00 || call_id || 0x00 || "" || 0x00 || chosen || 0x00 || list(offered) || 0x00 || enc
//
// offered is the caller's list as the answering device read it.
func AnswerMessage2(callID string, chosen int, offered []int, enc []byte) []byte {
	return m2(RoleAnswer2, callID, "", strconv.Itoa(chosen)+"\x00"+SuiteList(offered), enc)
}

// ConfirmKey is k_confirm = HKDF-SHA-256(ikm = k_call, salt =
// "vettid/vms/2/call-confirm", info = call_id, L = 32). The devices derive
// it before they wipe k_call.
func ConfirmKey(kCall []byte, callID string) ([]byte, error) {
	k, err := hkdf.Key(sha256.New, kCall, []byte(LabelConfirm), callID, KeySize)
	if err != nil {
		return nil, ErrCall
	}
	return k, nil
}

// Confirm is confirm = HMAC-SHA-256(k_confirm, chosen || 0x00 ||
// list(offered) || 0x00 || call_id), with chosen and offered as in the
// answer's m2.
func Confirm(kConfirm []byte, chosen int, offered []int, callID string) []byte {
	mac := hmac.New(sha256.New, kConfirm)
	mac.Write([]byte(strconv.Itoa(chosen) + "\x00" + SuiteList(offered) + "\x00" + callID))
	return mac.Sum(nil)
}

// VerifyConfirm checks confirm in constant time (the calling device).
func VerifyConfirm(kConfirm []byte, chosen int, offered []int, callID string, confirm []byte) bool {
	return hmac.Equal(Confirm(kConfirm, chosen, offered, callID), confirm)
}
