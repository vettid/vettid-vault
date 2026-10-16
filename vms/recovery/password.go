package recovery

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"math"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// Passwords (§11.14.7). The enclave normalizes every password to NFC
// before any use; a password that is set must also meet five rules, and
// recovery is armed only for a password that meets rules 1, 2 and 5.

// Weak password reasons (weak_password{reason}).
const (
	ReasonShort     = "short"
	ReasonRepeated  = "repeated"
	ReasonCommon    = "common"
	ReasonSameAsPIN = "same_as_pin"
	ReasonGuessable = "guessable"
)

// commonList is the release's common-password list: one per line, lower
// case, sorted, 12 or more characters. Its SHA-256 is printed in the
// release notes (CommonListSHA256).
//
//go:embed common-passwords.txt
var commonList []byte

// wordList is the estimator's own dictionary of words, names and
// keyboard-and-number patterns (lower case, one per line), written for
// VettID; it holds no third-party list.
//
//go:embed estimator-words.txt
var wordList []byte

var (
	common = loadList(commonList)
	words  = loadList(wordList)
)

func loadList(b []byte) map[string]int {
	m := map[string]int{}
	s := bufio.NewScanner(bytes.NewReader(b))
	rank := 0
	for s.Scan() {
		w := strings.TrimSpace(s.Text())
		if w == "" || strings.HasPrefix(w, "#") {
			continue
		}
		rank++
		if _, ok := m[w]; !ok {
			m[w] = rank
		}
	}
	return m
}

// CommonListSHA256 is the SHA-256 of the embedded common-password list,
// for the release notes.
func CommonListSHA256() string {
	h := sha256.Sum256(commonList)
	return hex.EncodeToString(h[:])
}

// CommonListSorted reports whether the embedded list keeps its form: lower
// case, sorted, unique, 12 or more characters each (a test asserts it).
func CommonListSorted() bool {
	var prev string
	s := bufio.NewScanner(bytes.NewReader(commonList))
	for s.Scan() {
		w := s.Text()
		if strings.HasPrefix(w, "#") {
			continue
		}
		if w != strings.ToLower(w) || utf8.RuneCountInString(w) < MinPasswordRunes || w <= prev {
			return false
		}
		prev = w
	}
	return true
}

// NormalizePassword returns the password's NFC form, or ok false for
// invalid UTF-8 or more than 1,024 bytes after normalization.
func NormalizePassword(pw []byte) ([]byte, bool) {
	if !utf8.Valid(pw) {
		return nil, false
	}
	n := norm.NFC.Bytes(pw)
	if len(n) == 0 || len(n) > MaxPasswordBytes {
		return nil, false
	}
	return n, true
}

func lowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

func oneRepeated(rs []rune) bool {
	for _, r := range rs[1:] {
		if r != rs[0] {
			return false
		}
	}
	return true
}

// CheckNewPassword applies the five rules of §11.14.7 to a normalized
// password being set, in order, and returns the first reason that breaks,
// or "".
func CheckNewPassword(pw []byte, pin string) string {
	rs := []rune(string(pw))
	if len(rs) < MinPasswordRunes {
		return ReasonShort
	}
	if oneRepeated(rs) {
		return ReasonRepeated
	}
	if _, ok := common[lowerASCII(string(pw))]; ok {
		return ReasonCommon
	}
	if pin != "" && string(pw) == pin {
		return ReasonSameAsPIN
	}
	if Guesses(string(pw)) < GuessabilityFloor {
		return ReasonGuessable
	}
	return ""
}

// ArmingAllowed reports whether a password meets rules 1, 2 and 5, the
// condition for arming recovery with it (§11.14.3, §11.14.7).
func ArmingAllowed(pw []byte) bool {
	rs := []rune(string(pw))
	return len(rs) >= MinPasswordRunes && !oneRepeated(rs) && Guesses(string(pw)) >= GuessabilityFloor
}

// --- the estimator ---
//
// In the manner of zxcvbn: every substring is matched against a
// dictionary (the common list and the estimator's words, also reversed and
// with common letter substitutions undone), repeats, sequences, keyboard
// runs and dates; each match has a guess count; the estimate is the
// cheapest way to cover the password with matches and brute-forced runs,
// times the number of ways to order that many parts. It is a model and
// can be wrong in both directions; the app runs the same model with a
// slightly higher threshold (§11.14.7).

const (
	minGuessesSingle = 10
	minGuessesMulti  = 50
	bruteforceCard   = 10
	maxEstimateRunes = 128 // beyond this the password is not guessable by any model here
)

var leet = map[rune]rune{'4': 'a', '@': 'a', '8': 'b', '(': 'c', '3': 'e', '6': 'g', '1': 'i', '!': 'i', '|': 'i',
	'0': 'o', '$': 's', '5': 's', '7': 't', '+': 't', '2': 'z'}

func unleet(rs []rune) ([]rune, int) {
	out := make([]rune, len(rs))
	subs := 0
	for i, r := range rs {
		if l, ok := leet[r]; ok {
			out[i] = l
			subs++
		} else {
			out[i] = r
		}
	}
	return out, subs
}

func dictGuesses(sub []rune, orig []rune) float64 {
	best := math.Inf(1)
	try := func(s string, factor float64) {
		if r, ok := common[s]; ok {
			best = math.Min(best, float64(r)*factor)
		}
		if r, ok := words[s]; ok {
			best = math.Min(best, float64(r)*factor)
		}
	}
	lower := strings.ToLower(string(sub))
	upper := 1.0
	if lower != string(orig) {
		upper = 2 // a capital first letter or all caps
		if !(unicode.IsUpper(orig[0]) && strings.ToLower(string(orig[1:])) == string(orig[1:])) && strings.ToUpper(string(orig)) != string(orig) {
			upper = math.Pow(2, float64(countUpper(orig)))
		}
	}
	try(lower, upper)
	try(reverse(lower), 2*upper)
	if ul, subs := unleet([]rune(lower)); subs > 0 {
		f := upper * math.Pow(2, float64(subs))
		try(string(ul), f)
		try(reverse(string(ul)), 2*f)
	}
	return best
}

func countUpper(rs []rune) int {
	n := 0
	for _, r := range rs {
		if unicode.IsUpper(r) {
			n++
		}
	}
	return n
}

func reverse(s string) string {
	rs := []rune(s)
	for i, j := 0, len(rs)-1; i < j; i, j = i+1, j-1 {
		rs[i], rs[j] = rs[j], rs[i]
	}
	return string(rs)
}

// sequenceGuesses matches abc…, 123…, zyx…, constant steps of 1 or 2.
func sequenceGuesses(rs []rune) float64 {
	if len(rs) < 3 {
		return math.Inf(1)
	}
	d := rs[1] - rs[0]
	if d == 0 || d > 2 || d < -2 {
		return math.Inf(1)
	}
	for i := 2; i < len(rs); i++ {
		if rs[i]-rs[i-1] != d {
			return math.Inf(1)
		}
	}
	base := 26.0
	switch first := unicode.ToLower(rs[0]); {
	case first == 'a' || first == 'z' || first == '0' || first == '1' || first == '9':
		base = 4
	case unicode.IsDigit(first):
		base = 10
	}
	if d < 0 {
		base *= 2
	}
	return base * float64(len(rs))
}

var keyboardRows = []string{"`1234567890-=", "qwertyuiop[]\\", "asdfghjkl;'", "zxcvbnm,./", "1qaz2wsx3edc4rfv5tgb6yhn7ujm8ik,9ol.0p;/"}

// keyboardGuesses matches runs along a keyboard row or column (either
// direction), zxcvbn's spatial estimate with one turn per change of run.
func keyboardGuesses(rs []rune) float64 {
	if len(rs) < 4 {
		return math.Inf(1)
	}
	s := strings.ToLower(string(rs))
	for _, row := range keyboardRows {
		if strings.Contains(row, s) || strings.Contains(reverse(row), s) {
			return 94 * 4.6 * float64(len(rs))
		}
	}
	return math.Inf(1)
}

// repeatGuesses matches a unit repeated two or more times.
func repeatGuesses(rs []rune) float64 {
	n := len(rs)
	for u := 1; u <= n/2; u++ {
		if n%u != 0 {
			continue
		}
		ok := true
		for i := u; i < n && ok; i++ {
			ok = rs[i] == rs[i-u]
		}
		if ok {
			return Guesses(string(rs[:u])) * float64(n/u)
		}
	}
	return math.Inf(1)
}

// dateGuesses matches 4 to 8 digits that read as a date or a year.
func dateGuesses(rs []rune) float64 {
	if len(rs) < 4 || len(rs) > 10 {
		return math.Inf(1)
	}
	digits := 0
	for _, r := range rs {
		if unicode.IsDigit(r) {
			digits++
		} else if r != '/' && r != '-' && r != '.' {
			return math.Inf(1)
		}
	}
	if digits < 4 || digits > 8 {
		return math.Inf(1)
	}
	if digits == 4 {
		return 119 // a year
	}
	return 365 * 119
}

func bruteforce(rs []rune) float64 {
	card := 0.0
	var lo, up, dg, sym, other bool
	for _, r := range rs {
		switch {
		case r >= 'a' && r <= 'z':
			lo = true
		case r >= 'A' && r <= 'Z':
			up = true
		case r >= '0' && r <= '9':
			dg = true
		case r < 128:
			sym = true
		default:
			other = true
		}
	}
	for _, c := range []struct {
		b bool
		n float64
	}{{lo, 26}, {up, 26}, {dg, 10}, {sym, 33}, {other, 100}} {
		if c.b {
			card += c.n
		}
	}
	card = math.Max(card, bruteforceCard)
	return math.Pow(card, float64(len(rs)))
}

// Guesses estimates how many guesses a well-informed attacker needs.
func Guesses(pw string) float64 {
	rs := []rune(pw)
	n := len(rs)
	if n == 0 {
		return 0
	}
	if n > maxEstimateRunes {
		return math.Inf(1)
	}
	// best[j][k]: the least product of guesses covering rs[:j] with k
	// parts.
	const maxParts = 12
	best := make([][maxParts + 1]float64, n+1)
	for j := range best {
		for k := range best[j] {
			best[j][k] = math.Inf(1)
		}
	}
	best[0][0] = 1
	for j := 1; j <= n; j++ {
		for i := 0; i < j; i++ {
			sub := rs[i:j]
			g := matchGuesses(sub)
			for k := 1; k <= maxParts; k++ {
				if p := best[i][k-1]; !math.IsInf(p, 1) {
					best[j][k] = math.Min(best[j][k], p*g)
				}
			}
		}
	}
	out := math.Inf(1)
	fact := 1.0
	for k := 1; k <= maxParts; k++ {
		fact *= float64(k)
		if g := best[n][k]; !math.IsInf(g, 1) {
			out = math.Min(out, fact*g+math.Pow(10000, float64(k-1)))
		}
	}
	return out
}

func matchGuesses(sub []rune) float64 {
	g := bruteforce(sub)
	for _, m := range []float64{dictGuesses(sub, sub), sequenceGuesses(sub), keyboardGuesses(sub), dateGuesses(sub)} {
		g = math.Min(g, m)
	}
	if len(sub) >= 2 {
		g = math.Min(g, repeatGuesses(sub))
	}
	floor := float64(minGuessesMulti)
	if len(sub) == 1 {
		floor = minGuessesSingle
	}
	return math.Max(g, floor)
}

// commonWords returns the embedded common list's entries (tests).
func commonWords() []string {
	out := make([]string, 0, len(common))
	for w := range common {
		out = append(out, w)
	}
	sort.Strings(out)
	return out
}
