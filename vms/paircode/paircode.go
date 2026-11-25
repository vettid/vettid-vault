// Package paircode implements the crypto of the short pairing codes for
// desktops and agents (VAULT-MESSAGING 0.94.0 §6.7.2, RELAY-PROTOCOL
// 0.14.0 §6.9.1): the 8-symbol code, the relay's canonical base URL `r`,
// the hourly lookup salts and their checks, the lookup tag, the key k_w
// and the sealed bundle.
//
// The code is a bearer secret for 10 minutes: nothing here logs it, and
// callers MUST NOT log, store or send it anywhere but in the sealed
// answer to the app (§13.6).
package paircode

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"

	"github.com/vettid/vettid-vault/vms/altchan"
	"github.com/vettid/vettid-vault/vms/suite"
)

// The code (§6.7.2 "The code").
const (
	// Alphabet is ENROLLMENT-CODES §3.1's: no 0, 1, I, L or O.
	Alphabet = altchan.CodeAlphabet
	// Length is the code's number of symbols (31^8, about 39.6 bits).
	Length = altchan.CodeLength
	// TTL is a code pairing's life: exp is creation plus 600 s.
	TTL = 600 * time.Second
)

// The two derivations' parameters (§6.7.2 "Two derivations"): Argon2id
// version 0x13, t = 3, m = 256 MiB, p = 1, 32 bytes. Fixed with the
// code's version 1: nothing carries them.
const (
	ArgonTime      = 3
	ArgonMemoryKiB = 256 * 1024
	ArgonThreads   = 1
	KeySize        = 32
	// SaltSize is the size of s_r and of s_c.
	SaltSize = 16
	// NonceSize is a lookup salt's relay nonce.
	NonceSize = 16
)

// Purposes: the role's `t` (§6.4).
const (
	PurposeAgent   = "a"
	PurposeDesktop = "d"
)

// The labels (§6.7.2). Each is followed by 0x00 where it is used.
const (
	labelSalt   = "vettid/pair-code/1/salt"
	labelPW     = "vettid/pair-code/1/"
	labelKey    = "vettid/pair-code/1/key"
	labelBundle = "vettid/pair-code/1/bundle"
)

// The salt list's window (§6.7.2): a salt is listed from 2 minutes before
// its hour until 10 minutes after it ends, and every client checks every
// entry against that window with 120 s of clock skew.
const (
	Hour       = 3600
	listBefore = 120
	listAfter  = 600
	Skew       = 120
	// MaxSalts is the most entries a list may have.
	MaxSalts = 2
)

// Errors.
var (
	ErrCode    = errors.New("paircode: not a pairing code")
	ErrSymbol  = errors.New("paircode: codes never contain 0, 1, I, L or O")
	ErrRelay   = errors.New("paircode: not a relay base URL a code can use")
	ErrPurpose = errors.New("paircode: unknown purpose")
	ErrInput   = errors.New("paircode: bad input")
	ErrOpen    = errors.New("paircode: blob does not open")
)

// The code is handled as bytes throughout, so that the vault can wipe it
// once its answer is sealed (a string cannot be wiped).

// NewCode returns a fresh code from the CSPRNG by rejection sampling:
// bytes 248–255 discarded, the rest taken mod 31 (ENROLLMENT-CODES §3.1).
// The caller wipes it.
func NewCode() ([]byte, error) {
	code := make([]byte, 0, Length)
	for len(code) < Length {
		buf, err := suite.RandomBytes(32)
		if err != nil {
			suite.Wipe(code)
			return nil, err
		}
		code = appendSymbols(code, buf)
		suite.Wipe(buf)
	}
	return code, nil
}

// appendSymbols appends to code the symbols drawn from r (bytes 248–255
// discarded, the rest mod 31) until code has Length symbols; the same
// sampling as altchan.CodeFromBytes, kept in bytes.
func appendSymbols(code, r []byte) []byte {
	for _, c := range r {
		if len(code) == Length {
			break
		}
		if c < 248 {
			code = append(code, Alphabet[int(c)%len(Alphabet)])
		}
	}
	return code
}

// Display shows a code as XXXX-XXXX.
func Display(code []byte) string {
	if len(code) != Length {
		return string(code)
	}
	return string(code[:4]) + "-" + string(code[4:])
}

// Normalize applies the new device's input order (§6.7.2): spaces and
// hyphens removed; if 8 characters remain it is a code, upper-cased, and
// refused with ErrSymbol if any is outside the alphabet; otherwise it is
// not a code (ErrCode: the caller parses the original input as a link).
func Normalize(input string) ([]byte, error) {
	s := strings.NewReplacer(" ", "", "-", "").Replace(input)
	if utf8.RuneCountInString(s) != Length {
		return nil, ErrCode // counted in characters, as typed
	}
	// Only ASCII is upper-cased: a non-ASCII character is refused before
	// any case mapping (Go maps U+017F to S; full case mapping, as other
	// platforms use, changes the length), so `code` is always the 8
	// normalized ASCII bytes.
	b := []byte(s)
	for i, c := range b {
		if c >= 0x80 {
			// A second guard: the alphabet check below refuses such a
			// byte too. The first is that nothing here case-maps it.
			return nil, ErrSymbol
		}
		if c >= 'a' && c <= 'z' {
			b[i] = c - 'a' + 'A'
		}
		if strings.IndexByte(Alphabet, b[i]) < 0 {
			return nil, ErrSymbol
		}
	}
	return b, nil
}

// ValidCode reports whether code is 8 symbols of the alphabet, already
// normalized.
func ValidCode(code []byte) bool {
	if len(code) != Length {
		return false
	}
	for i := 0; i < len(code); i++ {
		if strings.IndexByte(Alphabet, code[i]) < 0 {
			return false
		}
	}
	return true
}

// CanonicalRelay returns the canonical form of a relay's base URL
// (§6.7.2 "The relay's base URL"): `https://`, the host in lower case,
// then `:port` only when it is not 443, with no path and no trailing
// slash. A bare host or host:port gets `https://`. It refuses a path, a
// query, a fragment, user information, an IP literal, a non-ASCII host
// (an internationalized name only in its xn-- form) and any scheme other
// than https. A lone trailing "/" is the empty path, and is dropped.
func CanonicalRelay(s string) (string, error) {
	if s == "" || len(s) > 2048 || strings.ContainsAny(s, " \t\r\n\\") {
		return "", ErrRelay
	}
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" ||
		strings.Contains(s, "#") || strings.ToLower(u.Scheme) != "https" {
		return "", ErrRelay
	}
	if u.Path != "" && u.Path != "/" || u.RawPath != "" {
		return "", ErrRelay
	}
	host, port := u.Hostname(), u.Port()
	if strings.HasPrefix(u.Host, "[") || net.ParseIP(host) != nil || !dnsName(host) {
		return "", ErrRelay
	}
	if strings.HasSuffix(u.Host, ":") {
		return "", ErrRelay // an empty port
	}
	host = strings.ToLower(host)
	out := "https://" + host
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return "", ErrRelay
		}
		if n != 443 {
			out += ":" + port
		}
	}
	return out, nil
}

// dnsName reports whether h is a DNS name in ASCII: labels of letters,
// digits and hyphens, 1 to 63 bytes, not starting or ending with a hyphen,
// at most 253 bytes, and a last label that is not a number, which URL
// parsers (WHATWG) read as an IPv4 address (127.1, 0x7f.1, 1.0x).
func dnsName(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	labels := strings.Split(h, ".")
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			switch {
			case c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '-' || c >= '0' && c <= '9':
			default:
				return false
			}
		}
	}
	return !numericLabel(labels[len(labels)-1])
}

// numericLabel reports a label WHATWG's host parser reads as a number,
// whatever its size: all decimal digits, or 0x / 0X followed by zero or
// more hex digits (0x alone is 0). Tested by character, so a number too
// large for any integer type is refused too.
func numericLabel(l string) bool {
	digits := l
	hex := len(l) >= 2 && (l[:2] == "0x" || l[:2] == "0X")
	if hex {
		digits = l[2:]
	} else if l == "" {
		return false
	}
	for i := 0; i < len(digits); i++ {
		c := digits[i]
		if !(c >= '0' && c <= '9' || hex && (c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// Epoch returns the hour of t: floor(unix time / 3600).
func Epoch(t time.Time) int64 { return floorDiv(t.Unix(), Hour) }

func floorDiv(a, b int64) int64 {
	q := a / b
	if a%b != 0 && (a < 0) != (b < 0) {
		q--
	}
	return q
}

// SaltR returns the hour's lookup salt: the first 16 bytes of
// SHA-256("vettid/pair-code/1/salt" || 0x00 || r || 0x00 || epoch (8 bytes
// big-endian) || 0x00 || nonce).
func SaltR(r string, epoch int64, nonce []byte) []byte {
	h := sha256.New()
	h.Write([]byte(labelSalt))
	h.Write([]byte{0})
	h.Write([]byte(r))
	h.Write([]byte{0})
	var e [8]byte
	binary.BigEndian.PutUint64(e[:], uint64(epoch))
	h.Write(e[:])
	h.Write([]byte{0})
	h.Write(nonce)
	return h.Sum(nil)[:SaltSize]
}

// SaltID returns the lowercase hex of s_r's first 4 bytes.
func SaltID(sr []byte) string { return hex.EncodeToString(sr[:4]) }

// Salt is one entry of the relay's list, with s_r recomputed.
type Salt struct {
	SaltID string `json:"salt_id"`
	Epoch  int64  `json:"epoch"`
	Nonce  []byte `json:"nonce"` // base64, as listed
	SR     []byte `json:"-"`     // set by CheckSalts
}

// The checks a salt list can fail (§6.7.2), the reasons recorded for
// pair_code.salts_refused. ReasonClock is the one a device shows its
// clock text for.
const (
	ReasonCount    = "count"         // none, or more than 2 entries
	ReasonNonce    = "nonce_size"    // a nonce that is not 16 bytes
	ReasonEpochDup = "epoch_twice"   // two entries for one epoch
	ReasonSaltID   = "salt_id"       // a salt_id that does not recompute
	ReasonClock    = "clock"         // an epoch outside its listing window
	ReasonChanged  = "nonce_changed" // an epoch seen before with another nonce
)

// RefusedError is a refused list, with the check that failed.
type RefusedError struct{ Reason string }

func (e *RefusedError) Error() string { return "paircode: salt list refused: " + e.Reason }

// CheckSalts checks a relay's salt list for r by the client's clock now
// (§6.7.2) and refuses the whole list on any failure. seen holds the
// nonces of epochs already seen (in this pairing, or for the vault in the
// last hour); it may be nil, and it is not updated: the caller records
// the returned entries itself. On success each entry's SR is set.
func CheckSalts(r string, list []Salt, now time.Time, seen map[int64][]byte) ([]Salt, error) {
	if len(list) == 0 || len(list) > MaxSalts {
		return nil, &RefusedError{ReasonCount}
	}
	for _, e := range list {
		if len(e.Nonce) != NonceSize {
			return nil, &RefusedError{ReasonNonce}
		}
	}
	out := make([]Salt, len(list))
	epochs := map[int64]bool{}
	for i, e := range list {
		if epochs[e.Epoch] {
			return nil, &RefusedError{ReasonEpochDup}
		}
		epochs[e.Epoch] = true
		sr := SaltR(r, e.Epoch, e.Nonce)
		if SaltID(sr) != e.SaltID {
			return nil, &RefusedError{ReasonSaltID}
		}
		out[i] = Salt{SaltID: e.SaltID, Epoch: e.Epoch, Nonce: append([]byte(nil), e.Nonce...), SR: sr}
	}
	for _, e := range out {
		if !inWindow(e.Epoch, now) {
			return nil, &RefusedError{ReasonClock}
		}
	}
	for _, e := range out {
		if n, ok := seen[e.Epoch]; ok && string(n) != string(e.Nonce) {
			return nil, &RefusedError{ReasonChanged}
		}
	}
	return out, nil
}

// inWindow reports whether epoch's listing window, widened by the skew on
// both sides, holds now: from 2 minutes before the hour starts until 10
// minutes after it ends.
func inWindow(epoch int64, now time.Time) bool {
	if epoch < 0 || epoch > (1<<62)/Hour {
		return false
	}
	start := epoch * Hour
	t := now.Unix()
	return t >= start-listBefore-Skew && t <= start+Hour+listAfter+Skew
}

// ForPut orders entries that passed CheckSalts for a vault's PUT (§6.7.2
// "Which entry a vault uses"): first the one whose epoch is current by the
// vault's clock, within the 120 s skew, then the other only if it passes
// the same check (the clock is within the skew of the hour the two
// share), to be tried once if the relay answers bad_request for the
// first. It returns no entry when none is current.
func ForPut(list []Salt, now time.Time) []Salt {
	cur := Epoch(now)
	var first, other []Salt
	for _, e := range list {
		if e.Epoch == cur {
			first = append(first, e)
		}
	}
	if first == nil {
		// Within the skew of an hour's edge: the epoch the clock is about
		// to enter or has just left.
		for _, e := range list {
			start := e.Epoch * Hour
			t := now.Unix()
			if t >= start-Skew && t < start+Hour+Skew {
				first = append(first, e)
				break
			}
		}
	}
	if first == nil {
		return nil
	}
	t := now.Unix()
	for _, e := range list {
		if e.Epoch == first[0].Epoch {
			continue
		}
		if start := e.Epoch * Hour; t >= start-Skew && t < start+Hour+Skew {
			other = append(other, e)
		}
	}
	return append(first[:1], other...)
}

func checkPurpose(p string) error {
	if p != PurposeAgent && p != PurposeDesktop {
		return ErrPurpose
	}
	return nil
}

// PW returns pw(l) = "vettid/pair-code/1/" || l || 0x00 || purpose || 0x00
// || r || 0x00 || code. It holds 0x00 bytes: pass it as bytes with its
// length, never as a NUL-terminated string. The caller wipes it.
func PW(label, purpose, r string, code []byte) []byte {
	b := make([]byte, 0, len(labelPW)+len(label)+len(purpose)+len(r)+len(code)+3)
	b = append(b, labelPW...)
	b = append(b, label...)
	b = append(b, 0)
	b = append(b, purpose...)
	b = append(b, 0)
	b = append(b, r...)
	b = append(b, 0)
	b = append(b, code...)
	return b
}

func derive(label, purpose, r string, code, salt []byte) ([]byte, error) {
	if err := checkPurpose(purpose); err != nil {
		return nil, err
	}
	if !ValidCode(code) || len(salt) != SaltSize || !canonical(r) {
		return nil, ErrInput
	}
	pw := PW(label, purpose, r, code)
	defer suite.Wipe(pw)
	return argon2.IDKey(pw, salt, ArgonTime, ArgonMemoryKiB, ArgonThreads, KeySize), nil
}

// Tag returns the lookup tag Argon2id(pw("lookup"), s_r, P).
func Tag(purpose, r string, code, sr []byte) ([]byte, error) {
	return derive("lookup", purpose, r, code, sr)
}

// X returns Argon2id(pw("key"), s_c, P). The caller wipes it.
func X(purpose, r string, code, sc []byte) ([]byte, error) {
	return derive("key", purpose, r, code, sc)
}

// KW returns k_w = HKDF-SHA-256(ikm = x, salt = "", info =
// "vettid/pair-code/1/key", L = 32). The caller wipes it.
func KW(x []byte) ([]byte, error) {
	if len(x) != KeySize {
		return nil, ErrInput
	}
	k := make([]byte, KeySize)
	if _, err := hkdf.New(sha256.New, x, nil, []byte(labelKey)).Read(k); err != nil {
		return nil, err
	}
	return k, nil
}

// AAD returns "vettid/pair-code/1/bundle" || 0x00 || purpose || 0x00 || r
// || 0x00 || claim_id || 0x00 || s_c.
func AAD(purpose, r, claimID string, sc []byte) []byte {
	b := make([]byte, 0, len(labelBundle)+len(purpose)+len(r)+len(claimID)+len(sc)+4)
	b = append(b, labelBundle...)
	b = append(b, 0)
	b = append(b, purpose...)
	b = append(b, 0)
	b = append(b, r...)
	b = append(b, 0)
	b = append(b, claimID...)
	b = append(b, 0)
	b = append(b, sc...)
	return b
}

// canonical reports whether r is a relay base URL in its canonical form.
func canonical(r string) bool {
	c, err := CanonicalRelay(r)
	return err == nil && c == r
}

// ValidClaimID reports whether id is a code claim id: 128 bits as 26
// lowercase unpadded base32 characters, in the canonical spelling (the
// last character's two low bits zero), as the relay parses claim ids
// (RELAY-PROTOCOL §6.9, §6.9.1).
func ValidClaimID(id string) bool {
	if len(id) != 26 {
		return false
	}
	for i := 0; i < len(id); i++ {
		if c := id[i]; !(c >= 'a' && c <= 'z' || c >= '2' && c <= '7') {
			return false
		}
	}
	b, err := claimEncoding.DecodeString(strings.ToUpper(id))
	return err == nil && len(b) == 16 && strings.ToLower(claimEncoding.EncodeToString(b)) == id
}

var claimEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewClaimID returns a fresh code claim id from the CSPRNG (the creator
// chooses it, RELAY-PROTOCOL §6.9.1).
func NewClaimID() (string, error) {
	b, err := suite.RandomBytes(16)
	if err != nil {
		return "", err
	}
	return strings.ToLower(claimEncoding.EncodeToString(b)), nil
}

// checkBinding checks the inputs the associated data binds: the fields
// are fixed in form, so the NUL-separated aad has one reading.
func checkBinding(purpose, r, claimID string, sc []byte) error {
	if checkPurpose(purpose) != nil || !canonical(r) || !ValidClaimID(claimID) || len(sc) != SaltSize {
		return ErrInput
	}
	return nil
}

// Seal returns blob = nonce (24) || XChaCha20-Poly1305(k_w, nonce, aad,
// bundle), with a fresh random nonce.
func Seal(kw []byte, purpose, r, claimID string, sc, bundle []byte) ([]byte, error) {
	if err := checkBinding(purpose, r, claimID, sc); err != nil {
		return nil, err
	}
	nonce, err := suite.NewNonce()
	if err != nil {
		return nil, err
	}
	return sealWithNonce(kw, nonce, purpose, r, claimID, sc, bundle)
}

func sealWithNonce(kw, nonce []byte, purpose, r, claimID string, sc, bundle []byte) ([]byte, error) {
	if len(nonce) != suite.XNonceSize || checkBinding(purpose, r, claimID, sc) != nil {
		return nil, ErrInput
	}
	ct, err := suite.SealX(kw, nonce, AAD(purpose, r, claimID, sc), bundle)
	if err != nil {
		return nil, err
	}
	return append(append(make([]byte, 0, len(nonce)+len(ct)), nonce...), ct...), nil
}

// Open opens a blob as the claim it was made for. Any failure is ErrOpen.
func Open(kw []byte, purpose, r, claimID string, sc, blob []byte) ([]byte, error) {
	if checkBinding(purpose, r, claimID, sc) != nil || len(blob) <= suite.XNonceSize {
		return nil, ErrOpen
	}
	pt, err := suite.OpenX(kw, blob[:suite.XNonceSize], AAD(purpose, r, claimID, sc), blob[suite.XNonceSize:])
	if err != nil {
		return nil, ErrOpen
	}
	return pt, nil
}
