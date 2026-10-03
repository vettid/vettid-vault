// Package btc is the wallet feature's Bitcoin code (VAULT-MESSAGING
// §10.18): BIP39 recovery phrases, BIP32/BIP84 account keys and receive
// addresses, and the validation and signing of PSBTs (BIP174) that spend
// from a BIP84 (P2WPKH) account. It has no network access and no state:
// chain data comes inside the PSBT, from the member's app.
//
// Secp256k1, BIP32, transaction serialisation, sighashes and PSBT
// encoding are btcd's (github.com/btcsuite/btcd, the library lnd and btcd
// use); this package only adds BIP39 (stdlib PBKDF2) and the vault's
// policy: what a PSBT may contain before the vault signs it.
package btc

import (
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/sha512"
	_ "embed"
	"errors"
	"strings"
)

// The BIP39 English wordlist (bitcoin/bips bip-0039/english.txt,
// SHA-256 2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda,
// checked by TestWordlist).
//
//go:embed bip39-english.txt
var wordlistText string // read-only

// MaxPassphrase bounds a BIP39 passphrase (ASCII only: without Unicode
// normalisation a non-ASCII passphrase could derive another seed than
// other wallets do).
const MaxPassphrase = 256

// ErrMnemonic is a phrase that is not a valid BIP39 English phrase.
var ErrMnemonic = errors.New("btc: invalid recovery phrase")

func words() []string { return strings.Fields(wordlistText) }

func index(ws []string, w string) int {
	lo, hi := 0, len(ws)
	for lo < hi { // the list is sorted
		m := (lo + hi) / 2
		if ws[m] < w {
			lo = m + 1
		} else {
			hi = m
		}
	}
	if lo < len(ws) && ws[lo] == w {
		return lo
	}
	return -1
}

// NewMnemonic encodes 16–32 bytes of entropy (a multiple of 4) as a BIP39
// phrase.
func NewMnemonic(entropy []byte) (string, error) {
	n := len(entropy)
	if n < 16 || n > 32 || n%4 != 0 {
		return "", ErrMnemonic
	}
	h := sha256.Sum256(entropy)
	cs := n / 4 // checksum bits
	bits := make([]byte, 0, n*8+cs)
	for _, b := range entropy {
		for i := 7; i >= 0; i-- {
			bits = append(bits, b>>uint(i)&1)
		}
	}
	for i := 0; i < cs; i++ {
		bits = append(bits, h[0]>>uint(7-i)&1)
	}
	ws := words()
	out := make([]string, 0, len(bits)/11)
	for i := 0; i < len(bits); i += 11 {
		v := 0
		for _, b := range bits[i : i+11] {
			v = v<<1 | int(b)
		}
		out = append(out, ws[v])
	}
	for i := range bits {
		bits[i] = 0
	}
	return strings.Join(out, " "), nil
}

// NormalizeMnemonic checks a phrase (12, 15, 18, 21 or 24 English words,
// any case and white space) and its checksum, and returns it in canonical
// form: lower case, single spaces.
func NormalizeMnemonic(phrase string) (string, error) {
	if len(phrase) > 1024 {
		return "", ErrMnemonic
	}
	for i := 0; i < len(phrase); i++ {
		if phrase[i] >= 0x80 {
			return "", ErrMnemonic
		}
	}
	fs := strings.Fields(strings.ToLower(phrase))
	switch len(fs) {
	case 12, 15, 18, 21, 24:
	default:
		return "", ErrMnemonic
	}
	ws := words()
	bits := make([]byte, 0, len(fs)*11)
	for _, w := range fs {
		i := index(ws, w)
		if i < 0 {
			return "", ErrMnemonic
		}
		for k := 10; k >= 0; k-- {
			bits = append(bits, byte(i>>uint(k)&1))
		}
	}
	cs := len(bits) / 33
	ent := make([]byte, (len(bits)-cs)/8)
	for i := range ent {
		for k := 0; k < 8; k++ {
			ent[i] = ent[i]<<1 | bits[i*8+k]
		}
	}
	h := sha256.Sum256(ent)
	for i := range ent {
		ent[i] = 0
	}
	for i := 0; i < cs; i++ {
		if bits[len(ent)*8+i] != h[0]>>uint(7-i)&1 {
			return "", ErrMnemonic
		}
	}
	return strings.Join(fs, " "), nil
}

// ValidPassphrase reports whether p is an acceptable BIP39 passphrase:
// printable ASCII, at most MaxPassphrase bytes ("" for none).
func ValidPassphrase(p string) bool {
	if len(p) > MaxPassphrase {
		return false
	}
	for i := 0; i < len(p); i++ {
		if p[i] < 0x20 || p[i] > 0x7e {
			return false
		}
	}
	return true
}

// Seed derives the 64-byte BIP39 seed of a canonical phrase and a
// passphrase. The caller wipes it.
func Seed(mnemonic, passphrase string) ([]byte, error) {
	return pbkdf2.Key(sha512.New, mnemonic, []byte("mnemonic"+passphrase), 2048, 64)
}
