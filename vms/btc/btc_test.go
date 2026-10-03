package btc

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
)

const abandon = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

func TestWordlist(t *testing.T) {
	h := sha256.Sum256([]byte(wordlistText))
	if hex.EncodeToString(h[:]) != "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda" {
		t.Fatal("wordlist hash")
	}
	if len(words()) != 2048 {
		t.Fatal("wordlist size")
	}
}

// BIP39 vectors (trezor/python-mnemonic vectors.json, passphrase TREZOR).
func TestBIP39Vectors(t *testing.T) {
	for _, v := range []struct{ ent, phrase, seed string }{
		{"00000000000000000000000000000000", abandon,
			"c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"},
		{"7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f", "legal winner thank year wave sausage worth useful legal winner thank yellow",
			"2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607"},
		{"0000000000000000000000000000000000000000000000000000000000000000",
			"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
			"bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8"},
	} {
		ent, _ := hex.DecodeString(v.ent)
		got, err := NewMnemonic(ent)
		if err != nil || got != v.phrase {
			t.Fatalf("mnemonic %s: %q %v", v.ent, got, err)
		}
		n, err := NormalizeMnemonic("  " + strings.ToUpper(v.phrase) + "\n")
		if err != nil || n != v.phrase {
			t.Fatalf("normalize: %q %v", n, err)
		}
		seed, err := Seed(v.phrase, "TREZOR")
		if err != nil || hex.EncodeToString(seed) != v.seed {
			t.Fatalf("seed %s", v.ent)
		}
	}
	for _, bad := range []string{"", "abandon", strings.Replace(abandon, "about", "abandon", 1), abandon + " zoo",
		strings.Replace(abandon, "about", "abou", 1), "abandön" + abandon[7:]} {
		if _, err := NormalizeMnemonic(bad); !errors.Is(err, ErrMnemonic) {
			t.Fatalf("accepted %q", bad)
		}
	}
	if ValidPassphrase("é") || ValidPassphrase("a\nb") || !ValidPassphrase("") || !ValidPassphrase("TREZOR") {
		t.Fatal("passphrase rules")
	}
}

func account(t testing.TB, network string) (*Account, []byte) {
	t.Helper()
	n, _ := LookupNetwork(network)
	seed, err := Seed(abandon, "")
	if err != nil {
		t.Fatal(err)
	}
	a, err := NewAccount(seed, n)
	if err != nil {
		t.Fatal(err)
	}
	return a, seed
}

// BIP84 vectors (mnemonic "abandon ... about", no passphrase).
func TestBIP84Vectors(t *testing.T) {
	a, _ := account(t, Mainnet)
	if a.FingerprintHex() != "73c5da0a" {
		t.Fatalf("fingerprint %s", a.FingerprintHex())
	}
	for _, v := range []struct {
		chain, index uint32
		addr         string
	}{{0, 0, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"}, {0, 1, "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g"},
		{1, 0, "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el"}} {
		got, _, err := a.Address(v.chain, v.index)
		if err != nil || got != v.addr {
			t.Fatalf("%d/%d: %s %v", v.chain, v.index, got, err)
		}
	}
	b, err := ParseAccount(Mainnet, a.FingerprintHex(), a.XPub)
	if err != nil {
		t.Fatal(err)
	}
	if x, _, _ := b.Address(0, 0); x != "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu" {
		t.Fatal("parsed account")
	}
	if _, err := ParseAccount(Regtest, a.FingerprintHex(), a.XPub); err == nil {
		t.Fatal("mainnet xpub accepted for regtest")
	}
	r, _ := account(t, Regtest)
	if x, _, _ := r.Address(0, 0); !strings.HasPrefix(x, "bcrt1q") {
		t.Fatal(x)
	}
	if !strings.Contains(r.Descriptor(1), "/84'/1'/0']tpub") {
		t.Fatal(r.Descriptor(1))
	}
}

func regtestPSBT(t testing.TB, a *Account, pay string, amount, change int64) []byte {
	t.Helper()
	f1, err := FundingTx(a, 0, 0, 60000, 1)
	if err != nil {
		t.Fatal(err)
	}
	f2, _ := FundingTx(a, 1, 3, 50000, 2)
	payees := []Payee{{Address: pay, Amount: amount}}
	if change > 0 {
		payees = append(payees, Payee{Change: true, Chain: 1, Index: 4, Amount: change})
	}
	raw, err := BuildPSBT(a, []Coin{{PrevTx: f1, Vout: 0, Chain: 0, Index: 0}, {PrevTx: f2, Vout: 0, Chain: 1, Index: 3}}, payees)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

const payee = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"

func TestSignRegtest(t *testing.T) {
	a, seed := account(t, Regtest)
	raw := regtestPSBT(t, a, payee, 70000, 39000)
	s, err := Inspect(a, raw)
	if err != nil {
		t.Fatal(err)
	}
	if s.TotalIn != 110000 || s.Sending != 70000 || s.Change != 39000 || s.Fee != 1000 || s.VSize < 200 || s.VSize > 260 {
		t.Fatalf("%+v", s)
	}
	if err := s.PayCheck(payee, 70000); err != nil {
		t.Fatal(err)
	}
	if err := s.PayCheck(payee, 69999); err == nil {
		t.Fatal("amount mismatch accepted")
	}
	tx, err := Sign(a, s, seed)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := DecodeTx(tx)
	if err != nil || dec.TxHash().String() != s.TxID || len(dec.TxIn[0].Witness) != 2 {
		t.Fatal("signed tx")
	}
	other, _ := Seed(abandon, "x")
	if _, err := Sign(a, s, other); err == nil {
		t.Fatal("signed with another seed")
	}
}

func mutate(t *testing.T, a *Account, f func(p *psbt.Packet)) []byte {
	raw := regtestPSBT(t, a, payee, 70000, 39000)
	p, err := ParsePSBT(raw)
	if err != nil {
		t.Fatal(err)
	}
	f(p)
	var buf bytes.Buffer
	if err := p.Serialize(&buf); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestInspectRefusals(t *testing.T) {
	a, _ := account(t, Regtest)
	n, _ := LookupNetwork(Regtest)
	oseed, _ := Seed(abandon, "other")
	other, _ := NewAccount(oseed, n)
	for name, raw := range map[string][]byte{
		"fee_rate":     regtestPSBT(t, a, payee, 70000, 300),
		"fee":          regtestPSBT(t, a, payee, 110000, 0),
		"output":       regtestPSBT(t, a, payee, 100, 0),
		"no_prev_tx":   mutate(t, a, func(p *psbt.Packet) { p.Inputs[0].NonWitnessUtxo = nil }),
		"witness_utxo": mutate(t, a, func(p *psbt.Packet) { p.Inputs[0].WitnessUtxo.Value = 1 }),
		"sighash":      mutate(t, a, func(p *psbt.Packet) { p.Inputs[0].SighashType = txscript.SigHashNone }),
		"foreign":      mutate(t, a, func(p *psbt.Packet) { p.Inputs[1].Bip32Derivation = nil }),
		"bad_path":     mutate(t, a, func(p *psbt.Packet) { p.Inputs[1].Bip32Derivation[0].Bip32Path[4] = 9 }),
		"fake_change":  mutate(t, a, func(p *psbt.Packet) { p.Outputs[1].Bip32Derivation[0].Bip32Path[4] = 5 }),
		"garbage":      []byte("psbt\xff\x00"),
	} {
		if _, err := Inspect(a, raw); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	// A PSBT of another account is all foreign inputs.
	if _, err := Inspect(other, regtestPSBT(t, a, payee, 70000, 39000)); err == nil {
		t.Fatal("other account")
	}
}

func TestCheckAddress(t *testing.T) {
	r, _ := LookupNetwork(Regtest)
	m, _ := LookupNetwork(Mainnet)
	if got, err := CheckAddress(r, strings.ToUpper(payee)); err != nil || got != payee {
		t.Fatal(got, err)
	}
	if _, err := CheckAddress(m, payee); err == nil {
		t.Fatal("regtest address on mainnet")
	}
	for _, ok := range []string{"bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
		"bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297"} {
		if _, err := CheckAddress(m, ok); err != nil {
			t.Fatalf("%s: %v", ok, err)
		}
	}
}

func FuzzInspect(f *testing.F) {
	a, _ := account(f, Regtest)
	f.Add(regtestPSBT(f, a, payee, 70000, 39000))
	f.Add([]byte("psbt\xff"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = Inspect(a, raw)
	})
}

func FuzzNormalizeMnemonic(f *testing.F) {
	f.Add(abandon)
	f.Add("zoo zoo zoo")
	f.Fuzz(func(t *testing.T, s string) {
		n, err := NormalizeMnemonic(s)
		if err == nil {
			if again, err := NormalizeMnemonic(n); err != nil || again != n {
				t.Fatal("not idempotent")
			}
		}
	})
}

func FuzzCheckAddress(f *testing.F) {
	n, _ := LookupNetwork(Regtest)
	f.Add(payee)
	f.Add("bcrt1")
	f.Fuzz(func(t *testing.T, s string) {
		if c, err := CheckAddress(n, s); err == nil {
			if again, err := CheckAddress(n, c); err != nil || again != c {
				t.Fatal("canonical form")
			}
		}
	})
}
