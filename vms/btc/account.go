package btc

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strconv"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
)

// Networks.
const (
	Mainnet = "mainnet"
	Testnet = "testnet" // testnet3 and testnet4 share their encodings
	Signet  = "signet"
	Regtest = "regtest"
)

// Network is one Bitcoin network's parameters.
type Network struct {
	Name     string
	CoinType uint32 // BIP44 coin type: 0 mainnet, 1 every test network
	Params   *chaincfg.Params
}

// LookupNetwork returns a network by name. The parameters are copies, so
// callers cannot change btcd's package-level values through them.
func LookupNetwork(name string) (Network, bool) {
	var p chaincfg.Params
	coin := uint32(1)
	switch name {
	case Mainnet:
		p, coin = chaincfg.MainNetParams, 0
	case Testnet:
		p = chaincfg.TestNet3Params
	case Signet:
		p = chaincfg.SigNetParams
	case Regtest:
		p = chaincfg.RegressionNetParams
	default:
		return Network{}, false
	}
	return Network{Name: name, CoinType: coin, Params: &p}, true
}

// Purpose is BIP84 (P2WPKH).
const Purpose = 84

const hardened = hdkeychain.HardenedKeyStart

// MaxIndex bounds address indices the vault derives or accepts.
const MaxIndex = 1 << 20

// Account is a BIP84 account's public half: what the vault keeps in DEK
// state so that it can derive addresses and check PSBTs without the
// recovery phrase.
type Account struct {
	Network     Network
	Fingerprint [4]byte // the master key's fingerprint (BIP32)
	XPub        string  // the account key m/84'/coin'/0', serialised
	key         *hdkeychain.ExtendedKey
}

// ErrKey is a malformed key.
var ErrKey = errors.New("btc: invalid key")

// hash160 is RIPEMD-160(SHA-256(b)) (btcutil's, as Bitcoin defines it).
func hash160(b []byte) []byte { return btcutil.Hash160(b) }

// AccountPath is the account's derivation path, m/84'/coin'/0'.
func (a *Account) AccountPath() []uint32 {
	return []uint32{hardened + Purpose, hardened + a.Network.CoinType, hardened}
}

// PathString is a path in the m/84'/1'/0'/0/5 notation.
func PathString(path []uint32) string {
	s := "m"
	for _, p := range path {
		if p >= hardened {
			s += "/" + strconv.FormatUint(uint64(p-hardened), 10) + "'"
		} else {
			s += "/" + strconv.FormatUint(uint64(p), 10)
		}
	}
	return s
}

// FingerprintUint32 is the fingerprint as PSBTs carry it (little-endian
// uint32 of the four bytes).
func (a *Account) FingerprintUint32() uint32 { return binary.LittleEndian.Uint32(a.Fingerprint[:]) }

// FingerprintHex is the fingerprint as wallets show it.
func (a *Account) FingerprintHex() string { return hex.EncodeToString(a.Fingerprint[:]) }

// Descriptor is the account's output descriptor for one chain (0 receive,
// 1 change), without checksum.
func (a *Account) Descriptor(change uint32) string {
	return "wpkh([" + a.FingerprintHex() + "/84'/" + strconv.FormatUint(uint64(a.Network.CoinType), 10) + "'/0']" +
		a.XPub + "/" + strconv.FormatUint(uint64(change), 10) + "/*)"
}

// NewAccount derives the BIP84 account of a BIP39 seed.
func NewAccount(seed []byte, n Network) (*Account, error) {
	acct, master, err := derivePrivate(seed, n, nil)
	if err != nil {
		return nil, err
	}
	defer acct.Zero()
	mpub, err := master.ECPubKey()
	master.Zero()
	if err != nil {
		return nil, ErrKey
	}
	neutered, err := acct.Neuter() // shares the chain code with acct, which is zeroed
	if err != nil {
		return nil, ErrKey
	}
	xpub := neutered.String()
	pub, err := hdkeychain.NewKeyFromString(xpub)
	if err != nil {
		return nil, ErrKey
	}
	a := &Account{Network: n, XPub: xpub, key: pub}
	copy(a.Fingerprint[:], hash160(mpub.SerializeCompressed())[:4])
	return a, nil
}

// derivePrivate derives the account key and then path below it; the
// caller zeroes both returned keys.
func derivePrivate(seed []byte, n Network, below []uint32) (*hdkeychain.ExtendedKey, *hdkeychain.ExtendedKey, error) {
	master, err := hdkeychain.NewMaster(seed, n.Params)
	if err != nil {
		return nil, nil, ErrKey
	}
	k := master
	for _, i := range append([]uint32{hardened + Purpose, hardened + n.CoinType, hardened}, below...) {
		next, err := k.Derive(i)
		if k != master {
			k.Zero()
		}
		if err != nil {
			master.Zero()
			return nil, nil, ErrKey
		}
		k = next
	}
	return k, master, nil
}

// ParseAccount restores an account from what the vault stored.
func ParseAccount(network, fingerprintHex, xpub string) (*Account, error) {
	n, ok := LookupNetwork(network)
	if !ok {
		return nil, ErrKey
	}
	k, err := hdkeychain.NewKeyFromString(xpub)
	if err != nil || k.IsPrivate() || !k.IsForNet(n.Params) || k.Depth() != 3 {
		return nil, ErrKey
	}
	fp, err := hex.DecodeString(fingerprintHex)
	if err != nil || len(fp) != 4 {
		return nil, ErrKey
	}
	a := &Account{Network: n, XPub: xpub, key: k}
	copy(a.Fingerprint[:], fp)
	return a, nil
}

// PubKey derives the public key at chain/index (chain 0 receive, 1
// change).
func (a *Account) PubKey(chain, index uint32) ([]byte, error) {
	if chain > 1 || index >= MaxIndex {
		return nil, ErrKey
	}
	c, err := a.key.Derive(chain)
	if err != nil {
		return nil, ErrKey
	}
	k, err := c.Derive(index)
	if err != nil {
		return nil, ErrKey
	}
	pk, err := k.ECPubKey()
	if err != nil {
		return nil, ErrKey
	}
	return pk.SerializeCompressed(), nil
}

// Address derives the P2WPKH address at chain/index and its script.
func (a *Account) Address(chain, index uint32) (string, []byte, error) {
	pk, err := a.PubKey(chain, index)
	if err != nil {
		return "", nil, err
	}
	addr, err := btcutil.NewAddressWitnessPubKeyHash(hash160(pk), a.Network.Params)
	if err != nil {
		return "", nil, ErrKey
	}
	return addr.EncodeAddress(), p2wpkh(hash160(pk)), nil
}

func p2wpkh(h []byte) []byte { return append([]byte{0x00, 0x14}, h...) }
