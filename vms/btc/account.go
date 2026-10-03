package btc

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strconv"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
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

// Address types and their BIP44-style purposes.
const (
	P2WPKH = "p2wpkh" // BIP84, native segwit v0
	P2TR   = "p2tr"   // BIP86, taproot key path
)

// PurposeOf returns the purpose of an address type (84 or 86), 0 if unknown.
func PurposeOf(addrType string) uint32 {
	switch addrType {
	case P2WPKH:
		return 84
	case P2TR:
		return 86
	}
	return 0
}

const hardened = hdkeychain.HardenedKeyStart

// MaxIndex bounds address indices the vault derives or accepts.
const MaxIndex = 1 << 20

// Account is a BIP84 or BIP86 account's public half: what the vault keeps
// in DEK state so that it can derive addresses and check PSBTs without
// the recovery phrase.
type Account struct {
	Network     Network
	Type        string  // P2WPKH or P2TR
	Fingerprint [4]byte // the master key's fingerprint (BIP32)
	XPub        string  // the account key m/purpose'/coin'/0', serialised
	key         *hdkeychain.ExtendedKey
}

// ErrKey is a malformed key.
var ErrKey = errors.New("btc: invalid key")

// hash160 is RIPEMD-160(SHA-256(b)) (btcutil's, as Bitcoin defines it).
func hash160(b []byte) []byte { return btcutil.Hash160(b) }

// Purpose is the account's purpose, 84 or 86.
func (a *Account) Purpose() uint32 { return PurposeOf(a.Type) }

// AccountPath is the account's derivation path, m/purpose'/coin'/0'.
func (a *Account) AccountPath() []uint32 {
	return []uint32{hardened + a.Purpose(), hardened + a.Network.CoinType, hardened}
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
	fn := "wpkh"
	if a.Type == P2TR {
		fn = "tr"
	}
	return fn + "([" + a.FingerprintHex() + "/" + strconv.FormatUint(uint64(a.Purpose()), 10) + "'/" +
		strconv.FormatUint(uint64(a.Network.CoinType), 10) + "'/0']" + a.XPub + "/" + strconv.FormatUint(uint64(change), 10) + "/*)"
}

// NewAccount derives the account of a BIP39 seed for an address type.
func NewAccount(seed []byte, n Network, addrType string) (*Account, error) {
	if PurposeOf(addrType) == 0 {
		return nil, ErrKey
	}
	acct, master, err := derivePrivate(seed, n, PurposeOf(addrType))
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
	a := &Account{Network: n, Type: addrType, XPub: xpub, key: pub}
	copy(a.Fingerprint[:], hash160(mpub.SerializeCompressed())[:4])
	return a, nil
}

// derivePrivate derives the account key m/purpose'/coin'/0'; the caller
// zeroes both returned keys (the account key and the master key).
func derivePrivate(seed []byte, n Network, purpose uint32) (*hdkeychain.ExtendedKey, *hdkeychain.ExtendedKey, error) {
	master, err := hdkeychain.NewMaster(seed, n.Params)
	if err != nil {
		return nil, nil, ErrKey
	}
	k := master
	for _, i := range []uint32{hardened + purpose, hardened + n.CoinType, hardened} {
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
func ParseAccount(network, addrType, fingerprintHex, xpub string) (*Account, error) {
	n, ok := LookupNetwork(network)
	if !ok || PurposeOf(addrType) == 0 {
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
	a := &Account{Network: n, Type: addrType, XPub: xpub, key: k}
	copy(a.Fingerprint[:], fp)
	return a, nil
}

func (a *Account) pub(chain, index uint32) (*btcec.PublicKey, error) {
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
	return pk, nil
}

// PubKey derives the public key at chain/index (chain 0 receive, 1
// change) as PSBTs name it: compressed (33 bytes) for P2WPKH, the x-only
// internal key (32 bytes) for P2TR.
func (a *Account) PubKey(chain, index uint32) ([]byte, error) {
	pk, err := a.pub(chain, index)
	if err != nil {
		return nil, err
	}
	if a.Type == P2TR {
		return schnorr.SerializePubKey(pk), nil
	}
	return pk.SerializeCompressed(), nil
}

// Address derives the address at chain/index and its output script:
// P2WPKH, or P2TR with the BIP86 key-path-only tweak.
func (a *Account) Address(chain, index uint32) (string, []byte, error) {
	pk, err := a.pub(chain, index)
	if err != nil {
		return "", nil, err
	}
	if a.Type == P2TR {
		out := txscript.ComputeTaprootKeyNoScript(pk)
		addr, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(out), a.Network.Params)
		if err != nil {
			return "", nil, ErrKey
		}
		script, err := txscript.PayToTaprootScript(out)
		if err != nil {
			return "", nil, ErrKey
		}
		return addr.EncodeAddress(), script, nil
	}
	h := hash160(pk.SerializeCompressed())
	addr, err := btcutil.NewAddressWitnessPubKeyHash(h, a.Network.Params)
	if err != nil {
		return "", nil, ErrKey
	}
	return addr.EncodeAddress(), append([]byte{0x00, 0x14}, h...), nil
}
