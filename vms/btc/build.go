package btc

import (
	"bytes"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// Coin is an unspent output of the account, as the app's chain source
// reports it: the full previous transaction and the output's derivation.
type Coin struct {
	PrevTx *wire.MsgTx
	Vout   uint32
	Chain  uint32
	Index  uint32
	Acct   *Account // the coin's account; nil: BuildPSBT's
}

// Payee is an output to build.
type Payee struct {
	Address string
	Amount  int64
	// Change outputs pay the account at Chain/Index (Address is then
	// derived).
	Change bool
	Chain  uint32
	Index  uint32
	Acct   *Account // change: its account; nil: BuildPSBT's
}

// BuildPSBT makes the unsigned PSBT an app gives the vault (§10.18): the
// coins with their previous transactions and BIP32 derivations, the
// payees, and change derivations. Apps in other languages produce the
// same BIP174 structure with their own libraries.
func BuildPSBT(a *Account, coins []Coin, payees []Payee) ([]byte, error) {
	tx := wire.NewMsgTx(2)
	for _, c := range coins {
		h := c.PrevTx.TxHash()
		in := wire.NewTxIn(wire.NewOutPoint(&h, c.Vout), nil, nil)
		in.Sequence = wire.MaxTxInSequenceNum - 2 // signals RBF (BIP125)
		tx.AddTxIn(in)
	}
	for _, p := range payees {
		addr := p.Address
		if p.Change {
			var err error
			if addr, _, err = or(p.Acct, a).Address(p.Chain, p.Index); err != nil {
				return nil, err
			}
		}
		dec, err := btcutil.DecodeAddress(addr, a.Network.Params)
		if err != nil {
			return nil, ErrKey
		}
		script, err := txscript.PayToAddrScript(dec)
		if err != nil {
			return nil, ErrKey
		}
		tx.AddTxOut(wire.NewTxOut(p.Amount, script))
	}
	pkt, err := psbt.NewFromUnsignedTx(tx)
	if err != nil {
		return nil, err
	}
	for i, c := range coins {
		ca := or(c.Acct, a)
		pk, err := ca.PubKey(c.Chain, c.Index)
		if err != nil {
			return nil, err
		}
		in := &pkt.Inputs[i]
		in.NonWitnessUtxo = c.PrevTx
		if int(c.Vout) < len(c.PrevTx.TxOut) {
			in.WitnessUtxo = c.PrevTx.TxOut[c.Vout]
		}
		path := append(ca.AccountPath(), c.Chain, c.Index)
		if ca.Type == P2TR {
			in.TaprootInternalKey = pk
			in.TaprootBip32Derivation = []*psbt.TaprootBip32Derivation{{XOnlyPubKey: pk, MasterKeyFingerprint: ca.FingerprintUint32(), Bip32Path: path}}
			in.SighashType = txscript.SigHashDefault
		} else {
			in.Bip32Derivation = []*psbt.Bip32Derivation{{PubKey: pk, MasterKeyFingerprint: ca.FingerprintUint32(), Bip32Path: path}}
			in.SighashType = txscript.SigHashAll
		}
	}
	for i, p := range payees {
		if !p.Change {
			continue
		}
		pa := or(p.Acct, a)
		pk, err := pa.PubKey(p.Chain, p.Index)
		if err != nil {
			return nil, err
		}
		path := append(pa.AccountPath(), p.Chain, p.Index)
		if pa.Type == P2TR {
			pkt.Outputs[i].TaprootInternalKey = pk
			pkt.Outputs[i].TaprootBip32Derivation = []*psbt.TaprootBip32Derivation{{XOnlyPubKey: pk, MasterKeyFingerprint: pa.FingerprintUint32(), Bip32Path: path}}
		} else {
			pkt.Outputs[i].Bip32Derivation = []*psbt.Bip32Derivation{{PubKey: pk, MasterKeyFingerprint: pa.FingerprintUint32(), Bip32Path: path}}
		}
	}
	var buf bytes.Buffer
	if err := pkt.Serialize(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func or(a, b *Account) *Account {
	if a != nil {
		return a
	}
	return b
}

// FundingTx makes a synthetic transaction paying amount to the account's
// chain/index address: test vectors and regtest only (it spends a
// made-up outpoint and is never valid on a real chain).
func FundingTx(a *Account, chain, index uint32, amount int64, salt byte) (*wire.MsgTx, error) {
	_, script, err := a.Address(chain, index)
	if err != nil {
		return nil, err
	}
	tx := wire.NewMsgTx(2)
	var h [32]byte
	h[0] = salt
	prev := wire.NewOutPoint((*chainhash.Hash)(&h), 0)
	tx.AddTxIn(wire.NewTxIn(prev, []byte{0x51}, nil))
	tx.AddTxOut(wire.NewTxOut(amount, script))
	return tx, nil
}

// DecodeTx parses a serialised transaction (for tests and apps).
func DecodeTx(raw []byte) (*wire.MsgTx, error) {
	tx := &wire.MsgTx{}
	if err := tx.Deserialize(bytes.NewReader(raw)); err != nil {
		return nil, err
	}
	return tx, nil
}
