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
			if addr, _, err = a.Address(p.Chain, p.Index); err != nil {
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
	deriv := func(chain, index uint32) ([]*psbt.Bip32Derivation, error) {
		pk, err := a.PubKey(chain, index)
		if err != nil {
			return nil, err
		}
		return []*psbt.Bip32Derivation{{PubKey: pk, MasterKeyFingerprint: a.FingerprintUint32(),
			Bip32Path: append(a.AccountPath(), chain, index)}}, nil
	}
	for i, c := range coins {
		d, err := deriv(c.Chain, c.Index)
		if err != nil {
			return nil, err
		}
		pkt.Inputs[i].NonWitnessUtxo = c.PrevTx
		if int(c.Vout) < len(c.PrevTx.TxOut) {
			pkt.Inputs[i].WitnessUtxo = c.PrevTx.TxOut[c.Vout]
		}
		pkt.Inputs[i].Bip32Derivation = d
		pkt.Inputs[i].SighashType = txscript.SigHashAll
	}
	for i, p := range payees {
		if p.Change {
			d, err := deriv(p.Chain, p.Index)
			if err != nil {
				return nil, err
			}
			pkt.Outputs[i].Bip32Derivation = d
		}
	}
	var buf bytes.Buffer
	if err := pkt.Serialize(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
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
