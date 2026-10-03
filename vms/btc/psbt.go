package btc

import (
	"bytes"
	"errors"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"

	"github.com/vettid/vettid-vault/vms/suite"
)

// PSBT policy limits (VAULT-MESSAGING §10.18).
const (
	MaxPSBT    = 65536 // bytes, decoded
	MaxInputs  = 64
	MaxOutputs = 64
	// MaxFeeRate refuses fees above 1,000 sat/vB: a lying chain source or
	// a compromised app cannot burn the wallet in fees.
	MaxFeeRate = 1000
	// MinOutput refuses dust outputs.
	MinOutput = 330
	// MaxAddress bounds an address string.
	MaxAddress = 90
)

// ErrSignature is a signature that does not verify after signing.
var ErrSignature = errors.New("btc: signature check failed")

// PSBTError is a PSBT the vault refuses to sign; Reason is a short,
// non-secret code for the app (`invalid_psbt` with this message).
type PSBTError struct{ Reason string }

func (e *PSBTError) Error() string { return "btc: psbt: " + e.Reason }

func refuse(reason string) error { return &PSBTError{Reason: reason} }

// Input is one checked input.
type Input struct {
	TxID   string
	Vout   uint32
	Amount int64
	Chain  uint32
	Index  uint32
}

// Output is one checked output.
type Output struct {
	Address string
	Amount  int64
	Change  bool // pays the wallet itself (with its derivation)
	Chain   uint32
	Index   uint32
}

// Summary is the vault's view of a PSBT it is willing to sign: what the
// app shows the member before approval, computed from the previous
// transactions themselves, not from amounts the PSBT merely claims.
type Summary struct {
	TxID     string
	Inputs   []Input
	Outputs  []Output
	TotalIn  int64
	TotalOut int64
	Sending  int64 // to addresses that are not the wallet's
	Change   int64
	Fee      int64
	VSize    int64

	pkt      *psbt.Packet
	prevOuts map[wire.OutPoint]*wire.TxOut
}

// ParsePSBT decodes a PSBT's binary form strictly (size-bounded; a
// panic inside the decoder is a refusal).
func ParsePSBT(raw []byte) (p *psbt.Packet, err error) {
	if len(raw) == 0 || len(raw) > MaxPSBT {
		return nil, refuse("size")
	}
	defer func() {
		if recover() != nil {
			p, err = nil, refuse("malformed")
		}
	}()
	p, err = psbt.NewFromRawBytes(bytes.NewReader(raw), false)
	if err != nil {
		return nil, refuse("malformed")
	}
	return p, nil
}

func ownPath(a *Account, d []*psbt.Bip32Derivation, script []byte) (uint32, uint32, bool, error) {
	fp := a.FingerprintUint32()
	want := a.AccountPath()
	for _, x := range d {
		if x.MasterKeyFingerprint != fp {
			continue
		}
		if len(x.Bip32Path) != 5 || x.Bip32Path[0] != want[0] || x.Bip32Path[1] != want[1] || x.Bip32Path[2] != want[2] {
			return 0, 0, false, refuse("derivation_path")
		}
		chain, idx := x.Bip32Path[3], x.Bip32Path[4]
		if chain > 1 || idx >= MaxIndex {
			return 0, 0, false, refuse("derivation_path")
		}
		pk, err := a.PubKey(chain, idx)
		if err != nil || !suite.Equal(pk, x.PubKey) {
			return 0, 0, false, refuse("derivation_key")
		}
		if !suite.Equal(script, p2wpkh(hash160(pk))) {
			return 0, 0, false, refuse("derivation_script")
		}
		return chain, idx, true, nil
	}
	return 0, 0, false, nil
}

// Inspect checks a PSBT against the vault's signing policy for account a:
//   - every input spends a P2WPKH output of the account (BIP32 derivation
//     with the account's fingerprint and path m/84'/coin'/0'/{0,1}/i whose
//     key and script the vault re-derives), with the full previous
//     transaction (whose txid must match, so the amounts signed for are
//     the real ones, CVE-2020-14199), SIGHASH_ALL only, not yet finalised;
//   - every output is a standard address of the account's network, at
//     least MinOutput; outputs with the account's derivation are change;
//   - the fee is positive and at most MaxFeeRate.
func Inspect(a *Account, raw []byte) (*Summary, error) {
	p, err := ParsePSBT(raw)
	if err != nil {
		return nil, err
	}
	tx := p.UnsignedTx
	if len(tx.TxIn) == 0 || len(tx.TxIn) > MaxInputs || len(tx.TxOut) == 0 || len(tx.TxOut) > MaxOutputs ||
		len(p.Inputs) != len(tx.TxIn) || len(p.Outputs) != len(tx.TxOut) {
		return nil, refuse("shape")
	}
	if tx.Version < 1 || tx.Version > 2 {
		return nil, refuse("version")
	}
	s := &Summary{pkt: p, prevOuts: map[wire.OutPoint]*wire.TxOut{}}
	for i, in := range p.Inputs {
		op := tx.TxIn[i].PreviousOutPoint
		if _, dup := s.prevOuts[op]; dup {
			return nil, refuse("duplicate_input")
		}
		if in.NonWitnessUtxo == nil || in.NonWitnessUtxo.TxHash() != op.Hash || int(op.Index) >= len(in.NonWitnessUtxo.TxOut) {
			return nil, refuse("previous_tx")
		}
		prev := in.NonWitnessUtxo.TxOut[op.Index]
		if in.WitnessUtxo != nil && (in.WitnessUtxo.Value != prev.Value || !suite.Equal(in.WitnessUtxo.PkScript, prev.PkScript)) {
			return nil, refuse("witness_utxo")
		}
		if in.SighashType != 0 && in.SighashType != txscript.SigHashAll {
			return nil, refuse("sighash")
		}
		if len(in.FinalScriptSig) > 0 || len(in.FinalScriptWitness) > 0 || len(in.RedeemScript) > 0 || len(in.WitnessScript) > 0 {
			return nil, refuse("input_script")
		}
		if prev.Value <= 0 || prev.Value > btcutil.MaxSatoshi {
			return nil, refuse("amount")
		}
		chain, idx, own, err := ownPath(a, in.Bip32Derivation, prev.PkScript)
		if err != nil {
			return nil, err
		}
		if !own {
			return nil, refuse("foreign_input")
		}
		s.prevOuts[op] = prev
		s.TotalIn += prev.Value
		s.Inputs = append(s.Inputs, Input{TxID: op.Hash.String(), Vout: op.Index, Amount: prev.Value, Chain: chain, Index: idx})
	}
	for i, out := range tx.TxOut {
		if out.Value < MinOutput || out.Value > btcutil.MaxSatoshi {
			return nil, refuse("output_amount")
		}
		class, addrs, _, err := txscript.ExtractPkScriptAddrs(out.PkScript, a.Network.Params)
		if err != nil || len(addrs) != 1 || !standard(class) {
			return nil, refuse("output_script")
		}
		o := Output{Address: addrs[0].EncodeAddress(), Amount: out.Value}
		chain, idx, own, err := ownPath(a, p.Outputs[i].Bip32Derivation, out.PkScript)
		if err != nil {
			return nil, err
		}
		if own {
			o.Change, o.Chain, o.Index = true, chain, idx
			s.Change += out.Value
		} else {
			s.Sending += out.Value
		}
		s.TotalOut += out.Value
		s.Outputs = append(s.Outputs, o)
	}
	if s.TotalIn > btcutil.MaxSatoshi || s.TotalOut >= s.TotalIn {
		return nil, refuse("fee")
	}
	s.Fee = s.TotalIn - s.TotalOut
	s.VSize = vsize(tx)
	if s.Fee > MaxFeeRate*s.VSize {
		return nil, refuse("fee_rate")
	}
	s.TxID = tx.TxHash().String() // final: every input is segwit
	return s, nil
}

func standard(c txscript.ScriptClass) bool {
	switch c {
	case txscript.PubKeyHashTy, txscript.ScriptHashTy, txscript.WitnessV0PubKeyHashTy,
		txscript.WitnessV0ScriptHashTy, txscript.WitnessV1TaprootTy:
		return true
	}
	return false
}

// vsize is the signed transaction's virtual size: the stripped size, plus
// the marker, flag and one P2WPKH witness (a 72-byte signature and a
// 33-byte key, with their pushes and count) per input, in weight units.
func vsize(tx *wire.MsgTx) int64 {
	weight := int64(tx.SerializeSizeStripped())*4 + 2 + int64(len(tx.TxIn))*108
	return (weight + 3) / 4
}

// PayCheck says whether a summary pays exactly amount to address (and
// nothing to anyone else but the wallet itself): what a payment request
// approved by the member may sign (§10.14).
func (s *Summary) PayCheck(address string, amount int64) error {
	var paid int64
	for _, o := range s.Outputs {
		switch {
		case o.Change:
		case o.Address == address:
			paid += o.Amount
		default:
			return refuse("other_payee")
		}
	}
	if paid != amount {
		return refuse("amount_mismatch")
	}
	return nil
}

// Sign signs every input of an inspected PSBT with keys derived from the
// BIP39 seed, checks each signature with the script engine and returns the
// final transaction. The caller wipes seed.
func Sign(a *Account, s *Summary, seed []byte) ([]byte, error) {
	acct, master, err := derivePrivate(seed, a.Network, nil)
	if err != nil {
		return nil, err
	}
	master.Zero()
	defer acct.Zero()
	pub, err := acct.Neuter()
	if err != nil || pub.String() != a.XPub {
		return nil, refuse("wrong_seed")
	}
	tx := s.pkt.UnsignedTx.Copy()
	fetch := txscript.NewMultiPrevOutFetcher(s.prevOuts)
	hashes := txscript.NewTxSigHashes(tx, fetch)
	for i, in := range s.Inputs {
		c, err := acct.Derive(in.Chain)
		if err != nil {
			return nil, ErrKey
		}
		k, err := c.Derive(in.Index)
		c.Zero()
		if err != nil {
			return nil, ErrKey
		}
		priv, err := k.ECPrivKey()
		k.Zero()
		if err != nil {
			return nil, ErrKey
		}
		prev := s.prevOuts[tx.TxIn[i].PreviousOutPoint]
		w, err := txscript.WitnessSignature(tx, hashes, i, prev.Value, prev.PkScript, txscript.SigHashAll, priv, true)
		priv.Zero()
		if err != nil {
			return nil, ErrKey
		}
		tx.TxIn[i].Witness = w
	}
	for i := range tx.TxIn {
		prev := s.prevOuts[tx.TxIn[i].PreviousOutPoint]
		vm, err := txscript.NewEngine(prev.PkScript, tx, i, txscript.StandardVerifyFlags, nil, hashes, prev.Value, fetch)
		if err != nil || vm.Execute() != nil {
			return nil, ErrSignature
		}
	}
	var buf bytes.Buffer
	if err := tx.Serialize(&buf); err != nil {
		return nil, ErrKey
	}
	return buf.Bytes(), nil
}

// CheckAddress parses a payee address for network n: a standard address
// of that network, in its canonical encoding.
func CheckAddress(n Network, s string) (string, error) {
	if s == "" || len(s) > MaxAddress {
		return "", ErrKey
	}
	addr, err := btcutil.DecodeAddress(s, n.Params)
	if err != nil || !addr.IsForNet(n.Params) {
		return "", ErrKey
	}
	script, err := txscript.PayToAddrScript(addr)
	if err != nil {
		return "", ErrKey
	}
	class, addrs, _, err := txscript.ExtractPkScriptAddrs(script, n.Params)
	if err != nil || len(addrs) != 1 || !standard(class) {
		return "", ErrKey
	}
	return addrs[0].EncodeAddress(), nil
}
