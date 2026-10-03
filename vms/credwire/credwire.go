// Package credwire is the wire crypto of the Protean Credential's one-time
// keys (VAULT-MESSAGING §3.5.4): payloads sealed to a UTK inside the
// session, and secret values sealed to a one-time reply key. Both are
// HPKE suite 2 (MLKEM768X25519), one context per message.
package credwire

import (
	"errors"

	"github.com/vettid/vettid-vault/vms/suite"
)

// Labels and sizes.
const (
	LabelUTK   = "vettid/vms/2/utk"
	LabelReply = "vettid/vms/2/reply"
	EncSize    = 1120
	// MaxPayload bounds a UTK payload's plaintext (§3.5.4).
	MaxPayload = 16 * 1024
	// MaxValue bounds a reply-sealed value.
	MaxValue = 64 * 1024
)

// ErrOpen is any failure to open a sealed payload or value.
var ErrOpen = errors.New("credwire: cannot open")

func utkInfo(vaultID, utkID string) string { return LabelUTK + "\x00" + vaultID + "\x00" + utkID }

func utkAAD(typ, innerID string) []byte { return []byte(typ + "\x00" + innerID) }

// SealPayload seals pt to the UTK ek for one request of type typ with inner
// id innerID: enc || ct.
func SealPayload(ek *suite.PublicKey, vaultID, utkID, typ, innerID string, pt []byte) ([]byte, error) {
	if len(pt) > MaxPayload {
		return nil, ErrOpen
	}
	enc, ctx, err := suite.SetupSender(ek, utkInfo(vaultID, utkID))
	if err != nil {
		return nil, err
	}
	ct, err := ctx.Seal(utkAAD(typ, innerID), pt)
	if err != nil {
		return nil, err
	}
	return append(enc, ct...), nil
}

// OpenPayload opens a sealed payload with the LTK.
func OpenPayload(ltk *suite.PrivateKey, vaultID, utkID, typ, innerID string, sealed []byte) ([]byte, error) {
	if len(sealed) < EncSize+16 || len(sealed) > EncSize+MaxPayload+16 {
		return nil, ErrOpen
	}
	r, err := suite.SetupRecipient(sealed[:EncSize], ltk, utkInfo(vaultID, utkID))
	if err != nil {
		return nil, ErrOpen
	}
	pt, err := r.Open(utkAAD(typ, innerID), sealed[EncSize:])
	if err != nil {
		return nil, ErrOpen
	}
	return pt, nil
}

func replyInfo(vaultID, innerID string) string {
	return LabelReply + "\x00" + vaultID + "\x00" + innerID
}

// SealValue seals a secret value to the request's one-time reply key.
func SealValue(reply *suite.PublicKey, vaultID, innerID string, value []byte) ([]byte, error) {
	if len(value) > MaxValue {
		return nil, ErrOpen
	}
	enc, ctx, err := suite.SetupSender(reply, replyInfo(vaultID, innerID))
	if err != nil {
		return nil, err
	}
	ct, err := ctx.Seal(nil, value)
	if err != nil {
		return nil, err
	}
	return append(enc, ct...), nil
}

// OpenValue opens a reply-sealed value with the app's one-time key.
func OpenValue(reply *suite.PrivateKey, vaultID, innerID string, sealed []byte) ([]byte, error) {
	if len(sealed) < EncSize+16 || len(sealed) > EncSize+MaxValue+16 {
		return nil, ErrOpen
	}
	r, err := suite.SetupRecipient(sealed[:EncSize], reply, replyInfo(vaultID, innerID))
	if err != nil {
		return nil, ErrOpen
	}
	v, err := r.Open(nil, sealed[EncSize:])
	if err != nil {
		return nil, ErrOpen
	}
	return v, nil
}
