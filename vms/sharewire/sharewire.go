// Package sharewire holds the cryptographic pieces of sharing between
// connections (VAULT-MESSAGING §10.12, §10.13): a granted item's content
// sealed to the fetching device's one-time reply key, and the
// domain-separated message of a critical-item `auth` use.
package sharewire

import (
	"errors"

	"github.com/vettid/vettid-vault/vms/suite"
)

// Labels and sizes.
const (
	LabelGrant        = "vettid/vms/2/grant"
	LabelCriticalAuth = "vettid/vms/2/critical-auth"
	EncSize           = 1120
	// MaxValue bounds a granted value: an item's shared content (§10.12).
	MaxValue = 65536
)

// ErrOpen is returned for any value that does not open.
var ErrOpen = errors.New("sharewire: cannot open")

func grantInfo(grantID, fetchID string) string {
	return LabelGrant + "\x00" + grantID + "\x00" + fetchID
}

// SealValue seals a granted value to the fetching device's reply key
// (§10.12): enc || HPKE ciphertext, bound to the grant and the fetch.
func SealValue(reply *suite.PublicKey, grantID, fetchID string, value []byte) ([]byte, error) {
	if len(value) > MaxValue {
		return nil, ErrOpen
	}
	enc, ctx, err := suite.SetupSender(reply, grantInfo(grantID, fetchID))
	if err != nil {
		return nil, err
	}
	ct, err := ctx.Seal(nil, value)
	if err != nil {
		return nil, err
	}
	return append(enc, ct...), nil
}

// OpenValue opens a granted value with the device's one-time key.
func OpenValue(reply *suite.PrivateKey, grantID, fetchID string, sealed []byte) ([]byte, error) {
	if len(sealed) < EncSize+16 || len(sealed) > EncSize+MaxValue+16 {
		return nil, ErrOpen
	}
	r, err := suite.SetupRecipient(sealed[:EncSize], reply, grantInfo(grantID, fetchID))
	if err != nil {
		return nil, ErrOpen
	}
	v, err := r.Open(nil, sealed[EncSize:])
	if err != nil {
		return nil, ErrOpen
	}
	return v, nil
}

// AuthMessage is the message a critical-secret `auth` use signs, after
// LabelCriticalAuth (§10.13):
//
//	requester_ik (32) || owner_ik (32) || request_id (26) || payload
func AuthMessage(requesterIK, ownerIK []byte, requestID string, payload []byte) []byte {
	m := make([]byte, 0, len(requesterIK)+len(ownerIK)+len(requestID)+len(payload))
	m = append(append(m, requesterIK...), ownerIK...)
	return append(append(m, requestID...), payload...)
}
