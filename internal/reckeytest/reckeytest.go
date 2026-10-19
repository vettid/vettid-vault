// Package reckeytest is the TEST-ONLY recovery request key of the member
// API stand-in (VAULT-MESSAGING 0.33.0 §11.14.8): a fixed P-256 scalar,
// pinned by the development and test enclave configurations. Never
// linked into a release package (check-tcb).
package reckeytest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"

	"github.com/vettid/vettid-vault/enclave/releasecfg"
	"github.com/vettid/vettid-vault/vms/recovery"
)

// KeyID names the test key in queue messages.
const KeyID = "test-recovery-request-key"

// Key returns the test key.
func Key() *ecdsa.PrivateKey {
	k, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), bytes.Repeat([]byte{0x2b}, 32))
	if err != nil {
		panic(err)
	}
	return k
}

// Pinned is the key as a release pins it.
func Pinned() []releasecfg.RequestKey {
	return []releasecfg.RequestKey{{KeyID: KeyID, Key: &Key().PublicKey}}
}

// Sign signs a recovery or recovery_cancel queue message's members and
// returns sig (base64 DER).
func Sign(op, vaultID, userGUID, requestID, signedAt string, browserKey []byte) string {
	return SignNamed(op, vaultID, userGUID, requestID, signedAt, browserKey, "")
}

// SignNamed is Sign with a cancel's recovery_id (0.49.0, the eight-line
// string; "" for the seven-line one).
func SignNamed(op, vaultID, userGUID, requestID, signedAt string, browserKey []byte, recoveryID string) string {
	s, err := recovery.RequestSigningString(op, vaultID, userGUID, requestID, signedAt, browserKey, recoveryID)
	if err != nil {
		return ""
	}
	h := sha256.Sum256([]byte(s))
	sig, err := ecdsa.SignASN1(rand.Reader, Key(), h[:])
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(sig)
}
