// Package handshake implements the session handshake of VAULT-MESSAGING §6:
// the three messages hs.init, hs.resp and hs.fin (§6.1, §6.2), the key
// schedule and SAS (§6.3), epochs, rekey and key retention (§6.5), the
// crypto and wire parts of reconnects (§6.6) and the rotation chains they
// rely on (§3.4).
//
// Runtime state (which invites are outstanding, approval, persistence,
// dedupe, acks) belongs to the vault runtime; this package exposes the
// checks the runtime must apply as functions so that they are testable.
package handshake

import "errors"

// Errors. None of them carries key material, plaintext or input bytes.
var (
	ErrBody         = errors.New("handshake: malformed message body")
	ErrType         = errors.New("handshake: unexpected message type")
	ErrPurpose      = errors.New("handshake: purpose not allowed here")
	ErrNoKey        = errors.New("handshake: no key for recipient kid")
	ErrSenderKid    = errors.New("handshake: sender kid does not match")
	ErrSender       = errors.New("handshake: relay sender does not match")
	ErrIdentity     = errors.New("handshake: identity key does not match the record")
	ErrCtx          = errors.New("handshake: ctx does not match")
	ErrRotation     = errors.New("handshake: invalid rotation statement or chain")
	ErrSigResp      = errors.New("handshake: sig_R verification failed")
	ErrSigFin       = errors.New("handshake: sig_I verification failed")
	ErrAborted      = errors.New("handshake: handshake aborted")
	ErrDone         = errors.New("handshake: handshake already completed")
	ErrConfig       = errors.New("handshake: invalid configuration")
	ErrEpochRetired = errors.New("handshake: epoch key retired")
	ErrTokenUse     = errors.New("handshake: message not permitted on a reconnect token")
)
