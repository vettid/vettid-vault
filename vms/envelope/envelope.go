// Package envelope implements the v2 envelope of VAULT-MESSAGING §5: the
// byte layout for session and sealed modes (§5.2), the inner plaintext
// (§5.3), padding (§5.4), size limits and the claim-check blob (§5.5).
//
// Parsing is strict: anything that is not exactly what a conforming sender
// produces is rejected before any decryption is attempted. Errors never
// carry input bytes, plaintext or key material.
package envelope

import (
	"errors"

	"github.com/vettid/vettid-vault/vms/suite"
)

// Mode is the envelope mode byte.
type Mode uint8

const (
	ModeSession Mode = 0x01
	ModeSealed  Mode = 0x02
)

func (m Mode) String() string {
	switch m {
	case ModeSession:
		return "session"
	case ModeSealed:
		return "sealed"
	}
	return "invalid"
}

// Layout constants (§5.2).
const (
	Version byte = 0x02

	offVer          = 0
	offSuite        = 1
	offMode         = 2
	offFlags        = 3
	offSenderKid    = 4
	offRecipientKid = 12
	offBody         = 20

	HeaderSession = offBody + suite.XNonceSize // 44
	HeaderSealed  = offBody + suite.EncSize    // 1140

	OverheadSession = HeaderSession + suite.TagSize // 60
	OverheadSealed  = HeaderSealed + suite.TagSize  // 1156
)

// Size limits (§5.4, §5.5).
const (
	// MinPadded is the smallest padded inner plaintext.
	MinPadded = 512
	// SmallBucketLimit is the boundary between 512-byte and 16 KiB buckets.
	SmallBucketLimit = 16 * 1024
	// MaxPadded is the largest padded inner plaintext a sender may produce.
	MaxPadded = 245760
	// AltChannelPadded is the fixed padded size of alternate-channel
	// plaintexts (§5.4, §11).
	AltChannelPadded = 4096
	// DefaultMaxPayload is the relay's default max_payload_bytes.
	DefaultMaxPayload = 262144
	// BlobThreshold is the content size above which the claim-check blob
	// flow SHOULD be used (§5.5).
	BlobThreshold = 64 * 1024
)

// Errors.
var (
	ErrTruncated   = errors.New("envelope: truncated")
	ErrVersion     = errors.New("envelope: unsupported version")
	ErrMode        = errors.New("envelope: invalid mode")
	ErrFlags       = errors.New("envelope: reserved flags set")
	ErrLength      = errors.New("envelope: invalid length")
	ErrTooLarge    = errors.New("envelope: padded plaintext exceeds the size limit")
	ErrPadding     = errors.New("envelope: malformed padding")
	ErrKid         = errors.New("envelope: kid does not match the key")
	ErrWrongMode   = errors.New("envelope: wrong mode for this operation")
	ErrDecrypt     = errors.New("envelope: decryption failed")
	ErrInner       = errors.New("envelope: malformed inner plaintext")
	ErrClockFuture = errors.New("envelope: timestamp too far in the future")
	ErrClockPast   = errors.New("envelope: timestamp too old")
	ErrExpired     = errors.New("envelope: message expired")
)

// Envelope is a structurally valid, still-encrypted v2 envelope.
type Envelope struct {
	raw          []byte
	mode         Mode
	suite        uint8
	senderKid    suite.Kid
	recipientKid suite.Kid
}

// Parse validates the structure of an envelope without decrypting it:
// version 2, suite 2 (suite 1 rejected), mode session or sealed, flags
// zero, and a ciphertext whose length is the tag plus a valid padded size
// (§5.4) no larger than MaxPadded (§5.5). The input is copied.
func Parse(b []byte) (*Envelope, error) {
	if len(b) < offBody {
		return nil, ErrTruncated
	}
	if b[offVer] != Version {
		return nil, ErrVersion
	}
	if err := suite.Check(int(b[offSuite]), 0); err != nil {
		return nil, err
	}
	if b[offFlags] != 0 {
		return nil, ErrFlags
	}
	var h int
	switch Mode(b[offMode]) {
	case ModeSession:
		h = HeaderSession
	case ModeSealed:
		h = HeaderSealed
	default:
		return nil, ErrMode
	}
	if len(b) < h+suite.TagSize+MinPadded {
		return nil, ErrTruncated
	}
	if !ValidPaddedLen(len(b) - h - suite.TagSize) {
		return nil, ErrLength
	}
	e := &Envelope{
		raw:   append([]byte(nil), b...),
		mode:  Mode(b[offMode]),
		suite: b[offSuite],
	}
	copy(e.senderKid[:], b[offSenderKid:offRecipientKid])
	copy(e.recipientKid[:], b[offRecipientKid:offBody])
	return e, nil
}

// Mode returns the envelope mode.
func (e *Envelope) Mode() Mode { return e.mode }

// Suite returns the suite byte.
func (e *Envelope) Suite() uint8 { return e.suite }

// SenderKid returns the sender kid.
func (e *Envelope) SenderKid() suite.Kid { return e.senderKid }

// RecipientKid returns the recipient kid, the only routing hint a receiver
// uses besides the collect `sender` (§13.6).
func (e *Envelope) RecipientKid() suite.Kid { return e.recipientKid }

// HeaderLen returns 44 (session) or 1,140 (sealed).
func (e *Envelope) HeaderLen() int {
	if e.mode == ModeSession {
		return HeaderSession
	}
	return HeaderSealed
}

// Header returns a copy of the header, which is also the AAD.
func (e *Envelope) Header() []byte { return append([]byte(nil), e.raw[:e.HeaderLen()]...) }

// Bytes returns a copy of the whole envelope.
func (e *Envelope) Bytes() []byte { return append([]byte(nil), e.raw...) }

// Len returns the envelope length.
func (e *Envelope) Len() int { return len(e.raw) }

// PaddedLen returns the length of the padded inner plaintext.
func (e *Envelope) PaddedLen() int { return len(e.raw) - e.HeaderLen() - suite.TagSize }

func (e *Envelope) body() []byte { return e.raw[offBody:e.HeaderLen()] }

func (e *Envelope) ciphertext() []byte { return e.raw[e.HeaderLen():] }

func header(mode Mode, senderKid, recipientKid suite.Kid, body []byte) []byte {
	h := make([]byte, 0, offBody+len(body))
	h = append(h, Version, suite.Suite2, byte(mode), 0x00)
	h = append(h, senderKid[:]...)
	h = append(h, recipientKid[:]...)
	return append(h, body...)
}
