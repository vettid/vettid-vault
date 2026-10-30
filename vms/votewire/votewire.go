// Package votewire is the vault's side of the ballot protocol's bytes
// (VAULT-MESSAGING 0.81.0 §10.19; BALLOT-PROTOCOL 0.12.0, vettid/service-vault
// docs/BALLOT-PROTOCOL.md): the signed strings, the strict Ed25519 rules, the
// RFC 6962 trees, the JCS documents, and the bodies of the vote messages. It
// holds no state and does no I/O; the checks that need the vault's clock,
// its connections or its storage are in features/vote.
//
// Nothing here verifies a Sigstore bundle: that is a separate question
// (PR 2 of the series, see the dependency note in the PR description).
package votewire

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
)

// Labels (BALLOT-PROTOCOL §2): the VMS convention, each ending in its own
// 0x00 byte, which separates it from the message (suite.Sign signs
// label ‖ m). No label is a prefix of another.
const (
	LabelProposal    = "vettid/vote/1/proposal\x00"
	LabelExtended    = "vettid/vote/1/extended\x00"
	LabelResults     = "vettid/vote/1/results\x00"
	LabelBallot      = "vettid/vote/1/ballot\x00"
	LabelCast        = "vettid/vote/1/cast\x00"
	LabelReceipt     = "vettid/vote/1/receipt\x00"
	LabelStatus      = "vettid/vote/1/status\x00"
	LabelRefusal     = "vettid/vote/1/refusal\x00"
	LabelAnchorKey   = "vettid/vote/1/anchor-key\x00"
	LabelServiceList = "vettid/vote/1/service-list\x00"
	labelRecord      = "vettid/vote/1/record\x00"
)

// Sizes of the fixed fields.
const (
	ProposalIDLen = 26 // a canonical ULID
	HashLen       = sha256.Size
	KeyLen        = 32 // an Ed25519 public key
	SigLen        = 64 // an Ed25519 signature
	SecretLen     = 32 // record_secret
)

// Bounds (VAULT-MESSAGING §10.19.2, §10.19.4; §10.1).
const (
	MaxBody         = 196608  // a vote.proposal body
	MaxProposal     = 65536   // the decoded proposal document
	MaxBundle       = 65536   // a Sigstore bundle
	MaxRecordPath   = 32      // entries of a record_proof path
	MaxExtensionDoc = 4096    // an extension document (0.81.1; the votes site's bound)
	MaxResultsDoc   = MaxBody // the results document (chosen)
	MaxExtensions   = 24      // extensions total at most 24 h, in steps of an hour
	MaxWindow       = 7 * 24 * 3600
	MaxExtension    = 24 * 3600 // extensions move the close by at most this, in total
	MaxTitle        = 200
	MaxText         = 16384
	MaxLabel        = 200
	MaxQuorumText   = 1024
	MaxOutageRule   = 1024
	MinOutage       = 3600 // an extension's outage is longer than this (0.81.1)
	// The service list's bounds (BALLOT-PROTOCOL 0.12.5): no limit on the
	// number of services or keys, a name of 1 to 100 bytes, and the list at
	// most 4 MiB. The size is checked first.
	MaxServiceList = 4 << 20
	MaxServiceName = 100
	// MaxSyncBytes bounds the encoded request body of one vote.site.sync
	// (§10.19.8, 0.81.2): attachment_max_bytes at vettid.org's relay, the
	// relay's max_blob_bytes less the 41-byte header and the Padmé padding
	// (§10.5.1). The vault also holds it to the relay it is on
	// (Session.BlobLimit). It is the one constant to change.
	MaxSyncBytes = 8257532
	// MaxSyncInline is §5.5's cap on an inline padded plaintext: a request
	// over it travels as one claim-check blob.
	MaxSyncInline = 245760
	// A vote.site.sync carries at most this many lists (one when a list is
	// over BigList bytes) and entries.
	MaxSyncLists   = 8
	MaxSyncEntries = 8
	BigList        = 1 << 20
	// Extension source: 1 to 1,024 bytes of UTF-8 (BALLOT-PROTOCOL 0.12.4).
	MaxExtensionSource = 1024
	MinChoices         = 3
	MaxChoices         = 17
	AbstainID          = "abstain"
)

// Limits of what the vault keeps (§10.19.2).
const (
	MaxProposals             = 128
	MaxPerConnection         = 32
	MaxOpenPerConnection     = 16
	MaxProblemsPerConnection = 16
	MaxCompactPerConnection  = 512
	CompactRetentionDays     = 365
	MaxRefusalsKept          = 8
)

// Errors are fixed sentinels (VAULT-MESSAGING §13.6): none echoes input.
var (
	// ErrField is a field outside its bounds (a length, an id).
	ErrField = errors.New("votewire: field out of bounds")
	// ErrSignature is a signature that does not verify by BALLOT-PROTOCOL §2.
	ErrSignature = errors.New("votewire: signature refused")
	// ErrProof is a Merkle proof that does not verify.
	ErrProof = errors.New("votewire: inclusion proof refused")
	// ErrDocument is a document that is not exactly its own JCS form, or
	// does not have exactly the members and types of BALLOT-PROTOCOL §8.5.
	ErrDocument = errors.New("votewire: not a canonical document")
	// ErrBody is a message body that does not have the members of
	// VAULT-MESSAGING §6.4 "Votes" with their types.
	ErrBody = errors.New("votewire: malformed vote message")
)

func eq(a, b []byte) bool { return subtle.ConstantTimeCompare(a, b) == 1 }

// ValidProposalID reports whether id is a canonical upper-case ULID: 26
// characters of Crockford base32 whose first is at most 7 (BALLOT-PROTOCOL
// §2).
func ValidProposalID(id string) bool {
	if len(id) != ProposalIDLen || id[0] < '0' || id[0] > '7' {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'A' && c <= 'Z' && c != 'I' && c != 'L' && c != 'O' && c != 'U':
		default:
			return false
		}
	}
	return true
}

// ValidChoiceID reports whether id matches [a-z0-9-]{1,32}.
func ValidChoiceID(id string) bool {
	if len(id) < 1 || len(id) > 32 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// lp is u16(len(x)) ‖ x (BALLOT-PROTOCOL §2); callers keep len(x) ≤ 65535.
func lp(b, x []byte) []byte {
	b = binary.BigEndian.AppendUint16(b, uint16(len(x)))
	return append(b, x...)
}

// H is SHA-256 of the concatenation of parts.
func H(parts ...[]byte) []byte {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

// RecordTag is H("vettid/vote/1/record\x00" ‖ proposal_id ‖ record_secret)
// (BALLOT-PROTOCOL §3.2).
func RecordTag(proposalID string, secret []byte) ([]byte, error) {
	if !ValidProposalID(proposalID) || len(secret) != SecretLen {
		return nil, ErrField
	}
	return H([]byte(labelRecord), []byte(proposalID), secret), nil
}

// BallotMsg is proposal_hash ‖ record_tag ‖ lp(choice_id), signed under
// LabelBallot with the voting key (§5).
func BallotMsg(proposalHash, recordTag []byte, choiceID string) ([]byte, error) {
	if len(proposalHash) != HashLen || len(recordTag) != HashLen || !ValidChoiceID(choiceID) {
		return nil, ErrField
	}
	b := append(append([]byte{}, proposalHash...), recordTag...)
	return lp(b, []byte(choiceID)), nil
}

// Ballot is a ballot as the service keeps and the results publish it.
type Ballot struct {
	RecordTag []byte
	VK        []byte
	ChoiceID  string
	BallotSig []byte
}

// Leaf is ballot_leaf: record_tag ‖ lp(vk) ‖ lp(choice_id) ‖ lp(ballot_sig)
// (§5, §8.2). It is the row leaf of a ballot, and what the credential
// signature and the receipt cover.
func (b *Ballot) Leaf() ([]byte, error) {
	if len(b.RecordTag) != HashLen || len(b.VK) != KeyLen || !ValidChoiceID(b.ChoiceID) || len(b.BallotSig) != SigLen {
		return nil, ErrField
	}
	out := append([]byte{}, b.RecordTag...)
	out = lp(out, b.VK)
	out = lp(out, []byte(b.ChoiceID))
	return lp(out, b.BallotSig), nil
}

// EmptyRowLeaf is the row leaf of a tag that did not vote: the tag alone
// (§8.2).
func EmptyRowLeaf(recordTag []byte) ([]byte, error) {
	if len(recordTag) != HashLen {
		return nil, ErrField
	}
	return append([]byte{}, recordTag...), nil
}

// CastMsg is proposal_hash ‖ H(ballot_leaf), signed under LabelCast with the
// member's credential key (§5).
func CastMsg(proposalHash, ballotLeaf []byte) ([]byte, error) {
	if len(proposalHash) != HashLen {
		return nil, ErrField
	}
	return append(append([]byte{}, proposalHash...), H(ballotLeaf)...), nil
}

// ReceiptMsg is proposal_hash ‖ H(ballot_leaf) ‖ u64(msg_ms), signed under
// LabelReceipt with the service identity key (§5).
func ReceiptMsg(proposalHash, ballotLeaf []byte, msgMS uint64) ([]byte, error) {
	b, err := CastMsg(proposalHash, ballotLeaf)
	if err != nil {
		return nil, err
	}
	return binary.BigEndian.AppendUint64(b, msgMS), nil
}

// StatusMsg is lp(proposal_id) ‖ lp(record_tag) ‖ H(ballot_leaf), signed
// under LabelStatus (§4.2). For an answer without a ballot ballotLeaf is
// empty and the last part is H("") (e3b0c442...). recordTag may be empty.
func StatusMsg(proposalID string, recordTag, ballotLeaf []byte) ([]byte, error) {
	if !ValidProposalID(proposalID) || (len(recordTag) != 0 && len(recordTag) != HashLen) {
		return nil, ErrField
	}
	b := lp(nil, []byte(proposalID))
	b = lp(b, recordTag)
	return append(b, H(ballotLeaf)...), nil
}

// RefusalMsg is lp(proposal_id) ‖ lp(connection) ‖ lp(record_tag) ‖
// lp(type) ‖ lp(code) ‖ u64(msg_ms) ‖ request_hash, signed under
// LabelRefusal (§4.2). connection is H(the vault's identity key on the
// connection); recordTag may be empty. requestHash is H(ballot_leaf) for
// vote.cast and H(proposal_id) for vote.status.
func RefusalMsg(proposalID string, connection, recordTag []byte, typ, code string, msgMS uint64, requestHash []byte) ([]byte, error) {
	if !ValidProposalID(proposalID) || len(connection) != HashLen || (len(recordTag) != 0 && len(recordTag) != HashLen) ||
		typ == "" || len(typ) > 64 || code == "" || len(code) > 64 || len(requestHash) != HashLen {
		return nil, ErrField
	}
	b := lp(nil, []byte(proposalID))
	b = lp(b, connection)
	b = lp(b, recordTag)
	b = lp(b, []byte(typ))
	b = lp(b, []byte(code))
	b = binary.BigEndian.AppendUint64(b, msgMS)
	return append(b, requestHash...), nil
}

// ProposalSigMsg is H(proposal bytes), signed under LabelProposal (§3.1).
func ProposalSigMsg(doc []byte) []byte { return H(doc) }

// DocSigMsg is proposal_hash ‖ H(document bytes), the signed message of an
// extension (LabelExtended) or the results (LabelResults).
func DocSigMsg(proposalHash, doc []byte) ([]byte, error) {
	if len(proposalHash) != HashLen {
		return nil, ErrField
	}
	return append(append([]byte{}, proposalHash...), H(doc)...), nil
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
