package votewire

import (
	"crypto/ed25519"

	"github.com/vettid/vettid-vault/vms/suite"
)

// Verify checks an Ed25519 signature over label ‖ msg by the four steps of
// BALLOT-PROTOCOL §2, which every verifier applies so that they all agree:
//
//  1. A and R are 32 bytes whose y is below p, and not x = 0 with the sign
//     bit set;
//  2. neither [8]A nor [8]R is the identity (no small-order key or R);
//  3. S < L;
//  4. [S]B = R + [k]A, cofactorless.
//
// Go's ed25519.Verify does steps 3 and 4 and decodes a non-canonical y, so
// steps 1 and 2 are made here. Step 2 is a table: the points of small order
// are the eight whose y is 0, 1, p-1 or one of the two y of the order-8
// points (each with either sign of x), and the table is checked against the
// reference vectors and by arithmetic in the tests.
func Verify(pub []byte, label string, msg, sig []byte) error {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return ErrSignature
	}
	if !strictPoint(pub) || !strictPoint(sig[:32]) {
		return ErrSignature
	}
	if suite.Verify(pub, label, msg, sig) != nil {
		return ErrSignature
	}
	return nil
}

// p = 2^255 - 19, little-endian.
var fieldP = [32]byte{
	0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
}

// smallOrderY lists the y coordinates (little-endian, sign bit clear) of
// the points of order 1, 2, 4 and 8: x = 0 gives y = 1 (identity) and
// y = p-1 (order 2); y = 0 gives the two points of order 4; the other two
// y give the four points of order 8. A point with one of these y is of
// small order whichever sign its x has, and the encoding of x = 0 with the
// sign bit set (y = 1 or p-1) is among them.
var smallOrderY = [5][32]byte{
	{0: 0x00}, // y = 0
	{0: 0x01}, // y = 1
	{ // y = p - 1
		0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
	{ // order 8
		0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0,
		0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05},
	{ // order 8
		0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f,
		0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a},
}

// strictPoint reports whether b is a 32-byte encoding whose y is below p
// and which is not of small order (steps 1 and 2). It does not decide
// whether b is on the curve: ed25519.Verify refuses an undecodable key or
// R.
func strictPoint(b []byte) bool {
	var y [32]byte
	copy(y[:], b)
	y[31] &= 0x7f
	if !lessLE(y[:], fieldP[:]) {
		return false
	}
	for i := range smallOrderY {
		if eq(y[:], smallOrderY[i][:]) {
			return false
		}
	}
	return true
}

// lessLE reports a < b for little-endian numbers of equal length.
func lessLE(a, b []byte) bool {
	for i := len(a) - 1; i >= 0; i-- {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// VerifyProposal checks proposal_sig over H(proposal bytes) under the
// service's identity key.
func VerifyProposal(ik, doc, sig []byte) error {
	return Verify(ik, LabelProposal, ProposalSigMsg(doc), sig)
}

// VerifyExtension checks extension_sig over proposal_hash ‖ H(extension).
func VerifyExtension(ik, proposalHash, doc, sig []byte) error {
	m, err := DocSigMsg(proposalHash, doc)
	if err != nil {
		return err
	}
	return Verify(ik, LabelExtended, m, sig)
}

// VerifyResults checks results_sig over proposal_hash ‖ H(results).
func VerifyResults(ik, proposalHash, doc, sig []byte) error {
	m, err := DocSigMsg(proposalHash, doc)
	if err != nil {
		return err
	}
	return Verify(ik, LabelResults, m, sig)
}

// VerifyReceipt checks receipt_sig over proposal_hash ‖ H(ballot_leaf) ‖
// u64(msg_ms) under the service's key.
func VerifyReceipt(ik, proposalHash, ballotLeaf []byte, msgMS uint64, sig []byte) error {
	m, err := ReceiptMsg(proposalHash, ballotLeaf, msgMS)
	if err != nil {
		return err
	}
	return Verify(ik, LabelReceipt, m, sig)
}

// VerifyStatus checks status_sig for the answer carrying ballotLeaf (nil
// for an answer without a ballot).
func VerifyStatus(ik []byte, proposalID string, recordTag, ballotLeaf, sig []byte) error {
	m, err := StatusMsg(proposalID, recordTag, ballotLeaf)
	if err != nil {
		return err
	}
	return Verify(ik, LabelStatus, m, sig)
}

// VerifyBallot checks ballot_sig under the ballot's vk for the proposal.
func VerifyBallot(proposalHash []byte, b *Ballot) error {
	m, err := BallotMsg(proposalHash, b.RecordTag, b.ChoiceID)
	if err != nil {
		return err
	}
	return Verify(b.VK, LabelBallot, m, b.BallotSig)
}

// VerifyCast checks cast_sig over proposal_hash ‖ H(ballot_leaf) under the
// credential key (the service does this; the vault does it in tests).
func VerifyCast(credentialKey, proposalHash, ballotLeaf, sig []byte) error {
	m, err := CastMsg(proposalHash, ballotLeaf)
	if err != nil {
		return err
	}
	return Verify(credentialKey, LabelCast, m, sig)
}

// VerifyServiceList checks the service list's signature under the site key
// pinned in the release (§10.19.4): Sign(site key, LabelServiceList,
// H(bytes)).
func VerifyServiceList(siteKey, doc, sig []byte) error {
	return Verify(siteKey, LabelServiceList, H(doc), sig)
}

// VerifyAnchorCert checks an anchor key's anchor_cert: Sign(service ik,
// LabelAnchorKey, H(SPKI DER)).
func VerifyAnchorCert(ik, spki, cert []byte) error {
	return Verify(ik, LabelAnchorKey, H(spki), cert)
}

// SignBallot makes the ballot for choiceID under the voting key vk: the
// ballot_msg is signed under LabelBallot (§10.19.5 step 1).
func SignBallot(vk ed25519.PrivateKey, proposalHash, recordTag []byte, choiceID string) (*Ballot, error) {
	m, err := BallotMsg(proposalHash, recordTag, choiceID)
	if err != nil {
		return nil, err
	}
	sig, err := suite.Sign(vk, LabelBallot, m)
	if err != nil {
		return nil, err
	}
	return &Ballot{
		RecordTag: append([]byte{}, recordTag...),
		VK:        append([]byte{}, vk.Public().(ed25519.PublicKey)...),
		ChoiceID:  choiceID,
		BallotSig: sig,
	}, nil
}

// SignCast signs proposal_hash ‖ H(ballot_leaf) with the credential key
// under LabelCast. The caller holds the credential key only inside its
// unlock window (§3.5.3).
func SignCast(credentialKey ed25519.PrivateKey, proposalHash, ballotLeaf []byte) ([]byte, error) {
	m, err := CastMsg(proposalHash, ballotLeaf)
	if err != nil {
		return nil, err
	}
	return suite.Sign(credentialKey, LabelCast, m)
}
