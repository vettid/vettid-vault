//go:build vmsvectors

package vectors

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/peerwire"
)

// The §16 "approval document, document form" inputs (VAULT-MESSAGING 0.89.0, TEST ONLY).
const (
	SeedDocCredential = 0x31
	SeedDocChallenger = 0x32
	SeedDocResponder  = 0x33
	NonceDoc          = 0x34
	DocRequestID      = "01JB2Z6V9K3M4N5P6Q7R8S9T30"
	DocDocument       = `{"action":"proposal.create","payload":{"binding":true,"choices":[{"label":"Yes"},{"label":"No"}],"closes_at":1796720400,"opens_at":1796115600,"outage_rule":"Extended by a relay outage over 1 hour, 24 h at most.","quorum":{"min_ballots":10,"text":"A tenth of the members."},"removed_may_vote":false,"text":"The members adopt the 2027 budget as circulated on 2026-11-20.\nThe board reports on it quarterly.","title":"Adopt the 2027 budget"},"summary":"Adopt the 2027 budget"}`
	DocContext        = "Approve on Example Service: New vote: Adopt the 2027 budget (full text attached) — ref e8af8815891e434b"
)

// genConnAuthDocument builds connauth_document.json (VAULT-MESSAGING 0.89.0 §10.4 "Approval documents", §16): the
// approval challenge with its document (document_required), its d, m_d, the document-form signature and response,
// and the purpose-form signature of the same challenge.
func genConnAuthDocument() (obj, error) {
	ed := func(seed byte) ed25519.PrivateKey { return ed25519.NewKeyFromSeed(rep(seed, 32)) }
	pub := func(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }
	challenger, responder, cred := pub(ed(SeedDocChallenger)), pub(ed(SeedDocResponder)), ed(SeedDocCredential)
	signedAt, err := envelope.ParseTS(TS)
	if err != nil {
		return nil, err
	}
	doc := []byte(DocDocument)
	d := sha256.Sum256(doc)
	c := &peerwire.ConnAuthChallenge{RequestID: DocRequestID, Nonce: rep(NonceDoc, peerwire.ConnAuthNonceSize), Context: DocContext,
		Purpose: peerwire.PurposeApproval, Document: doc, DocumentRequired: true}
	// The receiver's checks pass on the challenge as sent.
	parsed, err := peerwire.ParseConnAuthChallenge(c.Marshal())
	if err != nil {
		return nil, err
	}
	if _, pd, req, reason := parsed.CheckDocument(); reason != "" || pd != d || !req {
		return nil, errors.New("vectors: the approval document fails the receiver's checks: " + reason)
	}
	r, err := peerwire.SignConnAuthDocument(cred, challenger, responder, c, d, signedAt, nil)
	if err != nil {
		return nil, err
	}
	if peerwire.VerifyConnAuthResponse(r, challenger, responder, c) != nil {
		return nil, errors.New("vectors: the document-form response does not verify")
	}
	purpose, err := peerwire.SignConnAuth(cred, challenger, responder, c, signedAt, nil)
	if err != nil {
		return nil, err
	}
	m := c.Message(challenger, responder)
	return obj{
		{"description", "VAULT-MESSAGING 0.89.0 §10.4 \"Approval documents\", §16 (vms/peerwire), TEST ONLY: credential key seed 32 x 0x31, challenger_ik seed 32 x 0x32, responder_ik seed 32 x 0x33, nonce 32 x 0x34. document is the bytes of JCS({action, payload, summary}); d = SHA-256(document); the context ends with the hex of d[0:8]. m is ConnAuthMessage(challenger_ik, responder_ik, nonce, request_id, context); m_d = len(purpose) (1 byte) || purpose || d || m; sig = Ed25519(credential key, label_document || m_d), and the response carries purpose and document_sha256. purpose_sig is the purpose form of the same challenge (a vault before 0.89.0): Ed25519(credential key, \"vettid/vms/2/conn-auth-purpose\" || len(purpose) || purpose || m). document_required is not signed. Bodies are the exact bytes sent."},
		{"label_document", peerwire.ConnAuthDocumentLabel},
		{"challenge_body", string(c.Marshal())},
		{"document", DocDocument},
		{"document_sha256_hex", hx(d[:])},
		{"document_sha256_b64", b64(d[:])},
		{"context", DocContext},
		{"message_document_hex", hx(peerwire.ConnAuthDocumentMessage(peerwire.PurposeApproval, d, m))},
		{"sig_b64", b64(r.Sig)},
		{"response_body", string(r.Marshal())},
		{"purpose_sig_b64", b64(purpose.Sig)},
	}, nil
}
