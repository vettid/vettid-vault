package votewire

import (
	"encoding/json"

	"github.com/vettid/vettid-vault/internal/strictjson"
)

// The bodies of the vote messages (VAULT-MESSAGING §6.4 "Votes"; BALLOT-
// PROTOCOL §4). `_sig` members are the standard base64 of 64 bytes,
// `record_secret`, `record_tag`, `results_hash` and `connection` of 32
// bytes, `vk` of 32 bytes, `proposal` and `extension` the base64 of the
// document's exact JCS bytes, `bundle` a Sigstore bundle as a JSON object,
// `msg_ms` a JSON integer. A body is parsed strictly (VAULT-MESSAGING
// §5.3: valid UTF-8, no duplicate names); members the section does not
// name are ignored.

// RecordProof is `record_proof`: {index, tree_size, path} (§8.5), the audit
// path of the member's tag in `record_root`.
type RecordProof struct {
	Index    uint64
	TreeSize uint64
	Path     [][]byte
}

func parseRecordProof(raw json.RawMessage) (*RecordProof, error) {
	o, err := strictjson.AsObject(raw)
	if err != nil {
		return nil, ErrBody
	}
	idx, err := o.Uint("index", 0, strictjson.MaxSafeInteger)
	if err != nil {
		return nil, ErrBody
	}
	size, err := o.Uint("tree_size", 1, strictjson.MaxSafeInteger)
	if err != nil {
		return nil, ErrBody
	}
	arr, err := o.Array("path")
	if err != nil || len(arr) > MaxRecordPath {
		return nil, ErrBody
	}
	rp := &RecordProof{Index: idx, TreeSize: size, Path: make([][]byte, 0, len(arr))}
	for _, e := range arr {
		s, err := strictjson.AsString(e)
		if err != nil {
			return nil, ErrBody
		}
		b, err := strictjson.DecodeStd(s, HashLen)
		if err != nil {
			return nil, ErrBody
		}
		rp.Path = append(rp.Path, b)
	}
	if idx >= size {
		return nil, ErrBody
	}
	return rp, nil
}

// ParseRecordProof parses a {index, tree_size, path} member as a body has it.
func ParseRecordProof(raw json.RawMessage) (*RecordProof, error) { return parseRecordProof(raw) }

// JSON returns the proof as it appears in a body.
func (r *RecordProof) JSON() []byte {
	b := strictjson.NewBuilder().Uint("index", r.Index).Uint("tree_size", r.TreeSize)
	arr := []byte{'['}
	for i, p := range r.Path {
		if i > 0 {
			arr = append(arr, ',')
		}
		arr = append(arr, strictjson.MarshalString(b64(p))...)
	}
	return b.Raw("path", append(arr, ']')).Bytes()
}

// Verify checks that tag is the leaf at Index of the tree of proposal's
// record_root: tree_size equal to `eligible`, index below it, at most 32
// path entries of 32 bytes, and the RFC 9162 §2.1.3.2 check (§10.19.4
// step 4).
func (r *RecordProof) Verify(p *Proposal, tag []byte) error {
	if p.Eligible < 1 || r.TreeSize != uint64(p.Eligible) || r.Index >= r.TreeSize || len(r.Path) > MaxRecordPath ||
		len(tag) != HashLen || !VerifyProof(p.RecordRoot, tag, r.Index, r.TreeSize, r.Path) {
		return ErrProof
	}
	return nil
}

// bundleOf reads a required or optional `bundle`: a JSON object of at most
// 65,536 bytes, kept as received.
func bundleOf(o strictjson.Object, required bool) (json.RawMessage, error) {
	raw, ok := o["bundle"]
	if !ok {
		if required {
			return nil, ErrBody
		}
		return nil, nil
	}
	if len(raw) > MaxBundle {
		return nil, ErrBody
	}
	if _, err := strictjson.AsObject(raw); err != nil {
		return nil, ErrBody
	}
	return append(json.RawMessage{}, raw...), nil
}

func proposalIDOf(o strictjson.Object) (string, error) {
	id, err := o.String("proposal_id")
	if err != nil || !ValidProposalID(id) {
		return "", ErrBody
	}
	return id, nil
}

// docOf reads a document member: base64 of at most max bytes.
func docOf(o strictjson.Object, name string, max int) ([]byte, error) {
	d, err := o.Base64(name, -1)
	if err != nil || len(d) == 0 || len(d) > max {
		return nil, ErrBody
	}
	return d, nil
}

// ProposalMsg is a vote.proposal body: {proposal, proposal_sig, bundle,
// record_secret, record_proof}.
type ProposalMsg struct {
	Proposal     []byte
	ProposalSig  []byte
	Bundle       json.RawMessage
	RecordSecret []byte
	RecordProof  *RecordProof
}

// ParseProposalMsg parses a vote.proposal body of at most 196,608 bytes
// (§10.19.4 step 1). The document itself is not parsed here: ParseProposal
// does that, so that a bad document and a bad body are told apart.
func ParseProposalMsg(body []byte) (*ProposalMsg, error) {
	if len(body) > MaxBody {
		return nil, ErrBody
	}
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, ErrBody
	}
	m := &ProposalMsg{}
	if m.Proposal, err = docOf(o, "proposal", MaxProposal); err != nil {
		return nil, err
	}
	if m.ProposalSig, err = o.Base64("proposal_sig", SigLen); err != nil {
		return nil, ErrBody
	}
	if m.Bundle, err = bundleOf(o, true); err != nil {
		return nil, err
	}
	if m.RecordSecret, err = o.Base64("record_secret", SecretLen); err != nil {
		return nil, ErrBody
	}
	raw, ok := o["record_proof"]
	if !ok {
		return nil, ErrBody
	}
	if m.RecordProof, err = parseRecordProof(raw); err != nil {
		return nil, err
	}
	return m, nil
}

// Marshal returns the body (the service's side; used by tests).
func (m *ProposalMsg) Marshal() []byte {
	return strictjson.NewBuilder().Base64("proposal", m.Proposal).Base64("proposal_sig", m.ProposalSig).
		Raw("bundle", m.Bundle).Base64("record_secret", m.RecordSecret).Raw("record_proof", m.RecordProof.JSON()).Bytes()
}

// ExtendedMsg is a vote.extended body: {proposal_id, extension,
// extension_sig, bundle}.
type ExtendedMsg struct {
	ProposalID   string
	Extension    []byte
	ExtensionSig []byte
	Bundle       json.RawMessage
}

// ParseExtendedMsg parses a vote.extended body.
func ParseExtendedMsg(body []byte) (*ExtendedMsg, error) {
	if len(body) > MaxBody {
		return nil, ErrBody
	}
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, ErrBody
	}
	m := &ExtendedMsg{}
	if m.ProposalID, err = proposalIDOf(o); err != nil {
		return nil, err
	}
	if m.Extension, err = docOf(o, "extension", MaxProposal); err != nil {
		return nil, err
	}
	if m.ExtensionSig, err = o.Base64("extension_sig", SigLen); err != nil {
		return nil, ErrBody
	}
	if m.Bundle, err = bundleOf(o, true); err != nil {
		return nil, err
	}
	return m, nil
}

// Marshal returns the body (the service's side; used by tests).
func (m *ExtendedMsg) Marshal() []byte {
	return strictjson.NewBuilder().String("proposal_id", m.ProposalID).Base64("extension", m.Extension).
		Base64("extension_sig", m.ExtensionSig).Raw("bundle", m.Bundle).Bytes()
}

// ClosedMsg is a vote.closed body: {proposal_id, results_hash}.
type ClosedMsg struct {
	ProposalID  string
	ResultsHash []byte
}

// ParseClosedMsg parses a vote.closed body.
func ParseClosedMsg(body []byte) (*ClosedMsg, error) {
	if len(body) > MaxBody {
		return nil, ErrBody
	}
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, ErrBody
	}
	m := &ClosedMsg{}
	if m.ProposalID, err = proposalIDOf(o); err != nil {
		return nil, err
	}
	if m.ResultsHash, err = o.Base64("results_hash", HashLen); err != nil {
		return nil, ErrBody
	}
	return m, nil
}

// Marshal returns the body (the service's side; used by tests).
func (m *ClosedMsg) Marshal() []byte {
	return strictjson.NewBuilder().String("proposal_id", m.ProposalID).Base64("results_hash", m.ResultsHash).Bytes()
}

// MarshalCast is the vote.cast body the vault sends: {proposal_id,
// record_tag, vk, choice_id, ballot_sig, cast_sig}.
func MarshalCast(proposalID string, b *Ballot, castSig []byte) ([]byte, error) {
	if !ValidProposalID(proposalID) || len(b.RecordTag) != HashLen || len(b.VK) != KeyLen || !ValidChoiceID(b.ChoiceID) ||
		len(b.BallotSig) != SigLen || len(castSig) != SigLen {
		return nil, ErrField
	}
	return strictjson.NewBuilder().String("proposal_id", proposalID).Base64("record_tag", b.RecordTag).
		Base64("vk", b.VK).String("choice_id", b.ChoiceID).Base64("ballot_sig", b.BallotSig).
		Base64("cast_sig", castSig).Bytes(), nil
}

// MarshalStatusRequest is the vote.status body the vault sends:
// {proposal_id}.
func MarshalStatusRequest(proposalID string) ([]byte, error) {
	if !ValidProposalID(proposalID) {
		return nil, ErrField
	}
	return strictjson.NewBuilder().String("proposal_id", proposalID).Bytes(), nil
}

// CastAnswer is the service's ok to vote.cast: {proposal_id, msg_ms,
// receipt_sig}.
type CastAnswer struct {
	ProposalID string
	MsgMS      uint64
	ReceiptSig []byte
}

// ParseCastAnswer parses the ok answer to vote.cast.
func ParseCastAnswer(body []byte) (*CastAnswer, error) {
	if len(body) > MaxBody {
		return nil, ErrBody
	}
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, ErrBody
	}
	a := &CastAnswer{}
	if a.ProposalID, err = proposalIDOf(o); err != nil {
		return nil, err
	}
	if a.MsgMS, err = o.Uint("msg_ms", 0, strictjson.MaxSafeInteger); err != nil {
		return nil, ErrBody
	}
	if a.ReceiptSig, err = o.Base64("receipt_sig", SigLen); err != nil {
		return nil, ErrBody
	}
	return a, nil
}

// Verify checks the receipt over the ballot this vault sent, by the
// service's key (§10.19.5). The caller then checks msg_ms against the
// voting window.
func (a *CastAnswer) Verify(ik []byte, proposalID string, proposalHash, ballotLeaf []byte) error {
	if a.ProposalID != proposalID {
		return ErrSignature
	}
	return VerifyReceipt(ik, proposalHash, ballotLeaf, a.MsgMS, a.ReceiptSig)
}

// RowBallot is `{vk, choice_id, ballot_sig}`, a ballot as an answer carries
// it.
type RowBallot struct {
	VK        []byte
	ChoiceID  string
	BallotSig []byte
}

func parseRowBallot(raw json.RawMessage) (*RowBallot, error) {
	o, err := strictjson.AsObject(raw)
	if err != nil {
		return nil, ErrBody
	}
	b := &RowBallot{}
	if b.VK, err = o.Base64("vk", KeyLen); err != nil {
		return nil, ErrBody
	}
	if b.ChoiceID, err = o.String("choice_id"); err != nil || !ValidChoiceID(b.ChoiceID) {
		return nil, ErrBody
	}
	if b.BallotSig, err = o.Base64("ballot_sig", SigLen); err != nil {
		return nil, ErrBody
	}
	return b, nil
}

// Ballot returns the ballot under tag.
func (b *RowBallot) Ballot(tag []byte) *Ballot {
	return &Ballot{RecordTag: tag, VK: b.VK, ChoiceID: b.ChoiceID, BallotSig: b.BallotSig}
}

// StatusAnswer is the ok answer to vote.status: {proposal_id, proposal,
// proposal_sig, bundle?, record_secret, record_proof, ballot?, msg_ms?,
// receipt_sig?, status_sig}. `bundle` is absent until the proposal is
// anchored; `ballot`, `msg_ms` and `receipt_sig` are present together or
// all absent.
type StatusAnswer struct {
	ProposalID   string
	Proposal     []byte
	ProposalSig  []byte
	Bundle       json.RawMessage // nil when absent
	RecordSecret []byte
	RecordProof  *RecordProof
	Ballot       *RowBallot // nil when the service holds none
	MsgMS        uint64
	ReceiptSig   []byte // nil when there is no receipt
	StatusSig    []byte
}

// ParseStatusAnswer parses an ok answer to vote.status.
func ParseStatusAnswer(body []byte) (*StatusAnswer, error) {
	if len(body) > MaxBody {
		return nil, ErrBody
	}
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, ErrBody
	}
	a := &StatusAnswer{}
	if a.ProposalID, err = proposalIDOf(o); err != nil {
		return nil, err
	}
	if a.Proposal, err = docOf(o, "proposal", MaxProposal); err != nil {
		return nil, err
	}
	if a.ProposalSig, err = o.Base64("proposal_sig", SigLen); err != nil {
		return nil, ErrBody
	}
	if a.Bundle, err = bundleOf(o, false); err != nil {
		return nil, err
	}
	if a.RecordSecret, err = o.Base64("record_secret", SecretLen); err != nil {
		return nil, ErrBody
	}
	raw, ok := o["record_proof"]
	if !ok {
		return nil, ErrBody
	}
	if a.RecordProof, err = parseRecordProof(raw); err != nil {
		return nil, err
	}
	if raw, ok := o["ballot"]; ok {
		if a.Ballot, err = parseRowBallot(raw); err != nil {
			return nil, err
		}
	}
	ms, hasMS, err := o.OptUint("msg_ms", 0, strictjson.MaxSafeInteger)
	if err != nil {
		return nil, ErrBody
	}
	a.MsgMS = ms
	if _, has := o["receipt_sig"]; has {
		if a.ReceiptSig, err = o.Base64("receipt_sig", SigLen); err != nil {
			return nil, ErrBody
		}
	}
	// A ballot, msg_ms and receipt_sig come together or not at all
	// (BALLOT-PROTOCOL 0.12.1).
	if (a.ReceiptSig != nil) != hasMS || (a.ReceiptSig != nil) != (a.Ballot != nil) {
		return nil, ErrBody
	}
	if a.StatusSig, err = o.Base64("status_sig", SigLen); err != nil {
		return nil, ErrBody
	}
	return a, nil
}

// Tag is the record tag the answer implies: H(label ‖ proposal_id ‖
// record_secret).
func (a *StatusAnswer) Tag() ([]byte, error) { return RecordTag(a.ProposalID, a.RecordSecret) }

// VerifySig checks status_sig under the service's key over the answer's own
// tag and ballot leaf (H("") when there is no ballot); when there is a
// ballot, its ballot_sig under its vk and the receipt, both for the HELD
// proposal's hash (§10.19.5). The proposal, its signature, bundle and proof
// are checked by the caller as in §10.19.4 steps 2 to 6, and the caller
// passes the hash of the proposal it holds, not the answer's.
func (a *StatusAnswer) VerifySig(ik, proposalHash []byte) error {
	tag, err := a.Tag()
	if err != nil || len(proposalHash) != HashLen {
		return ErrSignature
	}
	var leaf []byte
	if a.Ballot != nil {
		b := a.Ballot.Ballot(tag)
		if leaf, err = b.Leaf(); err != nil {
			return ErrSignature
		}
		if a.ReceiptSig == nil {
			return ErrSignature
		}
		if err := VerifyBallot(proposalHash, b); err != nil {
			return err
		}
	}
	if err := VerifyStatus(ik, a.ProposalID, tag, leaf, a.StatusSig); err != nil {
		return err
	}
	if a.Ballot != nil {
		return VerifyReceipt(ik, proposalHash, leaf, a.MsgMS, a.ReceiptSig)
	}
	return nil
}

// Refusal is the body of a refusal, an `error` response of vote.cast or
// vote.status: {refusal_sig, msg_ms, connection, record_tag} and, for
// already_voted, {ballot, ballot_msg_ms, receipt_sig}.
type Refusal struct {
	RefusalSig  []byte // nil: unsigned, which is no answer
	MsgMS       uint64
	Connection  []byte
	RecordTag   []byte // nil: empty
	Ballot      *RowBallot
	BallotMsgMS uint64
	ReceiptSig  []byte
}

// optB64 reads an optional base64 member of n bytes that may also be null
// or the empty string (the deployed service writes an empty tag as "" and
// an unsigned refusal's signature as null).
func optB64(o strictjson.Object, name string, n int) ([]byte, error) {
	raw, ok := o[name]
	if !ok || string(raw) == "null" || string(raw) == `""` {
		return nil, nil
	}
	return o.Base64(name, n)
}

// ParseRefusal parses a refusal body. A refusal without a signature parses
// with RefusalSig nil; Verify refuses it.
func ParseRefusal(body []byte) (*Refusal, error) {
	if len(body) > MaxBody {
		return nil, ErrBody
	}
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, ErrBody
	}
	r := &Refusal{}
	if r.RefusalSig, err = optB64(o, "refusal_sig", SigLen); err != nil {
		return nil, ErrBody
	}
	if r.MsgMS, err = o.Uint("msg_ms", 0, strictjson.MaxSafeInteger); err != nil {
		return nil, ErrBody
	}
	if r.Connection, err = o.Base64("connection", HashLen); err != nil {
		return nil, ErrBody
	}
	if r.RecordTag, err = optB64(o, "record_tag", HashLen); err != nil {
		return nil, ErrBody
	}
	if raw, ok := o["ballot"]; ok && string(raw) != "null" {
		if r.Ballot, err = parseRowBallot(raw); err != nil {
			return nil, err
		}
		if r.BallotMsgMS, err = o.Uint("ballot_msg_ms", 0, strictjson.MaxSafeInteger); err != nil {
			return nil, ErrBody
		}
		if r.ReceiptSig, err = o.Base64("receipt_sig", SigLen); err != nil {
			return nil, ErrBody
		}
	}
	return r, nil
}

// Verify checks that the refusal is the service's signed answer to this
// vault's request (§10.19.5): it is signed; `connection` is H of one of the
// vault's own identity keys on the connection (current or earlier);
// `record_tag` is the vault's tag or empty; and refusal_sig verifies over
// the message of BALLOT-PROTOCOL §4.2 with the request's type, the error
// code and request_hash (H(ballot_leaf) for vote.cast, H(proposal_id) for
// vote.status), by the service's key.
func (r *Refusal) Verify(ik []byte, proposalID, typ, code string, requestHash []byte, connections [][]byte, tag []byte) error {
	if r.RefusalSig == nil {
		return ErrSignature
	}
	known := false
	for _, c := range connections {
		known = known || eq(c, r.Connection)
	}
	if !known || (len(r.RecordTag) != 0 && !eq(r.RecordTag, tag)) {
		return ErrSignature
	}
	m, err := RefusalMsg(proposalID, r.Connection, r.RecordTag, typ, code, r.MsgMS, requestHash)
	if err != nil {
		return err
	}
	return Verify(ik, LabelRefusal, m, r.RefusalSig)
}

// VerifyExisting checks the ballot an already_voted refusal carries: its
// ballot_sig under its vk for the proposal and tag, and the receipt over
// its leaf at ballot_msg_ms. It returns the ballot. A refusal without a
// ballot is ErrBody.
func (r *Refusal) VerifyExisting(ik, proposalHash, tag []byte) (*Ballot, error) {
	if r.Ballot == nil || r.ReceiptSig == nil {
		return nil, ErrBody
	}
	b := r.Ballot.Ballot(tag)
	if err := VerifyBallot(proposalHash, b); err != nil {
		return nil, err
	}
	leaf, err := b.Leaf()
	if err != nil {
		return nil, err
	}
	if err := VerifyReceipt(ik, proposalHash, leaf, r.BallotMsgMS, r.ReceiptSig); err != nil {
		return nil, err
	}
	return b, nil
}
