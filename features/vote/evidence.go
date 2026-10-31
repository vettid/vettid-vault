package vote

import (
	"encoding/base64"
	"encoding/json"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/suite"
	"github.com/vettid/vettid-vault/vms/votewire"
)

// vote.evidence and vote.release (VAULT-MESSAGING 0.81.2 §10.19.6 step 5,
// §10.19.2).

func ballotEvidence(vk []byte, choice string, sig []byte, msgMS int64, receipt []byte) []byte {
	b := strictjson.NewBuilder().Base64("vk", vk).String("choice_id", choice).Base64("ballot_sig", sig)
	if len(receipt) > 0 {
		b.Uint("msg_ms", uint64(msgMS)).Base64("receipt_sig", receipt)
	}
	return b.Bytes()
}

func arrOfB64(list [][]byte) []byte {
	arr := []byte{'['}
	for i, x := range list {
		if i > 0 {
			arr = append(arr, ',')
		}
		arr = append(arr, strictjson.MarshalString(base64Std(x))...)
	}
	return append(arr, ']')
}

func svcBallotJSON(sb *svcBallot) []byte {
	return ballotEvidence(sb.VK, sb.ChoiceID, sb.BallotSig, sb.MsgMS, sb.ReceiptSig)
}

func evidenceCopy(e *evidence) []byte {
	b := strictjson.NewBuilder().Base64("proposal", e.Proposal)
	if len(e.Sig) > 0 {
		b.Base64("proposal_sig", e.Sig)
	}
	if len(e.Bundle) > 0 {
		b.Raw("bundle", e.Bundle)
	}
	return b.Bytes()
}

// evidenceFor is what a member can show the organisation or an auditor, the
// exact signed bytes as base64: for a record held, everything it holds; for
// one evicted clean or released, its compact record (with evicted or
// released true).
func (f *Feature) evidenceFor(s *vault.Session, conn, id string) ([]byte, bool) {
	if r := f.get(conn, id); r != nil {
		return f.recordEvidence(s, r), true
	}
	for _, c := range f.st.Compact[conn] {
		if c.ID == id {
			return compactEvidence(c), true
		}
	}
	return nil, false
}

func (f *Feature) recordEvidence(s *vault.Session, r *record) []byte {
	now := s.Now()
	e := strictjson.NewBuilder().String("connection_id", r.Conn).String("proposal_id", r.ID).String("state", r.state(now)).
		Base64("ik", r.ServiceIK).Base64("proposal_hash", r.Hash).Base64("record_tag", r.Tag)
	if r.RejectReason != "" {
		e.String("reason", r.RejectReason)
	}
	if r.Site != "" {
		e.String("site", r.Site)
	}
	e.Base64("proposal", r.Proposal).Base64("proposal_sig", r.ProposalSig)
	if len(r.Bundle) > 0 {
		e.Raw("bundle", r.Bundle)
	}
	if r.Proof != nil {
		e.Raw("record_proof", (&votewire.RecordProof{Index: r.Proof.Index, TreeSize: r.Proof.TreeSize, Path: r.Proof.Path}).JSON())
	}
	ex := []byte{'['}
	for i, x := range r.Exts {
		if i > 0 {
			ex = append(ex, ',')
		}
		xb := strictjson.NewBuilder().Base64("extension", x.Doc).Base64("extension_sig", x.Sig)
		if len(x.Bundle) > 0 {
			xb.Raw("bundle", x.Bundle)
		}
		ex = append(ex, xb.Bytes()...)
	}
	e.Raw("extensions", append(ex, ']'))
	if b := r.Ballot; b != nil {
		bb := strictjson.NewBuilder().String("state", b.State).Raw("ballot", ballotEvidence(b.VK, b.ChoiceID, b.BallotSig, b.MsgMS, b.ReceiptSig))
		if b.Code != "" {
			bb.String("code", b.Code)
		}
		e.Raw("member", bb.Bytes())
		e.Raw("refusals", arrOfB64(b.Refusals))
	}
	e.Raw("status_answers", arrOfB64(r.StatusAnswers))
	if r.Other != nil {
		e.Raw("other_ballot", svcBallotJSON(r.Other))
	}
	if r.OtherLatest != nil {
		e.Raw("other_ballot_latest", svcBallotJSON(r.OtherLatest))
	}
	if r.ServiceBallot != nil {
		e.Raw("service_ballot", svcBallotJSON(r.ServiceBallot))
	}
	if r.Conflict != nil {
		e.Raw("conflicting_proposal", evidenceCopy(r.Conflict))
	}
	if r.SiteCopy != nil {
		e.Raw("site_copy", evidenceCopy(r.SiteCopy))
	}
	if rs := r.Results; rs != nil {
		rb := strictjson.NewBuilder().Base64("results", rs.Doc).Base64("results_sig", rs.Sig)
		if len(rs.Bundle) > 0 {
			rb.Raw("bundle", rs.Bundle)
		}
		if rs.Row != nil {
			rb.Raw("row", strictjson.NewBuilder().Raw("ballot", strictjson.NewBuilder().Base64("vk", rs.Row.VK).String("choice_id", rs.Row.ChoiceID).Base64("ballot_sig", rs.Row.BallotSig).Bytes()).Bytes())
		} else {
			rb.Raw("row", []byte(`{"ballot":null}`))
		}
		if rs.Proof != nil {
			rb.Raw("row_proof", (&votewire.RecordProof{Index: rs.Proof.Index, TreeSize: rs.Proof.TreeSize, Path: rs.Proof.Path}).JSON())
		}
		e.Raw("results", rb.Bytes())
	}
	if r.Check != "" {
		c := strictjson.NewBuilder().String("state", r.Check)
		if r.CheckReason != "" {
			c.String("reason", r.CheckReason)
		}
		e.Raw("check", c.Bytes())
	}
	if len(r.ResultsHash) > 0 {
		e.Base64("results_hash", r.ResultsHash)
	}
	return e.Bytes()
}

func compactEvidence(c *compact) []byte {
	e := strictjson.NewBuilder().String("connection_id", c.Conn).String("proposal_id", c.ID)
	if c.Released {
		e.Bool("released", true)
	} else {
		e.Bool("evicted", true)
	}
	e.Base64("ik", c.ServiceIK).Base64("proposal_hash", c.Hash).Base64("record_tag", c.Tag).String("outcome", c.Outcome)
	if len(c.BallotSig) > 0 {
		e.Raw("ballot", ballotEvidence(c.VK, c.ChoiceID, c.BallotSig, c.MsgMS, c.ReceiptSig))
	}
	e.Raw("refusals", arrOfB64(c.Refusals))
	if c.Released {
		if c.RejectReason != "" {
			e.String("reason", c.RejectReason)
		}
		if c.Site != "" {
			e.String("site", c.Site)
		}
		if len(c.Proposal) > 0 {
			e.Base64("proposal", c.Proposal).Base64("proposal_sig", c.ProposalSig)
			if len(c.Bundle) > 0 {
				e.Raw("bundle", c.Bundle)
			}
		}
		if c.SiteCopy != nil {
			e.Raw("site_copy", evidenceCopy(c.SiteCopy))
		}
		e.Raw("status_answers", arrOfB64(c.StatusAnswers))
		if c.Other != nil {
			e.Raw("other_ballot", svcBallotJSON(c.Other))
		}
	}
	return e.Bytes()
}

func (f *Feature) apiEvidence(s *vault.Session, body []byte) (json.RawMessage, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	conn, id, err := pair(o)
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	ev, ok := f.evidenceFor(s, conn, id)
	if !ok {
		return nil, errNotFound
	}
	if r := f.get(conn, id); r != nil {
		// What was exported, and when: vote.release needs the record unchanged
		// since.
		r.EvidenceHash, r.EvidenceMS = r.digest(), s.Now().UnixMilli()
	}
	return strictjson.NewBuilder().Raw("evidence", ev).Bytes(), nil
}

// apiRelease is vote.release (§10.19.2): a problem record whose proposal is
// closed or rejected, exported after its last change, goes to its compact
// record, which stops counting toward the cap of 16. The order is
// audit.export's: the UTK spent and the holder, the payload, not_found and
// the record's state, the PIN backoff, the PIN.
func (f *Feature) apiRelease(s *vault.Session, in *envelope.Inner) (json.RawMessage, error) {
	if f.dep.Cred == nil {
		return nil, vault.NewError("forbidden", "")
	}
	if err := f.dep.Cred.HolderGate(s, in); err != nil {
		return nil, err
	}
	o, err := strictjson.ParseObject(in.Body)
	if err != nil {
		return nil, errBad
	}
	utkID, err := o.String("utk_id")
	if err != nil || utkID == "" || len(utkID) > 64 {
		return nil, errBad
	}
	sealedS, err := o.String("sealed")
	if err != nil || len(sealedS) > 64*1024 {
		return nil, errBad
	}
	sealed, err := strictjson.DecodeStd(sealedS, -1)
	if err != nil {
		return nil, errBad
	}
	pin, err := f.dep.Cred.SpendPIN(s, in, utkID, sealed)
	if err != nil {
		return nil, err
	}
	defer suite.Wipe(pin)
	conn, id, err := pair(o)
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.get(conn, id)
	if r == nil {
		return nil, errNotFound
	}
	now := s.Now()
	if st := r.state(now); !r.problem() || st != StateClosed && st != StateRejected {
		return nil, errBad
	}
	if len(r.EvidenceHash) == 0 || !eq(r.EvidenceHash, r.digest()) {
		return nil, vault.NewError("evidence_not_exported", "")
	}
	if err := s.VerifyPIN(string(pin)); err != nil {
		return nil, err
	}
	f.st.Compact[conn] = append(f.st.Compact[conn], r.release())
	delete(f.st.Records, key(conn, id))
	problems := 0
	for _, x := range f.st.Records {
		if x.Conn == conn && x.problem() {
			problems++
		}
	}
	if problems < votewire.MaxProblemsPerConnection {
		delete(f.st.Problems, conn) // the notice stays until a record is released
	}
	f.audit(s, "vote.released", conn, id)
	return json.RawMessage(`{}`), nil
}

func base64Std(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
