package vote

import (
	"encoding/json"
	"time"

	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/votewire"
)

// ResultsSubmit is vote.results.submit (§10.19.6): the results as the site
// serves them, their signature and bundle, and the member's own row with
// its inclusion proof to rows_root. The vault never relies on the app's
// verdict: it checks everything itself.
type ResultsSubmit struct {
	Results []byte
	Sig     []byte
	Bundle  json.RawMessage
	Row     *votewire.RowBallot // nil: an empty row
	Proof   *votewire.RecordProof
}

// CheckOutcome is the state of the results check: pending (also when the
// check cannot be made yet, with a reason), verified, unconfirmed, failed
// (with its reason) or gave_up.
type CheckOutcome struct{ State, Reason string }

// tickCheck marks the results check pending when it is due and gives up
// seven days after (§10.19.6).
func (f *Feature) tickCheck(s *vault.Session, r *record, now time.Time) {
	if r.RejectReason != "" || r.Reason != "" || r.Restore || !r.closed(now) {
		return
	}
	if r.Check == "" && !now.Before(r.dueAt()) {
		r.Check = CheckPending
		r.ChangedMS = now.UnixMilli()
		if !r.CheckDueSent {
			r.CheckDueSent = true
			f.event(s, r, "check_due")
		}
	}
	if r.Check == CheckPending && now.Sub(r.dueAt()) >= CheckGiveUp {
		r.Check = CheckGaveUp
		r.ChangedMS = now.UnixMilli()
		f.audit(s, "vote.check_gave_up", r.Conn, r.ID)
		f.event(s, r, "check")
	}
}

func (f *Feature) failCheck(s *vault.Session, r *record, reason string) CheckOutcome {
	r.Check, r.CheckReason = CheckFailed, reason
	r.ChangedMS = s.Now().UnixMilli()
	f.audit(s, "vote.check_failed", r.Conn, r.ID+":"+reason)
	f.feed(s, "vote.problem", r.Conn, r.ID, "high")
	f.event(s, r, "check")
	return CheckOutcome{State: CheckFailed, Reason: reason}
}

func sameBallot(b *ballot, row *votewire.RowBallot) bool {
	return row != nil && eq(row.VK, b.VK) && row.ChoiceID == b.ChoiceID && eq(row.BallotSig, b.BallotSig)
}

// verdict is the table of §10.19.6 step 3: what the vault holds against
// the member's row.
func verdict(r *record, row *votewire.RowBallot) (state, reason string) {
	b := r.Ballot
	switch {
	case b != nil && b.State == BallotConflict:
		return CheckFailed, "conflict"
	case b != nil && b.State == BallotDisputed:
		return CheckFailed, "disputed"
	case b != nil && b.State == BallotRecorded: // a receipt: exactly that ballot
		if sameBallot(b, row) {
			return CheckVerified, ""
		}
		return CheckFailed, "row_mismatch"
	case b == nil:
		if row == nil {
			return CheckVerified, ""
		}
		if sb := r.ServiceBallot; sb != nil && eq(row.VK, sb.VK) && row.ChoiceID == sb.ChoiceID && eq(row.BallotSig, sb.BallotSig) {
			return CheckUnconfirmed, "" // the member has not yet answered vote.confirm
		}
		return CheckFailed, "row_unexpected"
	case b.State == BallotRefused && b.Code != "connection_ended": // only a verified refusal
		if row == nil || sameBallot(b, row) {
			return CheckVerified, ""
		}
		return CheckFailed, "row_mismatch"
	}
	return CheckUnconfirmed, "" // a ballot with neither receipt nor refusal: the row may carry it or not
}

// SubmitResults is vote.results.submit (§10.19.6 steps 2 to 4): the
// strict results document and its signature, the bundle, that the proposal
// and the extensions in it are the ones the vault holds, `tally` and
// `counts.eligible`, and the row against the table. A check that cannot be
// made yet (the list does not name the key, the roots are out of date, the
// clock) stays pending with the reason; a check already final is answered
// with its state.
func (f *Feature) SubmitResults(s *vault.Session, conn, id string, in ResultsSubmit) (CheckOutcome, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.get(conn, id)
	if r == nil || r.RejectReason != "" {
		return CheckOutcome{}, errNotFound
	}
	now := s.Now()
	switch r.Check {
	case CheckVerified, CheckUnconfirmed, CheckFailed, CheckGaveUp:
		return CheckOutcome{State: r.Check, Reason: r.CheckReason}, nil
	}
	if r.checkingReason() != "" || !r.closed(now) {
		return CheckOutcome{}, errBad
	}
	p, err := votewire.ParseProposal(r.Proposal)
	if err != nil {
		return CheckOutcome{}, errBad
	}
	res, err := votewire.ParseResults(in.Results)
	if err != nil || votewire.VerifyResults(r.Signer, r.Hash, in.Results, in.Sig) != nil {
		return f.failCheck(s, r, "results"), nil
	}
	switch f.anchor(s, conn, r.signers(), in.Results, in.Bundle, time.Time{}) {
	case anchorOK:
	case anchorRejected, anchorLate:
		return f.failCheck(s, r, "anchor"), nil
	case anchorServiceList:
		return CheckOutcome{State: CheckPending, Reason: ReasonServiceList}, nil
	case anchorClock:
		return CheckOutcome{State: CheckPending, Reason: ReasonClock}, nil
	default:
		return CheckOutcome{State: CheckPending, Reason: ReasonTrustRoot}, nil
	}
	// The proposal in the results is, byte for byte, the one held with its
	// signature; the extensions are the ones held, in order.
	if !eq(res.Proposal.Doc, r.Proposal) || !eq(res.Proposal.Sig, r.ProposalSig) || len(res.Extensions) < len(r.Exts) {
		return f.failCheck(s, r, "results"), nil
	}
	for i, e := range r.Exts {
		if !eq(res.Extensions[i].Doc, e.Doc) || !eq(res.Extensions[i].Sig, e.Sig) {
			return f.failCheck(s, r, "results"), nil
		}
	}
	// An extension in the results that the vault lacks is checked as in
	// vote.extended (the results carry no bundle for it) and adopted.
	var adopt []*extRec
	closes := r.Closes
	for i := len(r.Exts); i < len(res.Extensions); i++ {
		x := res.Extensions[i]
		ext, err := votewire.ParseExtension(x.Doc)
		if err != nil || ext.ProposalID != r.ID || ext.N != int64(i+1) || votewire.VerifyExtension(r.Signer, r.Hash, x.Doc, x.Sig) != nil ||
			ext.ClosesAt <= closes || !ext.OrderOK(p.OpensAt, closes) || ext.ClosesAt-r.OrigClose > votewire.MaxExtension {
			return f.failCheck(s, r, "results"), nil
		}
		adopt = append(adopt, &extRec{N: ext.N, Doc: x.Doc, Sig: x.Sig, Closes: ext.ClosesAt})
		closes = ext.ClosesAt
	}
	if res.CheckProposal(p) != nil {
		return f.failCheck(s, r, "results"), nil
	}
	// The row: tree_size equal to counts.eligible and to the record proof's,
	// row_proof.index equal to the record proof's, and the proof to rows_root.
	if in.Proof == nil || r.Proof == nil || in.Proof.TreeSize != uint64(res.Counts.Eligible) || in.Proof.TreeSize != r.Proof.TreeSize ||
		in.Proof.Index != r.Proof.Index || len(in.Proof.Path) > votewire.MaxRecordPath {
		return f.failCheck(s, r, "results"), nil
	}
	var leaf []byte
	if in.Row == nil {
		leaf, err = votewire.EmptyRowLeaf(r.Tag)
	} else {
		rb := &votewire.Ballot{RecordTag: r.Tag, VK: in.Row.VK, ChoiceID: in.Row.ChoiceID, BallotSig: in.Row.BallotSig}
		if !p.HasChoice(in.Row.ChoiceID) || votewire.VerifyBallot(r.Hash, rb) != nil {
			return f.failCheck(s, r, "results"), nil
		}
		leaf, err = rb.Leaf()
	}
	if err != nil || !votewire.VerifyProof(res.RowsRoot, leaf, in.Proof.Index, in.Proof.TreeSize, in.Proof.Path) {
		return f.failCheck(s, r, "results"), nil
	}
	r.Exts = append(r.Exts, adopt...)
	if len(adopt) > 0 {
		r.Closes = closes
	}
	// The vault keeps the results with its row; vote.closed's hash against
	// them is evidence only.
	rs := &results{Doc: in.Results, Sig: in.Sig, Bundle: in.Bundle, AtMS: now.UnixMilli(), Proof: &proof{Index: in.Proof.Index, TreeSize: in.Proof.TreeSize, Path: in.Proof.Path}}
	if in.Row != nil {
		rs.Row = &svcBallot{VK: in.Row.VK, ChoiceID: in.Row.ChoiceID, BallotSig: in.Row.BallotSig}
	}
	r.Results = rs
	if r.ResultsHash != nil {
		r.ResultsMatch = "no"
		if eq(r.ResultsHash, votewire.H(in.Results)) {
			r.ResultsMatch = "yes"
		}
	}
	state, reason := verdict(r, in.Row)
	if state == CheckFailed {
		return f.failCheck(s, r, reason), nil
	}
	r.Check, r.CheckReason, r.ChangedMS = state, "", now.UnixMilli()
	if state == CheckVerified {
		f.audit(s, "vote.check_ok", r.Conn, r.ID)
	} else {
		f.audit(s, "vote.check_unconfirmed", r.Conn, r.ID)
	}
	f.feed(s, "vote.result", r.Conn, r.ID, "")
	f.event(s, r, "check")
	return CheckOutcome{State: state}, nil
}
