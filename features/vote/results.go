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
	// Others are the other rows of rows.json under the member's tag, with
	// their proofs (at most MaxOtherRows); RowsUnavailable says the app
	// could not get the member's row (then there is no row, proof or
	// Others).
	Others          []OtherRow
	RowsUnavailable bool
}

// MaxOtherRows bounds other_rows of vote.results.submit (0.83.3).
const MaxOtherRows = 4

// OtherRow is an entry of other_rows: a row of any choice id (or an empty
// one) and its proof. Bad is an entry whose members do not decode (base64,
// types): input that does not verify, not a bad request.
type OtherRow struct {
	Empty     bool // {ballot: null}
	VK        []byte
	ChoiceID  string
	BallotSig []byte
	Proof     *votewire.RecordProof
	Bad       bool
}

// CheckOutcome is the state of the results check: pending (also when the
// check cannot be made yet, with a reason), verified, unconfirmed, failed
// (with its reason) or gave_up.
type CheckOutcome struct {
	State, Reason string
	// ConflictEvidence: the service showed a ballot under the member's code
	// that is not the member's (carried beside a `verified` state).
	ConflictEvidence bool
}

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
		// The reason rows_unavailable carries over (0.83.3).
		r.Check = CheckGaveUp
		r.ChangedMS = now.UnixMilli()
		f.audit(s, "vote.check_gave_up", r.Conn, r.ID)
		// One normal item; the app says the check runs again by itself
		// and asks nothing of the member (0.83.6).
		f.feed(s, "vote.result", r.Conn, r.ID, "")
		f.event(s, r, "check")
	}
}

func (f *Feature) failCheck(s *vault.Session, r *record, reason string) CheckOutcome {
	r.Check, r.CheckReason = CheckFailed, reason
	r.ChangedMS = s.Now().UnixMilli()
	f.audit(s, "vote.check_failed", r.Conn, r.ID+":"+reason)
	f.feed(s, "vote.problem", r.Conn, r.ID, "high")
	f.event(s, r, "check")
	return CheckOutcome{State: CheckFailed, Reason: reason, ConflictEvidence: r.conflictEvidence()}
}

func sameBallot(b *ballot, row *votewire.RowBallot) bool {
	return row != nil && eq(row.VK, b.VK) && row.ChoiceID == b.ChoiceID && eq(row.BallotSig, b.BallotSig)
}

// conflictEvidence reports whether the service showed a ballot under the
// member's code that is not the member's.
func (r *record) conflictEvidence() bool {
	return r.ConflictEv || r.Ballot != nil && r.Ballot.State == BallotConflict
}

// conflictVerdict is what the results check says of a record with conflict
// evidence or a disputed ballot, in one place (0.81.3, owner decision
// 2026-10-30): a ballot with a receipt (`recorded`) whose row is exactly that
// ballot is `verified` with the flag conflict_evidence beside it (the
// record stays in the problem set); another row is `failed` (`row_mismatch`); a ballot
// in `conflict`, none, or one without a receipt, with conflict evidence, is
// `failed` (`conflict`).
func conflictVerdict(r *record, row *votewire.RowBallot) (state, reason string, ok bool) {
	b := r.Ballot
	switch {
	case b != nil && b.State == BallotConflict:
		return CheckFailed, "conflict", true
	case r.ConflictEv:
		if b != nil && b.State == BallotRecorded {
			if sameBallot(b, row) {
				return CheckVerified, "", true
			}
			return CheckFailed, "row_mismatch", true
		}
		return CheckFailed, "conflict", true
	case b != nil && b.State == BallotDisputed:
		return CheckFailed, "disputed", true
	}
	return "", "", false
}

// verdict is the table of §10.19.6 step 3: what the vault holds against
// the member's row.
func verdict(r *record, row *votewire.RowBallot) (state, reason string) {
	b := r.Ballot
	if st, why, ok := conflictVerdict(r, row); ok {
		return st, why
	}
	switch {
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
// clock) stays pending with the reason; input that does not verify (the
// signature, the bundle, the row's proof to the signed rows_root) is no
// answer, also pending (reason "input"), and a later correct submission is
// judged; a check already final is answered
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
	case CheckVerified, CheckUnconfirmed, CheckFailed:
		return CheckOutcome{State: r.Check, Reason: r.CheckReason, ConflictEvidence: r.conflictEvidence()}, nil
	}
	// A gave_up check is not final (0.83.6): a later submission is judged
	// as for a pending one, and one that is no answer leaves it gave_up.
	unsettled := CheckPending
	if r.Check == CheckGaveUp {
		unsettled = CheckGaveUp
	}
	if r.checkingReason() != "" || !r.closed(now) {
		return CheckOutcome{}, errBad
	}
	p, err := votewire.ParseProposal(r.Proposal)
	if err != nil {
		return CheckOutcome{}, errBad
	}
	// What does not verify is no answer: the check stays pending and a later
	// correct submission is judged. Only a contradiction under the service's
	// signature and a verified anchor fails the check.
	noAnswer := CheckOutcome{State: unsettled, Reason: "input"}
	res, err := votewire.ParseResults(in.Results)
	if err != nil || votewire.VerifyResults(r.Signer, r.Hash, in.Results, in.Sig) != nil {
		return noAnswer, nil
	}
	switch f.anchor(s, conn, r.signers(), in.Results, in.Bundle, time.Time{}) {
	case anchorOK:
	case anchorServiceList:
		return CheckOutcome{State: unsettled, Reason: ReasonServiceList}, nil
	case anchorClock:
		return CheckOutcome{State: unsettled, Reason: ReasonClock}, nil
	case anchorTrustRoot:
		return CheckOutcome{State: unsettled, Reason: ReasonTrustRoot}, nil
	default: // a bundle that does not hold for these results
		return noAnswer, nil
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
	if res.CheckProposal(p) != nil || r.Proof == nil || res.Counts.Eligible != int64(r.Proof.TreeSize) {
		return f.failCheck(s, r, "results"), nil
	}
	if in.RowsUnavailable {
		// The app could not get the member's row (0.83.3). The results are
		// verified; the vault cannot check the claim, so the check waits:
		// pending with the reason (a gave_up one stays gave_up), and one
		// vote.problem for the record.
		r.Exts = append(r.Exts, adopt...)
		if len(adopt) > 0 {
			r.Closes = closes
			r.ChangedMS = now.UnixMilli() // an earlier evidence export is no longer current
		}
		return f.rowsUnavailable(s, r, now), nil
	}
	// The row. The proof must verify to the signed rows_root before the row
	// is judged; one that does not is no answer. A proof that verifies at
	// another index or tree size than the record proof's is the service's
	// own contradiction.
	// The tree size is the signed counts.eligible (equal to the record
	// proof's, checked above); a proof submitted for another size is the
	// app's mistake, not evidence.
	if in.Proof == nil || len(in.Proof.Path) > votewire.MaxRecordPath || in.Proof.TreeSize != uint64(res.Counts.Eligible) {
		return noAnswer, nil
	}
	var leaf []byte
	var rb *votewire.Ballot
	if in.Row == nil {
		leaf, err = votewire.EmptyRowLeaf(r.Tag)
	} else {
		rb = &votewire.Ballot{RecordTag: r.Tag, VK: in.Row.VK, ChoiceID: in.Row.ChoiceID, BallotSig: in.Row.BallotSig}
		leaf, err = rb.Leaf()
	}
	if err != nil || !votewire.VerifyProof(res.RowsRoot, leaf, in.Proof.Index, in.Proof.TreeSize, in.Proof.Path) {
		return noAnswer, nil
	}
	// Extra rows (0.83.3): a second row under the member's tag that
	// verifies to the signed rows_root at another index is a signed
	// contradiction, whatever its choice id, and takes precedence over
	// every other row outcome. An entry that does not verify, repeats an
	// index or sits at the main row's index is input that does not verify.
	dups, badInput := f.judgeOthers(r, in, res.RowsRoot)
	if len(dups) == 0 && badInput {
		return noAnswer, nil
	}
	rs := &results{Doc: in.Results, Sig: in.Sig, Bundle: in.Bundle, AtMS: now.UnixMilli(), Proof: &proof{Index: in.Proof.Index, TreeSize: in.Proof.TreeSize, Path: in.Proof.Path}, Others: dups}
	if in.Row != nil {
		rs.Row = &svcBallot{VK: in.Row.VK, ChoiceID: in.Row.ChoiceID, BallotSig: in.Row.BallotSig}
	}
	if len(dups) > 0 {
		r.Exts = append(r.Exts, adopt...)
		if len(adopt) > 0 {
			r.Closes = closes
		}
		r.Results = rs
		r.setResultsMatch(in.Results)
		return f.failCheck(s, r, "row_duplicate"), nil
	}
	if in.Proof.Index != r.Proof.Index {
		return f.failCheck(s, r, "results"), nil // the member's row is not at the member's index
	}
	if rb != nil && (!p.HasChoice(rb.ChoiceID) || votewire.VerifyBallot(r.Hash, rb) != nil) {
		return f.failCheck(s, r, "results"), nil // the service published an invalid ballot under the member's code
	}
	r.Exts = append(r.Exts, adopt...)
	if len(adopt) > 0 {
		r.Closes = closes
	}
	// The vault keeps the results with its row; vote.closed's hash against
	// them is evidence only.
	r.Results = rs
	r.setResultsMatch(in.Results)
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
	return CheckOutcome{State: state, ConflictEvidence: r.conflictEvidence()}, nil
}

// judgeOthers sorts the entries of other_rows: dups are the rows that
// verify to rowsRoot at an index other than the main row's, each index
// once, as they are kept and shown in vote.evidence; badInput says some
// entry is input that does not verify.
func (f *Feature) judgeOthers(r *record, in ResultsSubmit, rowsRoot []byte) (dups []*otherRow, badInput bool) {
	seen := map[uint64]bool{in.Proof.Index: true}
	for _, e := range in.Others {
		if e.Bad || e.Proof == nil || len(e.Proof.Path) > votewire.MaxRecordPath || e.Proof.TreeSize != in.Proof.TreeSize || seen[e.Proof.Index] {
			badInput = true
			continue
		}
		var leaf []byte
		var err error
		if e.Empty {
			leaf, err = votewire.EmptyRowLeaf(r.Tag)
		} else {
			leaf, err = votewire.RowLeaf(r.Tag, e.VK, e.ChoiceID, e.BallotSig)
		}
		if err != nil || !votewire.VerifyProof(rowsRoot, leaf, e.Proof.Index, e.Proof.TreeSize, e.Proof.Path) {
			badInput = true
			continue
		}
		seen[e.Proof.Index] = true
		o := &otherRow{Proof: &proof{Index: e.Proof.Index, TreeSize: e.Proof.TreeSize, Path: e.Proof.Path}}
		if !e.Empty {
			o.Row = &svcBallot{VK: e.VK, ChoiceID: e.ChoiceID, BallotSig: e.BallotSig}
		}
		dups = append(dups, o)
	}
	return dups, badInput
}

// rowsUnavailable records a submission of which the app says it could not
// get the member's row (0.83.3): the check stays pending (a gave_up one
// stays gave_up) with the reason rows_unavailable, and the member is told
// once per record.
func (f *Feature) rowsUnavailable(s *vault.Session, r *record, now time.Time) CheckOutcome {
	if r.Check == "" {
		r.Check = CheckPending
	}
	if r.CheckReason != CheckRowsUnavailable {
		r.CheckReason = CheckRowsUnavailable
		r.ChangedMS = now.UnixMilli()
	}
	if !r.RowsProblem {
		r.RowsProblem = true
		r.ChangedMS = now.UnixMilli()
		f.feed(s, "vote.problem", r.Conn, r.ID, "high")
		f.event(s, r, "problem")
	}
	return CheckOutcome{State: r.Check, Reason: CheckRowsUnavailable, ConflictEvidence: r.conflictEvidence()}
}

// setResultsMatch compares vote.closed's hash with the results (evidence only).
func (r *record) setResultsMatch(doc []byte) {
	if r.ResultsHash != nil {
		r.ResultsMatch = "no"
		if eq(r.ResultsHash, votewire.H(doc)) {
			r.ResultsMatch = "yes"
		}
	}
}
