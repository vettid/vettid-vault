package vote

import (
	"crypto/ed25519"
	"encoding/json"
	"sort"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/credwire"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/suite"
	"github.com/vettid/vettid-vault/vms/votewire"
)

// Timers between a vault and a service are not scaled (VAULT-MESSAGING
// §10.19.2, STAGING-TIME-SCALE T4): the service and the relay count real time.
const (
	CastMargin    = 120 * time.Second // casting stops this long before the close in force
	StatusEvery   = time.Hour
	NoAnswerAfter = 24 * time.Hour
	FinalAfter    = 24 * time.Hour // a signed answer without a ballot is final this long after the close
	CheckGiveUp   = 7 * 24 * time.Hour
	CheckAskEvery = 10 * time.Minute
	pendTTL       = 25 * time.Hour // an unanswered request is forgotten (the Manager's featureReqTTL)
)

// The schedule of sending again (chosen): 1, 5 and 30 minutes after the
// first send of a round, then hourly.
var sendOffsets = []time.Duration{time.Minute, 5 * time.Minute, 30 * time.Minute}

// pendRef is a request this feature sent and awaits an answer to.
type pendRef struct {
	conn, id string // the record
	kind     string // "cast" or "status"
	want     []byte // a status request for a proposal not held: the site's bytes it must equal
	restore  bool   // the record was waiting for the answer to a restore when the request was sent
	atMS     int64
}

// errs with the codes and bodies of §10.19.5.
func codeErr(code string, body []byte) error {
	return &vault.HandlerError{Code: code, Body: body}
}

func tsBody(name string, unix int64) []byte {
	return strictjson.NewBuilder().String(name, envelope.FormatTS(time.Unix(unix, 0))).Bytes()
}

// CastResult is the answer to vote.cast: {proposal_id, ballot: {state}}.
type CastResult struct {
	ProposalID string
	State      string
}

// Body is the response body.
func (c CastResult) Body() json.RawMessage {
	return strictjson.NewBuilder().String("proposal_id", c.ProposalID).
		Raw("ballot", strictjson.NewBuilder().String("state", c.State).Bytes()).Bytes()
}

func (f *Feature) get(conn, id string) *record { return f.st.Records[key(conn, id)] }

// ballotLeaf is the leaf of the stored ballot.
func (r *record) ballotLeaf() ([]byte, error) {
	b := r.Ballot
	return (&votewire.Ballot{RecordTag: r.Tag, VK: b.VK, ChoiceID: b.ChoiceID, BallotSig: b.BallotSig}).Leaf()
}

// Cast is vote.cast (§10.19.5): the checks in their order, then the ballot
// signed, stored (the batch's flush comes before anything is sent), and
// sent after any rotation statement still owed to the connection. The
// caller (the app's request) has the credential's unlock window open or is
// refused credential_locked.
func (f *Feature) Cast(s *vault.Session, conn, id, choice string) (CastResult, error) {
	// What member authentication knows is read before this feature's lock is
	// taken (each has its own, and they are never held across each other).
	var pinned, owed []byte
	if f.dep.Auth != nil {
		pinned, owed = f.dep.Auth.SignedInKey(conn), f.dep.Auth.RotatedBody(conn)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	now := s.Now()
	r := f.get(conn, id)
	if r == nil || r.RejectReason != "" {
		return CastResult{}, errNotFound
	}
	switch r.state(now) {
	case StateChecking:
		return CastResult{}, codeErr("checking", nil)
	case StateUpcoming:
		return CastResult{}, codeErr("not_open", tsBody("opens_at", r.Opens))
	case StateClosed:
		return CastResult{}, codeErr("closed", tsBody("closes_at", r.Closes))
	}
	if !now.Before(time.Unix(r.Closes, 0).Add(-CastMargin)) {
		return CastResult{}, codeErr("closing", tsBody("closes_at", r.Closes))
	}
	p, err := votewire.ParseProposal(r.Proposal)
	if err != nil || !p.HasChoice(choice) {
		return CastResult{}, errBad
	}
	if b := r.Ballot; b != nil {
		if b.ChoiceID == choice {
			return CastResult{ProposalID: id, State: b.State}, nil // a repeat
		}
		return CastResult{}, codeErr("already_voted", strictjson.NewBuilder().Raw("ballot", strictjson.NewBuilder().String("state", b.State).Bytes()).Bytes())
	}
	if r.Site == SiteMismatch {
		return CastResult{}, codeErr("site_mismatch", nil)
	}
	if c, ok := s.Connection(conn); !ok || c.State != vault.PeerActive {
		return CastResult{}, codeErr("connection_unavailable", nil)
	}
	if len(pinned) == 0 {
		return CastResult{}, codeErr("not_signed_in", strictjson.NewBuilder().String("connection_id", conn).Bytes())
	}
	if r.Restore { // not reachable while state() says checking; kept as the spec's own row
		return CastResult{}, codeErr("checking", nil)
	}
	if f.dep.Keys == nil {
		return CastResult{}, codeErr("credential_locked", nil)
	}
	credKey, ok := f.dep.Keys.UseKey(now, s.Settings().UnlockTTL())
	if !ok {
		return CastResult{}, codeErr("credential_locked", nil)
	}
	// 1. The ballot, signed by the voting key, and cast_sig by the credential
	// key.
	if len(r.VKSeed) != ed25519.SeedSize {
		return CastResult{}, vault.NewError("internal", "")
	}
	vk := ed25519.NewKeyFromSeed(r.VKSeed)
	bal, err := votewire.SignBallot(vk, r.Hash, r.Tag, choice)
	suite.Wipe(vk)
	if err != nil {
		return CastResult{}, vault.NewError("internal", "")
	}
	leaf, err := bal.Leaf()
	if err != nil {
		return CastResult{}, vault.NewError("internal", "")
	}
	castSig, err := votewire.SignCast(credKey, r.Hash, leaf)
	if err != nil {
		return CastResult{}, vault.NewError("internal", "")
	}
	body, err := votewire.MarshalCast(id, bal, castSig)
	if err != nil {
		return CastResult{}, vault.NewError("internal", "")
	}
	// 2. Stored; the flush precedes the sending. A rotation statement still
	// owed to the connection goes first in the same outbox.
	r.Ballot = &ballot{State: BallotSending, ChoiceID: choice, VK: bal.VK, BallotSig: bal.BallotSig, CastSig: castSig, Body: body}
	r.ChangedMS = now.UnixMilli()
	f.audit(s, "vote.cast", conn, id) // never the choice
	if len(owed) > 0 {
		_ = s.SendToConnection(conn, "connection.authenticate.rotated", owed)
	}
	f.sendBallot(s, r)
	f.event(s, r, "ballot")
	return CastResult{ProposalID: id, State: r.Ballot.State}, nil
}

// sendBallot sends the stored body as a new request with a new inner id.
func (f *Feature) sendBallot(s *vault.Session, r *record) {
	b := r.Ballot
	now := s.Now()
	id, err := s.SendRequest(r.Conn, "vote.cast", b.Body)
	if err != nil {
		// No session now: tried again at the next tick.
		b.NextSendMS = now.Add(time.Minute).UnixMilli()
		return
	}
	f.pend[id] = pendRef{conn: r.Conn, id: r.ID, kind: "cast", atMS: now.UnixMilli()}
	b.Sends = append(b.Sends, sendRec{ID: id, AtMS: now.UnixMilli(), Gen: b.Gen})
	if len(b.Sends) > 64 {
		if !b.Sends[0].Answered {
			b.LostOld = true
		}
		b.Sends = b.Sends[len(b.Sends)-64:]
	}
	b.SentGen = b.Gen
	if b.FirstSendMS == 0 {
		b.FirstSendMS = now.UnixMilli()
	}
	if b.Round == 0 {
		b.RoundStartMS = now.UnixMilli()
	}
	switch {
	case b.Reason == "not_signed_in":
		b.NextSendMS = now.Add(time.Hour).UnixMilli() // hourly
	case b.Round < len(sendOffsets):
		b.NextSendMS = time.UnixMilli(b.RoundStartMS).Add(sendOffsets[b.Round]).UnixMilli()
	default:
		b.NextSendMS = now.Add(time.Hour).UnixMilli()
	}
	if b.NextSendMS <= now.UnixMilli() {
		b.NextSendMS = now.Add(time.Minute).UnixMilli()
	}
	b.Round++
}

// askStatus sends vote.status for a record.
func (f *Feature) askStatus(s *vault.Session, conn, id string, want []byte) bool {
	restore := false
	if r := f.get(conn, id); r != nil {
		restore = r.Restore
	}
	body, err := votewire.MarshalStatusRequest(id)
	if err != nil {
		return false
	}
	reqID, err := s.SendRequest(conn, "vote.status", body)
	if err != nil {
		return false
	}
	f.pend[reqID] = pendRef{conn: conn, id: id, kind: "status", want: want, restore: restore, atMS: s.Now().UnixMilli()}
	return true
}

// setFinal ends the ballot in a final state: the seed of vk is erased (the
// public half stays, for comparing with the service's ballot after a
// restore), and the app is told.
func (f *Feature) setFinal(s *vault.Session, r *record, state, code string) {
	b := r.Ballot
	b.State, b.Code, b.Reason = state, code, ""
	suite.Wipe(r.VKSeed)
	r.VKSeed = nil
	r.ChangedMS = s.Now().UnixMilli()
	f.event(s, r, "ballot")
}

func (f *Feature) setWaiting(s *vault.Session, r *record, reason string) {
	b := r.Ballot
	b.State, b.Reason = BallotWaiting, reason
	if reason == "not_signed_in" {
		b.NextSendMS = s.Now().Add(time.Hour).UnixMilli() // hourly, and at once after the next signed response
	}
	r.ChangedMS = s.Now().UnixMilli()
	f.event(s, r, "ballot")
}

// Response implements vault.ResponseObserver: the answers to vote.cast and
// vote.status. Only a verified answer counts (§10.19.5).
func (f *Feature) Response(s *vault.Session, in *envelope.Inner) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	ref, ok := f.pend[in.Re]
	if !ok {
		return true // after a restart: dropped, as an answer matching no request
	}
	delete(f.pend, in.Re)
	switch ref.kind {
	case "cast":
		if r := f.get(ref.conn, ref.id); r != nil && r.Ballot != nil {
			f.castAnswer(s, r, in)
		}
	case "status":
		f.statusAnswer(s, ref, in)
	}
	return true
}

// ownConnections are H of the vault's own identity keys, current or earlier.
func ownConnections(s *vault.Session) [][]byte {
	var out [][]byte
	for _, k := range s.OwnIdentityKeys() {
		out = append(out, votewire.H(k))
	}
	return out
}

// marksAnswered records that the send answered by reqID got a verified
// answer.
func (b *ballot) marksAnswered(reqID string, now time.Time) (gen int) {
	for i := range b.Sends {
		if b.Sends[i].ID == reqID {
			b.Sends[i].Answered = true
			gen = b.Sends[i].Gen
		}
	}
	b.LastAnswerMS = now.UnixMilli()
	return gen
}

// unansweredBefore reports whether a send other than reqID has no verified
// answer.
func (b *ballot) unansweredBefore(reqID string) bool {
	if b.LostOld {
		return true
	}
	for _, x := range b.Sends {
		if x.ID != reqID && !x.Answered {
			return true
		}
	}
	return false
}

func keepRefusal(list [][]byte, body []byte) [][]byte {
	list = append(list, append([]byte{}, body...))
	if len(list) > votewire.MaxRefusalsKept {
		list = list[len(list)-votewire.MaxRefusalsKept:]
	}
	return list
}

// receipt records a verified receipt for the stored ballot: it always wins
// over a refusal, whenever it arrives.
func (f *Feature) receipt(s *vault.Session, r *record, msgMS int64, sig []byte) {
	b := r.Ballot
	b.MsgMS, b.ReceiptSig = msgMS, append([]byte{}, sig...)
	f.setFinal(s, r, BallotRecorded, "")
	f.audit(s, "vote.recorded", r.Conn, r.ID)
}

func (r *record) msgInWindow(msgMS int64) bool {
	return msgMS >= r.Opens*1000 && msgMS < r.Closes*1000
}

// castAnswer handles the answer to a vote.cast (§10.19.5 "The answer").
func (f *Feature) castAnswer(s *vault.Session, r *record, in *envelope.Inner) {
	b := r.Ballot
	now := s.Now()
	if b.State == BallotRecorded || b.State == BallotConflict || b.State == BallotDisputed {
		return
	}
	if b.State == BallotRefused && in.Status == envelope.StatusError {
		return // a late refusal after the ballot is refused: nothing to audit or tell again
	}
	leaf, err := r.ballotLeaf()
	if err != nil {
		return
	}
	if in.Status != envelope.StatusError {
		a, err := votewire.ParseCastAnswer(in.Body)
		if err != nil || a.Verify(r.Signer, r.ID, r.Hash, leaf) != nil || !r.msgInWindow(int64(a.MsgMS)) {
			f.audit(s, "vote.receipt_rejected", r.Conn, r.ID)
			return
		}
		b.marksAnswered(in.Re, now)
		f.receipt(s, r, int64(a.MsgMS), a.ReceiptSig)
		return
	}
	if in.Error == nil {
		return
	}
	code := in.Error.Code
	rf, err := votewire.ParseRefusal(in.Body)
	if err != nil || rf.Verify(r.Signer, r.ID, "vote.cast", code, votewire.H(leaf), ownConnections(s), r.Tag) != nil {
		return // unsigned or failing: no answer
	}
	switch code {
	case "not_open", "not_signed_in", "closed", "late", "not_active", "not_eligible", "bad_ballot", "already_voted":
	default:
		return // a code the vault does not know is no answer
	}
	gen := b.marksAnswered(in.Re, now)
	if code != "already_voted" {
		b.Refusals = keepRefusal(b.Refusals, in.Body)
	}
	switch code {
	case "not_open":
		f.setWaiting(s, r, "not_open")
	case "not_signed_in":
		f.setWaiting(s, r, "not_signed_in")
	case "closed", "late":
		if b.unansweredBefore(in.Re) {
			// An earlier send may have arrived in time: ask what the service holds.
			f.setWaiting(s, r, "closed")
			b.NextStatusMS = now.UnixMilli()
			return
		}
		f.refuse(s, r, code, false)
	case "not_active", "not_eligible":
		f.refuse(s, r, code, true)
	case "bad_ballot":
		if gen < b.Gen {
			// A send made before the re-signed body: the body already
			// re-signed is the answer, sent once if it was not yet.
			f.setWaiting(s, r, "bad_ballot")
			if b.SentGen < b.Gen && now.Before(time.Unix(r.Closes, 0)) {
				f.sendBallot(s, r)
			}
			return
		}
		f.refuse(s, r, code, true)
	case "already_voted":
		eb, err := rf.VerifyExisting(r.Signer, r.Hash, r.Tag)
		if err != nil || !r.msgInWindow(int64(rf.BallotMsgMS)) {
			return
		}
		if eq(eb.VK, b.VK) && eb.ChoiceID == b.ChoiceID && eq(eb.BallotSig, b.BallotSig) {
			f.receipt(s, r, int64(rf.BallotMsgMS), rf.ReceiptSig) // exactly this vault's ballot: it is the receipt
			return
		}
		f.foreign(s, r, b, &svcBallot{VK: eb.VK, ChoiceID: eb.ChoiceID, BallotSig: eb.BallotSig, MsgMS: int64(rf.BallotMsgMS), ReceiptSig: rf.ReceiptSig})
	}
}

// refuse ends the ballot in `refused` with the signed refusal as evidence.
func (f *Feature) refuse(s *vault.Session, r *record, code string, problem bool) {
	f.setFinal(s, r, BallotRefused, code)
	f.audit(s, "vote.refused", r.Conn, r.ID+":"+code)
	if problem {
		r.RefusalProblem = true
		f.feed(s, "vote.problem", r.Conn, r.ID, "high")
	}
}

// statusAnswer handles the answer to a vote.status (§10.19.5).
func (f *Feature) statusAnswer(s *vault.Session, ref pendRef, in *envelope.Inner) {
	now := s.Now()
	r := f.get(ref.conn, ref.id)
	if in.Status == envelope.StatusError {
		f.statusRefusal(s, r, ref, in)
		return
	}
	a, err := votewire.ParseStatusAnswer(in.Body)
	if err != nil || a.ProposalID != ref.id {
		return
	}
	if r == nil {
		// A proposal the vault was not sent (the site's index has it): the
		// answer is checked as a vote.proposal would be, and its bytes must
		// equal the site's.
		if len(ref.want) > 0 && !eq(a.Proposal, ref.want) {
			return
		}
		f.intakeStatus(s, ref.conn, a)
		return
	}
	if !eq(a.Proposal, r.Proposal) || a.VerifySig(r.Signer, r.Hash) != nil {
		return
	}
	tag, err := a.Tag()
	if err != nil || !eq(tag, r.Tag) {
		return
	}
	if a.Ballot != nil && !r.msgInWindow(int64(a.MsgMS)) {
		return // a receipt outside the window is no answer, as for vote.cast
	}
	r.StatusAnswers = keepRefusal(r.StatusAnswers, in.Body)
	r.Restore = false // the service answered: a cast is possible again
	r.ChangedMS = now.UnixMilli()
	b := r.Ballot
	if b != nil {
		b.LastAnswerMS = now.UnixMilli()
	}
	if a.Ballot == nil {
		switch {
		case b != nil && b.State == BallotRecorded:
			// A receipt held and the service says it has none: evidence against it.
			r.RefusalProblem = true
			f.feed(s, "vote.problem", r.Conn, r.ID, "high")
			f.event(s, r, "problem")
		case b != nil && b.State == BallotWaiting && b.Reason == "closed" && now.After(time.Unix(r.Closes, 0).Add(FinalAfter)):
			f.refuse(s, r, "closed", false) // final only after closes_at + 24 h
		}
		f.event(s, r, "ballot")
		return
	}
	sb := &svcBallot{VK: a.Ballot.VK, ChoiceID: a.Ballot.ChoiceID, BallotSig: a.Ballot.BallotSig, MsgMS: int64(a.MsgMS), ReceiptSig: a.ReceiptSig}
	same := b != nil && eq(sb.VK, b.VK) && sb.ChoiceID == b.ChoiceID && eq(sb.BallotSig, b.BallotSig)
	switch {
	case same:
		// The vault's own ballot (a refused connection_ended one included):
		// the receipt, a lost answer recovered.
		if b.State != BallotRecorded && b.State != BallotConflict && b.State != BallotDisputed {
			f.receipt(s, r, sb.MsgMS, sb.ReceiptSig)
		} else {
			f.event(s, r, "ballot")
		}
	case b == nil && ref.restore && eq(sb.VK, r.VK):
		// After a restore the service holds a ballot made with this record's
		// own voting key that the vault lost: the member confirms it
		// (vote.confirm).
		r.ServiceBallot = sb
		f.event(s, r, "ballot")
	default:
		// A ballot the vault never signed (another vk, or no restore), or
		// another one than its own: a conflict, kept as evidence. Without a
		// ballot of the vault's own it prompts nothing and does not change
		// whether it can cast.
		f.foreign(s, r, b, sb)
	}
}

// foreign records a ballot the vault did not sign (or another than its
// own): the first is kept as the evidence (the latest beside it), and the
// audit entry and the feed item are made once per record.
func (f *Feature) foreign(s *vault.Session, r *record, b *ballot, sb *svcBallot) {
	first := r.Other == nil
	if first {
		r.Other = sb
	} else {
		r.OtherLatest = sb
	}
	if !first || r.ConflictEv || b != nil && b.State == BallotConflict {
		return // raised already
	}
	switch {
	case b != nil && (b.State == BallotRecorded || !b.final()):
		f.setFinal(s, r, BallotConflict, "")
	default:
		r.ConflictEv = true
	}
	f.audit(s, "vote.conflict", r.Conn, r.ID)
	f.feed(s, "vote.problem", r.Conn, r.ID, "high")
	f.event(s, r, "problem")
}

// statusRefusal: a signed not_eligible or unknown_proposal is kept as
// evidence and shown (decision 7).
func (f *Feature) statusRefusal(s *vault.Session, r *record, ref pendRef, in *envelope.Inner) {
	if r == nil || in.Error == nil {
		return
	}
	code := in.Error.Code
	if code != "not_eligible" && code != "unknown_proposal" {
		return
	}
	rf, err := votewire.ParseRefusal(in.Body)
	if err != nil || rf.Verify(r.Signer, r.ID, "vote.status", code, votewire.H([]byte(r.ID)), ownConnections(s), r.Tag) != nil {
		return
	}
	r.StatusAnswers = keepRefusal(r.StatusAnswers, in.Body)
	r.Restore = false
	if !r.RefusalProblem {
		r.RefusalProblem = true
		f.feed(s, "vote.problem", r.Conn, r.ID, "high")
	}
	r.ChangedMS = s.Now().UnixMilli()
	f.event(s, r, "problem")
}

// intakeStatus keeps a proposal from a status answer (§10.19.4 "A proposal
// the vault was never sent"): steps 2 to 6 on the answer's members, a
// missing bundle leaving it `checking` (site) until the site's arrives.
func (f *Feature) intakeStatus(s *vault.Session, conn string, a *votewire.StatusAnswer) {
	// The answer's signatures first: nothing is kept (not even a rejected
	// record) from an answer that does not verify under the service's key.
	p, err := votewire.ParseProposal(a.Proposal)
	if err != nil || !isConnKey(s, conn, p.Service) || a.VerifySig(p.Service, votewire.H(a.Proposal)) != nil {
		return
	}
	msg := &votewire.ProposalMsg{Proposal: a.Proposal, ProposalSig: a.ProposalSig, Bundle: a.Bundle, RecordSecret: a.RecordSecret, RecordProof: a.RecordProof}
	_, _ = f.intake(s, conn, msg)
}

// RequestProposal asks the service for a proposal on the site's index that
// the vault does not hold (vote.status, §10.19.4): at most once an hour per
// proposal. The answer must carry exactly siteBytes, the site's proposal.
// It reports whether the request was sent.
func (f *Feature) RequestProposal(s *vault.Session, conn, id string, siteBytes []byte) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requestProposal(s, conn, id, siteBytes)
}

func (f *Feature) requestProposal(s *vault.Session, conn, id string, siteBytes []byte) bool {
	k := key(conn, id)
	now := s.Now()
	if f.st.Records[k] != nil || !votewire.ValidProposalID(id) || len(siteBytes) == 0 {
		return false
	}
	if at, ok := f.asked[k]; ok && now.Sub(time.UnixMilli(at)) < StatusEvery {
		return false
	}
	if !f.askStatus(s, conn, id, siteBytes) {
		return false
	}
	f.asked[k] = now.UnixMilli()
	return true
}

// Check is vote.check: ask the service what it recorded now, at most once
// per proposal per ten minutes (else `limit` with retry_after).
func (f *Feature) Check(s *vault.Session, conn, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.get(conn, id)
	if r == nil || r.RejectReason != "" {
		return errNotFound
	}
	now := s.Now()
	if at := time.UnixMilli(r.CheckAskMS); r.CheckAskMS != 0 && now.Sub(at) < CheckAskEvery {
		left := CheckAskEvery - now.Sub(at)
		return &vault.HandlerError{Code: "limit", Body: strictjson.NewBuilder().String("limit", "vote.check").
			Uint("retry_after", uint64((left+time.Second-1)/time.Second)).Bytes()}
	}
	if !f.askStatus(s, conn, id, nil) {
		return codeErr("connection_unavailable", nil)
	}
	r.CheckAskMS = now.UnixMilli()
	return nil
}

// Confirm is vote.confirm: the member's answer to a ballot the service
// holds that the vault has not (after a restore). "Yes" stores the
// service's ballot and receipt as recorded; "no" sets disputed and keeps
// everything as evidence (BALLOT-PROTOCOL §5).
func (f *Feature) Confirm(s *vault.Session, conn, id string, mine bool) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.get(conn, id)
	if r == nil || r.RejectReason != "" {
		return "", errNotFound
	}
	sb := r.ServiceBallot
	if sb == nil {
		return "", errBad
	}
	r.ServiceBallot = nil
	r.Ballot = &ballot{ChoiceID: sb.ChoiceID, VK: sb.VK, BallotSig: sb.BallotSig, MsgMS: sb.MsgMS, ReceiptSig: sb.ReceiptSig}
	if mine {
		f.setFinal(s, r, BallotRecorded, "")
		f.audit(s, "vote.recorded", r.Conn, r.ID)
	} else {
		f.setFinal(s, r, BallotDisputed, "")
		f.audit(s, "vote.disputed", r.Conn, r.ID)
		f.feed(s, "vote.problem", r.Conn, r.ID, "high")
	}
	return r.Ballot.State, nil
}

// Tick implements vault.TickObserver: the sending schedule, the asks for
// status, the seed of a vote never cast, and the result checks that come
// due. It runs whenever the vault is unlocked, held included.
func (f *Feature) Tick(s *vault.Session) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := s.Now()
	for id, p := range f.pend { // as the Manager forgets its own requests
		if now.Sub(time.UnixMilli(p.atMS)) > pendTTL {
			delete(f.pend, id)
		}
	}
	keys := make([]string, 0, len(f.st.Records))
	for k := range f.st.Records {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if r := f.st.Records[k]; r != nil && r.RejectReason == "" {
			f.tickRecord(s, r, now)
		}
	}
}

// closingAt is when vote.closing is due (§10.19.7): the close in force minus
// the lesser of 24 hours and half the voting window (the proposal's own).
func closingAt(r *record) time.Time {
	lead := 24 * time.Hour
	if half := time.Duration(r.OrigClose-r.Opens) * time.Second / 2; half < lead {
		lead = half
	}
	return time.Unix(r.Closes, 0).Add(-lead)
}

// closingFeed makes the vote.closing item once, if the vote is open and the
// member has not voted. A vault that was locked at the moment makes it at
// the next unlock if more than an hour remains; a held vault makes it
// without a wake. An extension makes no second one.
func (f *Feature) closingFeed(s *vault.Session, r *record, now time.Time) {
	if r.ClosingFeed || r.Ballot != nil || r.state(now) != StateOpen {
		return
	}
	at := closingAt(r)
	if now.Before(at) {
		return
	}
	r.ClosingFeed = true
	if now.Sub(at) > closingLate && time.Unix(r.Closes, 0).Sub(now) <= time.Hour {
		return // missed while locked, and too late to be of use
	}
	f.feed(s, "vote.closing", r.Conn, r.ID, "")
}

// closingLate is how late a tick may be and still count as "at the moment"
// (the vault was unlocked).
const closingLate = 10 * time.Minute

func (f *Feature) tickRecord(s *vault.Session, r *record, now time.Time) {
	closed := r.closed(now)
	f.closingFeed(s, r, now)
	// A vote never cast has no use for its voting key once it closes.
	if r.Ballot == nil && closed && len(r.VKSeed) > 0 {
		suite.Wipe(r.VKSeed)
		r.VKSeed = nil
	}
	f.tickCheck(s, r, now)
	conn, ok := s.Connection(r.Conn)
	active := ok && conn.State == vault.PeerActive
	// After a restore: ask what the service recorded, hourly, until it answers.
	if r.Restore && active && now.UnixMilli() >= r.AskMS {
		if f.askStatus(s, r.Conn, r.ID, nil) {
			r.AskMS = now.Add(StatusEvery).UnixMilli()
		}
	}
	b := r.Ballot
	if b == nil || b.final() || !active {
		return
	}
	if b.Body == nil {
		return
	}
	if !closed {
		if b.State == BallotWaiting && b.Reason == "closed" {
			// An earlier send may have arrived: ask, no more casts.
			f.statusDue(s, r, now)
			return
		}
		if now.UnixMilli() >= b.NextSendMS {
			f.sendBallot(s, r)
		}
		// 24 hours without a verified answer: also ask.
		last := b.LastAnswerMS
		if last == 0 {
			last = b.FirstSendMS
		}
		if last != 0 && now.Sub(time.UnixMilli(last)) >= NoAnswerAfter {
			f.statusDue(s, r, now)
		}
		return
	}
	// The close in force has been reached: sending stops, the status is asked.
	f.statusDue(s, r, now)
}

func (f *Feature) statusDue(s *vault.Session, r *record, now time.Time) {
	b := r.Ballot
	if now.UnixMilli() >= b.NextStatusMS {
		if f.askStatus(s, r.Conn, r.ID, nil) {
			b.NextStatusMS = now.Add(StatusEvery).UnixMilli()
		}
	}
}

// ResponseSigned implements connauth.ResponseObserver: a waiting ballot of
// the connection is sent at once after the vault's next signed
// authentication response (§10.19.5 `not_signed_in`).
func (f *Feature) ResponseSigned(_ *vault.Session, conn string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.st.Records {
		if r.Conn == conn && r.Ballot != nil && r.Ballot.State == BallotWaiting && r.Ballot.Reason == "not_signed_in" {
			r.Ballot.NextSendMS = 0
		}
	}
}

// ConnectionRemoved implements vault.ConnectionRemovedObserver: records and
// ballots stay as evidence; a ballot still sending or waiting can no longer
// be sent and becomes refused (connection_ended).
func (f *Feature) ConnectionRemoved(s *vault.Session, conn string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.st.Records {
		if r.Conn == conn && r.Ballot != nil && !r.Ballot.final() {
			f.setFinal(s, r, BallotRefused, "connection_ended")
		}
	}
	for id, p := range f.pend {
		if p.conn == conn {
			delete(f.pend, id)
		}
	}
}

// markRestore: after a recovery or a transfer the vault's records may be
// behind the service's. Every proposal without a receipt is `checking`
// (restore) and asked, and nothing is cast until the answer (§10.19.5).
func (f *Feature) markRestore(s *vault.Session) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.st.Records {
		if r.RejectReason != "" || (r.Ballot != nil && r.Ballot.State == BallotRecorded) {
			continue
		}
		r.Restore, r.AskMS, r.ChangedMS = true, 0, s.Now().UnixMilli()
		f.event(s, r, "proposal")
	}
}

// TransferCompleted implements vault.TransferObserver (a transfer to a new
// phone, and the release-R recovery).
func (f *Feature) TransferCompleted(s *vault.Session, _, _ string) { f.markRestore(s) }

// RecoveryCompleted implements vault.RecoveryObserver.
func (f *Feature) RecoveryCompleted(s *vault.Session) { f.markRestore(s) }

// CredentialKeyRotated implements credential.KeyRotationObserver: nothing to
// do with the statement (member authentication sends it); the re-signing
// is CredentialKeysOpen.
func (f *Feature) CredentialKeyRotated(*vault.Session, *credwire.KeyRotation) {}

// CredentialKeysOpen implements credential.KeyRotationSigner (VAULT-
// MESSAGING 0.81.1 §3.5.5): while both credential keys are open, the
// cast_sig of every ballot that is not final is signed again under the new
// key, the stored body replaced (the rotation's flush persists it), and the
// new body is sent once, after the rotation statement, to a connection that
// pinned the old key. After the close in force it is only replaced.
// vote.cast and credential.rotate run one at a time in the vault, so no
// cast signed under the old key is flushed after this pass.
func (f *Feature) CredentialKeysOpen(s *vault.Session, _, newKey ed25519.PrivateKey) {
	newPub := newKey.Public().(ed25519.PublicKey)
	// Read what member authentication pinned before taking this lock.
	pins := map[string][]byte{}
	f.mu.Lock()
	conns := map[string]bool{}
	for _, r := range f.st.Records {
		if r.Ballot != nil && !r.Ballot.final() {
			conns[r.Conn] = true
		}
	}
	f.mu.Unlock()
	if f.dep.Auth != nil {
		for c := range conns {
			pins[c] = f.dep.Auth.SignedInKey(c)
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	now := s.Now()
	keys := make([]string, 0, len(f.st.Records))
	for k := range f.st.Records {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		r := f.st.Records[k]
		b := r.Ballot
		if b == nil || b.final() {
			continue
		}
		leaf, err := r.ballotLeaf()
		if err != nil {
			continue
		}
		sig, err := votewire.SignCast(newKey, r.Hash, leaf)
		if err != nil {
			continue
		}
		bal := &votewire.Ballot{RecordTag: r.Tag, VK: b.VK, ChoiceID: b.ChoiceID, BallotSig: b.BallotSig}
		body, err := votewire.MarshalCast(r.ID, bal, sig)
		if err != nil {
			continue
		}
		b.CastSig, b.Body = sig, body // the same ballot: vk, choice, ballot_sig and leaf do not change
		pin := pins[r.Conn]
		if len(pin) == 0 || eq(pin, newPub) {
			continue // pinned no key: only replaced
		}
		// Every re-sign for a connection that pinned a key is a new
		// generation, sent or not: a bad_ballot answering an older send is
		// answered by it, whether or not the connection was reachable now.
		b.Gen++
		if !now.Before(time.Unix(r.Closes, 0)) {
			continue // after the close in force: only replaced
		}
		c, ok := s.Connection(r.Conn)
		if !ok || c.State != vault.PeerActive {
			continue // sent at the next tick, by the schedule
		}
		f.sendBallot(s, r)
	}
}
