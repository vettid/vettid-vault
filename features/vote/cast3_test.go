package vote

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/internal/votetest"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/suite"
	"github.com/vettid/vettid-vault/vms/votewire"
)

// answer sends a signed ok vote.status answer for v's member; ballot nil
// is the answer without one (H("") signed).
func (c *cenv) answer(v *votetest.Vote, reqID string, ballot *votewire.Ballot, msgMS uint64, withReceipt bool) {
	c.t.Helper()
	var leaf, rsig []byte
	if ballot != nil {
		leaf = must(ballot.Leaf())
		if withReceipt {
			rsig, _ = suite.Sign(c.svc.IK, votewire.LabelReceipt, must(votewire.ReceiptMsg(v.Hash, leaf, msgMS)))
		}
	}
	ssig, _ := suite.Sign(c.svc.IK, votewire.LabelStatus, must(votewire.StatusMsg(v.ID, v.Tag, leaf)))
	var rb *votewire.RowBallot
	if ballot != nil {
		rb = &votewire.RowBallot{VK: ballot.VK, ChoiceID: ballot.ChoiceID, BallotSig: ballot.BallotSig}
	}
	body := c.statusBody(v, rb, msgMS, rsig, ssig)
	c.respond(reqID, "vote.status", &envelope.Inner{Status: envelope.StatusOK, Body: body})
}

// alreadyVoted answers the vault's cast reqID with a signed already_voted
// carrying shown and its receipt at msgMS.
func (c *cenv) alreadyVoted(v *votetest.Vote, reqID string, shown *votewire.Ballot, msgMS uint64) {
	c.t.Helper()
	sleaf := must(shown.Leaf())
	rsig, _ := suite.Sign(c.svc.IK, votewire.LabelReceipt, must(votewire.ReceiptMsg(v.Hash, sleaf, msgMS)))
	msg := must(votewire.RefusalMsg(v.ID, votewire.H(c.h.IK), v.Tag, "vote.cast", "already_voted", msgMS, votewire.H(c.leafOf(v))))
	sig, _ := suite.Sign(c.svc.IK, votewire.LabelRefusal, msg)
	body := strictjson.NewBuilder().Base64("refusal_sig", sig).Uint("msg_ms", msgMS).Base64("connection", votewire.H(c.h.IK)).Base64("record_tag", v.Tag).
		Raw("ballot", strictjson.NewBuilder().Base64("vk", shown.VK).String("choice_id", shown.ChoiceID).Base64("ballot_sig", shown.BallotSig).Bytes()).
		Uint("ballot_msg_ms", msgMS).Base64("receipt_sig", rsig).Bytes()
	c.respond(reqID, "vote.cast", &envelope.Inner{Status: envelope.StatusError, Error: &envelope.Error{Code: "already_voted"}, Body: body})
}

func (c *cenv) ownBallot(v *votetest.Vote) *votewire.Ballot {
	b := c.rec(v.ID).Ballot
	return &votewire.Ballot{RecordTag: v.Tag, VK: b.VK, ChoiceID: b.ChoiceID, BallotSig: b.BallotSig}
}

func TestStatusRecoversALostReceipt(t *testing.T) {
	c := newCastEnv(t)
	v := c.open(1)
	c.cast(v, "yes")
	if r := c.f.Check(c.session(), "svc", v.ID); r != nil {
		t.Fatal(r)
	}
	ids := c.statuses()
	c.answer(v, ids[0], c.ownBallot(v), uint64(c.now.UnixMilli()), true)
	if c.state(v) != BallotRecorded || len(c.rec(v.ID).StatusAnswers) != 1 {
		t.Errorf("%s", c.state(v))
	}
	// vote.check is limited to once per proposal per ten minutes.
	err := c.f.Check(c.session(), "svc", v.ID)
	if code(err) != "limit" {
		t.Fatalf("%v", err)
	}
	o, _ := strictjson.ParseObject(err.(*vault.HandlerError).Body)
	if n, _ := o.Uint("retry_after", 0, 1000); n < 1 || n > 600 {
		t.Errorf("retry_after %d", n)
	}
	c.now = c.now.Add(11 * time.Minute)
	if err := c.f.Check(c.session(), "svc", v.ID); err != nil {
		t.Errorf("after ten minutes: %v", err)
	}
}

func TestStatusAnswersAreCheckedAndPartialOnesIgnored(t *testing.T) {
	c := newCastEnv(t)
	v := c.open(1)
	c.cast(v, "yes")
	c.f.Check(c.session(), "svc", v.ID)
	ids := c.statuses()
	// A ballot without a receipt, a receipt without a ballot: no answer.
	ssig, _ := suite.Sign(c.svc.IK, votewire.LabelStatus, must(votewire.StatusMsg(v.ID, v.Tag, nil)))
	bad := c.statusBody(v, nil, 5, make([]byte, 64), ssig) // receipt members without a ballot: statusBody omits them
	_ = bad
	// A status_sig that fails.
	body := c.statusBody(v, nil, 0, nil, make([]byte, 64))
	c.respond(ids[0], "vote.status", &envelope.Inner{Status: envelope.StatusOK, Body: body})
	if len(c.rec(v.ID).StatusAnswers) != 0 || c.rec(v.ID).Restore {
		t.Error("a failing answer was kept")
	}
	// An answer for other proposal bytes.
	c.f.pend[ids[0]] = pendRef{conn: "svc", id: v.ID, kind: "status"}
	w := c.svc.NewVote(votetest.VoteSpec{ID: v.ID, Opens: c.now.Add(-time.Hour), Closes: c.now.Add(5 * time.Hour)})
	sig2, _ := suite.Sign(c.svc.IK, votewire.LabelStatus, must(votewire.StatusMsg(w.ID, w.Tag, nil)))
	c.respond(ids[0], "vote.status", &envelope.Inner{Status: envelope.StatusOK, Body: c.statusBody(w, nil, 0, nil, sig2)})
	if len(c.rec(v.ID).StatusAnswers) != 0 {
		t.Error("an answer for other bytes was kept")
	}
}

func TestStatusNoBallotWhileReceiptHeld(t *testing.T) {
	c := newCastEnv(t)
	v := c.open(1)
	c.cast(v, "yes")
	_, ids := c.casts()
	c.okReceipt(v, ids[0], c.leafOf(v), uint64(c.now.UnixMilli()))
	c.f.Check(c.session(), "svc", v.ID)
	sid := c.statuses()[0]
	c.h.Reset()
	c.answer(v, sid, nil, 0, false)
	r := c.rec(v.ID)
	if r.Ballot.State != BallotRecorded || !r.RefusalProblem || !c.has("vote.problem", v.ID) || len(r.Ballot.Body) == 0 {
		t.Errorf("%+v", r)
	}
}

func TestStatusConflictWithADifferentVK(t *testing.T) {
	c := newCastEnv(t)
	v := c.open(1)
	c.cast(v, "yes")
	c.f.Check(c.session(), "svc", v.ID)
	_, vk2, _ := ed25519.GenerateKey(rand.Reader)
	other := must(votewire.SignBallot(vk2, v.Hash, v.Tag, "no"))
	c.answer(v, c.statuses()[0], other, uint64(c.now.UnixMilli()), true)
	r := c.rec(v.ID)
	// A flag on the record (0.81.3), not a ballot state: the ballot goes on.
	if r.Ballot.State != BallotSending || !r.ConflictEv || r.Other == nil || !c.has("vote.conflict", v.ID) || !r.problem() {
		t.Errorf("%s", r.Ballot.State)
	}
}

func TestStatusRefusals(t *testing.T) {
	c := newCastEnv(t)
	v := c.open(1)
	c.rec(v.ID).Restore = true
	c.f.Tick(c.session())
	ids := c.statuses()
	if len(ids) != 1 {
		t.Fatalf("%d", len(ids))
	}
	// The refusal to vote.status: request_hash = H(proposal_id).
	c.refusal(v, ids[0], "vote.status", "not_eligible", votewire.H([]byte(v.ID)))
	r := c.rec(v.ID)
	if r.Restore || len(r.StatusAnswers) != 1 || !r.RefusalProblem || !c.has("vote.problem", v.ID) {
		t.Errorf("%+v", r)
	}
	// With request_hash of H(ballot_leaf) it does not verify.
	c2 := newCastEnv(t)
	w := c2.open(1)
	c2.rec(w.ID).Restore = true
	c2.f.Tick(c2.session())
	c2.refusal(w, c2.statuses()[0], "vote.status", "not_eligible", make([]byte, 32))
	if !c2.rec(w.ID).Restore || len(c2.rec(w.ID).StatusAnswers) != 0 {
		t.Error("a refusal with the wrong request_hash counted")
	}
}

func TestRestore(t *testing.T) {
	c := newCastEnv(t)
	v := c.open(1) // no ballot
	w := c.open(2) // a recorded ballot
	x := c.open(3) // a sending ballot
	c.cast(w, "yes")
	_, ids := c.casts()
	c.okReceipt(w, ids[0], c.leafOf(w), uint64(c.now.UnixMilli()))
	c.cast(x, "no")
	c.h.Reset()
	c.f.TransferCompleted(c.session(), "old", "new")
	if !c.rec(v.ID).Restore || c.rec(w.ID).Restore || !c.rec(x.ID).Restore {
		t.Fatal("marks")
	}
	if c.rec(v.ID).state(c.now) != StateChecking || c.rec(v.ID).checkingReason() != ReasonRestore {
		t.Error("not checking (restore)")
	}
	if _, err := c.cast(v, "yes"); code(err) != "checking" {
		t.Errorf("cast during restore: %q", code(err))
	}
	// Asked at the next tick, then hourly until answered.
	c.f.Tick(c.session())
	if len(c.statuses()) != 2 {
		t.Fatalf("%d asks", len(c.statuses()))
	}
	c.tickAt(30 * time.Minute)
	if len(c.statuses()) != 2 {
		t.Error("asked within the hour")
	}
	c.tickAt(31 * time.Minute)
	if len(c.statuses()) != 4 {
		t.Errorf("%d asks", len(c.statuses()))
	}
	// The service holds a ballot the vault has not (v): the member confirms.
	sts := c.statuses()
	// (made with this record's own voting key, which the restore lost the ballot of)
	vk2 := ed25519.NewKeyFromSeed(c.rec(v.ID).VKSeed)
	svcBal := must(votewire.SignBallot(vk2, v.Hash, v.Tag, "no"))
	// find v's ask: the one for v is the first of each pair (sorted by key)
	c.answer(v, sts[len(sts)-2], svcBal, uint64(c.now.UnixMilli()), true)
	r := c.rec(v.ID)
	if r.Restore || r.ServiceBallot == nil || r.Ballot != nil {
		t.Fatalf("%+v", r)
	}
	if st, err := c.f.Confirm(c.session(), "svc", v.ID, true); err != nil || st != BallotRecorded {
		t.Fatalf("%q %v", st, err)
	}
	if b := c.rec(v.ID).Ballot; b.ChoiceID != "no" || string(b.VK) != string(vk2.Public().(ed25519.PublicKey)) || len(b.ReceiptSig) == 0 || len(c.rec(v.ID).VKSeed) != 0 {
		t.Errorf("%+v", b)
	}
	// "No": disputed, everything kept.
	c2 := newCastEnv(t)
	u := c2.open(1)
	c2.rec(u.ID).Restore = true
	c2.f.Tick(c2.session())
	c2.answer(u, c2.statuses()[0], svcBal2(c2, u), uint64(c2.now.UnixMilli()), true)
	if st, err := c2.f.Confirm(c2.session(), "svc", u.ID, false); err != nil || st != BallotDisputed || !c2.rec(u.ID).problem() {
		t.Errorf("%q %v", st, err)
	}
	if _, err := c2.f.Confirm(c2.session(), "svc", u.ID, true); code(err) != "bad_request" {
		t.Errorf("a second confirm: %v", err)
	}
	// An answer without a ballot ends the restore: a cast is possible.
	c3 := newCastEnv(t)
	y := c3.open(1)
	c3.rec(y.ID).Restore = true
	c3.f.Tick(c3.session())
	c3.answer(y, c3.statuses()[0], nil, 0, false)
	if c3.rec(y.ID).Restore {
		t.Fatal("restore not ended")
	}
	if _, err := c3.cast(y, "yes"); err != nil {
		t.Errorf("cast after the answer: %v", err)
	}
	// A recovery marks too.
	c4 := newCastEnv(t)
	z := c4.open(1)
	c4.f.RecoveryCompleted(c4.session())
	if !c4.rec(z.ID).Restore {
		t.Error("recovery")
	}
}

func svcBal2(c *cenv, v *votetest.Vote) *votewire.Ballot {
	return must(votewire.SignBallot(ed25519.NewKeyFromSeed(c.rec(v.ID).VKSeed), v.Hash, v.Tag, "no"))
}

// A proposal on the site's index the vault was never sent: asked with
// vote.status (once an hour), checked as a vote.proposal is, its bytes
// equal to the site's; no bundle leaves it checking (site) until the
// site's arrives.
func TestStatusForAProposalNotHeld(t *testing.T) {
	c := newCastEnv(t)
	v := c.svc.NewVote(votetest.VoteSpec{ID: lid(7), Opens: c.now.Add(-time.Hour), Closes: c.now.Add(time.Hour)})
	if !c.f.RequestProposal(c.session(), "svc", v.ID, v.Doc) {
		t.Fatal("not asked")
	}
	if c.f.RequestProposal(c.session(), "svc", v.ID, v.Doc) {
		t.Error("asked twice within the hour")
	}
	ids := c.statuses()
	// The site's bytes must equal the answer's.
	ssig, _ := suite.Sign(c.svc.IK, votewire.LabelStatus, must(votewire.StatusMsg(v.ID, v.Tag, nil)))
	other := c.svc.NewVote(votetest.VoteSpec{ID: v.ID, Opens: c.now.Add(-time.Hour), Closes: c.now.Add(2 * time.Hour)})
	_ = other
	c.f.pend[ids[0]] = pendRef{conn: "svc", id: v.ID, kind: "status", want: []byte("other bytes")}
	c.respond(ids[0], "vote.status", &envelope.Inner{Status: envelope.StatusOK, Body: c.statusBody(v, nil, 0, nil, ssig)})
	if c.rec(v.ID) != nil {
		t.Fatal("kept despite other site bytes")
	}
	// Without a bundle: checking (site). statusBody always adds one, so
	// build the body without.
	c.now = c.now.Add(2 * time.Hour)
	v2 := c.svc.NewVote(votetest.VoteSpec{ID: lid(8), Opens: c.now.Add(-time.Hour), Closes: c.now.Add(time.Hour)})
	c.f.RequestProposal(c.session(), "svc", v2.ID, v2.Doc)
	ids = c.statuses()
	ssig2, _ := suite.Sign(c.svc.IK, votewire.LabelStatus, must(votewire.StatusMsg(v2.ID, v2.Tag, nil)))
	nob := strictjson.NewBuilder().String("proposal_id", v2.ID).Base64("proposal", v2.Doc).Base64("proposal_sig", v2.Sig).Base64("record_secret", v2.Secret).
		Raw("record_proof", (&votewire.RecordProof{Index: uint64(v2.Index), TreeSize: uint64(len(v2.Tags)), Path: must(votewire.Proof(v2.Tags, v2.Index))}).JSON()).
		Base64("status_sig", ssig2).Bytes()
	c.respond(ids[len(ids)-1], "vote.status", &envelope.Inner{Status: envelope.StatusOK, Body: nob})
	r := c.rec(v2.ID)
	if r == nil || r.state(c.now) != StateChecking || r.Reason != ReasonSite {
		t.Fatalf("%+v", r)
	}
	// The site's bundle arrives with its document.
	bundle := c.env.auth.Bundle(v2.Doc, c.svc.Anchor, c.now)
	if err := c.f.SiteDocument(c.session(), "svc", v2.ID, SiteDoc{Status: StatusFound, Proposal: v2.Doc, Sig: v2.Sig, Bundle: bundle}); err != nil {
		t.Fatal(err)
	}
	if c.rec(v2.ID).Reason != "" || c.rec(v2.ID).state(c.now) != StateOpen || !c.has("vote.open", v2.ID) {
		t.Errorf("not completed: %+v", c.rec(v2.ID))
	}
	// With a bundle in the answer: kept as a proposal.
	v3 := c.svc.NewVote(votetest.VoteSpec{ID: lid(9), Opens: c.now.Add(-time.Hour), Closes: c.now.Add(time.Hour)})
	c.now = c.now.Add(time.Second)
	c.f.RequestProposal(c.session(), "svc", v3.ID, v3.Doc)
	ids = c.statuses()
	ssig3, _ := suite.Sign(c.svc.IK, votewire.LabelStatus, must(votewire.StatusMsg(v3.ID, v3.Tag, nil)))
	c.respond(ids[len(ids)-1], "vote.status", &envelope.Inner{Status: envelope.StatusOK, Body: c.statusBody(v3, nil, 0, nil, ssig3)})
	if r := c.rec(v3.ID); r == nil || r.state(c.now) != StateOpen {
		t.Errorf("%+v", r)
	}
}

// A recorded ballot stays recorded when the service shows a foreign ballot
// (owner decision, 0.81.3): the flag, the problem, once; only a ballot
// without a receipt goes to `conflict`.
func TestRecordedStaysRecordedWithConflictEvidence(t *testing.T) {
	c := newCastEnv(t)
	v := c.open(1)
	c.cast(v, "yes")
	_, ids := c.casts()
	c.okReceipt(v, ids[0], c.leafOf(v), uint64(c.now.UnixMilli()))
	c.f.Check(c.session(), "svc", v.ID)
	_, vk2, _ := ed25519.GenerateKey(rand.Reader)
	other := must(votewire.SignBallot(vk2, v.Hash, v.Tag, "no"))
	c.answer(v, c.statuses()[0], other, uint64(c.now.UnixMilli()), true)
	r := c.rec(v.ID)
	if r.Ballot.State != BallotRecorded || !r.ConflictEv || !r.problem() || c.count("vote.problem") != 1 || c.count("vote.conflict") != 1 {
		t.Errorf("%s %v", r.Ballot.State, r.ConflictEv)
	}
	g := obj(t, c.app("vote.get", pairBody("svc", v.ID)))
	if !boolOf(g, "conflict_evidence") {
		t.Errorf("%v", g)
	}
}

// 0.88.12 (§10.19.3 "A ballot under the record's own voting key"): a status
// answer carrying a ballot under the record's own vk with no restore, the
// vault holding no ballot, is self_unrecorded (no prompt, no vote.conflict,
// one vote.self_mismatch); a cast after it makes self_conflict.
func TestStatusOwnVKWithoutARestore(t *testing.T) {
	c := newCastEnv(t)
	v := c.open(1)
	shown := c.selfBallot(v, "no")
	c.f.Check(c.session(), "svc", v.ID)
	c.answer(v, c.statuses()[0], shown, uint64(c.now.UnixMilli()), true)
	r := c.rec(v.ID)
	if !r.SelfUnrecorded || r.SelfConflict || r.ServiceBallot != nil || r.ConflictEv || r.Ballot != nil || r.Self == nil || !r.problem() || r.capProblem() {
		t.Fatalf("%+v", r)
	}
	if !c.has("vote.self_unrecorded", v.ID) || c.hasKind("vote.conflict") || c.hasKind("vote.problem") || c.countKind("vote.self_mismatch") != 1 {
		t.Errorf("%v", c.h.Activities)
	}
	for _, a := range c.h.Activities {
		if a.Kind == "vote.self_mismatch" && (a.Priority != "high" || a.Ref != v.ID || !a.Feed) {
			t.Errorf("%+v", a)
		}
	}
	g := obj(t, c.app("vote.get", pairBody("svc", v.ID)))
	if !boolOf(g, "self_unrecorded") || boolOf(g, "self_conflict") || boolOf(g, "conflict_evidence") || boolOf(g, "confirm_pending") || !boolOf(g, "can_cast") {
		t.Errorf("vote.get %v", g)
	}
	// The same ballot shown again changes nothing the member is told.
	c.now = c.now.Add(11 * time.Minute)
	c.f.Check(c.session(), "svc", v.ID)
	c.answer(v, c.statuses()[1], shown, uint64(c.now.UnixMilli()), true)
	if c.countKind("vote.self_mismatch") != 1 || c.countKind("vote.self_unrecorded") != 1 || c.rec(v.ID).SelfLatest == nil {
		t.Errorf("a repeat: %v", c.h.Activities)
	}
	// A cast after it: the vault's own ballot meets the shown one.
	if _, err := c.cast(v, "yes"); err != nil {
		t.Fatal(err)
	}
	if r := c.rec(v.ID); !r.SelfConflict || r.Ballot.State != BallotSending || r.conflictEvidence() || !c.has("vote.self_conflict", v.ID) || c.countKind("vote.self_mismatch") != 1 {
		t.Errorf("after the cast: %+v %v", r.Ballot, c.h.Activities)
	}
	e := c.evidence(t, v.ID)
	if _, ok := e["self_ballot"]; !ok {
		t.Errorf("evidence %v", e)
	}
	if _, ok := e["self_ballot_latest"]; !ok {
		t.Errorf("evidence %v", e)
	}
	l := obj(t, c.app("vote.list", "{}"))
	if votes, _ := l.Array("votes"); len(votes) != 1 || !strings.Contains(string(votes[0]), `"self_unrecorded":true`) || !strings.Contains(string(votes[0]), `"self_conflict":true`) {
		t.Errorf("vote.list %s", votes)
	}
}

// 0.88.12: already_voted carrying a different ballot under the record's own
// vk sets self_conflict: audit vote.self_conflict, feed item
// vote.self_mismatch, no vote.conflict and no vote.problem; it is not
// conflict evidence. (GC #7991 E) The ballot keeps its state and is not
// sent again. A foreign ballot after it is conflict evidence.
func TestAlreadyVotedOwnVK(t *testing.T) {
	c := newCastEnv(t)
	v := c.open(1)
	shown := c.selfBallot(v, "no")
	c.cast(v, "yes")
	_, ids := c.casts()
	c.h.Reset()
	c.alreadyVoted(v, ids[0], shown, uint64(c.now.UnixMilli()))
	r := c.rec(v.ID)
	if r.Ballot.State != BallotSending || !r.Ballot.Stopped || !r.SelfConflict || r.SelfUnrecorded || r.Other != nil || r.conflictEvidence() || !r.problem() || r.capProblem() {
		t.Fatalf("%+v", r.Ballot)
	}
	before, _ := c.casts()
	c.tickAt(10 * time.Minute) // before the close: the schedule would send
	c.tickAt(40 * time.Minute)
	if after, _ := c.casts(); len(after) != len(before) {
		t.Error("sent again after already_voted with an own-vk ballot")
	}
	if !c.has("vote.self_conflict", v.ID) || c.hasKind("vote.conflict") || c.hasKind("vote.problem") || c.countKind("vote.self_mismatch") != 1 {
		t.Errorf("%v", c.h.Activities)
	}
	g := obj(t, c.app("vote.get", pairBody("svc", v.ID)))
	if !boolOf(g, "self_conflict") || boolOf(g, "conflict_evidence") {
		t.Errorf("vote.get %v", g)
	}
	// A foreign ballot after it is conflict evidence.
	_, vk2, _ := ed25519.GenerateKey(rand.Reader)
	c.f.Check(c.session(), "svc", v.ID)
	c.answer(v, c.statuses()[0], must(votewire.SignBallot(vk2, v.Hash, v.Tag, "no")), uint64(c.rec(v.ID).Opens*1000+1), true)
	if r := c.rec(v.ID); !r.conflictEvidence() || !c.has("vote.conflict", v.ID) || !r.capProblem() {
		t.Errorf("foreign after self: %+v", r)
	}
}

// 0.88.12: after a restore the confirm prompt for a ballot under the
// record's own vk is unchanged (no self flags).
func TestRestorePromptUnchangedByOwnVKRule(t *testing.T) {
	c := newCastEnv(t)
	v := c.open(1)
	c.f.TransferCompleted(c.session(), "old", "new")
	c.f.Tick(c.session())
	c.answer(v, c.statuses()[0], c.selfBallot(v, "no"), uint64(c.now.UnixMilli()), true)
	if r := c.rec(v.ID); r.ServiceBallot == nil || r.SelfUnrecorded || r.SelfConflict || c.hasKind("vote.self_mismatch") {
		t.Errorf("%+v", r)
	}
}

// 0.88.12 ("A proposal the vault was never sent"; GC #7991 A): a status
// answer that carries a ballot keeps the proposal with conflict evidence
// (one vote.conflict, one vote.problem) and the answer in vote.evidence,
// after a restore too: there is no prompt for a proposal never held.
func TestStatusBallotForAProposalNeverSent(t *testing.T) {
	_, svk, _ := ed25519.GenerateKey(rand.Reader)
	for _, restore := range []bool{false, true} {
		c := newCastEnv(t)
		if restore {
			c.f.RecoveryCompleted(c.session())
		}
		v := c.unheld(5)
		body := `{"entries":[{"proposal_id":"` + v.ID + `","document":` + c.foundDoc(v, "", "") + `}]}`
		if got := c.syncResults(t, "entries", body); len(got) != 1 || !strings.HasSuffix(got[0], ":kept") {
			t.Fatalf("%v", got)
		}
		ids := c.statuses()
		c.answer(v, ids[len(ids)-1], must(votewire.SignBallot(svk, v.Hash, v.Tag, "no")), uint64(c.now.UnixMilli()), true)
		r := c.rec(v.ID)
		if r == nil || !r.ConflictEv || r.Other == nil || r.ServiceBallot != nil || c.countKind("vote.conflict") != 1 || c.problems(v.ID) != 1 || len(r.StatusAnswers) != 1 {
			t.Fatalf("restore %v: %+v", restore, r)
		}
		if arr, _ := c.evidence(t, v.ID).Array("status_answers"); len(arr) != 1 {
			t.Errorf("restore %v: status answers in evidence: %d", restore, len(arr))
		}
		if _, err := c.cast(v, "yes"); err != nil {
			t.Errorf("restore %v: casting stays allowed: %v", restore, err)
		}
	}
}
