package vote

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/votetest"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/strictjson"
	"github.com/vettid/vettid-vault/vms/suite"
	"github.com/vettid/vettid-vault/vms/votewire"
)

// BALLOT-PROTOCOL 0.15.0 §4.2: the vault's checks of v2 status answers and
// refusals (VAULT-MESSAGING §10.19.5).

func zeroHash(o *refOpts)            { o.hash = votewire.NoProposal() }
func hashOf(h []byte) func(*refOpts) { return func(o *refOpts) { o.hash = h } }
func msgAt(ms uint64) func(*refOpts) { return func(o *refOpts) { o.msgMS = ms } }

// pending makes id a pending request again (an answer takes it away,
// whether or not it counts).
func (c *cenv) pending(id, kind string, v *votetest.Vote) {
	c.f.pend[id] = pendRef{conn: "svc", id: v.ID, kind: kind}
}

func (c *cenv) depositsOnly(id string, ms ...int64) {
	c.untimed = true
	if c.h.Deposits == nil {
		c.h.Deposits = map[string][]int64{}
	}
	c.h.Deposits[id] = ms
}

// A cast refusal timed at no deposit of the request the relay told the
// vault of (none: the deposit's answer was lost; or another time) is no
// answer: final or not, nothing changes and nothing is kept. Timed at one
// of the request's deposits (retries kept), it counts.
func TestV2CastRefusalMustBeTimedAtADeposit(t *testing.T) {
	c := newCastEnv(t)
	v := c.open(1)
	c.cast(v, "yes")
	_, ids := c.casts()
	before := c.state(v)
	now := uint64(c.now.UnixMilli())
	for name, deps := range map[string][]int64{"lost": nil, "another time": {int64(now) - 1, int64(now) + 1}} {
		c.depositsOnly(ids[0], deps...)
		c.pending(ids[0], "cast", v)
		c.refusal(v, ids[0], "vote.cast", "not_active", votewire.H(c.leafOf(v)), msgAt(now))
		if c.state(v) != before || len(c.rec(v.ID).Ballot.Refusals) != 0 {
			t.Errorf("%s: %s, %d refusals kept", name, c.state(v), len(c.rec(v.ID).Ballot.Refusals))
		}
	}
	// The second of the request's deposits (a retry) is a time it may name.
	c.depositsOnly(ids[0], int64(now)-5000, int64(now))
	c.pending(ids[0], "cast", v)
	c.refusal(v, ids[0], "vote.cast", "not_active", votewire.H(c.leafOf(v)), msgAt(now))
	if c.state(v) != "refused:not_active" {
		t.Errorf("timed at a retry's deposit: %s", c.state(v))
	}
}

// (§4.2, §8.3) A cast refusal under the zero hash is kept and shown, not
// evidence, and the ballot goes on as it was; under another non-zero hash
// it is evidence (a refusal signed for another version under this id),
// the ballot as it was. The zero hash with another code does not verify.
func TestV2CastRefusalOtherHashes(t *testing.T) {
	c := newCastEnv(t)
	v := c.open(1)
	c.cast(v, "yes")
	_, ids := c.casts()
	before := c.state(v)
	leaf := votewire.H(c.leafOf(v))
	c.pending(ids[0], "cast", v)
	c.refusal(v, ids[0], "vote.cast", "closed", leaf, zeroHash)
	if c.state(v) != before || len(c.rec(v.ID).Ballot.Refusals) != 0 {
		t.Fatalf("a zero hash with closed: %s", c.state(v))
	}
	c.pending(ids[0], "cast", v)
	c.refusal(v, ids[0], "vote.cast", "not_eligible", leaf, zeroHash)
	r := c.rec(v.ID)
	if c.state(v) != before || len(r.Ballot.Refusals) != 1 || r.RefusalProblem || c.has("vote.problem", v.ID) {
		t.Fatalf("the zero hash: %s, %d kept, problem %v", c.state(v), len(r.Ballot.Refusals), r.RefusalProblem)
	}
	other := votewire.H([]byte("another version of the proposal"))
	c.pending(ids[0], "cast", v)
	c.refusal(v, ids[0], "vote.cast", "not_eligible", leaf, hashOf(other))
	if c.state(v) != before || len(r.Ballot.Refusals) != 2 || !r.RefusalProblem || !c.has("vote.problem", v.ID) {
		t.Fatalf("another hash: %s, %d kept, problem %v", c.state(v), len(r.Ballot.Refusals), r.RefusalProblem)
	}
}

// A status answer timed at no deposit of its request is no answer; a
// status refusal likewise.
func TestV2StatusMustBeTimedAtADeposit(t *testing.T) {
	c := newCastEnv(t)
	v := c.open(1)
	c.cast(v, "yes")
	c.f.Check(c.session(), "svc", v.ID)
	sid := c.statuses()[0]
	for name, deps := range map[string][]int64{"lost": nil, "another time": {c.now.UnixMilli() - 1}} {
		c.depositsOnly(sid, deps...)
		c.pending(sid, "status", v)
		c.answer(v, sid, nil, 0, false)
		c.pending(sid, "status", v)
		c.refusal(v, sid, "vote.status", "not_eligible", votewire.H([]byte(v.ID)))
		r := c.rec(v.ID)
		if len(r.StatusAnswers) != 0 || r.RefusalProblem {
			t.Errorf("%s: %d kept, problem %v", name, len(r.StatusAnswers), r.RefusalProblem)
		}
	}
	c.depositsOnly(sid, c.now.UnixMilli())
	c.pending(sid, "status", v)
	c.answer(v, sid, nil, 0, false)
	if len(c.rec(v.ID).StatusAnswers) != 1 {
		t.Error("an answer timed at the deposit was not kept")
	}
}

// A status refusal under the zero hash is kept, not evidence; under the
// held proposal's hash it is (a signed not_eligible), and under another
// non-zero hash too.
func TestV2StatusRefusalHashes(t *testing.T) {
	for _, tc := range []struct {
		name    string
		opt     func(*refOpts)
		problem bool
	}{
		{"zero", zeroHash, false},
		{"held", func(*refOpts) {}, true},
		{"other", hashOf(votewire.H([]byte("other"))), true},
	} {
		c := newCastEnv(t)
		v := c.open(1)
		c.f.Check(c.session(), "svc", v.ID)
		sid := c.statuses()[0]
		c.pending(sid, "status", v)
		c.refusal(v, sid, "vote.status", "unknown_proposal", votewire.H([]byte(v.ID)), tc.opt)
		r := c.rec(v.ID)
		if len(r.StatusAnswers) != 1 || r.RefusalProblem != tc.problem || c.has("vote.problem", v.ID) != tc.problem {
			t.Errorf("%s: %d kept, problem %v", tc.name, len(r.StatusAnswers), r.RefusalProblem)
		}
	}
}

// A status answer signed for another connection (not H of any of the
// vault's identity keys) is no answer.
func TestV2StatusOtherConnection(t *testing.T) {
	c := newCastEnv(t)
	v := c.open(1)
	c.f.Check(c.session(), "svc", v.ID)
	sid := c.statuses()[0]
	conn := votewire.H([]byte("another vault's key"))
	ssig, _ := suite.Sign(c.svc.IK, votewire.LabelStatus, must(votewire.StatusMsg(v.Hash, conn, v.Tag, nil, c.statusMS())))
	own := base64.StdEncoding.EncodeToString(votewire.H(c.h.IK))
	body := bytes.Replace(c.statusBody(v, nil, 0, nil, ssig), []byte(own), []byte(base64.StdEncoding.EncodeToString(conn)), 1)
	c.respond(sid, "vote.status", &envelope.Inner{Status: envelope.StatusOK, Body: body})
	if len(c.rec(v.ID).StatusAnswers) != 0 {
		t.Error("an answer for another connection was kept")
	}
}

// (0.15.0) Answers stored before this release are kept, and the evidence
// export marks them "unverifiable (v1)" by position.
func TestV2EvidenceMarksV1Answers(t *testing.T) {
	c := newCastEnv(t)
	v := c.open(1)
	c.cast(v, "yes")
	r := c.rec(v.ID)
	v1Status := []byte(`{"proposal_id":"` + v.ID + `","status_sig":"AAAA"}`)
	v2Status := []byte(`{"proposal_id":"` + v.ID + `","status_msg_ms":1,"status_sig":"AAAA"}`)
	v1Refusal := []byte(`{"refusal_sig":"AAAA","msg_ms":1}`)
	unsigned := []byte(`{"refusal_sig":null,"msg_ms":1}`)
	r.StatusAnswers = [][]byte{v2Status, v1Status}
	r.Ballot.Refusals = [][]byte{v1Refusal, unsigned}
	ev := obj(t, c.app("vote.evidence", pairBody("svc", v.ID)))
	eo, _ := ev.Object("evidence")
	u, err := eo.Object("unverifiable_v1")
	if err != nil {
		t.Fatalf("no unverifiable_v1: %v", err)
	}
	if string(u["status_answers"]) != "[1]" || string(u["refusals"]) != "[0]" {
		t.Errorf("%s / %s", u["status_answers"], u["refusals"])
	}
	r.StatusAnswers, r.Ballot.Refusals = [][]byte{v2Status}, [][]byte{unsigned}
	ev = obj(t, c.app("vote.evidence", pairBody("svc", v.ID)))
	eo, _ = ev.Object("evidence")
	if eo.Has("unverifiable_v1") {
		t.Error("marked with no v1 answer")
	}
}

// unreachable are receipt times no extension can make valid: before the
// open, and past the original close plus the most an extension adds.
func unreachable(r *record) map[string]uint64 {
	return map[string]uint64{
		"before the open":     uint64((r.Opens - 3600) * 1000),
		"past the last close": uint64((r.OrigClose + votewire.MaxExtension + 3600) * 1000),
	}
}

// (VAULT-MESSAGING 0.81.3, 0.90.19) A status naming another ballot whose
// receipt time no extension can reach is conflict evidence at once, its
// receipt rejected at once: the results check then ends, it never waits
// for an extension.
func TestV2ForeignBallotOutsideAnyWindowInAStatus(t *testing.T) {
	probe := newCastEnv(t)
	for name := range unreachable(probe.rec(probe.open(1).ID)) {
		_, vk2, _ := ed25519.GenerateKey(rand.Reader)
		c, v := closedWith(t, func(c *cenv, v *votetest.Vote) {
			receipted(c, v)
			c.f.Check(c.session(), "svc", v.ID)
			other := must(votewire.SignBallot(vk2, v.Hash, v.Tag, "no"))
			c.answer(v, c.statuses()[0], other, unreachable(c.rec(v.ID))[name], true)
		})
		r := c.rec(v.ID)
		if r.Ballot.State != BallotRecorded || !r.ConflictEv || r.Other == nil || !c.has("vote.conflict", v.ID) || !r.problem() {
			t.Errorf("%s: %s, conflict %v, other %v", name, r.Ballot.State, r.ConflictEv, r.Other != nil)
		}
		if r.Other != nil && (!r.Other.Late || !r.Other.LateRejected) || r.asidePending() != 0 || !c.has("vote.receipt_rejected", v.ID) {
			t.Errorf("%s: the receipt not rejected at once (pending %d)", name, r.asidePending())
		}
		out, err := c.f.SubmitResults(c.session(), "svc", v.ID, c.resultsFor(v, resOpts{mine: c.ownBallot(v)}))
		if err != nil || out.State == CheckPending || !out.ConflictEvidence {
			t.Errorf("%s: the check %+v %v", name, out, err)
		}
	}
}

// The same for an already_voted refusal carrying another ballot.
func TestV2ForeignBallotOutsideAnyWindowInAlreadyVoted(t *testing.T) {
	probe := newCastEnv(t)
	for name := range unreachable(probe.rec(probe.open(1).ID)) {
		c, w := closedWith(t, func(c *cenv, w *votetest.Vote) {
			c.cast(w, "yes")
			_, ids := c.casts()
			now := uint64(c.now.UnixMilli())
			ballotMS := unreachable(c.rec(w.ID))[name]
			_, vk2, _ := ed25519.GenerateKey(rand.Reader)
			other := must(votewire.SignBallot(vk2, w.Hash, w.Tag, "no"))
			orsig, _ := suite.Sign(c.svc.IK, votewire.LabelReceipt, must(votewire.ReceiptMsg(w.Hash, must(other.Leaf()), ballotMS)))
			msg := must(votewire.RefusalMsg(w.Hash, w.ID, votewire.H(c.h.IK), w.Tag, "vote.cast", "already_voted", now, votewire.H(c.leafOf(w))))
			sig, _ := suite.Sign(c.svc.IK, votewire.LabelRefusal, msg)
			body := strictjson.NewBuilder().Base64("refusal_sig", sig).Base64("proposal_hash", w.Hash).Uint("msg_ms", now).Base64("connection", votewire.H(c.h.IK)).Base64("record_tag", w.Tag).
				Raw("ballot", strictjson.NewBuilder().Base64("vk", other.VK).String("choice_id", "no").Base64("ballot_sig", other.BallotSig).Bytes()).
				Uint("ballot_msg_ms", ballotMS).Base64("receipt_sig", orsig).Bytes()
			c.respond(ids[0], "vote.cast", &envelope.Inner{Status: envelope.StatusError, Error: &envelope.Error{Code: "already_voted"}, Body: body})
		})
		r := c.rec(w.ID)
		if r.Other == nil || !c.has("vote.conflict", w.ID) || !r.problem() || r.asidePending() != 0 {
			t.Errorf("%s: %s, other %v, pending %d", name, r.Ballot.State, r.Other != nil, r.asidePending())
		}
		out, err := c.f.SubmitResults(c.session(), "svc", w.ID, c.resultsFor(w, resOpts{mine: c.ownBallot(w)}))
		if err != nil || out.State == CheckPending {
			t.Errorf("%s: the check %+v %v", name, out, err)
		}
	}
}

// (§8.3 (c)) A cast refusal under another non-zero hash that comes after
// the ballot is final is still evidence; one under the held hash or the
// zero hash changes nothing then.
func TestV2LateRefusalUnderAnotherHash(t *testing.T) {
	c := newCastEnv(t)
	v := c.open(1)
	c.cast(v, "yes")
	_, ids := c.casts()
	c.okReceipt(v, ids[0], c.leafOf(v), uint64(c.now.UnixMilli()))
	leaf := votewire.H(c.leafOf(v))
	for _, opt := range []func(*refOpts){func(*refOpts) {}, zeroHash} {
		c.pending(ids[0], "cast", v)
		c.refusal(v, ids[0], "vote.cast", "not_eligible", leaf, opt)
	}
	r := c.rec(v.ID)
	if r.RefusalProblem || len(r.Ballot.Refusals) != 0 {
		t.Fatalf("held or zero hash after the receipt: problem %v, %d kept", r.RefusalProblem, len(r.Ballot.Refusals))
	}
	c.pending(ids[0], "cast", v)
	c.refusal(v, ids[0], "vote.cast", "no_such_code", leaf, hashOf(votewire.H([]byte("other"))))
	if r.RefusalProblem || len(r.Ballot.Refusals) != 0 {
		t.Fatal("an unknown code after the receipt was kept")
	}
	c.pending(ids[0], "cast", v)
	c.refusal(v, ids[0], "vote.cast", "not_eligible", leaf, hashOf(votewire.H([]byte("other"))))
	if r.Ballot.State != BallotRecorded || !r.RefusalProblem || len(r.Ballot.Refusals) != 1 {
		t.Errorf("another hash after the receipt: %s, problem %v, %d kept", r.Ballot.State, r.RefusalProblem, len(r.Ballot.Refusals))
	}
	// The same after a final refusal.
	c2 := newCastEnv(t)
	w := c2.open(1)
	c2.cast(w, "yes")
	_, ids2 := c2.casts()
	l2 := votewire.H(c2.leafOf(w))
	c2.refusal(w, ids2[0], "vote.cast", "not_active", l2)
	if c2.state(w) != "refused:not_active" {
		t.Fatalf("setup: %s", c2.state(w))
	}
	r2 := c2.rec(w.ID)
	n := len(r2.Ballot.Refusals)
	c2.pending(ids2[0], "cast", w)
	c2.refusal(w, ids2[0], "vote.cast", "not_eligible", l2, hashOf(votewire.H([]byte("other"))))
	if len(r2.Ballot.Refusals) != n+1 || c2.state(w) != "refused:not_active" {
		t.Errorf("another hash after a final refusal: %d kept, %s", len(r2.Ballot.Refusals), c2.state(w))
	}
}

// The other-proposal evidence needs a proposal the service signed, under
// the same id: a bad proposal_sig or another id is no answer.
func TestV2OtherProposalNeedsTheServicesSignatureAndTheID(t *testing.T) {
	for _, tc := range []string{"bad proposal_sig", "another id"} {
		c := newCastEnv(t)
		v := c.open(1)
		c.f.Check(c.session(), "svc", v.ID)
		sid := c.statuses()[0]
		id := v.ID
		if tc == "another id" {
			id = lid(77)
		}
		w := c.svc.NewVote(votetest.VoteSpec{ID: id, Opens: c.now.Add(-time.Hour), Closes: c.now.Add(5 * time.Hour)})
		if tc == "bad proposal_sig" {
			w.Sig = make([]byte, 64)
		}
		sig, _ := c.statusSigBy(c.svc.IK, w, nil)
		body := c.statusBody(w, nil, 0, nil, sig)
		if tc == "another id" { // the answer names ours, the proposal another
			body = bytes.Replace(body, []byte(`"proposal_id":"`+id+`"`), []byte(`"proposal_id":"`+v.ID+`"`), 1)
		}
		c.respond(sid, "vote.status", &envelope.Inner{Status: envelope.StatusOK, Body: body})
		if r := c.rec(v.ID); len(r.StatusAnswers) != 0 || r.RefusalProblem {
			t.Errorf("%s: %d kept, problem %v", tc, len(r.StatusAnswers), r.RefusalProblem)
		}
	}
}

// A status for a proposal not held whose proposal_id is not the proposal's
// own keeps nothing (status_sig does not cover proposal_id).
func TestV2IntakeStatusTiesTheIDToTheProposal(t *testing.T) {
	for _, guard := range []bool{false, true} {
		c := newCastEnv(t)
		c.open(1) // the service's connection
		w := c.svc.NewVote(votetest.VoteSpec{ID: lid(8), Opens: c.now.Add(-time.Hour), Closes: c.now.Add(time.Hour)})
		asked := lid(9)
		if !guard {
			asked = w.ID // control: the same answer under its own id is kept
		}
		c.f.RequestProposal(c.session(), "svc", asked, w.Doc)
		ids := c.statuses()
		sig, _ := c.statusSigBy(c.svc.IK, w, nil)
		body := bytes.Replace(c.statusBody(w, nil, 0, nil, sig), []byte(`"proposal_id":"`+w.ID+`"`), []byte(`"proposal_id":"`+asked+`"`), 1)
		c.respond(ids[len(ids)-1], "vote.status", &envelope.Inner{Status: envelope.StatusOK, Body: body})
		if kept := c.rec(w.ID) != nil; kept == guard {
			t.Errorf("answer naming %s for proposal %s: kept %v", asked, w.ID, kept)
		}
	}
}

// (finding: compact records) An evicted record exports its refusals with
// the v1 ones marked; a released one its refusals and status answers.
func TestV2CompactEvidenceMarksV1(t *testing.T) {
	v1 := []byte(`{"refusal_sig":"AAAA","msg_ms":1}`)
	v2 := []byte(`{"refusal_sig":"AAAA","proposal_hash":"AAAA","msg_ms":1}`)
	st := []byte(`{"proposal_id":"x","status_sig":"AAAA"}`)
	for _, released := range []bool{false, true} {
		c := &compact{Conn: "svc", ID: lid(1), Refusals: [][]byte{v2, v1}, StatusAnswers: [][]byte{st}, Released: released}
		o, err := strictjson.ParseObject(compactEvidence(c))
		if err != nil {
			t.Fatal(err)
		}
		u, err := o.Object("unverifiable_v1")
		if err != nil {
			t.Fatalf("released %v: no unverifiable_v1", released)
		}
		if string(u["refusals"]) != "[1]" {
			t.Errorf("released %v: refusals %s", released, u["refusals"])
		}
		if _, ok := u["status_answers"]; ok != released {
			t.Errorf("released %v: status_answers %s", released, u["status_answers"])
		}
	}
}

// A kept proof survives the honest answers that follow it, the clock
// moving between them (each v2 answer carries a fresh time and signature):
// an answer the same but for those is kept once, so the record's digest
// (what the member exported) does not change with each hourly answer.
func TestV2KeptEvidenceSurvivesRepeatedAnswers(t *testing.T) {
	c := newCastEnv(t)
	v := c.open(1)
	c.cast(v, "yes")
	c.f.Check(c.session(), "svc", v.ID)
	sid := c.statuses()[0]
	w := c.svc.NewVote(votetest.VoteSpec{ID: v.ID, Opens: c.now.Add(-time.Hour), Closes: c.now.Add(5 * time.Hour)})
	sig, _ := c.statusSigBy(c.svc.IK, w, nil)
	proof := c.statusBody(w, nil, 0, nil, sig)
	c.pending(sid, "status", v)
	c.respond(sid, "vote.status", &envelope.Inner{Status: envelope.StatusOK, Body: proof})
	r := c.rec(v.ID)
	if len(r.StatusAnswers) != 1 || !r.RefusalProblem {
		t.Fatalf("setup: %d kept, problem %v", len(r.StatusAnswers), r.RefusalProblem)
	}
	var digest []byte
	for i := 0; i < 2*votewire.MaxRefusalsKept; i++ {
		c.now = c.now.Add(time.Hour)
		c.pending(sid, "status", v)
		c.answer(v, sid, nil, 0, false)
		if i == 0 {
			digest = r.digest()
		}
	}
	if len(r.StatusAnswers) != 2 || !bytes.Equal(r.StatusAnswers[0], proof) {
		t.Errorf("%d kept, the proof first: %v", len(r.StatusAnswers), len(r.StatusAnswers) > 0 && bytes.Equal(r.StatusAnswers[0], proof))
	}
	if !bytes.Equal(digest, r.digest()) {
		t.Error("the digest changed with the same answer again")
	}
	// The same for refusals: a zero-hash refusal again at another time.
	_, ids := c.casts()
	for i := 0; i < 3; i++ {
		c.now = c.now.Add(time.Minute)
		c.pending(ids[0], "cast", v)
		c.depositsOnly(ids[0], c.now.UnixMilli())
		c.refusal(v, ids[0], "vote.cast", "not_eligible", votewire.H(c.leafOf(v)), zeroHash, msgAt(uint64(c.now.UnixMilli())))
	}
	if n := len(r.Ballot.Refusals); n != 1 {
		t.Errorf("the same zero-hash refusal kept %d times", n)
	}
}

// When the list is full, an answer that is not evidence never pushes out
// one that is; the oldest that is not evidence goes first.
func TestV2KeepNeverEvictsEvidence(t *testing.T) {
	r := &record{Proposal: []byte("held proposal")}
	ref := func(h byte) []byte { // a signed refusal under the hash h..h (0: the zero hash)
		return []byte(`{"refusal_sig":"AAAA","proposal_hash":"` + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{h}, 32)) + `","msg_ms":1}`)
	}
	var list [][]byte
	for i := 1; i <= votewire.MaxRefusalsKept; i++ {
		list, _ = r.keep(list, ref(byte(i)))
	}
	l2, added := r.keep(list, ref(0))
	if added || len(l2) != votewire.MaxRefusalsKept || !bytes.Equal(l2[0], ref(1)) {
		t.Fatalf("a non-evidence answer into a full list of evidence: added %v", added)
	}
	// Seven evidence and one zero-hash answer: a new evidence one pushes the
	// zero-hash one out, not the oldest evidence.
	list = append(list[1:], ref(0))
	l3, added := r.keep(list, ref(99))
	if !added || len(l3) != votewire.MaxRefusalsKept || !bytes.Equal(l3[0], ref(2)) || bytes.Equal(l3[len(l3)-2], ref(0)) {
		t.Errorf("evidence into a full list: added %v", added)
	}
	for _, x := range l3 {
		if bytes.Equal(x, ref(0)) {
			t.Error("the zero-hash answer kept over evidence")
		}
	}
	// The same answer but for the request's time and signature is held.
	if _, added := r.keep(l3, []byte(`{"refusal_sig":"BBBB","proposal_hash":"`+base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{99}, 32))+`","msg_ms":2}`)); added {
		t.Error("the same refusal at another time kept again")
	}
}

// A late refusal under another hash timed at no deposit of its request is
// no answer, as on the live path.
func TestV2LateRefusalMustBeTimed(t *testing.T) {
	c := newCastEnv(t)
	v := c.open(1)
	c.cast(v, "yes")
	_, ids := c.casts()
	c.okReceipt(v, ids[0], c.leafOf(v), uint64(c.now.UnixMilli()))
	c.pending(ids[0], "cast", v)
	c.depositsOnly(ids[0], c.now.UnixMilli()-1)
	c.refusal(v, ids[0], "vote.cast", "not_eligible", votewire.H(c.leafOf(v)), hashOf(votewire.H([]byte("other"))))
	if r := c.rec(v.ID); r.RefusalProblem || len(r.Ballot.Refusals) != 0 {
		t.Error("an untimed late refusal was kept")
	}
}

// What counts as evidence when the list is full: a status answer for the
// held proposal is evidence only with a ballot; another proposal, a stored
// v1 answer and a non-zero refusal hash are; a zero hash is not.
func TestV2EvidenceAnswer(t *testing.T) {
	held := []byte("held proposal")
	r := &record{Proposal: held}
	b64 := base64.StdEncoding.EncodeToString
	for body, want := range map[string]bool{
		`{"status_msg_ms":1,"proposal":"` + b64(held) + `","status_sig":"AAAA"}`:                        false,
		`{"status_msg_ms":1,"proposal":"` + b64(held) + `","ballot":{"vk":"AAAA"},"status_sig":"AAAA"}`: true,
		`{"status_msg_ms":1,"proposal":"` + b64([]byte("other")) + `","status_sig":"AAAA"}`:             true,
		`{"proposal":"` + b64(held) + `","status_sig":"AAAA"}`:                                          true, // v1
		`{"refusal_sig":"AAAA","proposal_hash":"` + b64(make([]byte, 32)) + `","msg_ms":1}`:             false,
		`{"refusal_sig":"AAAA","proposal_hash":"` + b64(bytes.Repeat([]byte{1}, 32)) + `","msg_ms":1}`:  true,
		`{"refusal_sig":"AAAA","msg_ms":1}`:                                                             true, // v1
		`{"refusal_sig":null,"msg_ms":1}`:                                                               false,
	} {
		if got := r.evidenceAnswer([]byte(body)); got != want {
			t.Errorf("%s: %v, want %v", body, got, want)
		}
	}
}
