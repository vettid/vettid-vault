package vote

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/internal/votetest"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/suite"
	"github.com/vettid/vettid-vault/vms/votewire"
)

// resultsFor builds the results document of v (rows: our member's row is
// `mine`, nil for an empty one; the others are empty), signed and anchored.
type resOpts struct {
	mine      *votewire.Ballot
	extra     []votewire.Signed
	badSig    bool
	tamper    func(r *votewire.Results)
	dupAt     *int // a copy of the member's leaf also at this index, and the proof taken there
	rowIndex  int  // added to the member's index in the proof
	tree      int  // added to the tree size of the proof
	otherBndl []byte
	others    []otherOpt // entries of other_rows
	stampAt   time.Time  // the bundle's t_tsa (zero: now)
}

// otherOpt is an entry of other_rows: the member's row published again at
// index at (choice "" with empty false: not placed in the tree, so its
// proof does not verify).
type otherOpt struct {
	at        int
	choice    string // any string, valid choice id or not
	empty     bool   // the entry is an empty row
	notInTree bool   // the tree keeps the other tag at that index
}

func (c *cenv) resultsFor(v *votetest.Vote, o resOpts) ResultsSubmit {
	c.t.Helper()
	leaves := make([][]byte, len(v.Tags))
	for i, tag := range v.Tags {
		leaves[i] = tag
		if i == v.Index && o.mine != nil {
			leaves[i] = must(o.mine.Leaf())
		}
	}
	proofAt := v.Index
	if o.dupAt != nil {
		leaves[*o.dupAt] = leaves[v.Index] // the service published the member's row twice
		proofAt = *o.dupAt
	}
	otherVK, otherSig := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 64)
	otherLeaf := func(oo otherOpt) []byte {
		if oo.empty {
			return v.Tag
		}
		return must(votewire.RowLeaf(v.Tag, otherVK, oo.choice, otherSig))
	}
	for _, oo := range o.others {
		if !oo.notInTree {
			leaves[oo.at] = otherLeaf(oo)
		}
	}
	tally := map[string]int64{"yes": 0, "no": 0, "abstain": 0}
	ballots := int64(0)
	if o.mine != nil {
		tally[o.mine.ChoiceID]++
		ballots++
	}
	exts := []votewire.Signed{}
	for _, e := range c.rec(v.ID).Exts {
		exts = append(exts, votewire.Signed{Doc: e.Doc, Sig: e.Sig})
	}
	exts = append(exts, o.extra...)
	res := &votewire.Results{V: 1, ProposalID: v.ID, Proposal: votewire.Signed{Doc: v.Doc, Sig: v.Sig}, Extensions: exts,
		RowsHash: votewire.H([]byte("rows")), RowsRoot: votewire.Root(leaves), Tally: tally,
		Counts: votewire.Counts{Eligible: int64(len(v.Tags)), Ballots: ballots}}
	if o.tamper != nil {
		o.tamper(res)
	}
	doc := must(votewire.EncodeDocument(res))
	sig, _ := suite.Sign(c.svc.IK, votewire.LabelResults, must(votewire.DocSigMsg(v.Hash, doc)))
	if o.badSig {
		sig = make([]byte, 64)
	}
	path := must(votewire.Proof(leaves, proofAt))
	in := ResultsSubmit{Results: doc, Sig: sig, Bundle: c.env.auth.Bundle(doc, c.svc.Anchor, c.now),
		Proof: &votewire.RecordProof{Index: uint64(proofAt + o.rowIndex), TreeSize: uint64(len(v.Tags) + o.tree), Path: path}}
	if o.otherBndl != nil {
		in.Bundle = o.otherBndl
	}
	if !o.stampAt.IsZero() {
		in.Bundle = c.env.auth.Bundle(doc, c.svc.Anchor, o.stampAt)
	}
	if o.mine != nil {
		in.Row = &votewire.RowBallot{VK: o.mine.VK, ChoiceID: o.mine.ChoiceID, BallotSig: o.mine.BallotSig}
	}
	for _, oo := range o.others {
		in.Others = append(in.Others, OtherRow{Empty: oo.empty, VK: otherVK, ChoiceID: oo.choice, BallotSig: otherSig,
			Proof: &votewire.RecordProof{Index: uint64(oo.at), TreeSize: uint64(len(v.Tags)), Path: must(votewire.Proof(leaves, oo.at))}})
	}
	return in
}

// closedWith returns a cenv, a vote that has closed and whose check is due,
// with the member's ballot set up by setup.
func closedWith(t *testing.T, setup func(c *cenv, v *votetest.Vote)) (*cenv, *votetest.Vote) {
	c := newCastEnv(t)
	v := c.open(1)
	if setup != nil {
		setup(c, v)
	}
	c.now = time.Unix(c.rec(v.ID).Closes, 0).Add(CheckDelay + time.Minute)
	c.f.Tick(c.session())
	return c, v
}

func receipted(c *cenv, v *votetest.Vote) {
	c.cast(v, "yes")
	_, ids := c.casts()
	c.okReceipt(v, ids[0], c.leafOf(v), uint64(c.now.UnixMilli()))
}

func TestResultsTable(t *testing.T) {
	_, vkOther, _ := ed25519.GenerateKey(rand.Reader)
	type tc struct {
		name   string
		setup  func(c *cenv, v *votetest.Vote)
		row    func(c *cenv, v *votetest.Vote) *votewire.Ballot
		state  string
		reason string
	}
	own := func(c *cenv, v *votetest.Vote) *votewire.Ballot { return c.ownBallot(v) }
	empty := func(*cenv, *votetest.Vote) *votewire.Ballot { return nil }
	other := func(c *cenv, v *votetest.Vote) *votewire.Ballot {
		return must(votewire.SignBallot(vkOther, v.Hash, v.Tag, "no"))
	}
	refused := func(c *cenv, v *votetest.Vote) {
		c.cast(v, "yes")
		_, ids := c.casts()
		c.refusal(v, ids[0], "vote.cast", "not_active", votewire.H(c.leafOf(v)))
	}
	sending := func(c *cenv, v *votetest.Vote) { c.cast(v, "yes") }
	conflictAfterReceipt := func(c *cenv, v *votetest.Vote) {
		receipted(c, v)
		r := c.rec(v.ID)
		c.f.foreign(c.session(), r, r.Ballot, &svcBallot{VK: vkOther[32:], ChoiceID: "no", BallotSig: make([]byte, 64)}, false)
	}
	for _, x := range []tc{
		{"receipt, exactly that ballot", receipted, own, CheckVerified, ""},
		{"receipt, row empty", receipted, empty, CheckFailed, "row_mismatch"},
		{"receipt, another ballot", receipted, other, CheckFailed, "row_mismatch"},
		{"no ballot, empty row", nil, empty, CheckVerified, ""},
		{"no ballot, a ballot in the row", nil, other, CheckFailed, "row_unexpected"},
		{"sending, the ballot", sending, own, CheckUnconfirmed, ""},
		{"sending, empty", sending, empty, CheckUnconfirmed, ""},
		{"verified refusal, empty", refused, empty, CheckVerified, ""},
		{"verified refusal, exactly the ballot", refused, own, CheckVerified, ""},
		{"verified refusal, another ballot", refused, other, CheckFailed, "row_mismatch"},
		{"conflict", func(c *cenv, v *votetest.Vote) { sending(c, v); c.rec(v.ID).Ballot.State = BallotConflict }, empty, CheckFailed, "conflict"},
		{"no ballot, a foreign ballot", func(c *cenv, v *votetest.Vote) { c.rec(v.ID).ConflictEv = true }, empty, CheckFailed, "conflict"},
		{"receipt, then a foreign ballot, row is the member's", conflictAfterReceipt, own, CheckVerified, ""},
		{"receipt, then a foreign ballot, row empty", conflictAfterReceipt, empty, CheckFailed, "row_mismatch"},
		{"receipt, then a foreign ballot, row another", conflictAfterReceipt, other, CheckFailed, "row_mismatch"},
		{"receipt, in conflict by already_voted", func(c *cenv, v *votetest.Vote) { receipted(c, v); c.rec(v.ID).Ballot.State = BallotConflict }, own, CheckFailed, "conflict"},
		{"no receipt, a foreign ballot, row is the member's", func(c *cenv, v *votetest.Vote) { sending(c, v); c.rec(v.ID).ConflictEv = true }, own, CheckFailed, "conflict"},
		{"disputed", func(c *cenv, v *votetest.Vote) { sending(c, v); c.rec(v.ID).Ballot.State = BallotDisputed }, own, CheckFailed, "disputed"},
		{"connection ended is no refusal", func(c *cenv, v *votetest.Vote) {
			sending(c, v)
			c.f.ConnectionRemoved(c.session(), "svc")
		}, other, CheckUnconfirmed, ""},
	} {
		c, v := closedWith(t, x.setup)
		in := c.resultsFor(v, resOpts{mine: x.row(c, v)})
		out, err := c.f.SubmitResults(c.session(), "svc", v.ID, in)
		if err != nil || out.State != x.state || out.Reason != x.reason {
			t.Errorf("%s: %+v %v", x.name, out, err)
			continue
		}
		r := c.rec(v.ID)
		if r.Check != x.state || r.Results == nil {
			t.Errorf("%s: not kept: %+v", x.name, r.Check)
		}
		switch x.state {
		case CheckFailed:
			if !c.has("vote.check_failed", v.ID+":"+x.reason) || !c.has("vote.problem", v.ID) || !r.problem() {
				t.Errorf("%s: %v", x.name, c.h.Activities)
			}
		case CheckVerified:
			if !c.has("vote.check_ok", v.ID) || !c.has("vote.result", v.ID) {
				t.Errorf("%s: %v", x.name, c.h.Activities)
			}
		case CheckUnconfirmed:
			if !c.has("vote.check_unconfirmed", v.ID) || !c.has("vote.result", v.ID) {
				t.Errorf("%s: %v", x.name, c.h.Activities)
			}
		}
		// A repeat for a final check is answered with that state.
		again, err := c.f.SubmitResults(c.session(), "svc", v.ID, in)
		if err != nil || again.State != x.state {
			t.Errorf("%s: repeat %+v", x.name, again)
		}
	}
}

// Contradictions under the service's signature and the verified anchor
// fail the check.
func TestResultsFailures(t *testing.T) {
	cases := map[string]func(c *cenv, v *votetest.Vote) resOpts{
		"a changed proposal": func(c *cenv, v *votetest.Vote) resOpts {
			return resOpts{tamper: func(r *votewire.Results) { r.Proposal.Sig = make([]byte, 64) }}
		},
		"tally missing a choice": func(c *cenv, v *votetest.Vote) resOpts {
			return resOpts{tamper: func(r *votewire.Results) { delete(r.Tally, "no") }}
		},
		"eligible differs from the proposal's": func(c *cenv, v *votetest.Vote) resOpts {
			return resOpts{tamper: func(r *votewire.Results) { r.Counts.Eligible++ }}
		},
		"a verifying proof at another index": func(c *cenv, v *votetest.Vote) resOpts {
			other := (v.Index + 1) % len(v.Tags)
			return resOpts{dupAt: &other}
		},
	}
	for name, mk := range cases {
		c, v := closedWith(t, nil)
		out, err := c.f.SubmitResults(c.session(), "svc", v.ID, c.resultsFor(v, mk(c, v)))
		if err != nil || out.State != CheckFailed || out.Reason != "results" {
			t.Errorf("%s: %+v %v", name, out, err)
		}
	}
}

// Input that does not verify is no answer: the check stays pending and a
// later correct submission is judged (H2).
func TestResultsNoAnswer(t *testing.T) {
	cases := map[string]func(c *cenv, v *votetest.Vote) resOpts{
		"results_sig": func(c *cenv, v *votetest.Vote) resOpts { return resOpts{badSig: true} },
		"row index":   func(c *cenv, v *votetest.Vote) resOpts { return resOpts{rowIndex: 1} },
		"tree size":   func(c *cenv, v *votetest.Vote) resOpts { return resOpts{tree: 1} },
		"rows_root": func(c *cenv, v *votetest.Vote) resOpts {
			return resOpts{tamper: func(r *votewire.Results) { r.RowsRoot = make([]byte, 32) }}
		},
		"a bundle for other results": func(c *cenv, v *votetest.Vote) resOpts {
			return resOpts{otherBndl: c.env.auth.Bundle([]byte(`{"x":1}`), c.svc.Anchor, c.now)}
		},
	}
	for name, mk := range cases {
		c, v := closedWith(t, nil)
		out, err := c.f.SubmitResults(c.session(), "svc", v.ID, c.resultsFor(v, mk(c, v)))
		if err != nil || out.State != CheckPending {
			t.Errorf("%s: %+v %v", name, out, err)
			continue
		}
		if c.rec(v.ID).Check == CheckFailed || c.has("vote.check_failed", "") || c.has("vote.problem", v.ID) {
			t.Errorf("%s: failed on input that does not verify", name)
		}
		// Unparseable bytes too; then the correct submission is judged.
		if out, _ := c.f.SubmitResults(c.session(), "svc", v.ID, ResultsSubmit{Results: []byte("not json")}); out.State != CheckPending {
			t.Errorf("%s: garbage: %+v", name, out)
		}
		out, _ = c.f.SubmitResults(c.session(), "svc", v.ID, c.resultsFor(v, resOpts{}))
		if out.State != CheckVerified {
			t.Errorf("%s: the correct submission after: %+v", name, out)
		}
	}
}

func TestResultsMissingAHeldExtension(t *testing.T) {
	c := newCastEnv(t)
	v := c.open(1)
	closes := time.Unix(c.rec(v.ID).Closes, 0)
	_, msg := c.svc.Extension(v, 1, closes.Add(time.Hour), c.now)
	if r := c.call("vote.extended", msg); !r.OK() {
		t.Fatal(r.Code)
	}
	c.now = closes.Add(time.Hour + CheckDelay + time.Minute)
	c.f.Tick(c.session())
	in := c.resultsFor(v, resOpts{tamper: func(r *votewire.Results) { r.Extensions = r.Extensions[:0] }})
	if out, _ := c.f.SubmitResults(c.session(), "svc", v.ID, in); out.State != CheckFailed || out.Reason != "results" {
		t.Errorf("%+v", out)
	}
}

func TestResultsBundleAndPreconditions(t *testing.T) {
	// Not closed: bad_request. Checking: bad_request.
	c := newCastEnv(t)
	v := c.open(1)
	if _, err := c.f.SubmitResults(c.session(), "svc", v.ID, c.resultsFor(v, resOpts{})); code(err) != "bad_request" {
		t.Errorf("open: %q", code(err))
	}
	if _, err := c.f.SubmitResults(c.session(), "svc", lid(99), ResultsSubmit{}); code(err) != "not_found" {
		t.Errorf("unknown: %q", code(err))
	}
	// A bundle for another document under the accepted key: failed (anchor).
	c, v = closedWith(t, nil)
	bad := c.env.auth.Bundle([]byte(`{"x":1}`), c.svc.Anchor, c.now)
	out, _ := c.f.SubmitResults(c.session(), "svc", v.ID, c.resultsFor(v, resOpts{otherBndl: bad}))
	if out.State != CheckPending {
		t.Errorf("a bundle for other bytes: %+v", out)
	}
	// Out-of-date roots: pending (trust_root), nothing changes; the check
	// can be made later.
	c, v = closedWith(t, nil)
	roots := c.f.opt.Roots
	c.f.opt.Roots = votetest.NewAuthority(c.now).Roots
	out, _ = c.f.SubmitResults(c.session(), "svc", v.ID, c.resultsFor(v, resOpts{}))
	if out.State != CheckPending || out.Reason != ReasonTrustRoot || c.rec(v.ID).Check == CheckFailed {
		t.Errorf("roots: %+v", out)
	}
	c.f.opt.Roots = roots
	if out, _ = c.f.SubmitResults(c.session(), "svc", v.ID, c.resultsFor(v, resOpts{})); out.State != CheckVerified {
		t.Errorf("later: %+v", out)
	}
}

func TestResultsAdoptsAnExtensionItLacks(t *testing.T) {
	c := newCastEnv(t)
	v := c.open(1)
	closes := time.Unix(c.rec(v.ID).Closes, 0)
	// An extension the vault never received.
	doc, _ := c.svc.Extension(v, 1, closes.Add(time.Hour), c.now)
	extra := votewire.Signed{Doc: doc, Sig: signExt(c.svc, v, doc)}
	c.now = closes.Add(time.Hour + CheckDelay + time.Minute)
	c.f.Tick(c.session())
	out, err := c.f.SubmitResults(c.session(), "svc", v.ID, c.resultsFor(v, resOpts{extra: []votewire.Signed{extra}}))
	if err != nil || out.State != CheckVerified {
		t.Fatalf("%+v %v", out, err)
	}
	if len(c.rec(v.ID).Exts) != 1 || c.rec(v.ID).Closes != closes.Add(time.Hour).Unix() {
		t.Errorf("not adopted: %+v", c.rec(v.ID).Exts)
	}
	// An extension with a bad signature is a failure.
	c2 := newCastEnv(t)
	w := c2.open(1)
	cl := time.Unix(c2.rec(w.ID).Closes, 0)
	d2, _ := c2.svc.Extension(w, 1, cl.Add(time.Hour), c2.now)
	c2.now = cl.Add(time.Hour + CheckDelay + time.Minute)
	c2.f.Tick(c2.session())
	out, _ = c2.f.SubmitResults(c2.session(), "svc", w.ID, c2.resultsFor(w, resOpts{extra: []votewire.Signed{{Doc: d2, Sig: make([]byte, 64)}}}))
	if out.State != CheckFailed {
		t.Errorf("%+v", out)
	}
}

func TestResultsHashIsEvidenceOnly(t *testing.T) {
	c, v := closedWith(t, nil)
	c.call("vote.closed", []byte(`{"proposal_id":"`+v.ID+`","results_hash":"`+e64(make([]byte, 32))+`"}`))
	out, _ := c.f.SubmitResults(c.session(), "svc", v.ID, c.resultsFor(v, resOpts{}))
	if out.State != CheckVerified || c.rec(v.ID).ResultsMatch != "no" {
		t.Errorf("%+v %q", out, c.rec(v.ID).ResultsMatch)
	}
}

// A recorded ballot with conflict evidence whose row verifies is `verified`
// with the conflict carried beside it: the flag in vote.get and in the
// outcome, the record in the problem set, vote.problem raised once.
func TestVerifiedWithConflictEvidence(t *testing.T) {
	_, vkOther, _ := ed25519.GenerateKey(rand.Reader)
	c, v := closedWith(t, func(c *cenv, v *votetest.Vote) {
		receipted(c, v)
		r := c.rec(v.ID)
		sb := &svcBallot{VK: vkOther[32:], ChoiceID: "no", BallotSig: make([]byte, 64)}
		c.f.foreign(c.session(), r, r.Ballot, sb, false)
		c.f.foreign(c.session(), r, r.Ballot, sb, false)
	})
	if c.count("vote.problem") != 1 || c.count("vote.conflict") != 1 {
		t.Errorf("raised %d %d", c.count("vote.problem"), c.count("vote.conflict"))
	}
	out, err := c.f.SubmitResults(c.session(), "svc", v.ID, c.resultsFor(v, resOpts{mine: c.ownBallot(v)}))
	if err != nil || out.State != CheckVerified || !out.ConflictEvidence {
		t.Fatalf("%+v %v", out, err)
	}
	r := c.rec(v.ID)
	if !r.problem() || r.Other == nil {
		t.Error("not in the problem set, or the foreign ballot dropped")
	}
	if c.count("vote.problem") != 1 {
		t.Errorf("vote.problem again: %d", c.count("vote.problem"))
	}
	o := obj(t, c.app("vote.get", pairBody("svc", v.ID)))
	rec, _ := o.Object("proposal")
	if rec == nil {
		rec = o
	}
	if !boolOf(rec, "conflict_evidence") {
		t.Errorf("vote.get: %v", o)
	}
	if c.rec(v.ID).Ballot.State != BallotRecorded {
		t.Error("the recorded ballot left `recorded`")
	}
	lo := obj(t, c.app("vote.list", `{}`))
	vs, _ := lo.Array("votes")
	if len(vs) != 1 {
		t.Fatalf("votes %d", len(vs))
	}
	if eo, _ := strictjson.AsObject(vs[0]); eo == nil || !boolOf(eo, "conflict_evidence") {
		t.Errorf("vote.list: %s", vs[0])
	}
	ev := obj(t, c.app("vote.evidence", pairBody("svc", v.ID)))
	if e, _ := ev.Object("evidence"); e == nil || !e.Has("other_ballot") || !e.Has("other_ballot_latest") {
		t.Errorf("the evidence lacks the foreign ballots: %v", ev)
	}
}

func boolOf(o strictjson.Object, k string) bool { v, _ := o.Bool(k); return v }

// A gave_up check is not final (0.83.6, owner decision a): it makes one
// vote.result item, a submission that does not verify leaves it gave_up, and
// a verifying one is judged and takes the record out of the problem set.
func TestGaveUpIsCheckedAgain(t *testing.T) {
	c, v := closedWith(t, receipted)
	// The results as published when the check was due; the member's app
	// only gets to them after the vault gave up.
	good := c.resultsFor(v, resOpts{mine: c.ownBallot(v)})
	r := c.rec(v.ID)
	c.now = r.dueAt().Add(CheckGiveUp + time.Second)
	c.f.Tick(c.session())
	if r = c.rec(v.ID); r.Check != CheckGaveUp || !r.problem() {
		t.Fatalf("%q problem=%v", r.Check, r.problem())
	}
	results := func() (n int) {
		for _, a := range c.h.Activities {
			if a.Kind == "vote.result" && a.Ref == v.ID {
				n++
			}
		}
		return
	}
	if results() != 1 {
		t.Fatalf("%d vote.result items at gave_up", results())
	}
	c.f.Tick(c.session())
	if results() != 1 {
		t.Fatal("the gave_up item came twice")
	}
	bad := c.resultsFor(v, resOpts{mine: c.ownBallot(v), badSig: true})
	out, err := c.f.SubmitResults(c.session(), "svc", v.ID, bad)
	if err != nil || out.State != CheckGaveUp || out.Reason != "input" || c.rec(v.ID).Check != CheckGaveUp {
		t.Fatalf("no answer: %+v %v", out, err)
	}
	out, err = c.f.SubmitResults(c.session(), "svc", v.ID, good)
	if err != nil || out.State != CheckVerified {
		t.Fatalf("late check: %+v %v", out, err)
	}
	if r = c.rec(v.ID); r.Check != CheckVerified || r.problem() || !c.has("vote.check_ok", v.ID) {
		t.Fatalf("%q problem=%v", r.Check, r.problem())
	}
}

// 0.88.12 (GC #1344): the results' bundle is stamped at or after the close
// in force once the results' extensions are adopted; an earlier stamp is
// `failed` (results), judged before the extra rows.
func TestResultsAnchoredBeforeTheClose(t *testing.T) {
	submit := func(c *cenv, v *votetest.Vote, o resOpts) CheckOutcome {
		t.Helper()
		out, err := c.f.SubmitResults(c.session(), "svc", v.ID, c.resultsFor(v, o))
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	c, v := closedWith(t, receipted)
	closes := time.Unix(c.rec(v.ID).Closes, 0)
	if out := submit(c, v, resOpts{mine: c.ownBallot(v), stampAt: closes.Add(-time.Second)}); out.State != CheckFailed || out.Reason != "results" ||
		!c.has("vote.check_failed", v.ID+":results") || !c.has("vote.problem", v.ID) {
		t.Errorf("1 s before the close: %+v", out)
	}
	c, v = closedWith(t, receipted)
	if out := submit(c, v, resOpts{mine: c.ownBallot(v), stampAt: time.Unix(c.rec(v.ID).Closes, 0)}); out.State != CheckVerified {
		t.Errorf("at the close: %+v", out)
	}
	// With an extension adopted from the results the bound is the extended
	// close: a stamp between the original and the extended close fails.
	ext := func() (*cenv, *votetest.Vote, votewire.Signed, time.Time) {
		c := newCastEnv(t)
		v := c.open(1)
		closes := time.Unix(c.rec(v.ID).Closes, 0)
		doc, _ := c.svc.Extension(v, 1, closes.Add(time.Hour), c.now)
		c.now = closes.Add(time.Hour + CheckDelay + time.Minute)
		c.f.Tick(c.session())
		return c, v, votewire.Signed{Doc: doc, Sig: signExt(c.svc, v, doc)}, closes
	}
	c, v, x, orig := ext()
	if out := submit(c, v, resOpts{extra: []votewire.Signed{x}, stampAt: orig.Add(30 * time.Minute)}); out.State != CheckFailed || out.Reason != "results" {
		t.Errorf("between the original and the extended close: %+v", out)
	}
	if len(c.rec(v.ID).Exts) != 0 {
		t.Error("a failed submission adopted its extension")
	}
	c, v, x, orig = ext()
	if out := submit(c, v, resOpts{extra: []votewire.Signed{x}, stampAt: orig.Add(time.Hour)}); out.State != CheckVerified || len(c.rec(v.ID).Exts) != 1 {
		t.Errorf("at the extended close: %+v", out)
	}
	// Precedence: an early stamp (a contradiction in the results) wins over
	// row_duplicate and over a rows_unavailable claim.
	c, v = closedWith(t, receipted)
	early := time.Unix(c.rec(v.ID).Closes, 0).Add(-time.Second)
	if out := submit(c, v, resOpts{mine: c.ownBallot(v), stampAt: early, others: []otherOpt{{at: notMine(v, 0), choice: "no"}}}); out.Reason != "results" {
		t.Errorf("against row_duplicate: %+v", out)
	}
	c, v = closedWith(t, nil)
	in := c.resultsFor(v, resOpts{stampAt: time.Unix(c.rec(v.ID).Closes, 0).Add(-time.Second)})
	in.Row, in.Proof, in.RowsUnavailable = nil, nil, true
	if out, _ := c.f.SubmitResults(c.session(), "svc", v.ID, in); out.State != CheckFailed || out.Reason != "results" {
		t.Errorf("against rows_unavailable: %+v", out)
	}
}

// selfBallot is a ballot signed under the record's own voting key (its seed
// still held), not the vault's own: a rollback's or a leaked seed's.
func (c *cenv) selfBallot(v *votetest.Vote, choice string) *votewire.Ballot {
	c.t.Helper()
	return must(votewire.SignBallot(ed25519.NewKeyFromSeed(c.rec(v.ID).VKSeed), v.Hash, v.Tag, choice))
}

// 0.88.12: the results check of self_unrecorded and self_conflict is
// `unconfirmed` for a row that is exactly the receipted own-vk ballot and
// `failed` (row_mismatch) for any other row; with the vault's own receipt
// for a different ballot as well, `failed` (row_mismatch) whatever the row.
func TestResultsSelfRows(t *testing.T) {
	var shown *votewire.Ballot
	// The service shows, in a status answer, an own-vk ballot "no".
	showStatus := func(c *cenv, v *votetest.Vote) {
		shown = c.selfBallot(v, "no")
		c.now = c.now.Add(11 * time.Minute)
		c.f.Check(c.session(), "svc", v.ID)
		ids := c.statuses()
		c.answer(v, ids[len(ids)-1], shown, uint64(c.now.UnixMilli()), true)
	}
	unrecorded := func(c *cenv, v *votetest.Vote) {
		showStatus(c, v)
		if !c.rec(v.ID).SelfUnrecorded {
			t.Fatal("not self_unrecorded")
		}
	}
	unrecordedThenCast := func(c *cenv, v *votetest.Vote) {
		unrecorded(c, v)
		c.cast(v, "yes")
		if !c.rec(v.ID).SelfConflict {
			t.Fatal("a cast after self_unrecorded is not self_conflict")
		}
	}
	receiptedThenShown := func(c *cenv, v *votetest.Vote) {
		shown = c.selfBallot(v, "no") // before the receipt erases the seed
		receipted(c, v)
		c.f.Check(c.session(), "svc", v.ID)
		c.answer(v, c.statuses()[0], shown, uint64(c.now.UnixMilli()), true)
		if r := c.rec(v.ID); !r.SelfConflict || r.Ballot.State != BallotRecorded || !r.TwoReceipts || !r.capProblem() || c.problems(v.ID) != 1 {
			t.Fatal("not self_conflict with two receipts")
		}
	}
	alreadyVoted := func(c *cenv, v *votetest.Vote) {
		shown = c.selfBallot(v, "no")
		c.cast(v, "yes")
		_, ids := c.casts()
		c.alreadyVoted(v, ids[0], shown, uint64(c.now.UnixMilli()))
		if r := c.rec(v.ID); !r.SelfConflict || r.Ballot.State != BallotSending {
			t.Fatal("not self_conflict")
		}
	}
	_, vkOther, _ := ed25519.GenerateKey(rand.Reader)
	rowShown := func(*cenv, *votetest.Vote) *votewire.Ballot { return shown }
	rowOwn := func(c *cenv, v *votetest.Vote) *votewire.Ballot { return c.ownBallot(v) }
	rowEmpty := func(*cenv, *votetest.Vote) *votewire.Ballot { return nil }
	rowOther := func(c *cenv, v *votetest.Vote) *votewire.Ballot {
		return must(votewire.SignBallot(vkOther, v.Hash, v.Tag, "no"))
	}
	for _, x := range []struct {
		name   string
		setup  func(c *cenv, v *votetest.Vote)
		row    func(c *cenv, v *votetest.Vote) *votewire.Ballot
		state  string
		reason string
	}{
		{"self_unrecorded, the receipted own-vk ballot", unrecorded, rowShown, CheckUnconfirmed, ""},
		{"self_unrecorded, empty", unrecorded, rowEmpty, CheckFailed, "row_mismatch"},
		{"self_unrecorded, another", unrecorded, rowOther, CheckFailed, "row_mismatch"},
		{"self_unrecorded then cast, the shown ballot", unrecordedThenCast, rowShown, CheckUnconfirmed, ""},
		{"self_unrecorded then cast, the vault's own", unrecordedThenCast, rowOwn, CheckFailed, "row_mismatch"},
		{"already_voted self_conflict, the shown ballot", alreadyVoted, rowShown, CheckUnconfirmed, ""},
		{"already_voted self_conflict, empty", alreadyVoted, rowEmpty, CheckFailed, "row_mismatch"},
		{"already_voted self_conflict, the vault's own", alreadyVoted, rowOwn, CheckFailed, "row_mismatch"},
		{"self_conflict and the vault's receipt, the shown ballot", receiptedThenShown, rowShown, CheckFailed, "row_mismatch"},
		{"self_conflict and the vault's receipt, its own", receiptedThenShown, rowOwn, CheckFailed, "row_mismatch"},
		{"self_conflict and the vault's receipt, empty", receiptedThenShown, rowEmpty, CheckFailed, "row_mismatch"},
	} {
		c, v := closedWith(t, x.setup)
		out, err := c.f.SubmitResults(c.session(), "svc", v.ID, c.resultsFor(v, resOpts{mine: x.row(c, v)}))
		if err != nil || out.State != x.state || out.Reason != x.reason || out.ConflictEvidence {
			t.Errorf("%s: %+v %v", x.name, out, err)
		}
	}
}

// 0.88.12: vote.closed is compared with the results in either order:
// results_hash_match in vote.evidence, and a "no" audited
// vote.results_conflict once, with no feed item and no change to the check.
func TestClosedComparedInEitherOrder(t *testing.T) {
	closed := func(c *cenv, v *votetest.Vote, hash []byte) {
		t.Helper()
		body := strictjson.NewBuilder().String("proposal_id", v.ID).Base64("results_hash", hash).Bytes()
		if r := c.call("vote.closed", body); !r.OK() {
			t.Fatalf("vote.closed: %q", r.Code)
		}
	}
	for _, resultsFirst := range []bool{true, false} {
		for _, same := range []bool{true, false} {
			c, v := closedWith(t, receipted)
			in := c.resultsFor(v, resOpts{mine: c.ownBallot(v)})
			hash := votewire.H(in.Results)
			if !same {
				hash = votewire.H([]byte("other results"))
			}
			if !resultsFirst {
				closed(c, v, hash)
			}
			c.h.Reset()
			c.f.SubmitResults(c.session(), "svc", v.ID, in)
			if resultsFirst {
				closed(c, v, hash)
				closed(c, v, hash) // a repeat changes nothing
			}
			want := map[bool]string{true: "yes", false: "no"}[same]
			if m, _ := c.evidence(t, v.ID).String("results_hash_match"); m != want {
				t.Errorf("results first %v, same %v: results_hash_match %q", resultsFirst, same, m)
			}
			n := c.countKind("vote.results_conflict")
			if same && n != 0 || !same && n != 1 {
				t.Errorf("results first %v, same %v: %d vote.results_conflict", resultsFirst, same, n)
			}
			if r := c.rec(v.ID); r.Check != CheckVerified || c.problems(v.ID) != 0 {
				t.Errorf("results first %v, same %v: check %q, %d problems", resultsFirst, same, r.Check, c.problems(v.ID))
			}
		}
	}
}

// 0.88.12 and GC #7991 F: a kept-aside receipt still outside the window at
// a final judgement is audited vote.receipt_rejected, kept in vote.evidence
// (late_receipt) and raises vote.problem; the row check is unchanged by it.
// A gave_up or pending judgement is not final.
func TestReceiptAsideAtTheFinalJudgement(t *testing.T) {
	c, v := closedWith(t, func(c *cenv, v *votetest.Vote) {
		c.cast(v, "yes")
		_, ids := c.casts()
		c.okReceipt(v, ids[0], c.leafOf(v), uint64(time.Unix(c.rec(v.ID).Closes, 0).Add(time.Hour).UnixMilli()))
	})
	ru := c.resultsFor(v, resOpts{})
	ru.Row, ru.Proof, ru.RowsUnavailable = nil, nil, true
	c.f.SubmitResults(c.session(), "svc", v.ID, ru)
	if c.hasKind("vote.receipt_rejected") {
		t.Fatal("rejected at a pending judgement")
	}
	c.h.Reset()
	out, _ := c.f.SubmitResults(c.session(), "svc", v.ID, c.resultsFor(v, resOpts{}))
	if out.State != CheckUnconfirmed || !c.has("vote.receipt_rejected", v.ID) || c.problems(v.ID) != 1 || !c.rec(v.ID).capProblem() {
		t.Errorf("%+v %v", out, c.h.Activities)
	}
	lr, err := c.evidence(t, v.ID).Object("late_receipt")
	if err != nil || !boolOf(lr, "rejected") {
		t.Errorf("late_receipt: %v %v", lr, err)
	}
	if c.state(v) != BallotSending {
		t.Errorf("%s", c.state(v))
	}
	// Later hourly status answers carrying the same late receipt stay quiet
	// (review fix 2): no audit, no change, the export stays current.
	c.evidence(t, v.ID)
	changed := c.rec(v.ID).ChangedMS
	c.h.Reset()
	late := uint64(time.Unix(c.rec(v.ID).Closes, 0).Add(time.Hour).UnixMilli())
	// The service's answer is the same bytes each time (its proposal bundle
	// does not change).
	own := c.ownBallot(v)
	leaf := must(own.Leaf())
	rsig, _ := suite.Sign(c.svc.IK, votewire.LabelReceipt, must(votewire.ReceiptMsg(v.Hash, leaf, late)))
	ssig, _ := suite.Sign(c.svc.IK, votewire.LabelStatus, must(votewire.StatusMsg(v.ID, v.Tag, leaf)))
	body := c.statusBody(v, &votewire.RowBallot{VK: own.VK, ChoiceID: own.ChoiceID, BallotSig: own.BallotSig}, late, rsig, ssig)
	for i := 0; i < 3; i++ {
		c.now = c.now.Add(61 * time.Minute)
		n := len(c.statuses())
		c.f.Tick(c.session())
		st := c.statuses()
		if len(st) == n {
			t.Fatalf("round %d: no status asked", i)
		}
		c.respond(st[len(st)-1], "vote.status", &envelope.Inner{Status: envelope.StatusOK, Body: body})
		if i == 0 {
			if c.hasKind("vote.receipt_rejected") || c.problems(v.ID) != 0 {
				t.Errorf("the first later answer: %v", c.h.Activities)
			}
			c.evidence(t, v.ID) // the first one is new evidence; the export after it
			changed = c.rec(v.ID).ChangedMS
			c.h.Reset()
		}
	}
	if r := c.rec(v.ID); len(c.h.Activities) != 0 || r.ChangedMS != changed || !eq(r.EvidenceHash, r.digest()) {
		t.Errorf("later answers: %v changed %d->%d", c.h.Activities, changed, r.ChangedMS)
	}
}

// GC #7991 C, 7adc8fe: a shown ballot whose receipt is for an extension
// not learned yet is judged at once (here: foreign, a conflict) and only
// its receipt is kept aside, in vote.evidence, until a verified extension
// covers it.
func TestShownBallotKeptAside(t *testing.T) {
	c := newCastEnv(t)
	v := c.open(1)
	c.cast(v, "yes")
	_, ids := c.casts()
	_, vk2, _ := ed25519.GenerateKey(rand.Reader)
	closes := time.Unix(c.rec(v.ID).Closes, 0)
	c.alreadyVoted(v, ids[0], must(votewire.SignBallot(vk2, v.Hash, v.Tag, "no")), uint64(closes.Add(30*time.Minute).UnixMilli()))
	r := c.rec(v.ID)
	if r.Ballot.State != BallotConflict || !c.has("vote.conflict", v.ID) || !r.Other.Late {
		t.Fatalf("%+v", r.Other)
	}
	// Its receipt is inside other_ballot (review fix 6d).
	if ob, err := c.evidence(t, v.ID).Object("other_ballot"); err != nil || ob["receipt_sig"] == nil {
		t.Errorf("other_ballot %v %v", ob, err)
	}
	_, msg := c.svc.Extension(v, 1, closes.Add(time.Hour), c.now)
	c.call("vote.extended", msg)
	if r := c.rec(v.ID); r.Other.Late || c.countKind("vote.conflict") != 1 {
		t.Errorf("%+v", r.Other)
	}
}

// 7adc8fe: an own-vk ballot shown with a receipt kept aside is self_* at
// once; its receipt counts for two receipts only once a verified extension
// covers it (then vote.problem, once, and a failed check adds none); at a
// final judgement still aside, the row is judged as if it did not exist.
func TestLateSelfReceipt(t *testing.T) {
	late := func(c *cenv, v *votetest.Vote) *votewire.Ballot {
		shown := c.selfBallot(v, "no")
		c.f.Check(c.session(), "svc", v.ID)
		c.answer(v, c.statuses()[0], shown, uint64(time.Unix(c.rec(v.ID).Closes, 0).Add(30*time.Minute).UnixMilli()), true)
		return shown
	}
	// Still aside at the final judgement: no ballot, empty row: verified.
	c, v := closedWith(t, func(c *cenv, v *votetest.Vote) { late(c, v) })
	if r := c.rec(v.ID); !r.SelfUnrecorded || !r.Self.Late {
		t.Fatalf("%+v", r.Self)
	}
	out, _ := c.f.SubmitResults(c.session(), "svc", v.ID, c.resultsFor(v, resOpts{}))
	if out.State != CheckVerified || !c.has("vote.receipt_rejected", v.ID) {
		t.Errorf("%+v", out)
	}
	// Two receipts once the late one counts.
	c = newCastEnv(t)
	v = c.open(1)
	var shown *votewire.Ballot
	c.cast(v, "yes")
	shown = must(votewire.SignBallot(ed25519.NewKeyFromSeed(c.rec(v.ID).VKSeed), v.Hash, v.Tag, "no"))
	_, ids := c.casts()
	c.okReceipt(v, ids[0], c.leafOf(v), uint64(c.now.UnixMilli()))
	c.f.Check(c.session(), "svc", v.ID)
	closes := time.Unix(c.rec(v.ID).Closes, 0)
	c.answer(v, c.statuses()[0], shown, uint64(closes.Add(30*time.Minute).UnixMilli()), true)
	if r := c.rec(v.ID); !r.SelfConflict || r.TwoReceipts || c.problems(v.ID) != 0 {
		t.Fatalf("two receipts before the late one counts: %v", r.TwoReceipts)
	}
	_, msg := c.svc.Extension(v, 1, closes.Add(time.Hour), c.now)
	c.call("vote.extended", msg)
	if r := c.rec(v.ID); !r.TwoReceipts || c.problems(v.ID) != 1 || !r.capProblem() {
		t.Fatalf("two receipts: %v %d", r.TwoReceipts, c.problems(v.ID))
	}
	c.now = closes.Add(time.Hour + CheckDelay + time.Minute)
	c.f.Tick(c.session())
	if out, _ := c.f.SubmitResults(c.session(), "svc", v.ID, c.resultsFor(v, resOpts{mine: c.ownBallot(v)})); out.State != CheckFailed || out.Reason != "row_mismatch" || c.problems(v.ID) != 1 {
		t.Errorf("%+v problems %d", out, c.problems(v.ID))
	}
}

// GC #7991 G: a ballot under an earlier voting key of the record (a vote
// never cast, reopened by an extension, gets a fresh one) is own-vk.
func TestEarlierVoteKeyIsOwn(t *testing.T) {
	c := newCastEnv(t)
	v := c.open(1)
	old := ed25519.NewKeyFromSeed(append([]byte{}, c.rec(v.ID).VKSeed...))
	closes := time.Unix(c.rec(v.ID).Closes, 0)
	_, msg := c.svc.Extension(v, 1, closes.Add(time.Hour), closes.Add(-time.Minute))
	c.now = closes.Add(time.Second)
	c.f.Tick(c.session()) // closed: the seed of a vote never cast is erased
	if len(c.rec(v.ID).VKSeed) != 0 {
		t.Fatal("seed kept")
	}
	if r := c.call("vote.extended", msg); !r.OK() {
		t.Fatalf("%q", r.Code)
	}
	r := c.rec(v.ID)
	if len(r.OldVKs) != 1 || eq(r.VK, old.Public().(ed25519.PublicKey)) {
		t.Fatalf("no fresh key: %d", len(r.OldVKs))
	}
	c.f.Check(c.session(), "svc", v.ID)
	c.answer(v, c.statuses()[0], must(votewire.SignBallot(old, v.Hash, v.Tag, "no")), uint64(c.now.UnixMilli()), true)
	if r := c.rec(v.ID); !r.SelfUnrecorded || r.ConflictEv {
		t.Errorf("self %v conflict %v", r.SelfUnrecorded, r.ConflictEv)
	}
}

// GC #7991 B: disputed is tried first, then conflict evidence, then the
// self rows, then the rest; reached through the service's answers.
func TestVerdictOrder(t *testing.T) {
	_, vk2, _ := ed25519.GenerateKey(rand.Reader)
	var shown *votewire.Ballot
	foreignTo := func(c *cenv, v *votetest.Vote) {
		c.now = c.now.Add(11 * time.Minute)
		c.f.Check(c.session(), "svc", v.ID)
		st := c.statuses()
		c.answer(v, st[len(st)-1], must(votewire.SignBallot(vk2, v.Hash, v.Tag, "yes")), uint64(c.rec(v.ID).Opens*1000+1), true)
	}
	// Disputed, then a foreign ballot: disputed.
	c, v := closedWith(t, func(c *cenv, v *votetest.Vote) {
		shown = c.selfBallot(v, "no")
		c.f.TransferCompleted(c.session(), "old", "new")
		c.f.Tick(c.session())
		c.answer(v, c.statuses()[0], shown, uint64(c.now.UnixMilli()), true)
		if _, err := c.f.Confirm(c.session(), "svc", v.ID, false); err != nil {
			t.Fatal(err)
		}
		foreignTo(c, v)
	})
	if r := c.rec(v.ID); !r.ConflictEv || r.Ballot.State != BallotDisputed {
		t.Fatalf("%+v", r.Ballot)
	}
	if out, _ := c.f.SubmitResults(c.session(), "svc", v.ID, c.resultsFor(v, resOpts{mine: shown})); out.Reason != "disputed" {
		t.Errorf("disputed first: %+v", out)
	}
	// self_unrecorded, then a foreign ballot: conflict, even for the
	// receipted own-vk row.
	c, v = closedWith(t, func(c *cenv, v *votetest.Vote) {
		shown = c.selfBallot(v, "no")
		c.f.Check(c.session(), "svc", v.ID)
		c.answer(v, c.statuses()[0], shown, uint64(c.now.UnixMilli()), true)
		foreignTo(c, v)
	})
	if out, _ := c.f.SubmitResults(c.session(), "svc", v.ID, c.resultsFor(v, resOpts{mine: shown})); out.Reason != "conflict" {
		t.Errorf("conflict evidence before self: %+v", out)
	}
	// self_conflict beside the vault's receipt, the vault's own row: the
	// self row (two receipts), not the receipt row.
	c, v = closedWith(t, func(c *cenv, v *votetest.Vote) {
		shown = c.selfBallot(v, "no")
		receipted(c, v)
		c.f.Check(c.session(), "svc", v.ID)
		c.answer(v, c.statuses()[0], shown, uint64(c.now.UnixMilli()), true)
	})
	if out, _ := c.f.SubmitResults(c.session(), "svc", v.ID, c.resultsFor(v, resOpts{mine: c.ownBallot(v)})); out.State != CheckFailed || out.Reason != "row_mismatch" {
		t.Errorf("self before the receipt row: %+v", out)
	}
}

// GC #7991 I: the latest vote.closed hash is kept and compared again; the
// audit entry stays once per record.
func TestClosedLatestHash(t *testing.T) {
	c, v := closedWith(t, receipted)
	in := c.resultsFor(v, resOpts{mine: c.ownBallot(v)})
	c.f.SubmitResults(c.session(), "svc", v.ID, in)
	for _, h := range [][]byte{votewire.H([]byte("x")), votewire.H(in.Results), votewire.H([]byte("y"))} {
		c.call("vote.closed", strictjson.NewBuilder().String("proposal_id", v.ID).Base64("results_hash", h).Bytes())
	}
	if r := c.rec(v.ID); r.ResultsMatch != "no" || !eq(r.ResultsHash, votewire.H([]byte("y"))) || c.countKind("vote.results_conflict") != 1 {
		t.Errorf("%q %d", r.ResultsMatch, c.countKind("vote.results_conflict"))
	}
}

// Review fix 1: an extension adopted from the results alone (here with
// rows_unavailable) moves no receipt window: a receipt that arrives after
// it, by a cast answer, a status answer or already_voted, is kept aside;
// a vote.extended with the same bytes and a bundle that verifies (or the
// site's entry) verifies it, and the receipt is taken.
func TestAdoptedExtensionTakesNoReceipt(t *testing.T) {
	setup := func() (*cenv, *votetest.Vote, []string, time.Time, []byte) {
		c := newCastEnv(t)
		v := c.open(1)
		c.cast(v, "yes")
		_, ids := c.casts()
		closes := time.Unix(c.rec(v.ID).Closes, 0)
		doc, msg := c.svc.Extension(v, 1, closes.Add(time.Hour), c.now)
		c.now = closes.Add(time.Hour + CheckDelay + time.Minute)
		c.f.Tick(c.session())
		ru := c.resultsFor(v, resOpts{extra: []votewire.Signed{{Doc: doc, Sig: signExt(c.svc, v, doc)}}})
		ru.Row, ru.Proof, ru.RowsUnavailable = nil, nil, true
		if out, _ := c.f.SubmitResults(c.session(), "svc", v.ID, ru); out.State != CheckPending || len(c.rec(v.ID).Exts) != 1 {
			t.Fatalf("%+v", out)
		}
		return c, v, ids, closes, msg
	}
	for _, via := range []string{"cast", "status", "already_voted"} {
		c, v, ids, closes, msg := setup()
		at := uint64(closes.Add(30 * time.Minute).UnixMilli())
		switch via {
		case "cast":
			c.okReceipt(v, ids[0], c.leafOf(v), at)
		case "status":
			c.f.Check(c.session(), "svc", v.ID)
			c.answer(v, c.statuses()[len(c.statuses())-1], c.ownBallot(v), at, true)
		case "already_voted":
			c.alreadyVoted(v, ids[0], c.ownBallot(v), at)
		}
		if b := c.rec(v.ID).Ballot; b.State == BallotRecorded || b.Aside == nil || c.hasKind("vote.recorded") {
			t.Fatalf("%s: taken on an unverified extension: %s", via, b.State)
		}
		if r := c.call("vote.extended", msg); !r.OK() {
			t.Fatalf("%s: %q", via, r.Code)
		}
		if c.state(v) != BallotRecorded || len(c.rec(v.ID).Exts[0].Bundle) == 0 {
			t.Errorf("%s: the extension's bundle verified: %s", via, c.state(v))
		}
	}
	// The site's entry verifies it too.
	c, v, ids, closes, msg := setup()
	c.okReceipt(v, ids[0], c.leafOf(v), uint64(closes.Add(30*time.Minute).UnixMilli()))
	mm, _ := votewire.ParseExtendedMsg(msg)
	e1 := `{"extension":"` + b64(mm.Extension) + `","extension_sig":"` + b64(mm.ExtensionSig) + `","bundle":` + string(mm.Bundle) + `}`
	doc := `{"status":"found","proposal":"` + b64(v.Doc) + `","proposal_sig":"` + b64(v.Sig) + `","extensions":[` + e1 + `]}`
	c.syncResults(t, "entries", `{"entries":[{"proposal_id":"`+v.ID+`","document":`+doc+`}]}`)
	if c.state(v) != BallotRecorded {
		t.Errorf("site entry: %s", c.state(v))
	}
	// A shown own-vk ballot's receipt does not count toward two receipts on
	// an unverified extension.
	c = newCastEnv(t)
	v = c.open(1)
	shown := c.selfBallot(v, "no")
	receipted(c, v)
	closes = time.Unix(c.rec(v.ID).Closes, 0)
	d2, _ := c.svc.Extension(v, 1, closes.Add(time.Hour), c.now)
	c.now = closes.Add(time.Hour + CheckDelay + time.Minute)
	c.f.Tick(c.session())
	ru := c.resultsFor(v, resOpts{extra: []votewire.Signed{{Doc: d2, Sig: signExt(c.svc, v, d2)}}})
	ru.Row, ru.Proof, ru.RowsUnavailable = nil, nil, true
	c.f.SubmitResults(c.session(), "svc", v.ID, ru)
	c.f.Check(c.session(), "svc", v.ID)
	c.answer(v, c.statuses()[0], shown, uint64(closes.Add(30*time.Minute).UnixMilli()), true)
	if r := c.rec(v.ID); r.TwoReceipts || !r.Self.Late {
		t.Errorf("two receipts on an unverified extension: %v", r.TwoReceipts)
	}
}

// Review fix 3: a kept-aside receipt that a verified extension brings into
// the window is never reported late, whatever the ballot's state.
func TestAsideInWindowNotLateInAnyState(t *testing.T) {
	c := newCastEnv(t)
	v := c.open(1)
	c.cast(v, "yes")
	_, ids := c.casts()
	closes := time.Unix(c.rec(v.ID).Closes, 0)
	c.okReceipt(v, ids[0], c.leafOf(v), uint64(closes.Add(30*time.Minute).UnixMilli()))
	_, vk2, _ := ed25519.GenerateKey(rand.Reader)
	c.tickAt(2 * time.Minute)
	_, ids = c.casts()
	c.alreadyVoted(v, ids[len(ids)-1], must(votewire.SignBallot(vk2, v.Hash, v.Tag, "no")), uint64(c.now.UnixMilli()))
	if c.state(v) != BallotConflict {
		t.Fatalf("%s", c.state(v))
	}
	_, msg := c.svc.Extension(v, 1, closes.Add(time.Hour), c.now)
	c.call("vote.extended", msg)
	if r := c.rec(v.ID); r.Ballot.Aside != nil || len(r.Ballot.ReceiptSig) == 0 || r.asidePending() != 0 {
		t.Errorf("not judged in conflict: %+v", r.Ballot.Aside)
	}
	c.now = closes.Add(time.Hour + CheckDelay + time.Minute)
	c.f.Tick(c.session())
	c.h.Reset()
	c.f.SubmitResults(c.session(), "svc", v.ID, c.resultsFor(v, resOpts{mine: c.ownBallot(v)}))
	if c.hasKind("vote.receipt_rejected") || c.rec(v.ID).AsideProblem {
		t.Errorf("an in-window receipt was reported late: %v", c.h.Activities)
	}
}

// Review fix 4: the `extension` wait comes after the contradictions in the
// results (a tally that does not name every choice is failed), and a
// rows_unavailable record stays in the problem set while it waits.
func TestExtensionWaitOrder(t *testing.T) {
	aside := func() (*cenv, *votetest.Vote, votewire.Signed) {
		c := newCastEnv(t)
		v := c.open(1)
		c.cast(v, "yes")
		_, ids := c.casts()
		closes := time.Unix(c.rec(v.ID).Closes, 0)
		c.okReceipt(v, ids[0], c.leafOf(v), uint64(closes.Add(30*time.Minute).UnixMilli()))
		doc, _ := c.svc.Extension(v, 1, closes.Add(time.Hour), c.now)
		c.now = closes.Add(time.Hour + CheckDelay + time.Minute)
		c.f.Tick(c.session())
		return c, v, votewire.Signed{Doc: doc, Sig: signExt(c.svc, v, doc)}
	}
	c, v, x := aside()
	in := c.resultsFor(v, resOpts{extra: []votewire.Signed{x}, tamper: func(r *votewire.Results) { delete(r.Tally, "no") }})
	if out, _ := c.f.SubmitResults(c.session(), "svc", v.ID, in); out.State != CheckFailed || out.Reason != "results" {
		t.Errorf("a contradiction while waiting: %+v", out)
	}
	c, v, x = aside()
	ru := c.resultsFor(v, resOpts{extra: []votewire.Signed{x}})
	ru.Row, ru.Proof, ru.RowsUnavailable = nil, nil, true
	out, _ := c.f.SubmitResults(c.session(), "svc", v.ID, ru)
	if r := c.rec(v.ID); out.Reason != CheckExtension || !r.capProblem() || !r.RowsProblem {
		t.Errorf("rows_unavailable dropped while waiting: %+v", out)
	}
}

// Review fix 5 (the coordinator's ruling): after a restore, an own-vk
// ballot whose receipt is kept aside is held with no prompt and no self
// flag (no cast); a verified extension offers the prompt; still outside
// at a final judgement it is a late receipt and then self_unrecorded.
func TestRestoreLateOwnVK(t *testing.T) {
	restored := func() (*cenv, *votetest.Vote, time.Time) {
		c := newCastEnv(t)
		v := c.open(1)
		shown := c.selfBallot(v, "no")
		c.f.TransferCompleted(c.session(), "old", "new")
		c.f.Tick(c.session())
		closes := time.Unix(c.rec(v.ID).Closes, 0)
		c.answer(v, c.statuses()[0], shown, uint64(closes.Add(30*time.Minute).UnixMilli()), true)
		r := c.rec(v.ID)
		if r.ServiceBallot == nil || !r.ServiceBallot.Late || r.SelfUnrecorded || c.hasKind("vote.self_mismatch") {
			t.Fatalf("%+v", r.ServiceBallot)
		}
		if g := obj(t, c.app("vote.get", pairBody("svc", v.ID))); boolOf(g, "confirm_pending") || boolOf(g, "can_cast") {
			t.Errorf("vote.get %v", g)
		}
		if _, err := c.f.Confirm(c.session(), "svc", v.ID, true); code(err) != "bad_request" {
			t.Errorf("confirm offered: %v", err)
		}
		if _, err := c.cast(v, "yes"); code(err) != "checking" {
			t.Errorf("cast: %v", err)
		}
		return c, v, closes
	}
	c, v, closes := restored()
	_, msg := c.svc.Extension(v, 1, closes.Add(time.Hour), c.now)
	c.call("vote.extended", msg)
	if g := obj(t, c.app("vote.get", pairBody("svc", v.ID))); !boolOf(g, "confirm_pending") {
		t.Errorf("not offered: %v", g)
	}
	if st, err := c.f.Confirm(c.session(), "svc", v.ID, true); err != nil || st != BallotRecorded {
		t.Errorf("%s %v", st, err)
	}
	c, v, closes = restored()
	c.now = closes.Add(CheckDelay + time.Minute)
	c.f.Tick(c.session())
	c.f.SubmitResults(c.session(), "svc", v.ID, c.resultsFor(v, resOpts{}))
	if r := c.rec(v.ID); r.ServiceBallot != nil || !r.SelfUnrecorded || !c.has("vote.receipt_rejected", v.ID) || c.problems(v.ID) != 1 {
		t.Errorf("%+v", r.ServiceBallot)
	}
	if sb, err := c.evidence(t, v.ID).Object("self_ballot"); err != nil || !boolOf(sb, "late_receipt") {
		t.Errorf("self_ballot %v", sb)
	}
}

// Review fix 6a, 6c: Confirm "yes" runs the two-receipts check against an
// own-vk ballot shown while the prompt was pending (which set no flag);
// an already_voted own receipt past the original close + 86,400 s is
// vote.receipt_rejected.
func TestConfirmTwoReceiptsAndLateAlreadyVoted(t *testing.T) {
	c := newCastEnv(t)
	v := c.open(1)
	a, b := c.selfBallot(v, "no"), c.selfBallot(v, "yes")
	c.f.TransferCompleted(c.session(), "old", "new")
	c.f.Tick(c.session())
	c.answer(v, c.statuses()[0], a, uint64(c.now.UnixMilli()), true)
	c.now = c.now.Add(11 * time.Minute)
	c.f.Check(c.session(), "svc", v.ID)
	st := c.statuses()
	c.answer(v, st[len(st)-1], b, uint64(c.now.UnixMilli()), true)
	if r := c.rec(v.ID); r.SelfUnrecorded || r.Self == nil || r.ServiceBallot == nil {
		t.Fatalf("while pending: %+v", r)
	}
	c.f.Confirm(c.session(), "svc", v.ID, true)
	if r := c.rec(v.ID); !r.TwoReceipts || !r.SelfConflict || c.problems(v.ID) != 1 {
		t.Errorf("after yes: two %v self %v", r.TwoReceipts, r.SelfConflict)
	}
	c = newCastEnv(t)
	v = c.open(1)
	c.cast(v, "yes")
	_, ids := c.casts()
	c.alreadyVoted(v, ids[0], c.ownBallot(v), uint64((c.rec(v.ID).OrigClose+votewire.MaxExtension)*1000))
	if !c.has("vote.receipt_rejected", v.ID) || c.state(v) == BallotRecorded {
		t.Errorf("%s", c.state(v))
	}
}

// Recheck of a07d2fe: after a final check, a receipt below the close in
// force but outside the verified close (an extension adopted from the
// results, not verified yet) stays aside, unaccused, and is taken once the
// extension's bundle is verified; the same holds for a shown own-vk ballot
// and a held restore prompt. One at or after the close in force is
// rejected at once.
func TestFinalCheckKeepsReceiptsForAnAdoptedExtension(t *testing.T) {
	judged := func() (*cenv, *votetest.Vote, []string, time.Time, []byte) {
		c := newCastEnv(t)
		v := c.open(1)
		c.cast(v, "yes")
		_, ids := c.casts()
		closes := time.Unix(c.rec(v.ID).Closes, 0)
		doc, msg := c.svc.Extension(v, 1, closes.Add(time.Hour), c.now) // its vote.extended is lost
		c.now = closes.Add(time.Hour + CheckDelay + time.Minute)
		c.f.Tick(c.session())
		out, _ := c.f.SubmitResults(c.session(), "svc", v.ID, c.resultsFor(v, resOpts{mine: c.ownBallot(v), extra: []votewire.Signed{{Doc: doc, Sig: signExt(c.svc, v, doc)}}}))
		if out.State != CheckUnconfirmed && out.State != CheckVerified || len(c.rec(v.ID).Exts) != 1 {
			t.Fatalf("%+v", out)
		}
		c.h.Reset()
		return c, v, ids, closes, msg
	}
	quiet := func(c *cenv, what string) {
		t.Helper()
		if c.hasKind("vote.receipt_rejected") || c.hasKind("vote.problem") {
			t.Errorf("%s: accused: %v", what, c.h.Activities)
		}
	}
	// The vault's own receipt.
	c, v, ids, closes, msg := judged()
	c.okReceipt(v, ids[0], c.leafOf(v), uint64(closes.Add(30*time.Minute).UnixMilli()))
	quiet(c, "own")
	if b := c.rec(v.ID).Ballot; b.Aside == nil || b.Aside.Rejected {
		t.Fatalf("own: %+v", b.Aside)
	}
	c.call("vote.extended", msg)
	if c.state(v) != BallotRecorded {
		t.Errorf("own: %s", c.state(v))
	}
	// One at or after the close in force is rejected at once.
	c, v, ids, closes, _ = judged()
	c.okReceipt(v, ids[0], c.leafOf(v), uint64(closes.Add(70*time.Minute).UnixMilli()))
	if !c.has("vote.receipt_rejected", v.ID) || !c.rec(v.ID).Ballot.Aside.Rejected {
		t.Error("past the close in force: not rejected")
	}
	// A shown own-vk ballot (its seed taken before the close erases it).
	c = newCastEnv(t)
	v = c.open(1)
	shown := c.selfBallot(v, "no")
	closes = time.Unix(c.rec(v.ID).Closes, 0)
	doc, msg := c.svc.Extension(v, 1, closes.Add(time.Hour), c.now)
	c.now = closes.Add(time.Hour + CheckDelay + time.Minute)
	c.f.Tick(c.session())
	c.f.SubmitResults(c.session(), "svc", v.ID, c.resultsFor(v, resOpts{extra: []votewire.Signed{{Doc: doc, Sig: signExt(c.svc, v, doc)}}}))
	c.h.Reset()
	c.f.Check(c.session(), "svc", v.ID)
	c.answer(v, c.statuses()[len(c.statuses())-1], shown, uint64(closes.Add(30*time.Minute).UnixMilli()), true)
	if r := c.rec(v.ID); !r.SelfUnrecorded || !r.Self.Late || r.Self.LateRejected || c.hasKind("vote.receipt_rejected") {
		t.Errorf("shown: %+v", r.Self)
	}
	c.call("vote.extended", msg)
	if r := c.rec(v.ID); r.Self.Late {
		t.Error("shown: still late after the extension")
	}
}

// Recheck of a07d2fe: a restore prompt held for a receipt inside an
// adopted, unverified extension after a final check stays held (no
// self_unrecorded) and is offered once the extension verifies.
func TestFinalCheckKeepsRestorePrompt(t *testing.T) {
	c := newCastEnv(t)
	v := c.open(1)
	shown := c.selfBallot(v, "no")
	closes := time.Unix(c.rec(v.ID).Closes, 0)
	doc, msg := c.svc.Extension(v, 1, closes.Add(time.Hour), c.now)
	c.now = closes.Add(time.Hour + CheckDelay + time.Minute)
	c.f.Tick(c.session())
	c.f.SubmitResults(c.session(), "svc", v.ID, c.resultsFor(v, resOpts{extra: []votewire.Signed{{Doc: doc, Sig: signExt(c.svc, v, doc)}}}))
	c.f.TransferCompleted(c.session(), "old", "new")
	c.f.Tick(c.session())
	st := c.statuses()
	c.h.Reset()
	c.answer(v, st[len(st)-1], shown, uint64(closes.Add(30*time.Minute).UnixMilli()), true)
	if r := c.rec(v.ID); r.ServiceBallot == nil || r.SelfUnrecorded || c.hasKind("vote.receipt_rejected") || c.hasKind("vote.problem") {
		t.Fatalf("%+v", r.ServiceBallot)
	}
	c.call("vote.extended", msg)
	if g := obj(t, c.app("vote.get", pairBody("svc", v.ID))); !boolOf(g, "confirm_pending") {
		t.Errorf("not offered: %v", g)
	}
}

// Recheck of a07d2fe: with a gave_up check, a receipt inside an adopted
// extension is taken once it verifies, and a later submission is verified.
func TestGaveUpThenVerifiedExtension(t *testing.T) {
	c := newCastEnv(t)
	v := c.open(1)
	c.cast(v, "yes")
	_, ids := c.casts()
	closes := time.Unix(c.rec(v.ID).Closes, 0)
	doc, msg := c.svc.Extension(v, 1, closes.Add(time.Hour), c.now)
	x := votewire.Signed{Doc: doc, Sig: signExt(c.svc, v, doc)}
	c.now = closes.Add(time.Hour + CheckDelay + time.Minute)
	c.f.Tick(c.session())
	ru := c.resultsFor(v, resOpts{extra: []votewire.Signed{x}})
	ru.Row, ru.Proof, ru.RowsUnavailable = nil, nil, true
	c.f.SubmitResults(c.session(), "svc", v.ID, ru)
	c.now = c.now.Add(CheckGiveUp + time.Hour)
	c.f.Tick(c.session())
	if c.rec(v.ID).Check != CheckGaveUp {
		t.Fatalf("%q", c.rec(v.ID).Check)
	}
	c.f.pend[ids[0]] = pendRef{conn: "svc", id: v.ID, kind: "cast", atMS: c.now.UnixMilli()}
	c.okReceipt(v, ids[0], c.leafOf(v), uint64(closes.Add(30*time.Minute).UnixMilli()))
	c.call("vote.extended", msg)
	if c.state(v) != BallotRecorded {
		t.Fatalf("%s", c.state(v))
	}
	stamp := closes.Add(time.Hour + CheckDelay + time.Minute) // the results were anchored then
	if out, _ := c.f.SubmitResults(c.session(), "svc", v.ID, c.resultsFor(v, resOpts{mine: c.ownBallot(v), stampAt: stamp})); out.State != CheckVerified {
		t.Errorf("%+v", out)
	}
}

// GC #8012 fix 1: an extension adopted from results.json stays unverified
// across a save and a reload (its absent bundle is not read back as
// `null`): a receipt inside it is not taken at the next submit; a record
// of an older release whose extension holds a real bundle and no Verified
// flag counts it verified.
func TestAdoptedExtensionSurvivesReload(t *testing.T) {
	c := newCastEnv(t)
	v := c.open(1)
	c.cast(v, "yes")
	_, ids := c.casts()
	closes := time.Unix(c.rec(v.ID).Closes, 0)
	doc, _ := c.svc.Extension(v, 1, closes.Add(time.Hour), c.now)
	x := votewire.Signed{Doc: doc, Sig: signExt(c.svc, v, doc)}
	c.now = closes.Add(time.Hour + CheckDelay + time.Minute)
	c.f.Tick(c.session())
	ru := c.resultsFor(v, resOpts{extra: []votewire.Signed{x}})
	ru.Row, ru.Proof, ru.RowsUnavailable = nil, nil, true
	c.f.SubmitResults(c.session(), "svc", v.ID, ru)
	pend := c.f.pend
	c.reload()
	c.f.pend = pend
	if e := c.rec(v.ID).Exts[0]; e.Verified || len(e.Bundle) != 0 || c.rec(v.ID).verifiedClose() != closes.Unix() {
		t.Fatalf("reloaded as verified: %q %v", e.Bundle, e.Verified)
	}
	c.okReceipt(v, ids[0], c.leafOf(v), uint64(closes.Add(30*time.Minute).UnixMilli()))
	c.reload()
	out, _ := c.f.SubmitResults(c.session(), "svc", v.ID, c.resultsFor(v, resOpts{mine: c.ownBallot(v)})) // E1 is held: resultsFor carries it
	if c.state(v) == BallotRecorded || out.Reason != CheckExtension {
		t.Errorf("taken after a reload: %s %+v", c.state(v), out)
	}
	// An older release's extension: a real bundle, no Verified flag.
	c2 := newCastEnv(t)
	w := c2.open(1)
	_, msg := c2.svc.Extension(w, 1, time.Unix(c2.rec(w.ID).Closes, 0).Add(time.Hour), c2.now)
	c2.call("vote.extended", msg)
	c2.rec(w.ID).Exts[0].Verified = false
	c2.reload()
	if e := c2.rec(w.ID).Exts[0]; !e.Verified || c2.rec(w.ID).verifiedClose() != e.Closes {
		t.Error("an older release's verified extension is not verified")
	}
	// A bundle written as JSON null is absent.
	c2.rec(w.ID).Exts[0].Bundle, c2.rec(w.ID).Exts[0].Verified = json.RawMessage("null"), false
	c2.reload()
	if e := c2.rec(w.ID).Exts[0]; e.Verified || len(e.Bundle) != 0 {
		t.Errorf("null bundle: %q %v", e.Bundle, e.Verified)
	}
}

// GC #8012 fixes 2, 3 and GC #8014 1: while a restore prompt is pending
// for own-vk ballot A, a second own-vk ballot B does not replace it and is
// two receipts at once (A's counts); the check fails whatever the row.
func TestRestorePromptTwoReceiptsAndNoOverwrite(t *testing.T) {
	var a *votewire.Ballot
	c, v := closedWith(t, func(c *cenv, v *votetest.Vote) {
		a = c.selfBallot(v, "no")
		b := c.selfBallot(v, "yes")
		c.f.TransferCompleted(c.session(), "old", "new")
		c.f.Tick(c.session())
		c.tickAt(61 * time.Minute) // a second ask for the restore
		st := c.statuses()
		c.answer(v, st[0], a, uint64(c.rec(v.ID).Opens*1000+1), true)
		c.answer(v, st[1], b, uint64(c.rec(v.ID).Opens*1000+2), true)
		r := c.rec(v.ID)
		if sb := r.ServiceBallot; sb == nil || sb.ChoiceID != "no" {
			t.Fatalf("the pending prompt was replaced: %+v", sb)
		}
		if !r.TwoReceipts || r.SelfUnrecorded || c.problems(v.ID) != 1 {
			t.Fatalf("two %v self %v problems %d", r.TwoReceipts, r.SelfUnrecorded, c.problems(v.ID))
		}
	})
	if out, _ := c.f.SubmitResults(c.session(), "svc", v.ID, c.resultsFor(v, resOpts{mine: a})); out.State != CheckFailed || out.Reason != "row_mismatch" {
		t.Errorf("%+v", out)
	}
}

// GC #8014 2: two receipts that fire when a verified extension clears a
// shown receipt kept aside fail a final check, with no second vote.problem.
func TestTwoReceiptsAfterAFinalCheck(t *testing.T) {
	c := newCastEnv(t)
	v := c.open(1)
	shown := c.selfBallot(v, "no")
	receipted(c, v)
	closes := time.Unix(c.rec(v.ID).Closes, 0)
	doc, msg := c.svc.Extension(v, 1, closes.Add(time.Hour), c.now)
	c.now = closes.Add(time.Hour + CheckDelay + time.Minute)
	c.f.Tick(c.session())
	if out, _ := c.f.SubmitResults(c.session(), "svc", v.ID, c.resultsFor(v, resOpts{mine: c.ownBallot(v), extra: []votewire.Signed{{Doc: doc, Sig: signExt(c.svc, v, doc)}}})); out.State != CheckVerified {
		t.Fatalf("%+v", out)
	}
	c.f.Check(c.session(), "svc", v.ID)
	c.answer(v, c.statuses()[len(c.statuses())-1], shown, uint64(closes.Add(30*time.Minute).UnixMilli()), true)
	if r := c.rec(v.ID); r.TwoReceipts || !r.Self.Late || c.hasKind("vote.receipt_rejected") {
		t.Fatalf("before the extension: %v", r.TwoReceipts)
	}
	c.h.Reset()
	c.call("vote.extended", msg)
	if r := c.rec(v.ID); !r.TwoReceipts || r.Check != CheckFailed || r.CheckReason != "row_mismatch" || c.problems(v.ID) != 1 {
		t.Errorf("%v %q %q problems %d", r.TwoReceipts, r.Check, r.CheckReason, c.problems(v.ID))
	}
}

// GC #8014 3: an extension held with a bundle but not marked verified does
// not move the verified close, and the site's entry verifies it
// (verifyHeld); vote.evidence leaves out a receipt still kept aside.
func TestHeldUnverifiedExtensionAndEvidence(t *testing.T) {
	c := newCastEnv(t)
	v := c.open(1)
	c.cast(v, "yes")
	_, ids := c.casts()
	closes := time.Unix(c.rec(v.ID).Closes, 0)
	_, msg := c.svc.Extension(v, 1, closes.Add(time.Hour), c.now)
	c.call("vote.extended", msg)
	c.rec(v.ID).Exts[0].Verified = false
	if c.rec(v.ID).verifiedClose() != closes.Unix() {
		t.Fatal("an unverified extension moved the verified close")
	}
	c.okReceipt(v, ids[0], c.leafOf(v), uint64(closes.Add(30*time.Minute).UnixMilli()))
	if b := c.rec(v.ID).Ballot; b.Aside == nil || b.State == BallotRecorded {
		t.Fatalf("%+v", b.Aside)
	}
	if _, ok := c.evidence(t, v.ID)["late_receipt"]; ok {
		t.Error("a receipt still kept aside is exported as late")
	}
	mm, _ := votewire.ParseExtendedMsg(msg)
	e1 := `{"extension":"` + b64(mm.Extension) + `","extension_sig":"` + b64(mm.ExtensionSig) + `","bundle":` + string(mm.Bundle) + `}`
	doc := `{"status":"found","proposal":"` + b64(v.Doc) + `","proposal_sig":"` + b64(v.Sig) + `","extensions":[` + e1 + `]}`
	c.syncResults(t, "entries", `{"entries":[{"proposal_id":"`+v.ID+`","document":`+doc+`}]}`)
	if !c.rec(v.ID).Exts[0].Verified || c.state(v) != BallotRecorded {
		t.Errorf("site entry: %v %s", c.rec(v.ID).Exts[0].Verified, c.state(v))
	}
}

// GC #8012 fixes 4, 5: a failed check does not reject a receipt inside a
// held, unverified extension; once it verifies the receipt is taken and a
// final check is judged again on its stored row (a mismatch is failed with
// one vote.problem; a match upgrades unconfirmed to verified).
func TestReceiptTakenAfterAFinalCheck(t *testing.T) {
	setup := func() (*cenv, *votetest.Vote, votewire.Signed, []byte, time.Time) {
		c := newCastEnv(t)
		v := c.open(1)
		c.cast(v, "yes")
		_, ids := c.casts()
		closes := time.Unix(c.rec(v.ID).Closes, 0)
		doc, msg := c.svc.Extension(v, 1, closes.Add(time.Hour), c.now)
		x := votewire.Signed{Doc: doc, Sig: signExt(c.svc, v, doc)}
		c.now = closes.Add(time.Hour + CheckDelay + time.Minute)
		c.f.Tick(c.session())
		ru := c.resultsFor(v, resOpts{extra: []votewire.Signed{x}})
		ru.Row, ru.Proof, ru.RowsUnavailable = nil, nil, true
		c.f.SubmitResults(c.session(), "svc", v.ID, ru) // adopts E1, unverified
		c.okReceipt(v, ids[0], c.leafOf(v), uint64(closes.Add(30*time.Minute).UnixMilli()))
		return c, v, x, msg, closes
	}
	// Fix 4: a contradiction fails the check; the receipt stays aside.
	c, v, x, msg, _ := setup()
	in := c.resultsFor(v, resOpts{extra: []votewire.Signed{x}, tamper: func(r *votewire.Results) { delete(r.Tally, "no") }})
	if out, _ := c.f.SubmitResults(c.session(), "svc", v.ID, in); out.State != CheckFailed || c.hasKind("vote.receipt_rejected") || c.rec(v.ID).Ballot.Aside.Rejected {
		t.Fatalf("%+v", out)
	}
	c.call("vote.extended", msg)
	if c.state(v) != BallotRecorded {
		t.Errorf("not taken after a failed check: %s", c.state(v))
	}
	// Fix 5: the results (adopting E1) are judged unconfirmed before the
	// receipt arrives; it is taken once E1 verifies, and the stored row is
	// judged again.
	for _, ownRow := range []bool{false, true} {
		c := newCastEnv(t)
		v := c.open(1)
		c.cast(v, "yes")
		_, ids := c.casts()
		closes := time.Unix(c.rec(v.ID).Closes, 0)
		doc, msg := c.svc.Extension(v, 1, closes.Add(time.Hour), c.now)
		c.now = closes.Add(time.Hour + CheckDelay + time.Minute)
		c.f.Tick(c.session())
		var mine *votewire.Ballot
		if ownRow {
			mine = c.ownBallot(v)
		}
		if out, _ := c.f.SubmitResults(c.session(), "svc", v.ID, c.resultsFor(v, resOpts{mine: mine, extra: []votewire.Signed{{Doc: doc, Sig: signExt(c.svc, v, doc)}}})); out.State != CheckUnconfirmed {
			t.Fatalf("%+v", out)
		}
		c.okReceipt(v, ids[0], c.leafOf(v), uint64(closes.Add(30*time.Minute).UnixMilli()))
		c.h.Reset()
		c.call("vote.extended", msg)
		r := c.rec(v.ID)
		switch {
		case c.state(v) != BallotRecorded:
			t.Errorf("own row %v: %s", ownRow, c.state(v))
		case !ownRow && (r.Check != CheckFailed || r.CheckReason != "row_mismatch" || c.problems(v.ID) != 1):
			t.Errorf("empty row: %q %q %d", r.Check, r.CheckReason, c.problems(v.ID))
		case ownRow && (r.Check != CheckVerified || !c.has("vote.check_ok", v.ID)):
			t.Errorf("own row: %q", r.Check)
		}
	}
}

// Two receipts in the reverse order: an own-vk ballot shown first in a
// status answer, then a different one at the restore prompt. The service
// signed both, so two receipts fire (one vote.problem) and the check of
// either row fails.
func TestTwoReceiptsShownThenRestorePrompt(t *testing.T) {
	var a, b *votewire.Ballot
	c, v := closedWith(t, func(c *cenv, v *votetest.Vote) {
		a, b = c.selfBallot(v, "no"), c.selfBallot(v, "yes")
		c.now = c.now.Add(11 * time.Minute)
		c.f.Check(c.session(), "svc", v.ID)
		ids := c.statuses()
		c.answer(v, ids[len(ids)-1], b, uint64(c.now.UnixMilli()), true)
		if r := c.rec(v.ID); !r.SelfUnrecorded || r.TwoReceipts {
			t.Fatalf("shown: self %v two %v", r.SelfUnrecorded, r.TwoReceipts)
		}
		c.f.TransferCompleted(c.session(), "old", "new")
		c.f.Tick(c.session())
		ids = c.statuses()
		c.answer(v, ids[len(ids)-1], a, uint64(c.rec(v.ID).Opens*1000+1), true)
		r := c.rec(v.ID)
		if sb := r.ServiceBallot; sb == nil || sb.ChoiceID != "no" {
			t.Fatalf("no restore prompt: %+v", sb)
		}
		if !r.TwoReceipts || c.problems(v.ID) != 1 {
			t.Fatalf("two %v problems %d", r.TwoReceipts, c.problems(v.ID))
		}
	})
	if out, _ := c.f.SubmitResults(c.session(), "svc", v.ID, c.resultsFor(v, resOpts{mine: b})); out.State != CheckFailed || out.Reason != "row_mismatch" {
		t.Errorf("%+v", out)
	}
	if c.problems(v.ID) != 1 {
		t.Errorf("problems %d", c.problems(v.ID))
	}
}

// Two receipts that fire after a final check (an in-window own-vk ballot
// shown beside the vault's own receipt) fail that check at once, with one
// vote.problem.
func TestTwoReceiptsInWindowAfterAFinalCheck(t *testing.T) {
	c := newCastEnv(t)
	v := c.open(1)
	shown := c.selfBallot(v, "no") // before the receipt erases the seed
	receipted(c, v)
	closes := time.Unix(c.rec(v.ID).Closes, 0)
	c.now = closes.Add(CheckDelay + time.Minute)
	c.f.Tick(c.session())
	if out, _ := c.f.SubmitResults(c.session(), "svc", v.ID, c.resultsFor(v, resOpts{mine: c.ownBallot(v)})); out.State != CheckVerified {
		t.Fatalf("%+v", out)
	}
	c.h.Reset()
	c.f.Check(c.session(), "svc", v.ID)
	ids := c.statuses()
	c.answer(v, ids[len(ids)-1], shown, uint64(closes.Add(-30*time.Minute).UnixMilli()), true)
	if r := c.rec(v.ID); !r.TwoReceipts || r.Check != CheckFailed || r.CheckReason != "row_mismatch" || c.problems(v.ID) != 1 {
		t.Errorf("%v %q %q problems %d", r.TwoReceipts, r.Check, r.CheckReason, c.problems(v.ID))
	}
}

// The same own-vk ballot shown twice (Self and SelfLatest) and a different
// one at the restore prompt: three receipts held, two of them different,
// so two receipts fire.
func TestTwoReceiptsSameSelfTwiceThenRestorePrompt(t *testing.T) {
	closedWith(t, func(c *cenv, v *votetest.Vote) {
		a, b := c.selfBallot(v, "no"), c.selfBallot(v, "yes")
		for i := 0; i < 2; i++ {
			c.now = c.now.Add(11 * time.Minute)
			c.f.Check(c.session(), "svc", v.ID)
			ids := c.statuses()
			c.answer(v, ids[len(ids)-1], b, uint64(c.now.UnixMilli()), true)
		}
		if r := c.rec(v.ID); r.Self == nil || r.SelfLatest == nil || !sameSvc(r.Self, r.SelfLatest) || r.TwoReceipts {
			t.Fatalf("shown twice: %+v %+v two %v", r.Self, r.SelfLatest, r.TwoReceipts)
		}
		c.f.TransferCompleted(c.session(), "old", "new")
		c.f.Tick(c.session())
		ids := c.statuses()
		c.answer(v, ids[len(ids)-1], a, uint64(c.rec(v.ID).Opens*1000+1), true)
		if r := c.rec(v.ID); r.ServiceBallot == nil || !r.TwoReceipts || c.problems(v.ID) != 1 {
			t.Fatalf("two %v problems %d", r.TwoReceipts, c.problems(v.ID))
		}
	})
}

// A restore prompt whose receipt is kept aside (Late) beside a held,
// different own-vk ballot: no two receipts until a verified extension
// brings it into the window.
func TestTwoReceiptsLateRestorePrompt(t *testing.T) {
	c := newCastEnv(t)
	v := c.open(1)
	a, b := c.selfBallot(v, "no"), c.selfBallot(v, "yes")
	c.now = c.now.Add(11 * time.Minute)
	c.f.Check(c.session(), "svc", v.ID)
	ids := c.statuses()
	c.answer(v, ids[len(ids)-1], b, uint64(c.now.UnixMilli()), true)
	closes := time.Unix(c.rec(v.ID).Closes, 0)
	_, msg := c.svc.Extension(v, 1, closes.Add(time.Hour), c.now)
	c.now = closes.Add(time.Minute)
	c.f.TransferCompleted(c.session(), "old", "new")
	c.f.Tick(c.session())
	ids = c.statuses()
	c.answer(v, ids[len(ids)-1], a, uint64(closes.Add(30*time.Minute).UnixMilli()), true)
	if r := c.rec(v.ID); r.ServiceBallot == nil || !r.ServiceBallot.Late || r.TwoReceipts || c.problems(v.ID) != 0 {
		t.Fatalf("late prompt: %+v two %v problems %d", r.ServiceBallot, r.TwoReceipts, c.problems(v.ID))
	}
	c.call("vote.extended", msg)
	if r := c.rec(v.ID); r.ServiceBallot == nil || r.ServiceBallot.Late || !r.TwoReceipts || c.problems(v.ID) != 1 {
		t.Errorf("after the extension: %+v two %v problems %d", r.ServiceBallot, r.TwoReceipts, c.problems(v.ID))
	}
}

// A pending restore prompt is not an own-vk ballot shown for the self
// rows: with the only shown one kept aside, the row is judged by the rows
// after them, never against the prompt's ballot.
func TestRestorePromptIsNotASelfRow(t *testing.T) {
	c := newCastEnv(t)
	v := c.open(1)
	a, b := c.selfBallot(v, "no"), c.selfBallot(v, "yes")
	closes := time.Unix(c.rec(v.ID).Closes, 0)
	c.now = closes.Add(time.Minute)
	c.f.Check(c.session(), "svc", v.ID)
	ids := c.statuses()
	c.answer(v, ids[len(ids)-1], b, uint64(closes.Add(30*time.Minute).UnixMilli()), true)
	c.f.TransferCompleted(c.session(), "old", "new")
	c.f.Tick(c.session())
	ids = c.statuses()
	c.answer(v, ids[len(ids)-1], a, uint64(c.rec(v.ID).Opens*1000+1), true)
	r := c.rec(v.ID)
	if r.Self == nil || !r.Self.Late || !r.SelfUnrecorded || r.ServiceBallot == nil || r.ServiceBallot.Late || r.TwoReceipts {
		t.Fatalf("setup: self %+v unrecorded %v prompt %+v two %v", r.Self, r.SelfUnrecorded, r.ServiceBallot, r.TwoReceipts)
	}
	c.now = closes.Add(CheckDelay + time.Minute)
	// The row is the shown ballot whose receipt is kept aside: judged as if
	// it were not there (no ballot of the vault's own), not against the
	// prompt's ballot.
	if out, _ := c.f.SubmitResults(c.session(), "svc", v.ID, c.resultsFor(v, resOpts{mine: b})); out.State != CheckFailed || out.Reason != "row_unexpected" {
		t.Errorf("%+v", out)
	}
}

// With conflict evidence, a final check that two receipts fail on re-judging
// still raises its own vote.problem: the two receipts' one does not stand
// for the conflict's (pins the quiet rule's conflict term).
func TestRejudgeWithConflictEvidenceAndTwoReceipts(t *testing.T) {
	c := newCastEnv(t)
	v := c.open(1)
	other := c.selfBallot(v, "no") // before the receipt erases the seed
	receipted(c, v)
	c.now = time.Unix(c.rec(v.ID).Closes, 0).Add(CheckDelay + time.Minute)
	c.f.Tick(c.session())
	if out, _ := c.f.SubmitResults(c.session(), "svc", v.ID, c.resultsFor(v, resOpts{mine: c.ownBallot(v)})); out.State != CheckVerified {
		t.Fatalf("%+v", out)
	}
	// The stored row turns out to be another ballot, with conflict
	// evidence and two receipts already held.
	r := c.rec(v.ID)
	r.ConflictEv, r.TwoReceipts = true, true
	r.Results.Row = &svcBallot{VK: other.VK, ChoiceID: other.ChoiceID, BallotSig: other.BallotSig}
	c.h.Reset()
	c.f.rejudgeResults(c.session(), r)
	if r.Check != CheckFailed || r.CheckReason != "row_mismatch" || c.problems(v.ID) != 1 {
		t.Errorf("%q %q problems %d", r.Check, r.CheckReason, c.problems(v.ID))
	}
}
