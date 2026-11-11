package vote

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/internal/votetest"
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
	if r.AsideShown == nil || r.Ballot.State != BallotConflict || !c.has("vote.conflict", v.ID) || !r.Other.Late {
		t.Fatalf("%+v", r.AsideShown)
	}
	if _, ok := c.evidence(t, v.ID)["ballot_aside"]; !ok {
		t.Error("not in vote.evidence")
	}
	_, msg := c.svc.Extension(v, 1, closes.Add(time.Hour), c.now)
	c.call("vote.extended", msg)
	if r := c.rec(v.ID); r.AsideShown != nil || r.Other.Late || c.countKind("vote.conflict") != 1 {
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
// self rows, then the rest.
func TestVerdictOrder(t *testing.T) {
	sb := &svcBallot{VK: make([]byte, 32), ChoiceID: "no", BallotSig: make([]byte, 64)}
	r := &record{Ballot: &ballot{State: BallotDisputed}, ConflictEv: true, SelfUnrecorded: true, Self: sb}
	if st, why := verdict(r, nil); st != CheckFailed || why != "disputed" {
		t.Errorf("disputed first: %s %s", st, why)
	}
	r.Ballot = nil
	if st, why := verdict(r, &votewire.RowBallot{VK: sb.VK, ChoiceID: sb.ChoiceID, BallotSig: sb.BallotSig}); st != CheckFailed || why != "conflict" {
		t.Errorf("conflict evidence before self: %s %s", st, why)
	}
	r.ConflictEv = false
	r.Ballot = &ballot{State: BallotRecorded, VK: sb.VK, ChoiceID: "yes", BallotSig: make([]byte, 64), ReceiptSig: []byte{1}}
	if st, why := verdict(r, &votewire.RowBallot{VK: sb.VK, ChoiceID: "yes", BallotSig: make([]byte, 64)}); st != CheckFailed || why != "row_mismatch" {
		t.Errorf("self before the receipt row: %s %s", st, why)
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
