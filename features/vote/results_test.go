package vote

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

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
	rowIndex  int // added to the member's index in the proof
	tree      int // added to the tree size of the proof
	otherBndl []byte
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
	path := must(votewire.Proof(leaves, v.Index))
	in := ResultsSubmit{Results: doc, Sig: sig, Bundle: c.env.auth.Bundle(doc, c.svc.Anchor, c.now),
		Proof: &votewire.RecordProof{Index: uint64(v.Index + o.rowIndex), TreeSize: uint64(len(v.Tags) + o.tree), Path: path}}
	if o.otherBndl != nil {
		in.Bundle = o.otherBndl
	}
	if o.mine != nil {
		in.Row = &votewire.RowBallot{VK: o.mine.VK, ChoiceID: o.mine.ChoiceID, BallotSig: o.mine.BallotSig}
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

func TestResultsFailures(t *testing.T) {
	cases := map[string]func(c *cenv, v *votetest.Vote) resOpts{
		"results_sig": func(c *cenv, v *votetest.Vote) resOpts { return resOpts{badSig: true} },
		"a changed proposal": func(c *cenv, v *votetest.Vote) resOpts {
			return resOpts{tamper: func(r *votewire.Results) { r.Proposal.Sig = make([]byte, 64) }}
		},
		"tally missing a choice": func(c *cenv, v *votetest.Vote) resOpts {
			return resOpts{tamper: func(r *votewire.Results) { delete(r.Tally, "no") }}
		},
		"eligible differs": func(c *cenv, v *votetest.Vote) resOpts {
			return resOpts{tamper: func(r *votewire.Results) { r.Counts.Eligible++ }}
		},
		"row index": func(c *cenv, v *votetest.Vote) resOpts { return resOpts{rowIndex: 1} },
		"tree size": func(c *cenv, v *votetest.Vote) resOpts { return resOpts{tree: 1} },
		"rows_root": func(c *cenv, v *votetest.Vote) resOpts {
			return resOpts{tamper: func(r *votewire.Results) { r.RowsRoot = make([]byte, 32) }}
		},
	}
	for name, mk := range cases {
		c, v := closedWith(t, nil)
		out, err := c.f.SubmitResults(c.session(), "svc", v.ID, c.resultsFor(v, mk(c, v)))
		if err != nil || out.State != CheckFailed || out.Reason != "results" {
			t.Errorf("%s: %+v %v", name, out, err)
		}
	}
	// A row proof whose index differs from the record proof's, with a valid
	// proof for that index, is still failed (results).
	c, v := closedWith(t, nil)
	in := c.resultsFor(v, resOpts{})
	other := (v.Index + 1) % len(v.Tags)
	leaves := make([][]byte, len(v.Tags))
	copy(leaves, v.Tags)
	in.Proof = &votewire.RecordProof{Index: uint64(other), TreeSize: uint64(len(v.Tags)), Path: must(votewire.Proof(leaves, other))}
	if out, _ := c.f.SubmitResults(c.session(), "svc", v.ID, in); out.State != CheckFailed || out.Reason != "results" {
		t.Errorf("another index: %+v", out)
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
	if out.State != CheckFailed || out.Reason != "anchor" {
		t.Errorf("anchor: %+v", out)
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
