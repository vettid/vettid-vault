package vote

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/votetest"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/strictjson"
	"github.com/vettid/vettid-vault/vms/suite"
	"github.com/vettid/vettid-vault/vms/votewire"
)

// closedElig is closedWith for an electorate of n.
func closedElig(t *testing.T, n int, setup func(c *cenv, v *votetest.Vote)) (*cenv, *votetest.Vote) {
	c := newCastEnv(t)
	v := c.svc.NewVote(votetest.VoteSpec{ID: lid(1), Opens: c.now.Add(-time.Hour), Closes: c.now.Add(2 * time.Hour), Eligible: n})
	if r := c.send(v); !r.OK() {
		t.Fatalf("vote: %q", r.Code)
	}
	if setup != nil {
		setup(c, v)
	}
	c.now = time.Unix(c.rec(v.ID).Closes, 0).Add(CheckDelay + time.Minute)
	c.f.Tick(c.session())
	return c, v
}

// notMine is the k-th index that is not the member's.
func notMine(v *votetest.Vote, k int) int {
	i := 0
	for n := 0; n < len(v.Tags); n++ {
		if n == v.Index {
			continue
		}
		if i == k {
			return n
		}
		i++
	}
	panic("no such index")
}

func (c *cenv) problems(id string) (n int) {
	for _, a := range c.h.Activities {
		if a.Kind == "vote.problem" && a.Ref == id {
			n++
		}
	}
	return
}

func (c *cenv) evidence(t *testing.T, id string) strictjson.Object {
	t.Helper()
	o := obj(t, c.app("vote.evidence", pairBody("svc", id)))
	e, err := o.Object("evidence")
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// A second verifying row under the member's tag is `failed` (row_duplicate),
// whatever its choice, ahead of every other row outcome; the extra rows are
// kept and shown in vote.evidence with pad.
func TestRowDuplicate(t *testing.T) {
	for _, x := range []struct {
		name string
		oo   otherOpt
	}{
		{"a valid choice", otherOpt{choice: "no"}},
		{"a malformed choice", otherOpt{choice: "No Such_Choice!"}},
		{"an empty choice id", otherOpt{choice: ""}},
		{"a choice id over 32 bytes", otherOpt{choice: strings.Repeat("y", 40)}},
		{"an empty row", otherOpt{empty: true}},
	} {
		c, v := closedWith(t, receipted)
		x.oo.at = notMine(v, 0)
		out, err := c.f.SubmitResults(c.session(), "svc", v.ID, c.resultsFor(v, resOpts{mine: c.ownBallot(v), others: []otherOpt{x.oo}}))
		if err != nil || out.State != CheckFailed || out.Reason != "row_duplicate" {
			t.Fatalf("%s: %+v %v", x.name, out, err)
		}
		if !c.has("vote.check_failed", v.ID+":row_duplicate") || c.problems(v.ID) != 1 || !c.rec(v.ID).problem() {
			t.Errorf("%s: audit, feed or problem set", x.name)
		}
		ev := c.evidence(t, v.ID)
		res, _ := ev.Object("results")
		arr, err := res.Array("other_rows")
		if err != nil || len(arr) != 1 {
			t.Fatalf("%s: other_rows %v: %v", x.name, err, res)
		}
		eo, _ := strictjson.AsObject(arr[0])
		ro, _ := eo.Object("row")
		if !x.oo.empty {
			bo, err := ro.Object("ballot")
			if err != nil {
				t.Fatalf("%s: %v", x.name, err)
			}
			if pad, err := bo.String("pad"); err != nil || pad != votewire.Pad(x.oo.choice) || len(pad)+len(x.oo.choice) != max(32, len(x.oo.choice)) {
				t.Errorf("%s: pad %q %v", x.name, pad, err)
			}
		} else if string(ro["ballot"]) != "null" {
			t.Errorf("%s: %s", x.name, ro["ballot"])
		}
		if !eo.Has("proof") {
			t.Errorf("%s: no proof", x.name)
		}
		if ck, _ := ev.Object("check"); func() string { s, _ := ck.String("reason"); return s }() != "row_duplicate" {
			t.Errorf("%s: check %v", x.name, ev["check"])
		}
		// A repeat is answered with that state.
		if out, _ := c.f.SubmitResults(c.session(), "svc", v.ID, c.resultsFor(v, resOpts{mine: c.ownBallot(v)})); out.State != CheckFailed || out.Reason != "row_duplicate" {
			t.Errorf("%s: repeat %+v", x.name, out)
		}
	}
}

func TestRowDuplicatePrecedence(t *testing.T) {
	dup := func(v *votetest.Vote) []otherOpt { return []otherOpt{{at: notMine(v, 0), choice: "no"}} }
	_, vkOther, _ := ed25519.GenerateKey(rand.Reader)
	t.Run("row_mismatch", func(t *testing.T) {
		c, v := closedWith(t, receipted)
		out, _ := c.f.SubmitResults(c.session(), "svc", v.ID, c.resultsFor(v, resOpts{others: dup(v)})) // an empty main row
		if out.State != CheckFailed || out.Reason != "row_duplicate" {
			t.Errorf("%+v", out)
		}
	})
	t.Run("row_unexpected", func(t *testing.T) {
		c, v := closedWith(t, nil)
		row := must(votewire.SignBallot(vkOther, v.Hash, v.Tag, "no"))
		out, _ := c.f.SubmitResults(c.session(), "svc", v.ID, c.resultsFor(v, resOpts{mine: row, others: dup(v)}))
		if out.State != CheckFailed || out.Reason != "row_duplicate" {
			t.Errorf("%+v", out)
		}
	})
	t.Run("conflict", func(t *testing.T) {
		c, v := closedWith(t, func(c *cenv, v *votetest.Vote) {
			receipted(c, v)
			r := c.rec(v.ID)
			c.f.foreign(c.session(), r, r.Ballot, &svcBallot{VK: vkOther[32:], ChoiceID: "no", BallotSig: make([]byte, 64)}, false)
		})
		out, _ := c.f.SubmitResults(c.session(), "svc", v.ID, c.resultsFor(v, resOpts{mine: c.ownBallot(v), others: dup(v)}))
		if out.State != CheckFailed || out.Reason != "row_duplicate" {
			t.Errorf("%+v", out)
		}
	})
	t.Run("an index other than the record proof's", func(t *testing.T) {
		c, v := closedWith(t, nil)
		// The main row's proof is at another index than the member's, and
		// the second copy is at the member's own.
		at := notMine(v, 0)
		out, _ := c.f.SubmitResults(c.session(), "svc", v.ID, c.resultsFor(v, resOpts{dupAt: &at, others: []otherOpt{{at: v.Index, empty: true}}}))
		if out.State != CheckFailed || out.Reason != "row_duplicate" {
			t.Errorf("%+v", out)
		}
		// Without the second row it is the index failure.
		c, v = closedWith(t, nil)
		at = notMine(v, 0)
		out, _ = c.f.SubmitResults(c.session(), "svc", v.ID, c.resultsFor(v, resOpts{dupAt: &at}))
		if out.State != CheckFailed || out.Reason != "results" {
			t.Errorf("%+v", out)
		}
	})
	t.Run("input beside a duplicate", func(t *testing.T) {
		c, v := closedWith(t, nil)
		out, _ := c.f.SubmitResults(c.session(), "svc", v.ID, c.resultsFor(v, resOpts{others: []otherOpt{{at: notMine(v, 0), notInTree: true, choice: "no"}, {at: notMine(v, 1), choice: "no"}}}))
		if out.State != CheckFailed || out.Reason != "row_duplicate" {
			t.Errorf("%+v", out)
		}
	})
}

// An entry that does not verify, sits at the main row's index or states a
// tree of another size leaves the check pending (input), and a later
// correct submission is judged.
func TestOtherRowsInput(t *testing.T) {
	cases := map[string]func(v *votetest.Vote) []otherOpt{
		"another tag at that index": func(v *votetest.Vote) []otherOpt {
			return []otherOpt{{at: notMine(v, 0), choice: "no", notInTree: true}}
		},
		"the main row's index": func(v *votetest.Vote) []otherOpt {
			return []otherOpt{{at: v.Index, empty: true, notInTree: true}}
		},
		"an index twice": func(v *votetest.Vote) []otherOpt {
			return []otherOpt{{at: notMine(v, 0), choice: "no", notInTree: true}, {at: notMine(v, 0), choice: "no", notInTree: true}}
		},
	}
	for name, mk := range cases {
		c, v := closedWith(t, nil)
		out, err := c.f.SubmitResults(c.session(), "svc", v.ID, c.resultsFor(v, resOpts{others: mk(v)}))
		if err != nil || out.State != CheckPending || out.Reason != "input" || c.rec(v.ID).Check == CheckFailed {
			t.Errorf("%s: %+v %v", name, out, err)
		}
		if c.problems(v.ID) != 0 || c.has("vote.check_failed", "") {
			t.Errorf("%s: raised a problem", name)
		}
		if out, _ = c.f.SubmitResults(c.session(), "svc", v.ID, c.resultsFor(v, resOpts{})); out.State != CheckVerified {
			t.Errorf("%s: later %+v", name, out)
		}
	}
	c, v := closedWith(t, nil)
	in := c.resultsFor(v, resOpts{others: []otherOpt{{at: notMine(v, 0), choice: "no"}}})
	in.Others[0].Proof.TreeSize++
	if out, _ := c.f.SubmitResults(c.session(), "svc", v.ID, in); out.State != CheckPending || out.Reason != "input" {
		t.Errorf("tree size: %+v", out)
	}
	in = c.resultsFor(v, resOpts{others: []otherOpt{{at: notMine(v, 0), choice: "no"}}})
	in.Others[0].Bad = true
	if out, _ := c.f.SubmitResults(c.session(), "svc", v.ID, in); out.State != CheckPending || out.Reason != "input" {
		t.Errorf("undecodable: %+v", out)
	}
}

// submitBody is vote.results.submit's body for in with the members given.
func submitBody(v *votetest.Vote, in ResultsSubmit, members ...string) string {
	b := strictjson.NewBuilder().String("connection_id", "svc").String("proposal_id", v.ID).Base64("results", in.Results).
		Base64("results_sig", in.Sig).Raw("bundle", in.Bundle).Bytes()
	for _, m := range members {
		b = append(b[:len(b)-1], ',')
		b = append(append(b, m...), '}')
	}
	return string(b)
}

func rowMember(in ResultsSubmit) string {
	return `"row":{"ballot":null},"row_proof":` + string(in.Proof.JSON())
}

func otherJSON(o OtherRow, pad string) string {
	ballot := `null`
	if !o.Empty {
		ballot = string(strictjson.NewBuilder().Base64("vk", o.VK).String("choice_id", o.ChoiceID).Base64("ballot_sig", o.BallotSig).Bytes())
		ballot = ballot[:len(ballot)-1] + pad + "}"
	}
	return `{"row":{"ballot":` + ballot + `},"proof":` + string(o.Proof.JSON()) + `}`
}

func otherRowsMember(in ResultsSubmit, pad string) string {
	var parts []string
	for _, o := range in.Others {
		parts = append(parts, otherJSON(o, pad))
	}
	return `"other_rows":[` + strings.Join(parts, ",") + `]`
}

func TestAPIOtherRows(t *testing.T) {
	c, v := closedElig(t, 9, nil)
	mk := func(n int) ResultsSubmit {
		var oo []otherOpt
		for i := 0; i < n; i++ {
			oo = append(oo, otherOpt{at: notMine(v, i), choice: "no"})
		}
		return c.resultsFor(v, resOpts{others: oo})
	}
	// More than 4 entries.
	in := mk(5)
	if r := c.app("vote.results.submit", submitBody(v, in, rowMember(in), otherRowsMember(in, ""))); r.Code != "bad_request" {
		t.Errorf("5 entries: %q", r.Code)
	}
	if c.rec(v.ID).Check == CheckFailed {
		t.Error("failed")
	}
	// Only a value that is not an array is a bad request.
	in = mk(1)
	good := otherJSON(in.Others[0], "")
	for name, m := range map[string]string{
		"not an array": `"other_rows":{}`,
		"null":         `"other_rows":null`,
	} {
		if r := c.app("vote.results.submit", submitBody(v, in, rowMember(in), m)); r.Code != "bad_request" {
			t.Errorf("%s: %q", name, r.Code)
		}
	}
	// A bad entry (shape or members) is input for that entry: pending, input.
	pj := string(in.Others[0].Proof.JSON())
	for name, m := range map[string]string{
		"entry not object":  `"other_rows":[1]`,
		"no proof":          `"other_rows":[{"row":{"ballot":null}}]`,
		"no row":            `"other_rows":[{"proof":` + pj + `}]`,
		"row without":       `"other_rows":[{"row":{},"proof":` + pj + `}]`,
		"ballot not object": `"other_rows":[{"row":{"ballot":3},"proof":` + pj + `}]`,
		"bad vk":            `"other_rows":[` + strings.Replace(good, `"vk":"`, `"vk":"!`, 1) + `]`,
		"bad proof":         `"other_rows":[{"row":{"ballot":null},"proof":{"index":"x"}}]`,
	} {
		r := c.app("vote.results.submit", submitBody(v, in, rowMember(in), m))
		if !r.OK() {
			t.Errorf("%s: %q", name, r.Code)
			continue
		}
		ck, _ := obj(t, r).Object("check")
		if st, _ := ck.String("state"); st != CheckPending {
			t.Errorf("%s: %s", name, r.Body)
		}
		if why, _ := ck.String("reason"); why != "input" {
			t.Errorf("%s: %s", name, r.Body)
		}
	}
	// Unknown members of an entry and of its row are ignored: a verifying
	// second row is judged.
	for name, m := range map[string]string{
		"entry member": `"other_rows":[` + good[:len(good)-1] + `,"x":1}]`,
		"row member":   `"other_rows":[` + strings.Replace(good, `"row":{`, `"row":{"x":1,`, 1) + `]`,
	} {
		r := c.app("vote.results.submit", submitBody(v, in, rowMember(in), m))
		ck, _ := obj(t, r).Object("check")
		if st, _ := ck.String("state"); st != CheckFailed {
			t.Errorf("%s: %s", name, r.Body)
		}
		c.rec(v.ID).Check, c.rec(v.ID).CheckReason = CheckPending, ""
	}
	// Four entries, each with pad of any form, are accepted and judged.
	in = mk(4)
	for _, pad := range []string{``, `,"pad":"` + votewire.Pad("no") + `"`, `,"pad":"x"`, `,"pad":7`} {
		r := c.app("vote.results.submit", submitBody(v, in, rowMember(in), otherRowsMember(in, pad)))
		ck, _ := obj(t, r).Object("check")
		if st, _ := ck.String("state"); st != CheckFailed {
			t.Fatalf("pad %q: %s", pad, r.Body)
		}
		if rs := c.rec(v.ID).Results; rs == nil || len(rs.Others) != 4 {
			t.Fatalf("pad %q: kept %+v", pad, rs)
		}
		c.rec(v.ID).Check, c.rec(v.ID).CheckReason = CheckPending, "" // judge it again
	}
	// A duplicate pad is refused by the strict parse.
	r := c.app("vote.results.submit", submitBody(v, in, rowMember(in), otherRowsMember(in, `,"pad":"","pad":""`)))
	if r.Code != "bad_request" {
		t.Errorf("duplicate pad: %q", r.Code)
	}
}

// rows_unavailable is a call of its own: with a row, a proof or other rows
// it is a bad request, and it is `true` or absent.
func TestAPIRowsUnavailableShape(t *testing.T) {
	c, v := closedWith(t, nil)
	in := c.resultsFor(v, resOpts{})
	for name, m := range map[string][]string{
		"with row":        {`"rows_unavailable":true`, `"row":{"ballot":null}`},
		"with row_proof":  {`"rows_unavailable":true`, `"row_proof":` + string(in.Proof.JSON())},
		"with other_rows": {`"rows_unavailable":true`, `"other_rows":[]`},
		"with all":        {`"rows_unavailable":true`, rowMember(in), `"other_rows":[]`},
		"a string":        {`"rows_unavailable":"true"`},
		"null":            {`"rows_unavailable":null`},
	} {
		if r := c.app("vote.results.submit", submitBody(v, in, m...)); r.Code != "bad_request" {
			t.Errorf("%s: %q", name, r.Code)
		}
	}
	if k := c.rec(v.ID).Check; k == CheckFailed || c.rec(v.ID).CheckReason != "" {
		t.Errorf("a bad request changed the check: %q", k)
	}
	// false is as absent: a normal submission with a row is judged.
	if r := c.app("vote.results.submit", submitBody(v, in, `"rows_unavailable":false`)); r.Code != "bad_request" {
		t.Errorf("false without a row: %q", r.Code)
	}
	if r := c.app("vote.results.submit", submitBody(v, in, `"rows_unavailable":false`, rowMember(in))); !r.OK() {
		t.Errorf("false with a row: %q", r.Code)
	} else if ck, _ := obj(t, r).Object("check"); func() string { s, _ := ck.String("state"); return s }() != CheckVerified {
		t.Errorf("false with a row: %s", r.Body)
	}
	c, v = closedWith(t, nil)
	in = c.resultsFor(v, resOpts{})
	r := c.app("vote.results.submit", submitBody(v, in, `"rows_unavailable":true`))
	ck, _ := obj(t, r).Object("check")
	if st, _ := ck.String("state"); st != CheckPending {
		t.Fatalf("%s", r.Body)
	}
	if rs, _ := ck.String("reason"); rs != "rows_unavailable" {
		t.Errorf("%s", r.Body)
	}
}

func checkOf(t *testing.T, c *cenv, id string) (state, reason string) {
	t.Helper()
	g := obj(t, c.app("vote.get", pairBody("svc", id)))
	ck, err := g.Object("check")
	if err != nil {
		t.Fatal(err)
	}
	state, _ = ck.String("state")
	reason, _ = ck.String("reason")
	return
}

// rows_unavailable: the check stays pending (reason rows_unavailable) with
// one vote.problem, a later verifying row is judged, at 7 days it is gave_up
// with the reason, and the record is a problem record that is never evicted.
func TestRowsUnavailable(t *testing.T) {
	c, v := closedWith(t, nil)
	in := c.resultsFor(v, resOpts{})
	ru := in
	ru.Row, ru.Proof, ru.Others, ru.RowsUnavailable = nil, nil, nil, true
	for i := 0; i < 3; i++ {
		out, err := c.f.SubmitResults(c.session(), "svc", v.ID, ru)
		if err != nil || out.State != CheckPending || out.Reason != "rows_unavailable" {
			t.Fatalf("%d: %+v %v", i, out, err)
		}
	}
	r := c.rec(v.ID)
	if r.Check != CheckPending || r.CheckReason != "rows_unavailable" || !r.problem() || r.evictable(c.now) {
		t.Fatalf("%q %q problem=%v", r.Check, r.CheckReason, r.problem())
	}
	if c.problems(v.ID) != 1 || c.countKind("vote.check_failed") != 0 {
		t.Errorf("%d vote.problem items", c.problems(v.ID))
	}
	if st, why := checkOf(t, c, v.ID); st != CheckPending || why != "rows_unavailable" {
		t.Errorf("vote.get check %q %q", st, why)
	}
	if st, why := func() (string, string) {
		ev := c.evidence(t, v.ID)
		ck, _ := ev.Object("check")
		s, _ := ck.String("state")
		w, _ := ck.String("reason")
		return s, w
	}(); st != CheckPending || why != "rows_unavailable" {
		t.Errorf("vote.evidence check %q %q", st, why)
	}
	// Contradictions in the results themselves are judged as usual.
	bad := c.resultsFor(v, resOpts{tamper: func(r *votewire.Results) { r.Counts.Eligible++ }})
	bad.Row, bad.Proof, bad.RowsUnavailable = nil, nil, true
	if out, _ := c.f.SubmitResults(c.session(), "svc", v.ID, bad); out.State != CheckFailed || out.Reason != "results" {
		t.Errorf("contradiction: %+v", out)
	}
}

func TestRowsUnavailableThenRow(t *testing.T) {
	c, v := closedWith(t, nil)
	ru := c.resultsFor(v, resOpts{})
	ru.Row, ru.Proof, ru.RowsUnavailable = nil, nil, true
	c.f.SubmitResults(c.session(), "svc", v.ID, ru)
	// A submission that is no answer leaves it as it was.
	if out, _ := c.f.SubmitResults(c.session(), "svc", v.ID, c.resultsFor(v, resOpts{badSig: true})); out.State != CheckPending || out.Reason != "input" {
		t.Errorf("%+v", out)
	}
	if r := c.rec(v.ID); r.CheckReason != "rows_unavailable" {
		t.Errorf("%q", r.CheckReason)
	}
	out, _ := c.f.SubmitResults(c.session(), "svc", v.ID, c.resultsFor(v, resOpts{}))
	if out.State != CheckVerified || out.Reason != "" {
		t.Fatalf("%+v", out)
	}
	if r := c.rec(v.ID); r.CheckReason != "" || r.problem() {
		t.Errorf("%q problem=%v", r.CheckReason, r.problem())
	}
	// A verified check answers a later rows_unavailable with its state.
	if out, _ := c.f.SubmitResults(c.session(), "svc", v.ID, ru); out.State != CheckVerified || out.Reason != "" || c.problems(v.ID) != 1 {
		t.Errorf("%+v %d", out, c.problems(v.ID))
	}
	// A failed one too.
	c, v = closedWith(t, receipted)
	c.f.SubmitResults(c.session(), "svc", v.ID, c.resultsFor(v, resOpts{}))
	if c.rec(v.ID).Check != CheckFailed {
		t.Fatal("not failed")
	}
	ru = c.resultsFor(v, resOpts{})
	ru.Row, ru.Proof, ru.RowsUnavailable = nil, nil, true
	if out, _ := c.f.SubmitResults(c.session(), "svc", v.ID, ru); out.State != CheckFailed || out.Reason != "row_mismatch" {
		t.Errorf("%+v", out)
	}
	// A verifying row after the row was unavailable can fail too.
	c, v = closedWith(t, receipted)
	ru = c.resultsFor(v, resOpts{})
	ru.Row, ru.Proof, ru.RowsUnavailable = nil, nil, true
	c.f.SubmitResults(c.session(), "svc", v.ID, ru)
	if out, _ := c.f.SubmitResults(c.session(), "svc", v.ID, c.resultsFor(v, resOpts{})); out.State != CheckFailed || out.Reason != "row_mismatch" {
		t.Errorf("%+v", out)
	}
}

func TestRowsUnavailableGivesUp(t *testing.T) {
	c, v := closedWith(t, nil)
	ru := c.resultsFor(v, resOpts{})
	ru.Row, ru.Proof, ru.RowsUnavailable = nil, nil, true
	good := c.resultsFor(v, resOpts{})
	c.f.SubmitResults(c.session(), "svc", v.ID, ru)
	r := c.rec(v.ID)
	c.now = r.dueAt().Add(CheckGiveUp + time.Second)
	c.f.Tick(c.session())
	if r.Check != CheckGaveUp || r.CheckReason != "rows_unavailable" || !r.problem() || r.evictable(c.now) {
		t.Fatalf("%q %q", r.Check, r.CheckReason)
	}
	if st, why := checkOf(t, c, v.ID); st != CheckGaveUp || why != "rows_unavailable" {
		t.Errorf("vote.get check %q %q", st, why)
	}
	if n := c.countKind("vote.result"); n != 1 || !c.has("vote.check_gave_up", v.ID) {
		t.Errorf("%d vote.result items", n)
	}
	// Again at gave_up: still gave_up with the reason, and no second problem.
	if out, _ := c.f.SubmitResults(c.session(), "svc", v.ID, ru); out.State != CheckGaveUp || out.Reason != "rows_unavailable" || c.problems(v.ID) != 1 {
		t.Errorf("%+v problems=%d", out, c.problems(v.ID))
	}
	// A later verifying row is judged as usual.
	if out, _ := c.f.SubmitResults(c.session(), "svc", v.ID, good); out.State != CheckVerified || c.rec(v.ID).problem() {
		t.Errorf("%+v", out)
	}
}

// A gave_up check that meets rows_unavailable for the first time keeps
// gave_up, takes the reason and raises one vote.problem, at most one for the
// record.
func TestRowsUnavailableAfterGaveUp(t *testing.T) {
	c, v := closedWith(t, nil)
	ru := c.resultsFor(v, resOpts{})
	ru.Row, ru.Proof, ru.RowsUnavailable = nil, nil, true
	r := c.rec(v.ID)
	c.now = r.dueAt().Add(CheckGiveUp + time.Second)
	c.f.Tick(c.session())
	if r.Check != CheckGaveUp || r.CheckReason != "" {
		t.Fatalf("%q %q", r.Check, r.CheckReason)
	}
	for i := 0; i < 2; i++ {
		out, _ := c.f.SubmitResults(c.session(), "svc", v.ID, ru)
		if out.State != CheckGaveUp || out.Reason != "rows_unavailable" || r.Check != CheckGaveUp || r.CheckReason != "rows_unavailable" || c.problems(v.ID) != 1 {
			t.Fatalf("%d: %+v problems=%d", i, out, c.problems(v.ID))
		}
	}
}

// A check pending with rows_unavailable is a problem record: not "in
// progress", counted apart from the 32, and never evicted.
func TestRowsUnavailableIsNotEvicted(t *testing.T) {
	e := newEnv(t)
	e.publish(e.svc)
	e.closedVote(1)
	e.rec(lid(1)).Check, e.rec(lid(1)).CheckReason = CheckPending, CheckRowsUnavailable
	for i := 2; i <= votewire.MaxPerConnection+1; i++ {
		e.closedVote(i)
		e.rec(lid(i)).Check = CheckVerified
	}
	if len(e.f.st.Records) != votewire.MaxPerConnection+1 {
		t.Fatalf("%d records", len(e.f.st.Records))
	}
	e.closedVote(100)
	if e.rec(lid(1)) == nil || e.rec(lid(2)) != nil {
		t.Fatalf("the rows_unavailable record or the oldest clean one: %v %v", e.rec(lid(1)) != nil, e.rec(lid(2)) != nil)
	}
	r := e.rec(lid(1))
	if !r.problem() || r.evictable(e.now) {
		t.Error("not a problem record")
	}
	// It counts toward the cap of 16 problems.
	for i := 200; i < 200+votewire.MaxProblemsPerConnection-1; i++ {
		e.closedVote(i)
		e.rec(lid(i)).Check = CheckFailed
	}
	if hit := e.f.admit(&record{Conn: "svc", ID: lid(999), Opens: e.now.Unix() - 3600, Closes: e.now.Unix() - 10}, e.now); hit == nil || !hit.problems {
		t.Errorf("problem cap: %+v", hit)
	}
}

// A proposal with `eligible` 100,000 is accepted and 100,001 is refused
// (malformed).
func TestEligibleBound(t *testing.T) {
	e := newEnv(t)
	e.publish(e.svc)
	v := e.svc.NewVote(votetest.VoteSpec{ID: lid(1), Opens: e.now.Add(-time.Hour), Closes: e.now.Add(time.Hour), Eligible: 100000})
	if r := e.send(v); !r.OK() || e.rec(lid(1)) == nil || e.rec(lid(1)).RejectReason != "" {
		t.Fatalf("100,000: %q", r.Code)
	}
	w := e.svc.NewVote(votetest.VoteSpec{ID: lid(2), Opens: e.now.Add(-time.Hour), Closes: e.now.Add(time.Hour), Eligible: 100001})
	e.h.Reset()
	if r := e.send(w); r.Code != "bad_request" || !e.has("vote.proposal_rejected", lid(2)+":malformed") {
		t.Fatalf("100,001: %q", r.Code)
	}
	if rec := e.rec(lid(2)); rec != nil && rec.RejectReason != "malformed" {
		t.Errorf("rejected as %q", rec.RejectReason)
	}
}

// A service's vote.status answer and an already_voted refusal whose ballot
// carries pad are accepted, whatever the pad.
func TestServiceBallotsMayCarryPad(t *testing.T) {
	pads := []string{``, `,"pad":"` + votewire.Pad("yes") + `"`, `,"pad":""`, `,"pad":"` + strings.Repeat("0", 99) + `"`, `,"pad":7`}
	for _, pad := range pads {
		c := newCastEnv(t)
		v := c.open(1)
		c.cast(v, "yes")
		if err := c.f.Check(c.session(), "svc", v.ID); err != nil {
			t.Fatal(err)
		}
		ids := c.statuses()
		own := c.ownBallot(v)
		now := uint64(c.now.UnixMilli())
		leaf := must(own.Leaf())
		rsig, _ := suite.Sign(c.svc.IK, votewire.LabelReceipt, must(votewire.ReceiptMsg(v.Hash, leaf, now)))
		ssig, _ := suite.Sign(c.svc.IK, votewire.LabelStatus, must(votewire.StatusMsg(v.ID, v.Tag, leaf)))
		body := c.statusBody(v, &votewire.RowBallot{VK: own.VK, ChoiceID: own.ChoiceID, BallotSig: own.BallotSig}, now, rsig, ssig)
		body = bytes.Replace(body, []byte(`"choice_id":"yes"`), []byte(`"choice_id":"yes"`+pad), 1)
		c.respond(ids[0], "vote.status", &envelope.Inner{Status: envelope.StatusOK, Body: body})
		if c.state(v) != BallotRecorded {
			t.Errorf("status answer, pad %q: %s", pad, c.state(v))
		}
	}
	for _, pad := range pads {
		c := newCastEnv(t)
		v := c.open(1)
		c.cast(v, "yes")
		_, ids := c.casts()
		own := c.ownBallot(v)
		leaf := must(own.Leaf())
		msgMS := uint64(c.now.UnixMilli())
		rsig, _ := suite.Sign(c.svc.IK, votewire.LabelReceipt, must(votewire.ReceiptMsg(v.Hash, leaf, msgMS)))
		msg := must(votewire.RefusalMsg(v.ID, votewire.H(c.h.IK), v.Tag, "vote.cast", "already_voted", msgMS, votewire.H(leaf)))
		sig, _ := suite.Sign(c.svc.IK, votewire.LabelRefusal, msg)
		ballot := strictjson.NewBuilder().Base64("vk", own.VK).String("choice_id", own.ChoiceID).Base64("ballot_sig", own.BallotSig).Bytes()
		ballot = append(ballot[:len(ballot)-1:len(ballot)-1], append([]byte(pad), '}')...)
		body := strictjson.NewBuilder().Base64("refusal_sig", sig).Uint("msg_ms", msgMS).Base64("connection", votewire.H(c.h.IK)).Base64("record_tag", v.Tag).
			Raw("ballot", ballot).Uint("ballot_msg_ms", msgMS).Base64("receipt_sig", rsig).Bytes()
		c.respond(ids[0], "vote.cast", &envelope.Inner{Status: envelope.StatusError, Error: &envelope.Error{Code: "already_voted"}, Body: body})
		if c.state(v) != BallotRecorded {
			t.Errorf("already_voted, pad %q: %s", pad, c.state(v))
		}
	}
}

// reload makes the feature again from its saved state, as a restart does.
func (c *cenv) reload() {
	c.t.Helper()
	raw, err := c.f.Save()
	if err != nil {
		c.t.Fatal(err)
	}
	f := New(Options{SiteKey: c.site.Public().(ed25519.PublicKey), Roots: c.env.auth.Roots})
	f.dep = c.f.dep
	if err := f.Load(raw); err != nil {
		c.t.Fatal(err)
	}
	c.f = f
}

// The reason, the once-flag and the extra rows survive a save and a load.
func TestRowsStateSurvivesARestart(t *testing.T) {
	c, v := closedWith(t, nil)
	ru := c.resultsFor(v, resOpts{})
	ru.Row, ru.Proof, ru.RowsUnavailable = nil, nil, true
	c.f.SubmitResults(c.session(), "svc", v.ID, ru)
	c.reload()
	r := c.rec(v.ID)
	if r.Check != CheckPending || r.CheckReason != "rows_unavailable" || !r.RowsProblem || !r.problem() {
		t.Fatalf("%q %q %v", r.Check, r.CheckReason, r.RowsProblem)
	}
	if st, why := checkOf(t, c, v.ID); st != CheckPending || why != "rows_unavailable" {
		t.Errorf("vote.get %q %q", st, why)
	}
	n := c.problems(v.ID)
	c.f.SubmitResults(c.session(), "svc", v.ID, ru)
	if c.problems(v.ID) != n {
		t.Error("a second vote.problem after a restart")
	}
	// Extra rows.
	c, v = closedWith(t, receipted)
	c.f.SubmitResults(c.session(), "svc", v.ID, c.resultsFor(v, resOpts{mine: c.ownBallot(v), others: []otherOpt{{at: notMine(v, 0), choice: "No!"}}}))
	c.reload()
	if rs := c.rec(v.ID).Results; rs == nil || len(rs.Others) != 1 || rs.Others[0].Row.ChoiceID != "No!" {
		t.Fatalf("%+v", rs)
	}
	res, _ := c.evidence(t, v.ID).Object("results")
	if arr, _ := res.Array("other_rows"); len(arr) != 1 {
		t.Errorf("evidence after a restart: %v", res)
	}
	if r := c.rec(v.ID); r.Check != CheckFailed || r.CheckReason != "row_duplicate" {
		t.Errorf("%q %q", r.Check, r.CheckReason)
	}
	// Gave up with the reason, and the once, after a restart.
	c, v = closedWith(t, nil)
	ru = c.resultsFor(v, resOpts{})
	ru.Row, ru.Proof, ru.RowsUnavailable = nil, nil, true
	c.f.SubmitResults(c.session(), "svc", v.ID, ru)
	c.now = c.rec(v.ID).dueAt().Add(CheckGiveUp + time.Second)
	c.reload()
	c.f.Tick(c.session())
	if r := c.rec(v.ID); r.Check != CheckGaveUp || r.CheckReason != "rows_unavailable" || !r.RowsProblem {
		t.Fatalf("%q %q %v", r.Check, r.CheckReason, r.RowsProblem)
	}
}

// A rows_unavailable submission that adopts an extension changes the
// record, so an earlier evidence export is no longer current.
func TestRowsUnavailableAdoptingAnExtensionIsAChange(t *testing.T) {
	c := newCastEnv(t)
	v := c.open(1)
	closes := time.Unix(c.rec(v.ID).Closes, 0)
	doc, _ := c.svc.Extension(v, 1, closes.Add(time.Hour), c.now)
	extra := votewire.Signed{Doc: doc, Sig: signExt(c.svc, v, doc)}
	c.now = closes.Add(time.Hour + CheckDelay + time.Minute)
	c.f.Tick(c.session())
	// The first submission (no extension) is the one that sets the reason.
	first := c.resultsFor(v, resOpts{})
	first.Row, first.Proof, first.RowsUnavailable = nil, nil, true
	if out, _ := c.f.SubmitResults(c.session(), "svc", v.ID, first); out.State != CheckPending {
		t.Fatalf("%+v", out)
	}
	c.now = c.now.Add(time.Minute)
	c.evidence(t, v.ID) // the export is current now
	r := c.rec(v.ID)
	exported := r.EvidenceMS
	if r.ChangedMS > exported {
		t.Fatalf("changed %d after the export %d", r.ChangedMS, exported)
	}
	c.now = c.now.Add(time.Minute)
	again := c.resultsFor(v, resOpts{extra: []votewire.Signed{extra}})
	again.Row, again.Proof, again.RowsUnavailable = nil, nil, true
	out, _ := c.f.SubmitResults(c.session(), "svc", v.ID, again)
	if out.State != CheckPending || len(r.Exts) != 1 {
		t.Fatalf("%+v exts=%d", out, len(r.Exts))
	}
	if r.ChangedMS != c.now.UnixMilli() || r.ChangedMS <= exported {
		t.Errorf("changed %d, exported %d", r.ChangedMS, exported)
	}
}

// vote.closed's results_hash is compared on a row_duplicate too.
func TestRowDuplicateSetsResultsMatch(t *testing.T) {
	c, v := closedWith(t, receipted)
	in := c.resultsFor(v, resOpts{mine: c.ownBallot(v), others: []otherOpt{{at: notMine(v, 0), choice: "no"}}})
	c.rec(v.ID).ResultsHash = votewire.H(in.Results)
	c.f.SubmitResults(c.session(), "svc", v.ID, in)
	if r := c.rec(v.ID); r.Check != CheckFailed || r.ResultsMatch != "yes" {
		t.Errorf("%q match=%q", r.Check, r.ResultsMatch)
	}
}

// 0.88.12: a record whose only problem is self_unrecorded or
// self_conflict does not count toward the cap of 16 problems and is never
// evicted; (GC #7991 D) two receipts for one tag do count. Reached through
// the service's answers.
func TestProblemCapSelfOnly(t *testing.T) {
	keep := func(c *cenv, n int) bool {
		v := c.svc.NewVote(votetest.VoteSpec{ID: lid(n), Opens: c.now.Add(-time.Hour), Closes: c.now.Add(2 * time.Hour)})
		return c.send(v).OK()
	}
	c := newCastEnv(t)
	for i := 1; i <= votewire.MaxProblemsPerConnection; i++ {
		v := c.open(i)
		shown := c.selfBallot(v, "no")
		if i%2 == 0 {
			c.cast(v, "yes") // self_conflict, the vault's ballot unreceipted
		}
		c.f.Check(c.session(), "svc", v.ID)
		ids := c.statuses()
		c.answer(v, ids[len(ids)-1], shown, uint64(c.now.UnixMilli()), true)
		r := c.rec(v.ID)
		if !(r.SelfUnrecorded || r.SelfConflict) || !r.problem() || r.capProblem() || r.evictable(c.now) {
			t.Fatalf("%d: %+v", i, r)
		}
	}
	if !keep(c, 99) {
		t.Error("self-only records hit the cap")
	}
	// Two receipts for one tag count.
	c = newCastEnv(t)
	for i := 1; i <= votewire.MaxProblemsPerConnection; i++ {
		v := c.open(i)
		shown := c.selfBallot(v, "no")
		c.cast(v, "yes")
		_, ids := c.casts()
		c.okReceipt(v, ids[len(ids)-1], c.leafOf(v), uint64(c.now.UnixMilli()))
		c.f.Check(c.session(), "svc", v.ID)
		st := c.statuses()
		c.answer(v, st[len(st)-1], shown, uint64(c.now.UnixMilli()), true)
		if r := c.rec(v.ID); !r.TwoReceipts || !r.capProblem() {
			t.Fatalf("%d: two receipts %v", i, r.TwoReceipts)
		}
	}
	if keep(c, 99) {
		t.Error("two receipts do not count toward the cap")
	}
}
