package vote

import (
	"fmt"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/votetest"
	"github.com/vettid/vettid-vault/vms/votewire"
)

// VAULT-MESSAGING 0.90.20 §10.19.4 (owner decision 2026-11-18): a signed
// not_eligible for a proposal on the votes site that the vault was never
// sent is kept as a record of its own, shown and exportable.

func noTag(o *refOpts) { o.tag = nil }

// notHeld returns an env with the service connected, a proposal w on the
// site the vault does not hold, and the status request asked for it.
func notHeld(t *testing.T) (*cenv, *votetest.Vote, string) {
	t.Helper()
	c := newCastEnv(t)
	c.open(1) // the service's connection
	w := c.svc.NewVote(votetest.VoteSpec{ID: lid(40), Opens: c.now.Add(-time.Hour), Closes: c.now.Add(time.Hour)})
	if !c.f.RequestProposal(c.session(), "svc", w.ID, c.sitePublished(w)) {
		t.Fatal("not asked")
	}
	ids := c.statuses()
	return c, w, ids[len(ids)-1]
}

func TestNotHeldNotEligibleIsKept(t *testing.T) {
	c, w, sid := notHeld(t)
	c.refusal(w, sid, "vote.status", "not_eligible", votewire.H([]byte(w.ID)), noTag)
	r := c.rec(w.ID)
	if r == nil || !r.NotEligible || len(r.StatusAnswers) != 1 || !r.StatusAnswers[0].Pinned || r.StatusAnswers[0].Code != "not_eligible" {
		t.Fatalf("%+v", r)
	}
	if !c.has("vote.refused", w.ID+":not_eligible") || c.has("vote.open", w.ID) || c.has("vote.closing", w.ID) {
		t.Error("the audit, or a vote.open / vote.closing item")
	}
	if !r.RefusalProblem || c.count("vote.problem") != 1 || len(r.VKSeed) != 0 || r.Tag != nil {
		t.Errorf("problem %v, vote.problem %d, seed %d, tag %v", r.RefusalProblem, c.count("vote.problem"), len(r.VKSeed), r.Tag)
	}
	// vote.list / vote.get: listed, not castable, said so.
	g := obj(t, c.app("vote.get", pairBody("svc", w.ID)))
	if !boolOf(g, "not_eligible") || boolOf(g, "can_cast") {
		t.Errorf("vote.get: %v", g)
	}
	if cc, _ := g.String("cannot_cast"); cc != "not_eligible" {
		t.Errorf("cannot_cast %q", cc)
	}
	if _, err := c.cast(w, "yes"); code(err) != "not_eligible" {
		t.Errorf("cast: %q", code(err))
	}
	// The export carries the proof: the site's documents and the signed refusal with its code.
	ev := obj(t, c.app("vote.evidence", pairBody("svc", w.ID)))
	eo, _ := ev.Object("evidence")
	if !boolOf(eo, "not_eligible") || string(eo["status_answer_codes"]) != `["not_eligible"]` {
		t.Errorf("evidence: %s %s", eo["not_eligible"], eo["status_answer_codes"])
	}
	if p, _ := eo.Base64("proposal", -1); string(p) != string(w.Doc) {
		t.Error("the site's proposal is not exported")
	}
	// Nothing is asked again for it.
	c.h.Reset()
	c.now = c.now.Add(3 * time.Hour)
	c.f.Tick(c.session())
	if len(c.statuses()) != 0 || len(c.h.Sent) != 0 {
		t.Errorf("sent %d after keeping", len(c.h.Sent))
	}
}

// Anything short of a verified, timed not_eligible under the hash of the
// site's checked proposal keeps nothing.
func TestNotHeldRefusalsThatKeepNothing(t *testing.T) {
	cases := map[string]func(c *cenv, w *votetest.Vote, sid string){
		"zero hash": func(c *cenv, w *votetest.Vote, sid string) {
			c.refusal(w, sid, "vote.status", "not_eligible", votewire.H([]byte(w.ID)), noTag, zeroHash)
		},
		"another hash": func(c *cenv, w *votetest.Vote, sid string) {
			c.refusal(w, sid, "vote.status", "not_eligible", votewire.H([]byte(w.ID)), noTag, hashOf(votewire.H([]byte("other"))))
		},
		"unknown_proposal": func(c *cenv, w *votetest.Vote, sid string) {
			c.refusal(w, sid, "vote.status", "unknown_proposal", votewire.H([]byte(w.ID)), noTag)
		},
		"untimed": func(c *cenv, w *votetest.Vote, sid string) {
			c.depositsOnly(sid)
			c.refusal(w, sid, "vote.status", "not_eligible", votewire.H([]byte(w.ID)), noTag)
		},
		"a tag": func(c *cenv, w *votetest.Vote, sid string) {
			c.refusal(w, sid, "vote.status", "not_eligible", votewire.H([]byte(w.ID)))
		},
		"unsigned": func(c *cenv, w *votetest.Vote, sid string) {
			c.refusal(w, sid, "vote.status", "not_eligible", votewire.H([]byte(w.ID)), noTag, func(o *refOpts) { o.sign = false })
		},
		"another connection": func(c *cenv, w *votetest.Vote, sid string) {
			c.refusal(w, sid, "vote.status", "not_eligible", votewire.H([]byte(w.ID)), noTag, func(o *refOpts) { o.conn = votewire.H([]byte("x")) })
		},
	}
	for name, do := range cases {
		c, w, sid := notHeld(t)
		do(c, w, sid)
		if c.rec(w.ID) != nil || c.count("vote.problem") != 0 {
			t.Errorf("%s: kept", name)
		}
	}
	// The site's documents must check out: a bad signature, another id, a bundle that does not anchor.
	for name, edit := range map[string]func(c *cenv, w *votetest.Vote) SiteProposal{
		"bad proposal_sig": func(c *cenv, w *votetest.Vote) SiteProposal {
			s := c.sitePublished(w)
			s.Sig = make([]byte, 64)
			return s
		},
		"no bundle": func(c *cenv, w *votetest.Vote) SiteProposal {
			s := c.sitePublished(w)
			s.Bundle = nil
			return s
		},
		"another proposal's bundle": func(c *cenv, w *votetest.Vote) SiteProposal {
			x := c.svc.NewVote(votetest.VoteSpec{ID: lid(41), Opens: c.now.Add(-time.Hour), Closes: c.now.Add(time.Hour)})
			s := c.sitePublished(w)
			s.Bundle = c.auth0Bundle(x)
			return s
		},
	} {
		c := newCastEnv(t)
		c.open(1)
		w := c.svc.NewVote(votetest.VoteSpec{ID: lid(40), Opens: c.now.Add(-time.Hour), Closes: c.now.Add(time.Hour)})
		c.f.RequestProposal(c.session(), "svc", w.ID, edit(c, w))
		ids := c.statuses()
		c.refusal(w, ids[len(ids)-1], "vote.status", "not_eligible", votewire.H([]byte(w.ID)), noTag)
		if c.rec(w.ID) != nil {
			t.Errorf("%s: kept", name)
		}
	}
}

// A not-eligible record is inert: past its close no results check is due,
// and results submitted for it are not judged.
func TestNotHeldRecordIsInert(t *testing.T) {
	c, w, sid := notHeld(t)
	c.refusal(w, sid, "vote.status", "not_eligible", votewire.H([]byte(w.ID)), noTag)
	c.now = time.Unix(c.rec(w.ID).Closes, 0).Add(CheckDelay + time.Minute)
	c.h.Reset()
	c.f.Tick(c.session())
	r := c.rec(w.ID)
	if r.Check != "" || c.hasKind("vote.check_due") || len(c.h.Sent) != 0 {
		t.Errorf("check %q, sent %d", r.Check, len(c.h.Sent))
	}
	if _, err := c.f.SubmitResults(c.session(), "svc", w.ID, ResultsSubmit{}); err == nil {
		t.Error("results judged for a record with no tag")
	}
}

// The site's proposal must be the one asked about: a refusal signed under
// the hash of a proposal of another id keeps nothing.
func TestNotHeldSiteProposalOfAnotherID(t *testing.T) {
	c := newCastEnv(t)
	c.open(1)
	w := c.svc.NewVote(votetest.VoteSpec{ID: lid(40), Opens: c.now.Add(-time.Hour), Closes: c.now.Add(time.Hour)})
	x := c.svc.NewVote(votetest.VoteSpec{ID: lid(42), Opens: c.now.Add(-time.Hour), Closes: c.now.Add(time.Hour)})
	c.f.RequestProposal(c.session(), "svc", w.ID, c.sitePublished(x))
	ids := c.statuses()
	c.refusal(w, ids[len(ids)-1], "vote.status", "not_eligible", votewire.H([]byte(w.ID)), noTag, hashOf(votewire.H(x.Doc)))
	if c.rec(w.ID) != nil || c.rec(x.ID) != nil {
		t.Error("kept a refusal for a site proposal of another id")
	}
}

// leftOff makes a NotEligible record of a new site proposal n on c's
// service connection, through the not_eligible answer.
func leftOff(t *testing.T, c *cenv, n int) *votetest.Vote {
	t.Helper()
	w := c.svc.NewVote(votetest.VoteSpec{ID: lid(n), Opens: c.now.Add(-time.Hour), Closes: c.now.Add(time.Hour)})
	if !c.f.RequestProposal(c.session(), "svc", w.ID, c.sitePublished(w)) {
		t.Fatalf("%d: not asked", n)
	}
	ids := c.statuses()
	c.refusal(w, ids[len(ids)-1], "vote.status", "not_eligible", votewire.H([]byte(w.ID)), noTag)
	c.now = c.now.Add(time.Second)
	return w
}

// (Owner decision 2026-11-19) Their own limit: at most 16 per connection,
// the oldest going first to a compact record (not asked about again); they
// never count toward the 16 problems, so a vote the member may cast is
// never refused because of them.
func TestNotHeldOwnLimit(t *testing.T) {
	c := newCastEnv(t)
	c.open(1)
	var first *votetest.Vote
	for i := 0; i < votewire.MaxNotEligiblePerConnection+1; i++ {
		w := leftOff(t, c, 100+i)
		if i == 0 {
			first = w
		}
	}
	n := 0
	for _, r := range c.f.st.Records {
		if r.NotEligible {
			n++
		}
	}
	if n != votewire.MaxNotEligiblePerConnection || c.rec(first.ID) != nil || c.rec(lid(100+votewire.MaxNotEligiblePerConnection)) == nil {
		t.Fatalf("%d kept, the oldest gone %v", n, c.rec(first.ID) == nil)
	}
	// The evicted one keeps its proof: the signed refusal and its code.
	ev := obj(t, c.app("vote.evidence", pairBody("svc", first.ID)))
	eo, _ := ev.Object("evidence")
	if !boolOf(eo, "evicted") || !boolOf(eo, "not_eligible") || string(eo["status_answer_codes"]) != `["not_eligible"]` {
		t.Errorf("evicted evidence: %s", ev["evidence"])
	}
	if out, _ := eo.String("outcome"); out != "not_eligible" {
		t.Errorf("outcome %q", out)
	}
	c.now = c.now.Add(2 * StatusEvery) // past the hourly limit on asking
	if c.f.RequestProposal(c.session(), "svc", first.ID, c.sitePublished(first)) {
		t.Error("an evicted proposal is asked about again")
	}
	// A vote the member is on the roster of is still kept.
	for i := 2; i <= votewire.MaxOpenPerConnection; i++ {
		c.open(i)
	}
	if len(c.f.problemsJSON()) != 2 {
		t.Errorf("counted as problems: %s", c.f.problemsJSON())
	}
}

// With the vault's bound full, a record of a proposal some member was left
// off goes before a vote is refused, and a new one never pushes out
// another record.
func TestNotHeldVaultBound(t *testing.T) {
	c := newCastEnv(t)
	c.open(1)
	old := leftOff(t, c, 100)
	for i := len(c.f.st.Records); i < votewire.MaxProposals; i++ {
		k := key(fmt.Sprintf("other%03d", i), lid(i))
		c.f.st.Records[k] = &record{Conn: fmt.Sprintf("other%03d", i), ID: lid(i), KeptMS: c.now.UnixMilli(), Opens: c.now.Add(-time.Hour).Unix(), Closes: c.now.Add(time.Hour).Unix()}
	}
	rec := &record{Conn: "svc", ID: lid(300), Opens: c.now.Add(-time.Hour).Unix(), Closes: c.now.Add(time.Hour).Unix()}
	if hit := c.f.admit(rec, c.now); hit != nil || c.rec(old.ID) != nil {
		t.Fatalf("a vote refused (%v) or the left-off record kept (%v)", hit, c.rec(old.ID) != nil)
	}
	c.f.st.Records[key("svc", lid(300))] = rec
	// Full of others: a new left-off record is not kept, and pushes nothing out.
	before := len(c.f.st.Records)
	w := c.svc.NewVote(votetest.VoteSpec{ID: lid(301), Opens: c.now.Add(-time.Hour), Closes: c.now.Add(time.Hour)})
	c.f.RequestProposal(c.session(), "svc", w.ID, c.sitePublished(w))
	ids := c.statuses()
	c.refusal(w, ids[len(ids)-1], "vote.status", "not_eligible", votewire.H([]byte(w.ID)), noTag)
	if c.rec(w.ID) != nil || len(c.f.st.Records) != before {
		t.Error("kept over a full vault")
	}
	// Full, with an older left-off record of another connection: that one
	// goes, and the new one is kept.
	delete(c.f.st.Records, key("other127", lid(127)))
	c.f.st.Records[key("otherNE", lid(299))] = &record{Conn: "otherNE", ID: lid(299), NotEligible: true, KeptMS: 1}
	kept := leftOff(t, c, 302)
	if c.rec(kept.ID) == nil || c.f.st.Records[key("otherNE", lid(299))] != nil {
		t.Fatal("the vault-wide oldest left-off record did not make room")
	}
}

// The service then sends the proposal with a record proof, contradicting
// its signed not_eligible: kept as the conflict, vote.problem once more.
func TestNotHeldThenAProposal(t *testing.T) {
	c, w, sid := notHeld(t)
	c.refusal(w, sid, "vote.status", "not_eligible", votewire.H([]byte(w.ID)), noTag)
	before := c.count("vote.problem")
	c.send(w)
	c.send(w)
	r := c.rec(w.ID)
	if r.Conflict == nil || !r.NotEligible || c.count("vote.problem") != before+1 {
		t.Errorf("conflict %v, vote.problem %d (was %d)", r.Conflict != nil, c.count("vote.problem"), before)
	}
}

// A second not_eligible for the same proposal (a request still pending)
// keeps the one record and says nothing more.
func TestNotHeldSecondRefusal(t *testing.T) {
	c := newCastEnv(t)
	c.open(1)
	w := c.svc.NewVote(votetest.VoteSpec{ID: lid(40), Opens: c.now.Add(-time.Hour), Closes: c.now.Add(time.Hour)})
	c.f.RequestProposal(c.session(), "svc", w.ID, c.sitePublished(w))
	first := c.statuses()[len(c.statuses())-1]
	c.f.pend["second"] = c.f.pend[first]
	c.refusal(w, first, "vote.status", "not_eligible", votewire.H([]byte(w.ID)), noTag)
	c.now = c.now.Add(time.Minute)
	c.depositsOnly("second", c.now.UnixMilli())
	c.refusal(w, "second", "vote.status", "not_eligible", votewire.H([]byte(w.ID)), noTag, msgAt(uint64(c.now.UnixMilli())))
	if r := c.rec(w.ID); len(r.StatusAnswers) != 1 || c.count("vote.problem") != 1 {
		t.Errorf("%d kept, vote.problem %d", len(r.StatusAnswers), c.count("vote.problem"))
	}
}

// A site proposal signed by a key not the connection's, or a refusal
// signed by another key, keeps nothing.
func TestNotHeldOtherKeys(t *testing.T) {
	c := newCastEnv(t)
	c.open(1)
	other := votetest.NewService(c.env.auth)
	w := other.NewVote(votetest.VoteSpec{ID: lid(40), Opens: c.now.Add(-time.Hour), Closes: c.now.Add(time.Hour)})
	c.f.RequestProposal(c.session(), "svc", w.ID, SiteProposal{Proposal: w.Doc, Sig: w.Sig, Bundle: c.env.auth.Bundle(w.Doc, other.Anchor, c.now)})
	ids := c.statuses()
	c.refusal(w, ids[len(ids)-1], "vote.status", "not_eligible", votewire.H([]byte(w.ID)), noTag)
	if c.rec(w.ID) != nil {
		t.Error("kept a site proposal of another service")
	}
	c2, w2, sid := notHeld(t)
	svc := c2.svc
	c2.svc = votetest.NewService(c2.env.auth) // the refusal signed by another key
	c2.refusal(w2, sid, "vote.status", "not_eligible", votewire.H([]byte(w2.ID)), noTag)
	c2.svc = svc
	if c2.rec(w2.ID) != nil {
		t.Error("kept a refusal signed by another key")
	}
}
