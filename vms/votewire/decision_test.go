package votewire

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"testing"
)

// BALLOT-PROTOCOL 0.14.0 §11 item 5 and the 0.14.1 refused proposal, from
// the copied vectors (a vector that stops matching is a stop-and-report
// item, never a reason to edit the file).

// withMembers re-encodes a canonical document with its members replaced.
func withMembers(t *testing.T, doc string, set map[string]json.RawMessage) []byte {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(doc), &m); err != nil {
		t.Fatal(err)
	}
	for k, v := range set {
		m[k] = v
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	c, err := Canonicalize(b)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func raw(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Every outcome vector: Decide gives its outcome, or refuses its tally.
func TestOutcomeVectors(t *testing.T) {
	v := load(t)
	if len(v.Outcomes) < 30 {
		t.Fatalf("only %d outcome vectors", len(v.Outcomes))
	}
	for _, c := range v.Outcomes {
		p := &Proposal{Decision: c.Decision, Quorum: Quorum{MinBallots: c.MinBallots}, Eligible: c.Eligible, RemovedMayVote: c.RemovedMayVote}
		for _, id := range c.Choices {
			p.Choices = append(p.Choices, Choice{ID: id, Label: id})
		}
		got, err := Decide(p, c.Tally, c.Ballots)
		switch {
		case c.Outcome == nil && err == nil:
			t.Errorf("%s: decided %+v, want refused", c.Case, got)
		case c.Outcome != nil && err != nil:
			t.Errorf("%s: refused: %v", c.Case, err)
		case c.Outcome != nil && !got.Equal(*c.Outcome):
			t.Errorf("%s: got %+v, want %+v", c.Case, got, *c.Outcome)
		}
		if c.Outcome != nil && c.Outcome.Validate() != nil {
			t.Errorf("%s: the vector's own outcome is not consistent", c.Case)
		}
	}
}

// Every decision vector, judged as the member of a proposal (the document
// vector's, with that decision): parsed iff valid.
func TestDecisionVectors(t *testing.T) {
	v := load(t)
	for _, c := range v.Decisions {
		doc := withMembers(t, v.Documents.Proposal, map[string]json.RawMessage{
			"decision": c.Decision, "removed_may_vote": raw(t, c.RemovedMayVote),
		})
		_, err := ParseProposal(doc)
		if (err == nil) != c.Valid {
			t.Errorf("%s: parsed %v, valid %v", c.Case, err == nil, c.Valid)
		}
	}
}

// Every outcome object, as the member of the decided results: valid iff it
// parses and is consistent in itself.
func TestOutcomeShapeVectors(t *testing.T) {
	v := load(t)
	for _, c := range v.OutcomeShapes {
		doc := withMembers(t, v.DocumentsDecided.Results, map[string]json.RawMessage{"outcome": c.Outcome})
		res, err := ParseResults(doc)
		ok := err == nil && res.Outcome.Validate() == nil
		if ok != c.Valid {
			t.Errorf("%s: accepted %v, valid %v", c.Case, ok, c.Valid)
		}
	}
}

// The decided documents verify and check as the first set does, and their
// outcome recomputes: decided, for yes.
func TestDecidedDocumentVectors(t *testing.T) {
	v := load(t)
	d := v.DocumentsDecided
	ik := ed25519.NewKeyFromSeed(hx(t, d.ServiceSeed)).Public().(ed25519.PublicKey)
	prop, err := ParseProposal([]byte(d.Proposal))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyProposal(ik, []byte(d.Proposal), hx(t, d.ProposalSig)); err != nil {
		t.Errorf("proposal_sig: %v", err)
	}
	res, err := ParseResults([]byte(d.Results))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyResults(ik, H([]byte(d.Proposal)), []byte(d.Results), hx(t, d.ResultsSig)); err != nil {
		t.Errorf("results_sig: %v", err)
	}
	if err := res.CheckProposal(prop); err != nil {
		t.Errorf("results against the proposal: %v", err)
	}
	if res.Outcome.Status != StatusDecided || res.Outcome.Choice == nil || *res.Outcome.Choice != "yes" || !res.Outcome.QuorumMet {
		t.Errorf("outcome %+v", res.Outcome)
	}
	if !bytes.Equal(res.Proposal.Doc, []byte(d.Proposal)) {
		t.Error("the results' proposal is not the proposal")
	}
}

// The results check fails each contradiction of BALLOT-PROTOCOL 0.14.0
// §8.3 step 2 under the service's signature: an outcome that does not
// recompute or is not consistent, and a tally that is negative, sums to
// other than ballots, lacks or adds a choice, or counts more ballots than
// eligible.
func TestCheckProposalRefusesWhatDoesNotRecompute(t *testing.T) {
	v := load(t)
	d := v.DocumentsDecided
	prop, err := ParseProposal([]byte(d.Proposal))
	if err != nil {
		t.Fatal(err)
	}
	no := "no"
	cases := map[string]map[string]json.RawMessage{
		"another choice decided":   {"outcome": raw(t, Outcome{QuorumMet: true, Status: StatusDecided, Choice: &no})},
		"not decided":              {"outcome": raw(t, Outcome{QuorumMet: true, Status: StatusNotDecided})},
		"no quorum, inconsistent":  {"outcome": raw(t, Outcome{QuorumMet: true, Status: StatusNoQuorum})},
		"a negative count":         {"tally": raw(t, map[string]int64{"yes": 5, "no": -2, "abstain": 1})},
		"a sum other than ballots": {"tally": raw(t, map[string]int64{"yes": 2, "no": 1, "abstain": 0})},
		"a choice missing":         {"tally": raw(t, map[string]int64{"yes": 3, "no": 1})},
		"another choice":           {"tally": raw(t, map[string]int64{"yes": 2, "no": 1, "abstain": 1, "maybe": 0})},
	}
	for name, set := range cases {
		res, err := ParseResults(withMembers(t, d.Results, set))
		if err != nil {
			t.Errorf("%s: does not parse (%v): the check, not the parse, refuses it", name, err)
			continue
		}
		if res.CheckProposal(prop) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// More ballots than eligible: counts.ballots above the proposal's eligible.
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(d.Results), &m); err != nil {
		t.Fatal(err)
	}
	var counts Counts
	if err := json.Unmarshal(m["counts"], &counts); err != nil {
		t.Fatal(err)
	}
	counts.Ballots = counts.Eligible + 1
	res, err := ParseResults(withMembers(t, d.Results, map[string]json.RawMessage{
		"counts": raw(t, counts), "tally": raw(t, map[string]int64{"yes": counts.Ballots - 2, "no": 1, "abstain": 1}),
	}))
	if err != nil || res.CheckProposal(prop) == nil {
		t.Errorf("more ballots than eligible: parsed %v, accepted", err)
	}
}

// (0.14.1) A proposal with removed_may_vote true is refused, and the same
// proposal with false parses: the flag alone refuses it.
func TestProposalRemovedMayVoteRefused(t *testing.T) {
	v := load(t)
	if _, err := ParseProposal([]byte(v.ProposalRemovedMayVote)); err == nil {
		t.Fatal("a proposal with removed_may_vote true parses")
	}
	if _, err := ParseProposal(withMembers(t, v.ProposalRemovedMayVote, map[string]json.RawMessage{"removed_may_vote": raw(t, false)})); err != nil {
		t.Errorf("the same proposal with false: %v", err)
	}
}

// (0.14.0) min_ballots above eligible is refused; equal to it parses.
func TestQuorumAtMostEligible(t *testing.T) {
	v := load(t)
	p, err := ParseProposal([]byte(v.Documents.Proposal))
	if err != nil {
		t.Fatal(err)
	}
	for mb, ok := range map[int64]bool{p.Eligible: true, p.Eligible + 1: false} {
		doc := withMembers(t, v.Documents.Proposal, map[string]json.RawMessage{"quorum": raw(t, Quorum{Text: p.Quorum.Text, MinBallots: mb})})
		if _, err := ParseProposal(doc); (err == nil) != ok {
			t.Errorf("min_ballots %d of %d: parsed %v", mb, p.Eligible, err == nil)
		}
	}
}

// A member that may be null is refused with any other type than its own,
// and a member that may not be null is refused as null.
func TestNullableMembersRefuseOtherTypes(t *testing.T) {
	v := load(t)
	for name, dec := range map[string]string{
		"threshold an array":  `{"base":"cast","rule":"threshold","threshold":[2,3]}`,
		"threshold a string":  `{"base":"cast","rule":"threshold","threshold":"2/3"}`,
		"threshold a boolean": `{"base":"cast","rule":"threshold","threshold":true}`,
		"base a number":       `{"base":1,"rule":"majority","threshold":null}`,
		"base an object":      `{"base":{},"rule":"majority","threshold":null}`,
		"rule null":           `{"base":"cast","rule":null,"threshold":null}`,
		"num null":            `{"base":"cast","rule":"threshold","threshold":{"den":3,"num":null}}`,
		"threshold num a str": `{"base":"cast","rule":"threshold","threshold":{"den":3,"num":"2"}}`,
	} {
		if _, err := ParseProposal(withMembers(t, v.Documents.Proposal, map[string]json.RawMessage{"decision": json.RawMessage(dec)})); err == nil {
			t.Errorf("decision, %s: parsed", name)
		}
	}
	if _, err := ParseProposal(withMembers(t, v.Documents.Proposal, map[string]json.RawMessage{"decision": json.RawMessage("null")})); err == nil {
		t.Error("decision null: parsed")
	}
	for name, out := range map[string]string{
		"choice an object": `{"choice":{},"quorum_met":true,"status":"decided"}`,
		"choice a number":  `{"choice":1,"quorum_met":true,"status":"decided"}`,
		"status null":      `{"choice":null,"quorum_met":true,"status":null}`,
		"quorum_met null":  `{"choice":null,"quorum_met":null,"status":"tied"}`,
	} {
		if _, err := ParseResults(withMembers(t, v.DocumentsDecided.Results, map[string]json.RawMessage{"outcome": json.RawMessage(out)})); err == nil {
			t.Errorf("outcome, %s: parsed", name)
		}
	}
	if _, err := ParseResults(withMembers(t, v.DocumentsDecided.Results, map[string]json.RawMessage{"outcome": json.RawMessage("null")})); err == nil {
		t.Error("outcome null: parsed")
	}
}

// Decide on its own (without the parser's integer bound) refuses a count
// above the ballots instead of wrapping.
func TestDecideRefusesACountAboveTheBallots(t *testing.T) {
	cast := BaseCast
	p := &Proposal{Decision: Decision{Rule: RuleMajority, Base: &cast}, Eligible: 10,
		Choices: []Choice{{ID: "c1"}, {ID: "c2"}, {ID: "c3"}, {ID: AbstainID}}}
	// 2·MaxInt64 + 7 wraps to 5, the ballots: only the bound refuses it.
	const big = int64(^uint64(0) >> 1)
	if o, err := Decide(p, map[string]int64{"c1": big, "c2": big, "c3": 7, AbstainID: 0}, 5); err == nil {
		t.Errorf("a tally that wraps decides: %+v", o)
	}
}
