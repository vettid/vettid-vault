package vote

import (
	"bytes"
	"encoding/base64"
	"testing"

	"github.com/vettid/vettid-vault/internal/votetest"
	"github.com/vettid/vettid-vault/vms/envelope"
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
