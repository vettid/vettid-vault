package vote

import (
	"fmt"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/votetest"
	"github.com/vettid/vettid-vault/vms/votewire"
)

func lid(n int) string { return fmt.Sprintf("01JBQZ%020d", n) }

// closedVote sends a proposal that is already closed.
func (e *env) closedVote(n int) *votetest.Vote {
	e.t.Helper()
	v := e.svc.NewVote(votetest.VoteSpec{ID: lid(n), Opens: e.now.Add(-3 * time.Hour), Closes: e.now.Add(-2 * time.Hour)})
	if r := e.send(v); !r.OK() {
		e.t.Fatalf("vote %d: %q", n, r.Code)
	}
	e.now = e.now.Add(time.Second) // KeptMS orders by arrival
	return v
}

func (e *env) openVote(n int) (*votetest.Vote, string) {
	e.t.Helper()
	v := e.svc.NewVote(votetest.VoteSpec{ID: lid(n), Opens: e.now.Add(-time.Hour), Closes: e.now.Add(time.Hour)})
	r := e.send(v)
	e.now = e.now.Add(time.Second)
	return v, r.Code
}

func TestEvictionKeepsACompactRecord(t *testing.T) {
	e := newEnv(t)
	e.publish(e.svc)
	for i := 1; i <= votewire.MaxPerConnection; i++ {
		e.closedVote(i)
		e.rec(lid(i)).Check = CheckVerified // final and clean: evictable
	}
	if len(e.f.st.Records) != votewire.MaxPerConnection {
		t.Fatalf("%d records", len(e.f.st.Records))
	}
	// Give the oldest a ballot and a receipt so the compact record has them.
	old := e.rec(lid(1))
	old.Ballot = &ballot{State: BallotRecorded, ChoiceID: "yes", BallotSig: make([]byte, 64), MsgMS: 12345, ReceiptSig: make([]byte, 64), Refusals: [][]byte{[]byte("r")}}
	// The 33rd evicts the oldest evictable, not a newer one.
	e.closedVote(100)
	if e.rec(lid(1)) != nil || e.rec(lid(2)) == nil || len(e.f.st.Records) != votewire.MaxPerConnection {
		t.Fatalf("oldest not evicted: %d", len(e.f.st.Records))
	}
	cs := e.f.st.Compact["svc"]
	if len(cs) != 1 {
		t.Fatalf("%d compact records", len(cs))
	}
	c := cs[0]
	if c.ID != lid(1) || len(c.Hash) != 32 || len(c.Tag) != 32 || string(c.ServiceIK) != string(e.svc.Pub()) || c.ChoiceID != "yes" ||
		c.MsgMS != 12345 || len(c.ReceiptSig) != 64 || len(c.Refusals) != 1 || c.Outcome != CheckVerified || len(c.VK) != 32 {
		t.Errorf("%+v", c)
	}
	// Retention: 365 days after the close; at most 512 per connection.
	s := e.session()
	e.now = e.now.Add(364 * 24 * time.Hour)
	e.f.prune(s)
	if len(e.f.st.Compact["svc"]) != 1 {
		t.Error("compact record deleted early")
	}
	e.now = e.now.Add(3 * 24 * time.Hour)
	e.f.prune(e.session())
	if len(e.f.st.Compact["svc"]) != 0 {
		t.Error("compact record kept past 365 days")
	}
	for i := 0; i < votewire.MaxCompactPerConnection+5; i++ {
		e.f.st.Compact["svc"] = append(e.f.st.Compact["svc"], &compact{ID: lid(i), ClosedAt: e.now.Unix() - int64(i)})
	}
	e.f.prune(e.session())
	if n := len(e.f.st.Compact["svc"]); n != votewire.MaxCompactPerConnection {
		t.Errorf("%d compact records", n)
	}
	for _, c := range e.f.st.Compact["svc"] {
		if c.ID == lid(votewire.MaxCompactPerConnection+4) {
			t.Error("the oldest was kept over newer ones")
		}
	}
}

func TestInProgressIsNeverEvicted(t *testing.T) {
	e := newEnv(t)
	e.publish(e.svc)
	for i := 1; i <= votewire.MaxPerConnection; i++ {
		e.closedVote(i)
	}
	// Closed, no ballot, check not due or settled: may go. Make each a
	// different in-progress kind, then none may.
	kinds := []func(r *record){
		func(r *record) { r.Reason = ReasonTrustRoot },                // checking
		func(r *record) { r.Check = CheckPending },                    // a pending check
		func(r *record) { r.Ballot = &ballot{State: BallotSending} },  // a ballot not final
		func(r *record) { r.Ballot = &ballot{State: BallotRecorded} }, // final, but the check has not run
		func(r *record) { r.Ballot = &ballot{State: BallotWaiting}; r.Check = CheckVerified },
	}
	for i := 1; i <= votewire.MaxPerConnection; i++ {
		kinds[i%len(kinds)](e.rec(lid(i)))
	}
	if e.f.oldestEvictable("svc", e.now) != nil {
		t.Fatal("an in-progress record is evictable")
	}
	_, code := e.openVote(200) // an open proposal: the vault has no room
	if code != "limit" {
		t.Fatalf("%q", code)
	}
	if len(e.f.st.Compact["svc"]) != 0 || len(e.f.st.Records) != votewire.MaxPerConnection {
		t.Error("something was deleted")
	}
	// Each reason an unfinished closed record cannot go, and each way one can.
	r := &record{Closes: e.now.Add(-time.Hour).Unix()}
	if !r.evictable(e.now) {
		t.Error("closed, no ballot, check not due: evictable")
	}
	r.Opens = r.Closes - 100
	r.Closes = e.now.Add(-3 * time.Hour).Unix()
	if r.evictable(e.now) { // check due (2 h passed) but not settled
		t.Error("check due and unsettled: not evictable")
	}
	for _, c := range []string{CheckVerified, CheckUnconfirmed, CheckGaveUp} {
		r.Check = c
		if !r.evictable(e.now) {
			t.Errorf("check %s: evictable", c)
		}
	}
	r.Check = CheckFailed
	if r.evictable(e.now) || !r.problem() {
		t.Error("failed check: a problem, never evicted")
	}
	r.Check = CheckVerified
	r.RefusalProblem = true
	if r.evictable(e.now) {
		t.Error("a refusal that raised a problem")
	}
}

func TestProblemSet(t *testing.T) {
	now := time.Now()
	for name, mod := range map[string]func(r *record){
		"rejected":    func(r *record) { r.RejectReason = RejectAnchor },
		"failed":      func(r *record) { r.Check = CheckFailed },
		"conflict":    func(r *record) { r.Ballot = &ballot{State: BallotConflict} },
		"disputed":    func(r *record) { r.Ballot = &ballot{State: BallotDisputed} },
		"mismatch":    func(r *record) { r.Site = SiteMismatch },
		"unpublished": func(r *record) { r.Site = SiteUnpublished },
		"refusal":     func(r *record) { r.RefusalProblem = true },
	} {
		r := &record{Closes: now.Unix() - 10}
		if r.problem() {
			t.Fatal("clean record is a problem")
		}
		mod(r)
		if !r.problem() || r.evictable(now) {
			t.Errorf("%s: problem=%v evictable=%v", name, r.problem(), r.evictable(now))
		}
	}
	for name, mod := range map[string]func(r *record){
		"not_listed":  func(r *record) { r.Site = SiteNotListed },
		"unreachable": func(r *record) { r.Site = SiteUnreachable },
		"unconfirmed": func(r *record) { r.Check = CheckUnconfirmed },
		"refused":     func(r *record) { r.Ballot = &ballot{State: BallotRefused} },
	} {
		r := &record{}
		mod(r)
		if r.problem() {
			t.Errorf("%s is not a problem", name)
		}
	}
}

func TestOpenCapAndTheNotices(t *testing.T) {
	e := newEnv(t)
	e.publish(e.svc)
	for i := 1; i <= votewire.MaxOpenPerConnection; i++ {
		if _, code := e.openVote(i); code != "" {
			t.Fatalf("%d: %q", i, code)
		}
	}
	e.h.Reset()
	v := e.svc.NewVote(votetest.VoteSpec{ID: lid(99), Opens: e.now.Add(-time.Hour), Closes: e.now.Add(time.Hour)})
	r := e.send(v)
	if r.Code != "limit" {
		t.Fatalf("%q", r.Code)
	}
	o := r.Obj(t)
	if l, _ := o.String("limit"); l != "votes" {
		t.Errorf("limit %q", l)
	}
	if m, _ := o.Uint("max", 0, 1000); m != votewire.MaxOpenPerConnection {
		t.Errorf("max %d", m)
	}
	if !e.has("drop.vote_limit", "svc") || !e.has("vote.problem", "svc") || e.rec(lid(99)) != nil {
		t.Errorf("%v", e.h.Activities)
	}
	if d := e.f.st.Dropped["svc"]; d == nil || d.Count != 1 || d.LastMS == 0 {
		t.Errorf("dropped %+v", d)
	}
	// At most one feed item per connection per 24 hours; every drop is
	// audited and counted.
	e.h.Reset()
	e.now = e.now.Add(30 * time.Minute)
	e.send(e.svc.NewVote(votetest.VoteSpec{ID: lid(98), Opens: e.now.Add(-time.Hour), Closes: e.now.Add(time.Hour)}))
	if e.count("vote.problem") != 0 || e.count("drop.vote_limit") != 1 || e.f.st.Dropped["svc"].Count != 2 {
		t.Errorf("%v", e.h.Activities)
	}
	// Past 24 hours a new drop makes a new feed item.
	e.now = e.now.Add(24 * time.Hour)
	e.h.Reset()
	for _, rec := range e.f.st.Records {
		rec.Check = CheckVerified // the old ones have closed: settle them
	}
	for i := 0; i < votewire.MaxOpenPerConnection; i++ {
		e.f.st.Records[key("svc", lid(300+i))] = &record{Conn: "svc", ID: lid(300 + i), Opens: e.now.Unix() - 10, Closes: e.now.Unix() + 3600, KeptMS: e.now.UnixMilli()}
	}
	e.send(e.svc.NewVote(votetest.VoteSpec{ID: lid(96), Opens: e.now.Add(-time.Hour), Closes: e.now.Add(time.Hour)}))
	if e.count("vote.problem") != 1 {
		t.Errorf("no new feed item after 24 hours: %v", e.h.Activities)
	}
	// A closed proposal does not count toward the 16 open ones.
	e2 := newEnv(t)
	e2.publish(e2.svc)
	for i := 1; i <= votewire.MaxOpenPerConnection; i++ {
		e2.openVote(i)
	}
	if r := e2.send(e2.svc.NewVote(votetest.VoteSpec{ID: lid(50), Opens: e2.now.Add(-3 * time.Hour), Closes: e2.now.Add(-2 * time.Hour)})); !r.OK() {
		t.Errorf("a closed proposal at the open cap: %q", r.Code)
	}
}

func TestPerConnectionCapOf32(t *testing.T) {
	e := newEnv(t)
	e.publish(e.svc)
	for i := 1; i <= votewire.MaxPerConnection; i++ {
		e.closedVote(i)
		e.rec(lid(i)).Ballot = &ballot{State: BallotSending} // not final: stays
	}
	v := e.svc.NewVote(votetest.VoteSpec{ID: lid(99), Opens: e.now.Add(-3 * time.Hour), Closes: e.now.Add(-2 * time.Hour)})
	r := e.send(v)
	if m, _ := r.Obj(t).Uint("max", 0, 1000); r.Code != "limit" || m != votewire.MaxPerConnection {
		t.Errorf("%q %d", r.Code, m)
	}
}

func TestProblemCap(t *testing.T) {
	e := newEnv(t)
	e.publish(e.svc)
	// 16 rejected proposals are kept as evidence.
	for i := 1; i <= votewire.MaxProblemsPerConnection; i++ {
		v := e.svc.NewVote(votetest.VoteSpec{ID: lid(i), Opens: e.now.Add(-time.Hour), Closes: e.now.Add(time.Hour)})
		m, _ := votewire.ParseProposalMsg(e.svc.Msg(v, e.now))
		m.ProposalSig = make([]byte, 64)
		if r := e.call("vote.proposal", m.Marshal()); r.Code != "bad_request" {
			t.Fatalf("%d: %q", i, r.Code)
		}
		e.now = e.now.Add(time.Second)
	}
	if len(e.f.st.Records) != votewire.MaxProblemsPerConnection {
		t.Fatalf("%d", len(e.f.st.Records))
	}
	// Problem records do not count toward the 32 or the 16 open.
	// At 16, nothing new is kept from the connection: a good proposal is
	// answered limit, the notice is set, nothing is deleted.
	e.h.Reset()
	v := e.svc.NewVote(votetest.VoteSpec{ID: lid(99), Opens: e.now.Add(-time.Hour), Closes: e.now.Add(time.Hour)})
	r := e.send(v)
	if m, _ := r.Obj(t).Uint("max", 0, 1000); r.Code != "limit" || m != votewire.MaxProblemsPerConnection {
		t.Fatalf("%q %d", r.Code, m)
	}
	if !e.f.st.Problems["svc"] || len(e.f.st.Records) != votewire.MaxProblemsPerConnection || !e.has("drop.vote_limit", "svc") {
		t.Errorf("notice %v, %d records", e.f.st.Problems, len(e.f.st.Records))
	}
	// Another rejected one is not kept either (limit, not bad_request).
	m, _ := votewire.ParseProposalMsg(e.svc.Msg(v, e.now))
	m.ProposalSig = make([]byte, 64)
	if r := e.call("vote.proposal", m.Marshal()); r.Code != "limit" {
		t.Errorf("a 17th problem: %q", r.Code)
	}
	// A record that turns into a problem after it was kept may pass 16.
	e2 := newEnv(t)
	e2.publish(e2.svc)
	for i := 1; i <= votewire.MaxProblemsPerConnection+2; i++ {
		e2.closedVote(i)
	}
	for i := 1; i <= votewire.MaxProblemsPerConnection+2; i++ {
		e2.rec(lid(i)).Check = CheckFailed
	}
	if len(e2.f.st.Records) != 18 {
		t.Errorf("%d", len(e2.f.st.Records))
	}
	// Problem records are deleted 365 days after their close.
	e2.now = e2.now.Add(366 * 24 * time.Hour)
	e2.f.prune(e2.session())
	if len(e2.f.st.Records) != 0 {
		t.Errorf("%d problem records left", len(e2.f.st.Records))
	}
}

func TestVaultCapOf128(t *testing.T) {
	e := newEnv(t)
	e.publish(e.svc)
	for i := 0; i < votewire.MaxProposals; i++ {
		other := fmt.Sprintf("other%d", i/16)
		e.f.st.Records[key(other, lid(i))] = &record{Conn: other, ID: lid(i), Opens: e.now.Unix() - 10, Closes: e.now.Unix() + 3600, KeptMS: int64(i)}
	}
	v, code := e.openVote(500)
	r := e.send(v)
	_ = code
	if m, _ := r.Obj(t).Uint("max", 0, 1000); r.Code != "limit" || m != votewire.MaxProposals {
		t.Errorf("%q %d", r.Code, m)
	}
	// Evicting this connection's own makes room.
	e.f.st.Records[key("svc", lid(600))] = &record{Conn: "svc", ID: lid(600), Opens: e.now.Unix() - 9000, Closes: e.now.Unix() - 4000, KeptMS: 1, Check: CheckVerified}
	delete(e.f.st.Records, key("other0", lid(0)))
	v2 := e.svc.NewVote(votetest.VoteSpec{ID: lid(501), Opens: e.now.Add(-time.Hour), Closes: e.now.Add(time.Hour)})
	if r := e.send(v2); !r.OK() {
		t.Errorf("with room: %q", r.Code)
	}
}
