package vote

import (
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/votetest"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/votewire"
)

// castWith casts on a fresh vault, for a proposal whose only choices are an
// id of n bytes and a label that makes the proposal document the same
// length for every n.
func castWith(t *testing.T, n int) (c *cenv, v *votetest.Vote, choice string) {
	c = newCastEnv(t)
	choice = strings.Repeat("c", n)
	v = c.svc.NewVote(votetest.VoteSpec{ID: lid(1), Opens: c.now.Add(-time.Hour), Closes: c.now.Add(2 * time.Hour),
		Edit: func(p *votewire.Proposal) {
			p.Choices = []votewire.Choice{{ID: choice, Label: strings.Repeat("L", 40-n)}, {ID: "no", Label: "No"}, {ID: "abstain", Label: "Abstain"}}
		}})
	if r := c.send(v); !r.OK() {
		t.Fatalf("vote: %q", r.Code)
	}
	if _, err := c.cast(v, choice); err != nil {
		t.Fatal(err)
	}
	return c, v, choice
}

// The vote.cast the vault sends is 418 bytes in a 1,024-byte padded inner
// plaintext, for every choice id length (VAULT-MESSAGING 0.83.6 §10.19.5);
// the vote.get and vote.evidence answers have one length for all of them.
func TestSizesDoNotDependOnTheChoice(t *testing.T) {
	var getLen, evLen int
	for n := 1; n <= 32; n++ {
		c, v, choice := castWith(t, n)
		bodies, _ := c.casts()
		if len(bodies) != 1 || len(bodies[0]) != 418 || string(bodies[0]) != string(c.rec(v.ID).Ballot.Body) {
			t.Fatalf("choice len %d: sent bodies %d", n, len(bodies))
		}
		in := &envelope.Inner{ID: "01JBQZ0000000000000000000B", Type: "vote.cast", TS: c.now, Seq: 1<<53 - 1, Body: bodies[0]}
		j, err := in.Marshal(envelope.ModeSession)
		if err != nil {
			t.Fatal(err)
		}
		if p, err := envelope.Pad(j); err != nil || len(p) != 1024 {
			t.Fatalf("choice len %d: padded %d %v", n, len(p), err)
		}
		g := c.app("vote.get", pairBody("svc", v.ID))
		if !g.OK() || !strings.Contains(string(g.Body), `"choice_id":"`+choice+`"`) {
			t.Fatalf("vote.get: %q %s", g.Code, g.Body)
		}
		ev := c.app("vote.evidence", pairBody("svc", v.ID))
		if !ev.OK() {
			t.Fatalf("vote.evidence: %q", ev.Code)
		}
		// The bundle's signatures vary in length by themselves; the member's
		// own ballot is the part that depends on the choice.
		eo, _ := obj(t, ev).Object("evidence")
		mem, ok := eo["member"]
		if !ok {
			t.Fatalf("no member in the evidence")
		}
		if n == 1 {
			getLen, evLen = len(g.Body), len(mem)
		}
		if len(g.Body) != getLen {
			t.Errorf("vote.get at choice len %d: %d bytes, want %d", n, len(g.Body), getLen)
		}
		if len(mem) != evLen {
			t.Errorf("vote.evidence member at choice len %d: %d bytes, want %d", n, len(mem), evLen)
		}
	}
}

// Every ballot object the vault shows has pad beside choice_id, so its size
// is the same for every choice id.
func TestBallotObjectsArePadded(t *testing.T) {
	var want, wantSvc int
	for n := 1; n <= 32; n++ {
		id := strings.Repeat("x", n)
		b := ballotEvidence(make([]byte, 32), id, make([]byte, 64), 1, make([]byte, 64))
		if n == 1 {
			want = len(b)
		}
		if len(b) != want {
			t.Errorf("ballot evidence at %d: %d, want %d", n, len(b), want)
		}
		sl := len(svcBallotJSON(&svcBallot{VK: make([]byte, 32), ChoiceID: id, BallotSig: make([]byte, 64)}))
		if n == 1 {
			wantSvc = sl
		}
		if sl != wantSvc {
			t.Errorf("service ballot at %d: %d, want %d", n, sl, wantSvc)
		}
	}
	// A foreign choice id over 32 bytes gets an empty pad.
	if b := ballotEvidence(make([]byte, 32), strings.Repeat("y", 40), make([]byte, 64), 0, nil); !strings.Contains(string(b), `"pad":""`) {
		t.Errorf("%s", b)
	}
}

// A new record in `checking` is not refused by the cap on the 16 not yet
// closed.
func TestAdmitCheckingAtTheOpenCap(t *testing.T) {
	e := newEnv(t)
	e.publish(e.svc)
	for i := 1; i <= votewire.MaxOpenPerConnection; i++ {
		e.openVote(i)
	}
	rec := &record{Conn: "svc", ID: lid(90), Reason: ReasonTrustRoot, Opens: e.now.Unix() - 10, Closes: e.now.Unix() + 3600}
	if hit := e.f.admit(rec, e.now); hit != nil {
		t.Errorf("a checking record was refused: %+v", hit)
	}
	rec.Reason = ""
	if hit := e.f.admit(rec, e.now); hit == nil || hit.max != votewire.MaxOpenPerConnection {
		t.Errorf("an open record at the cap: %+v", hit)
	}
}
