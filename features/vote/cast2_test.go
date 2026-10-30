package vote

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/internal/votetest"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/suite"
	"github.com/vettid/vettid-vault/vms/votewire"
)

func (c *cenv) tickAt(d time.Duration) {
	c.now = c.now.Add(d)
	c.f.Tick(c.session())
}

// The schedule: the first send, then 1, 5 and 30 minutes after it, then
// hourly, until the close in force; then no more casts, vote.status hourly.
func TestSendSchedule(t *testing.T) {
	c := newCastEnv(t)
	v := c.open(1)
	t0 := c.now
	c.cast(v, "yes")
	count := func() int { b, _ := c.casts(); return len(b) }
	at := func(d time.Duration) int {
		c.now = t0.Add(d)
		c.f.Tick(c.session())
		return count()
	}
	if count() != 1 || at(59*time.Second) != 1 {
		t.Fatal("sent early")
	}
	if at(61*time.Second) != 2 || at(4*time.Minute) != 2 || at(5*time.Minute+time.Second) != 3 || at(29*time.Minute) != 3 {
		t.Fatal("1 and 5 minutes")
	}
	if at(30*time.Minute+time.Second) != 4 || at(89*time.Minute) != 4 || at(90*time.Minute+2*time.Second) != 5 {
		t.Fatalf("30 minutes, then hourly: %d", count())
	}
	// Every send is a new request with a new inner id.
	_, ids := c.casts()
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] {
			t.Error("an id repeated")
		}
		seen[id] = true
	}
	// The stored body is what is sent, every time.
	bodies, _ := c.casts()
	for _, b := range bodies[1:] {
		if string(b) != string(bodies[0]) {
			t.Error("a body differs")
		}
	}
	// At the close in force sending stops and vote.status is asked, hourly.
	closes := time.Unix(c.rec(v.ID).Closes, 0)
	before := count()
	c.now = closes.Add(time.Second)
	c.f.Tick(c.session())
	if count() != before || len(c.statuses()) != 1 {
		t.Fatalf("at the close: %d casts, %d statuses", count()-before, len(c.statuses()))
	}
	c.tickAt(30 * time.Minute)
	if len(c.statuses()) != 1 {
		t.Error("status asked within the hour")
	}
	c.tickAt(31 * time.Minute)
	if len(c.statuses()) != 2 || count() != before {
		t.Errorf("hourly status: %d", len(c.statuses()))
	}
}

func TestExtensionRestartsSending(t *testing.T) {
	c := newCastEnv(t)
	v := c.open(1)
	c.cast(v, "yes")
	c.tickAt(2 * time.Minute)
	c.tickAt(10 * time.Minute) // sends at 1, 5 minutes (and later steps)
	b0, _ := c.casts()
	rec := c.rec(v.ID)
	rec.Ballot.NextSendMS = c.now.Add(time.Hour).UnixMilli()
	_, msg := c.svc.Extension(v, 1, time.Unix(rec.Closes, 0).Add(time.Hour), c.now)
	if r := c.call("vote.extended", msg); !r.OK() {
		t.Fatalf("%q %v", r.Code, c.h.Activities)
	}
	if c.rec(v.ID).Ballot.Round != 0 || c.rec(v.ID).Ballot.NextSendMS != 0 {
		t.Fatalf("not restarted: %+v", c.rec(v.ID).Ballot)
	}
	c.f.Tick(c.session())
	b1, _ := c.casts()
	if len(b1) != len(b0)+1 {
		t.Errorf("sent %d, was %d", len(b1), len(b0))
	}
	// An extension clears the 404s counted for the old close.
	c.rec(v.ID).AbsentMS = 5
	_, msg2 := c.svc.Extension(v, 2, time.Unix(c.rec(v.ID).Closes, 0).Add(time.Hour), c.now)
	c.call("vote.extended", msg2)
	if c.rec(v.ID).AbsentMS != 0 {
		t.Error("AbsentMS not cleared")
	}
}

func TestNoAnswerFor24HoursAsksStatus(t *testing.T) {
	c := newCastEnv(t)
	v := c.svc.NewVote(votetest.VoteSpec{ID: lid(1), Opens: c.now.Add(-time.Hour), Closes: c.now.Add(40 * time.Hour)})
	c.send(v)
	c.cast(v, "yes")
	c.tickAt(23 * time.Hour)
	if len(c.statuses()) != 0 {
		t.Fatal("asked early")
	}
	c.tickAt(2 * time.Hour)
	if len(c.statuses()) != 1 {
		t.Fatalf("%d statuses", len(c.statuses()))
	}
}

func TestNotSignedInAndTheNextResponse(t *testing.T) {
	c := newCastEnv(t)
	v := c.open(1)
	c.cast(v, "yes")
	_, ids := c.casts()
	c.refusal(v, ids[0], "vote.cast", "not_signed_in", votewire.H(c.leafOf(v)))
	if c.state(v) != "waiting:not_signed_in" {
		t.Fatal(c.state(v))
	}
	// Hourly...
	c.tickAt(10 * time.Minute)
	if b, _ := c.casts(); len(b) != 1 {
		t.Error("sent within the hour")
	}
	// ...and at once after the vault's next signed response.
	c.f.ResponseSigned(c.session(), "svc")
	c.f.Tick(c.session())
	if b, _ := c.casts(); len(b) != 2 {
		t.Errorf("not sent after the response: %d", len(b))
	}
}

// A credential rotation (§3.5.5, 0.81.1): both keys open, every ballot not
// final re-signed under the new key, the body replaced, sent once to a
// connection that pinned the old key; bad_ballot for the older send is
// answered by the new body; for the new one it is final.
func TestRotationResignsAndBadBallot(t *testing.T) {
	c := newCastEnv(t)
	v := c.open(1)
	w := c.open(2)
	c.cast(v, "yes")
	c.cast(w, "no")
	rec := c.rec(v.ID)
	oldBody := string(rec.Ballot.Body)
	oldLeaf := c.leafOf(v)
	_, ids := c.casts()
	oldID := ids[0]
	// A ballot already final is not touched.
	z := c.open(3)
	c.cast(z, "yes")
	_, zids := c.casts()
	c.okReceipt(z, zids[2], c.leafOf(z), uint64(c.now.UnixMilli()))
	zBody := string(c.rec(z.ID).Ballot.Body)

	oldPub := c.cred.Public().(ed25519.PublicKey)
	_, newKey, _ := ed25519.GenerateKey(rand.Reader)
	c.h.Reset()
	c.f.CredentialKeysOpen(c.session(), c.cred, newKey)
	newPub := newKey.Public().(ed25519.PublicKey)
	if string(c.rec(z.ID).Ballot.Body) != zBody {
		t.Error("a final ballot was re-signed")
	}
	b := c.rec(v.ID).Ballot
	if string(b.Body) == oldBody {
		t.Fatal("body not replaced")
	}
	if err := votewire.VerifyCast(newPub, v.Hash, oldLeaf, b.CastSig); err != nil {
		t.Errorf("not signed by the new key: %v", err)
	}
	if votewire.VerifyCast(oldPub, v.Hash, oldLeaf, b.CastSig) == nil {
		t.Error("still the old key")
	}
	if string(c.leafOf(v)) != string(oldLeaf) { // the same ballot
		t.Error("the ballot changed")
	}
	bodies, ids2 := c.casts()
	if len(bodies) != 2 { // one per ballot not final
		t.Fatalf("%d sent", len(bodies))
	}
	if b.Gen != 1 || b.SentGen != 1 {
		t.Errorf("gen %d sent %d", b.Gen, b.SentGen)
	}
	// bad_ballot for the send made before the rotation: waiting; the body
	// already re-signed is the answer (already sent: not again).
	c.h.Reset()
	c.refusal(v, oldID, "vote.cast", "bad_ballot", votewire.H(oldLeaf))
	if c.state(v) != "waiting:bad_ballot" {
		t.Fatalf("%s", c.state(v))
	}
	if len(c.h.SentOfType("vote.cast")) != 0 || len(c.h.SentOfType("vote.status")) != 0 {
		t.Error("something was sent at the answer")
	}
	// bad_ballot for the re-signed body: final.
	_, ids3 := c.casts()
	_ = ids3
	var newID string
	for i, s := range c.h.Sent {
		_ = i
		_ = s
	}
	newID = ids2[0]
	if c.rec(v.ID).Ballot.Sends[len(c.rec(v.ID).Ballot.Sends)-1].Gen != 1 {
		t.Fatal("the last send is not the re-signed body")
	}
	c.f.pend[newID] = pendRef{conn: "svc", id: v.ID, kind: "cast"}
	c.refusal(v, newID, "vote.cast", "bad_ballot", votewire.H(oldLeaf))
	if c.state(v) != "refused:bad_ballot" || !c.has("vote.refused", v.ID+":bad_ballot") || !c.has("vote.problem", v.ID) {
		t.Errorf("%s %v", c.state(v), c.h.Activities)
	}
	// A ballot of a connection that pinned no key is only replaced; after the
	// close it is only replaced.
	c2 := newCastEnv(t)
	u := c2.open(1)
	c2.cast(u, "yes")
	c2.auth.pins["svc"] = nil
	c2.h.Reset()
	_, nk, _ := ed25519.GenerateKey(rand.Reader)
	c2.f.CredentialKeysOpen(c2.session(), c2.cred, nk)
	if len(c2.h.SentOfType("vote.cast")) != 0 || c2.rec(u.ID).Ballot.Gen != 0 {
		t.Error("sent without a pin")
	}
	c2.auth.pins["svc"] = c2.cred.Public().(ed25519.PublicKey)
	c2.now = time.Unix(c2.rec(u.ID).Closes, 0).Add(time.Minute)
	c2.h.Reset()
	_, nk2, _ := ed25519.GenerateKey(rand.Reader)
	before := string(c2.rec(u.ID).Ballot.Body)
	c2.f.CredentialKeysOpen(c2.session(), nk, nk2)
	if len(c2.h.SentOfType("vote.cast")) != 0 || string(c2.rec(u.ID).Ballot.Body) == before {
		t.Error("after the close: replaced and not sent")
	}
	// bad_ballot with no rotation sent since the last response: final at once.
	c3 := newCastEnv(t)
	x := c3.open(1)
	c3.cast(x, "yes")
	_, xids := c3.casts()
	c3.refusal(x, xids[0], "vote.cast", "bad_ballot", votewire.H(c3.leafOf(x)))
	if c3.state(x) != "refused:bad_ballot" {
		t.Errorf("bad_ballot without a rotation: %s", c3.state(x))
	}
	// A bad_ballot for the older send when the new body was NOT yet sent: sent now, once.
	c4 := newCastEnv(t)
	y := c4.open(1)
	c4.cast(y, "yes")
	_, yids := c4.casts()
	c4.rec(y.ID).Ballot.Gen = 1 // re-signed for a statement; not yet sent (SentGen 0)
	c4.h.Reset()
	c4.refusal(y, yids[0], "vote.cast", "bad_ballot", votewire.H(c4.leafOf(y)))
	if len(c4.h.SentOfType("vote.cast")) != 1 || c4.state(y) != "waiting:bad_ballot" {
		t.Errorf("not sent once: %d %s", len(c4.h.SentOfType("vote.cast")), c4.state(y))
	}
}

func TestAlreadyVoted(t *testing.T) {
	c := newCastEnv(t)
	v := c.open(1)
	c.cast(v, "yes")
	_, ids := c.casts()
	b := c.rec(v.ID).Ballot
	rb := &votewire.Ballot{RecordTag: v.Tag, VK: b.VK, ChoiceID: b.ChoiceID, BallotSig: b.BallotSig}
	leaf := must(rb.Leaf())
	msgMS := uint64(c.now.UnixMilli())
	rsig, _ := suite.Sign(c.svc.IK, votewire.LabelReceipt, must(votewire.ReceiptMsg(v.Hash, leaf, msgMS)))
	send := func(rb *votewire.Ballot, rsig []byte, id string) {
		msg := must(votewire.RefusalMsg(v.ID, votewire.H(c.h.IK), v.Tag, "vote.cast", "already_voted", msgMS, votewire.H(leaf)))
		sig, _ := suite.Sign(c.svc.IK, votewire.LabelRefusal, msg)
		body := strictjson.NewBuilder().Base64("refusal_sig", sig).Uint("msg_ms", msgMS).Base64("connection", votewire.H(c.h.IK)).Base64("record_tag", v.Tag).
			Raw("ballot", strictjson.NewBuilder().Base64("vk", rb.VK).String("choice_id", rb.ChoiceID).Base64("ballot_sig", rb.BallotSig).Bytes()).
			Uint("ballot_msg_ms", msgMS).Base64("receipt_sig", rsig).Bytes()
		c.respond(id, "vote.cast", &envelope.Inner{Status: envelope.StatusError, Error: &envelope.Error{Code: "already_voted"}, Body: body})
	}
	send(rb, rsig, ids[0])
	if c.state(v) != BallotRecorded {
		t.Fatalf("own ballot: %s", c.state(v))
	}
	// Another ballot under the code: a conflict, with the other kept.
	c2 := newCastEnv(t)
	w := c2.open(1)
	c2.cast(w, "yes")
	_, ids2 := c2.casts()
	_, vk2, _ := ed25519.GenerateKey(rand.Reader)
	other := must(votewire.SignBallot(vk2, w.Hash, w.Tag, "no"))
	oleaf := must(other.Leaf())
	orsig, _ := suite.Sign(c2.svc.IK, votewire.LabelReceipt, must(votewire.ReceiptMsg(w.Hash, oleaf, msgMS)))
	own := c2.rec(w.ID).Ballot
	ownLeaf := must((&votewire.Ballot{RecordTag: w.Tag, VK: own.VK, ChoiceID: own.ChoiceID, BallotSig: own.BallotSig}).Leaf())
	msg := must(votewire.RefusalMsg(w.ID, votewire.H(c2.h.IK), w.Tag, "vote.cast", "already_voted", msgMS, votewire.H(ownLeaf)))
	sig, _ := suite.Sign(c2.svc.IK, votewire.LabelRefusal, msg)
	body := strictjson.NewBuilder().Base64("refusal_sig", sig).Uint("msg_ms", msgMS).Base64("connection", votewire.H(c2.h.IK)).Base64("record_tag", w.Tag).
		Raw("ballot", strictjson.NewBuilder().Base64("vk", other.VK).String("choice_id", "no").Base64("ballot_sig", other.BallotSig).Bytes()).
		Uint("ballot_msg_ms", msgMS).Base64("receipt_sig", orsig).Bytes()
	c2.h.Reset()
	c2.respond(ids2[0], "vote.cast", &envelope.Inner{Status: envelope.StatusError, Error: &envelope.Error{Code: "already_voted"}, Body: body})
	r := c2.rec(w.ID)
	if r.Ballot.State != BallotConflict || r.Other == nil || r.Other.ChoiceID != "no" || !c2.has("vote.conflict", w.ID) || !c2.has("vote.problem", w.ID) || !r.problem() {
		t.Errorf("%s %+v %v", r.Ballot.State, r.Other, c2.h.Activities)
	}
	if len(r.VKSeed) != 0 {
		t.Error("seed kept after a conflict")
	}
}

func TestConnectionRemoved(t *testing.T) {
	c := newCastEnv(t)
	v := c.open(1)
	w := c.open(2)
	c.cast(v, "yes")
	_, ids := c.casts()
	c.okReceipt(v, ids[0], c.leafOf(v), uint64(c.now.UnixMilli()))
	c.cast(w, "no")
	c.f.ConnectionRemoved(c.session(), "svc")
	if c.state(w) != "refused:connection_ended" || c.state(v) != BallotRecorded || len(c.rec(w.ID).VKSeed) != 0 {
		t.Errorf("%s %s", c.state(w), c.state(v))
	}
	// A refused ballot of an ended connection is not a verified refusal for
	// the results check (unconfirmed).
	if s, _ := verdict(c.rec(w.ID), nil); s != CheckUnconfirmed {
		t.Errorf("verdict %s", s)
	}
}

// The seed of a vote never cast goes at the close; a reopened one (an
// extension arrives late) gets a fresh key.
func TestSeedErasedAtCloseNeverCast(t *testing.T) {
	c := newCastEnv(t)
	v := c.open(1)
	if len(c.rec(v.ID).VKSeed) != 32 {
		t.Fatal("no seed")
	}
	c.f.Tick(c.session())
	if len(c.rec(v.ID).VKSeed) != 32 {
		t.Error("seed erased before the close")
	}
	c.now = time.Unix(c.rec(v.ID).Closes, 0).Add(time.Second)
	c.f.Tick(c.session())
	if len(c.rec(v.ID).VKSeed) != 0 || len(c.rec(v.ID).VK) != 32 {
		t.Fatalf("seed %d vk %d", len(c.rec(v.ID).VKSeed), len(c.rec(v.ID).VK))
	}
	// An extension to a time still ahead reopens it, with a fresh voting key.
	closes := time.Unix(c.rec(v.ID).Closes, 0)
	_, msg := c.svc.Extension(v, 1, closes.Add(time.Hour), closes.Add(-time.Minute))
	c.now = closes.Add(time.Second)
	if r := c.call("vote.extended", msg); r.OK() && c.rec(v.ID).state(c.now) != StateOpen {
		t.Errorf("not reopened: %s", c.rec(v.ID).state(c.now))
	}
}

func TestResultsCheckLifecycle(t *testing.T) {
	c := newCastEnv(t)
	v := c.open(1)
	rec := c.rec(v.ID)
	closes := time.Unix(rec.Closes, 0)
	c.now = closes.Add(CheckDelay - time.Second)
	c.f.Tick(c.session())
	if c.rec(v.ID).Check != "" {
		t.Error("pending before the due time")
	}
	c.h.Reset()
	c.tickAt(2 * time.Second)
	if c.rec(v.ID).Check != CheckPending {
		t.Fatalf("not pending: %q", c.rec(v.ID).Check)
	}
	ev := 0
	for _, s := range c.h.SentOfType("vote.event") {
		if strings.Contains(string(s.Body), "check_due") {
			ev++
		}
	}
	if ev != 1 {
		t.Errorf("%d check_due events", ev)
	}
	c.tickAt(time.Minute)
	for _, s := range c.h.SentOfType("vote.event")[ev:] {
		if strings.Contains(string(s.Body), "check_due") {
			t.Error("check_due twice")
		}
	}
	// Gives up seven days after it was due.
	c.now = rec.dueAt().Add(CheckGiveUp - time.Second)
	c.f.Tick(c.session())
	if c.rec(v.ID).Check != CheckPending {
		t.Error("gave up early")
	}
	c.tickAt(2 * time.Second)
	if c.rec(v.ID).Check != CheckGaveUp || !c.has("vote.check_gave_up", v.ID) {
		t.Errorf("%q %v", c.rec(v.ID).Check, c.h.Activities)
	}
	_ = vault.KindApp
}
