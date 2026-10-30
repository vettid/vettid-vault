package vote

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/internal/votetest"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/suite"
	"github.com/vettid/vettid-vault/vms/votewire"
)

// statusNoBundle is an ok vote.status answer without a bundle.
func (c *cenv) statusNoBundle(v *votetest.Vote, ballot *votewire.Ballot, msgMS uint64, badSig bool) []byte {
	var leaf []byte
	if ballot != nil {
		leaf = must(ballot.Leaf())
	}
	ssig, _ := suite.Sign(c.svc.IK, votewire.LabelStatus, must(votewire.StatusMsg(v.ID, v.Tag, leaf)))
	if badSig {
		ssig = make([]byte, 64)
	}
	b := strictjson.NewBuilder().String("proposal_id", v.ID).Base64("proposal", v.Doc).Base64("proposal_sig", v.Sig).Base64("record_secret", v.Secret).
		Raw("record_proof", (&votewire.RecordProof{Index: uint64(v.Index), TreeSize: uint64(len(v.Tags)), Path: must(votewire.Proof(v.Tags, v.Index))}).JSON())
	return b.Base64("status_sig", ssig).Bytes()
}

// checkingSite keeps a proposal from a status answer without a bundle.
func (c *cenv) checkingSite(n int) *votetest.Vote {
	c.t.Helper()
	v := c.svc.NewVote(votetest.VoteSpec{ID: lid(n), Opens: c.now.Add(-time.Hour), Closes: c.now.Add(time.Hour)})
	c.now = c.now.Add(time.Second)
	if !c.f.RequestProposal(c.session(), "svc", v.ID, v.Doc) {
		c.t.Fatal("not asked")
	}
	ids := c.statuses()
	c.respond(ids[len(ids)-1], "vote.status", &envelope.Inner{Status: envelope.StatusOK, Body: c.statusNoBundle(v, nil, 0, false)})
	if r := c.rec(v.ID); r == nil || r.Reason != ReasonSite {
		c.t.Fatalf("not checking (site): %+v", c.rec(v.ID))
	}
	return v
}

// H1: the site's bundle completes a checking (site) record only if it
// verifies for the held bytes; anything else leaves it as it is.
func TestSiteBundleOnlyIfItVerifies(t *testing.T) {
	c := newCastEnv(t)
	v := c.checkingSite(1)
	q := c.svc.NewVote(votetest.VoteSpec{ID: lid(2), Opens: c.now.Add(-time.Hour), Closes: c.now.Add(time.Hour)})
	found := func(bundle []byte) {
		t.Helper()
		if err := c.f.SiteDocument(c.session(), "svc", v.ID, SiteDoc{Status: StatusFound, Proposal: v.Doc, Sig: v.Sig, Bundle: bundle}); err != nil {
			t.Fatal(err)
		}
	}
	// Another proposal's bundle, a bundle for other bytes under the key, a
	// late stamp, garbage: still checking (site), never rejected, never
	// another reason.
	for name, b := range map[string][]byte{
		"another proposal's": c.env.auth.Bundle(q.Doc, c.svc.Anchor, c.now),
		"garbage":            []byte(`{"mediaType":"x"}`),
		"not json":           []byte(`x`),
		"a bundle stamped after the relay window": c.env.auth.Bundle(v.Doc, c.svc.Anchor, c.now.Add(time.Hour)),
	} {
		found(b)
		r := c.rec(v.ID)
		if r.Reason != ReasonSite || r.RejectReason != "" || r.state(c.now) != StateChecking {
			t.Fatalf("%s: %+v", name, r)
		}
	}
	// A key the list does not name, or roots that do not verify, also leave it.
	other := votetest.NewAnchorKey()
	found(c.env.auth.Bundle(v.Doc, other, c.now))
	if c.rec(v.ID).Reason != ReasonSite {
		t.Error("an unnamed key moved it")
	}
	// Then the correct bundle completes it.
	found(c.env.auth.Bundle(v.Doc, c.svc.Anchor, c.now))
	r := c.rec(v.ID)
	if r.Reason != "" || r.RejectReason != "" || r.state(c.now) != StateOpen || !c.has("vote.open", v.ID) {
		t.Errorf("not completed: %+v", r)
	}
}

// H3: Confirm is offered only after a restore and only for the record's own
// voting key; any other ballot the vault never signed is a conflict kept as
// evidence, with no prompt and no change to whether it can cast.
func TestForeignBallotIsAConflictNotAPrompt(t *testing.T) {
	// A restore, a ballot made with another vk.
	c := newCastEnv(t)
	v := c.open(1)
	c.rec(v.ID).Restore = true
	c.f.Tick(c.session())
	_, vk2, _ := ed25519.GenerateKey(rand.Reader)
	sid := c.statuses()[0]
	c.h.Reset()
	c.answer(v, sid, must(votewire.SignBallot(vk2, v.Hash, v.Tag, "no")), uint64(c.now.UnixMilli()), true)
	r := c.rec(v.ID)
	if r.ServiceBallot != nil || !r.ConflictEv || r.Other == nil || !c.has("vote.conflict", v.ID) || !c.has("vote.problem", v.ID) || !r.problem() {
		t.Fatalf("restore, another vk: %+v", r.ServiceBallot)
	}
	if r.Restore {
		t.Error("the restore did not end")
	}
	if _, err := c.f.Confirm(c.session(), "svc", v.ID, true); code(err) != "bad_request" {
		t.Errorf("confirm offered: %v", err)
	}
	// It still can cast.
	if _, err := c.cast(v, "yes"); err != nil {
		t.Errorf("cast after the conflict evidence: %v", err)
	}
	// The results check fails with the conflict.
	// Without a restore: a ballot the vault never signed, even with the
	// record's own vk, is a conflict.
	c2 := newCastEnv(t)
	w := c2.open(1)
	c2.f.Check(c2.session(), "svc", w.ID)
	own := ed25519.NewKeyFromSeed(c2.rec(w.ID).VKSeed)
	c2.answer(w, c2.statuses()[0], must(votewire.SignBallot(own, w.Hash, w.Tag, "no")), uint64(c2.now.UnixMilli()), true)
	if r := c2.rec(w.ID); r.ServiceBallot != nil || !r.ConflictEv {
		t.Errorf("no restore: %+v", r.ServiceBallot)
	}
	if s, why := verdict(c2.rec(w.ID), nil); s != CheckFailed || why != "conflict" {
		t.Errorf("verdict %s %s", s, why)
	}
	// After a restore, the record's own vk: offered.
	c3 := newCastEnv(t)
	x := c3.open(1)
	c3.rec(x.ID).Restore = true
	c3.f.Tick(c3.session())
	own3 := ed25519.NewKeyFromSeed(c3.rec(x.ID).VKSeed)
	c3.answer(x, c3.statuses()[0], must(votewire.SignBallot(own3, x.Hash, x.Tag, "no")), uint64(c3.now.UnixMilli()), true)
	if c3.rec(x.ID).ServiceBallot == nil || c3.rec(x.ID).ConflictEv {
		t.Error("not offered after a restore with the own vk")
	}
	// connection_ended: the vault's own ballot is a receipt, another vk is a
	// conflict at once.
	c4 := newCastEnv(t)
	y := c4.open(1)
	c4.cast(y, "yes")
	c4.f.ConnectionRemoved(c4.session(), "svc")
	if c4.state(y) != "refused:connection_ended" {
		t.Fatal(c4.state(y))
	}
	b := c4.ownBallot(y)
	c4.rec(y.ID).Restore = false
	if !c4.f.askStatus(c4.session(), "svc", y.ID, nil) {
		// the connection is gone from the host: restore it for the request
		c4.h.AddConnection("svc")
		cc := c4.h.Conns["svc"]
		cc.PeerKind, cc.IK = "service", c4.svc.Pub()
		c4.h.Conns["svc"] = cc
		c4.f.askStatus(c4.session(), "svc", y.ID, nil)
	}
	c4.answer(y, c4.statuses()[0], b, uint64(c4.now.UnixMilli()), true)
	if c4.state(y) != BallotRecorded {
		t.Errorf("own ballot after connection_ended: %s", c4.state(y))
	}
	c5 := newCastEnv(t)
	z := c5.open(1)
	c5.cast(z, "yes")
	c5.f.ConnectionRemoved(c5.session(), "svc")
	c5.f.askStatus(c5.session(), "svc", z.ID, nil)
	_, vk3, _ := ed25519.GenerateKey(rand.Reader)
	c5.answer(z, c5.statuses()[0], must(votewire.SignBallot(vk3, z.Hash, z.Tag, "no")), uint64(c5.now.UnixMilli()), true)
	if !c5.rec(z.ID).ConflictEv || !c5.rec(z.ID).problem() {
		t.Error("another vk after connection_ended is not a conflict")
	}
}

// M1: every re-sign is a new generation, whether or not it was sent, so a
// bad_ballot answering a send made before the rotation is not final when
// the connection was unreachable at the rotation.
func TestRotationWhileTheConnectionWasDown(t *testing.T) {
	c := newCastEnv(t)
	v := c.open(1)
	c.cast(v, "yes")
	_, ids := c.casts()
	oldLeaf := c.leafOf(v)
	cc := c.h.Conns["svc"]
	cc.State = "closed"
	c.h.Conns["svc"] = cc
	_, nk, _ := ed25519.GenerateKey(rand.Reader)
	c.h.Reset()
	c.f.CredentialKeysOpen(c.session(), c.cred, nk)
	b := c.rec(v.ID).Ballot
	if b.Gen != 1 || b.SentGen != 0 || len(c.h.SentOfType("vote.cast")) != 0 {
		t.Fatalf("gen %d sent %d", b.Gen, b.SentGen)
	}
	// The connection is back; the answer to the pre-rotation send is
	// bad_ballot: waiting, and the re-signed body is sent once.
	cc.State = vault.PeerActive
	c.h.Conns["svc"] = cc
	c.refusal(v, ids[0], "vote.cast", "bad_ballot", votewire.H(oldLeaf))
	if c.state(v) != "waiting:bad_ballot" || len(c.h.SentOfType("vote.cast")) != 1 {
		t.Errorf("%s, %d sent", c.state(v), len(c.h.SentOfType("vote.cast")))
	}
}

// M2: a verified extension puts a waiting (closed) ballot back to sending
// while the close in force is in the future.
func TestExtensionRevivesWaitingClosed(t *testing.T) {
	c := newCastEnv(t)
	v := c.open(1)
	c.cast(v, "yes")
	c.rec(v.ID).Ballot.State, c.rec(v.ID).Ballot.Reason = BallotWaiting, "closed"
	_, msg := c.svc.Extension(v, 1, time.Unix(c.rec(v.ID).Closes, 0).Add(time.Hour), c.now)
	if r := c.call("vote.extended", msg); !r.OK() {
		t.Fatal(r.Code)
	}
	if c.state(v) != BallotSending {
		t.Fatalf("%s", c.state(v))
	}
	n0, _ := c.casts()
	c.f.Tick(c.session())
	if n1, _ := c.casts(); len(n1) != len(n0)+1 {
		t.Error("not sent again")
	}
}

// M3: a status answer for a proposal the vault was never sent is verified
// (status_sig) before anything is kept; empty site bytes are refused.
func TestUnheldStatusIsVerified(t *testing.T) {
	c := newCastEnv(t)
	v := c.svc.NewVote(votetest.VoteSpec{ID: lid(5), Opens: c.now.Add(-time.Hour), Closes: c.now.Add(time.Hour)})
	if c.f.RequestProposal(c.session(), "svc", v.ID, nil) {
		t.Error("asked without the site's bytes")
	}
	if !c.f.RequestProposal(c.session(), "svc", v.ID, v.Doc) {
		t.Fatal("not asked")
	}
	ids := c.statuses()
	// A bad status_sig keeps nothing, not even a rejected record.
	c.respond(ids[0], "vote.status", &envelope.Inner{Status: envelope.StatusOK, Body: c.statusNoBundle(v, nil, 0, true)})
	if c.rec(v.ID) != nil {
		t.Fatal("kept from an answer whose status_sig fails")
	}
	// An answer for a proposal signed by another service: nothing kept.
	other := votetest.NewService(c.env.auth)
	w := other.NewVote(votetest.VoteSpec{ID: lid(6), Opens: c.now.Add(-time.Hour), Closes: c.now.Add(time.Hour)})
	c.f.RequestProposal(c.session(), "svc", w.ID, w.Doc)
	ids = c.statuses()
	ssig, _ := suite.Sign(other.IK, votewire.LabelStatus, must(votewire.StatusMsg(w.ID, w.Tag, nil)))
	body := strictjson.NewBuilder().String("proposal_id", w.ID).Base64("proposal", w.Doc).Base64("proposal_sig", w.Sig).Base64("record_secret", w.Secret).
		Raw("record_proof", (&votewire.RecordProof{Index: uint64(w.Index), TreeSize: uint64(len(w.Tags)), Path: must(votewire.Proof(w.Tags, w.Index))}).JSON()).
		Base64("status_sig", ssig).Bytes()
	c.respond(ids[len(ids)-1], "vote.status", &envelope.Inner{Status: envelope.StatusOK, Body: body})
	if c.rec(w.ID) != nil {
		t.Error("kept a proposal of another service")
	}
}

// Receipts that arrive in a status answer are held to the window as those of
// vote.cast are.
func TestStatusReceiptWindow(t *testing.T) {
	c := newCastEnv(t)
	v := c.open(1)
	c.cast(v, "yes")
	c.f.Check(c.session(), "svc", v.ID)
	c.answer(v, c.statuses()[0], c.ownBallot(v), uint64(c.rec(v.ID).Closes*1000), true) // not before the close
	if c.state(v) == BallotRecorded || len(c.rec(v.ID).StatusAnswers) != 0 {
		t.Error("a receipt outside the window was taken")
	}
}

// Unanswered requests are forgotten after 25 hours, as the Manager's are.
func TestPendIsPruned(t *testing.T) {
	c := newCastEnv(t)
	v := c.open(1)
	c.cast(v, "yes")
	if len(c.f.pend) != 1 {
		t.Fatalf("%d", len(c.f.pend))
	}
	c.now = c.now.Add(26 * time.Hour)
	c.f.Tick(c.session())
	for _, p := range c.f.pend {
		if c.now.Sub(time.UnixMilli(p.atMS)) > pendTTL {
			t.Error("an old request is kept")
		}
	}
}

// A late refusal after the ballot is refused changes nothing, audits and
// tells nothing again.
func TestLateRefusalAfterRefused(t *testing.T) {
	c := newCastEnv(t)
	v := c.open(1)
	c.cast(v, "yes")
	c.tickAt(2 * time.Minute)
	_, ids := c.casts()
	hash := votewire.H(c.leafOf(v))
	c.refusal(v, ids[0], "vote.cast", "not_active", hash)
	if c.state(v) != "refused:not_active" {
		t.Fatal(c.state(v))
	}
	c.h.Reset()
	c.f.pend[ids[1]] = pendRef{conn: "svc", id: v.ID, kind: "cast", atMS: c.now.UnixMilli()}
	c.refusal(v, ids[1], "vote.cast", "not_active", hash)
	if len(c.h.Activities) != 0 || len(c.rec(v.ID).Ballot.Refusals) != 1 {
		t.Errorf("a late refusal acted again: %v", c.h.Activities)
	}
}
