package vote

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/featuretest"
	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/internal/votetest"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/suite"
	"github.com/vettid/vettid-vault/vms/votewire"
)

type fakeKeys struct {
	key ed25519.PrivateKey
	ok  bool
}

func (k *fakeKeys) UseKey(time.Time, time.Duration) (ed25519.PrivateKey, bool) { return k.key, k.ok }

type fakeAuth struct{ pins, owed map[string][]byte }

func (a *fakeAuth) SignedInKey(c string) []byte { return a.pins[c] }
func (a *fakeAuth) RotatedBody(c string) []byte { return a.owed[c] }

// cenv is an env whose vault can cast: a credential key in its unlock
// window and a connection that pinned it.
type cenv struct {
	*env
	cred ed25519.PrivateKey
	keys *fakeKeys
	auth *fakeAuth
}

func newCastEnv(t *testing.T) *cenv {
	e := newEnv(t)
	_, cred, _ := ed25519.GenerateKey(rand.Reader)
	c := &cenv{env: e, cred: cred, keys: &fakeKeys{key: cred, ok: true},
		auth: &fakeAuth{pins: map[string][]byte{"svc": cred.Public().(ed25519.PublicKey)}, owed: map[string][]byte{}}}
	e.f.dep = Deps{Keys: c.keys, Auth: c.auth}
	e.publish(e.svc)
	return c
}

// open sends an open vote and returns it.
func (c *cenv) open(n int) *votetest.Vote {
	c.t.Helper()
	v := c.svc.NewVote(votetest.VoteSpec{ID: lid(n), Opens: c.now.Add(-time.Hour), Closes: c.now.Add(2 * time.Hour)})
	if r := c.send(v); !r.OK() {
		c.t.Fatalf("vote: %q", r.Code)
	}
	return v
}

func (c *cenv) cast(v *votetest.Vote, choice string) (CastResult, error) {
	c.t.Helper()
	return c.f.Cast(c.session(), "svc", v.ID, choice)
}

func code(err error) string {
	if he, ok := err.(*vault.HandlerError); ok {
		return he.Code
	}
	if err == nil {
		return ""
	}
	return "?" + err.Error()
}

// casts are the vote.cast requests sent, and their request ids.
func (c *cenv) casts() (bodies [][]byte, ids []string) {
	for i, s := range c.h.Sent {
		if s.Type == "vote.cast" {
			bodies = append(bodies, s.Body)
			ids = append(ids, c.h.SentIDs[i])
		}
	}
	return
}

func (c *cenv) statuses() (ids []string) {
	for i, s := range c.h.Sent {
		if s.Type == "vote.status" {
			ids = append(ids, c.h.SentIDs[i])
		}
	}
	return
}

func (c *cenv) respond(reqID, typ string, in *envelope.Inner) {
	c.t.Helper()
	in.Re, in.Type = reqID, typ
	c.f.Response(c.session(), in)
}

func (c *cenv) okReceipt(v *votetest.Vote, reqID string, leaf []byte, msgMS uint64) {
	sig, _ := suite.Sign(c.svc.IK, votewire.LabelReceipt, must(votewire.ReceiptMsg(v.Hash, leaf, msgMS)))
	body := strictjson.NewBuilder().String("proposal_id", v.ID).Uint("msg_ms", msgMS).Base64("receipt_sig", sig).Bytes()
	c.respond(reqID, "vote.cast", &envelope.Inner{Status: envelope.StatusOK, Body: body})
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

// refusal answers a request with a signed refusal; sign=false leaves it
// unsigned, conn overrides the connection hash.
func (c *cenv) refusal(v *votetest.Vote, reqID, typ, codeStr string, hash []byte, opts ...func(*refOpts)) []byte {
	o := &refOpts{conn: votewire.H(c.h.IK), tag: v.Tag, sign: true, msgMS: uint64(c.now.UnixMilli())}
	for _, f := range opts {
		f(o)
	}
	msg := must(votewire.RefusalMsg(v.ID, o.conn, o.tag, typ, codeStr, o.msgMS, hash))
	b := strictjson.NewBuilder()
	if o.sign {
		sig, _ := suite.Sign(c.svc.IK, votewire.LabelRefusal, msg)
		b.Base64("refusal_sig", sig)
	} else {
		b.Raw("refusal_sig", []byte("null"))
	}
	b.Uint("msg_ms", o.msgMS).Base64("connection", o.conn).Base64("record_tag", o.tag)
	body := b.Bytes()
	c.respond(reqID, typ, &envelope.Inner{Status: envelope.StatusError, Error: &envelope.Error{Code: codeStr}, Body: body})
	return body
}

type refOpts struct {
	conn, tag []byte
	sign      bool
	msgMS     uint64
}

func (c *cenv) leafOf(v *votetest.Vote) []byte {
	return must(c.rec(v.ID).ballotLeaf())
}

func (c *cenv) state(v *votetest.Vote) string {
	b := c.rec(v.ID).Ballot
	if b == nil {
		return ""
	}
	if b.State == BallotWaiting {
		return "waiting:" + b.Reason
	}
	if b.State == BallotRefused {
		return "refused:" + b.Code
	}
	return b.State
}

func TestCastCheckOrder(t *testing.T) {
	c := newCastEnv(t)
	v := c.open(1)
	// not_found.
	if _, err := c.f.Cast(c.session(), "svc", lid(99), "yes"); code(err) != "not_found" {
		t.Errorf("not_found: %q", code(err))
	}
	// Each refusal, in the order of the table.
	chk := func(want string, f func()) {
		t.Helper()
		if f != nil {
			f()
		}
		if _, err := c.cast(v, "yes"); code(err) != want {
			t.Errorf("want %s, got %q", want, code(err))
		}
	}
	rec := c.rec(v.ID)
	rec.Reason = ReasonServiceList
	chk("checking", nil)
	rec.Reason = ""
	rec.Opens = c.now.Unix() + 3600
	chk("not_open", nil)
	rec.Opens = c.now.Unix() - 3600
	rec.Closes = c.now.Unix() - 1
	chk("closed", nil)
	rec.Closes = c.now.Unix() + 119
	chk("closing", nil)
	rec.Closes = c.now.Unix() + 7200
	if _, err := c.cast(v, "nonesuch"); code(err) != "bad_request" {
		t.Errorf("bad choice: %q", code(err))
	}
	rec.Site = SiteMismatch
	chk("site_mismatch", nil)
	rec.Site = SiteUnreachable // an unreachable or silent site does not block
	c.h.Conns["svc"] = vault.PeerInfo{ID: "svc", Kind: vault.KindConnection, State: "closed", IK: c.svc.Pub(), PeerKind: "service"}
	chk("connection_unavailable", nil)
	c.h.Conns["svc"] = vault.PeerInfo{ID: "svc", Kind: vault.KindConnection, State: vault.PeerActive, IK: c.svc.Pub(), PeerKind: "service"}
	pin := c.auth.pins["svc"]
	c.auth.pins["svc"] = nil
	_, err := c.cast(v, "yes")
	if code(err) != "not_signed_in" || !strings.Contains(string(err.(*vault.HandlerError).Body), "svc") {
		t.Errorf("not_signed_in: %v", err)
	}
	c.auth.pins["svc"] = pin
	c.keys.ok = false
	chk("credential_locked", nil)
	if len(c.h.Sent) > 0 && len(c.h.SentOfType("vote.cast")) > 0 {
		t.Error("something was sent while refused")
	}
	c.keys.ok = true
	// Nothing was signed or stored by any refusal.
	if c.rec(v.ID).Ballot != nil {
		t.Fatal("a ballot after refusals")
	}
	// Restore blocks.
	rec.Restore = true
	chk("checking", nil)
	rec.Restore = false
}

func TestCastSignsStoresAndSends(t *testing.T) {
	c := newCastEnv(t)
	v := c.open(1)
	// A rotation statement still owed to the connection goes first.
	c.auth.owed["svc"] = []byte(`{"chain":[]}`)
	c.h.Reset()
	res, err := c.cast(v, "yes")
	if err != nil || res.State != BallotSending || res.ProposalID != v.ID {
		t.Fatalf("%v %+v", err, res)
	}
	if string(res.Body()) != `{"proposal_id":"`+v.ID+`","ballot":{"state":"sending"}}` {
		t.Errorf("%s", res.Body())
	}
	var order []string
	for _, s := range c.h.Sent {
		if s.Type == "connection.authenticate.rotated" || s.Type == "vote.cast" {
			order = append(order, s.Type)
		}
	}
	if strings.Join(order, ",") != "connection.authenticate.rotated,vote.cast" {
		t.Errorf("order %v", order)
	}
	bodies, ids := c.casts()
	if len(bodies) != 1 || ids[0] == "" {
		t.Fatalf("%d casts", len(bodies))
	}
	o, _ := strictjson.ParseObject(bodies[0])
	for _, n := range []string{"proposal_id", "record_tag", "vk", "choice_id", "ballot_sig", "cast_sig"} {
		if !o.Has(n) {
			t.Errorf("no %s", n)
		}
	}
	// The ballot and the cast signature verify, byte for byte as §16 pins.
	rec := c.rec(v.ID)
	b := rec.Ballot
	bal := &votewire.Ballot{RecordTag: v.Tag, VK: rec.VK, ChoiceID: "yes", BallotSig: b.BallotSig}
	if err := votewire.VerifyBallot(v.Hash, bal); err != nil {
		t.Errorf("ballot_sig: %v", err)
	}
	leaf, _ := bal.Leaf()
	if err := votewire.VerifyCast(c.cred.Public().(ed25519.PublicKey), v.Hash, leaf, b.CastSig); err != nil {
		t.Errorf("cast_sig: %v", err)
	}
	// Audited without the choice; no event, feed or audit entry names it.
	if !c.has("vote.cast", v.ID) {
		t.Error("no audit entry")
	}
	for _, a := range c.h.Activities {
		if strings.Contains(a.Ref, "yes") || strings.Contains(a.Kind, "yes") {
			t.Errorf("choice in %+v", a)
		}
	}
	for _, s := range c.h.Sent {
		if s.Type == "vote.event" && strings.Contains(string(s.Body), "yes") {
			t.Errorf("choice in an event: %s", s.Body)
		}
	}
	// A repeat of the same choice answers with the state and changes nothing;
	// another choice is already_voted.
	c.h.Reset()
	if r, err := c.cast(v, "yes"); err != nil || r.State != BallotSending || len(c.h.Sent) != 0 {
		t.Errorf("repeat: %v %+v", err, r)
	}
	_, err = c.cast(v, "no")
	if code(err) != "already_voted" || !strings.Contains(string(err.(*vault.HandlerError).Body), `"state":"sending"`) {
		t.Errorf("already_voted: %v", err)
	}
	// The state is vault state.
	g := New(c.f.opt, c.f.dep)
	featuretest.RoundTrip(t, c.f, g)
	if g.st.Records[key("svc", v.ID)].Ballot == nil || len(g.st.Records[key("svc", v.ID)].Ballot.Body) == 0 {
		t.Error("the stored body did not survive")
	}
}

func TestReceiptRecords(t *testing.T) {
	c := newCastEnv(t)
	v := c.open(1)
	c.cast(v, "yes")
	_, ids := c.casts()
	leaf := c.leafOf(v)
	seed := c.rec(v.ID).VKSeed
	if len(seed) == 0 {
		t.Fatal("no seed")
	}
	c.h.Reset()
	// A receipt that fails, or is outside the window: no answer.
	bad := strictjson.NewBuilder().String("proposal_id", v.ID).Uint("msg_ms", uint64(c.now.UnixMilli())).Base64("receipt_sig", make([]byte, 64)).Bytes()
	c.respond(ids[0], "vote.cast", &envelope.Inner{Status: envelope.StatusOK, Body: bad})
	if !c.has("vote.receipt_rejected", v.ID) || c.state(v) != BallotSending {
		t.Errorf("failing receipt: %s %v", c.state(v), c.h.Activities)
	}
	c.f.pend[ids[0]] = pendRef{conn: "svc", id: v.ID, kind: "cast"}
	c.okReceipt(v, ids[0], leaf, uint64(c.rec(v.ID).Opens*1000-1)) // before opens_at
	c.f.pend[ids[0]] = pendRef{conn: "svc", id: v.ID, kind: "cast"}
	c.okReceipt(v, ids[0], leaf, uint64(c.rec(v.ID).Closes*1000)) // not before the close
	if c.state(v) != BallotSending {
		t.Errorf("a receipt outside the window was taken: %s", c.state(v))
	}
	c.f.pend[ids[0]] = pendRef{conn: "svc", id: v.ID, kind: "cast"}
	c.h.Reset()
	c.okReceipt(v, ids[0], leaf, uint64(c.now.UnixMilli()))
	rec := c.rec(v.ID)
	if c.state(v) != BallotRecorded || rec.Ballot.ReceiptSig == nil || len(rec.VKSeed) != 0 || len(rec.VK) != 32 {
		t.Fatalf("%s %+v", c.state(v), rec.Ballot)
	}
	if !c.has("vote.recorded", v.ID) || len(c.h.SentOfType("vote.event")) == 0 {
		t.Errorf("%v", c.h.Activities)
	}
	// A recorded ballot is final: nothing is sent again.
	c.now = c.now.Add(3 * time.Hour)
	c.h.Reset()
	c.f.Tick(c.session())
	if len(c.h.SentOfType("vote.cast")) != 0 {
		t.Error("sent after the receipt")
	}
}

func TestRefusalsByCode(t *testing.T) {
	c := newCastEnv(t)
	n := 0
	fresh := func() (*votetest.Vote, string) {
		n++
		v := c.open(n)
		c.h.Reset()
		c.cast(v, "yes")
		_, ids := c.casts()
		return v, ids[0]
	}
	hash := func(v *votetest.Vote) []byte { return votewire.H(c.leafOf(v)) }

	// Unsigned, another connection, another tag, a code unknown to the
	// vault: no answer.
	v, id := fresh()
	c.refusal(v, id, "vote.cast", "not_open", hash(v), func(o *refOpts) { o.sign = false })
	c.f.pend[id] = pendRef{conn: "svc", id: v.ID, kind: "cast"}
	c.refusal(v, id, "vote.cast", "not_open", hash(v), func(o *refOpts) { o.conn = make([]byte, 32) })
	c.f.pend[id] = pendRef{conn: "svc", id: v.ID, kind: "cast"}
	c.refusal(v, id, "vote.cast", "not_open", hash(v), func(o *refOpts) { o.tag = make([]byte, 32) })
	c.f.pend[id] = pendRef{conn: "svc", id: v.ID, kind: "cast"}
	c.refusal(v, id, "vote.cast", "mystery", hash(v))
	if c.state(v) != BallotSending {
		t.Errorf("no answer changed the state: %s", c.state(v))
	}
	// An empty record_tag verifies (the service sends it for a connection
	// with no tag).
	c.f.pend[id] = pendRef{conn: "svc", id: v.ID, kind: "cast"}
	c.refusal(v, id, "vote.cast", "not_open", hash(v), func(o *refOpts) { o.tag = nil })
	if c.state(v) != "waiting:not_open" {
		t.Errorf("empty tag: %s", c.state(v))
	}

	for _, tc := range []struct {
		code, want string
		problem    bool
	}{
		{"not_open", "waiting:not_open", false},
		{"not_signed_in", "waiting:not_signed_in", false},
		{"closed", "refused:closed", false}, // no earlier send unanswered: final at once
		{"late", "refused:late", false},
		{"not_active", "refused:not_active", true},
		{"not_eligible", "refused:not_eligible", true},
	} {
		c.h.Reset()
		v, id := fresh()
		c.h.Reset()
		c.refusal(v, id, "vote.cast", tc.code, hash(v))
		if c.state(v) != tc.want {
			t.Errorf("%s: %s", tc.code, c.state(v))
		}
		final := strings.HasPrefix(tc.want, "refused")
		if final && (!c.has("vote.refused", v.ID+":"+tc.code) || len(c.rec(v.ID).VKSeed) != 0 || len(c.rec(v.ID).Ballot.Refusals) != 1) {
			t.Errorf("%s: final but %v", tc.code, c.h.Activities)
		}
		if c.has("vote.problem", v.ID) != tc.problem {
			t.Errorf("%s: problem=%v %v", tc.code, !tc.problem, c.h.Activities)
		}
		if tc.problem && !c.rec(v.ID).problem() {
			t.Errorf("%s: not in the problem set", tc.code)
		}
	}
}

// closed/late with an earlier send unanswered is not final: the vault asks
// the service; an answer with the ballot is the receipt, one without is
// final only after closes_at + 24 hours; a receipt always wins.
func TestClosedWithAnEarlierSendUnanswered(t *testing.T) {
	c := newCastEnv(t)
	v := c.open(1)
	c.cast(v, "yes")
	c.now = c.now.Add(90 * time.Second)
	c.f.Tick(c.session()) // the second send (1 minute)
	_, ids := c.casts()
	if len(ids) != 2 {
		t.Fatalf("%d sends", len(ids))
	}
	c.h.Reset()
	hash := votewire.H(c.leafOf(v))
	c.refusal(v, ids[1], "vote.cast", "closed", hash) // the first send is unanswered
	if c.state(v) != "waiting:closed" {
		t.Fatalf("%s", c.state(v))
	}
	if c.rec(v.ID).Ballot.NextStatusMS > c.now.UnixMilli() {
		t.Error("not asked at once")
	}
	c.f.Tick(c.session())
	st := c.statuses()
	if len(st) != 1 {
		t.Fatalf("%d status asks", len(st))
	}
	// A signed answer without a ballot, before closes_at + 24 h: still waiting.
	statusNone := func(reqID string) {
		sig, _ := suite.Sign(c.svc.IK, votewire.LabelStatus, must(votewire.StatusMsg(v.ID, v.Tag, nil)))
		body := c.statusBody(v, nil, 0, nil, sig)
		c.respond(reqID, "vote.status", &envelope.Inner{Status: envelope.StatusOK, Body: body})
	}
	statusNone(st[0])
	if c.state(v) != "waiting:closed" {
		t.Errorf("early: %s", c.state(v))
	}
	// After closes_at + 24 h: final.
	c.now = time.Unix(c.rec(v.ID).Closes, 0).Add(25 * time.Hour)
	c.f.Tick(c.session())
	st = c.statuses()
	statusNone(st[len(st)-1])
	if c.state(v) != "refused:closed" {
		t.Errorf("late: %s", c.state(v))
	}
	// A receipt for any send wins, whenever it arrives (here the first send
	// answered after the refusal was final).
	c.f.pend[ids[0]] = pendRef{conn: "svc", id: v.ID, kind: "cast"}
	c.okReceipt(v, ids[0], c.leafOf(v), uint64(c.rec(v.ID).Opens*1000+5))
	if c.state(v) != BallotRecorded {
		t.Errorf("receipt did not win: %s", c.state(v))
	}
}

// statusBody builds an ok vote.status answer for v's member.
func (c *cenv) statusBody(v *votetest.Vote, ballot *votewire.RowBallot, msgMS uint64, receiptSig, statusSig []byte) []byte {
	b := strictjson.NewBuilder().String("proposal_id", v.ID).Base64("proposal", v.Doc).Base64("proposal_sig", v.Sig).
		Raw("bundle", c.auth0Bundle(v)).Base64("record_secret", v.Secret).
		Raw("record_proof", (&votewire.RecordProof{Index: uint64(v.Index), TreeSize: uint64(len(v.Tags)), Path: must(votewire.Proof(v.Tags, v.Index))}).JSON())
	if ballot != nil {
		b.Raw("ballot", strictjson.NewBuilder().Base64("vk", ballot.VK).String("choice_id", ballot.ChoiceID).Base64("ballot_sig", ballot.BallotSig).Bytes())
		b.Uint("msg_ms", msgMS).Base64("receipt_sig", receiptSig)
	}
	return b.Base64("status_sig", statusSig).Bytes()
}

func (c *cenv) auth0Bundle(v *votetest.Vote) []byte {
	return c.env.auth.Bundle(v.Doc, c.svc.Anchor, c.now)
}
