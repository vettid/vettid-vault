package vote

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/featuretest"
	"github.com/vettid/vettid-vault/internal/votetest"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/suite"
	"github.com/vettid/vettid-vault/vms/votewire"
)

type env struct {
	t     *testing.T
	f     *Feature
	h     *featuretest.Host
	auth  *votetest.Authority
	svc   *votetest.Service
	site  ed25519.PrivateKey
	now   time.Time
	list  []byte // the list held, for chaining
	lists int64
}

func newEnv(t *testing.T) *env {
	t.Helper()
	now := time.Now().Truncate(time.Second)
	e := &env{t: t, now: now, auth: votetest.NewAuthority(now)}
	_, e.site, _ = ed25519.GenerateKey(rand.Reader)
	e.svc = votetest.NewService(e.auth)
	e.f = New(Options{SiteKey: e.site.Public().(ed25519.PublicKey), Roots: e.auth.Roots})
	e.h = featuretest.NewHost()
	e.h.AddConnection("svc")
	c := e.h.Conns["svc"]
	c.PeerKind = "service"
	c.IK = e.svc.Pub()
	e.h.Conns["svc"] = c
	return e
}

func (e *env) session() *vault.Session {
	e.t.Helper()
	from, _ := e.h.Connection("svc")
	s := vault.NewSession(context.Background(), e.h, from, e.now, nil)
	return s
}

// publish gives the vault a service list naming the services.
func (e *env) publish(svcs ...*votetest.Service) string {
	e.t.Helper()
	e.lists++
	doc, sig := votetest.List(e.site, e.lists, hashOrNil(e.list), svcs...)
	res := e.f.SyncServices(e.session(), doc, sig)
	if res == ListKept {
		e.list = doc
	}
	return res
}

func hashOrNil(b []byte) []byte {
	if b == nil {
		return nil
	}
	return votewire.H(b)
}

func (e *env) call(typ string, body []byte) featuretest.Result {
	e.t.Helper()
	return featuretest.Call(e.f, e.h, e.now, "connection:svc", typ, string(body))
}

func (e *env) spec(opens, closes time.Duration) votetest.VoteSpec {
	return votetest.VoteSpec{Opens: e.now.Add(opens), Closes: e.now.Add(closes)}
}

func (e *env) send(v *votetest.Vote) featuretest.Result {
	e.t.Helper()
	return e.call("vote.proposal", e.svc.Msg(v, e.now))
}

func (e *env) rec(id string) *record { return e.f.st.Records[key("svc", id)] }

func (e *env) has(kind, ref string) bool {
	for _, a := range e.h.Activities {
		if a.Kind == kind && (ref == "" || a.Ref == ref) {
			return true
		}
	}
	return false
}

func (e *env) count(kind string) int {
	n := 0
	for _, a := range e.h.Activities {
		if a.Kind == kind {
			n++
		}
	}
	return n
}

func TestTypesAreServiceOnly(t *testing.T) {
	for _, ts := range New(Options{}).Types() {
		service := map[string]bool{"vote.proposal": true, "vote.extended": true, "vote.closed": true}[ts.Type]
		switch {
		case service && (ts.Connections != vault.PeersService || !ts.Request || !ts.Allows(vault.KindConnection) || ts.Allows(vault.KindApp)):
			t.Errorf("%s: %+v", ts.Type, ts)
		case !service && (!ts.Request || ts.Allows(vault.KindConnection) || ts.Allows(vault.KindDesktop) || ts.Allows(vault.KindAgent) || !ts.Allows(vault.KindApp)):
			t.Errorf("%s is not the app's alone: %+v", ts.Type, ts)
		}
	}
	e := newEnv(t)
	// A person connection is the gate's to answer; the feature refuses it too.
	c := e.h.Conns["svc"]
	c.PeerKind = ""
	e.h.Conns["svc"] = c
	v := e.svc.NewVote(e.spec(-time.Hour, time.Hour))
	if r := e.send(v); r.Code != "unsupported_type" {
		t.Errorf("person connection: %q", r.Code)
	}
}

func TestProposalKept(t *testing.T) {
	e := newEnv(t)
	if got := e.publish(e.svc); got != ListKept {
		t.Fatal(got)
	}
	v := e.svc.NewVote(e.spec(-time.Hour, time.Hour))
	r := e.send(v)
	if !r.OK() || r.Obj(t).Has("proposal_id") == false {
		t.Fatalf("%+v", r)
	}
	rec := e.rec(v.ID)
	if rec == nil || rec.state(e.now) != StateOpen || len(rec.VKSeed) != 32 || len(rec.VK) != 32 || rec.Reason != "" {
		t.Fatalf("%+v", rec)
	}
	if string(ed25519.NewKeyFromSeed(rec.VKSeed).Public().(ed25519.PublicKey)) != string(rec.VK) {
		t.Error("vk is not the public half of the seed")
	}
	if !e.has("vote.open", v.ID) || e.count("vote.open") != 1 {
		t.Errorf("feed %v", e.h.Activities)
	}
	if len(e.h.SentOfType("vote.event")) == 0 {
		t.Error("no vote.event")
	}
	for _, sent := range e.h.SentOfType("vote.event") {
		if sent.Opt.Kind != vault.KindApp {
			t.Errorf("vote.event not for the app only: %q", sent.Opt.Kind)
		}
	}
	// A re-send: ok, nothing changes (no new key, feed item or event).
	seed := string(rec.VKSeed)
	e.h.Reset()
	if r := e.send(v); !r.OK() {
		t.Fatalf("resend %+v", r)
	}
	if string(e.rec(v.ID).VKSeed) != seed || len(e.h.Activities) != 0 || len(e.h.Sent) != 0 {
		t.Errorf("a re-send changed something: %v %v", e.h.Activities, e.h.Sent)
	}
	// The state is vault state: it survives Save and Load.
	g := New(e.f.opt)
	featuretest.RoundTrip(t, e.f, g)
	if r := g.st.Records[key("svc", v.ID)]; r == nil || string(r.VKSeed) != seed || g.st.List == nil {
		t.Errorf("round trip %+v", r)
	}
	// The raw state holds no choice and never could: no ballot yet.
	raw, _ := e.f.Save()
	if strings.Contains(string(raw), `"choice_id"`) {
		t.Error("choice in state")
	}
}

func TestStatesByClock(t *testing.T) {
	e := newEnv(t)
	e.publish(e.svc)
	up := e.svc.NewVote(votetest.VoteSpec{ID: "01JBQZ000000000000000000B1", Opens: e.now.Add(time.Hour), Closes: e.now.Add(2 * time.Hour)})
	closed := e.svc.NewVote(votetest.VoteSpec{ID: "01JBQZ000000000000000000B2", Opens: e.now.Add(-2 * time.Hour), Closes: e.now.Add(-time.Hour)})
	for _, v := range []*votetest.Vote{up, closed} {
		if r := e.send(v); !r.OK() {
			t.Fatalf("%+v", r)
		}
	}
	if e.rec(up.ID).state(e.now) != StateUpcoming || !e.has("vote.open", up.ID) {
		t.Error("upcoming")
	}
	// A proposal already past its close is kept closed, with no feed item.
	if e.rec(closed.ID).state(e.now) != StateClosed || e.has("vote.open", closed.ID) {
		t.Error("closed")
	}
	if e.rec(up.ID).state(e.now.Add(90*time.Minute)) != StateOpen || e.rec(up.ID).state(e.now.Add(3*time.Hour)) != StateClosed {
		t.Error("the state follows the clock")
	}
}

func TestStep1Shape(t *testing.T) {
	e := newEnv(t)
	e.publish(e.svc)
	for name, body := range map[string]string{"not json": `x`, "empty": `{}`, "array": `[]`} {
		if r := e.call("vote.proposal", []byte(body)); r.Code != "bad_request" {
			t.Errorf("%s: %q", name, r.Code)
		}
	}
	if !e.has("drop.vote_malformed", "svc") || len(e.f.st.Records) != 0 {
		t.Errorf("%v", e.h.Activities)
	}
}

func TestStep2To4Rejections(t *testing.T) {
	e := newEnv(t)
	e.publish(e.svc)
	other := votetest.NewService(e.auth)
	cases := []struct {
		name   string
		id     string
		mutate func(m *votewire.ProposalMsg, v *votetest.Vote)
		build  func() *votetest.Vote
		reason string
		ref    string
	}{
		{name: "non-canonical document", id: "01JBQZ00000000000000000001", reason: "malformed",
			mutate: func(m *votewire.ProposalMsg, v *votetest.Vote) { m.Proposal = append([]byte{' '}, v.Doc...) }},
		{name: "another service key", id: "01JBQZ00000000000000000002", reason: "service",
			build: func() *votetest.Vote {
				return other.NewVote(votetest.VoteSpec{ID: "01JBQZ00000000000000000002", Opens: e.now.Add(-time.Hour), Closes: e.now.Add(time.Hour)})
			}},
		{name: "bad signature", id: "01JBQZ00000000000000000003", reason: "signature",
			mutate: func(m *votewire.ProposalMsg, v *votetest.Vote) { m.ProposalSig = make([]byte, 64) }},
		{name: "small-order service key", id: "01JBQZ00000000000000000004", reason: "service",
			build: func() *votetest.Vote {
				return e.svc.NewVote(votetest.VoteSpec{ID: "01JBQZ00000000000000000004", Opens: e.now.Add(-time.Hour), Closes: e.now.Add(time.Hour),
					Edit: func(p *votewire.Proposal) { p.Service = append([]byte{1}, make([]byte, 31)...) }})
			}},
		{name: "another secret", id: "01JBQZ00000000000000000005", reason: "record",
			mutate: func(m *votewire.ProposalMsg, v *votetest.Vote) { m.RecordSecret = make([]byte, 32) }},
		{name: "bad proof", id: "01JBQZ00000000000000000006", reason: "record",
			mutate: func(m *votewire.ProposalMsg, v *votetest.Vote) { m.RecordProof.TreeSize++ }},
		{name: "out of bounds", id: "01JBQZ00000000000000000007", reason: "malformed",
			build: func() *votetest.Vote {
				return e.svc.NewVote(votetest.VoteSpec{ID: "01JBQZ00000000000000000007", Opens: e.now.Add(-time.Hour), Closes: e.now.Add(time.Hour),
					Edit: func(p *votewire.Proposal) { p.Title = "" }})
			}},
	}
	for _, c := range cases {
		v := e.svc.NewVote(votetest.VoteSpec{ID: c.id, Opens: e.now.Add(-time.Hour), Closes: e.now.Add(time.Hour)})
		if c.build != nil {
			v = c.build()
		}
		msg, err := votewire.ParseProposalMsg(e.svc.Msg(v, e.now))
		if err != nil {
			t.Fatal(err)
		}
		if c.mutate != nil {
			c.mutate(msg, v)
		}
		e.h.Reset()
		r := e.call("vote.proposal", msg.Marshal())
		if r.Code != "bad_request" {
			t.Errorf("%s: %q", c.name, r.Code)
		}
		if !e.has("vote.proposal_rejected", c.id+":"+c.reason) {
			t.Errorf("%s: audit %v", c.name, e.h.Activities)
		}
		// It is kept as evidence, listed, with a feed item.
		rec := e.rec(c.id)
		if rec == nil || rec.state(e.now) != StateRejected || rec.RejectReason != c.reason || !e.has("vote.problem", c.id) {
			t.Errorf("%s: %+v", c.name, rec)
		}
		if rec != nil && !rec.problem() {
			t.Errorf("%s: not in the problem set", c.name)
		}
	}
	// A refused proposal without a valid id has no record: the ref is the
	// connection.
	e.h.Reset()
	msg, _ := votewire.ParseProposalMsg(e.svc.Msg(e.svc.NewVote(e.spec(-time.Hour, time.Hour)), e.now))
	msg.Proposal = []byte(`{"proposal_id":"nope"}`)
	if r := e.call("vote.proposal", msg.Marshal()); r.Code != "bad_request" || !e.has("vote.proposal_rejected", "svc:malformed") {
		t.Errorf("%q %v", r.Code, e.h.Activities)
	}
	// The same refused message again is refused again, not accepted.
	v := e.svc.NewVote(votetest.VoteSpec{ID: "01JBQZ00000000000000000008", Opens: e.now.Add(-time.Hour), Closes: e.now.Add(time.Hour)})
	m2, _ := votewire.ParseProposalMsg(e.svc.Msg(v, e.now))
	m2.ProposalSig = make([]byte, 64)
	e.call("vote.proposal", m2.Marshal())
	if r := e.call("vote.proposal", m2.Marshal()); r.Code != "bad_request" {
		t.Errorf("repeat of a rejected: %q", r.Code)
	}
}

func TestDuplicates(t *testing.T) {
	e := newEnv(t)
	e.publish(e.svc)
	v := e.svc.NewVote(e.spec(-time.Hour, time.Hour))
	e.send(v)
	// Another proposal under the same id: evidence, bad_request, the first
	// stays in use.
	v2 := e.svc.NewVote(votetest.VoteSpec{ID: v.ID, Opens: e.now.Add(-time.Hour), Closes: e.now.Add(3 * time.Hour)})
	e.h.Reset()
	if r := e.send(v2); r.Code != "bad_request" {
		t.Fatalf("%q", r.Code)
	}
	rec := e.rec(v.ID)
	if rec.Conflict == nil || string(rec.Conflict.Proposal) != string(v2.Doc) || string(rec.Proposal) != string(v.Doc) || !e.has("vote.proposal_conflict", v.ID) {
		t.Errorf("%+v %v", rec.Conflict, e.h.Activities)
	}
	// One copy only: a third does not replace it.
	v3 := e.svc.NewVote(votetest.VoteSpec{ID: v.ID, Opens: e.now.Add(-time.Hour), Closes: e.now.Add(4 * time.Hour)})
	e.send(v3)
	if string(e.rec(v.ID).Conflict.Proposal) != string(v2.Doc) {
		t.Error("the evidence copy was replaced")
	}
	// The same proposal with another secret is another proposal too.
	m, _ := votewire.ParseProposalMsg(e.svc.Msg(v, e.now))
	m.RecordSecret = make([]byte, 32)
	if r := e.call("vote.proposal", m.Marshal()); r.Code != "bad_request" {
		t.Errorf("other secret: %q", r.Code)
	}
	// Another connection's identical id is another record: a service
	// cannot squat on another's proposal ids.
	if len(e.f.st.Records) != 1 {
		t.Errorf("%d records", len(e.f.st.Records))
	}
}

func TestAnchorOutcomes(t *testing.T) {
	// No list at all: checking (service_list).
	e := newEnv(t)
	v := e.svc.NewVote(e.spec(-time.Hour, time.Hour))
	if r := e.send(v); !r.OK() {
		t.Fatal(r.Code)
	}
	rec := e.rec(v.ID)
	if rec.state(e.now) != StateChecking || rec.Reason != ReasonServiceList || e.has("vote.open", "") {
		t.Fatalf("%+v %v", rec, e.h.Activities)
	}
	// A list that does not name the service: still checking.
	stranger := votetest.NewService(e.auth)
	if e.publish(stranger) != ListKept || e.rec(v.ID).Reason != ReasonServiceList {
		t.Error("a list without the service")
	}
	// A merely re-confirmed list is no proof the key does not exist.
	doc := e.f.st.List.Doc
	if got := e.f.SyncServices(e.session(), doc, e.f.st.List.Sig); got != ListConfirmed || e.rec(v.ID).Reason != ReasonServiceList {
		t.Errorf("confirm: %s", got)
	}
	// The list that names it ends the state, and the feed item is made once.
	if e.publish(stranger, e.svc) != ListKept {
		t.Fatal("list not kept")
	}
	rec = e.rec(v.ID)
	if rec.state(e.now) != StateOpen || !e.has("vote.open", v.ID) || e.count("vote.open") != 1 {
		t.Fatalf("%+v %v", rec, e.h.Activities)
	}
	e.f.SyncServices(e.session(), e.f.st.List.Doc, e.f.st.List.Sig)
	if e.count("vote.open") != 1 {
		t.Error("vote.open made twice")
	}

	// Roots that do not verify the bundle (out of date): checking
	// (trust_root), then verified when the roots are right.
	e2 := newEnv(t)
	e2.f.opt.Roots = votetest.NewAuthority(e2.now).Roots
	e2.publish(e2.svc)
	v2 := e2.svc.NewVote(e2.spec(-time.Hour, time.Hour))
	if r := e2.send(v2); !r.OK() || e2.rec(v2.ID).Reason != ReasonTrustRoot {
		t.Fatalf("%q %+v", r.Code, e2.rec(v2.ID))
	}
	e2.f.opt.Roots = e2.auth.Roots
	e2.f.SyncServices(e2.session(), e2.f.st.List.Doc, e2.f.st.List.Sig)
	if e2.rec(v2.ID).Reason != "" || !e2.has("vote.open", v2.ID) {
		t.Errorf("after the roots: %+v", e2.rec(v2.ID))
	}

	// A bundle for another document under a key the list names: a
	// positive failure, rejected.
	e3 := newEnv(t)
	e3.publish(e3.svc)
	v3 := e3.svc.NewVote(e3.spec(-time.Hour, time.Hour))
	bad := e3.auth.Bundle([]byte(`{"another":"document"}`), e3.svc.Anchor, e3.now)
	if r := e3.call("vote.proposal", e3.svc.MsgWithBundle(v3, bad)); r.Code != "bad_request" || !e3.has("vote.proposal_rejected", v3.ID+":anchor") {
		t.Fatalf("%q %v", r.Code, e3.h.Activities)
	}
	if e3.rec(v3.ID).state(e3.now) != StateRejected || !e3.has("vote.problem", v3.ID) {
		t.Error("not rejected and listed")
	}
	// A timestamp after the relay's time of the message plus 5 minutes.
	v4 := e3.svc.NewVote(votetest.VoteSpec{ID: "01JBQZ00000000000000000009", Opens: e3.now.Add(-time.Hour), Closes: e3.now.Add(time.Hour)})
	late := e3.auth.Bundle(v4.Doc, e3.svc.Anchor, e3.now.Add(AnchorAhead+time.Minute))
	e3.now = e3.now.Add(AnchorAhead + 2*time.Minute) // so that the vault's clock is not behind the stamp
	e3.h.RelayAt = e3.now.Add(-AnchorAhead - 2*time.Minute)
	if r := e3.call("vote.proposal", e3.svc.MsgWithBundle(v4, late)); r.Code != "bad_request" || !e3.has("vote.proposal_rejected", v4.ID+":anchor") {
		t.Fatalf("late: %q %v", r.Code, e3.h.Activities)
	}
	// The same stamp within the 5 minutes is accepted.
	v5 := e3.svc.NewVote(votetest.VoteSpec{ID: "01JBQZ0000000000000000000B", Opens: e3.now.Add(-time.Hour), Closes: e3.now.Add(time.Hour)})
	ok := e3.auth.Bundle(v5.Doc, e3.svc.Anchor, e3.h.RelayAt.Add(AnchorAhead-time.Second))
	if r := e3.call("vote.proposal", e3.svc.MsgWithBundle(v5, ok)); !r.OK() {
		t.Errorf("within 5 minutes: %q", r.Code)
	}
}

// The anchor_cert must verify under an ik of the CONNECTION, not merely
// under the ik the list entry names (§10.19.4 step 6).
func TestAnchorCertMustBeTheConnectionsKey(t *testing.T) {
	e := newEnv(t)
	// A list whose entry names the connection's ik but certifies the anchor
	// key with another identity key it also lists.
	rogue := votetest.NewService(e.auth)
	l := &votewire.ServiceList{V: 1, Version: 1, Previous: make([]byte, 32), Services: []votewire.ServiceEntry{{
		ServiceID: serviceID(e.svc.Pub()), Name: "x", IKs: [][]byte{e.svc.Pub(), rogue.Pub()},
		AnchorKeys: []votewire.AnchorKey{{Key: e.svc.Anchor.SPKI, AnchorCert: e.svc.Anchor.Cert(rogue.IK), IK: rogue.Pub()}}}}}
	doc, _ := votewire.EncodeDocument(l)
	sig, _ := suite.Sign(e.site, votewire.LabelServiceList, votewire.H(doc))
	if e.f.SyncServices(e.session(), doc, sig) != ListKept {
		t.Fatal("list")
	}
	v := e.svc.NewVote(e.spec(-time.Hour, time.Hour))
	e.send(v)
	if e.rec(v.ID).Reason != ReasonServiceList {
		t.Errorf("an anchor key certified by a key that is not the connection's was accepted: %+v", e.rec(v.ID))
	}
	// An earlier key of the connection's rotation chain does count.
	e.h.PriorIKs = map[string][][]byte{"svc": {rogue.Pub()}}
	e.f.SyncServices(e.session(), doc, sig) // confirmed: re-checks
	if e.rec(v.ID).Reason != "" {
		t.Errorf("a key of the rotation chain: %+v", e.rec(v.ID))
	}
}

func serviceID(ik []byte) string { return hex.EncodeToString(votewire.H(ik)[:16]) }

func TestServiceListChaining(t *testing.T) {
	e := newEnv(t)
	if e.publish(e.svc) != ListKept {
		t.Fatal("first")
	}
	held := e.f.st.List
	// The same version again: confirmed, nothing else.
	if got := e.f.SyncServices(e.session(), held.Doc, held.Sig); got != ListConfirmed {
		t.Errorf("same: %s", got)
	}
	// A list not signed by the site key: rejected and audited.
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	doc, sig := votetest.List(other, 2, votewire.H(held.Doc), e.svc)
	if got := e.f.SyncServices(e.session(), doc, sig); got != ListRejected || !e.has("vote.list_rejected", "") {
		t.Errorf("foreign signature: %s", got)
	}
	// A newer list that does not chain: ignored and audited.
	e.h.Reset()
	doc, sig = votetest.List(e.site, 2, make([]byte, 32), e.svc)
	if got := e.f.SyncServices(e.session(), doc, sig); got != ListIgnored || !e.has("vote.list_rejected", "") {
		t.Errorf("no chain: %s", got)
	}
	// One that drops a service: ignored.
	doc, sig = votetest.List(e.site, 2, votewire.H(held.Doc))
	if got := e.f.SyncServices(e.session(), doc, sig); got != ListIgnored {
		t.Errorf("dropped: %s", got)
	}
	// An older copy is ignored quietly.
	e.h.Reset()
	d1, s1 := votetest.List(e.site, 3, votewire.H(held.Doc), e.svc)
	if e.f.SyncServices(e.session(), d1, s1) != ListKept {
		t.Fatal("v3 on v1 is a valid chain by hash? no: version may skip")
	}
	if got := e.f.SyncServices(e.session(), held.Doc, held.Sig); got != ListIgnored || e.has("vote.list_rejected", "") {
		t.Errorf("older: %s", got)
	}
	// Without a pinned site key nothing verifies.
	n := New(Options{})
	if got := n.SyncServices(e.session(), held.Doc, held.Sig); got != ListRejected {
		t.Errorf("no key: %s", got)
	}
	// 0.81.1: a vault with no list takes any that verifies and parses,
	// whatever its version or previous.
	m := New(e.f.opt)
	if got := m.SyncServices(e.session(), d1, s1); got != ListKept {
		t.Errorf("first list with a previous: %s", got)
	}
}

func TestExtensions(t *testing.T) {
	e := newEnv(t)
	e.publish(e.svc)
	closes := e.now.Add(time.Hour)
	v := e.svc.NewVote(votetest.VoteSpec{Opens: e.now.Add(-time.Hour), Closes: closes})
	e.send(v)
	// In order: the close moves, audited, an event, answered ok.
	doc1, msg1 := e.svc.Extension(v, 1, closes.Add(time.Hour), e.now)
	e.h.Reset()
	if r := e.call("vote.extended", msg1); !r.OK() {
		t.Fatalf("%q", r.Code)
	}
	if e.rec(v.ID).Closes != closes.Add(time.Hour).Unix() || !e.has("vote.extended", v.ID+":1") {
		t.Errorf("%+v %v", e.rec(v.ID), e.h.Activities)
	}
	// A repeat is ok and changes nothing.
	e.h.Reset()
	if r := e.call("vote.extended", msg1); !r.OK() || len(e.h.Activities) != 0 {
		t.Errorf("repeat %q %v", r.Code, e.h.Activities)
	}
	_ = doc1
	// n = 3 before 2: kept aside (one only), applied when 2 arrives.
	_, msg3 := e.svc.Extension(v, 3, closes.Add(3*time.Hour), e.now)
	_, msg2 := e.svc.Extension(v, 2, closes.Add(2*time.Hour), e.now)
	if r := e.call("vote.extended", msg3); !r.OK() || len(e.rec(v.ID).Exts) != 1 || e.rec(v.ID).Aside == nil {
		t.Fatalf("aside %q %+v", r.Code, e.rec(v.ID))
	}
	_, msg4 := e.svc.Extension(v, 4, closes.Add(4*time.Hour), e.now)
	if r := e.call("vote.extended", msg4); r.Code != "bad_request" {
		t.Errorf("second aside: %q", r.Code)
	}
	if r := e.call("vote.extended", msg2); !r.OK() || len(e.rec(v.ID).Exts) != 3 || e.rec(v.ID).Closes != closes.Add(3*time.Hour).Unix() {
		t.Fatalf("2 then 3: %q %+v", r.Code, e.rec(v.ID))
	}
	// Total over 24 h: refused, the old close stands.
	_, big := e.svc.Extension(v, 4, closes.Add(24*time.Hour+time.Second), e.now)
	if r := e.call("vote.extended", big); r.Code != "bad_request" || !e.has("vote.extension_rejected", v.ID+":total") {
		t.Errorf("total: %q %v", r.Code, e.h.Activities)
	}
	// Not above the close in force: order.
	_, back := e.svc.Extension(v, 4, closes, e.now)
	if r := e.call("vote.extended", back); r.Code != "bad_request" || !e.has("vote.extension_rejected", v.ID+":order") {
		t.Errorf("order: %q", r.Code)
	}
	// Unknown proposal, wrong signature, anchored after the close it
	// extends.
	e.h.Reset()
	other := e.svc.NewVote(votetest.VoteSpec{ID: "01JBQZ00000000000000000010", Opens: e.now.Add(-time.Hour), Closes: closes})
	_, om := e.svc.Extension(other, 1, closes.Add(time.Hour), e.now)
	if r := e.call("vote.extended", om); r.Code != "not_found" {
		t.Errorf("unknown: %q", r.Code)
	}
	m4, _ := votewire.ParseExtendedMsg(msg4)
	m4.ExtensionSig = make([]byte, 64)
	if r := e.call("vote.extended", m4.Marshal()); r.Code != "bad_request" || !e.has("vote.extension_rejected", v.ID+":signature") {
		t.Errorf("signature: %q", r.Code)
	}
	cur := time.Unix(e.rec(v.ID).Closes, 0)
	ed, _ := e.svc.Extension(v, 4, cur.Add(time.Hour), e.now)
	m := &votewire.ExtendedMsg{ProposalID: v.ID, Extension: ed, ExtensionSig: signExt(e.svc, v, ed),
		Bundle: e.auth.Bundle(ed, e.svc.Anchor, cur.Add(time.Minute))}
	e.now = cur.Add(2 * time.Minute) // the vault's clock is past the stamp
	if r := e.call("vote.extended", m.Marshal()); r.Code != "bad_request" || !e.has("vote.extension_rejected", v.ID+":late") {
		t.Errorf("late: %q %v", r.Code, e.h.Activities)
	}
}

func signExt(s *votetest.Service, v *votetest.Vote, doc []byte) []byte {
	msg, _ := votewire.DocSigMsg(v.Hash, doc)
	sig, _ := suite.Sign(s.IK, votewire.LabelExtended, msg)
	return sig
}

// A closed proposal is open again if its clock is still before the new
// time; the unsigned vote.closed never closes a vote.
func TestClosedAndReopened(t *testing.T) {
	e := newEnv(t)
	e.publish(e.svc)
	v := e.svc.NewVote(e.spec(-time.Hour, time.Hour))
	e.send(v)
	if r := e.call("vote.closed", []byte(`{"proposal_id":"01JBQZ00000000000000000099","results_hash":"`+e64(make([]byte, 32))+`"}`)); r.Code != "not_found" {
		t.Errorf("unknown: %q", r.Code)
	}
	body := []byte(`{"proposal_id":"` + v.ID + `","results_hash":"` + e64(make([]byte, 32)) + `"}`)
	if r := e.call("vote.closed", body); !r.OK() {
		t.Fatalf("%q", r.Code)
	}
	rec := e.rec(v.ID)
	if rec.state(e.now) != StateOpen {
		t.Error("vote.closed closed the vote")
	}
	// Before the close: the check is due at the close, not two hours after.
	if !rec.dueAt().Equal(time.Unix(rec.Closes, 0)) {
		t.Errorf("due %v, close %v", rec.dueAt(), time.Unix(rec.Closes, 0))
	}
	// Without vote.closed: two hours after the close in force.
	v2 := e.svc.NewVote(votetest.VoteSpec{ID: "01JBQZ00000000000000000011", Opens: e.now.Add(-time.Hour), Closes: e.now.Add(time.Hour)})
	e.send(v2)
	if got := e.rec(v2.ID).dueAt(); !got.Equal(time.Unix(e.rec(v2.ID).Closes, 0).Add(CheckDelay)) {
		t.Errorf("due %v", got)
	}
	// After the close: due at once (when it arrives).
	later := e.now.Add(3 * time.Hour)
	e.now = later
	body2 := []byte(`{"proposal_id":"` + v2.ID + `","results_hash":"` + e64(make([]byte, 32)) + `"}`)
	if r := e.call("vote.closed", body2); !r.OK() {
		t.Fatal(r.Code)
	}
	if !e.rec(v2.ID).dueAt().Equal(later) || !e.rec(v2.ID).checkPending(later) {
		t.Errorf("due %v", e.rec(v2.ID).dueAt())
	}
	// A reopened vote: closed, then extended past the clock.
	e.now = time.Unix(e.rec(v.ID).Closes, 0).Add(time.Minute)
	if e.rec(v.ID).state(e.now) != StateClosed {
		t.Fatal("not closed")
	}
	e.publish() // keep chain going (an empty list is fine)
}

func e64(b []byte) string {
	return strings.TrimSpace(string(mustJSON(b)))[1 : len(mustJSON(b))-1]
}

func mustJSON(b []byte) []byte { x, _ := json.Marshal(b); return x }

func TestSiteComparison(t *testing.T) {
	e := newEnv(t)
	e.publish(e.svc)
	v := e.svc.NewVote(e.spec(-time.Hour, time.Hour))
	e.send(v)
	check := func(d SiteDoc, site string, problem bool) {
		t.Helper()
		e.h.Reset()
		if err := e.f.SiteDocument(e.session(), "svc", v.ID, d); err != nil {
			t.Fatal(err)
		}
		if got := e.rec(v.ID).Site; got != site {
			t.Fatalf("site %q, want %q", got, site)
		}
		if e.has("vote.problem", v.ID) != problem {
			t.Fatalf("problem=%v: %v", !problem, e.h.Activities)
		}
	}
	check(SiteDoc{Status: StatusUnreachable}, SiteUnreachable, false)
	check(SiteDoc{Status: StatusFound, Proposal: v.Doc}, SiteMatches, false)
	// A 404 within ten minutes of arrival: not_listed, nothing raised.
	check(SiteDoc{Status: StatusAbsent}, SiteNotListed, false)
	// After ten minutes: raised once, and the member can still vote.
	e.now = e.now.Add(11 * time.Minute)
	check(SiteDoc{Status: StatusAbsent}, SiteNotListed, true)
	if !e.has("vote.proposal_conflict", v.ID+":not_listed") || e.rec(v.ID).problem() {
		t.Error("not_listed is a warning, not a problem record")
	}
	check(SiteDoc{Status: StatusAbsent}, SiteNotListed, false) // not raised twice
	// A mismatch: evidence, audit, feed; a problem record.
	// Garbage is not a split view: a document that is not a valid proposal
	// of this id signed by the service is as good as no answer.
	garbage := append([]byte{}, v.Doc...)
	garbage[len(garbage)-3] ^= 1
	check(SiteDoc{Status: StatusFound, Proposal: garbage, Sig: make([]byte, 64)}, SiteUnreachable, false)
	if e.rec(v.ID).SiteCopy != nil {
		t.Error("garbage kept as evidence of a mismatch")
	}
	// A valid proposal of the same id, signed by the service, with other
	// bytes: a mismatch.
	other := e.svc.NewVote(votetest.VoteSpec{ID: v.ID, Opens: e.now.Add(-time.Hour), Closes: e.now.Add(5 * time.Hour)})
	check(SiteDoc{Status: StatusFound, Proposal: other.Doc, Sig: other.Sig}, SiteMismatch, true)
	rec := e.rec(v.ID)
	if rec.SiteCopy == nil || !rec.problem() || !e.has("vote.proposal_conflict", v.ID+":mismatch") {
		t.Errorf("%+v", rec)
	}
	// Permanent: a later unreachable, 404 or matching answer resets nothing.
	e.h.Reset()
	for _, d := range []SiteDoc{{Status: StatusUnreachable}, {Status: StatusAbsent}, {Status: StatusFound, Proposal: v.Doc}} {
		if err := e.f.SiteDocument(e.session(), "svc", v.ID, d); err != nil {
			t.Fatal(err)
		}
		if e.rec(v.ID).Site != SiteMismatch || e.rec(v.ID).SiteAlert != "mismatch" || len(e.h.Activities) != 0 {
			t.Fatalf("mismatch reset by %+v: %q %v", d, e.rec(v.ID).Site, e.h.Activities)
		}
	}
	// After the close, one 404 is only not_listed; a second at least ten
	// minutes later, also after the close, is unpublished: a positive
	// problem. Both are timed on the vault's clock.
	e2 := newEnv(t)
	e2.publish(e2.svc)
	v2 := e2.svc.NewVote(e2.spec(-2*time.Hour, time.Hour))
	e2.send(v2)
	absent := func() {
		t.Helper()
		if err := e2.f.SiteDocument(e2.session(), "svc", v2.ID, SiteDoc{Status: StatusAbsent}); err != nil {
			t.Fatal(err)
		}
	}
	e2.now = e2.now.Add(2 * time.Hour)
	absent()
	if r := e2.rec(v2.ID); r.Site != SiteNotListed || r.problem() || r.AbsentMS == 0 || e2.has("vote.proposal_conflict", v2.ID+":unpublished") {
		t.Fatalf("one 404: %+v", r)
	}
	e2.now = e2.now.Add(9 * time.Minute) // too soon: does not count
	absent()
	if e2.rec(v2.ID).Site != SiteNotListed {
		t.Fatal("a second 404 within ten minutes")
	}
	// A found document in between clears the first.
	if err := e2.f.SiteDocument(e2.session(), "svc", v2.ID, SiteDoc{Status: StatusFound, Proposal: v2.Doc}); err != nil {
		t.Fatal(err)
	}
	if e2.rec(v2.ID).AbsentMS != 0 || e2.rec(v2.ID).Site != SiteMatches {
		t.Fatalf("found did not clear: %+v", e2.rec(v2.ID))
	}
	e2.now = e2.now.Add(11 * time.Minute)
	absent() // the first again
	if e2.rec(v2.ID).Site != SiteNotListed {
		t.Fatal("unpublished after a cleared first")
	}
	// Unreachable counts for nothing, and does not clear.
	e2.now = e2.now.Add(5 * time.Minute)
	_ = e2.f.SiteDocument(e2.session(), "svc", v2.ID, SiteDoc{Status: StatusUnreachable})
	e2.now = e2.now.Add(6 * time.Minute)
	absent() // 11 minutes after the first
	if r := e2.rec(v2.ID); r.Site != SiteUnpublished || !r.problem() || !e2.has("vote.proposal_conflict", v2.ID+":unpublished") {
		t.Errorf("second 404: %+v", r)
	}
	for _, d := range []SiteDoc{{Status: StatusUnreachable}, {Status: StatusFound, Proposal: v2.Doc}} {
		_ = e2.f.SiteDocument(e2.session(), "svc", v2.ID, d)
		if e2.rec(v2.ID).Site != SiteUnpublished {
			t.Errorf("unpublished reset by %+v", d)
		}
	}
	// Two 404s, the first before the close: only the one after counts.
	e3 := newEnv(t)
	e3.publish(e3.svc)
	v3 := e3.svc.NewVote(e3.spec(-time.Hour, time.Hour))
	e3.send(v3)
	_ = e3.f.SiteDocument(e3.session(), "svc", v3.ID, SiteDoc{Status: StatusAbsent})
	e3.now = e3.now.Add(time.Hour + time.Second)
	_ = e3.f.SiteDocument(e3.session(), "svc", v3.ID, SiteDoc{Status: StatusAbsent})
	if e3.rec(v3.ID).Site == SiteUnpublished || e3.rec(v3.ID).AbsentMS == 0 {
		t.Errorf("a 404 before the close counted: %+v", e3.rec(v3.ID))
	}
	if err := e2.f.SiteDocument(e2.session(), "svc", "01JBQZ00000000000000000077", SiteDoc{Status: StatusUnreachable}); err == nil {
		t.Error("unknown proposal")
	}
}
