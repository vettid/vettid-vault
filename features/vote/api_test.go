package vote

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/featuretest"
	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/internal/votetest"
	"github.com/vettid/vettid-vault/vms/votewire"
)

// app sends the owner app's request.
func (c *cenv) app(typ, body string) featuretest.Result {
	c.t.Helper()
	return featuretest.Call(c.f, c.h, c.now, "app", typ, body)
}

func pairBody(conn, id string, more ...string) string {
	b := `{"connection_id":"` + conn + `","proposal_id":"` + id + `"`
	for _, m := range more {
		b += "," + m
	}
	return b + "}"
}

func obj(t *testing.T, r featuretest.Result) strictjson.Object {
	t.Helper()
	if !r.OK() {
		t.Fatalf("error %q", r.Code)
	}
	return r.Obj(t)
}

func TestAPIIsTheAppsAlone(t *testing.T) {
	c := newCastEnv(t)
	for _, typ := range []string{"vote.list", "vote.get", "vote.cast", "vote.check", "vote.confirm", "vote.release", "vote.site.sync", "vote.results.submit", "vote.evidence"} {
		for _, kind := range []string{"desktop", "agent", "connection:svc"} {
			if r := featuretest.Call(c.f, c.h, c.now, kind, typ, `{}`); r.Code != "forbidden" {
				t.Errorf("%s from %s: %q", typ, kind, r.Code)
			}
		}
	}
}

func TestAPIPairErrors(t *testing.T) {
	c := newCastEnv(t)
	v := c.open(1)
	for _, typ := range []string{"vote.get", "vote.check", "vote.evidence"} {
		for name, body := range map[string]string{
			"no connection_id":    `{"proposal_id":"` + v.ID + `"}`,
			"empty connection_id": pairBody("", v.ID),
			"number":              `{"connection_id":5,"proposal_id":"` + v.ID + `"}`,
			"no proposal_id":      `{"connection_id":"svc"}`,
			"bad proposal_id":     pairBody("svc", "nope"),
			"not json":            `x`,
		} {
			if r := c.app(typ, body); r.Code != "bad_request" {
				t.Errorf("%s %s: %q", typ, name, r.Code)
			}
		}
		if r := c.app(typ, pairBody("other", v.ID)); r.Code != "not_found" {
			t.Errorf("%s unknown connection: %q", typ, r.Code)
		}
		if r := c.app(typ, pairBody("svc", lid(99))); r.Code != "not_found" {
			t.Errorf("%s unknown proposal: %q", typ, r.Code)
		}
	}
	if r := c.app("vote.cast", pairBody("svc", v.ID, `"choice_id":"Yes"`)); r.Code != "bad_request" {
		t.Errorf("cast bad choice: %q", r.Code)
	}
	if r := c.app("vote.confirm", pairBody("svc", v.ID)); r.Code != "bad_request" {
		t.Errorf("confirm without mine: %q", r.Code)
	}
	// Two services' records with the same proposal id are told apart.
	if r := c.app("vote.get", pairBody("svc", v.ID)); !r.OK() {
		t.Error(r.Code)
	}
}

func TestAPIListGetAndCast(t *testing.T) {
	c := newCastEnv(t)
	open := c.open(1)
	up := c.svc.NewVote(votetest.VoteSpec{ID: lid(2), Opens: c.now.Add(time.Hour), Closes: c.now.Add(5 * time.Hour)})
	c.send(up)
	closed := c.svc.NewVote(votetest.VoteSpec{ID: lid(3), Opens: c.now.Add(-5 * time.Hour), Closes: c.now.Add(-time.Hour)})
	c.send(closed)
	closed2 := c.svc.NewVote(votetest.VoteSpec{ID: lid(4), Opens: c.now.Add(-6 * time.Hour), Closes: c.now.Add(-2 * time.Hour)})
	c.send(closed2)
	w := c.svc.NewVote(votetest.VoteSpec{ID: lid(5), Opens: c.now.Add(-time.Hour), Closes: c.now.Add(4 * time.Hour)})
	c.send(w)
	c.rec(w.ID).Reason = ReasonTrustRoot // checking

	list := func(body string) strictjson.Object {
		t.Helper()
		return obj(t, c.app("vote.list", body))
	}
	ids := func(o strictjson.Object) (out []string) {
		arr, _ := o.Array("votes")
		for _, raw := range arr {
			vo, _ := strictjson.AsObject(raw)
			id, _ := vo.String("proposal_id")
			out = append(out, id[len(id)-1:])
		}
		return
	}
	// open, upcoming and checking first (by closes_at), then closed by
	// closes_at descending.
	all := list(`{}`)
	if got := strings.Join(ids(all), ","); got != "1,5,2,3,4" {
		t.Fatalf("order %s", got)
	}
	if got := strings.Join(ids(list(`{"state":"open"}`)), ","); got != "1,5,2" {
		t.Errorf("open %s", got)
	}
	if got := strings.Join(ids(list(`{"state":"closed"}`)), ","); got != "3,4" {
		t.Errorf("closed %s", got)
	}
	// Paging.
	p1 := list(`{"limit":2}`)
	next, _ := p1.String("next")
	if next == "" || strings.Join(ids(p1), ",") != "1,5" {
		t.Fatalf("page 1 %v %s", ids(p1), next)
	}
	p2 := list(`{"limit":2,"after":"` + next + `"}`)
	n2, _ := p2.String("next")
	if strings.Join(ids(p2), ",") != "2,3" || n2 == "" {
		t.Fatalf("page 2 %v", ids(p2))
	}
	p3 := list(`{"limit":2,"after":"` + n2 + `"}`)
	if strings.Join(ids(p3), ",") != "4" || p3.Has("next") {
		t.Fatalf("page 3 %v", ids(p3))
	}
	for _, bad := range []string{`{"limit":0}`, `{"limit":101}`, `{"state":"x"}`} {
		if r := c.app("vote.list", bad); r.Code != "bad_request" {
			t.Errorf("%s: %q", bad, r.Code)
		}
	}
	// list_version and list_sha256 of the held list.
	if v, _ := all.Uint("list_version", 0, 1000); v != uint64(c.f.st.List.Version) {
		t.Errorf("list_version %d", v)
	}
	if sum, _ := all.Base64("list_sha256", 32); !bytes.Equal(sum, votewire.H(c.f.st.List.Doc)) {
		t.Error("list_sha256")
	}
	// Summaries: states, reasons, can_cast.
	arr, _ := all.Array("votes")
	byID := map[string]strictjson.Object{}
	for _, raw := range arr {
		vo, _ := strictjson.AsObject(raw)
		id, _ := vo.String("proposal_id")
		byID[id] = vo
	}
	if st, _ := byID[w.ID].String("state"); st != "checking" {
		t.Error("checking")
	}
	if why, _ := byID[w.ID].String("reason"); why != ReasonTrustRoot {
		t.Errorf("reason %q", why)
	}
	cases := map[string]string{open.ID: "", up.ID: "not_open", closed.ID: "closed", w.ID: "checking"}
	for id, want := range cases {
		cc, _ := byID[id].Bool("can_cast")
		cannot, _, _ := byID[id].OptString("cannot_cast")
		if cannot != want || cc != (want == "") {
			t.Errorf("%s: can_cast=%v cannot_cast=%q want %q", id[len(id)-1:], cc, cannot, want)
		}
	}
	// can_cast agrees with Cast for the conditions it checks.
	c.auth.pins["svc"] = nil
	if o := obj(t, c.app("vote.get", pairBody("svc", open.ID))); func() bool { s, _, _ := o.OptString("cannot_cast"); return s != "not_signed_in" }() {
		t.Error("not_signed_in not reported")
	}
	c.auth.pins["svc"] = c.cred.Public().(ed25519.PublicKey)

	// vote.cast through the API, then the vote: choice_id only in vote.get.
	r := c.app("vote.cast", pairBody("svc", open.ID, `"choice_id":"yes"`))
	if !r.OK() || string(r.Body) != `{"proposal_id":"`+open.ID+`","ballot":{"state":"sending"}}` {
		t.Fatalf("%q %s", r.Code, r.Body)
	}
	if r := c.app("vote.cast", pairBody("svc", open.ID, `"choice_id":"no"`)); r.Code != "already_voted" {
		t.Errorf("%q", r.Code)
	}
	lst := c.app("vote.list", `{}`)
	if strings.Contains(string(lst.Body), `"choice_id"`) || strings.Contains(string(lst.Body), `"yes"`) {
		t.Errorf("the choice is in vote.list: %s", lst.Body)
	}
	g := obj(t, c.app("vote.get", pairBody("svc", open.ID)))
	if ch, _ := g.String("choice_id"); ch != "yes" {
		t.Errorf("choice_id %q", ch)
	}
	bo, _ := g.Object("ballot")
	if st, _ := bo.String("state"); st != BallotSending {
		t.Errorf("ballot %q", st)
	}
	if g0 := obj(t, c.app("vote.get", pairBody("svc", up.ID))); g0.Has("choice_id") || !g0.Has("text") || !g0.Has("choices") || !g0.Has("quorum") || !g0.Has("ik_fingerprint") || g0.Has("tally") {
		t.Error("vote members")
	}
	// vote.check: asks, then limited.
	if r := c.app("vote.check", pairBody("svc", open.ID)); !r.OK() || string(r.Body) != `{}` {
		t.Errorf("check %q", r.Code)
	}
	if r := c.app("vote.check", pairBody("svc", open.ID)); r.Code != "limit" {
		t.Errorf("check again: %q", r.Code)
	}
}

func TestAPIGetTallyOnlyFromVerifiedResults(t *testing.T) {
	c, v := closedWith(t, nil)
	g := obj(t, c.app("vote.get", pairBody("svc", v.ID)))
	if g.Has("tally") || g.Has("counts") {
		t.Error("tally before results")
	}
	out, _ := c.f.SubmitResults(c.session(), "svc", v.ID, c.resultsFor(v, resOpts{}))
	if out.State != CheckVerified {
		t.Fatal(out)
	}
	g = obj(t, c.app("vote.get", pairBody("svc", v.ID)))
	cn, _ := g.Object("counts")
	if e, _ := cn.Uint("eligible", 0, 100); e != 3 || !g.Has("tally") {
		t.Errorf("%s", g)
	}
	ck, _ := g.Object("check")
	if st, _ := ck.String("state"); st != CheckVerified {
		t.Errorf("check %q", st)
	}
}

func TestAPIResultsSubmit(t *testing.T) {
	c, v := closedWith(t, nil)
	in := c.resultsFor(v, resOpts{})
	body := strictjson.NewBuilder().String("connection_id", "svc").String("proposal_id", v.ID).Base64("results", in.Results).
		Base64("results_sig", in.Sig).Raw("bundle", in.Bundle).Raw("row", []byte(`{"ballot":null}`)).Raw("row_proof", in.Proof.JSON()).Bytes()
	r := c.app("vote.results.submit", string(body))
	o := obj(t, r)
	ck, _ := o.Object("check")
	if st, _ := ck.String("state"); st != CheckVerified {
		t.Fatalf("%s", r.Body)
	}
	if id, _ := o.String("proposal_id"); id != v.ID {
		t.Error("proposal_id")
	}
	// A repeat for a final check is answered with the state.
	if o := obj(t, c.app("vote.results.submit", string(body))); func() bool { ck, _ := o.Object("check"); st, _ := ck.String("state"); return st != CheckVerified }() {
		t.Error("repeat")
	}
	// Shapes.
	for name, b := range map[string]string{
		"no row":      strings.Replace(string(body), `"row":{"ballot":null},`, ``, 1),
		"row members": strings.Replace(string(body), `{"ballot":null}`, `{"ballot":null,"x":1}`, 1),
		"no bundle":   strings.Replace(string(body), `"bundle"`, `"bundlf"`, 1),
	} {
		if r := c.app("vote.results.submit", b); r.Code != "bad_request" {
			t.Errorf("%s: %q", name, r.Code)
		}
	}
}

func TestAPIConfirm(t *testing.T) {
	c := newCastEnv(t)
	v := c.open(1)
	c.rec(v.ID).Restore = true
	c.f.Tick(c.session())
	own := ed25519.NewKeyFromSeed(c.rec(v.ID).VKSeed)
	c.answer(v, c.statuses()[0], must(votewire.SignBallot(own, v.Hash, v.Tag, "no")), uint64(c.now.UnixMilli()), true)
	r := c.app("vote.confirm", pairBody("svc", v.ID, `"mine":true`))
	if !r.OK() || string(r.Body) != `{"ballot":{"state":"recorded"}}` {
		t.Errorf("%q %s", r.Code, r.Body)
	}
}

// Dropped proposals and the problem cap are noticed in vote.list; the
// reconnect notice names a person connection that is a listed service.
func TestAPINotices(t *testing.T) {
	c := newCastEnv(t)
	for i := 1; i <= votewire.MaxOpenPerConnection; i++ {
		c.open(i)
	}
	c.send(c.svc.NewVote(votetest.VoteSpec{ID: lid(99), Opens: c.now.Add(-time.Hour), Closes: c.now.Add(2 * time.Hour)})) // dropped for the cap
	o := obj(t, c.app("vote.list", `{"limit":1}`))
	dr, _ := o.Array("dropped")
	if len(dr) != 1 {
		t.Fatalf("dropped %d", len(dr))
	}
	do, _ := strictjson.AsObject(dr[0])
	if cid, _ := do.String("connection_id"); cid != "svc" {
		t.Error("dropped connection")
	}
	if n, _ := do.Uint("count", 0, 100); n != 1 {
		t.Errorf("count %d", n)
	}
	// Only an acknowledgement removes it (0.81.3): the next list returns it
	// again; an unknown connection and another are ignored; bad members are
	// bad_request.
	for _, body := range []string{`{"limit":1}`, `{"ack_dropped":["other"]}`, `{"ack_dropped":[]}`} {
		o = obj(t, c.app("vote.list", body))
		if dr, _ := o.Array("dropped"); len(dr) != 1 {
			t.Errorf("%s: the notice went without an acknowledgement", body)
		}
	}
	for _, bad := range []string{`{"ack_dropped":"svc"}`, `{"ack_dropped":[1]}`, `{"ack_dropped":{}}`} {
		if r := c.app("vote.list", bad); r.Code != "bad_request" {
			t.Errorf("%s: %q", bad, r.Code)
		}
	}
	o = obj(t, c.app("vote.list", `{"ack_dropped":["svc"]}`))
	if dr, _ := o.Array("dropped"); len(dr) != 0 {
		t.Error("dropped notice stayed after the acknowledgement")
	}
	o = obj(t, c.app("vote.list", `{}`))
	if dr, _ := o.Array("dropped"); len(dr) != 0 {
		t.Error("dropped notice came back")
	}
	// The problem cap: an entry until a record is released.
	c.f.st.Problems["svc"] = true
	o = obj(t, c.app("vote.list", `{}`))
	if pr, _ := o.Array("problems"); len(pr) != 1 {
		t.Error("problems")
	}
	// reconnect: a person connection with the key of a listed service.
	c.h.AddConnection("person")
	pc := c.h.Conns["person"]
	pc.IK = c.svc.Pub()
	c.h.Conns["person"] = pc
	o = obj(t, c.app("vote.list", `{}`))
	rc, _ := o.Array("reconnect")
	if len(rc) != 1 {
		t.Fatalf("reconnect %d", len(rc))
	}
	ro, _ := strictjson.AsObject(rc[0])
	if cid, _ := ro.String("connection_id"); cid != "person" {
		t.Error("reconnect connection")
	}
	if sid, _ := ro.String("service_id"); sid != serviceID(c.svc.Pub()) {
		t.Error("service_id")
	}
	// Nothing is listed before a list is held.
	c2 := newEnv(t)
	c2.h.AddConnection("person")
	pc = c2.h.Conns["person"]
	pc.IK = c2.svc.Pub()
	c2.h.Conns["person"] = pc
	o2 := obj(t, featuretest.Call(c2.f, c2.h, c2.now, "app", "vote.list", `{}`))
	if rc, _ := o2.Array("reconnect"); len(rc) != 0 {
		t.Error("reconnect without a list")
	}
	if o2.Has("list_version") {
		t.Error("list_version without a list")
	}
}
