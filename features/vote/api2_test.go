package vote

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/featuretest"
	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/internal/votetest"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/votewire"
)

type fakeCred struct {
	gate error
	pin  string
}

func (c *fakeCred) HolderGate(*vault.Session, *envelope.Inner) error { return c.gate }
func (c *fakeCred) SpendPIN(*vault.Session, *envelope.Inner, string, []byte) ([]byte, error) {
	return []byte(c.pin), nil
}

func (c *cenv) releaseBody(conn, id string) string {
	return pairBody(conn, id, `"utk_id":"u1"`, `"sealed":"AAAA"`)
}

// A closed problem record: failed check.
func (c *cenv) problemRecord(n int) *votetest.Vote {
	v := c.svc.NewVote(votetest.VoteSpec{ID: lid(n), Opens: c.now.Add(-3 * time.Hour), Closes: c.now.Add(-2 * time.Hour)})
	c.send(v)
	c.rec(v.ID).Check = CheckFailed
	return v
}

func TestEvidenceAndRelease(t *testing.T) {
	c := newCastEnv(t)
	cred := &fakeCred{pin: "135792"}
	c.f.dep.Cred = cred
	v := c.problemRecord(1)
	other := c.problemRecord(2)
	_ = other
	// Not exported: evidence_not_exported.
	if r := c.app("vote.release", c.releaseBody("svc", v.ID)); r.Code != "evidence_not_exported" {
		t.Fatalf("%q", r.Code)
	}
	ev := obj(t, c.app("vote.evidence", pairBody("svc", v.ID)))
	eo, _ := ev.Object("evidence")
	if p, _ := eo.Base64("proposal", -1); !bytes.Equal(p, v.Doc) {
		t.Error("the proposal bytes are not as held")
	}
	for _, m := range []string{"proposal_sig", "ik", "record_tag", "proposal_hash", "extensions", "record_proof"} {
		if !eo.Has(m) {
			t.Errorf("no %s", m)
		}
	}
	// A change after the export: not exported any more.
	c.rec(v.ID).StatusAnswers = [][]byte{[]byte("an answer")}
	if r := c.app("vote.release", c.releaseBody("svc", v.ID)); r.Code != "evidence_not_exported" {
		t.Fatalf("after a change: %q", r.Code)
	}
	c.app("vote.evidence", pairBody("svc", v.ID))
	// A wrong PIN, then the right one.
	cred.pin = "000000"
	if r := c.app("vote.release", c.releaseBody("svc", v.ID)); r.Code != "bad_pin" {
		t.Errorf("%q", r.Code)
	}
	cred.pin = "135792"
	c.f.st.Problems["svc"] = true
	c.h.Reset()
	if r := c.app("vote.release", c.releaseBody("svc", v.ID)); !r.OK() || string(r.Body) != `{}` {
		t.Fatalf("%q", r.Code)
	}
	if c.rec(v.ID) != nil || len(c.f.st.Compact["svc"]) != 1 {
		t.Fatal("not released")
	}
	cr := c.f.st.Compact["svc"][0]
	if !cr.Released || !bytes.Equal(cr.Proposal, v.Doc) || len(cr.StatusAnswers) != 1 || cr.Outcome != "released:"+CheckFailed {
		t.Errorf("%+v", cr)
	}
	if !c.has("vote.released", v.ID) {
		t.Error("not audited")
	}
	for _, a := range c.h.Activities {
		if strings.Contains(a.Ref, "yes") {
			t.Error("choice")
		}
	}
	if c.f.st.Problems["svc"] {
		t.Error("the problem notice stayed with a record below the cap")
	}
	// The export of a released record is its compact record, with released: true.
	ev2 := obj(t, c.app("vote.evidence", pairBody("svc", v.ID)))
	e2, _ := ev2.Object("evidence")
	if rel, _ := e2.Bool("released"); !rel || !e2.Has("proposal") || !e2.Has("status_answers") {
		t.Errorf("released form: %s", ev2)
	}
	// Refusals: not a problem record, an open proposal, an unknown pair,
	// the holder gate, a missing connection_id.
	good := c.svc.NewVote(votetest.VoteSpec{ID: lid(3), Opens: c.now.Add(-3 * time.Hour), Closes: c.now.Add(-2 * time.Hour)})
	c.send(good)
	c.app("vote.evidence", pairBody("svc", good.ID))
	if r := c.app("vote.release", c.releaseBody("svc", good.ID)); r.Code != "bad_request" {
		t.Errorf("not a problem record: %q", r.Code)
	}
	open := c.open(4)
	c.rec(open.ID).RefusalProblem = true
	c.app("vote.evidence", pairBody("svc", open.ID))
	if r := c.app("vote.release", c.releaseBody("svc", open.ID)); r.Code != "bad_request" {
		t.Errorf("an open proposal: %q", r.Code)
	}
	if r := c.app("vote.release", c.releaseBody("svc", lid(77))); r.Code != "not_found" {
		t.Errorf("unknown: %q", r.Code)
	}
	if r := c.app("vote.release", pairBody("", lid(1), `"utk_id":"u1"`, `"sealed":"AAAA"`)); r.Code != "bad_request" {
		t.Errorf("no connection: %q", r.Code)
	}
	cred.gate = vault.NewError("credential_frozen", "")
	if r := c.app("vote.release", c.releaseBody("svc", other.ID)); r.Code != "credential_frozen" {
		t.Errorf("gate: %q", r.Code)
	}
	c.f.dep.Cred = nil
	if r := c.app("vote.release", c.releaseBody("svc", other.ID)); r.Code != "forbidden" {
		t.Errorf("no credential: %q", r.Code)
	}
}

// Rejected is a problem record; closed or rejected may be released, and its
// compact record holds the rejected proposal with its reason.
func TestReleaseRejected(t *testing.T) {
	c := newCastEnv(t)
	c.f.dep.Cred = &fakeCred{pin: "135792"}
	v := c.svc.NewVote(votetest.VoteSpec{ID: lid(1), Opens: c.now.Add(-time.Hour), Closes: c.now.Add(time.Hour)})
	m, _ := votewire.ParseProposalMsg(c.svc.Msg(v, c.now))
	m.ProposalSig = make([]byte, 64)
	c.call("vote.proposal", m.Marshal())
	if c.rec(v.ID).RejectReason != RejectSignature {
		t.Fatal("not rejected")
	}
	c.app("vote.evidence", pairBody("svc", v.ID))
	if r := c.app("vote.release", c.releaseBody("svc", v.ID)); !r.OK() {
		t.Fatalf("%q", r.Code)
	}
	cr := c.f.st.Compact["svc"][0]
	if cr.RejectReason != RejectSignature || !bytes.Equal(cr.Proposal, v.Doc) {
		t.Errorf("%+v", cr)
	}
	ev := obj(t, c.app("vote.evidence", pairBody("svc", v.ID)))
	e, _ := ev.Object("evidence")
	if why, _ := e.String("reason"); why != RejectSignature {
		t.Errorf("reason %q", why)
	}
}

func TestEvictedEvidence(t *testing.T) {
	c := newCastEnv(t)
	v := c.closedVote(1)
	c.rec(v.ID).Check = CheckVerified
	c.f.evict(c.rec(v.ID))
	ev := obj(t, c.app("vote.evidence", pairBody("svc", v.ID)))
	e, _ := ev.Object("evidence")
	if evd, _ := e.Bool("evicted"); !evd || !e.Has("proposal_hash") || !e.Has("record_tag") || !e.Has("ik") || e.Has("proposal") {
		t.Errorf("%v", ev)
	}
}

// --- vote.site.sync ---

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func (c *cenv) listJSON(l ServiceListDoc) string {
	return `{"doc":"` + b64(l.Doc) + `","sig":"` + b64(l.Sig) + `"}`
}

func (c *cenv) nextList(version int64, svcs ...*votetest.Service) ServiceListDoc {
	var prev []byte
	if c.f.st.List != nil {
		prev = votewire.H(c.f.st.List.Doc)
	}
	d, s := votetest.List(c.site, version, prev, svcs...)
	return ServiceListDoc{Doc: d, Sig: s}
}

func TestSyncServices(t *testing.T) {
	c := newCastEnv(t)
	held := c.f.st.List
	// Confirm: only if both equal the held list's.
	conf := func(version uint64, sum []byte) string {
		r := c.app("vote.site.sync", `{"services_confirm":{"version":`+itoa(version)+`,"sha256":"`+b64(sum)+`"}}`)
		o := obj(t, r)
		s, _ := o.String("services_confirm")
		return s
	}
	c.now = c.now.Add(time.Hour)
	if conf(uint64(held.Version), votewire.H(held.Doc)) != ListConfirmed || held.ConfirmedMS != c.now.UnixMilli() {
		t.Error("confirm")
	}
	if conf(uint64(held.Version)+1, votewire.H(held.Doc)) != ListIgnored || conf(uint64(held.Version), make([]byte, 32)) != ListIgnored {
		t.Error("a wrong version or hash confirmed")
	}
	// Lists in order, oldest first, stopping at the first failure.
	l2 := c.nextList(held.Version+1, c.svc)
	d3, s3 := votetest.List(c.site, held.Version+2, votewire.H(l2.Doc), c.svc)
	body := `{"services":[` + c.listJSON(l2) + `,` + c.listJSON(ServiceListDoc{Doc: d3, Sig: s3}) + `]}`
	o := obj(t, c.app("vote.site.sync", body))
	arr, _ := o.Array("services")
	var got []string
	for _, raw := range arr {
		s, _ := strictjson.AsString(raw)
		got = append(got, s)
	}
	if strings.Join(got, ",") != "kept,kept" || c.f.st.List.Version != held.Version+2 {
		t.Errorf("%v v%d", got, c.f.st.List.Version)
	}
	// Limits: 9 lists; two lists with one over 1 MiB.
	nine := make([]string, 9)
	for i := range nine {
		nine[i] = c.listJSON(l2)
	}
	if r := c.app("vote.site.sync", `{"services":[`+strings.Join(nine, ",")+`]}`); r.Code != "bad_request" {
		t.Errorf("nine lists: %q", r.Code)
	}
	big := ServiceListDoc{Doc: bytes.Repeat([]byte(" "), votewire.BigList+1), Sig: make([]byte, 64)}
	if r := c.app("vote.site.sync", `{"services":[`+c.listJSON(big)+`,`+c.listJSON(l2)+`]}`); r.Code != "bad_request" {
		t.Errorf("two lists, one over 1 MiB: %q", r.Code)
	}
	// One large list alone is accepted by the shape (the vault decides).
	if r := c.app("vote.site.sync", `{"services":[`+c.listJSON(big)+`]}`); !r.OK() {
		t.Errorf("one large list: %q", r.Code)
	}
	// Nine entries.
	es := make([]string, 9)
	for i := range es {
		es[i] = `{"proposal_id":"` + lid(i+1) + `","document":{"status":"unreachable"}}`
	}
	if r := c.app("vote.site.sync", `{"entries":[`+strings.Join(es, ",")+`]}`); r.Code != "bad_request" {
		t.Errorf("nine entries: %q", r.Code)
	}
}

func itoa(n uint64) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func TestSyncEntries(t *testing.T) {
	c := newCastEnv(t)
	v := c.open(1)
	found := func(v *votetest.Vote, extra string) string {
		return `{"status":"found","proposal":"` + b64(v.Doc) + `","proposal_sig":"` + b64(v.Sig) + `","bundle":` + string(c.env.auth.Bundle(v.Doc, c.svc.Anchor, c.now)) + extra + `}`
	}
	sync := func(entries ...string) []string {
		t.Helper()
		o := obj(t, c.app("vote.site.sync", `{"entries":[`+strings.Join(entries, ",")+`]}`))
		arr, _ := o.Array("entries")
		var out []string
		for _, raw := range arr {
			eo, _ := strictjson.AsObject(raw)
			id, _ := eo.String("proposal_id")
			res, _ := eo.String("result")
			out = append(out, id[len(id)-1:]+":"+res)
		}
		return out
	}
	idx := `"index":{"proposal_id":"` + v.ID + `","service_id":"` + serviceID(c.svc.Pub()) + `","proposal_hash":"` + b64(v.Hash) + `","opens_at":1,"closes_at":2,"extended":0,"published":true}`
	// A held proposal: known, and compared.
	got := sync(`{"proposal_id":"` + v.ID + `",` + idx + `,"document":` + found(v, "") + `}`)
	if got[0] != "1:known" || c.rec(v.ID).Site != SiteMatches {
		t.Errorf("%v %q", got, c.rec(v.ID).Site)
	}
	// The vault stamps `absent` with its own clock; two 404s 10 minutes apart
	// after the close make unpublished. An `at` from the app is bad_request.
	if r := c.app("vote.site.sync", `{"entries":[{"proposal_id":"`+v.ID+`","document":{"status":"absent","at":5}}]}`); r.Code != "bad_request" {
		t.Errorf("absent with a time: %q", r.Code)
	}
	if r := c.app("vote.site.sync", `{"entries":[{"proposal_id":"`+v.ID+`","document":{"status":"gone"}}]}`); r.Code != "bad_request" {
		t.Errorf("unknown status: %q", r.Code)
	}
	w := c.closedVote(2)
	abs := `{"proposal_id":"` + w.ID + `","document":{"status":"absent"}}`
	sync(abs)
	c.now = c.now.Add(9 * time.Minute)
	sync(abs)
	if c.rec(w.ID).Site == SiteUnpublished {
		t.Error("unpublished after 9 minutes")
	}
	c.now = c.now.Add(2 * time.Minute)
	sync(abs)
	if c.rec(w.ID).Site != SiteUnpublished {
		t.Errorf("not unpublished: %q", c.rec(w.ID).Site)
	}
	// unreachable never counts.
	x := c.closedVote(3)
	un := `{"proposal_id":"` + x.ID + `","document":{"status":"unreachable"}}`
	for i := 0; i < 3; i++ {
		c.now = c.now.Add(15 * time.Minute)
		sync(un)
	}
	if c.rec(x.ID).Site == SiteUnpublished {
		t.Error("unreachable counted")
	}
	// An unheld proposal on the index: the service is asked (kept); the same
	// again within the hour is ignored; a proposal matching no service
	// connection is ignored.
	q := c.svc.NewVote(votetest.VoteSpec{ID: lid(7), Opens: c.now.Add(-time.Hour), Closes: c.now.Add(time.Hour)})
	qidx := `"index":{"proposal_id":"` + q.ID + `","service_id":"` + serviceID(c.svc.Pub()) + `"}`
	c.h.Reset()
	got = sync(`{"proposal_id":"` + q.ID + `",` + qidx + `,"document":` + found(q, "") + `}`)
	if got[0] != "7:kept" || len(c.statuses()) != 1 {
		t.Errorf("%v %d", got, len(c.statuses()))
	}
	got = sync(`{"proposal_id":"` + q.ID + `",` + qidx + `,"document":` + found(q, "") + `}`)
	if got[0] != "7:ignored" {
		t.Errorf("again: %v", got)
	}
	stranger := votetest.NewService(c.env.auth)
	sq := stranger.NewVote(votetest.VoteSpec{ID: lid(8), Opens: c.now.Add(-time.Hour), Closes: c.now.Add(time.Hour)})
	sidx := `"index":{"proposal_id":"` + sq.ID + `","service_id":"` + serviceID(stranger.Pub()) + `"}`
	got = sync(`{"proposal_id":"` + sq.ID + `",` + sidx + `,"document":` + found(sq, "") + `}`)
	if got[0] != "8:ignored" {
		t.Errorf("stranger: %v", got)
	}
	// Without an index: the service that signed the proposal.
	q2 := c.svc.NewVote(votetest.VoteSpec{ID: lid(9), Opens: c.now.Add(-time.Hour), Closes: c.now.Add(time.Hour)})
	if got = sync(`{"proposal_id":"` + q2.ID + `","document":` + found(q2, "") + `}`); got[0] != "9:kept" {
		t.Errorf("no index: %v", got)
	}
	// A proposal absent at the site that the vault lacks: ignored.
	if got = sync(`{"proposal_id":"` + lid(10) + `","document":{"status":"absent"}}`); got[0] != "0:ignored" {
		t.Errorf("absent, unheld: %v", got)
	}
}

func TestSyncLearnsExtensions(t *testing.T) {
	c := newCastEnv(t)
	v := c.open(1)
	closes := time.Unix(c.rec(v.ID).Closes, 0)
	doc, msg := c.svc.Extension(v, 1, closes.Add(time.Hour), c.now)
	m, _ := votewire.ParseExtendedMsg(msg)
	ext := `{"extension":"` + b64(doc) + `","extension_sig":"` + b64(m.ExtensionSig) + `","bundle":` + string(m.Bundle) + `}`
	body := `{"entries":[{"proposal_id":"` + v.ID + `","document":{"status":"found","proposal":"` + b64(v.Doc) + `","proposal_sig":"` + b64(v.Sig) +
		`","bundle":` + string(c.env.auth.Bundle(v.Doc, c.svc.Anchor, c.now)) + `,"extensions":[` + ext + `]}}]}`
	obj(t, c.app("vote.site.sync", body))
	if len(c.rec(v.ID).Exts) != 1 || c.rec(v.ID).Closes != closes.Add(time.Hour).Unix() {
		t.Fatalf("%d extensions", len(c.rec(v.ID).Exts))
	}
	// Again: already held, nothing changes.
	obj(t, c.app("vote.site.sync", body))
	if len(c.rec(v.ID).Exts) != 1 {
		t.Error("held twice")
	}
	// A bad one is checked as vote.extended is: rejected, audited.
	bad := strings.Replace(ext, b64(m.ExtensionSig), b64(make([]byte, 64)), 1)
	bad = strings.Replace(bad, `"extension":"`+b64(doc), `"extension":"`+b64(doc), 1)
	c2 := newCastEnv(t)
	v2 := c2.open(1)
	d2, m2 := c2.svc.Extension(v2, 1, time.Unix(c2.rec(v2.ID).Closes, 0).Add(time.Hour), c2.now)
	mm, _ := votewire.ParseExtendedMsg(m2)
	badExt := `{"extension":"` + b64(d2) + `","extension_sig":"` + b64(make([]byte, 64)) + `","bundle":` + string(mm.Bundle) + `}`
	obj(t, c2.app("vote.site.sync", `{"entries":[{"proposal_id":"`+v2.ID+`","document":{"status":"found","proposal":"`+b64(v2.Doc)+`","proposal_sig":"`+b64(v2.Sig)+`","extensions":[`+badExt+`]}}]}`))
	if len(c2.rec(v2.ID).Exts) != 0 || !c2.has("vote.extension_rejected", v2.ID+":signature") {
		t.Errorf("%v", c2.h.Activities)
	}
	_ = bad
}

// --- the blob form ---

func (c *cenv) blobBody(plain []byte) (body string, id string, key, sum []byte) {
	data, k, s, err := envelope.SealBlob(plain)
	if err != nil {
		c.t.Fatal(err)
	}
	if c.h.Blobs == nil {
		c.h.Blobs = map[string][]byte{}
	}
	id = "01JB2Z6V9K3M4N5P6Q7R8S" + "0001"
	c.h.Blobs[id] = data
	body = `{"blob":{"id":"` + id + `","key":"` + b64(k) + `","sha256":"` + b64(s[:]) + `","size":` + itoa(uint64(len(plain))) + `}}`
	return body, id, k, s[:]
}

func TestSyncBlob(t *testing.T) {
	c := newCastEnv(t)
	c.h.BlobMax = 16 << 20
	l2 := c.nextList(c.f.st.List.Version+1, c.svc)
	plain := []byte(`{"services":[` + c.listJSON(l2) + `]}`)
	body, id, _, _ := c.blobBody(plain)
	r := c.app("vote.site.sync", body)
	if r.Code != "deferred" || len(c.h.BlobResults) != 1 || c.h.BlobResults[0].Code != "" {
		t.Fatalf("%q %+v", r.Code, c.h.BlobResults)
	}
	if c.f.st.List.Version != l2.versionOf(t) {
		t.Error("the list in the blob was not handled")
	}
	if _, left := c.h.Blobs[id]; left {
		t.Error("the blob was not deleted")
	}
	o, _ := strictjson.ParseObject(c.h.BlobResults[0].Body)
	if arr, _ := o.Array("services"); len(arr) != 1 {
		t.Error("answer")
	}
	// Failures: bad_request, and the blob is deleted.
	for name, mk := range map[string]func() string{
		"wrong sha256": func() string {
			b, _, _, s := c.blobBody(plain)
			return strings.Replace(b, b64(s), b64(make([]byte, 32)), 1)
		},
		"wrong size": func() string {
			b, _, _, _ := c.blobBody(plain)
			return strings.Replace(b, `"size":`+itoa(uint64(len(plain))), `"size":`+itoa(uint64(len(plain)+1)), 1)
		},
		"wrong key": func() string {
			b, _, k, _ := c.blobBody(plain)
			return strings.Replace(b, b64(k), b64(make([]byte, 32)), 1)
		},
		"unknown blob": func() string {
			b, _, _, _ := c.blobBody(plain)
			delete(c.h.Blobs, id)
			return b
		},
		"plaintext not a body": func() string {
			b, _, _, _ := c.blobBody([]byte(`not json`))
			return b
		},
		"plaintext over the limits": func() string {
			b, _, _, _ := c.blobBody([]byte(`{"entries":[` + strings.Repeat(`{"proposal_id":"`+lid(1)+`","document":{"status":"unreachable"}},`, 9) + `{"proposal_id":"` + lid(1) + `","document":{"status":"unreachable"}}]}`))
			return b
		},
	} {
		c.h.BlobResults = nil
		r := c.app("vote.site.sync", mk())
		if r.Code != "deferred" && r.Code != "bad_request" {
			t.Errorf("%s: %q", name, r.Code)
			continue
		}
		if r.Code == "deferred" && (len(c.h.BlobResults) != 1 || c.h.BlobResults[0].Code != "bad_request") {
			t.Errorf("%s: %+v", name, c.h.BlobResults)
		}
		if len(c.h.Blobs) != 0 {
			t.Errorf("%s: a blob is left", name)
		}
	}
	// Shape of the blob member; the relay's limits.
	b0, _, key0, _ := c.blobBody(plain)
	for name, b := range map[string]string{
		"with a mime":   strings.Replace(b0, `"size"`, `"mime":"x","size"`, 1),
		"with a name":   strings.Replace(b0, `"size"`, `"name":"x","size"`, 1),
		"with another":  strings.TrimSuffix(b0, "}") + `,"entries":[]}`,
		"short key":     strings.Replace(b0, b64(key0), b64(key0[:16]), 1),
		"bad blob id":   strings.Replace(b0, `"id":"01JB2Z6V9K3M4N5P6Q7R8S0001"`, `"id":"x"`, 1),
		"no size":       strings.Replace(b0, `"size"`, `"sizx"`, 1),
		"size zero":     strings.Replace(b0, `"size":`+itoa(uint64(len(plain))), `"size":0`, 1),
		"not an object": `{"blob":5}`,
	} {
		if r := c.app("vote.site.sync", b); r.Code != "bad_request" {
			t.Errorf("%s: %q", name, r.Code)
		}
	}
	// Over the limit, and on a relay without blobs: payload_too_large, the
	// held list kept.
	version := c.f.st.List.Version
	over := strings.Replace(b0, `"size":`+itoa(uint64(len(plain))), `"size":`+itoa(votewire.MaxSyncBytes+1), 1)
	if r := c.app("vote.site.sync", over); r.Code != "payload_too_large" {
		t.Errorf("over MaxSyncBytes: %q", r.Code)
	}
	c.h.BlobMax = 10
	if r := c.app("vote.site.sync", b0); r.Code != "payload_too_large" {
		t.Errorf("over the relay's limit: %q", r.Code)
	}
	c.h.BlobMax = 0
	if r := c.app("vote.site.sync", b0); r.Code != "payload_too_large" || c.f.st.List.Version != version {
		t.Errorf("no relay blobs: %q", r.Code)
	}
	var _ = errors.New
	var _ = sha256.Sum256
	var _ = featuretest.Call
}

func (l ServiceListDoc) versionOf(t *testing.T) int64 {
	p, err := votewire.ParseServiceList(l.Doc)
	if err != nil {
		t.Fatal(err)
	}
	return p.Version
}

// vote.closing (§10.19.7).
func TestClosingReminder(t *testing.T) {
	count := func(c *cenv) int { return c.count("vote.closing") }
	// A 7-day window: 24 hours before the close.
	c := newCastEnv(t)
	v := c.svc.NewVote(votetest.VoteSpec{ID: lid(1), Opens: c.now.Add(-time.Minute), Closes: c.now.Add(7*24*time.Hour - time.Minute)})
	c.send(v)
	c.f.Tick(c.session())
	if count(c) != 0 {
		t.Fatal("early")
	}
	c.now = time.Unix(c.rec(v.ID).Closes, 0).Add(-24*time.Hour - time.Minute)
	c.f.Tick(c.session())
	if count(c) != 0 {
		t.Fatal("before the moment")
	}
	c.tickAt(2 * time.Minute)
	if count(c) != 1 {
		t.Fatalf("at the moment: %d", count(c))
	}
	it := c.h.Activities[len(c.h.Activities)-1]
	if it.Kind != "vote.closing" || it.Ref != v.ID || it.ConnectionID != "svc" || !it.Feed || it.Priority != "" {
		t.Errorf("%+v", it)
	}
	c.tickAt(time.Minute)
	if count(c) != 1 {
		t.Error("twice")
	}
	// An extension makes no second one.
	_, msg := c.svc.Extension(v, 1, time.Unix(c.rec(v.ID).Closes, 0).Add(time.Hour), c.now)
	c.call("vote.extended", msg)
	c.tickAt(time.Hour)
	if count(c) != 1 {
		t.Error("a second after an extension")
	}
	// A window under 48 hours gets its half: 10 hours -> at 5 hours.
	c2 := newCastEnv(t)
	w := c2.svc.NewVote(votetest.VoteSpec{ID: lid(1), Opens: c2.now, Closes: c2.now.Add(10 * time.Hour)})
	c2.send(w)
	c2.now = c2.now.Add(4*time.Hour + 59*time.Minute)
	c2.f.Tick(c2.session())
	if count(c2) != 0 {
		t.Error("before half")
	}
	c2.tickAt(2 * time.Minute)
	if count(c2) != 1 {
		t.Error("at half")
	}
	// Kept after its moment: none.
	c3 := newCastEnv(t)
	k := c3.svc.NewVote(votetest.VoteSpec{ID: lid(1), Opens: c3.now.Add(-9 * time.Hour), Closes: c3.now.Add(time.Hour)})
	c3.send(k)
	c3.f.Tick(c3.session())
	c3.tickAt(5 * time.Minute)
	if count(c3) != 0 {
		t.Error("a proposal kept after its moment")
	}
	// Voted: none.
	c4 := newCastEnv(t)
	x := c4.svc.NewVote(votetest.VoteSpec{ID: lid(1), Opens: c4.now, Closes: c4.now.Add(10 * time.Hour)})
	c4.send(x)
	c4.cast(x, "yes")
	c4.now = c4.now.Add(6 * time.Hour)
	c4.f.Tick(c4.session())
	if count(c4) != 0 {
		t.Error("after a ballot")
	}
	// Locked at the moment: at the next unlock, if more than an hour remains.
	c5 := newCastEnv(t)
	y := c5.svc.NewVote(votetest.VoteSpec{ID: lid(1), Opens: c5.now, Closes: c5.now.Add(10 * time.Hour)})
	c5.send(y)
	c5.now = c5.now.Add(5*time.Hour + 30*time.Minute) // 4.5 h left
	c5.f.Tick(c5.session())
	if count(c5) != 1 {
		t.Error("not made at the next unlock with 4.5 hours left")
	}
	c6 := newCastEnv(t)
	z := c6.svc.NewVote(votetest.VoteSpec{ID: lid(1), Opens: c6.now, Closes: c6.now.Add(10 * time.Hour)})
	c6.send(z)
	c6.now = c6.now.Add(9*time.Hour + 30*time.Minute) // 30 minutes left
	c6.f.Tick(c6.session())
	if count(c6) != 0 {
		t.Error("made with less than an hour left")
	}
	// Checking: it is made when the vote becomes open.
	c7 := newCastEnv(t)
	q := c7.svc.NewVote(votetest.VoteSpec{ID: lid(1), Opens: c7.now, Closes: c7.now.Add(10 * time.Hour)})
	c7.send(q)
	c7.rec(q.ID).Reason = ReasonTrustRoot
	c7.now = c7.now.Add(6 * time.Hour)
	c7.f.Tick(c7.session())
	if count(c7) != 0 {
		t.Error("made for a vote being checked")
	}
}

// Conflict evidence: the audit entry and the feed item once per record, the
// first foreign ballot kept, the latest beside it.
func TestConflictOncePerRecord(t *testing.T) {
	c := newCastEnv(t)
	v := c.open(1)
	for i := 0; i < 3; i++ {
		c.f.Check(c.session(), "svc", v.ID)
		c.now = c.now.Add(11 * time.Minute)
	}
	ids := c.statuses()
	vks := make([][]byte, 0, 3)
	for i, id := range ids {
		_, vk, _ := ed25519.GenerateKey(rand.Reader)
		b := must(votewire.SignBallot(vk, v.Hash, v.Tag, []string{"no", "yes", "abstain"}[i]))
		vks = append(vks, b.VK)
		c.answer(v, id, b, uint64(c.now.UnixMilli()), true)
	}
	r := c.rec(v.ID)
	if c.count("vote.conflict") != 1 || c.count("vote.problem") != 1 {
		t.Errorf("audit %d feed %d", c.count("vote.conflict"), c.count("vote.problem"))
	}
	if r.Other == nil || !bytes.Equal(r.Other.VK, vks[0]) || r.OtherLatest == nil || !bytes.Equal(r.OtherLatest.VK, vks[2]) {
		t.Error("first and latest not kept")
	}
	// The verdict is one function.
	if st, why, ok := conflictVerdict(r); !ok || st != CheckFailed || why != "conflict" {
		t.Errorf("%s %s", st, why)
	}
}
