package vote

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/votetest"
	"github.com/vettid/vettid-vault/vms/votewire"
)

// editBundle changes a bundle's JSON.
func editBundle(t *testing.T, b []byte, f func(m map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	f(m)
	out, _ := json.Marshal(m)
	return out
}

func entryOf(m map[string]any) map[string]any {
	return m["verificationMaterial"].(map[string]any)["tlogEntries"].([]any)[0].(map[string]any)
}

// H1 (0.81.1): what the vault does not recognise is `checking`
// (trust_root), never `rejected`; only a contradiction of the document
// under an accepted key and the time rules reject.
func TestUnrecognisedBundleIsCheckingNotRejected(t *testing.T) {
	e := newEnv(t)
	e.publish(e.svc)
	cases := map[string]func(m map[string]any){
		"another media type": func(m map[string]any) { m["mediaType"] = "application/vnd.dev.sigstore.bundle.v0.4+json" },
		"two entries": func(m map[string]any) {
			vm := m["verificationMaterial"].(map[string]any)
			es := vm["tlogEntries"].([]any)
			vm["tlogEntries"] = append(es, es[0])
		},
		"no entry": func(m map[string]any) { m["verificationMaterial"].(map[string]any)["tlogEntries"] = []any{} },
		"no timestamp": func(m map[string]any) {
			m["verificationMaterial"].(map[string]any)["timestampVerificationData"] = map[string]any{"rfc3161Timestamps": []any{}}
		},
		"Rekor v2": func(m map[string]any) {
			entryOf(m)["kindVersion"] = map[string]any{"kind": "hashedrekord", "version": "0.0.2"}
		},
		"another kind": func(m map[string]any) {
			entryOf(m)["kindVersion"] = map[string]any{"kind": "intoto", "version": "0.0.1"}
		},
		"unparseable body": func(m map[string]any) {
			entryOf(m)["canonicalizedBody"] = base64.StdEncoding.EncodeToString([]byte("not json"))
		},
		"another digest algorithm": func(m map[string]any) {
			m["messageSignature"].(map[string]any)["messageDigest"].(map[string]any)["algorithm"] = "SHA2_512"
		},
	}
	i := 0
	for name, mut := range cases {
		i++
		v := e.svc.NewVote(votetest.VoteSpec{ID: lid(900 + i), Opens: e.now.Add(-time.Hour), Closes: e.now.Add(time.Hour)})
		b := editBundle(t, e.auth.Bundle(v.Doc, e.svc.Anchor, e.now), mut)
		if r := e.call("vote.proposal", e.svc.MsgWithBundle(v, b)); !r.OK() {
			t.Errorf("%s: %q, want ok", name, r.Code)
			continue
		}
		if rec := e.rec(v.ID); rec == nil || rec.state(e.now) != StateChecking || rec.Reason != ReasonTrustRoot {
			t.Errorf("%s: %+v", name, rec)
		}
	}
	// A PEM that is not a PUBLIC KEY, and a key that is not P-256: also
	// unrecognised.
	for name, body := range map[string]string{
		"pem type": `{"apiVersion":"0.0.1","kind":"hashedrekord","spec":{"data":{"hash":{"algorithm":"sha256","value":"` + strings.Repeat("00", 32) + `"}},"signature":{"content":"AA==","publicKey":{"content":"` +
			base64.StdEncoding.EncodeToString([]byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")) + `"}}}}`,
	} {
		v := e.svc.NewVote(votetest.VoteSpec{ID: lid(950), Opens: e.now.Add(-time.Hour), Closes: e.now.Add(time.Hour)})
		b := editBundle(t, e.auth.Bundle(v.Doc, e.svc.Anchor, e.now), func(m map[string]any) {
			entryOf(m)["canonicalizedBody"] = base64.StdEncoding.EncodeToString([]byte(body))
		})
		if r := e.call("vote.proposal", e.svc.MsgWithBundle(v, b)); !r.OK() || e.rec(v.ID).Reason != ReasonTrustRoot {
			t.Errorf("%s: %q %+v", name, r.Code, e.rec(v.ID))
		}
	}
	// What still rejects: a contradiction under the accepted key, and the
	// time rules.
	for name, tc := range map[string]struct{ log, stamp time.Duration }{
		"t_int - t_tsa = 601": {0, -601 * time.Second},
		"t_int - t_tsa = -61": {0, 61 * time.Second},
	} {
		v := e.svc.NewVote(votetest.VoteSpec{ID: lid(960 + len(name)), Opens: e.now.Add(-time.Hour), Closes: e.now.Add(time.Hour)})
		b := e.auth.BundleStamped(v.Doc, e.svc.Anchor, e.now.Add(tc.log), e.now.Add(tc.stamp))
		if r := e.call("vote.proposal", e.svc.MsgWithBundle(v, b)); r.Code != "bad_request" || e.rec(v.ID).RejectReason != RejectAnchor {
			t.Errorf("%s: %q", name, r.Code)
		}
	}
}

// L5: a re-send with a different bundle for a record in `checking` (or one
// refused for its anchor) is looked at again, not answered bad_request.
func TestResendWithAnotherBundle(t *testing.T) {
	e := newEnv(t)
	e.publish(e.svc)
	v := e.svc.NewVote(e.spec(-time.Hour, time.Hour))
	// First an unrecognised bundle: checking (trust_root).
	bad := editBundle(t, e.auth.Bundle(v.Doc, e.svc.Anchor, e.now), func(m map[string]any) { m["mediaType"] = "x" })
	if r := e.call("vote.proposal", e.svc.MsgWithBundle(v, bad)); !r.OK() || e.rec(v.ID).Reason != ReasonTrustRoot {
		t.Fatalf("%q %+v", r.Code, e.rec(v.ID))
	}
	e.h.Reset()
	if r := e.send(v); !r.OK() { // the same proposal with the good bundle
		t.Fatalf("resend: %q", r.Code)
	}
	if rec := e.rec(v.ID); rec.Reason != "" || rec.state(e.now) != StateOpen || !e.has("vote.open", v.ID) {
		t.Errorf("not completed: %+v %v", rec, e.h.Activities)
	}
	// A verified record is not touched by another bundle.
	e.h.Reset()
	if r := e.call("vote.proposal", e.svc.MsgWithBundle(v, bad)); !r.OK() || e.rec(v.ID).Reason != "" || len(e.h.Activities) != 0 {
		t.Errorf("verified record re-evaluated: %q %+v", r.Code, e.rec(v.ID))
	}

	// Rejected for its anchor (a bundle for another document), then the
	// right bundle.
	w := e.svc.NewVote(votetest.VoteSpec{ID: lid(2), Opens: e.now.Add(-time.Hour), Closes: e.now.Add(time.Hour)})
	wrong := e.auth.Bundle([]byte(`{"x":1}`), e.svc.Anchor, e.now)
	if r := e.call("vote.proposal", e.svc.MsgWithBundle(w, wrong)); r.Code != "bad_request" || e.rec(w.ID).RejectReason != RejectAnchor {
		t.Fatalf("%q", r.Code)
	}
	if r := e.call("vote.proposal", e.svc.MsgWithBundle(w, wrong)); r.Code != "bad_request" {
		t.Errorf("the same wrong bundle again: %q", r.Code)
	}
	if r := e.send(w); !r.OK() || e.rec(w.ID).RejectReason != "" || e.rec(w.ID).state(e.now) != StateOpen {
		t.Errorf("the right bundle: %q %+v", r.Code, e.rec(w.ID))
	}
	// A refusal that no bundle changes stays: a bad signature.
	x := e.svc.NewVote(votetest.VoteSpec{ID: lid(3), Opens: e.now.Add(-time.Hour), Closes: e.now.Add(time.Hour)})
	m, _ := votewire.ParseProposalMsg(e.svc.Msg(x, e.now))
	m.ProposalSig = make([]byte, 64)
	e.call("vote.proposal", m.Marshal())
	if r := e.call("vote.proposal", m.Marshal()); r.Code != "bad_request" || e.rec(x.ID).RejectReason != RejectSignature {
		t.Errorf("%q", r.Code)
	}
}

// 0.81.1 clock: max(t_tsa, t_int) > now + 300 s is `checking` (clock);
// the check is made again at unlock and at each sync.
func TestClockReasonAndUnlock(t *testing.T) {
	e := newEnv(t)
	e.publish(e.svc)
	v := e.svc.NewVote(e.spec(-time.Hour, time.Hour))
	// The vault's clock is 301 s behind the stamp (the relay time is known
	// and fine: t_tsa <= t_relay + 300).
	e.h.RelayAt = e.now
	stamp := e.now
	e.now = stamp.Add(-301 * time.Second)
	b := e.auth.Bundle(v.Doc, e.svc.Anchor, stamp)
	if r := e.call("vote.proposal", e.svc.MsgWithBundle(v, b)); !r.OK() {
		t.Fatalf("%q", r.Code)
	}
	rec := e.rec(v.ID)
	if rec.Reason != ReasonClock || rec.state(e.now) != StateChecking || e.has("vote.open", v.ID) {
		t.Fatalf("%+v", rec)
	}
	// Still behind: unlock changes nothing. Caught up: unlock completes it.
	e.f.Unlocked(e.session())
	if e.rec(v.ID).Reason != ReasonClock {
		t.Error("cleared too early")
	}
	e.now = stamp.Add(-299 * time.Second)
	e.f.Unlocked(e.session())
	if e.rec(v.ID).Reason != "" || !e.has("vote.open", v.ID) {
		t.Errorf("at unlock: %+v %v", e.rec(v.ID), e.h.Activities)
	}
}

// Without a relay time (no deposited_at) the relay rule is skipped, and
// the processing time is not used in its place.
func TestNoRelayTimeSkipsTheRelayRule(t *testing.T) {
	e := newEnv(t)
	e.publish(e.svc)
	v := e.svc.NewVote(e.spec(-time.Hour, time.Hour))
	// A stamp that a known relay time would call late.
	late := e.auth.Bundle(v.Doc, e.svc.Anchor, e.now.Add(4*time.Minute))
	if r := e.call("vote.proposal", e.svc.MsgWithBundle(v, late)); !r.OK() || e.rec(v.ID).RejectReason != "" || !e.rec(v.ID).NoRelay {
		t.Fatalf("%q %+v", r.Code, e.rec(v.ID))
	}
}

// M1: a malformed proposal's record has no close, and is not deleted at the
// next message; it is kept 365 days from when it was kept.
func TestMalformedRecordIsRetained(t *testing.T) {
	e := newEnv(t)
	e.publish(e.svc)
	v := e.svc.NewVote(votetest.VoteSpec{ID: lid(1), Opens: e.now.Add(-time.Hour), Closes: e.now.Add(time.Hour), Edit: func(p *votewire.Proposal) { p.Title = "" }})
	if r := e.send(v); r.Code != "bad_request" || e.rec(v.ID) == nil || e.rec(v.ID).Closes != 0 {
		t.Fatalf("%q %+v", r.Code, e.rec(v.ID))
	}
	// Any later message prunes: the record stays.
	e.call("vote.closed", []byte(`{"proposal_id":"`+lid(77)+`","results_hash":"`+e64(make([]byte, 32))+`"}`))
	if e.rec(v.ID) == nil {
		t.Fatal("deleted at the next message")
	}
	e.now = e.now.Add(364 * 24 * time.Hour)
	e.f.prune(e.session())
	if e.rec(v.ID) == nil {
		t.Fatal("deleted before 365 days")
	}
	e.now = e.now.Add(2 * 24 * time.Hour)
	e.f.prune(e.session())
	if e.rec(v.ID) != nil {
		t.Error("kept past 365 days")
	}
}

// M4: the service list's bounds, the first list, and catch-up.
func TestServiceListBoundsAndCatchUp(t *testing.T) {
	e := newEnv(t)
	// A first list takes any version, whatever its previous.
	doc, sig := votetest.List(e.site, 7, bytes.Repeat([]byte{9}, 32), e.svc)
	if got := e.f.SyncServices(e.session(), doc, sig); got != ListKept {
		t.Fatalf("first: %s", got)
	}
	// Catch-up: versions 8, 9, 10 in order are all kept; a gap stops.
	d8, s8 := votetest.List(e.site, 8, votewire.H(doc), e.svc)
	d9, s9 := votetest.List(e.site, 9, votewire.H(d8), e.svc)
	d10, s10 := votetest.List(e.site, 10, votewire.H(d9), e.svc)
	got := e.f.SyncCatchUp(e.session(), []ServiceListDoc{{d8, s8}, {d9, s9}, {d10, s10}})
	if strings.Join(got, ",") != "kept,kept,kept" || e.f.st.List.Version != 10 {
		t.Fatalf("%v v%d", got, e.f.st.List.Version)
	}
	// Starting past a gap: the first fails, the rest are not tried.
	d12, s12 := votetest.List(e.site, 12, votewire.H(d10), e.svc)
	d13, s13 := votetest.List(e.site, 13, votewire.H(d12), e.svc)
	d11, s11 := votetest.List(e.site, 11, votewire.H(d10), e.svc)
	got = e.f.SyncCatchUp(e.session(), []ServiceListDoc{{d13, s13}, {d11, s11}})
	if strings.Join(got, ",") != "ignored,ignored" || e.f.st.List.Version != 10 {
		t.Errorf("gap: %v v%d", got, e.f.st.List.Version)
	}
	// In order from the gap, stopping at the first failure.
	got = e.f.SyncCatchUp(e.session(), []ServiceListDoc{{d11, s11}, {d13, s13}, {d12, s12}})
	if strings.Join(got, ",") != "kept,ignored,ignored" || e.f.st.List.Version != 11 {
		t.Errorf("stop: %v v%d", got, e.f.st.List.Version)
	}
	// The renaming of a service is a valid chain.
	if _, err := votewire.ParseServiceList(d11); err != nil {
		t.Fatal(err)
	}
}

func TestServiceListBounds(t *testing.T) {
	_, site, _ := ed25519.GenerateKey(rand.Reader)
	auth := votetest.NewAuthority(time.Now())
	svc := votetest.NewService(auth)
	entry := func(s *votetest.Service, name string) votewire.ServiceEntry {
		return votewire.ServiceEntry{ServiceID: serviceID(s.Pub()), Name: name, IKs: [][]byte{s.Pub()},
			AnchorKeys: []votewire.AnchorKey{{Key: s.Anchor.SPKI, AnchorCert: s.Anchor.Cert(s.IK), IK: s.Pub()}}}
	}
	parse := func(l *votewire.ServiceList) error {
		l.V, l.Version, l.Previous = 1, 1, make([]byte, 32)
		b, err := votewire.EncodeDocument(l)
		if err != nil {
			t.Fatal(err)
		}
		_, err = votewire.ParseServiceList(b)
		return err
	}
	_ = site
	if err := parse(&votewire.ServiceList{Services: []votewire.ServiceEntry{entry(svc, "x")}}); err != nil {
		t.Fatalf("good: %v", err)
	}
	if err := parse(&votewire.ServiceList{Services: []votewire.ServiceEntry{entry(svc, strings.Repeat("n", 100))}}); err != nil {
		t.Errorf("name of 100: %v", err)
	}
	for name, l := range map[string]*votewire.ServiceList{
		"empty name":  {Services: []votewire.ServiceEntry{entry(svc, "")}},
		"name of 101": {Services: []votewire.ServiceEntry{entry(svc, strings.Repeat("n", 101))}},
		"no services": {},
	} {
		if parse(l) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	many := func(n int) *votewire.ServiceList {
		l := &votewire.ServiceList{Services: []votewire.ServiceEntry{}}
		for i := 0; i < n; i++ {
			l.Services = append(l.Services, entry(votetest.NewService(auth), "s"))
		}
		return l
	}
	if parse(many(64)) != nil {
		t.Error("64 services refused")
	}
	if parse(many(65)) == nil {
		t.Error("65 services accepted")
	}
	keys := func(nik, nak int) *votewire.ServiceList {
		s := votetest.NewService(auth)
		e := entry(s, "s")
		for i := 1; i < nik; i++ {
			e.IKs = append(e.IKs, votetest.NewService(auth).Pub())
		}
		e.AnchorKeys = nil
		for i := 0; i < nak; i++ {
			k := votetest.NewAnchorKey()
			e.AnchorKeys = append(e.AnchorKeys, votewire.AnchorKey{Key: k.SPKI, AnchorCert: k.Cert(s.IK), IK: s.Pub()})
		}
		if e.AnchorKeys == nil {
			e.AnchorKeys = []votewire.AnchorKey{}
		}
		return &votewire.ServiceList{Services: []votewire.ServiceEntry{e}}
	}
	if parse(keys(16, 16)) != nil || parse(keys(17, 1)) == nil || parse(keys(1, 17)) == nil {
		t.Error("16 iks / 16 anchor keys")
	}
	// anchor_cert is verified at parse.
	bad := entry(svc, "s")
	bad.AnchorKeys[0].AnchorCert = make([]byte, 64)
	if parse(&votewire.ServiceList{Services: []votewire.ServiceEntry{bad}}) == nil {
		t.Error("a bad anchor_cert accepted")
	}
	// A document over 256 KiB.
	if _, err := votewire.ParseServiceList(bytes.Repeat([]byte(" "), votewire.MaxServiceList+1)); err == nil {
		t.Error("over 256 KiB")
	}
}

// The 0.81.1 extension rules and their reasons.
func TestExtensionOutageRules(t *testing.T) {
	e := newEnv(t)
	e.publish(e.svc)
	closes := e.now.Add(2 * time.Hour)
	v := e.svc.NewVote(votetest.VoteSpec{Opens: e.now.Add(-time.Hour), Closes: closes})
	e.send(v)
	opens := v.Proposal.OpensAt
	try := func(n int64, newClose time.Time, from, to int64, wantOK bool, reason string) {
		t.Helper()
		e.h.Reset()
		_, msg := e.svc.ExtensionOutage(v, n, newClose, e.now, from, to)
		r := e.call("vote.extended", msg)
		if wantOK != r.OK() {
			t.Errorf("n=%d from=%d to=%d close=%v: %q", n, from, to, newClose.Sub(closes), r.Code)
			return
		}
		if !wantOK && !e.has("vote.extension_rejected", v.ID+":"+reason) {
			t.Errorf("n=%d: want %s, got %v", n, reason, e.h.Activities)
		}
	}
	cur := closes
	// An outage of exactly 3,600 s: order. From == to: order.
	try(1, cur.Add(time.Hour), opens, opens+3600, false, "order")
	try(1, cur.Add(time.Hour), opens, opens, false, "order")
	// From after to: malformed.
	try(1, cur.Add(time.Hour), opens+10, opens, false, "malformed")
	// 3,601 s: the new close up to the next whole hour (7,200 s) is allowed,
	// above it is not.
	try(1, cur.Add(7201*time.Second), opens, opens+3601, false, "order")
	try(1, cur.Add(7200*time.Second), opens, opens+3601, true, "")
	cur = cur.Add(7200 * time.Second)
	// From before opens_at, and from at or after the close in force: order.
	try(2, cur.Add(time.Hour), opens-1, opens+7200, false, "order")
	try(2, cur.Add(time.Hour), cur.Unix(), cur.Unix()+7200, false, "order")
	// The 24 h total is a separate rule.
	try(2, closes.Add(24*time.Hour+time.Second), opens, opens+3*86400, false, "total")
	// An empty source and a document over 4,096 bytes: malformed.
	e.h.Reset()
	for _, src := range []string{"", strings.Repeat("s", votewire.MaxExtensionDoc)} {
		ext := &votewire.Extension{V: 1, ProposalID: v.ID, N: 2, ClosesAt: cur.Add(time.Hour).Unix(), Outage: votewire.Outage{From: opens, To: opens + 7200, Source: src}}
		doc, _ := votewire.EncodeDocument(ext)
		m := &votewire.ExtendedMsg{ProposalID: v.ID, Extension: doc, ExtensionSig: signExt(e.svc, v, doc), Bundle: e.auth.Bundle(doc, e.svc.Anchor, e.now)}
		if r := e.call("vote.extended", m.Marshal()); r.Code != "bad_request" || !e.has("vote.extension_rejected", v.ID+":malformed") {
			t.Errorf("source %d bytes: %q %v", len(src), r.Code, e.h.Activities)
		}
		e.h.Reset()
	}
}

// The timestamp authority's certificate may have no other key usage, an
// unknown one included (L1).
func TestTimestampEKUOnlyTimeStamping(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	for name, extra := range map[string][]asn1.ObjectIdentifier{
		"also server auth": {{1, 3, 6, 1, 5, 5, 7, 3, 1}},
		"an unknown usage": {{1, 2, 3, 4, 5}},
	} {
		auth := votetest.NewAuthorityEKU(now, extra)
		svc := votetest.NewService(auth)
		b := auth.Bundle([]byte(`{"v":1}`), svc.Anchor, now)
		if _, err := votewire.VerifyBundle([]byte(`{"v":1}`), b, [][]byte{svc.Anchor.SPKI}, auth.Roots, now.Add(time.Minute), now); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
