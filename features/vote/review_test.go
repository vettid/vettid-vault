package vote

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/votetest"
	"github.com/vettid/vettid-vault/vms/suite"
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

// §10.19.4 step 5: a re-send of the same proposal is answered with nothing
// changed, whatever bundle it carries. A service cannot undo a refusal, turn
// a late stamp into an open vote, complete a `checking` record with an
// anchor made after delivery, or get around the caps; a `checking` record
// recovers only through recheck.
func TestResendChangesNothing(t *testing.T) {
	e := newEnv(t)
	e.publish(e.svc)
	snapshot := func(r *record) string { b, _ := json.Marshal(r); return string(b) }

	// A checking record (unrecognised bundle) re-sent with a valid bundle.
	v := e.svc.NewVote(e.spec(-time.Hour, time.Hour))
	bad := editBundle(t, e.auth.Bundle(v.Doc, e.svc.Anchor, e.now), func(m map[string]any) { m["mediaType"] = "x" })
	if r := e.call("vote.proposal", e.svc.MsgWithBundle(v, bad)); !r.OK() || e.rec(v.ID).Reason != ReasonTrustRoot {
		t.Fatalf("%q %+v", r.Code, e.rec(v.ID))
	}
	before := snapshot(e.rec(v.ID))
	e.h.Reset()
	if r := e.send(v); !r.OK() {
		t.Fatalf("resend: %q", r.Code)
	}
	if snapshot(e.rec(v.ID)) != before || len(e.h.Activities) != 0 || len(e.h.Sent) != 0 {
		t.Errorf("a re-send changed a checking record: %v %v", e.h.Activities, e.h.Sent)
	}
	// It recovers through recheck, from the bundle it holds: here it cannot
	// (the held bundle is the unrecognised one).
	e.f.Unlocked(e.session())
	if e.rec(v.ID).Reason != ReasonTrustRoot {
		t.Errorf("recheck of the held bundle: %+v", e.rec(v.ID))
	}

	// A record rejected for its anchor (a bundle for another document)
	// re-sent with the right bundle: still rejected, evidence kept, no key.
	w := e.svc.NewVote(votetest.VoteSpec{ID: lid(2), Opens: e.now.Add(-time.Hour), Closes: e.now.Add(time.Hour)})
	wrong := e.auth.Bundle([]byte(`{"x":1}`), e.svc.Anchor, e.now)
	if r := e.call("vote.proposal", e.svc.MsgWithBundle(w, wrong)); r.Code != "bad_request" || e.rec(w.ID).RejectReason != RejectAnchor {
		t.Fatalf("%q", r.Code)
	}
	before = snapshot(e.rec(w.ID))
	e.h.Reset()
	if r := e.send(w); r.Code != "bad_request" {
		t.Errorf("resend of a rejected: %q", r.Code)
	}
	rec := e.rec(w.ID)
	if snapshot(rec) != before || rec.RejectReason != RejectAnchor || len(rec.VK) != 0 || len(rec.VKSeed) != 0 || len(e.h.Sent) != 0 {
		t.Errorf("a re-send changed a rejected record: %+v", rec)
	}

	// A late stamp, re-sent later: not turned into an open vote.
	l := e.svc.NewVote(votetest.VoteSpec{ID: lid(3), Opens: e.now.Add(-time.Hour), Closes: e.now.Add(time.Hour)})
	e.h.RelayAt = e.now
	late := e.auth.Bundle(l.Doc, e.svc.Anchor, e.now.Add(AnchorAhead+time.Minute))
	e.now = e.now.Add(10 * time.Minute)
	if r := e.call("vote.proposal", e.svc.MsgWithBundle(l, late)); r.Code != "bad_request" || e.rec(l.ID).RejectReason != RejectAnchor {
		t.Fatalf("late: %q", r.Code)
	}
	e.h.RelayAt = e.now // the service re-sends later, when the stamp is within 5 minutes of the relay's time
	if r := e.call("vote.proposal", e.svc.MsgWithBundle(l, late)); r.Code != "bad_request" || e.rec(l.ID).RejectReason != RejectAnchor || e.rec(l.ID).state(e.now) != StateRejected {
		t.Errorf("a late stamp re-sent: %q %+v", r.Code, e.rec(l.ID))
	}

	// A verified record is untouched by another bundle too.
	u := e.svc.NewVote(votetest.VoteSpec{ID: lid(4), Opens: e.now.Add(-time.Hour), Closes: e.now.Add(time.Hour)})
	e.h.RelayAt = time.Time{}
	e.send(u)
	before = snapshot(e.rec(u.ID))
	e.h.Reset()
	if r := e.call("vote.proposal", e.svc.MsgWithBundle(u, bad)); !r.OK() || snapshot(e.rec(u.ID)) != before || len(e.h.Activities) != 0 {
		t.Errorf("verified record changed: %q", r.Code)
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
	// BALLOT-PROTOCOL 0.12.5: no limit on the number of services or keys.
	if parse(many(65)) != nil || parse(many(200)) != nil {
		t.Error("many services refused")
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
	if parse(keys(16, 16)) != nil || parse(keys(17, 1)) != nil || parse(keys(1, 17)) != nil || parse(keys(40, 40)) != nil {
		t.Error("many iks / anchor keys refused")
	}
	// anchor_cert is verified at parse.
	bad := entry(svc, "s")
	bad.AnchorKeys[0].AnchorCert = make([]byte, 64)
	if parse(&votewire.ServiceList{Services: []votewire.ServiceEntry{bad}}) == nil {
		t.Error("a bad anchor_cert accepted")
	}
	// A document over 4 MiB: refused on its size, before anything is parsed.
	if _, err := votewire.ParseServiceList(bytes.Repeat([]byte(" "), votewire.MaxServiceList+1)); err == nil {
		t.Error("over 4 MiB")
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
	for _, src := range []string{"", strings.Repeat("s", votewire.MaxExtensionSource+1)} {
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

// A list over the cap changes nothing (VAULT-MESSAGING 0.81.2): it is
// answered `ignored`, audited once per list as `vote.list_ignored`
// (`size:<hash>`), makes no feed item, and the vault keeps the last list
// it verified and goes on with its services. Other failures stay rejected.
func TestOversizeListKeepsTheHeldOne(t *testing.T) {
	e := newEnv(t)
	if e.publish(e.svc) != ListKept {
		t.Fatal("list")
	}
	held := string(e.f.st.List.Doc)
	big := func(version int) []byte {
		pad := bytes.Repeat([]byte("x"), votewire.MaxServiceList)
		return []byte(`{"v":1,"version":` + strconv.Itoa(version) + `,"pad":"` + string(pad) + `"}`)
	}
	e.h.Reset()
	for i := 0; i < 3; i++ {
		if got := e.f.SyncServices(e.session(), big(9), make([]byte, 64)); got != ListIgnored || string(e.f.st.List.Doc) != held {
			t.Fatalf("%s", got)
		}
	}
	if e.count("vote.list_ignored") != 1 || !e.has("vote.list_ignored", "size:"+hex.EncodeToString(votewire.H(big(9))[:8])) || e.count("vote.list_rejected") != 0 || e.count("vote.problem") != 0 {
		t.Errorf("one entry for the version, no feed item: %v", e.h.Activities)
	}
	// Another list within a day: the latest hash is kept, nothing more is
	// audited; a day later a changed hash is audited again.
	other := bytes.Repeat([]byte(" "), votewire.MaxServiceList+1)
	for i := 0; i < 2; i++ {
		if got := e.f.SyncServices(e.session(), other, nil); got != ListIgnored {
			t.Errorf("other: %s", got)
		}
	}
	if e.count("vote.list_ignored") != 1 || e.count("vote.list_rejected") != 0 || e.f.st.OversizeHash != hex.EncodeToString(votewire.H(other)[:8]) {
		t.Errorf("within a day: %v", e.h.Activities)
	}
	e.now = e.now.Add(25 * time.Hour)
	third := append(bytes.Repeat([]byte(" "), votewire.MaxServiceList), ' ', ' ')
	e.f.SyncServices(e.session(), third, nil)
	e.f.SyncServices(e.session(), third, nil)
	if e.count("vote.list_ignored") != 2 || !e.has("vote.list_ignored", "size:"+hex.EncodeToString(votewire.H(third)[:8])) {
		t.Errorf("a day later: %v", e.h.Activities)
	}
	// The held list still names the service: a proposal is verified by it.
	v := e.svc.NewVote(e.spec(-time.Hour, time.Hour))
	if r := e.send(v); !r.OK() || e.rec(v.ID).Reason != "" {
		t.Errorf("%q %+v", r.Code, e.rec(v.ID))
	}
}

// An `anchor` rejection is final: neither a recheck (list, unlock) nor the
// site's documents revive it.
func TestAnchorRejectionIsFinal(t *testing.T) {
	e := newEnv(t)
	e.publish(e.svc)
	v := e.svc.NewVote(e.spec(-time.Hour, time.Hour))
	wrong := e.auth.Bundle([]byte(`{"x":1}`), e.svc.Anchor, e.now)
	if r := e.call("vote.proposal", e.svc.MsgWithBundle(v, wrong)); r.Code != "bad_request" {
		t.Fatalf("%q", r.Code)
	}
	e.f.Unlocked(e.session())
	e.f.SyncServices(e.session(), e.f.st.List.Doc, e.f.st.List.Sig) // confirm
	if err := e.f.SiteDocument(e.session(), "svc", v.ID, SiteDoc{Status: StatusFound, Proposal: v.Doc, Sig: v.Sig, Bundle: e.auth.Bundle(v.Doc, e.svc.Anchor, e.now)}); err != nil {
		t.Fatal(err)
	}
	rec := e.rec(v.ID)
	if rec.RejectReason != RejectAnchor || rec.state(e.now) != StateRejected || len(rec.VK) != 0 {
		t.Errorf("revived: %+v", rec)
	}
}

func TestSyncBytesIsOneConstant(t *testing.T) {
	if votewire.MaxSyncBytes != 8257532 || votewire.MaxServiceList != 4<<20 {
		t.Errorf("%d %d", votewire.MaxSyncBytes, votewire.MaxServiceList)
	}
}

// A list near the 4 MiB cap (about 9,000 services with one anchor key each)
// is parsed once when it is kept, not at every check: a proposal's check
// and a recheck of 128 `checking` records find their keys in the held,
// indexed list, and Extends is linear.
func TestLargeServiceListIsParsedOnce(t *testing.T) {
	e := newEnv(t)
	auth := e.auth
	mk := func(version int64, previous []byte, n int, extra *votetest.Service) ([]byte, []byte) {
		l := &votewire.ServiceList{V: 1, Version: version, Previous: previous, Services: make([]votewire.ServiceEntry, 0, n+1)}
		for i := 0; i < n; i++ {
			_, ik, _ := ed25519.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{byte(i), byte(i >> 8), 7}, 32)))
			pub := ik.Public().(ed25519.PublicKey)
			spki := make([]byte, 91)
			copy(spki, auth.Roots[0].Logs[0].LogID) // any bytes: the cert is over H(key)
			spki[90] = byte(i)
			spki[89] = byte(i >> 8)
			cert := ed25519.Sign(ik, append([]byte(votewire.LabelAnchorKey), votewire.H(spki)...))
			l.Services = append(l.Services, votewire.ServiceEntry{ServiceID: serviceID(pub), Name: "Org", IKs: [][]byte{pub},
				AnchorKeys: []votewire.AnchorKey{{Key: spki, AnchorCert: cert, IK: pub}}})
		}
		if extra != nil {
			l.Services = append(l.Services, votewire.ServiceEntry{ServiceID: serviceID(extra.Pub()), Name: "Us", IKs: [][]byte{extra.Pub()},
				AnchorKeys: []votewire.AnchorKey{{Key: extra.Anchor.SPKI, AnchorCert: extra.Anchor.Cert(extra.IK), IK: extra.Pub()}}})
		}
		doc, err := votewire.EncodeDocument(l)
		if err != nil {
			t.Fatal(err)
		}
		sig, _ := suite.Sign(e.site, votewire.LabelServiceList, votewire.H(doc))
		return doc, sig
	}
	const n = 9000
	d1, s1 := mk(1, make([]byte, 32), n, e.svc)
	if len(d1) < 3<<20 || len(d1) > votewire.MaxServiceList {
		t.Fatalf("list of %d bytes", len(d1))
	}
	start := time.Now()
	if got := e.f.SyncServices(e.session(), d1, s1); got != ListKept {
		t.Fatalf("%s", got)
	}
	t.Logf("kept a list of %d bytes in %v", len(d1), time.Since(start))
	// A proposal is checked, and 128 checking records are rechecked: the
	// list is not parsed again for each.
	start = time.Now()
	v := e.svc.NewVote(votetest.VoteSpec{ID: lid(500), Opens: e.now.Add(-time.Hour), Closes: e.now.Add(time.Hour)})
	if r := e.send(v); !r.OK() || e.rec(v.ID).Reason != "" {
		t.Fatalf("%q %+v", r.Code, e.rec(v.ID))
	}
	for i := 0; i < 128; i++ {
		e.f.st.Records[key("svc", lid(i))] = &record{Conn: "svc", ID: lid(i), Reason: ReasonServiceList, ServiceIK: e.svc.Pub(), Signer: e.svc.Pub(),
			Proposal: []byte(`{}`), Opens: e.now.Unix() - 10, Closes: e.now.Unix() + 3600, KeptMS: 1}
	}
	e.f.recheck(e.session())
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("a proposal and a recheck of 128 records took %v", d)
	}
	// Extends is linear: the next version, all services again plus one.
	d2, s2 := mk(2, votewire.H(d1), n, e.svc)
	l1, err := votewire.ParseServiceList(d1)
	if err != nil {
		t.Fatal(err)
	}
	l2, err := votewire.ParseServiceList(d2)
	if err != nil {
		t.Fatal(err)
	}
	start = time.Now()
	for i := 0; i < 20; i++ {
		if !l1.Extends(d1, l2) {
			t.Fatal("does not extend")
		}
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("20 x Extends of %d services took %v", n, d)
	}
	_ = s2
}

func BenchmarkExtendsLargeList(b *testing.B) {
	const n = 9000
	l1 := &votewire.ServiceList{Services: make([]votewire.ServiceEntry, n)}
	l2 := &votewire.ServiceList{Version: 2, Services: make([]votewire.ServiceEntry, n)}
	for i := 0; i < n; i++ {
		id := strconv.Itoa(i)
		e := votewire.ServiceEntry{ServiceID: id, IKs: [][]byte{[]byte(id)}, AnchorKeys: []votewire.AnchorKey{{Key: []byte(id)}}}
		l1.Services[i], l2.Services[i] = e, e
	}
	data := []byte("held")
	l2.Previous = votewire.H(data)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !l1.Extends(data, l2) {
			b.Fatal("no")
		}
	}
}

// A list B within a day of list A is still audited, when the day has passed
// (0.81.3): the hash stays pending and Tick audits it.
func TestOversizePendingIsAuditedLater(t *testing.T) {
	e := newEnv(t)
	a := bytes.Repeat([]byte(" "), votewire.MaxServiceList+1)
	b := bytes.Repeat([]byte(" "), votewire.MaxServiceList+2)
	e.h.Reset()
	e.f.SyncServices(e.session(), a, nil)
	e.now = e.now.Add(time.Hour)
	e.f.SyncServices(e.session(), b, nil)
	if e.count("vote.list_ignored") != 1 {
		t.Fatalf("within the day: %v", e.h.Activities)
	}
	e.now = e.now.Add(2 * time.Hour)
	e.f.Tick(e.session())
	if e.count("vote.list_ignored") != 1 {
		t.Fatal("audited before the day passed")
	}
	e.now = e.now.Add(22 * time.Hour)
	e.f.Tick(e.session())
	if e.count("vote.list_ignored") != 2 || !e.has("vote.list_ignored", "size:"+hex.EncodeToString(votewire.H(b)[:8])) {
		t.Fatalf("pending not audited: %v", e.h.Activities)
	}
	e.f.Tick(e.session())
	if e.count("vote.list_ignored") != 2 {
		t.Error("audited twice")
	}
	// The same list A again after B: nothing pending when it is the one last audited.
	e.now = e.now.Add(25 * time.Hour)
	e.f.SyncServices(e.session(), b, nil)
	e.f.Tick(e.session())
	if e.count("vote.list_ignored") != 2 {
		t.Error("the audited hash audited again")
	}
}
