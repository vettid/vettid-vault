package vote

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/internal/votetest"
	"github.com/vettid/vettid-vault/vms/votewire"
)

// Shape checks are per item (VAULT-MESSAGING 0.81.5 §10.19.8): one bad item
// is refused or trimmed alone and the call succeeds.

func (c *cenv) syncResults(t *testing.T, key, body string) []string {
	t.Helper()
	r := c.app("vote.site.sync", body)
	if !r.OK() {
		t.Fatalf("call refused: %q", r.Code)
	}
	o := obj(t, r)
	arr, _ := o.Array(key)
	var out []string
	for _, raw := range arr {
		if key == "services" {
			s, _ := strictjson.AsString(raw)
			out = append(out, s)
			continue
		}
		eo, _ := strictjson.AsObject(raw)
		id, _ := eo.String("proposal_id")
		res, _ := eo.String("result")
		out = append(out, id[len(id)-1:]+":"+res)
	}
	return out
}

func (c *cenv) foundDoc(v *votetest.Vote, bundle, extra string) string {
	if bundle == "" {
		bundle = string(c.env.auth.Bundle(v.Doc, c.svc.Anchor, c.now))
	}
	return `{"status":"found","proposal":"` + b64(v.Doc) + `","proposal_sig":"` + b64(v.Sig) + `","bundle":` + bundle + extra + `}`
}

func (c *cenv) unheld(n int) *votetest.Vote {
	return c.svc.NewVote(votetest.VoteSpec{ID: lid(n), Opens: c.now.Add(-time.Hour), Closes: c.now.Add(time.Hour)})
}

func TestSyncBadListEndsCatchUp(t *testing.T) {
	c := newCastEnv(t)
	held := c.f.st.List
	l2 := c.nextList(held.Version+1, c.svc)
	d3, s3 := votetest.List(c.site, held.Version+2, votewire.H(l2.Doc), c.svc)
	l3 := ServiceListDoc{Doc: d3, Sig: s3}
	d4, s4 := votetest.List(c.site, held.Version+3, votewire.H(d3), c.svc)
	l4 := ServiceListDoc{Doc: d4, Sig: s4}
	good := c.unheld(5)
	entry := `{"proposal_id":"` + good.ID + `","document":` + c.foundDoc(good, "", "") + `}`

	// Bad signature length on version 3: v2 applies, v3 rejected, v4 not applied.
	bad := ServiceListDoc{Doc: l3.Doc, Sig: make([]byte, 63)}
	body := `{"services":[` + c.listJSON(l2) + `,` + c.listJSON(bad) + `,` + c.listJSON(l4) + `],"entries":[` + entry + `]}`
	if got := c.syncResults(t, "services", body); strings.Join(got, ",") != "kept,rejected,ignored" || c.f.st.List.Version != held.Version+1 {
		t.Errorf("bad sig: %v v%d", got, c.f.st.List.Version)
	}
	if !c.hasKind("vote.list_rejected") {
		t.Error("no vote.list_rejected for the bad list")
	}
	// The entry in the same call is still processed.
	c.h.Reset()
	good2 := c.unheld(6)
	body2 := `{"services":[` + c.listJSON(ServiceListDoc{Doc: l3.Doc, Sig: nil}) + `],"entries":[{"proposal_id":"` + good2.ID + `","document":` + c.foundDoc(good2, "", "") + `}]}`
	if got := c.syncResults(t, "entries", body2); got[0] != "6:kept" {
		t.Errorf("entry beside a bad list: %v", got)
	}
	// An empty doc on the first list: nothing applies, all answered.
	c2 := newCastEnv(t)
	l2b := c2.nextList(c2.f.st.List.Version+1, c2.svc)
	body = `{"services":[{"doc":"","sig":"` + b64(make([]byte, 64)) + `"},` + c2.listJSON(l2b) + `]}`
	if got := c2.syncResults(t, "services", body); strings.Join(got, ",") != "rejected,ignored" || c2.f.st.List.Version != l2b.versionOf(t)-1 {
		t.Errorf("empty doc: %v v%d", got, c2.f.st.List.Version)
	}
	if !c2.hasKind("vote.list_rejected") {
		t.Error("empty doc: no vote.list_rejected")
	}
	// Malformed base64 of a list member stays a call-level refusal.
	if r := c2.app("vote.site.sync", `{"services":[{"doc":"!!","sig":"`+b64(make([]byte, 64))+`"}]}`); r.Code != "bad_request" {
		t.Errorf("bad base64: %q", r.Code)
	}
}

func TestSyncBadProposalIsUnreachable(t *testing.T) {
	c := newCastEnv(t)
	v := c.open(1)
	good := c.unheld(5)
	huge := `{"status":"found","proposal":"` + b64(bytes.Repeat([]byte("a"), votewire.MaxProposal+1)) + `","proposal_sig":"` + b64(make([]byte, 64)) + `"}`
	c.h.Reset()
	got := c.syncResults(t, "entries", `{"entries":[{"proposal_id":"`+v.ID+`","document":`+huge+`},{"proposal_id":"`+lid(9)+`","document":`+huge+`},{"proposal_id":"`+good.ID+`","document":`+c.foundDoc(good, "", "")+`}]}`)
	// Held: judged as unreachable (known, no mismatch). Unheld: ignored.
	if strings.Join(got, ",") != "1:known,9:ignored,5:kept" {
		t.Errorf("%v", got)
	}
	if c.rec(v.ID).Site == SiteMismatch {
		t.Error("an oversized proposal made a mismatch")
	}
	// Exactly at the limit is not oversized.
	if r := c.app("vote.site.sync", `{"entries":[{"proposal_id":"`+lid(9)+`","document":{"status":"found","proposal":"`+b64(bytes.Repeat([]byte("a"), votewire.MaxProposal))+`"}}]}`); !r.OK() {
		t.Errorf("at the limit: %q", r.Code)
	}
}

func TestSyncBadBundleIgnored(t *testing.T) {
	c := newCastEnv(t)
	q1, q2, q3, good := c.unheld(1), c.unheld(2), c.unheld(3), c.unheld(4)
	big := `{"x":"` + strings.Repeat("a", votewire.MaxBundle) + `"}`
	e := func(v *votetest.Vote, bundle string) string {
		return `{"proposal_id":"` + v.ID + `","document":` + c.foundDoc(v, bundle, "") + `}`
	}
	c.h.Reset()
	got := c.syncResults(t, "entries", `{"entries":[`+e(q1, `"not an object"`)+`,`+e(q2, big)+`,`+e(q3, `[1]`)+`,`+e(good, "")+`]}`)
	if strings.Join(got, ",") != "1:kept,2:kept,3:kept,4:kept" {
		t.Errorf("%v", got)
	}
}

func TestSyncBadExtensionsTruncated(t *testing.T) {
	c := newCastEnv(t)
	v := c.open(1)
	junk := func(doc []byte, sig []byte, bundle string) string {
		return `{"extension":"` + b64(doc) + `","extension_sig":"` + b64(sig) + `","bundle":` + bundle + `}`
	}
	two := junk([]byte("{}"), make([]byte, 64), `{}`)
	prop := func(id string, exts ...string) string {
		return `{"status":"found","proposal":"` + b64(v.Doc) + `","proposal_sig":"` + b64(v.Sig) + `","extensions":[` + strings.Join(exts, ",") + `]}`
	}
	badKinds := map[string]string{
		"over 4096":      junk(bytes.Repeat([]byte("a"), votewire.MaxExtensionDoc+1), make([]byte, 64), `{}`),
		"short sig":      junk([]byte("{}"), make([]byte, 63), `{}`),
		"bundle string":  junk([]byte("{}"), make([]byte, 64), `"x"`),
		"bundle over":    junk([]byte("{}"), make([]byte, 64), `{"x":"`+strings.Repeat("a", votewire.MaxBundle)+`"}`),
		"bundle missing": `{"extension":"` + b64([]byte("{}")) + `","extension_sig":"` + b64(make([]byte, 64)) + `"}`,
	}
	for name, bad := range badKinds {
		c2 := newCastEnv(t)
		v2 := c2.open(1)
		cl := time.Unix(c2.rec(v2.ID).Closes, 0)
		d2, m2 := c2.svc.Extension(v2, 1, cl.Add(time.Hour), c2.now)
		mm, _ := votewire.ParseExtendedMsg(m2)
		e1 := `{"extension":"` + b64(d2) + `","extension_sig":"` + b64(mm.ExtensionSig) + `","bundle":` + string(mm.Bundle) + `}`
		good := c2.unheld(5)
		pd := func(exts ...string) string {
			return `{"status":"found","proposal":"` + b64(v2.Doc) + `","proposal_sig":"` + b64(v2.Sig) + `","extensions":[` + strings.Join(exts, ",") + `]}`
		}
		c2.h.Reset()
		// First extension good, then the bad one, then one more (dropped).
		got := c2.syncResults(t, "entries", `{"entries":[{"proposal_id":"`+v2.ID+`","document":`+pd(e1, bad, two)+`},{"proposal_id":"`+good.ID+`","document":`+c2.foundDoc(good, "", "")+`}]}`)
		if strings.Join(got, ",") != "1:known,5:kept" || len(c2.rec(v2.ID).Exts) != 1 || c2.rec(v2.ID).Closes != cl.Add(time.Hour).Unix() {
			t.Errorf("%s: %v %d", name, got, len(c2.rec(v2.ID).Exts))
		}
		// Nothing after the good one was processed (it would be rejected).
		for _, a := range c2.h.Activities {
			if a.Kind == "vote.extension_rejected" {
				t.Errorf("%s: a dropped extension was processed", name)
			}
		}
		// A bad first one: none are kept, the entry is still processed.
		c3 := newCastEnv(t)
		v3 := c3.open(1)
		g3 := c3.unheld(5)
		pd3 := `{"status":"found","proposal":"` + b64(v3.Doc) + `","proposal_sig":"` + b64(v3.Sig) + `","extensions":[` + bad + `]}`
		if got := c3.syncResults(t, "entries", `{"entries":[{"proposal_id":"`+v3.ID+`","document":`+pd3+`},{"proposal_id":"`+g3.ID+`","document":`+c3.foundDoc(g3, "", "")+`}]}`); strings.Join(got, ",") != "1:known,5:kept" || len(c3.rec(v3.ID).Exts) != 0 {
			t.Errorf("%s first: %v", name, got)
		}
	}
	_ = prop

	// More than 24: the first 24 are looked at, the rest dropped; the call succeeds.
	many := make([]string, votewire.MaxExtensions+1)
	for i := range many {
		many[i] = two
	}
	c.h.Reset()
	if r := c.app("vote.site.sync", `{"entries":[{"proposal_id":"`+v.ID+`","document":`+prop(v.ID, many...)+`}]}`); !r.OK() {
		t.Errorf("25 extensions: %q", r.Code)
	}
	if n := c.countKind("vote.extension_rejected"); n != votewire.MaxExtensions {
		t.Errorf("%d extensions processed, want %d", n, votewire.MaxExtensions)
	}
}

func TestSyncBadIndexDropped(t *testing.T) {
	c := newCastEnv(t)
	q1, q2, good := c.unheld(1), c.unheld(2), c.unheld(3)
	c.h.Reset()
	got := c.syncResults(t, "entries", `{"entries":[`+
		`{"proposal_id":"`+q1.ID+`","index":{"proposal_id":"`+q1.ID+`","service_id":5},"document":`+c.foundDoc(q1, "", "")+`},`+
		`{"proposal_id":"`+q2.ID+`","index":{"service_id":["x"]},"document":`+c.foundDoc(q2, "", "")+`},`+
		`{"proposal_id":"`+good.ID+`","index":{"service_id":"`+serviceID(c.svc.Pub())+`"},"document":`+c.foundDoc(good, "", "")+`}]}`)
	if strings.Join(got, ",") != "1:kept,2:kept,3:kept" {
		t.Errorf("%v", got)
	}
}

// The refusals that stay call-level.
func TestSyncCallLevelRefusalsStay(t *testing.T) {
	c := newCastEnv(t)
	v := c.open(1)
	doc := c.foundDoc(v, "", "")
	for name, body := range map[string]string{
		"not json":               `{"entries":`,
		"entries not an array":   `{"entries":5}`,
		"services not an array":  `{"services":{}}`,
		"entry not an object":    `{"entries":[5]}`,
		"no proposal_id":         `{"entries":[{"document":` + doc + `}]}`,
		"bad proposal_id":        `{"entries":[{"proposal_id":"x","document":` + doc + `}]}`,
		"no document":            `{"entries":[{"proposal_id":"` + v.ID + `"}]}`,
		"index not an object":    `{"entries":[{"proposal_id":"` + v.ID + `","index":5,"document":` + doc + `}]}`,
		"found without proposal": `{"entries":[{"proposal_id":"` + v.ID + `","document":{"status":"found"}}]}`,
		"confirm not an object":  `{"services_confirm":5}`,
		"list not an object":     `{"services":[5]}`,
		"list without sig":       `{"services":[{"doc":"` + b64([]byte("x")) + `"}]}`,
		// VAULT-MESSAGING 0.81.6: the strict parse refuses a duplicate member
		// name anywhere in the body, a proposal bundle included, so the whole
		// call fails; the app guards against sending one.
		"duplicate name in a bundle": `{"entries":[{"proposal_id":"` + v.ID + `","document":` + c.foundDoc(v, `{"a":1,"a":2}`, "") + `}]}`,
		"duplicate name":             `{"entries":[],"entries":[]}`,
		"over the body limit":        `{"entries":[],"pad":"` + strings.Repeat("a", votewire.MaxSyncBytes) + `"}`,
	} {
		if r := c.app("vote.site.sync", body); r.Code != "bad_request" {
			t.Errorf("%s: %q", name, r.Code)
		}
	}
}

func (c *cenv) countKind(kind string) int {
	n := 0
	for _, a := range c.h.Activities {
		if a.Kind == kind {
			n++
		}
	}
	return n
}

func (c *cenv) hasKind(kind string) bool { return c.countKind(kind) > 0 }

// A list over 4 MiB with a bad signature: the size rule comes first, so it
// is `ignored` with vote.list_ignored, not `rejected` (§10.19.4).
func TestSyncOversizeListWithBadSigIgnored(t *testing.T) {
	c := newCastEnv(t)
	held := c.f.st.List
	huge := ServiceListDoc{Doc: bytes.Repeat([]byte(" "), votewire.MaxServiceList+1), Sig: make([]byte, 7)}
	c.h.Reset()
	if got := c.syncResults(t, "services", `{"services":[`+c.listJSON(huge)+`]}`); strings.Join(got, ",") != "ignored" {
		t.Errorf("%v", got)
	}
	if !c.hasKind("vote.list_ignored") || c.hasKind("vote.list_rejected") || c.f.st.List.Version != held.Version {
		t.Errorf("audits: %v", c.h.Activities)
	}
	// The 1 MiB rule still covers a bad-shaped list beside another.
	big := ServiceListDoc{Doc: bytes.Repeat([]byte(" "), votewire.BigList+1), Sig: nil}
	l2 := c.nextList(held.Version+1, c.svc)
	if r := c.app("vote.site.sync", `{"services":[`+c.listJSON(l2)+`,`+c.listJSON(big)+`]}`); r.Code != "bad_request" {
		t.Errorf("1 MiB rule: %q", r.Code)
	}
}

// A held record in checking (site): a bad bundle leaves it there and records
// no evidence.
func TestSyncBadBundleLeavesCheckingSite(t *testing.T) {
	c := newCastEnv(t)
	v := c.checkingSite(1)
	c.h.Reset()
	got := c.syncResults(t, "entries", `{"entries":[{"proposal_id":"`+v.ID+`","document":`+c.foundDoc(v, `"not an object"`, "")+`}]}`)
	r := c.rec(v.ID)
	if got[0] != "1:known" || r.Reason != ReasonSite || r.RejectReason != "" || r.state(c.now) != StateChecking {
		t.Errorf("%v %+v", got, r)
	}
	if r.Conflict != nil || r.ConflictEv || len(r.EvidenceHash) != 0 || c.hasKind("vote.proposal_conflict") {
		t.Errorf("evidence recorded: %+v", r)
	}
}
