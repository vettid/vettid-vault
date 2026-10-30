package votewire

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
)

// The small-order table of Verify is complete and correct: its points, with
// either sign of x, are eight distinct points and each is killed by 8.
func TestSmallOrderTable(t *testing.T) {
	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	inv := func(a *big.Int) *big.Int { return new(big.Int).ModInverse(a, p) }
	mod := func(a *big.Int) *big.Int { return a.Mod(a, p) }
	d := mod(new(big.Int).Mul(new(big.Int).Neg(big.NewInt(121665)), inv(big.NewInt(121666))))
	type pt struct{ x, y *big.Int }
	add := func(a, b pt) pt {
		xx := mod(new(big.Int).Mul(a.x, b.x))
		yy := mod(new(big.Int).Mul(a.y, b.y))
		dxy := mod(new(big.Int).Mul(d, mod(new(big.Int).Mul(xx, yy))))
		x3 := mod(new(big.Int).Mul(mod(new(big.Int).Add(mod(new(big.Int).Mul(a.x, b.y)), mod(new(big.Int).Mul(b.x, a.y)))),
			inv(mod(new(big.Int).Add(big.NewInt(1), dxy)))))
		y3 := mod(new(big.Int).Mul(mod(new(big.Int).Add(yy, xx)), inv(mod(new(big.Int).Sub(big.NewInt(1), dxy)))))
		return pt{x3, y3}
	}
	seen := map[string]bool{}
	for _, yle := range smallOrderY {
		be := make([]byte, 32)
		for i := range yle {
			be[31-i] = yle[i]
		}
		y := new(big.Int).SetBytes(be)
		// x^2 = (y^2 - 1) / (d y^2 + 1)
		y2 := mod(new(big.Int).Mul(y, y))
		x2 := mod(new(big.Int).Mul(mod(new(big.Int).Sub(y2, big.NewInt(1))), inv(mod(new(big.Int).Add(mod(new(big.Int).Mul(d, y2)), big.NewInt(1))))))
		x := new(big.Int).Exp(x2, new(big.Int).Rsh(new(big.Int).Add(p, big.NewInt(3)), 3), p)
		if mod(new(big.Int).Mul(x, x)).Cmp(x2) != 0 {
			x = mod(new(big.Int).Mul(x, new(big.Int).Exp(big.NewInt(2), new(big.Int).Rsh(new(big.Int).Sub(p, big.NewInt(1)), 2), p)))
		}
		if mod(new(big.Int).Mul(x, x)).Cmp(x2) != 0 {
			t.Fatalf("y=%x is not on the curve", y)
		}
		for _, sx := range []*big.Int{x, mod(new(big.Int).Neg(x))} {
			q := pt{sx, y}
			for i := 0; i < 3; i++ {
				q = add(q, q)
			}
			if q.x.Sign() != 0 || q.y.Cmp(big.NewInt(1)) != 0 {
				t.Errorf("8*(%x, %x) is not the identity", sx, y)
			}
			seen[sx.String()+","+y.String()] = true
		}
	}
	if len(seen) != 8 {
		t.Errorf("%d distinct small-order points, want 8", len(seen))
	}
}

func TestIDs(t *testing.T) {
	for id, ok := range map[string]bool{
		"01JBQZ0000000000000000000A": true, "7ZZZZZZZZZZZZZZZZZZZZZZZZZ": true,
		"81JBQZ0000000000000000000A": false, "01jbqz0000000000000000000a": false,
		"01JBQZ0000000000000000000": false, "01JBQZ00000000000000000000AA": false,
		"01JBQZ000000000000000000IA": false, "01JBQZ000000000000000000LA": false,
		"01JBQZ000000000000000000OA": false, "01JBQZ000000000000000000UA": false,
		"": false, "01JBQZ000000000000000000 A": false,
	} {
		if ValidProposalID(id) != ok {
			t.Errorf("ValidProposalID(%q) != %v", id, ok)
		}
	}
	for id, ok := range map[string]bool{"yes": true, "a-1": true, "abstain": true, "": false, "Yes": false, "a_b": false, "a b": false,
		strings.Repeat("a", 32): true, strings.Repeat("a", 33): false} {
		if ValidChoiceID(id) != ok {
			t.Errorf("ValidChoiceID(%q) != %v", id, ok)
		}
	}
}

func TestMessageFieldChecks(t *testing.T) {
	h32 := make([]byte, 32)
	if _, err := RecordTag("01JBQZ0000000000000000000A", make([]byte, 31)); err == nil {
		t.Error("short secret")
	}
	if _, err := BallotMsg(h32, h32, "Yes"); err == nil {
		t.Error("bad choice id")
	}
	if _, err := BallotMsg(h32[:31], h32, "yes"); err == nil {
		t.Error("short proposal hash")
	}
	if _, err := (&Ballot{RecordTag: h32, VK: h32, ChoiceID: "yes", BallotSig: make([]byte, 63)}).Leaf(); err == nil {
		t.Error("short ballot_sig")
	}
	if _, err := StatusMsg("01JBQZ0000000000000000000A", make([]byte, 5), nil); err == nil {
		t.Error("short tag in a status message")
	}
	if _, err := RefusalMsg("01JBQZ0000000000000000000A", h32, nil, "", "x", 1, h32); err == nil {
		t.Error("empty type")
	}
	if _, err := RefusalMsg("01JBQZ0000000000000000000A", h32[:5], nil, "t", "x", 1, h32); err == nil {
		t.Error("short connection")
	}
}

// Labels are distinct and none is a prefix of another (§10.4 "Labels").
func TestLabelsArePrefixFree(t *testing.T) {
	ls := []string{LabelProposal, LabelExtended, LabelResults, LabelBallot, LabelCast, LabelReceipt, LabelStatus, LabelRefusal,
		LabelAnchorKey, LabelServiceList, labelRecord}
	for i, a := range ls {
		if !strings.HasSuffix(a, "\x00") || !strings.HasPrefix(a, "vettid/vote/1/") {
			t.Errorf("label %q", a)
		}
		for j, b := range ls {
			if i != j && strings.HasPrefix(b, a) {
				t.Errorf("%q is a prefix of %q", a, b)
			}
		}
	}
}

// proposalFrom builds a proposal document from the vector's, changing
// members.
func proposalFrom(t *testing.T, mut func(m map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(load(t).Documents.Proposal), &m); err != nil {
		t.Fatal(err)
	}
	mut(m)
	b, _ := json.Marshal(m)
	out, err := Canonicalize(b)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func choices(n int, label string) []any {
	out := []any{map[string]any{"id": "abstain", "label": "Abstain"}}
	for i := 1; i < n; i++ {
		out = append(out, map[string]any{"id": "c" + string(rune('a'+i)), "label": label})
	}
	return out
}

// The bounds of VAULT-MESSAGING §10.19.4 step 2: each at its largest and
// smallest accepted value, and one past.
func TestProposalBounds(t *testing.T) {
	type c struct {
		name string
		mut  func(m map[string]any)
		ok   bool
	}
	big := func(n int) string { return strings.Repeat("a", n) }
	cases := []c{
		{"unchanged", func(m map[string]any) {}, true},
		{"v 2", func(m map[string]any) { m["v"] = 2 }, false},
		{"bad id", func(m map[string]any) { m["proposal_id"] = "01jbqz0000000000000000000a" }, false},
		{"title 200", func(m map[string]any) { m["title"] = big(200) }, true},
		{"title 201", func(m map[string]any) { m["title"] = big(201) }, false},
		{"title empty", func(m map[string]any) { m["title"] = "" }, false},
		{"text 16384", func(m map[string]any) { m["text"] = big(16384) }, true},
		{"text 16385", func(m map[string]any) { m["text"] = big(16385) }, false},
		{"text empty", func(m map[string]any) { m["text"] = "" }, true},
		{"17 choices", func(m map[string]any) { m["choices"] = choices(17, "x") }, true},
		{"18 choices", func(m map[string]any) { m["choices"] = choices(18, "x") }, false},
		{"3 choices", func(m map[string]any) { m["choices"] = choices(3, "x") }, true},
		{"2 choices", func(m map[string]any) { m["choices"] = choices(2, "x") }, false},
		{"label 200", func(m map[string]any) { m["choices"] = choices(3, big(200)) }, true},
		{"label 201", func(m map[string]any) { m["choices"] = choices(3, big(201)) }, false},
		{"label empty", func(m map[string]any) { m["choices"] = choices(3, "") }, false},
		{"no abstain", func(m map[string]any) {
			m["choices"] = []any{map[string]any{"id": "a", "label": "A"}, map[string]any{"id": "b", "label": "B"}, map[string]any{"id": "c", "label": "C"}}
		}, false},
		{"duplicate choice", func(m map[string]any) {
			m["choices"] = []any{map[string]any{"id": "abstain", "label": "A"}, map[string]any{"id": "b", "label": "B"}, map[string]any{"id": "b", "label": "C"}}
		}, false},
		{"choice id 33", func(m map[string]any) {
			m["choices"] = []any{map[string]any{"id": "abstain", "label": "A"}, map[string]any{"id": "b", "label": "B"}, map[string]any{"id": big(33), "label": "C"}}
		}, false},
		{"quorum text 1024", func(m map[string]any) { m["quorum"] = map[string]any{"text": big(1024), "min_ballots": 1} }, true},
		{"quorum text 1025", func(m map[string]any) { m["quorum"] = map[string]any{"text": big(1025), "min_ballots": 1} }, false},
		{"min_ballots 0", func(m map[string]any) { m["quorum"] = map[string]any{"text": "", "min_ballots": 0} }, true},
		{"min_ballots -1", func(m map[string]any) { m["quorum"] = map[string]any{"text": "", "min_ballots": -1} }, false},
		{"outage rule 1024", func(m map[string]any) { m["outage_rule"] = big(1024) }, true},
		{"outage rule 1025", func(m map[string]any) { m["outage_rule"] = big(1025) }, false},
		{"window 7 days", func(m map[string]any) { m["closes_at"] = 1793520000 + MaxWindow }, true},
		{"window past 7 days", func(m map[string]any) { m["closes_at"] = 1793520000 + MaxWindow + 1 }, false},
		{"opens = closes", func(m map[string]any) { m["closes_at"] = 1793520000 }, false},
		{"opens > closes", func(m map[string]any) { m["closes_at"] = 1793519999 }, false},
		{"eligible 1", func(m map[string]any) { m["eligible"] = 1 }, true},
		{"eligible 0", func(m map[string]any) { m["eligible"] = 0 }, false},
		{"short service", func(m map[string]any) { m["service"] = "AAAA" }, false},
		{"short record_root", func(m map[string]any) { m["record_root"] = "AAAA" }, false},
	}
	for _, c := range cases {
		_, err := ParseProposal(proposalFrom(t, c.mut))
		if (err == nil) != c.ok {
			t.Errorf("%s: err=%v, want ok=%v", c.name, err, c.ok)
		}
	}
	// The document size bound: all fields within bounds, but control
	// characters take six bytes each in JSON.
	doc := proposalFrom(t, func(m map[string]any) {
		m["text"] = strings.Repeat("\x01", 16384)
		m["quorum"] = map[string]any{"text": strings.Repeat("\x01", 1024), "min_ballots": 0}
		m["outage_rule"] = strings.Repeat("\x01", 1024)
		m["choices"] = choices(17, strings.Repeat("\x01", 200))
	})
	if len(doc) <= MaxProposal {
		t.Fatalf("test document is only %d bytes", len(doc))
	}
	if _, err := ParseProposal(doc); err == nil {
		t.Error("a proposal over 65,536 bytes is accepted")
	}
}

func TestExtensionBounds(t *testing.T) {
	good := `{"closes_at":1793786400,"n":1,"outage":{"from":1,"source":"s","to":2},"proposal_id":"01JBQZ0000000000000000000A","v":1}`
	if _, err := ParseExtension([]byte(good)); err != nil {
		t.Fatal(err)
	}
	for name, doc := range map[string]string{
		"n 0":          strings.Replace(good, `"n":1`, `"n":0`, 1),
		"v 2":          strings.Replace(good, `"v":1`, `"v":2`, 1),
		"from = to":    strings.Replace(good, `"to":2`, `"to":1`, 1),
		"from > to":    strings.Replace(good, `"from":1`, `"from":3`, 1),
		"bad id":       strings.Replace(good, `01JBQZ`, `01jbqz`, 1),
		"extra":        strings.Replace(good, `"v":1}`, `"v":1,"w":1}`, 1),
		"source int":   strings.Replace(good, `"source":"s"`, `"source":1`, 1),
		"missing from": strings.Replace(good, `"from":1,`, ``, 1),
	} {
		if _, err := ParseExtension([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestResultsCheckProposal(t *testing.T) {
	v := load(t)
	prop, _ := ParseProposal([]byte(v.Documents.Proposal))
	res, err := ParseResults([]byte(v.Documents.Results))
	if err != nil {
		t.Fatal(err)
	}
	if err := res.CheckProposal(prop); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(r *Results, p *Proposal){
		"eligible":      func(r *Results, p *Proposal) { r.Counts.Eligible = 4 },
		"tally missing": func(r *Results, p *Proposal) { delete(r.Tally, "no") },
		"tally extra":   func(r *Results, p *Proposal) { r.Tally["maybe"] = 0 },
		"other id":      func(r *Results, p *Proposal) { r.ProposalID = "01JBQZ0000000000000000000B" },
	} {
		r := *res
		r.Tally = map[string]int64{}
		for k, n := range res.Tally {
			r.Tally[k] = n
		}
		mut(&r, prop)
		if r.CheckProposal(prop) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// A service list with one service, signed by a site key and listing one
// anchor key certified by the service's identity key.
func TestServiceList(t *testing.T) {
	v := load(t)
	ik := ed25519.NewKeyFromSeed(hx(t, v.Documents.ServiceSeed))
	site := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{5}, 32))
	pub := ik.Public().(ed25519.PublicKey)
	spki := []byte("not a real spki, only bytes")
	cert := ed25519.Sign(ik, append([]byte(LabelAnchorKey), H(spki)...))
	doc := map[string]any{
		"v": 1, "version": 1, "previous": base64.StdEncoding.EncodeToString(make([]byte, 32)),
		"services": []any{map[string]any{
			"service_id": hex.EncodeToString(H(pub)[:16]), "name": "Example",
			"iks": []any{base64.StdEncoding.EncodeToString(pub)},
			"anchor_keys": []any{map[string]any{
				"key": base64.StdEncoding.EncodeToString(spki), "anchor_cert": base64.StdEncoding.EncodeToString(cert),
				"ik": base64.StdEncoding.EncodeToString(pub)}},
		}},
	}
	build := func(m map[string]any) []byte {
		b, _ := json.Marshal(m)
		out, err := Canonicalize(b)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	raw := build(doc)
	l, err := ParseServiceList(raw)
	if err != nil {
		t.Fatal(err)
	}
	if e := l.Entry(pub); e == nil || e.Name != "Example" || len(e.AnchorKeys) != 1 {
		t.Fatal("entry")
	}
	if l.Entry(make([]byte, 32)) != nil {
		t.Error("an entry for an unknown key")
	}
	sig := ed25519.Sign(site, append([]byte(LabelServiceList), H(raw)...))
	if err := VerifyServiceList(site.Public().(ed25519.PublicKey), raw, sig); err != nil {
		t.Errorf("list signature: %v", err)
	}
	if VerifyServiceList(pub, raw, sig) == nil {
		t.Error("list verifies under another key")
	}
	raw2 := append(append([]byte{}, raw[:len(raw)-1]...), []byte(` `)...)
	if VerifyServiceList(site.Public().(ed25519.PublicKey), raw2, sig) == nil {
		t.Error("list verifies after a change")
	}
	a := l.Services[0].AnchorKeys[0]
	if err := VerifyAnchorCert(pub, a.Key, a.AnchorCert); err != nil {
		t.Errorf("anchor cert: %v", err)
	}
	if VerifyAnchorCert(pub, []byte("another key"), a.AnchorCert) == nil {
		t.Error("anchor cert verifies for another key")
	}
	// Refusals.
	svc := func(m map[string]any) map[string]any { return m["services"].([]any)[0].(map[string]any) }
	for name, mut := range map[string]func(m map[string]any){
		"service_id": func(m map[string]any) { svc(m)["service_id"] = strings.ToUpper(svc(m)["service_id"].(string)) },
		"no iks":     func(m map[string]any) { svc(m)["iks"] = []any{} },
		"short ik":   func(m map[string]any) { svc(m)["iks"] = []any{"AAAA"} },
		"version 0":  func(m map[string]any) { m["version"] = 0 },
		"previous":   func(m map[string]any) { m["previous"] = "AAAA" },
		"v":          func(m map[string]any) { m["v"] = 2 },
		"extra":      func(m map[string]any) { m["extra"] = 1 },
		"cert":       func(m map[string]any) { svc(m)["anchor_keys"].([]any)[0].(map[string]any)["anchor_cert"] = "AAAA" },
		"no anchors": func(m map[string]any) { delete(svc(m), "anchor_keys") },
	} {
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		mut(m)
		b, _ := json.Marshal(m)
		c, err := Canonicalize(b)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if _, err := ParseServiceList(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := ParseServiceList(append([]byte{' '}, raw...)); err == nil {
		t.Error("non-canonical list accepted")
	}
}

func TestServiceListDuplicatesAndChaining(t *testing.T) {
	mk := func(version int64, prev []byte, services ...map[string]any) []byte {
		var ss []any
		for _, s := range services {
			ss = append(ss, s)
		}
		b, _ := json.Marshal(map[string]any{"v": 1, "version": version, "previous": e64(prev), "services": ss})
		c, err := Canonicalize(b)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	key := func(n byte) []byte { return bytes.Repeat([]byte{n}, 32) }
	svc := func(ik []byte, extraIKs [][]byte, anchors ...map[string]any) map[string]any {
		iks := []any{e64(ik)}
		for _, k := range extraIKs {
			iks = append(iks, e64(k))
		}
		as := []any{}
		for _, a := range anchors {
			as = append(as, a)
		}
		return map[string]any{"service_id": hex.EncodeToString(H(ik)[:16]), "name": "S", "iks": iks, "anchor_keys": as}
	}
	anchor := func(spki string, ik []byte) map[string]any {
		return map[string]any{"key": e64([]byte(spki)), "anchor_cert": e64(make([]byte, 64)), "ik": e64(ik)}
	}
	zero := make([]byte, 32)
	v1 := mk(1, zero, svc(key(1), nil, anchor("k1", key(1))))
	l1, err := ParseServiceList(v1)
	if err != nil {
		t.Fatal(err)
	}
	// Refusals.
	if _, err := ParseServiceList(mk(1, zero, svc(key(1), nil), svc(key(1), nil))); err == nil {
		t.Error("duplicate service_id")
	}
	if _, err := ParseServiceList(mk(1, zero, svc(key(1), nil), svc(key(2), [][]byte{key(1)}))); err == nil {
		t.Error("an ik under two services")
	}
	if _, err := ParseServiceList(mk(1, zero, svc(key(1), nil, anchor("k", key(9))))); err == nil {
		t.Error("an anchor key whose ik is not its service's")
	}
	// Chaining.
	next := func(version int64, prev []byte, services ...map[string]any) *ServiceList {
		l, err := ParseServiceList(mk(version, prev, services...))
		if err != nil {
			t.Fatal(err)
		}
		return l
	}
	p := H(v1)
	good := next(2, p, svc(key(1), [][]byte{key(5)}, anchor("k1", key(1)), anchor("k2", key(5))), svc(key(3), nil))
	if !l1.Extends(v1, good) {
		t.Error("a valid next version")
	}
	for name, n := range map[string]*ServiceList{
		"same version":   next(1, p, svc(key(1), nil, anchor("k1", key(1)))),
		"wrong previous": next(2, zero, svc(key(1), nil, anchor("k1", key(1)))),
		"dropped":        next(2, p, svc(key(3), nil)),
		"lost anchor":    next(2, p, svc(key(1), nil)),
		"changed anchor": next(2, p, svc(key(1), nil, anchor("other", key(1)))),
	} {
		if l1.Extends(v1, n) {
			t.Errorf("%s: accepted", name)
		}
	}
	l2 := next(3, H(v1), svc(key(1), [][]byte{key(5)}, anchor("k1", key(1))))
	_ = l2
	// An ik lost.
	withIK := mk(2, p, svc(key(1), [][]byte{key(5)}, anchor("k1", key(1))))
	lw, _ := ParseServiceList(withIK)
	if !l1.Extends(v1, lw) {
		t.Fatal("adding an ik")
	}
	lost := next(3, H(withIK), svc(key(1), nil, anchor("k1", key(1))))
	if lw.Extends(withIK, lost) {
		t.Error("an ik lost")
	}
}

func TestDocumentSizeBounds(t *testing.T) {
	if _, err := ParseExtension(bytes.Repeat([]byte(" "), MaxExtensionDoc+1)); err == nil {
		t.Error("oversized extension")
	}
	if _, err := ParseResults(bytes.Repeat([]byte(" "), MaxResultsDoc+1)); err == nil {
		t.Error("oversized results")
	}
	v := load(t)
	res, _ := ParseResults([]byte(v.Documents.Results))
	res.Extensions = make([]Signed, MaxExtensions+1)
	for i := range res.Extensions {
		res.Extensions[i] = Signed{Doc: []byte("x"), Sig: make([]byte, 64)}
	}
	b, _ := encodeCanonical(res)
	if _, err := ParseResults(b); err == nil {
		t.Error("25 extensions in results")
	}
	res.Extensions = res.Extensions[:MaxExtensions]
	b, _ = encodeCanonical(res)
	if _, err := ParseResults(b); err != nil {
		t.Errorf("24 extensions: %v", err)
	}
	if _, err := ParseCastAnswer(bytes.Repeat([]byte(" "), MaxBody+1)); err == nil {
		t.Error("oversized cast answer")
	}
	if _, err := ParseRefusal(bytes.Repeat([]byte(" "), MaxBody+1)); err == nil {
		t.Error("oversized refusal")
	}
}
