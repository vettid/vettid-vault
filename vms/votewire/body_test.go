package votewire

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/vettid/vettid-vault/internal/strictjson"
)

func e64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// proposalMsgBody is a vote.proposal body for member 1 of the vectors'
// three-member vote.
func proposalMsgBody(t *testing.T, v *vectors, mut func(m map[string]any)) []byte {
	t.Helper()
	d := v.Documents
	var rows struct {
		Rows []struct {
			RecordTag []byte `json:"record_tag"`
		} `json:"rows"`
	}
	if err := json.Unmarshal([]byte(d.Rows), &rows); err != nil {
		t.Fatal(err)
	}
	var tags [][]byte
	for _, r := range rows.Rows {
		tags = append(tags, r.RecordTag)
	}
	path, _ := Proof(tags, 1)
	var ps []any
	for _, p := range path {
		ps = append(ps, e64(p))
	}
	m := map[string]any{
		"proposal": e64([]byte(d.Proposal)), "proposal_sig": e64(hx(t, d.ProposalSig)),
		"bundle":        map[string]any{"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json"},
		"record_secret": e64(make([]byte, 32)),
		"record_proof":  map[string]any{"index": 1, "tree_size": 3, "path": ps},
	}
	if mut != nil {
		mut(m)
	}
	b, _ := json.Marshal(m)
	return b
}

func TestProposalMsg(t *testing.T) {
	v := load(t)
	body := proposalMsgBody(t, v, nil)
	m, err := ParseProposalMsg(body)
	if err != nil {
		t.Fatal(err)
	}
	prop, _ := ParseProposal(m.Proposal)
	tags := func() []byte {
		var rows struct {
			Rows []struct {
				RecordTag []byte `json:"record_tag"`
			} `json:"rows"`
		}
		_ = json.Unmarshal([]byte(v.Documents.Rows), &rows)
		return rows.Rows[1].RecordTag
	}()
	if err := m.RecordProof.Verify(prop, tags); err != nil {
		t.Errorf("record proof: %v", err)
	}
	// A proof for another tag, another size or another index is refused.
	if m.RecordProof.Verify(prop, make([]byte, 32)) == nil {
		t.Error("proof for another tag")
	}
	for name, mut := range map[string]func(r *RecordProof){
		"size":  func(r *RecordProof) { r.TreeSize = 4 },
		"index": func(r *RecordProof) { r.Index = 0 },
		"long":  func(r *RecordProof) { r.Path = append(r.Path, make([]byte, 32)) },
		"entry": func(r *RecordProof) { r.Path = [][]byte{make([]byte, 31), r.Path[1]} },
	} {
		rp := *m.RecordProof
		rp.Path = append([][]byte{}, m.RecordProof.Path...)
		mut(&rp)
		if rp.Verify(prop, tags) == nil {
			t.Errorf("record proof with a bad %s verifies", name)
		}
	}
	// Marshal and parse again.
	m2, err := ParseProposalMsg(m.Marshal())
	if err != nil || !bytes.Equal(m2.Proposal, m.Proposal) || !bytes.Equal(m2.Bundle, m.Bundle) {
		t.Errorf("round trip: %v", err)
	}

	for name, mut := range map[string]func(m map[string]any){
		"no proposal":    func(m map[string]any) { delete(m, "proposal") },
		"no bundle":      func(m map[string]any) { delete(m, "bundle") },
		"bundle string":  func(m map[string]any) { m["bundle"] = "x" },
		"bundle null":    func(m map[string]any) { m["bundle"] = nil },
		"bundle too big": func(m map[string]any) { m["bundle"] = map[string]any{"x": strings.Repeat("a", MaxBundle)} },
		"short sig":      func(m map[string]any) { m["proposal_sig"] = e64(make([]byte, 63)) },
		"short secret":   func(m map[string]any) { m["record_secret"] = e64(make([]byte, 31)) },
		"no proof":       func(m map[string]any) { delete(m, "record_proof") },
		"index >= size": func(m map[string]any) {
			m["record_proof"] = map[string]any{"index": 3, "tree_size": 3, "path": []any{}}
		},
		"size 0": func(m map[string]any) {
			m["record_proof"] = map[string]any{"index": 0, "tree_size": 0, "path": []any{}}
		},
		"33 entries": func(m map[string]any) {
			m["record_proof"] = map[string]any{"index": 0, "tree_size": 3, "path": make([]any, 33)}
		},
		"entry not base64": func(m map[string]any) {
			m["record_proof"] = map[string]any{"index": 0, "tree_size": 3, "path": []any{"!"}}
		},
		"proposal empty": func(m map[string]any) { m["proposal"] = "" },
		"proposal 65537": func(m map[string]any) { m["proposal"] = e64(make([]byte, MaxProposal+1)) },
		"unpadded base64": func(m map[string]any) {
			m["proposal_sig"] = strings.TrimRight(e64(hx(t, v.Documents.ProposalSig)), "=")
		},
	} {
		if _, err := ParseProposalMsg(proposalMsgBody(t, v, mut)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := ParseProposalMsg(bytes.Replace(body, []byte(`"bundle"`), []byte(`"bundle":{},"bundle"`), 1)); err == nil {
		t.Error("duplicate member accepted")
	}
	if _, err := ParseProposalMsg(append(body[:len(body)-1:len(body)-1], []byte(`,"x":"`+strings.Repeat("a", MaxBody)+`"}`)...)); err == nil {
		t.Error("a body over 196,608 bytes accepted")
	}
	// A bundle of exactly the largest size is accepted.
	big := proposalMsgBody(t, v, func(m map[string]any) {
		m["bundle"] = map[string]any{"x": strings.Repeat("a", MaxBundle-8)}
	})
	if _, err := ParseProposalMsg(big); err != nil {
		t.Errorf("a bundle of %d bytes: %v", MaxBundle, err)
	}
}

func TestExtendedAndClosedMsg(t *testing.T) {
	v := load(t)
	d := v.Documents
	body, _ := json.Marshal(map[string]any{
		"proposal_id": "01JBQZ0000000000000000000A", "extension": e64([]byte(d.Extension)),
		"extension_sig": e64(hx(t, d.ExtensionSig)), "bundle": map[string]any{"a": 1}})
	m, err := ParseExtendedMsg(body)
	if err != nil || string(m.Extension) != d.Extension || m.ProposalID != "01JBQZ0000000000000000000A" {
		t.Fatalf("%v", err)
	}
	if m2, err := ParseExtendedMsg(m.Marshal()); err != nil || m2.ProposalID != m.ProposalID {
		t.Errorf("round trip %v", err)
	}
	if _, err := ParseExtendedMsg(bytes.Replace(body, []byte(`"proposal_id"`), []byte(`"proposal_idx"`), 1)); err == nil {
		t.Error("no proposal_id")
	}
	if _, err := ParseExtendedMsg(bytes.Replace(body, []byte(`01JBQZ`), []byte(`01jbqz`), 1)); err == nil {
		t.Error("lower-case id")
	}

	cb, _ := json.Marshal(map[string]any{"proposal_id": "01JBQZ0000000000000000000A", "results_hash": e64(H([]byte(d.Results)))})
	c, err := ParseClosedMsg(cb)
	if err != nil || !bytes.Equal(c.ResultsHash, H([]byte(d.Results))) {
		t.Fatal(err)
	}
	if c2, err := ParseClosedMsg(c.Marshal()); err != nil || c2.ProposalID != c.ProposalID {
		t.Errorf("round trip %v", err)
	}
	if _, err := ParseClosedMsg([]byte(`{"proposal_id":"01JBQZ0000000000000000000A","results_hash":"AAAA"}`)); err == nil {
		t.Error("short results_hash")
	}
	if _, err := ParseClosedMsg([]byte(`{"proposal_id":"01JBQZ0000000000000000000A"}`)); err == nil {
		t.Error("no results_hash")
	}
}

func TestCastBody(t *testing.T) {
	v := load(t)
	ph, tag := hx(t, v.ProposalHash), hx(t, v.RecordTag)
	b := &Ballot{RecordTag: tag, VK: hx(t, v.VK), ChoiceID: v.ChoiceID, BallotSig: hx(t, v.BallotSig)}
	body, err := MarshalCast(v.ProposalID, b, hx(t, v.Credential.CastSig))
	if err != nil {
		t.Fatal(err)
	}
	o, err := strictjson.ParseObject(body)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"proposal_id", "record_tag", "vk", "choice_id", "ballot_sig", "cast_sig"} {
		if !o.Has(n) {
			t.Errorf("no %s", n)
		}
	}
	if len(o) != 6 {
		t.Errorf("%d members", len(o))
	}
	if got, _ := o.Base64("cast_sig", 64); !bytes.Equal(got, hx(t, v.Credential.CastSig)) {
		t.Error("cast_sig")
	}
	_ = ph
	if _, err := MarshalCast("x", b, hx(t, v.Credential.CastSig)); err == nil {
		t.Error("bad id")
	}
	if s, err := MarshalStatusRequest(v.ProposalID); err != nil || string(s) != `{"proposal_id":"`+v.ProposalID+`"}` {
		t.Errorf("%s %v", s, err)
	}
}

func TestCastAnswer(t *testing.T) {
	v := load(t)
	ph, leaf := hx(t, v.ProposalHash), hx(t, v.BallotLeaf)
	ik := hx(t, v.Service.IK)
	body, _ := json.Marshal(map[string]any{"proposal_id": v.ProposalID, "msg_ms": v.Service.MsgMS, "receipt_sig": e64(hx(t, v.Service.ReceiptSig))})
	a, err := ParseCastAnswer(body)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Verify(ik, v.ProposalID, ph, leaf); err != nil {
		t.Errorf("verify: %v", err)
	}
	if a.Verify(ik, "01JBQZ0000000000000000000B", ph, leaf) == nil {
		t.Error("an answer for another proposal verifies")
	}
	other := make([]byte, len(leaf))
	copy(other, leaf)
	other[len(other)-1] ^= 1
	if a.Verify(ik, v.ProposalID, ph, other) == nil {
		t.Error("a receipt for another ballot verifies")
	}
	for _, bad := range []string{
		`{"proposal_id":"` + v.ProposalID + `","msg_ms":-1,"receipt_sig":"` + e64(make([]byte, 64)) + `"}`,
		`{"proposal_id":"` + v.ProposalID + `","msg_ms":"1","receipt_sig":"` + e64(make([]byte, 64)) + `"}`,
		`{"proposal_id":"` + v.ProposalID + `","msg_ms":1.5,"receipt_sig":"` + e64(make([]byte, 64)) + `"}`,
		`{"proposal_id":"` + v.ProposalID + `","msg_ms":1}`,
		`{"proposal_id":"` + v.ProposalID + `","msg_ms":1,"receipt_sig":""}`,
	} {
		if _, err := ParseCastAnswer([]byte(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

func statusBody(t *testing.T, v *vectors, withBallot bool, mut func(m map[string]any)) []byte {
	t.Helper()
	d := v.Documents
	sk := ed25519.NewKeyFromSeed(hx(t, d.ServiceSeed))
	ph := H([]byte(d.Proposal))
	secret := bytes.Repeat([]byte{3}, 32)
	const id = "01JBQZ0000000000000000000A"
	tag, _ := RecordTag(id, secret)
	m := map[string]any{
		"proposal_id": id, "proposal": e64([]byte(d.Proposal)), "proposal_sig": e64(hx(t, d.ProposalSig)),
		"record_secret": e64(secret),
		"record_proof":  map[string]any{"index": 0, "tree_size": 3, "path": []any{}},
	}
	var leaf []byte
	if withBallot {
		vk := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{4}, 32))
		b, _ := SignBallot(vk, ph, tag, "yes")
		leaf, _ = b.Leaf()
		rm, _ := ReceiptMsg(ph, leaf, 1793606400123)
		m["ballot"] = map[string]any{"vk": e64(b.VK), "choice_id": "yes", "ballot_sig": e64(b.BallotSig)}
		m["msg_ms"] = 1793606400123
		m["receipt_sig"] = e64(ed25519.Sign(sk, append([]byte(LabelReceipt), rm...)))
	}
	sm, _ := StatusMsg(id, tag, leaf)
	m["status_sig"] = e64(ed25519.Sign(sk, append([]byte(LabelStatus), sm...)))
	if mut != nil {
		mut(m)
	}
	b, _ := json.Marshal(m)
	return b
}

func TestStatusAnswer(t *testing.T) {
	v := load(t)
	ik := ed25519.NewKeyFromSeed(hx(t, v.Documents.ServiceSeed)).Public().(ed25519.PublicKey)
	php := H([]byte(v.Documents.Proposal))
	for _, withBallot := range []bool{false, true} {
		a, err := ParseStatusAnswer(statusBody(t, v, withBallot, nil))
		if err != nil {
			t.Fatal(err)
		}
		if err := a.VerifySig(ik, php); err != nil {
			t.Errorf("ballot=%v: %v", withBallot, err)
		}
		if a.Bundle != nil {
			t.Error("a bundle appeared")
		}
		if (a.Ballot != nil) != withBallot || (a.ReceiptSig != nil) != withBallot {
			t.Error("ballot/receipt presence")
		}
		// The signature does not carry over to the other form.
		c := *a
		if withBallot {
			c.Ballot, c.ReceiptSig = nil, nil
		} else {
			c.Ballot = &RowBallot{VK: make([]byte, 32), ChoiceID: "yes", BallotSig: make([]byte, 64)}
		}
		if c.VerifySig(ik, php) == nil {
			t.Errorf("ballot=%v: the signature verifies for the other form", withBallot)
		}
	}
	a, _ := ParseStatusAnswer(statusBody(t, v, true, nil))
	a.MsgMS++
	if a.VerifySig(ik, php) == nil {
		t.Error("a receipt for another msg_ms verifies")
	}
	a.MsgMS--
	if a.VerifySig(ik, H([]byte("another proposal"))) == nil {
		t.Error("verifies against another held proposal")
	}
	// The reviewer's input: a correctly signed status_sig and receipt over a
	// ballot whose ballot_sig is 64 zero bytes.
	sk := ed25519.NewKeyFromSeed(hx(t, v.Documents.ServiceSeed))
	tag, _ := a.Tag()
	zero := &RowBallot{VK: a.Ballot.VK, ChoiceID: "yes", BallotSig: make([]byte, 64)}
	zl, _ := zero.Ballot(tag).Leaf()
	sm, _ := StatusMsg(a.ProposalID, tag, zl)
	rm, _ := ReceiptMsg(php, zl, a.MsgMS)
	z := *a
	z.Ballot = zero
	z.StatusSig = ed25519.Sign(sk, append([]byte(LabelStatus), sm...))
	z.ReceiptSig = ed25519.Sign(sk, append([]byte(LabelReceipt), rm...))
	if z.VerifySig(ik, php) == nil {
		t.Error("a status answer with a garbage ballot_sig verifies")
	}
	if _, err := ParseStatusAnswer(statusBody(t, v, false, func(m map[string]any) { m["bundle"] = map[string]any{"x": 1} })); err != nil {
		t.Errorf("bundle: %v", err)
	}
	for name, mut := range map[string]func(m map[string]any){
		"receipt without msg_ms": func(m map[string]any) { delete(m, "msg_ms") },
		"msg_ms without receipt": func(m map[string]any) { delete(m, "receipt_sig") },
		"receipt without ballot": func(m map[string]any) { delete(m, "ballot") },
		"ballot without receipt": func(m map[string]any) { delete(m, "msg_ms"); delete(m, "receipt_sig") },
		"no status_sig":          func(m map[string]any) { delete(m, "status_sig") },
		"no proposal":            func(m map[string]any) { delete(m, "proposal") },
		"ballot null":            func(m map[string]any) { m["ballot"] = nil },
		"bad choice":             func(m map[string]any) { m["ballot"].(map[string]any)["choice_id"] = "Yes" },
	} {
		if _, err := ParseStatusAnswer(statusBody(t, v, true, mut)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestRefusalBodyForms(t *testing.T) {
	conn := e64(bytes.Repeat([]byte{1}, 32))
	sig := e64(bytes.Repeat([]byte{2}, 64))
	// An empty tag as the deployed service writes it, and an unsigned
	// refusal (null signature).
	for body, signed := range map[string]bool{
		`{"refusal_sig":"` + sig + `","msg_ms":5,"connection":"` + conn + `","record_tag":""}`:   true,
		`{"refusal_sig":"` + sig + `","msg_ms":5,"connection":"` + conn + `","record_tag":null}`: true,
		`{"refusal_sig":"` + sig + `","msg_ms":5,"connection":"` + conn + `"}`:                   true,
		`{"refusal_sig":null,"msg_ms":5,"connection":"` + conn + `","record_tag":""}`:            false,
		`{"msg_ms":5,"connection":"` + conn + `"}`:                                               false,
	} {
		r, err := ParseRefusal([]byte(body))
		if err != nil {
			t.Errorf("%s: %v", body, err)
			continue
		}
		if (r.RefusalSig != nil) != signed || r.RecordTag != nil || r.MsgMS != 5 {
			t.Errorf("%s: %+v", body, r)
		}
		if !signed && r.Verify(make([]byte, 32), "01JBQZ0000000000000000000A", "vote.cast", "closed", make([]byte, 32), [][]byte{r.Connection}, nil) == nil {
			t.Error("an unsigned refusal verifies")
		}
	}
	for _, body := range []string{
		`{"refusal_sig":"` + sig + `","msg_ms":5,"connection":"AAAA"}`,
		`{"refusal_sig":"AAAA","msg_ms":5,"connection":"` + conn + `"}`,
		`{"refusal_sig":"` + sig + `","msg_ms":5,"connection":"` + conn + `","record_tag":"AAAA"}`,
		`{"refusal_sig":"` + sig + `","connection":"` + conn + `"}`,
		`{"refusal_sig":"` + sig + `","msg_ms":5,"connection":"` + conn + `","ballot":{"vk":"` + e64(make([]byte, 32)) + `","choice_id":"yes","ballot_sig":"` + sig + `"}}`,
	} {
		if _, err := ParseRefusal([]byte(body)); err == nil {
			t.Errorf("accepted %s", body)
		}
	}
}

// already_voted: the ballot the answer carries and its receipt verify, by
// the strict rules.
func TestRefusalExisting(t *testing.T) {
	v := load(t)
	ph, tag := hx(t, v.ProposalHash), hx(t, v.RecordTag)
	ik := hx(t, v.Service.IK)
	body, _ := json.Marshal(map[string]any{
		"refusal_sig": e64(bytes.Repeat([]byte{2}, 64)), "msg_ms": 9, "connection": e64(hx(t, v.Service.Refusal.Connection)), "record_tag": e64(tag),
		"ballot":        map[string]any{"vk": e64(hx(t, v.VK)), "choice_id": "yes", "ballot_sig": e64(hx(t, v.BallotSig))},
		"ballot_msg_ms": v.Service.MsgMS, "receipt_sig": e64(hx(t, v.Service.ReceiptSig)),
	})
	r, err := ParseRefusal(body)
	if err != nil {
		t.Fatal(err)
	}
	b, err := r.VerifyExisting(ik, ph, tag)
	if err != nil {
		t.Fatal(err)
	}
	if leaf, _ := b.Leaf(); hex.EncodeToString(leaf) != v.BallotLeaf {
		t.Error("leaf")
	}
	r.BallotMsgMS++
	if _, err := r.VerifyExisting(ik, ph, tag); err == nil {
		t.Error("receipt for another time verifies")
	}
	r.BallotMsgMS--
	r.Ballot.ChoiceID = "no"
	if _, err := r.VerifyExisting(ik, ph, tag); err == nil {
		t.Error("changed choice verifies")
	}
	r.Ballot = nil
	if _, err := r.VerifyExisting(ik, ph, tag); err == nil {
		t.Error("no ballot")
	}
}
