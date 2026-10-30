package votewire

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// The vectors of VAULT-MESSAGING §16 "§10.19 votes", copied byte for byte
// from vettid/service-vault vote/testdata/vectors.json at dc6a4d2
// (BALLOT-PROTOCOL 0.11.1 §11; unchanged at 0.12.0). The file is
// authoritative: a vector that stops matching is a stop-and-report item
// (BALLOT-PROTOCOL §11), never a reason to edit the file here.
const vectorsFile = "../../testdata/vote/vectors.json"

type vectors struct {
	ProposalID   string `json:"proposal_id"`
	ProposalHash string `json:"proposal_hash"`
	RecordSecret string `json:"record_secret"`
	RecordTag    string `json:"record_tag"`
	VKSeed       string `json:"vk_seed"`
	VK           string `json:"vk"`
	ChoiceID     string `json:"choice_id"`
	BallotMsg    string `json:"ballot_msg"`
	BallotSig    string `json:"ballot_sig"`
	BallotLeaf   string `json:"ballot_leaf"`
	Credential   struct {
		Seed    string `json:"seed"`
		Key     string `json:"key"`
		CastMsg string `json:"cast_msg"`
		CastSig string `json:"cast_sig"`
	} `json:"credential"`
	Service struct {
		Seed       string `json:"seed"`
		IK         string `json:"ik"`
		MsgMS      uint64 `json:"msg_ms"`
		ReceiptMsg string `json:"receipt_msg"`
		ReceiptSig string `json:"receipt_sig"`
		StatusMsg  string `json:"status_msg"`
		StatusSig  string `json:"status_sig"`
		Refusal    struct {
			Connection  string `json:"connection"`
			Type        string `json:"type"`
			Code        string `json:"code"`
			RequestHash string `json:"request_hash"`
			Msg         string `json:"msg"`
			Sig         string `json:"sig"`
		} `json:"refusal"`
	} `json:"service"`
	Merkle []struct {
		Leaves []string   `json:"leaves"`
		Root   string     `json:"root"`
		Proofs [][]string `json:"proofs"`
	} `json:"merkle"`
	Ed25519 []struct {
		Case  string `json:"case"`
		Key   string `json:"key"`
		Msg   string `json:"msg"`
		Sig   string `json:"sig"`
		Valid bool   `json:"valid"`
	} `json:"ed25519"`
	Documents struct {
		ServiceSeed  string `json:"service_seed"`
		Proposal     string `json:"proposal"`
		ProposalSig  string `json:"proposal_sig"`
		Extension    string `json:"extension"`
		ExtensionSig string `json:"extension_sig"`
		Rows         string `json:"rows"`
		Results      string `json:"results"`
		ResultsSig   string `json:"results_sig"`
	} `json:"documents"`
}

func load(t *testing.T) *vectors {
	t.Helper()
	b, err := os.ReadFile(vectorsFile)
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		t.Fatal(err)
	}
	return &v
}

func hx(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func same(t *testing.T, what string, got []byte, want string) {
	t.Helper()
	if hex.EncodeToString(got) != want {
		t.Errorf("%s:\n got  %x\n want %s", what, got, want)
	}
}

func TestBallotVectors(t *testing.T) {
	v := load(t)
	ph := hx(t, v.ProposalHash)
	secret := hx(t, v.RecordSecret)

	tag, err := RecordTag(v.ProposalID, secret)
	if err != nil {
		t.Fatal(err)
	}
	same(t, "record_tag", tag, v.RecordTag)

	msg, err := BallotMsg(ph, tag, v.ChoiceID)
	if err != nil {
		t.Fatal(err)
	}
	same(t, "ballot_msg", msg, v.BallotMsg)

	vk := ed25519.NewKeyFromSeed(hx(t, v.VKSeed))
	same(t, "vk", vk.Public().(ed25519.PublicKey), v.VK)
	b, err := SignBallot(vk, ph, tag, v.ChoiceID)
	if err != nil {
		t.Fatal(err)
	}
	same(t, "ballot_sig", b.BallotSig, v.BallotSig)
	leaf, err := b.Leaf()
	if err != nil {
		t.Fatal(err)
	}
	same(t, "ballot_leaf", leaf, v.BallotLeaf)
	if err := VerifyBallot(ph, b); err != nil {
		t.Errorf("ballot_sig does not verify: %v", err)
	}

	cred := ed25519.NewKeyFromSeed(hx(t, v.Credential.Seed))
	same(t, "credential key", cred.Public().(ed25519.PublicKey), v.Credential.Key)
	cm, _ := CastMsg(ph, leaf)
	same(t, "cast_msg", cm, v.Credential.CastMsg)
	cs, err := SignCast(cred, ph, leaf)
	if err != nil {
		t.Fatal(err)
	}
	same(t, "cast_sig", cs, v.Credential.CastSig)
	if err := VerifyCast(cred.Public().(ed25519.PublicKey), ph, leaf, cs); err != nil {
		t.Errorf("cast_sig does not verify: %v", err)
	}

	// The service's signatures: derived, byte for byte, and verified by
	// the strict rules under its key.
	ik := hx(t, v.Service.IK)
	ssk := ed25519.NewKeyFromSeed(hx(t, v.Service.Seed))
	same(t, "service ik", ssk.Public().(ed25519.PublicKey), v.Service.IK)

	rm, _ := ReceiptMsg(ph, leaf, v.Service.MsgMS)
	same(t, "receipt_msg", rm, v.Service.ReceiptMsg)
	same(t, "receipt_sig", ed25519.Sign(ssk, append([]byte(LabelReceipt), rm...)), v.Service.ReceiptSig)
	if err := VerifyReceipt(ik, ph, leaf, v.Service.MsgMS, hx(t, v.Service.ReceiptSig)); err != nil {
		t.Errorf("receipt: %v", err)
	}
	if VerifyReceipt(ik, ph, leaf, v.Service.MsgMS+1, hx(t, v.Service.ReceiptSig)) == nil {
		t.Error("a receipt for another msg_ms verifies")
	}

	sm, _ := StatusMsg(v.ProposalID, tag, leaf)
	same(t, "status_msg", sm, v.Service.StatusMsg)
	same(t, "status_sig", ed25519.Sign(ssk, append([]byte(LabelStatus), sm...)), v.Service.StatusSig)
	if err := VerifyStatus(ik, v.ProposalID, tag, leaf, hx(t, v.Service.StatusSig)); err != nil {
		t.Errorf("status: %v", err)
	}
	if VerifyStatus(ik, v.ProposalID, tag, nil, hx(t, v.Service.StatusSig)) == nil {
		t.Error("a status answer with a ballot verifies as one without")
	}

	r := v.Service.Refusal
	rq := hx(t, r.RequestHash)
	same(t, "refusal request_hash = H(ballot_leaf)", H(leaf), r.RequestHash)
	rf, err := RefusalMsg(v.ProposalID, hx(t, r.Connection), tag, r.Type, r.Code, v.Service.MsgMS, rq)
	if err != nil {
		t.Fatal(err)
	}
	same(t, "refusal msg", rf, r.Msg)
	same(t, "refusal sig", ed25519.Sign(ssk, append([]byte(LabelRefusal), rf...)), r.Sig)
	ref := &Refusal{RefusalSig: hx(t, r.Sig), MsgMS: v.Service.MsgMS, Connection: hx(t, r.Connection), RecordTag: tag}
	conns := [][]byte{bytes.Repeat([]byte{9}, 32), hx(t, r.Connection)}
	if err := ref.Verify(ik, v.ProposalID, r.Type, r.Code, rq, conns, tag); err != nil {
		t.Errorf("refusal: %v", err)
	}
	for name, mod := range map[string]func(*Refusal){
		"other connection": func(x *Refusal) { x.Connection = bytes.Repeat([]byte{9}, 32) },
		"other tag":        func(x *Refusal) { x.RecordTag = bytes.Repeat([]byte{7}, 32) },
		"other time":       func(x *Refusal) { x.MsgMS++ },
		"unsigned":         func(x *Refusal) { x.RefusalSig = nil },
	} {
		c := *ref
		mod(&c)
		if c.Verify(ik, v.ProposalID, r.Type, r.Code, rq, conns, tag) == nil {
			t.Errorf("refusal with %s verifies", name)
		}
	}
	if ref.Verify(ik, v.ProposalID, "vote.status", r.Code, rq, conns, tag) == nil {
		t.Error("a vote.cast refusal verifies as a vote.status one")
	}
	if ref.Verify(ik, v.ProposalID, r.Type, "closed", rq, conns, tag) == nil {
		t.Error("a bad_ballot refusal verifies as another code")
	}
	if ref.Verify(ik, v.ProposalID, r.Type, r.Code, rq, nil, tag) == nil {
		t.Error("a refusal for an unknown connection verifies")
	}
	// An empty tag in the refusal is accepted when signed as empty.
	rf0, _ := RefusalMsg(v.ProposalID, hx(t, r.Connection), nil, "vote.status", "not_eligible", 5, H([]byte(v.ProposalID)))
	e := &Refusal{RefusalSig: ed25519.Sign(ssk, append([]byte(LabelRefusal), rf0...)), MsgMS: 5, Connection: hx(t, r.Connection)}
	if err := e.Verify(ik, v.ProposalID, "vote.status", "not_eligible", H([]byte(v.ProposalID)), conns, nil); err != nil {
		t.Errorf("refusal with no tag: %v", err)
	}
}

// The status answer for a member with no ballot signs H("") in place of
// H(ballot_leaf) (VAULT-MESSAGING §10.19.5).
func TestStatusWithoutBallotIsHashOfEmpty(t *testing.T) {
	const emptyHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	v := load(t)
	m, err := StatusMsg(v.ProposalID, hx(t, v.RecordTag), nil)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(m[len(m)-32:]) != emptyHash {
		t.Errorf("tail %x", m[len(m)-32:])
	}
}

func TestMerkleVectors(t *testing.T) {
	v := load(t)
	if len(v.Merkle) != 6 {
		t.Fatalf("%d trees", len(v.Merkle))
	}
	for _, mv := range v.Merkle {
		leaves := make([][]byte, len(mv.Leaves))
		for i, l := range mv.Leaves {
			leaves[i] = hx(t, l)
		}
		root := Root(leaves)
		same(t, "root", root, mv.Root)
		for i := range leaves {
			p, err := Proof(leaves, i)
			if err != nil {
				t.Fatal(err)
			}
			if len(mv.Proofs) > 0 {
				if len(p) != len(mv.Proofs[i]) {
					t.Fatalf("proof %d has %d entries, vector %d", i, len(p), len(mv.Proofs[i]))
				}
				for j := range p {
					same(t, "proof entry", p[j], mv.Proofs[i][j])
				}
			}
			if !VerifyProof(root, leaves[i], uint64(i), uint64(len(leaves)), p) {
				t.Errorf("%d leaves: proof %d does not verify", len(leaves), i)
			}
			// A proof does not verify for another index, a
			// changed leaf or a changed entry, nor with an entry added or
			// removed.
			if len(leaves) > 1 && VerifyProof(root, leaves[i], uint64((i+1)%len(leaves)), uint64(len(leaves)), p) &&
				string(leaves[i]) != string(leaves[(i+1)%len(leaves)]) {
				t.Errorf("%d leaves: proof %d verifies at another index", len(leaves), i)
			}
			if VerifyProof(root, append(append([]byte{}, leaves[i]...), 0), uint64(i), uint64(len(leaves)), p) {
				t.Errorf("%d leaves: proof %d verifies a changed leaf", len(leaves), i)
			}
			if len(p) > 0 {
				if VerifyProof(root, leaves[i], uint64(i), uint64(len(leaves)), p[:len(p)-1]) {
					t.Errorf("%d leaves: a short proof %d verifies", len(leaves), i)
				}
				if VerifyProof(root, leaves[i], uint64(i), uint64(len(leaves)), append(append([][]byte{}, p...), p[0])) {
					t.Errorf("%d leaves: a long proof %d verifies", len(leaves), i)
				}
				bad := append([][]byte{}, p...)
				bad[0] = append([]byte{}, bad[0]...)
				bad[0][0] ^= 1
				if VerifyProof(root, leaves[i], uint64(i), uint64(len(leaves)), bad) {
					t.Errorf("%d leaves: a changed entry %d verifies", len(leaves), i)
				}
			}
		}
	}
	if VerifyProof(Root(nil), nil, 0, 0, nil) {
		t.Error("a proof in the empty tree verifies")
	}
}

// The twelve cases of BALLOT-PROTOCOL §2 (VAULT-MESSAGING §16): the strict
// verifier gives the vector's verdict on each.
func TestEd25519Vectors(t *testing.T) {
	v := load(t)
	if len(v.Ed25519) != 12 {
		t.Fatalf("%d cases", len(v.Ed25519))
	}
	for _, c := range v.Ed25519 {
		err := Verify(hx(t, c.Key), LabelBallot, hx(t, c.Msg), hx(t, c.Sig))
		if (err == nil) != c.Valid {
			t.Errorf("%s: verifies=%v, vector says %v", c.Case, err == nil, c.Valid)
		}
		// The cases are ones Go's ed25519.Verify alone accepts, except
		// S not below L: that is why the rules are made here.
		if !c.Valid && c.Case != "S not below L" && c.Case != "key with y not below p" && c.Case != "key with x = 0 and the sign bit" {
			m := append([]byte(LabelBallot), hx(t, c.Msg)...)
			if !ed25519.Verify(hx(t, c.Key), m, hx(t, c.Sig)) {
				t.Errorf("%s: the stdlib refuses it too; the case no longer shows the extra rules", c.Case)
			}
		}
	}
	// Wrong lengths.
	if Verify(make([]byte, 31), LabelBallot, nil, make([]byte, 64)) == nil || Verify(make([]byte, 32), LabelBallot, nil, make([]byte, 63)) == nil {
		t.Error("a wrong length verifies")
	}
}

func TestDocumentVectors(t *testing.T) {
	v := load(t)
	d := v.Documents
	ik := ed25519.NewKeyFromSeed(hx(t, d.ServiceSeed)).Public().(ed25519.PublicKey)

	prop, err := ParseProposal([]byte(d.Proposal))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(prop.Service, ik) {
		t.Error("the proposal's service is not the document seed's key")
	}
	if err := VerifyProposal(ik, []byte(d.Proposal), hx(t, d.ProposalSig)); err != nil {
		t.Errorf("proposal_sig: %v", err)
	}
	ph := H([]byte(d.Proposal))

	ext, err := ParseExtension([]byte(d.Extension))
	if err != nil {
		t.Fatal(err)
	}
	if ext.ProposalID != prop.ProposalID || ext.N != 1 {
		t.Error("extension fields")
	}
	if err := VerifyExtension(ik, ph, []byte(d.Extension), hx(t, d.ExtensionSig)); err != nil {
		t.Errorf("extension_sig: %v", err)
	}
	if VerifyExtension(ik, ph, []byte(d.Extension), hx(t, d.ProposalSig)) == nil {
		t.Error("a proposal signature verifies as an extension signature")
	}

	res, err := ParseResults([]byte(d.Results))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyResults(ik, ph, []byte(d.Results), hx(t, d.ResultsSig)); err != nil {
		t.Errorf("results_sig: %v", err)
	}
	if err := res.CheckProposal(prop); err != nil {
		t.Errorf("results against the proposal: %v", err)
	}
	// The results embed the proposal and the extension byte for byte.
	if !bytes.Equal(res.Proposal.Doc, []byte(d.Proposal)) || !bytes.Equal(res.Proposal.Sig, hx(t, d.ProposalSig)) {
		t.Error("the results' proposal is not the proposal")
	}
	if len(res.Extensions) != 1 || !bytes.Equal(res.Extensions[0].Doc, []byte(d.Extension)) || !bytes.Equal(res.Extensions[0].Sig, hx(t, d.ExtensionSig)) {
		t.Error("the results' extensions are not the extension")
	}
	if res.Counts.Eligible != 3 || res.Counts.Ballots != 2 || res.Tally["yes"] != 1 || res.Tally["no"] != 1 || res.Tally["abstain"] != 0 {
		t.Errorf("counts %+v tally %v", res.Counts, res.Tally)
	}

	// rows.json: its hash and root are the results', the tags reach the
	// proposal's record_root, and a ballot's row leaf is its ballot_leaf.
	if !bytes.Equal(H([]byte(d.Rows)), res.RowsHash) {
		t.Error("rows_hash")
	}
	var rows struct {
		Rows []struct {
			RecordTag []byte `json:"record_tag"`
			Ballot    *struct {
				VK        []byte `json:"vk"`
				ChoiceID  string `json:"choice_id"`
				BallotSig []byte `json:"ballot_sig"`
			} `json:"ballot"`
		} `json:"rows"`
	}
	if err := json.Unmarshal([]byte(d.Rows), &rows); err != nil || len(rows.Rows) != 3 {
		t.Fatal("rows", err)
	}
	var tags, leaves [][]byte
	for _, r := range rows.Rows {
		tags = append(tags, r.RecordTag)
		if r.Ballot == nil {
			l, err := EmptyRowLeaf(r.RecordTag)
			if err != nil {
				t.Fatal(err)
			}
			leaves = append(leaves, l)
			continue
		}
		b := &Ballot{RecordTag: r.RecordTag, VK: r.Ballot.VK, ChoiceID: r.Ballot.ChoiceID, BallotSig: r.Ballot.BallotSig}
		if err := VerifyBallot(ph, b); err != nil {
			t.Errorf("a row's ballot_sig: %v", err)
		}
		l, err := b.Leaf()
		if err != nil {
			t.Fatal(err)
		}
		leaves = append(leaves, l)
	}
	if !bytes.Equal(Root(tags), prop.RecordRoot) {
		t.Error("the tags do not reach record_root")
	}
	if !bytes.Equal(Root(leaves), res.RowsRoot) {
		t.Error("the rows do not reach rows_root")
	}
	// A member's record_proof and row proof against these roots, with equal
	// index and tree_size (VAULT-MESSAGING §10.19.6 step 3).
	for i, tag := range tags {
		p, _ := Proof(tags, i)
		rp := &RecordProof{Index: uint64(i), TreeSize: 3, Path: p}
		if err := rp.Verify(prop, tag); err != nil {
			t.Errorf("record_proof %d: %v", i, err)
		}
		q, _ := Proof(leaves, i)
		if !VerifyProof(res.RowsRoot, leaves[i], uint64(i), uint64(res.Counts.Eligible), q) {
			t.Errorf("row proof %d", i)
		}
	}
}

// Documents that are not exactly canonical, or whose members are not
// exactly the schema's, are refused.
func TestDocumentsRefuseNonCanonical(t *testing.T) {
	v := load(t)
	good := []byte(v.Documents.Proposal)
	if _, err := ParseProposal(good); err != nil {
		t.Fatal(err)
	}
	set := func(mut func(m map[string]any)) []byte {
		var m map[string]any
		dec := json.NewDecoder(bytes.NewReader(good))
		dec.UseNumber()
		if err := dec.Decode(&m); err != nil {
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
	bad := map[string][]byte{
		"whitespace":          bytes.Replace(good, []byte(`"v":1`), []byte(`"v": 1`), 1),
		"key order":           []byte(`{"v":1,` + string(good[1:len(good)-1]) + `}`),
		"duplicate name":      bytes.Replace(good, []byte(`"v":1}`), []byte(`"v":1,"v":1}`), 1),
		"fraction":            bytes.Replace(good, []byte(`"eligible":3`), []byte(`"eligible":3.0`), 1),
		"exponent":            bytes.Replace(good, []byte(`"eligible":3`), []byte(`"eligible":3e0`), 1),
		"unicode escape":      bytes.Replace(good, []byte(`"Yes"`), []byte(`"\u0059es"`), 1),
		"trailing data":       append(append([]byte{}, good...), ' '),
		"trailing object":     append(append([]byte{}, good...), '{', '}'),
		"not an object":       []byte(`[]`),
		"empty":               nil,
		"invalid utf-8":       bytes.Replace(good, []byte(`"Yes"`), []byte("\"\xffes\""), 1),
		"unknown member":      set(func(m map[string]any) { m["extra"] = true }),
		"missing member":      set(func(m map[string]any) { delete(m, "outage_rule") }),
		"null member":         set(func(m map[string]any) { m["outage_rule"] = nil }),
		"string for integer":  set(func(m map[string]any) { m["eligible"] = "3" }),
		"integer for bool":    set(func(m map[string]any) { m["binding"] = 0 }),
		"base64 no padding":   bytes.Replace(good, []byte(`qQUTrr2AV0249g+RVK3BoG1+fKW7liXjAALQFgd7FSQ=`), []byte(`qQUTrr2AV0249g+RVK3BoG1+fKW7liXjAALQFgd7FSQ`), 1),
		"base64 trailing bit": bytes.Replace(good, []byte(`qQUTrr2AV0249g+RVK3BoG1+fKW7liXjAALQFgd7FSQ=`), []byte(`qQUTrr2AV0249g+RVK3BoG1+fKW7liXjAALQFgd7FSR=`), 1),
		"integer past 2^53":   bytes.Replace(good, []byte(`"record_at":1793500000`), []byte(`"record_at":9007199254740993`), 1),
		"nested choice extra": bytes.Replace(good, []byte(`{"id":"yes","label":"Yes"}`), []byte(`{"id":"yes","label":"Yes","x":1}`), 1),
	}
	for name, b := range bad {
		if _, err := ParseProposal(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := ParseExtension([]byte(v.Documents.Results)); err == nil {
		t.Error("results parsed as an extension")
	}
	if _, err := ParseResults([]byte(v.Documents.Proposal)); err == nil {
		t.Error("a proposal parsed as results")
	}
	if _, err := ParseProposal(bytes.Repeat([]byte(" "), MaxProposal+1)); err == nil {
		t.Error("an oversized document")
	}
}

func TestCanonicalizeRules(t *testing.T) {
	cases := map[string]string{
		`{"b":1,"a":[true,null,"x"]}`:                 `{"a":[true,null,"x"],"b":1}`,
		"{\"a\":\"\\u0001\\u001f\\n\\u007f/\"}":       "{\"a\":\"\\u0001\\u001f\\n\x7f/\"}",
		`{"\u00e9":1,"z":2,"\ud83d\ude00":3}`:         `{"z":2,"é":1,"😀":3}`,
		`{"a":-5}`:                                    `{"a":-5}`,
		`{"\ufb01":1,"\uff21":2}`:                     `{"ﬁ":1,"Ａ":2}`,
		`{"<":"&>"}`:                                  `{"<":"&>"}`,
		`{"a":{"b":{"c":{"d":{"e":{"f":{"g":1}}}}}}}`: `{"a":{"b":{"c":{"d":{"e":{"f":{"g":1}}}}}}}`,
	}
	for in, want := range cases {
		got, err := Canonicalize([]byte(in))
		if err != nil || string(got) != want {
			t.Errorf("%s: %q, %v (want %q)", in, got, err, want)
		}
	}
	for _, in := range []string{`{"a":1,"a":2}`, `{"a":{"b":1,"b":2}}`, `{"a":1.5}`, `{"a":-0}`, `{"a":1E2}`, `{"a":01}`, `nul`, `{"a":1}x`,
		`{"a":{"b":{"c":{"d":{"e":{"f":{"g":{"h":{"i":1}}}}}}}}}`} {
		if _, err := Canonicalize([]byte(in)); err == nil {
			t.Errorf("%s: accepted", in)
		}
	}
	// A lone surrogate escape decodes to U+FFFD, so the document is not its
	// own canonical form and is refused where bytes must be exact.
	if _, err := checkCanonical([]byte(`{"a":"\ud800"}`)); err == nil {
		t.Error("a lone surrogate escape is canonical")
	}
}
