package peerwire

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

const docRID = "01JB2Z6V9K3M4N5P6Q7R8S9T30"

// docChallenge is an approval challenge body with the given document member (raw JSON) and extra members.
func docChallenge(context, document, extra string) []byte {
	b := `{"request_id":"` + docRID + `","nonce":"` + base64.StdEncoding.EncodeToString(make([]byte, ConnAuthNonceSize)) +
		`","context":"` + context + `","purpose":"approval"`
	if document != "" {
		b += `,"document":` + document
	}
	return []byte(b + extra + `}`)
}

func q(doc string) string { return `"` + base64.StdEncoding.EncodeToString([]byte(doc)) + `"` }

func ref(doc string) string {
	d := sha256.Sum256([]byte(doc))
	return "ref " + DocumentRef(d)
}

func check(t *testing.T, body []byte) (string, bool) {
	t.Helper()
	c, err := ParseConnAuthChallenge(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	_, _, req, reason := c.CheckDocument()
	return reason, req
}

// §10.4 "Approval documents": the receiver's four checks, in order, each with its reason.
func TestDocumentChecks(t *testing.T) {
	good := `{"action":"admin_set.add","payload":{"n":1},"summary":"Add Ann"}`
	if r, req := check(t, docChallenge("Approve — "+ref(good), q(good), "")); r != "" || req {
		t.Fatalf("a good document: %q %v", r, req)
	}
	if r, req := check(t, docChallenge(ref(good), q(good), `,"document_required":true`)); r != "" || !req {
		t.Fatalf("required: %q %v", r, req)
	}
	// The document is level 1 and payload level 2: 15 more objects make 17 levels, 14 make 16.
	deep := `{"action":"a","payload":{` + strings.Repeat(`"x":{`, 15) + strings.Repeat(`}`, 15) + `},"summary":""}`
	deepOK := `{"action":"a","payload":{` + strings.Repeat(`"x":{`, 14) + strings.Repeat(`}`, 14) + `},"summary":""}`
	big := `{"action":"a","payload":{"x":"` + strings.Repeat("a", MaxDocument) + `"},"summary":""}`
	for name, tc := range map[string]struct {
		body   []byte
		reason string
	}{
		"not a string":         {docChallenge(ref(good), `1`, ""), DocEncoding},
		"not base64":           {docChallenge(ref(good), `"%%%"`, ""), DocEncoding},
		"unpadded":             {docChallenge(ref(good), strings.TrimRight(q(good), `="`)+`"`, ""), DocEncoding},
		"url alphabet":         {docChallenge(ref(good), `"`+base64.URLEncoding.EncodeToString([]byte(good+"??>>"))+`"`, ""), DocEncoding},
		"too large":            {docChallenge(ref(big), q(big), ""), DocSize},
		"required false":       {docChallenge(ref(good), q(good), `,"document_required":false`), DocShape},
		"required a string":    {docChallenge(ref(good), q(good), `,"document_required":"true"`), DocShape},
		"not json":             {docChallenge(ref("x"), q("x"), ""), DocShape},
		"an array":             {docChallenge(ref(`[1]`), q(`[1]`), ""), DocShape},
		"a fourth member":      {docChallenge(ref(`{"action":"a","extra":1,"payload":{},"summary":""}`), q(`{"action":"a","extra":1,"payload":{},"summary":""}`), ""), DocShape},
		"no summary":           {docChallenge(ref(`{"action":"a","payload":{}}`), q(`{"action":"a","payload":{}}`), ""), DocShape},
		"payload an array":     {docChallenge(ref(`{"action":"a","payload":[],"summary":""}`), q(`{"action":"a","payload":[],"summary":""}`), ""), DocShape},
		"action upper case":    {docChallenge(ref(`{"action":"A","payload":{},"summary":""}`), q(`{"action":"A","payload":{},"summary":""}`), ""), DocShape},
		"action empty":         {docChallenge(ref(`{"action":"","payload":{},"summary":""}`), q(`{"action":"","payload":{},"summary":""}`), ""), DocShape},
		"action too long":      {docChallenge(ref(`{"action":"`+strings.Repeat("a", 65)+`","payload":{},"summary":""}`), q(`{"action":"`+strings.Repeat("a", 65)+`","payload":{},"summary":""}`), ""), DocShape},
		"summary too long":     {docChallenge(ref(`{"action":"a","payload":{},"summary":"`+strings.Repeat("s", 1025)+`"}`), q(`{"action":"a","payload":{},"summary":"`+strings.Repeat("s", 1025)+`"}`), ""), DocShape},
		"duplicate member":     {docChallenge(ref(`{"action":"a","payload":{"x":1,"x":2},"summary":""}`), q(`{"action":"a","payload":{"x":1,"x":2},"summary":""}`), ""), DocShape},
		"negative integer":     {docChallenge(ref(`{"action":"a","payload":{"x":-1},"summary":""}`), q(`{"action":"a","payload":{"x":-1},"summary":""}`), ""), DocShape},
		"fraction":             {docChallenge(ref(`{"action":"a","payload":{"x":1.5},"summary":""}`), q(`{"action":"a","payload":{"x":1.5},"summary":""}`), ""), DocShape},
		"over 2^53":            {docChallenge(ref(`{"action":"a","payload":{"x":9007199254740992},"summary":""}`), q(`{"action":"a","payload":{"x":9007199254740992},"summary":""}`), ""), DocShape},
		"lone surrogate":       {docChallenge(ref(`{"action":"a","payload":{"x":"\ud800"},"summary":""}`), q(`{"action":"a","payload":{"x":"\ud800"},"summary":""}`), ""), DocShape},
		"seventeen levels":     {docChallenge(ref(deep), q(deep), ""), DocDepth},
		"not canonical order":  {docChallenge(ref(`{"payload":{},"action":"a","summary":""}`), q(`{"payload":{},"action":"a","summary":""}`), ""), DocCanonical},
		"not canonical spaces": {docChallenge(ref(`{"action": "a","payload":{},"summary":""}`), q(`{"action": "a","payload":{},"summary":""}`), ""), DocCanonical},
		"not canonical escape": {docChallenge(ref(`{"action":"a","payload":{},"summary":"\u0041"}`), q(`{"action":"a","payload":{},"summary":"\u0041"}`), ""), DocCanonical},
		"no ref":               {docChallenge("Approve", q(good), ""), DocRef},
		"upper-case ref":       {docChallenge(strings.ToUpper(ref(good)), q(good), ""), DocRef},
		"another document's":   {docChallenge(ref(deepOK), q(good), ""), DocRef},
	} {
		if r, _ := check(t, tc.body); r != tc.reason {
			t.Errorf("%s: %q, want %q", name, r, tc.reason)
		}
	}
	// The size is of the decoded bytes: 65,537 is refused, 65,536 is not (it then fails no size check).
	pad := func(n int) string {
		head, tail := `{"action":"a","payload":{"x":"`, `"},"summary":""}`
		return head + strings.Repeat("a", n-len(head)-len(tail)) + tail
	}
	if r, _ := check(t, docChallenge(ref(pad(MaxDocument+1)), q(pad(MaxDocument+1)), "")); r != DocSize {
		t.Fatalf("65,537 bytes: %q", r)
	}
	if r, _ := check(t, docChallenge(ref(pad(MaxDocument)), q(pad(MaxDocument)), "")); r != "" {
		t.Fatalf("65,536 bytes: %q", r)
	}
	// Exactly 16 levels pass.
	if r, _ := check(t, docChallenge(ref(deepOK), q(deepOK), "")); r != "" {
		t.Fatalf("16 levels: %q", r)
	}
	// document_required without a document: no document at all (ignored).
	c, _ := ParseConnAuthChallenge(docChallenge(ref(good), "", `,"document_required":true`))
	if c.HasDocument() {
		t.Fatal("document_required alone made a document")
	}
}

// The document form verifies only for a challenge sent with that document, purpose approval, over its d; a vault
// that sends no documents refuses any response that carries document_sha256.
func TestDocumentFormVerify(t *testing.T) {
	_, cred, _ := ed25519.GenerateKey(nil)
	ci, ri := make([]byte, 32), make([]byte, 32)
	ci[0], ri[0] = 1, 2
	doc := []byte(`{"action":"a","payload":{},"summary":""}`)
	d := sha256.Sum256(doc)
	c := &ConnAuthChallenge{RequestID: docRID, Nonce: make([]byte, ConnAuthNonceSize), Context: "x " + DocumentRef(d),
		Purpose: PurposeApproval, Document: doc}
	r, err := SignConnAuthDocument(cred, ci, ri, c, d, time.Now(), nil)
	if err != nil || VerifyConnAuthResponse(r, ci, ri, c) != nil {
		t.Fatalf("%v", err)
	}
	pr, _ := ParseConnAuthResponse(r.Marshal())
	if VerifyConnAuthResponse(pr, ci, ri, c) != nil {
		t.Fatal("the parsed response does not verify")
	}
	noDoc := *c
	noDoc.Document = nil
	other := *c
	other.Document = []byte(`{"action":"b","payload":{},"summary":""}`)
	signin := *c
	signin.Purpose = PurposeSignIn
	for name, cc := range map[string]*ConnAuthChallenge{"sent without a document": &noDoc, "another document": &other, "sign-in": &signin} {
		if VerifyConnAuthResponse(pr, ci, ri, cc) == nil {
			t.Errorf("%s: verified", name)
		}
	}
	// A challenge sent without a document refuses a document-form answer, even one over the empty document's d.
	empty := sha256.Sum256(nil)
	re, _ := SignConnAuthDocument(cred, ci, ri, &noDoc, empty, time.Now(), nil)
	if VerifyConnAuthResponse(re, ci, ri, &noDoc) == nil {
		t.Fatal("a document-form answer verified for a challenge without a document")
	}
	noPurpose := *pr
	noPurpose.Purpose, noPurpose.HasPurpose = "", false
	if VerifyConnAuthResponse(&noPurpose, ci, ri, c) == nil {
		t.Fatal("document_sha256 without purpose verified")
	}
	// The document form and the purpose form are not each other.
	pf, _ := SignConnAuth(cred, ci, ri, c, time.Now(), nil)
	pf.DocumentSHA256 = d[:]
	if VerifyConnAuthResponse(pf, ci, ri, c) == nil {
		t.Fatal("a purpose-form signature verified as the document form")
	}
	if _, err := SignConnAuthDocument(cred, ci, ri, &signin, d, time.Now(), nil); err == nil {
		t.Fatal("signed the document form for a sign-in challenge")
	}
	// A malformed document_sha256 is a malformed response.
	bad := strings.Replace(string(r.Marshal()), `"document_sha256":"`, `"document_sha256":"AA`, 1)
	if _, err := ParseConnAuthResponse([]byte(bad)); err == nil {
		t.Fatal("a malformed document_sha256 parsed")
	}
}

// FuzzCheckDocument: the checks never panic, and a document they accept is canonical, within its bounds, and has
// the hash its context names.
func FuzzCheckDocument(f *testing.F) {
	f.Add([]byte(`{"action":"admin_set.add","payload":{"n":1},"summary":"Add Ann"}`), true)
	f.Add([]byte(`{"action":"a","payload":{"x":[1,{"y":"é"}]},"summary":""}`), false)
	f.Fuzz(func(t *testing.T, doc []byte, required bool) {
		d := sha256.Sum256(doc)
		extra := ""
		if required {
			extra = `,"document_required":true`
		}
		c, err := ParseConnAuthChallenge(docChallenge("ref "+DocumentRef(d), `"`+base64.StdEncoding.EncodeToString(doc)+`"`, extra))
		if err != nil {
			return
		}
		got, gd, req, reason := c.CheckDocument()
		if reason != "" {
			return
		}
		if string(got) != string(doc) || gd != d || req != required || len(got) > MaxDocument {
			t.Fatalf("accepted %q", doc)
		}
	})
}
