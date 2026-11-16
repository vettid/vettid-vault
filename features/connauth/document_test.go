package connauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/featuretest"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/peerwire"
	"github.com/vettid/vettid-vault/vms/strictjson"
)

const goodDoc = `{"action":"proposal.create","payload":{"text":"The members adopt the budget.\nIt runs a year.","title":"Budget"},"summary":"Adopt the budget"}`

// member is a vault whose member is asked by a service connection "cS" (and a person connection "cP").
func member() (*side, ed25519.PublicKey) {
	m := &side{h: featuretest.NewHost(), w: &window{key: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0xbb}, 32)), open: true}}
	m.f = New(m.w)
	m.h.IK = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32)).Public().(ed25519.PublicKey)
	svc := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, 32)).Public().(ed25519.PublicKey)
	m.h.Conns["cS"] = vault.PeerInfo{ID: "cS", Kind: vault.KindConnection, State: vault.PeerActive, IK: svc, PeerKind: "service"}
	m.h.Conns["cP"] = vault.PeerInfo{ID: "cP", Kind: vault.KindConnection, State: vault.PeerActive, IK: svc}
	return m, svc
}

var nextID = 0

// docChallenge sends the member an approval challenge with doc (and the context ending in its ref) from conn.
func docChallenge(t *testing.T, m *side, conn, doc string, required bool, purpose string) *peerwire.ConnAuthChallenge {
	t.Helper()
	nextID++
	d := sha256.Sum256([]byte(doc))
	const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ" // a ULID's alphabet (no I, L, O or U)
	c := &peerwire.ConnAuthChallenge{RequestID: "01JB2Z6V9K3M4N5P6Q7R8S9T" + string(crockford[nextID/32%32]) + string(crockford[nextID%32]),
		Nonce: bytes.Repeat([]byte{4}, peerwire.ConnAuthNonceSize), Context: "Approve: Budget — ref " + peerwire.DocumentRef(d),
		Purpose: purpose, Document: []byte(doc), DocumentRequired: required}
	featuretest.CallExp(m.f, m.h, t0, t0.Add(time.Hour), "connection:"+conn, peerwire.TypeConnAuthChallenge, string(c.Marshal()))
	return c
}

func call(m *side, kind, typ, body string) featuretest.Result {
	return featuretest.Call(m.f, m.h, t0.Add(time.Minute), kind, typ, body)
}

// §10.4 "Approval documents" (0.89.0): a checked document is kept with the ask; the pending event names its hash,
// size and document_required, never the document; an owner device fetches it; the approval with the hash from the
// device that fetched it signs the document form, audited with d; the document goes when the ask closes.
func TestApprovalDocumentFlow(t *testing.T) {
	m, svc := member()
	c := docChallenge(t, m, "cS", goodDoc, true, peerwire.PurposeApproval)
	d := sha256.Sum256([]byte(goodDoc))
	pend := last(t, m.h, "connection.authenticate.pending")
	o, _ := strictjson.ParseObject(pend.Body)
	if hash, _ := o.Base64("document_sha256", 32); !bytes.Equal(hash, d[:]) {
		t.Fatalf("pending: %s", pend.Body)
	}
	if size, _ := o.Uint("document_size", 0, 1<<20); size != uint64(len(goodDoc)) {
		t.Fatalf("pending size: %s", pend.Body)
	}
	if req, _ := o.Bool("document_required"); !req || o.Has("document") || strings.Contains(string(pend.Body), "budget") {
		t.Fatalf("pending: %s", pend.Body)
	}
	if asks := m.f.OpenAsks(t0); len(asks) != 1 || string(asks[0].Body) != string(pend.Body) {
		t.Fatal("pending.list does not repeat the event")
	}
	hash := `"document_sha256":"` + base64.StdEncoding.EncodeToString(d[:]) + `"`
	approve := `{"request_id":"` + c.RequestID + `",` + hash + `}`

	// Not fetched by the approving device yet: document_not_fetched, the challenge open, nothing signed.
	if r := call(m, "app", "connection.authenticate.approve", approve); r.Code != "document_not_fetched" {
		t.Fatalf("before the fetch: %q", r.Code)
	}
	// A desktop's fetch does not count for the app.
	if r := call(m, "desktop", "connection.authenticate.document", `{"request_id":"`+c.RequestID+`"}`); !r.OK() {
		t.Fatalf("desktop fetch: %s", r.Code)
	}
	if r := call(m, "app", "connection.authenticate.approve", approve); r.Code != "document_not_fetched" {
		t.Fatalf("after the desktop's fetch: %q", r.Code)
	}
	r := call(m, "app", "connection.authenticate.document", `{"request_id":"`+c.RequestID+`"}`)
	if got, _ := r.Obj(t).Base64("document", -1); string(got) != goodDoc {
		t.Fatalf("fetch: %s %s", r.Code, r.Body)
	}
	// The fetch record is kept with the ask (vault state).
	raw, _ := m.f.Save()
	g := New(m.w)
	if err := g.Load(raw); err != nil {
		t.Fatal(err)
	}
	m.f = g
	if len(m.h.SentOfType(peerwire.TypeConnAuthResponse)) != 0 {
		t.Fatal("a response went before the approval")
	}
	if r := call(m, "app", "connection.authenticate.approve", approve); !r.OK() {
		t.Fatalf("approve: %s", r.Code)
	}
	resp, err := peerwire.ParseConnAuthResponse(last(t, m.h, peerwire.TypeConnAuthResponse).Body)
	if err != nil || !bytes.Equal(resp.DocumentSHA256, d[:]) || resp.Purpose != peerwire.PurposeApproval {
		t.Fatalf("response: %+v %v", resp, err)
	}
	c.Document = []byte(goodDoc) // the service's record of what it sent
	if err := peerwire.VerifyConnAuthResponse(resp, svc, m.h.IK, c); err != nil {
		t.Fatalf("the document form does not verify: %v", err)
	}
	var signed bool
	for _, a := range m.h.Activities {
		if a.Kind == "connection.authenticate.document_signed" && a.Ref == c.RequestID+" "+hex.EncodeToString(d[:]) {
			signed = true
		}
	}
	if !signed || !m.h.HasActivity("connection.authenticate.signed") {
		t.Fatal("document_signed not audited")
	}
	// Decided: the document is gone.
	if r := call(m, "app", "connection.authenticate.document", `{"request_id":"`+c.RequestID+`"}`); r.Code != "not_found" {
		t.Fatalf("after the decision: %q", r.Code)
	}
	if raw, _ := m.f.Save(); strings.Contains(string(raw), base64.StdEncoding.EncodeToString([]byte(goodDoc))[:40]) {
		t.Fatal("the document outlived its ask")
	}
}

// §10.4 "Approving", the decision table: every row that answers a code leaves the challenge open.
func TestApprovalDocumentDecisionTable(t *testing.T) {
	m, svc := member()
	d := sha256.Sum256([]byte(goodDoc))
	b64d := base64.StdEncoding.EncodeToString(d[:])
	other := sha256.Sum256([]byte("other"))
	approve := func(id, hash string) featuretest.Result {
		b := `{"request_id":"` + id + `"`
		if hash != "" {
			b += `,"document_sha256":"` + hash + `"`
		}
		return call(m, "app", "connection.authenticate.approve", b+`}`)
	}
	req := docChallenge(t, m, "cS", goodDoc, true, peerwire.PurposeApproval)
	call(m, "app", "connection.authenticate.document", `{"request_id":"`+req.RequestID+`"}`)
	if r := approve(req.RequestID, base64.StdEncoding.EncodeToString(other[:])); r.Code != "bad_request" {
		t.Fatalf("another hash: %q", r.Code)
	}
	if r := approve(req.RequestID, "AAAA"); r.Code != "bad_request" {
		t.Fatalf("a malformed hash: %q", r.Code)
	}
	if r := approve(req.RequestID, ""); r.Code != "update_required" {
		t.Fatalf("no hash on a required one: %q", r.Code)
	}
	// Still open after every refusal.
	if r := approve(req.RequestID, b64d); !r.OK() {
		t.Fatalf("then approved: %s", r.Code)
	}
	// Not required, no hash: the purpose form, as before 0.89.0.
	opt := docChallenge(t, m, "cS", goodDoc, false, peerwire.PurposeApproval)
	if r := approve(opt.RequestID, ""); !r.OK() {
		t.Fatalf("purpose form: %s", r.Code)
	}
	resp, _ := peerwire.ParseConnAuthResponse(last(t, m.h, peerwire.TypeConnAuthResponse).Body)
	opt.Document = nil
	if resp.DocumentSHA256 != nil || peerwire.VerifyConnAuthResponse(resp, svc, m.h.IK, opt) != nil {
		t.Fatal("not the purpose form")
	}
	// No document, a hash: bad_request.
	nodoc := &peerwire.ConnAuthChallenge{RequestID: "01JB2Z6V9K3M4N5P6Q7R8S9TZZ", Nonce: bytes.Repeat([]byte{4}, 32), Purpose: peerwire.PurposeApproval}
	featuretest.CallExp(m.f, m.h, t0, t0.Add(time.Hour), "connection:cS", peerwire.TypeConnAuthChallenge, string(nodoc.Marshal()))
	if r := approve(nodoc.RequestID, b64d); r.Code != "bad_request" {
		t.Fatalf("a hash without a document: %q", r.Code)
	}
	if r := approve(nodoc.RequestID, ""); !r.OK() {
		t.Fatalf("as before: %s", r.Code)
	}
	// An unknown request: not_found first.
	if r := approve("01JB2Z6V9K3M4N5P6Q7R8S9TYY", "AAAA"); r.Code != "not_found" {
		t.Fatalf("unknown: %q", r.Code)
	}
}

// A document that fails a check drops the challenge, audited with the connection and the reason: no pending
// event, no ask kept. On a challenge from a person, or for a sign-in, the members are ignored.
func TestApprovalDocumentDropsAndIgnores(t *testing.T) {
	m, _ := member()
	docChallenge(t, m, "cS", `{"action":"A","payload":{},"summary":""}`, false, peerwire.PurposeApproval)
	var ref string
	for _, a := range m.h.Activities {
		if a.Kind == "drop.approval_document" {
			ref = a.Ref
		}
	}
	if ref != "cS shape" || len(m.h.SentOfType("connection.authenticate.pending")) != 0 || len(m.f.OpenAsks(t0)) != 0 {
		t.Fatalf("drop: %q, %d pending", ref, len(m.f.OpenAsks(t0)))
	}
	// From a person connection: the document is ignored (not checked, kept or shown), the ask is as before.
	p := docChallenge(t, m, "cP", `{"action":"A","payload":{},"summary":""}`, true, peerwire.PurposeApproval)
	pend := last(t, m.h, "connection.authenticate.pending")
	if strings.Contains(string(pend.Body), "document") {
		t.Fatalf("a person's document shown: %s", pend.Body)
	}
	if r := call(m, "app", "connection.authenticate.document", `{"request_id":"`+p.RequestID+`"}`); r.Code != "not_found" {
		t.Fatalf("a person's document fetched: %q", r.Code)
	}
	if r := call(m, "app", "connection.authenticate.approve", `{"request_id":"`+p.RequestID+`"}`); !r.OK() {
		t.Fatalf("a person's approval: %s", r.Code)
	}
	// A sign-in from the service with a document (not even base64): ignored too, the sign-in reaches the member.
	before := len(m.h.SentOfType("connection.authenticate.pending"))
	siBody := `{"request_id":"01JB2Z6V9K3M4N5P6Q7R8S9TXX","nonce":"` + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{4}, 32)) +
		`","purpose":"signin","document":"%%%","document_required":"yes"}`
	featuretest.CallExp(m.f, m.h, t0, t0.Add(time.Minute), "connection:cS", peerwire.TypeConnAuthChallenge, siBody)
	if len(m.h.SentOfType("connection.authenticate.pending")) != before+1 {
		t.Fatal("a sign-in carrying a document was dropped")
	}
	if r := call(m, "app", "connection.authenticate.document", `{"request_id":"01JB2Z6V9K3M4N5P6Q7R8S9TXX"}`); r.Code != "not_found" {
		t.Fatalf("a sign-in's document: %q", r.Code)
	}
	for _, a := range m.h.Activities {
		if a.Kind == "drop.approval_document" && a.Ref != "cS shape" {
			t.Fatalf("dropped an ignored document: %q", a.Ref)
		}
	}
}

// The document goes when the ask closes by expiry or withdrawal too.
func TestApprovalDocumentErasedAtClose(t *testing.T) {
	m, _ := member()
	c := docChallenge(t, m, "cS", goodDoc, false, peerwire.PurposeApproval)
	featuretest.Call(m.f, m.h, t0.Add(time.Minute), "connection:cS", peerwire.TypeConnAuthWithdraw, string(peerwire.ConnAuthWithdrawBody(c.RequestID)))
	if r := call(m, "app", "connection.authenticate.document", `{"request_id":"`+c.RequestID+`"}`); r.Code != "not_found" {
		t.Fatalf("withdrawn: %q", r.Code)
	}
	e := docChallenge(t, m, "cS", goodDoc, false, peerwire.PurposeApproval)
	if r := featuretest.Call(m.f, m.h, t0.Add(2*time.Hour), "app", "connection.authenticate.document", `{"request_id":"`+e.RequestID+`"}`); r.Code != "not_found" {
		t.Fatalf("expired: %q", r.Code)
	}
	if raw, _ := m.f.Save(); strings.Contains(string(raw), `"document"`) {
		t.Fatalf("a closed ask's document kept: %s", raw)
	}
}

// connection.authenticate.document is volatile (§8.2): its answer, the whole document, is never cached, so the
// document is not kept in the response cache after its ask closes. Apps and desktops may fetch; agents may not.
func TestDocumentFetchIsVolatile(t *testing.T) {
	m, _ := member()
	for _, ts := range m.f.Types() {
		if ts.Type == "connection.authenticate.document" {
			if !ts.Volatile || !ts.Request || !ts.Allows(vault.KindApp) || !ts.Allows(vault.KindDesktop) || ts.Allows(vault.KindAgent) {
				t.Fatalf("%+v", ts)
			}
			return
		}
	}
	t.Fatal("connection.authenticate.document is not registered")
}

// The document's checks come before the connection's limit: a bad document on a full connection is dropped as a bad
// document, not as one over the limit. And the decision table comes before the unlock window: with the window
// closed, an approval without the hash of a document_required challenge is update_required, not credential_locked.
func TestApprovalDocumentOrder(t *testing.T) {
	m, _ := member()
	for range MaxPendingIn {
		docChallenge(t, m, "cS", goodDoc, false, peerwire.PurposeApproval)
	}
	docChallenge(t, m, "cS", `{"action":"A","payload":{},"summary":""}`, false, peerwire.PurposeApproval)
	var drop string
	for _, a := range m.h.Activities {
		if strings.HasPrefix(a.Kind, "drop.") {
			drop = a.Kind
		}
	}
	if drop != "drop.approval_document" {
		t.Fatalf("a bad document on a full connection: %q", drop)
	}
	m2, _ := member()
	c := docChallenge(t, m2, "cS", goodDoc, true, peerwire.PurposeApproval)
	m2.w.open = false
	if r := call(m2, "app", "connection.authenticate.approve", `{"request_id":"`+c.RequestID+`"}`); r.Code != "update_required" {
		t.Fatalf("window closed: %q", r.Code)
	}
}

// An expired ask's document leaves the vault's state at the next batch's end, without waiting for a connauth
// message.
func TestApprovalDocumentExpiresAtBatchEnd(t *testing.T) {
	m, _ := member()
	docChallenge(t, m, "cS", goodDoc, false, peerwire.PurposeApproval)
	if raw, _ := m.f.Save(); !strings.Contains(string(raw), `"document"`) {
		t.Fatalf("not kept to begin with: %s", raw)
	}
	m.f.BatchEnd(vault.NewSession(context.Background(), m.h, vault.PeerInfo{}, t0.Add(2*time.Hour), nil))
	if raw, _ := m.f.Save(); strings.Contains(string(raw), `"document"`) {
		t.Fatalf("an expired ask's document kept: %s", raw)
	}
}
