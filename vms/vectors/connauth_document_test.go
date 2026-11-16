package vectors

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/vettid/vettid-vault/vms/peerwire"
)

func TestConnAuthDocumentVectors(t *testing.T) { checkConnAuthDocumentVectors(t, Dir) }

// checkConnAuthDocumentVectors re-derives connauth_document.json (0.89.0, §10.4 "Approval documents") by hand, and
// holds it to the values VAULT-MESSAGING §16 prints: d, document_sha256, m_d's size and both signatures; then
// through peerwire: the challenge passes the receiver's checks, the response parses, re-encodes and verifies, and
// signing again gives the same bytes.
func checkConnAuthDocumentVectors(t *testing.T, dir string) {
	v := load(t, dir, "connauth_document.json")
	if v.str("label_document") != "vettid/vms/2/conn-auth-document" || peerwire.ConnAuthDocumentLabel != v.str("label_document") {
		t.Fatalf("label %q", v.str("label_document"))
	}
	seed := func(b byte) ed25519.PrivateKey {
		s := make([]byte, 32)
		for i := range s {
			s[i] = b
		}
		return ed25519.NewKeyFromSeed(s)
	}
	pub := func(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }
	cred, challenger, responder := seed(0x31), pub(seed(0x32)), pub(seed(0x33))
	b64 := base64.StdEncoding.EncodeToString
	// §16, as printed.
	if b64(pub(cred)) != "SAdaWX5yGhVuLgeZ3lzAxTJNxufq8c3UYlCGjsUyFd0=" || b64(challenger) != "XiEsCYDks5/AlyETSqAhCTdO39JgwNPQPLUByNZUV6k=" ||
		b64(responder) != "F8t5+ytBIPKx7GXkGY1uCLKOgT/rAeSkAIObheGAgM4=" {
		t.Fatal("keys differ from §16")
	}
	doc := []byte(v.str("document"))
	d := sha256.Sum256(doc)
	if len(doc) != 473 || hex.EncodeToString(d[:]) != "e8af8815891e434b34fe3fedafb270f8df3bcae3a22017b92e92063e11340bf5" ||
		b64(d[:]) != "6K+IFYkeQ0s0/j/tr7Jw+N87yuOiIBe5LpIGPhE0C/U=" || v.str("document_sha256_b64") != b64(d[:]) {
		t.Fatalf("d %x", d)
	}
	ctxt := v.str("context")
	if len(ctxt) != 105 {
		t.Fatalf("context %d bytes", len(ctxt))
	}
	nonce := make([]byte, 32)
	for i := range nonce {
		nonce[i] = 0x34
	}
	reqID := "01JB2Z6V9K3M4N5P6Q7R8S9T30"
	m := append(append(append(append(append([]byte{}, challenger...), responder...), nonce...), reqID...), ctxt...)
	md := append(append(append([]byte{8}, "approval"...), d[:]...), m...)
	if len(md) != 268 {
		t.Fatalf("m_d %d bytes", len(md))
	}
	eq(t, "m_d", md, v.hex("message_document_hex"))
	sig := ed25519.Sign(cred, append([]byte("vettid/vms/2/conn-auth-document"), md...))
	if b64(sig) != "fXeHmkPFSXoOzjCfBuguXwK9xgXwIPRgd34Y74A3cIgDlxtm3KHaDjrUBus1Z8jYTUGK9Vda5od/K9KnwFPsAw==" || v.str("sig_b64") != b64(sig) {
		t.Fatalf("sig %s", b64(sig))
	}
	psig := ed25519.Sign(cred, append([]byte("vettid/vms/2/conn-auth-purpose"), append(append([]byte{8}, "approval"...), m...)...))
	if b64(psig) != "YeR8cdEVXH9I8fCb71wWuXgp31enSddxQAkavfZlN4+eREyka+TcFUETDRAj+GH3sFuvoYMgntUTJcBPpyzqAw==" || v.str("purpose_sig_b64") != b64(psig) {
		t.Fatalf("purpose sig %s", b64(psig))
	}

	// Through peerwire.
	c, err := peerwire.ParseConnAuthChallenge([]byte(v.str("challenge_body")))
	if err != nil || c.Purpose != peerwire.PurposeApproval || c.Context != ctxt || !c.HasDocument() {
		t.Fatalf("challenge: %v", err)
	}
	got, gd, req, reason := c.CheckDocument()
	if reason != "" || gd != d || !req || string(got) != string(doc) {
		t.Fatalf("checks: %q", reason)
	}
	r, err := peerwire.ParseConnAuthResponse([]byte(v.str("response_body")))
	if err != nil || r.Purpose != "approval" || b64(r.DocumentSHA256) != b64(d[:]) {
		t.Fatalf("response: %v", err)
	}
	eq(t, "response sig", r.Sig, sig)
	eq(t, "response re-encoded", r.Marshal(), []byte(v.str("response_body")))
	c.Document = doc // the challenger's record of what it sent
	if err := peerwire.VerifyConnAuthResponse(r, challenger, responder, c); err != nil {
		t.Fatal(err)
	}
	resigned, err := peerwire.SignConnAuthDocument(cred, challenger, responder, c, d, r.SignedAt, nil)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, "re-signed", resigned.Marshal(), []byte(v.str("response_body")))
}
