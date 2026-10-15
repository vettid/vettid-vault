//go:build devenclave && e2e

package e2e

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/client"
	"github.com/vettid/vettid-vault/internal/relaytest"
	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/attwire"
)

// photo returns a JPEG-looking content of n bytes (the vault sniffs only
// the first bytes; no decoder runs in the enclave).
func photo(t *testing.T, n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	copy(b, []byte{0xFF, 0xD8, 0xFF, 0xE0})
	return b
}

var testThumb = append([]byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, bytes.Repeat([]byte{3}, 600)...)

func fastAttach(o *vault.Options) { o.AttachTick = 100 * time.Millisecond }

// sendPhoto uploads content to the app's vault and sends it with a caption.
func sendPhoto(t *testing.T, tv *testVault, conn, caption string, content []byte) (msgID, attID string) {
	t.Helper()
	b, err := tv.app.UploadAttachment(ctxT(t, 30*time.Second), content, attwire.MimeJPEG)
	if err != nil {
		t.Fatal(err)
	}
	r := mustOK(t, tv.request(tv.app, "message.send", string(client.SendAttachmentBody(conn, caption, caption != "", b, 640, 480, testThumb))))
	msgID, _ = r.String("message_id")
	attID, _ = r.String("att_id")
	if msgID == "" || attID == "" {
		t.Fatal("message.send without message_id or att_id")
	}
	return msgID, attID
}

func attState(conn, msg, state string) func(json.RawMessage) bool {
	return func(b json.RawMessage) bool {
		return has("kind", "message.attachment")(b) && has("connection_id", conn)(b) && has("message_id", msg)(b) && has("state", state)(b)
	}
}

// fetchPhoto asks the app's vault for a message's photo and fetches it.
func fetchPhoto(t *testing.T, tv *testVault, conn, msg string) ([]byte, string) {
	t.Helper()
	r := tv.request(tv.app, "message.attachment.get", `{"connection_id":"`+conn+`","message_id":"`+msg+`"}`)
	if !r.OK() {
		t.Fatalf("message.attachment.get: %s", r.ErrorCode())
	}
	content, mime, err := tv.app.FetchAttachment(ctxT(t, 30*time.Second), r.Body())
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	return content, mime
}

// VAULT-MESSAGING 0.32.0 §10.5.1: a photo from the member's phone goes to
// its vault, which stores a copy and sends a fresh one to the
// connection's vault, which stores its own; each phone fetches it on
// demand from its own vault. Both relay blobs of the way are deleted
// once fetched, the caption arrives with it, and the device views carry
// the sniffed type, never a blob key.
func TestAttachmentPhotoEndToEnd(t *testing.T) {
	r := relaytest.Start(t, nil)
	a := newTestVault(t, r.URL, "a", fastAttach)
	b := newTestVault(t, r.URL, "b", fastAttach)
	aConn, bConn := connect(t, a, b, 3600)
	content := photo(t, 3<<20)

	msg, att := sendPhoto(t, a, aConn, "look", content)
	waitEvent(t, a.app, "sync.event", attState(aConn, msg, "delivered"))
	in := waitEvent(t, b.app, "message.new", has("message_id", msg))
	o, _ := strictjson.ParseObject(in.Body)
	if txt, _ := o.String("text"); txt != "look" {
		t.Fatalf("caption %q", txt)
	}
	ao, err := o.Object("attachment")
	if err != nil {
		t.Fatalf("message.new without attachment: %s", in.Body)
	}
	if th, err := ao.Base64("thumb", -1); err != nil || !bytes.Equal(th, testThumb) {
		t.Fatal("message.new thumbnail")
	}
	if ao.Has("blob") || ao.Has("key") {
		t.Fatal("a device view carries a blob")
	}
	waitEvent(t, b.app, "sync.event", attState(bConn, msg, "stored"))

	got, mime := fetchPhoto(t, b, bConn, msg)
	if !bytes.Equal(got, content) || mime != attwire.MimeJPEG {
		t.Fatalf("recipient's photo differs (%d bytes, %s)", len(got), mime)
	}
	got, _ = fetchPhoto(t, a, aConn, msg)
	if !bytes.Equal(got, content) {
		t.Fatal("sender's own copy differs")
	}
	// Views: message.get without thumb, with the stored size and sniffed
	// type; the thumbnail on its own; vault.status counts the store.
	g := mustOK(t, b.request(b.app, "message.get", `{"connection_id":"`+bConn+`","message_id":"`+msg+`"}`))
	gv, _ := g.Object("attachment")
	if st, _ := gv.String("state"); st != "stored" || gv.Has("thumb") {
		t.Fatalf("message.get view: %v", gv)
	}
	if m, _ := gv.String("mime"); m != attwire.MimeJPEG {
		t.Fatal("mime")
	}
	th := mustOK(t, b.request(b.app, "message.attachment.get", `{"connection_id":"`+bConn+`","message_id":"`+msg+`","part":"thumb"}`))
	if tb, _ := th.Base64("thumb", -1); !bytes.Equal(tb, testThumb) {
		t.Fatal("thumb part")
	}
	st := mustOK(t, a.request(a.app, "vault.status", `{}`))
	sa, err := st.Object("attachments")
	if err != nil {
		t.Fatal("vault.status without attachments")
	}
	if n, _ := sa.Uint("count", 0, 1<<20); n != 1 {
		t.Fatalf("count %d", n)
	}
	_ = att
	// Every blob was deleted by its recipient.
	waitNoBlobs(t, a)
	waitNoBlobs(t, b)
}

// waitNoBlobs waits until the vault's mailbox holds no blob.
func waitNoBlobs(t *testing.T, tv *testVault) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		n, err := tv.blobCount()
		if err == nil && n == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s's mailbox still holds %d blobs (%v)", tv.name, n, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (tv *testVault) blobCount() (int, error) {
	l, err := tv.manager().MailboxBlobs(ctxT(tv.t, 10*time.Second))
	return len(l.Blobs), err
}

// shiftClock is a clock that tests move forward (the attachment windows'
// clock, vault.Options.AttachClock; the relay keeps real time).
type shiftClock struct {
	mu  sync.Mutex
	off time.Duration
}

func (c *shiftClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Now().Add(c.off)
}

func (c *shiftClock) Add(d time.Duration) {
	c.mu.Lock()
	c.off += d
	c.mu.Unlock()
}

func withClock(c *shiftClock) func(*vault.Options) {
	return func(o *vault.Options) { fastAttach(o); o.AttachClock = c.Now }
}

func entryOf(t *testing.T, tv *testVault, msg string) vault.AttEntry {
	t.Helper()
	for _, e := range tv.manager().AttachEntries() {
		if e.Msg == msg {
			return e
		}
	}
	t.Fatalf("%s has no entry for %s", tv.name, msg)
	return vault.AttEntry{}
}

func waitEntry(t *testing.T, tv *testVault, msg string, pred func(vault.AttEntry) bool) vault.AttEntry {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		for _, e := range tv.manager().AttachEntries() {
			if e.Msg == msg && pred(e) {
				return e
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: entry of %s never matched: %+v", tv.name, msg, tv.manager().AttachEntries())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// lockVault stops a test vault's run loop and locks it.
func lockVault(t *testing.T, tv *testVault) {
	t.Helper()
	tv.stop()
	if err := tv.manager().Lock(ctxT(t, 30*time.Second)); err != nil {
		t.Fatal(err)
	}
}

// unlockVault unlocks a locked test vault again and runs it.
func unlockVault(t *testing.T, tv *testVault, tweak func(*vault.Options)) {
	t.Helper()
	m, f, err := tv.unlock(ctxT(t, 30*time.Second), tweak)
	if err != nil {
		t.Fatalf("unlock: %v", err)
	}
	tv.mu.Lock()
	tv.msg = f
	tv.mu.Unlock()
	tv.start(m)
}

// §10.5.1 owner decision 8: a recipient locked longer than the blob's TTL
// still gets the photo. The sender tells its member after the window
// (failed, unconfirmed, with a feed item); the recipient, unlocked, finds
// the blob expired and asks with missing; the sender, within
// missing_window, uploads a fresh blob and the attachment is delivered.
func TestAttachmentLockedRecipientReoffer(t *testing.T) {
	r := relaytest.Start(t, relaytest.Options{"RELAY_BLOB_TTL": "3s"})
	ca, cb := &shiftClock{}, &shiftClock{}
	a := newTestVault(t, r.URL, "a", withClock(ca))
	b := newTestVault(t, r.URL, "b", withClock(cb))
	aConn, bConn := connect(t, a, b, 3600)
	lockVault(t, b)
	content := photo(t, 200<<10)
	msg, _ := sendPhoto(t, a, aConn, "", content)
	waitEntry(t, a, msg, func(e vault.AttEntry) bool { return e.State == vault.AttSending && e.DeliverID != "" })
	time.Sleep(4 * time.Second) // the blob expires at the relay

	ca.Add(attwire.Window + time.Hour)
	waitEvent(t, a.app, "sync.event", func(m json.RawMessage) bool {
		return attState(aConn, msg, "failed")(m) && has("reason", "unconfirmed")(m)
	})

	unlockVault(t, b, withClock(cb))
	waitEvent(t, a.app, "sync.event", attState(aConn, msg, "delivered"))
	waitEvent(t, b.app, "sync.event", attState(bConn, msg, "stored"))
	if e := entryOf(t, a, msg); e.Reoffers != 1 {
		t.Fatalf("reoffers %d", e.Reoffers)
	}
	got, _ := fetchPhoto(t, b, bConn, msg)
	if !bytes.Equal(got, content) {
		t.Fatal("photo differs")
	}
	// The sender's member was told when the window ended (feed and audit).
	if !hasAudit(t, a, "message.attachment_failed", msg+":unconfirmed") {
		t.Fatal("no audit entry for the unconfirmed attachment")
	}
}

func hasAudit(t *testing.T, tv *testVault, kind, ref string) bool {
	t.Helper()
	r := mustOK(t, tv.request(tv.app, "audit.list", `{"limit":500}`))
	var es []struct {
		Kind string `json:"kind"`
		Ref  string `json:"ref"`
	}
	raw, _ := json.Marshal(r["entries"])
	_ = json.Unmarshal(r["entries"], &es)
	_ = raw
	for _, e := range es {
		if e.Kind == kind && (ref == "" || e.Ref == ref) {
			return true
		}
	}
	return false
}
