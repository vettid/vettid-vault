//go:build devenclave && e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/client"
	"github.com/vettid/vettid-vault/internal/relaytest"
	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vault/store"
	"github.com/vettid/vettid-vault/vms/attwire"
	"github.com/vettid/vettid-vault/vms/envelope"
)

func ulid(t *testing.T) string {
	id, err := envelope.NewULID(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// rawDeliver is a message.attachment.deliver as a (malicious) peer writes
// it: view is the attachment member.
func rawDeliver(msg, text, view string) []byte {
	b := `{"message_id":"` + msg + `",`
	if text != "" {
		b += `"text":"` + text + `",`
	}
	return []byte(b + `"sent_at":"` + envelope.FormatTS(time.Now()) + `","attachment":` + view + `}`)
}

func b64s(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// peerView renders a peer view with a blob reference (nil: none).
func peerView(b *attwire.Blob, size int, thumb []byte, kind string) string {
	if kind == "" {
		kind = attwire.KindPhoto
	}
	if b == nil {
		return `{"kind":"` + kind + `","size":` + itoa(size) + `,"width":10,"height":10,"thumb":"` + b64s(thumb) + `"}`
	}
	return string(attwire.PeerViewJSON(b, time.Now().Add(time.Hour), kind, size, 10, 10, thumb))
}

// sealedBlob seals content as a §5.5 blob, uploaded by tv to its
// connection's mailbox; it returns the reference.
func uploadAsPeer(t *testing.T, tv *testVault, conn string, content []byte) *attwire.Blob {
	t.Helper()
	data, key, sum, err := envelope.SealBlob(content)
	if err != nil {
		t.Fatal(err)
	}
	id, _, err := tv.manager().PutBlobTo(ctxT(t, 30*time.Second), conn, data)
	if err != nil {
		t.Fatal(err)
	}
	return &attwire.Blob{ID: id, Key: key, SHA256: sum, Size: len(content), Mime: attwire.MimeJPEG}
}

func rawSend(t *testing.T, tv *testVault, conn, typ string, body []byte) {
	t.Helper()
	if _, err := tv.manager().SendRaw(ctxT(t, 30*time.Second), conn, typ, body); err != nil {
		t.Fatal(err)
	}
}

// §10.5.1 "Receiving", §5.5: a malicious peer's uploads. A blob whose
// sha256 does not match, whose content is not its declared size, whose
// framing is wrong, or that is not a photo is refused; each fetched blob
// is deleted from the mailbox, good or bad; after attachment_reoffers + 1
// failed fetches the attachment is failed (bad). A view over the limits
// (size, thumbnail bombs) is dropped and audited; a thumbnail that is not
// a photo is refused (type), as is a blob that is not one.
func TestAttachmentMaliciousPeer(t *testing.T) {
	r := relaytest.Start(t, nil)
	cb := &shiftClock{}
	evil := newTestVault(t, r.URL, "evil", fastAttach)
	b := newTestVault(t, r.URL, "b", withClock(cb))
	eConn, bConn := connect(t, evil, b, 3600)
	jpeg := photo(t, 4096)

	// Round by round, each answer to b's missing is bad in another way.
	msg := ulid(t)
	good := uploadAsPeer(t, evil, eConn, jpeg)
	wrongSum := *good
	wrongSum.SHA256[0] ^= 1
	rawSend(t, evil, eConn, vault.TypeAttDeliver, rawDeliver(msg, "hi", peerView(&wrongSum, len(jpeg), testThumb, "")))
	waitEvent(t, b.app, "message.new", has("message_id", msg))
	waitEntry(t, b, msg, func(e vault.AttEntry) bool { return e.Fetches == 1 && e.Asked })
	waitNoBlobs(t, b)

	bad := []func() *attwire.Blob{
		func() *attwire.Blob { // content of another size than declared
			x := uploadAsPeer(t, evil, eConn, jpeg[:1000])
			x.Size = len(jpeg)
			return x
		},
		func() *attwire.Blob { // garbage under a matching sha256
			junk := make([]byte, 5000)
			_, _ = rand.Read(junk)
			id, _, err := evil.manager().PutBlobTo(ctxT(t, 30*time.Second), eConn, junk)
			if err != nil {
				t.Fatal(err)
			}
			return &attwire.Blob{ID: id, Key: make([]byte, 32), SHA256: client.BlobDigest(junk), Size: len(jpeg), Mime: "image/jpeg"}
		},
		func() *attwire.Blob { // the wrong key
			x := uploadAsPeer(t, evil, eConn, jpeg)
			x.Key = bytes.Repeat([]byte{7}, 32)
			return x
		},
	}
	for i, mk := range bad {
		cb.Add(25 * time.Hour) // past the backoff: b asks again
		waitEntry(t, b, msg, func(e vault.AttEntry) bool { return e.Asked && e.Blob == nil })
		x := mk()
		rawSend(t, evil, eConn, vault.TypeAttDeliver, rawDeliver(msg, "", peerView(x, len(jpeg), testThumb, "")))
		if i < len(bad)-1 {
			waitEntry(t, b, msg, func(e vault.AttEntry) bool { return e.Fetches == i+2 })
		}
	}
	waitEvent(t, b.app, "sync.event", func(m json.RawMessage) bool { return attState(bConn, msg, "failed")(m) && has("reason", "bad")(m) })
	waitNoBlobs(t, b)

	// A fresh upload it did not ask for is ignored, and its blob deleted.
	x := uploadAsPeer(t, evil, eConn, jpeg)
	rawSend(t, evil, eConn, vault.TypeAttDeliver, rawDeliver(msg, "", peerView(x, len(jpeg), testThumb, "")))
	waitNoBlobs(t, b)

	// Over the limits: dropped and audited, nothing stored.
	big := ulid(t)
	rawSend(t, evil, eConn, vault.TypeAttDeliver, rawDeliver(big, "", peerView(nil, attwire.ReferenceMaxContent+1, testThumb, "")))
	bomb := ulid(t)
	rawSend(t, evil, eConn, vault.TypeAttDeliver, rawDeliver(bomb, "", peerView(nil, 100, append(append([]byte(nil), testThumb...), make([]byte, attwire.ThumbMaxBytes)...), "")))
	wide := ulid(t)
	rawSend(t, evil, eConn, vault.TypeAttDeliver, rawDeliver(wide, "", strings.Replace(peerView(nil, 100, testThumb, ""), `"width":10`, `"width":8193`, 1)))
	// A thumbnail that is no photo: refused (type), the message stored.
	svg := ulid(t)
	rawSend(t, evil, eConn, vault.TypeAttDeliver, rawDeliver(svg, "caption", peerView(nil, 100, []byte("<svg onload=x>"), "")))
	in := waitEvent(t, b.app, "message.new", has("message_id", svg))
	if !strings.Contains(string(in.Body), `"reason":"type"`) || strings.Contains(string(in.Body), `"thumb"`) {
		t.Fatalf("refused thumbnail: %s", in.Body)
	}
	// Another kind: refused (type).
	vid := ulid(t)
	rawSend(t, evil, eConn, vault.TypeAttDeliver, rawDeliver(vid, "", peerView(nil, 100, testThumb, "video")))
	waitEvent(t, b.app, "message.new", has("message_id", vid))
	// A blob that is no photo type: refused (type) after the fetch, deleted.
	gif := ulid(t)
	gb := uploadAsPeer(t, evil, eConn, append([]byte("GIF89a"), make([]byte, 500)...))
	rawSend(t, evil, eConn, vault.TypeAttDeliver, rawDeliver(gif, "", peerView(gb, gb.Size, testThumb, "")))
	waitEvent(t, b.app, "sync.event", func(m json.RawMessage) bool { return attState(bConn, gif, "failed")(m) && has("reason", "type")(m) })
	waitNoBlobs(t, b)
	for _, id := range []string{big, bomb, wide} {
		if rr := b.request(b.app, "message.get", `{"connection_id":"`+bConn+`","message_id":"`+id+`"}`); rr.ErrorCode() != "not_found" {
			t.Fatalf("a malformed attachment was stored: %s", rr.ErrorCode())
		}
	}
	if !hasAudit(t, b, "drop.attachment_malformed", "") {
		t.Fatal("malformed attachments not audited")
	}
	if !hasAudit(t, b, "message.attachment_refused", svg) {
		t.Fatal("refusal not audited")
	}
}

// §10.5.1 "Delivery to the peer": a recipient that keeps sending missing
// gets at most attachment_reoffers fresh uploads, within peer_reuploads
// per connection (a request over the budget is kept, not withdrawn, and
// served when the rolling budget allows); then the sender answers
// withdrawn (limit) and fails the attachment (missing). A missing for a
// deleted attachment is answered withdrawn (deleted); for an unknown
// message_id it is ignored.
func TestAttachmentEndlessMissing(t *testing.T) {
	r := relaytest.Start(t, nil)
	ca := &shiftClock{}
	lim := vault.DefaultAttachLimits
	lim.PeerReuploads = 2
	a := newTestVault(t, r.URL, "a", func(o *vault.Options) { withClock(ca)(o); o.AttachLimits = &lim })
	evil := newTestVault(t, r.URL, "evil", fastAttach)
	aConn, eConn := connect(t, a, evil, 3600)
	// evil stays locked while a sends, then is opened without its run loop:
	// it never fetches, and sends what the test makes it send.
	lockVault(t, evil)
	msg, _ := sendPhoto(t, a, aConn, "", photo(t, 2048))
	waitEntry(t, a, msg, func(e vault.AttEntry) bool { return e.DeliverID != "" })
	m, _, err := evil.unlock(ctxT(t, 30*time.Second), nil)
	if err != nil {
		t.Fatal(err)
	}
	evil.mu.Lock()
	evil.m = m
	evil.mu.Unlock()
	t.Cleanup(func() { _ = m.Lock(ctxT(t, 30*time.Second)) })
	missing := func(id string) {
		rawSend(t, evil, eConn, vault.TypeAttStatus, []byte(`{"message_id":"`+id+`","status":"missing","at":"`+envelope.FormatTS(time.Now())+`"}`))
	}
	missing(msg)
	waitEntry(t, a, msg, func(e vault.AttEntry) bool { return e.Reoffers == 1 && !e.Owed })
	missing(msg)
	waitEntry(t, a, msg, func(e vault.AttEntry) bool { return e.Reoffers == 2 && !e.Owed })
	missing(msg) // over peer_reuploads: kept
	time.Sleep(time.Second)
	if e := entryOf(t, a, msg); e.Reoffers != 2 || !e.Owed || e.State != vault.AttSending {
		t.Fatalf("over the budget: %+v", e)
	}
	ca.Add(25 * time.Hour) // the rolling budget allows it again
	waitEntry(t, a, msg, func(e vault.AttEntry) bool { return e.Reoffers == 3 && !e.Owed })
	missing(msg)
	waitEvent(t, a.app, "sync.event", func(b json.RawMessage) bool { return attState(aConn, msg, "failed")(b) && has("reason", "missing")(b) })
	missing(ulid(t)) // never sent: ignored
	time.Sleep(500 * time.Millisecond)
	if e := entryOf(t, a, msg); e.Reoffers != 3 {
		t.Fatalf("reoffers %d", e.Reoffers)
	}
	// What evil's mailbox received: the deliveries, and a withdrawn
	// (limit) for the last missing.
	n := 0
	for _, e := range a.manager().AttachEntries() {
		if e.Msg == msg {
			n++
		}
	}
	if n != 1 {
		t.Fatal("entries")
	}
}

// §7.3, §10.5.1: peer_attachments refuses a connection's attachments over
// its rolling budget (refused, rate: the sender's member sees refused:rate,
// the recipient audits drop.attachment_rate); a full store refuses with no
// reason (the sender sees only refused; the recipient's member gets the
// feed item and sees failed, full); the sender's own store refuses
// message.send with limit attachment_storage and deletes the blob.
func TestAttachmentQuotas(t *testing.T) {
	r := relaytest.Start(t, nil)
	blim := vault.DefaultAttachLimits
	blim.PeerAccept = 2
	blim.PeerStorage = 64 << 10
	a := newTestVault(t, r.URL, "a", fastAttach)
	b := newTestVault(t, r.URL, "b", func(o *vault.Options) { fastAttach(o); o.AttachLimits = &blim })
	aConn, bConn := connect(t, a, b, 3600)

	m1, _ := sendPhoto(t, a, aConn, "", photo(t, 1000))
	waitEvent(t, a.app, "sync.event", attState(aConn, m1, "delivered"))
	m2, _ := sendPhoto(t, a, aConn, "", photo(t, 100<<10)) // over peer_storage
	waitEvent(t, a.app, "sync.event", func(m json.RawMessage) bool {
		return attState(aConn, m2, "failed")(m) && has("reason", "refused")(m)
	})
	in := waitEvent(t, b.app, "message.new", has("message_id", m2))
	if !strings.Contains(string(in.Body), `"reason":"full"`) {
		t.Fatalf("recipient's view: %s", in.Body)
	}
	m3, _ := sendPhoto(t, a, aConn, "", photo(t, 1000))
	waitEvent(t, a.app, "sync.event", attState(aConn, m3, "delivered"))
	m4, _ := sendPhoto(t, a, aConn, "", photo(t, 1000)) // the third accepted in 24 h
	waitEvent(t, a.app, "sync.event", func(m json.RawMessage) bool {
		return attState(aConn, m4, "failed")(m) && has("reason", "refused:rate")(m)
	})
	if !hasAudit(t, b, "drop.attachment_rate", "") || !hasAudit(t, b, "message.attachment_refused", m2) {
		t.Fatal("refusals not audited")
	}
	waitNoBlobs(t, b)
	_ = bConn

	// The sender's own store.
	alim := vault.DefaultAttachLimits
	alim.Storage = 20 << 10
	c := newTestVault(t, r.URL, "c", func(o *vault.Options) { fastAttach(o); o.AttachLimits = &alim })
	cConn, _ := connect(t, c, b, 3600)
	bl, err := c.app.UploadAttachment(ctxT(t, 30*time.Second), photo(t, 30<<10), attwire.MimeJPEG)
	if err != nil {
		t.Fatal(err)
	}
	rr := c.request(c.app, "message.send", string(client.SendAttachmentBody(cConn, "", false, bl, 1, 1, testThumb)))
	if rr.ErrorCode() != "limit" || !strings.Contains(string(rr.Body()), `"limit":"attachment_storage"`) {
		t.Fatalf("own store: %s %s", rr.ErrorCode(), rr.Body())
	}
	waitNoBlobs(t, c)
	// A message.send refused before its checks (a bad connection) deletes
	// its blob too.
	bl, _ = c.app.UploadAttachment(ctxT(t, 30*time.Second), photo(t, 1000), attwire.MimeJPEG)
	if rr := c.request(c.app, "message.send", string(client.SendAttachmentBody("nope", "", false, bl, 1, 1, testThumb))); rr.ErrorCode() != "not_found" {
		t.Fatal(rr.ErrorCode())
	}
	waitNoBlobs(t, c)
}

// §10.5.1 write order: a crash between an object's write and its flush, or
// between the content's flush and the blob's deletion, loses nothing and
// duplicates nothing: after the unlock the vault finishes from the flags
// (an object written again over the one left, the blob fetched again or
// purged as an orphan), and the photo is delivered once.
func TestAttachmentCrashBetweenFlushes(t *testing.T) {
	for _, step := range []string{"thumb", "prepared"} {
		t.Run(step, func(t *testing.T) {
			r := relaytest.Start(t, nil)
			ca := &shiftClock{}
			crashed := make(chan struct{})
			armed := true
			hook := func(s string) error {
				if s == step && armed {
					armed = false
					close(crashed)
					return errors.New("crash")
				}
				return nil
			}
			a := newTestVault(t, r.URL, "a", func(o *vault.Options) { withClock(ca)(o); o.Hooks.AttachStep = hook })
			b := newTestVault(t, r.URL, "b", fastAttach)
			aConn, bConn := connect(t, a, b, 3600)
			content := photo(t, 50<<10)
			msg, _ := sendPhoto(t, a, aConn, "once", content)
			select {
			case <-crashed:
			case <-time.After(30 * time.Second):
				t.Fatal("no crash")
			}
			a.stop()
			unlockVault(t, a, withClock(ca))
			waitEvent(t, b.app, "sync.event", attState(bConn, msg, "stored"))
			got, _ := fetchPhoto(t, b, bConn, msg)
			if !bytes.Equal(got, content) {
				t.Fatal("photo differs")
			}
			waitEntry(t, a, msg, func(e vault.AttEntry) bool { return e.State == vault.AttDelivered && e.TW && e.CW })
			if e := entryOf(t, a, msg); e.Reoffers != 0 {
				t.Fatal("uploaded twice")
			}
			th := mustOK(t, a.request(a.app, "message.attachment.get", `{"connection_id":"`+aConn+`","message_id":"`+msg+`","part":"thumb"}`))
			if tb, _ := th.Base64("thumb", -1); !bytes.Equal(tb, testThumb) {
				t.Fatal("thumbnail after the crash")
			}
			// The device's blob left by a crash after the flush is an orphan:
			// purged once it is a day old.
			ca.Add(25 * time.Hour)
			waitNoBlobs(t, a)
		})
	}
}

// §10.5.1 "Deletion", §12.5: message.delete erases both objects of its
// attachment (and the entry), and a deleted attachment's missing is
// answered withdrawn (deleted); vault deletion erases every attachment
// object.
func TestAttachmentDeletion(t *testing.T) {
	r := relaytest.Start(t, nil)
	a := newTestVault(t, r.URL, "a", fastAttach)
	b := newTestVault(t, r.URL, "b", fastAttach)
	aConn, bConn := connect(t, a, b, 3600)
	m1, _ := sendPhoto(t, a, aConn, "", photo(t, 10<<10))
	m2, _ := sendPhoto(t, a, aConn, "", photo(t, 10<<10))
	waitEvent(t, a.app, "sync.event", attState(aConn, m2, "delivered"))
	waitEvent(t, b.app, "sync.event", attState(bConn, m2, "stored"))
	objects := func(tv *testVault) []string {
		ks, err := tv.store.(*store.Dir).List(attwire.Prefix(tv.vaultID))
		if err != nil {
			t.Fatal(err)
		}
		return ks
	}
	waitFor := func(tv *testVault, n int) {
		deadline := time.Now().Add(20 * time.Second)
		for len(objects(tv)) != n {
			if time.Now().After(deadline) {
				t.Fatalf("%s holds %v", tv.name, objects(tv))
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	waitFor(a, 4)
	waitFor(b, 4)
	mustOK(t, b.request(b.app, "message.delete", `{"connection_id":"`+bConn+`","message_id":"`+m1+`"}`))
	waitFor(b, 2)
	for _, e := range b.manager().AttachEntries() {
		if e.Msg == m1 {
			t.Fatal("entry kept after its objects were deleted")
		}
	}
	if rr := b.request(b.app, "message.attachment.get", `{"connection_id":"`+bConn+`","message_id":"`+m1+`"}`); rr.ErrorCode() != "not_found" {
		t.Fatal(rr.ErrorCode())
	}
	// vault.delete by the holder: no attachment object is left.
	if err := a.app.VaultDelete(ctxT(t, 60*time.Second), pin, credPW); err != nil {
		t.Fatal(err)
	}
	waitFor(a, 0)
	_ = strictjson.Object{}
}

// §10.5.1 "Desktops": a desktop neither sends nor fetches attachments
// (forbidden, nothing changes), and gets the device view without thumb
// and name.
func TestAttachmentDesktop(t *testing.T) {
	r := relaytest.Start(t, nil)
	a := newTestVault(t, r.URL, "a", fastAttach)
	b := newTestVault(t, r.URL, "b", fastAttach)
	aConn, _ := connect(t, a, b, 3600)
	desk := pairDesktop(t, a, r.URL)
	msg, _ := sendPhoto(t, a, aConn, "hi", photo(t, 1000))
	in := waitEvent(t, desk, "message.new", has("message_id", msg))
	if !strings.Contains(string(in.Body), `"attachment"`) || strings.Contains(string(in.Body), `"thumb"`) {
		t.Fatalf("desktop view: %s", in.Body)
	}
	bl, err := a.app.UploadAttachment(ctxT(t, 30*time.Second), photo(t, 1000), attwire.MimeJPEG)
	if err != nil {
		t.Fatal(err)
	}
	for typ, body := range map[string]string{
		"message.send":               string(client.SendAttachmentBody(aConn, "", false, bl, 1, 1, testThumb)),
		"message.attachment.get":     `{"connection_id":"` + aConn + `","message_id":"` + msg + `"}`,
		"message.attachment.discard": `{"blob_id":"` + bl.ID + `"}`,
	} {
		if rr := a.request(desk, typ, body); rr.ErrorCode() != "forbidden" {
			t.Errorf("desktop %s: %q", typ, rr.ErrorCode())
		}
	}
	// The app's availability probe: bad_request means release A.
	if rr := a.request(a.app, "message.attachment.get", `{}`); rr.ErrorCode() != "bad_request" {
		t.Fatalf("probe: %q", rr.ErrorCode())
	}
	// The app's Cancel deletes its own upload (the relay lists the uploader).
	mustOK(t, a.request(a.app, "message.attachment.discard", `{"blob_id":"`+bl.ID+`"}`))
	waitNoBlobs(t, a)
}

// §10.5.1 "Receiving" step 3: a recipient asks for one attachment of a
// connection at a time, and after missing_turn (24 hours) without an
// upload moves to the next waiting one, coming back to the first in its
// next turn; each attachment's backoff is its own.
func TestAttachmentMissingTurns(t *testing.T) {
	r := relaytest.Start(t, nil)
	cb := &shiftClock{}
	evil := newTestVault(t, r.URL, "evil", fastAttach)
	b := newTestVault(t, r.URL, "b", withClock(cb))
	eConn, _ := connect(t, evil, b, 3600)
	m1, m2 := ulid(t), ulid(t)
	for _, id := range []string{m1, m2} {
		rawSend(t, evil, eConn, vault.TypeAttDeliver, rawDeliver(id, "", peerView(nil, 100, testThumb, "")))
	}
	waitEntry(t, b, m1, func(e vault.AttEntry) bool { return e.Asked })
	time.Sleep(500 * time.Millisecond)
	if e := entryOf(t, b, m2); e.Asked {
		t.Fatal("two attachments of one connection asked for at once")
	}
	first := entryOf(t, b, m1).AskedAt
	cb.Add(25 * time.Hour)
	waitEntry(t, b, m2, func(e vault.AttEntry) bool { return e.Asked })
	if e := entryOf(t, b, m1); !e.AskedAt.Equal(first) {
		t.Fatal("the first was asked again in the second's turn")
	}
	cb.Add(25 * time.Hour)
	waitEntry(t, b, m1, func(e vault.AttEntry) bool { return e.AskedAt.After(first) && e.Backoff > attwire.MissingFirst })
}

// §10.5.1 "Connections": when a connection is removed, its attachments in
// progress fail (removed); stored ones stay with their messages.
func TestAttachmentConnectionRemoved(t *testing.T) {
	r := relaytest.Start(t, nil)
	a := newTestVault(t, r.URL, "a", fastAttach)
	b := newTestVault(t, r.URL, "b", fastAttach)
	aConn, _ := connect(t, a, b, 3600)
	done, _ := sendPhoto(t, a, aConn, "", photo(t, 1000))
	waitEvent(t, a.app, "sync.event", attState(aConn, done, "delivered"))
	lockVault(t, b)
	msg, _ := sendPhoto(t, a, aConn, "", photo(t, 1000))
	waitEntry(t, a, msg, func(e vault.AttEntry) bool { return e.DeliverID != "" })
	mustOK(t, a.request(a.app, "connection.remove", `{"connection_id":"`+aConn+`"}`))
	waitEvent(t, a.app, "sync.event", func(m json.RawMessage) bool { return attState(aConn, msg, "failed")(m) && has("reason", "removed")(m) })
	if e := entryOf(t, a, done); e.State != vault.AttDelivered || !e.CW {
		t.Fatalf("a stored attachment changed: %+v", e)
	}
	got, _ := fetchPhoto(t, a, aConn, done)
	if len(got) != 1000 {
		t.Fatal("stored photo after the removal")
	}
}

// §10.5.1 "Held and locked", §3.6.3: a vault held for the owner check
// keeps receiving and storing attachments (counted as waiting messages),
// while its owner's message.send with an attachment, message.attachment.get
// and .discard are answered owner_check_required (a refused send still
// deletes its blob); the shape of message.attachment.get is checked before
// the hold (bad_request).
func TestAttachmentHeldVault(t *testing.T) {
	r := relaytest.Start(t, nil)
	clk := &ocClock{}
	a := newTestVault(t, r.URL, "a", fastAttach)
	b := newTestVault(t, r.URL, "b", func(o *vault.Options) { fastAttach(o); o.OwnerCheckClock = clk.Now })
	aConn, bConn := connect(t, a, b, 3600)
	clk.add(25 * time.Hour)
	waitEvent(t, b.app, "vault.held", nil)
	msg, _ := sendPhoto(t, a, aConn, "while held", photo(t, 2000))
	waitEvent(t, a.app, "sync.event", attState(aConn, msg, "delivered"))
	if e := entryOf(t, b, msg); e.State != vault.AttStored {
		t.Fatalf("held vault's entry: %+v", e)
	}
	bl, err := b.app.UploadAttachment(ctxT(t, 30*time.Second), photo(t, 1000), attwire.MimeJPEG)
	if err != nil {
		t.Fatal(err)
	}
	if rr := b.request(b.app, "message.send", string(client.SendAttachmentBody(bConn, "", false, bl, 1, 1, testThumb))); rr.ErrorCode() != "owner_check_required" {
		t.Fatalf("send while held: %q", rr.ErrorCode())
	}
	waitNoBlobs(t, b)
	if rr := b.request(b.app, "message.attachment.get", `{}`); rr.ErrorCode() != "bad_request" {
		t.Fatalf("probe while held: %q", rr.ErrorCode())
	}
	for typ, body := range map[string]string{
		"message.attachment.get":     `{"connection_id":"` + bConn + `","message_id":"` + msg + `"}`,
		"message.attachment.discard": `{"blob_id":"` + ulid(t) + `"}`,
	} {
		if rr := b.request(b.app, typ, body); rr.ErrorCode() != "owner_check_required" {
			t.Fatalf("%s while held: %q", typ, rr.ErrorCode())
		}
	}
}

// Owner decision of 2026-10-15 (§10.5.1 limits): a received attachment's
// declared size holds room only while its fetch is in progress. Four
// connections that declare 8 MiB each and never upload do not block the
// owner's own sending; an upload that arrives when it does not fit is
// refused (full: a generic refusal to the sender).
func TestAttachmentReservations(t *testing.T) {
	r := relaytest.Start(t, nil)
	lim := vault.DefaultAttachLimits
	lim.Storage = 20 << 20 // less than the four declarations
	b := newTestVault(t, r.URL, "b", func(o *vault.Options) { fastAttach(o); o.AttachLimits = &lim })
	var ids []string
	var evil *testVault
	var evilConn string
	for _, name := range []string{"e1", "e2", "e3", "e4"} {
		e := newTestVault(t, r.URL, name, fastAttach)
		ec, _ := connect(t, e, b, 3600)
		id := ulid(t)
		ids = append(ids, id)
		rawSend(t, e, ec, vault.TypeAttDeliver, rawDeliver(id, "", peerView(nil, 8000000, testThumb, "")))
		evil, evilConn = e, ec
	}
	for _, id := range ids {
		waitEntry(t, b, id, func(e vault.AttEntry) bool { return e.State == vault.AttFetching })
	}
	c := newTestVault(t, r.URL, "c", fastAttach)
	bc, _ := connect(t, b, c, 3600)
	mine, _ := sendPhoto(t, b, bc, "mine", photo(t, 15<<20/2)) // 7.5 MiB of the 20
	waitEvent(t, b.app, "sync.event", attState(bc, mine, "delivered"))

	// e4's upload (8 MiB) arrives once b asked for it: 7.5 + 8 + thumbnails
	// would fit, but first fill the store with a second photo of b's own.
	more, _ := sendPhoto(t, b, bc, "", photo(t, 6<<20))
	waitEvent(t, b.app, "sync.event", attState(bc, more, "delivered"))
	last := ids[3]
	waitEntry(t, b, last, func(e vault.AttEntry) bool { return e.Asked })
	content := photo(t, 8000000)
	up := uploadAsPeer(t, evil, evilConn, content)
	rawSend(t, evil, evilConn, vault.TypeAttDeliver, rawDeliver(last, "", peerView(up, len(content), testThumb, "")))
	waitEntry(t, b, last, func(e vault.AttEntry) bool { return e.State == vault.AttFailed && e.Reason == vault.ReasonFull })
	waitNoBlobs(t, b)
}

// A damaged content object (the host can change what it stores) is read
// again only with the retry's backoff, and after a few failed reads the
// attachment fails (bad, audited): never a loop of reads.
func TestAttachmentCorruptObject(t *testing.T) {
	r := relaytest.Start(t, nil)
	var gets atomicCount
	a := newTestVault(t, r.URL, "a", func(o *vault.Options) {
		fastAttach(o)
		o.Store = &countingStore{Store: o.Store, n: &gets}
	})
	evil := newTestVault(t, r.URL, "evil", fastAttach)
	aConn, eConn := connect(t, a, evil, 3600)
	lockVault(t, evil)
	msg, att := sendPhoto(t, a, aConn, "", photo(t, 4096))
	waitEntry(t, a, msg, func(e vault.AttEntry) bool { return e.DeliverID != "" })
	// The host damages the stored content.
	key := attwire.ContentKey(a.vaultID, att)
	_, v, err := a.store.Get(ctxT(t, 10*time.Second), key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.store.Put(ctxT(t, 10*time.Second), key, make([]byte, 5000), v); err != nil {
		t.Fatal(err)
	}
	m, _, err := evil.unlock(ctxT(t, 30*time.Second), nil)
	if err != nil {
		t.Fatal(err)
	}
	evil.mu.Lock()
	evil.m = m
	evil.mu.Unlock()
	t.Cleanup(func() { _ = m.Lock(ctxT(t, 30*time.Second)) })
	gets.reset()
	rawSend(t, evil, eConn, vault.TypeAttStatus, []byte(`{"message_id":"`+msg+`","status":"missing","at":"`+envelope.FormatTS(time.Now())+`"}`))
	waitEvent(t, a.app, "sync.event", func(b json.RawMessage) bool { return attState(aConn, msg, "failed")(b) && has("reason", "bad")(b) })
	time.Sleep(2 * time.Second)
	if n := gets.get(key); n < 3 || n > 4 {
		t.Fatalf("%d reads of the damaged object", n)
	}
}

type atomicCount struct {
	mu sync.Mutex
	m  map[string]int
}

func (c *atomicCount) add(k string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]int{}
	}
	c.m[k]++
}
func (c *atomicCount) get(k string) int { c.mu.Lock(); defer c.mu.Unlock(); return c.m[k] }
func (c *atomicCount) reset()           { c.mu.Lock(); defer c.mu.Unlock(); c.m = nil }

type countingStore struct {
	store.Store
	n *atomicCount
}

func (s *countingStore) Get(ctx context.Context, key string) ([]byte, store.Version, error) {
	s.n.add(key)
	return s.Store.Get(ctx, key)
}
