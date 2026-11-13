package vault

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vault/store"
	"github.com/vettid/vettid-vault/vms/attwire"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// The review's round on the rotating side: the switch's guard, blobs in
// an old mailbox, revocations to the issuing mailbox, the collector's
// waits, and the recovery open's attempt without the cost tag.

// The switch alone makes or opens no vault: relay.address.update and
// relay.mailbox.closed are not sent yet. Tests set the companion.
func TestRelayRotSwitchNeedsTheUnfinishedCompanion(t *testing.T) {
	f := newFixture(t)
	o := f.opts
	o.RelayKeyRotation = true
	k, err := MinKDF()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Create(context.Background(), CreateParams{Options: o, UserGUID: "u2", PIN: testPIN, UnlockSecret: testSecret, KDF: k,
		RelayURL: "https://relay.example.org"}); !errors.Is(err, ErrRelayKeyRotationUnfinished) {
		t.Fatalf("create: %v", err)
	}
	_ = f.m.Lock(context.Background())
	if _, _, err := Unlock(context.Background(), UnlockParams{Options: o, VaultID: f.vid, PIN: testPIN, UnlockSecret: testSecret}); !errors.Is(err, ErrRelayKeyRotationUnfinished) {
		t.Fatalf("unlock: %v", err)
	}
	o.RelayKeyRotationUnfinished = true
	m, _, err := Unlock(context.Background(), UnlockParams{Options: o, VaultID: f.vid, PIN: testPIN, UnlockSecret: testSecret})
	if err != nil {
		t.Fatal(err)
	}
	m.Crash()
}

// A blob put in the old mailbox (an attachment deposited to K before the
// second write, or during the 13 days) is fetched and deleted with K's key
// after the second write; once K's collects have ended it is unknown, as
// a blob the relay does not have.
func TestRelayRotBlobInTheOldMailbox(t *testing.T) {
	fx, old, cur := rotated(t)
	content := append([]byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}, bytes.Repeat([]byte{7}, 64)...)
	data, key, sum, err := envelope.SealBlob(content)
	if err != nil {
		t.Fatal(err)
	}
	fx.w.mu.Lock()
	fx.w.blobs[old] = map[string][]byte{"B1": data}
	fx.w.mu.Unlock()
	b := AttBlob{ID: "B1", Key: key, SHA256: sum[:], Size: len(content), Mailbox: old}
	got, _, why, err := fx.m.fetchBlob(context.Background(), b, 0)
	if err != nil || !bytes.Equal(got, content) {
		t.Fatalf("fetch from the old mailbox: %q %v", why, err)
	}
	// A message collected from the old mailbox names its blobs there.
	fx.do(func(m *Manager) {
		m.msgMailbox = old
		if mb := m.blobMailbox(); mb != old {
			t.Fatalf("blob mailbox %q", mb)
		}
		m.msgMailbox = ""
		if mb := m.blobMailbox(); mb != cur {
			t.Fatalf("blob mailbox outside a batch %q", mb)
		}
	})
	fx.m.deleteBlobIn(context.Background(), old, "B1")
	if rels := fx.m.ownRelays(); len(rels) != 2 {
		t.Fatalf("own relays %d: the old mailbox's blobs are not reached", len(rels))
	}
	fx.w.mu.Lock()
	dels := strings.Join(fx.w.blobDeletes, ",")
	fx.w.mu.Unlock()
	if dels != old+"/B1" {
		t.Fatalf("deletes %v", dels)
	}
	fx.w.mu.Lock()
	fx.w.blobs[old]["B1"] = data // still there at the relay
	fx.w.mu.Unlock()
	fx.setClk(fx.old(0).Anchor.Add(OldMailboxStop))
	fx.batch() // the stop
	if _, _, why, _ := fx.m.fetchBlob(context.Background(), b, 0); why != "unknown" {
		t.Fatalf("after the stop: %q", why)
	}
	if rels := fx.m.ownRelays(); len(rels) != 1 {
		t.Fatal("a stopped mailbox's blobs are still reached")
	}
}

// §3.4.1 S7: a token is revoked at the mailbox that issued it, an old
// one with the old key; a sender's key at every mailbox the vault keeps.
func TestRelayRotRevocationsGoToTheIssuingMailbox(t *testing.T) {
	fx, old, cur := rotated(t)
	fx.do(func(m *Manager) {
		m.st.Issued = append(m.st.Issued, IssuedToken{JTI: "j-old", Kind: TokStanding, Iss: old}, IssuedToken{JTI: "j-cur", Kind: TokStanding, Iss: cur})
		for _, v := range []string{"j-old", "j-cur"} {
			if err := m.revoke(context.Background(), "jti", v); err != nil {
				t.Fatal(err)
			}
		}
		if err := m.revoke(context.Background(), "sub", "S"); err != nil {
			t.Fatal(err)
		}
	})
	fx.w.mu.Lock()
	got := strings.Join(fx.w.revokes, ",")
	fx.w.mu.Unlock()
	want := old + ":jti:j-old," + cur + ":jti:j-cur," + cur + ":sub:S," + old + ":sub:S"
	if got != want {
		t.Fatalf("revokes %s, want %s", got, want)
	}
}

// With no current mailbox to long-poll (its collects ended while a key is
// pending) and an old one still collected, a round that releases nothing
// waits as a long-poll would.
func TestRelayRotCollectorWaitsWithoutTheCurrentMailbox(t *testing.T) {
	w := newRotWorld()
	c := &multiCollector{parts: []*collectPart{{mailbox: "old", c: &rotCollector{w: w, mb: "old"}}}, from: map[string]*collectPart{},
		now: time.Now, idle: 80 * time.Millisecond, gone: func(string) {}, stopped: func(string) bool { return false },
		given: func(string, []string) {}}
	t0 := time.Now()
	if _, err := c.Next(context.Background()); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(t0); d < 80*time.Millisecond {
		t.Fatalf("returned after %v", d)
	}
}

// A WebSocket batch ends on a time window, not at the relay's max: its
// collected-to never moves, and while an old mailbox is collected the
// current one is collected over HTTP.
func TestRelayRotWebSocketDoesNotMoveCollectedTo(t *testing.T) {
	w := newRotWorld()
	p := &collectPart{mailbox: "cur", c: &rotCollector{w: w, mb: "cur"}, main: true, stream: true}
	c := &multiCollector{parts: []*collectPart{p}, from: map[string]*collectPart{}, now: time.Now, idle: time.Millisecond,
		gone: func(string) {}, stopped: func(string) bool { return false }, given: func(string, []string) {}}
	if _, err := c.Next(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !p.to.IsZero() {
		t.Fatal("a WebSocket batch moved collected-to")
	}
	fx, _, cur := rotated(t)
	fx.do(func(m *Manager) {
		m.opt.WebSocket = true
		m.resetCollector()
	})
	fx.step()
	fx.w.mu.Lock()
	ws, asked := fx.w.wsAsked[cur]
	fx.w.mu.Unlock()
	if !asked || ws {
		t.Fatalf("websocket for the current mailbox (asked %v) while an old one is collected", asked)
	}
}

// A full batch (the relay's max) does not move a mailbox's collected-to:
// what it holds back waits for a collect that returns fewer.
func TestRelayRotFullBatchDoesNotMoveCollectedTo(t *testing.T) {
	fx, old, _ := rotated(t)
	for i := range MaxBatch + 1 {
		fx.w.put(old, fmt.Sprintf("01%03d", i), fx.clk.Add(-time.Hour), []byte("x"))
	}
	if n := fx.step(); n != 0 {
		t.Fatalf("released %d after a full batch", n)
	}
	if n := fx.step(); n != MaxBatch {
		t.Fatalf("released %d once fewer than max came back", n)
	}
}

// credential.rotate while a key is pending and not refused keeps that key
// (§3.4 "A rotation made while a relay key is pending (a
// credential.rotate, ...) keeps the pending relay key").
func TestRelayRotCredentialRotateKeepsANonRefusedPendingKey(t *testing.T) {
	fx := newRotFx(t)
	fx.w.rotate = []error{relayErr(503, ""), relayErr(503, "")}
	if err := fx.credRotate(); err != nil {
		t.Fatal(err)
	}
	k1 := fx.pendingMailbox()
	if err := fx.credRotate(); err != nil {
		t.Fatal(err)
	}
	if fx.pendingMailbox() != k1 {
		t.Fatal("credential.rotate replaced a pending key not refused")
	}
}

// A recovery's open, without the cost tag: the inherited key is completed
// in its one attempt; a retry_after still running makes none.
func TestRelayRotInheritedAttemptAtTheOpenUnit(t *testing.T) {
	fx := newRotFx(t)
	fx.w.rotate = []error{relayErr(503, "")}
	if err := fx.credRotate(); err != nil {
		t.Fatal(err)
	}
	p := fx.pendingMailbox()
	fx.do(func(m *Manager) {
		m.st.Relay.Pending.RetryAfter = fx.clk.Add(time.Hour)
		m.inheritedKeyAtOpen(context.Background(), RecoveryOpenParams{Options: fx.fixture.opts}, fx.clk)
	})
	if rot, _ := fx.w.log(); len(rot) != 1 || fx.pendingMailbox() != p {
		t.Fatalf("attempted while retry_after runs: %v", rot)
	}
	fx.do(func(m *Manager) {
		m.st.Relay.Pending.RetryAfter = time.Time{}
		m.inheritedKeyAtOpen(context.Background(), RecoveryOpenParams{Options: fx.fixture.opts}, fx.clk)
	})
	if fx.mailbox() != p || fx.pending() != nil {
		t.Fatal("the open's attempt did not complete the inherited key")
	}
}

// A blob call (§10.19.8) from a message collected from the old mailbox
// fetches and deletes its blob there, with the old key.
func TestRelayRotBlobCallFromTheOldMailbox(t *testing.T) {
	fx, old, _ := rotated(t)
	st := &blobStub{}
	fx.do(func(m *Manager) {
		m.addFeature(st)
		max, ttl := int64(1<<24), int64(3600)
		m.limits.MaxBlobBytes, m.limits.BlobTTLSeconds = &max, &ttl
	})
	data, k, s, err := envelope.SealBlob([]byte("hello blob"))
	if err != nil {
		t.Fatal(err)
	}
	fx.w.mu.Lock()
	fx.w.blobs[old] = map[string][]byte{"B2": data}
	fx.w.mu.Unlock()
	body := `{"id":"B2","key":"` + base64.StdEncoding.EncodeToString(k) + `","sha256":"` + base64.StdEncoding.EncodeToString(s[:]) + `","size":10}`
	id, _ := envelope.NewULID(time.Now())
	raw, err := fx.ep.Seal(&envelope.Inner{ID: id, Type: "test.blobcall", TS: time.Now(), Body: []byte(body)})
	if err != nil {
		t.Fatal(err)
	}
	if err := fx.m.ProcessBatch(context.Background(), &oneMailboxCollector{mb: old}, []Message{{MsgID: "r1", Sender: fx.devSender(), Payload: raw}}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, x := range fx.appInbox() {
			if x.Re == id {
				if x.Status != envelope.StatusOK || !strings.Contains(string(x.Body), `"len":10`) {
					t.Fatalf("%+v %s", x, x.Body)
				}
				fx.w.mu.Lock()
				defer fx.w.mu.Unlock()
				if strings.Join(fx.w.blobDeletes, ",") != old+"/B2" {
					t.Fatalf("deletes %v", fx.w.blobDeletes)
				}
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("no answer")
}

// The attachment paths that name a blob record the own mailbox their
// message was collected from: a peer's attachment received (AttachReceive)
// from K before the second write is fetched after it with K's key; a
// re-upload (AttachRedeliver) and a device's send (AttachSend) collected
// from the old mailbox during the 13 days name it too.
func TestRelayRotAttachmentPathsRecordTheirMailbox(t *testing.T) {
	fx := newRotFx(t)
	k := fx.mailbox()
	content := append([]byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}, bytes.Repeat([]byte{9}, 64)...)
	data, key, sum, err := envelope.SealBlob(content)
	if err != nil {
		t.Fatal(err)
	}
	view := func(id string) *attwire.PeerView {
		return &attwire.PeerView{Kind: attwire.KindPhoto, Size: len(content), Width: 1, Height: 1,
			Blob: &attwire.Blob{ID: id, Key: key, SHA256: sum, Size: len(content), Mime: "image/png"}}
	}
	session := func(m *Manager, id string) *Session {
		p := m.peer(id)
		return &Session{m: m, peer: p, host: managerHost{m}, from: info(p), now: m.now()}
	}
	var attID string
	fx.do(func(m *Manager) {
		m.attStop() // the test fetches itself
		var refused *AttView
		if attID, refused = (managerHost{m}).AttachReceive(session(m, "c1"), "msg-1", view("B3")); refused != nil {
			t.Fatalf("refused %+v", refused)
		}
	})
	if err := fx.credRotate(); err != nil { // the second write: K is old
		t.Fatal(err)
	}
	if fx.mailbox() == k {
		t.Fatal("not rotated")
	}
	fx.w.mu.Lock()
	fx.w.blobs[k] = map[string][]byte{"B3": data}
	fx.w.mu.Unlock()
	var b AttBlob
	fx.do(func(m *Manager) { b = *m.st.Attach.Entries[attID].Blob })
	if b.Mailbox != k {
		t.Fatalf("received blob's mailbox %q, want %q", b.Mailbox, k)
	}
	if got, _, why, err := fx.m.fetchBlob(context.Background(), b, 0); err != nil || !bytes.Equal(got, content) {
		t.Fatalf("fetch after the second write: %q %v", why, err)
	}
	fx.do(func(m *Manager) {
		// A re-upload the vault asked for, collected from the old mailbox.
		e := m.st.Attach.Entries[attID]
		e.State, e.Asked, e.Blob = AttFetching, true, nil
		m.msgMailbox = k
		(managerHost{m}).AttachRedeliver(session(m, "c1"), "msg-1", view("B4"))
		if e.Blob == nil || e.Blob.ID != "B4" || e.Blob.Mailbox != k {
			t.Fatalf("redelivered blob %+v", e.Blob)
		}
		// A device's send, collected from the old mailbox.
		d := &attwire.DeviceSend{Blob: &attwire.Blob{ID: "B5", Key: key, SHA256: sum, Size: len(content), Mime: "image/png"},
			Kind: attwire.KindPhoto, Width: 1, Height: 1}
		id, err := (managerHost{m}).AttachSend(session(m, "dev1"), "c1", "msg-2", m.now(), "", false, d)
		if err != nil {
			t.Fatal(err)
		}
		if mb := m.st.Attach.Entries[id].Blob.Mailbox; mb != k {
			t.Fatalf("sent blob's mailbox %q", mb)
		}
		m.msgMailbox = ""
	})
}

// countingStore counts reads.
type countingStore struct {
	store.Store
	mu    sync.Mutex
	reads int
}

func (s *countingStore) Get(ctx context.Context, key string) ([]byte, store.Version, error) {
	s.mu.Lock()
	s.reads++
	s.mu.Unlock()
	return s.Store.Get(ctx, key)
}

// RecoveryOpen with the switch and without its companion refuses before it
// reads anything (no attempt is spent).
func TestRelayRotRecoveryOpenRefusesWithoutTheCompanion(t *testing.T) {
	f := newFixture(t)
	cs := &countingStore{Store: f.store}
	o := f.opts
	o.Store, o.RelayKeyRotation = cs, true
	m, out := RecoveryOpen(context.Background(), RecoveryOpenParams{Options: o, VaultID: f.vid, UserGUID: "u1", RecoveryID: recID,
		PIN: testPIN, Password: []byte(rPW), UnlockSecret: testSecret})
	if m != nil || out.OK || out.Code != OpenRetry {
		t.Fatalf("open %+v", out)
	}
	if cs.reads != 0 {
		t.Fatalf("read %d objects", cs.reads)
	}
}
