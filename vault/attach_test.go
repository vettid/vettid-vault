package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault/store"
	"github.com/vettid/vettid-vault/vms/attwire"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// sendFrom sends one inner message from td (a request, an event, or with
// re an error response).
func (d *devFixture) sendFrom(t testing.TB, td *tdev, in *envelope.Inner) {
	t.Helper()
	d.seq++
	if in.ID == "" {
		in.ID, _ = envelope.NewULID(time.Now())
	}
	in.TS = time.Now()
	raw, err := td.ep.Seal(in)
	if err != nil {
		t.Fatal(err)
	}
	msg := Message{MsgID: fmt.Sprintf("att%d", d.seq), Sender: relayauth.EncodeKey(td.peer.Relay.PK), Payload: raw}
	if td.peer.Kind == KindConnection {
		msg.JTI = "standing-" + td.peer.ID
	}
	_ = d.m.ProcessBatch(context.Background(), &fakeCollector{}, []Message{msg})
}

// §7.2 (0.32.0): a connection whose standing token is not near its end
// asks after quota_exceeded: a fresh token at most once per 24 hours,
// the old one denylisted; otherwise too_soon {allowed_after}.
func TestTokenRefreshAfterQuota(t *testing.T) {
	d := newDevFixture(t)
	c := d.asConnection(t, "c1", 0x52)
	id := d.sendRaw(t, c, tokenRefreshType, "")
	r := find(d.inbox(c)["c1"], reply(id))
	if r == nil || r.Status != envelope.StatusOK {
		t.Fatalf("first refresh: %+v", r)
	}
	if !d.relayRevoked("jti", "standing-c1") {
		t.Fatal("the old standing token is not denylisted")
	}
	id = d.sendRaw(t, c, tokenRefreshType, "")
	r = find(d.inbox(c)["c1"], reply(id))
	if errCode(r) != "too_soon" || bodyStr(t, r, "allowed_after") == "" {
		t.Fatalf("second refresh within 24 h: %+v", r)
	}
	// The classification is by the latest standing token issued to the
	// peer, not by the one the request came under: an old token near its
	// end (the deposit's jti) mints nothing more within the day.
	d.withLock(func(m *Manager) {
		for i := range m.st.Issued {
			if m.st.Issued[i].JTI == "standing-c1" {
				m.st.Issued[i].Exp = time.Now().Add(24 * time.Hour)
			}
		}
	})
	id = d.sendRaw(t, c, tokenRefreshType, "")
	if r := find(d.inbox(c)["c1"], reply(id)); errCode(r) != "too_soon" {
		t.Fatalf("refresh under an old token: %+v", r)
	}
	// When the latest token itself is near its end (here standing tokens
	// are short, so none is re-minted), a refresh is answered as before
	// (§7.2), at most once an hour.
	d.withLock(func(m *Manager) {
		m.opt.ConnectionStandingTTL = 48 * time.Hour
		for i := range m.st.Issued {
			if m.st.Issued[i].PeerID == "c1" && !m.st.Issued[i].Denied {
				m.st.Issued[i].Exp = time.Now().Add(24 * time.Hour)
			}
		}
	})
	id = d.sendRaw(t, c, tokenRefreshType, "")
	if r := find(d.inbox(c)["c1"], reply(id)); r == nil || r.Status != envelope.StatusOK {
		t.Fatalf("refresh near the end: %+v", r)
	}
	d.withLock(func(m *Manager) {
		for i := range m.st.Issued {
			if m.st.Issued[i].PeerID == "c1" && !m.st.Issued[i].Denied {
				m.st.Issued[i].Exp = time.Now().Add(24 * time.Hour)
			}
		}
	})
	id = d.sendRaw(t, c, tokenRefreshType, "")
	if r := find(d.inbox(c)["c1"], reply(id)); errCode(r) != "too_soon" {
		t.Fatalf("second refresh near the end within the hour: %+v", r)
	}
}

// §10.5.1 (lock path): zeroize wipes every attachment secret the index
// holds (k_att, a blob key, a held thumbnail), and a dropped blob
// reference has its key wiped.
func TestZeroizeWipesAttachmentKeys(t *testing.T) {
	d := newDevFixture(t)
	k, bk, th, dk := []byte{1, 2, 3}, []byte{4, 5, 6}, []byte{7, 8, 9}, []byte{9, 9, 9}
	d.withLock(func(m *Manager) {
		m.st.attach().Entries["01JB2Z6V9K3M4N5P6Q7R8S9T70"] = &AttEntry{ID: "01JB2Z6V9K3M4N5P6Q7R8S9T70", Key: k, Thumb: th,
			Blob: &AttBlob{ID: "01JB2Z6V9K3M4N5P6Q7R8S9T71", Key: bk}, State: AttFetching, Dir: DirIn}
		e := &AttEntry{ID: "01JB2Z6V9K3M4N5P6Q7R8S9T72", Key: []byte{1}, Blob: &AttBlob{ID: "01JB2Z6V9K3M4N5P6Q7R8S9T73", Key: dk}}
		m.dropBlob(e)
		if e.Blob != nil {
			t.Fatal("blob kept")
		}
	})
	if err := d.m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string][]byte{"k_att": k, "blob key": bk, "thumbnail": th, "dropped blob key": dk} {
		for _, x := range b {
			if x != 0 {
				t.Fatalf("%s not wiped: %v", name, b)
			}
		}
	}
}

// §10.5.1: an outgoing attachment owed a fresh upload is failed
// (unconfirmed) and no longer owed when the peer's mailbox refused for
// good, or when missing_window has passed (a connection stale since);
// it is never left owed and unserved.
func TestOwedAttachmentEnds(t *testing.T) {
	d := newDevFixture(t)
	now := time.Now()
	d.withLock(func(m *Manager) {
		a := m.st.attach()
		a.Entries["01JB2Z6V9K3M4N5P6Q7R8S9T70"] = &AttEntry{ID: "01JB2Z6V9K3M4N5P6Q7R8S9T70", Conn: "c1", Msg: "01JB2Z6V9K3M4N5P6Q7R8S9T71", Dir: DirOut,
			State: AttSending, CW: true, Owed: true, Stopped: true, SentAt: now.Add(-time.Hour)}
		a.Entries["01JB2Z6V9K3M4N5P6Q7R8S9T72"] = &AttEntry{ID: "01JB2Z6V9K3M4N5P6Q7R8S9T72", Conn: "c2", Msg: "01JB2Z6V9K3M4N5P6Q7R8S9T73", Dir: DirOut,
			State: AttSending, CW: true, Owed: true, SentAt: now.Add(-attwire.MissingWindow - time.Hour)}
		a.Entries["01JB2Z6V9K3M4N5P6Q7R8S9T74"] = &AttEntry{ID: "01JB2Z6V9K3M4N5P6Q7R8S9T74", Conn: "c2", Msg: "01JB2Z6V9K3M4N5P6Q7R8S9T75", Dir: DirOut,
			State: AttSending, CW: true, Owed: true, SentAt: now.Add(-time.Hour)}
		m.attHousekeeping(now)
		for id, want := range map[string]string{"01JB2Z6V9K3M4N5P6Q7R8S9T70": AttFailed, "01JB2Z6V9K3M4N5P6Q7R8S9T72": AttFailed, "01JB2Z6V9K3M4N5P6Q7R8S9T74": AttSending} {
			e := a.Entries[id]
			if e.State != want || want == AttFailed && (e.Reason != ReasonUnconfirmed || e.Owed) {
				t.Errorf("%s: %s %s owed %v", id, e.State, e.Reason, e.Owed)
			}
		}
	})
}

// blockingStore holds Puts of attachment objects until released.
type blockingStore struct {
	store.Store
	started chan struct{}
	release chan struct{}
}

func (b *blockingStore) Put(ctx context.Context, key string, data []byte, ifMatch store.Version) (store.Version, error) {
	if strings.Contains(key, "/att/") {
		close(b.started)
		<-b.release
	}
	return b.Store.Put(ctx, key, data, ifMatch)
}

// §12.5, P15: a runner's object write under way when the vault is deleted
// lands before the erase, which then deletes it: no object is left after
// the deletion; and nothing is written once the vault is locked.
func TestDeletionWaitsForWrites(t *testing.T) {
	d := newDevFixture(t)
	ctx := context.Background()
	bs := &blockingStore{Store: d.store, started: make(chan struct{}), release: make(chan struct{})}
	id := "01JB2Z6V9K3M4N5P6Q7R8S9T70"
	var r *attRunner
	d.withLock(func(m *Manager) {
		m.opt.Store = bs
		m.attStart(ctx)
		r = m.att
		m.st.attach().Entries[id] = &AttEntry{ID: id, Dir: DirIn, State: AttFetching, Key: make([]byte, 32)}
	})
	key := attwire.ContentKey(d.vid, id)
	go func() { _, _ = d.m.putObject(r, key, []byte("object")) }()
	<-bs.started
	deleted := make(chan error, 1)
	go func() { deleted <- d.m.Delete(ctx) }()
	select {
	case <-deleted:
		t.Fatal("the deletion did not wait for the write")
	case <-time.After(200 * time.Millisecond):
	}
	close(bs.release)
	if err := <-deleted; err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.store.Get(ctx, key); err == nil {
		t.Fatal("an object written during the deletion was left")
	}
	if _, err := d.m.putObject(r, key, []byte("late")); err == nil {
		t.Fatal("a write after the lock")
	}
}

// §5.3, §10.5.1: a peer whose release has no attachments answers our
// message.attachment.deliver with unsupported_type: the attachment fails
// (unsupported) at once, audited, with the feed item.
func TestAttachmentUnsupportedPeer(t *testing.T) {
	d := newDevFixture(t)
	rec := &recSink{}
	d.m.addFeature(rec)
	c := d.asConnection(t, "c1", 0x53)
	d.withLock(func(m *Manager) {
		m.st.attach().Entries["01JB2Z6V9K3M4N5P6Q7R8S9T70"] = &AttEntry{ID: "01JB2Z6V9K3M4N5P6Q7R8S9T70", Conn: "c1", Msg: "01JB2Z6V9K3M4N5P6Q7R8S9T71",
			Dir: DirOut, Kind: attwire.KindPhoto, Size: 10, State: AttSending, CW: true, DeliverID: "01JB2Z6V9K3M4N5P6Q7R8S9T72",
			DeliverAt: time.Now(), SentAt: time.Now()}
	})
	d.sendFrom(t, c, &envelope.Inner{Type: TypeAttDeliver, Re: "01JB2Z6V9K3M4N5P6Q7R8S9T72", Status: envelope.StatusError,
		Error: &envelope.Error{Code: "unsupported_type"}, Body: []byte(`{}`)})
	e := d.m.st.Attach.Entries["01JB2Z6V9K3M4N5P6Q7R8S9T70"]
	if e.State != AttFailed || e.Reason != ReasonUnsupported {
		t.Fatalf("state %s %s", e.State, e.Reason)
	}
	feed, audit := false, false
	for _, a := range rec.got {
		if a.Kind == "message.attachment_failed" {
			feed = feed || a.Feed && a.Ref == e.Msg
			audit = audit || a.Audit && a.Ref == e.Msg
		}
	}
	if !feed || !audit {
		t.Fatalf("feed %v audit %v: %+v", feed, audit, rec.got)
	}
}

// appOnlyFeature has a type that apps and desktops may send, and agents
// under a grant, whose "photo" form only the app may send.
type appOnlyFeature struct {
	recSink
	handled int
}

func (f *appOnlyFeature) Types() []TypeSpec {
	return []TypeSpec{{Type: "test.send", Request: true, From: []string{KindApp, KindDesktop}}}
}

func (f *appOnlyFeature) Handle(context.Context, *Session, *envelope.Inner) (json.RawMessage, error) {
	f.handled++
	return nil, nil
}

func (f *appOnlyFeature) AppOnly(typ string, body json.RawMessage) bool {
	o, err := strictjson.ParseObject(body)
	return err == nil && o.Has("photo")
}

type allowAll struct{ recSink }

func (allowAll) AgentDecision(*Session, string, json.RawMessage) AgentDecision { return AgentAllow }

// §10.5.1 "Agents", "Desktops": message.send with an attachment is
// answered forbidden to an agent whatever its grants, and to a desktop;
// the same type without the attachment is handled.
func TestAppOnlyFormsForbidden(t *testing.T) {
	d := newDevFixture(t)
	f := &appOnlyFeature{}
	d.m.addFeature(f)
	d.m.addFeature(&allowAll{})
	ag := d.addDevice(t, "ag1", KindAgent, 0x61)
	desk := d.addDevice(t, "dk1", KindDesktop, 0x62)
	d.withLock(func(m *Manager) {
		for _, id := range []string{"ag1", "dk1"} {
			m.grantAccess(m.st.Devices[id], 3600, "dev1", time.Now())
		}
	})
	for _, td := range []*tdev{ag, desk} {
		id := d.sendAs(td, "test.send", `{"photo":1}`)
		if r := find(d.inbox(td)[td.peer.ID], reply(id)); errCode(r) != "forbidden" {
			t.Fatalf("%s: %+v", td.peer.Kind, r)
		}
		id = d.sendAs(td, "test.send", `{}`)
		if r := find(d.inbox(td)[td.peer.ID], reply(id)); r == nil || r.Status != envelope.StatusOK {
			t.Fatalf("%s without the form: %+v", td.peer.Kind, r)
		}
	}
	if f.handled != 2 {
		t.Fatalf("handled %d", f.handled)
	}
}

// §10.2 (0.32.0): vault.status carries attachments {count, bytes,
// max_count, max_bytes} to the app and desktops, not to agents.
func TestStatusAttachments(t *testing.T) {
	d := newDevFixture(t)
	d.withLock(func(m *Manager) {
		m.st.attach().Entries["01JB2Z6V9K3M4N5P6Q7R8S9T70"] = &AttEntry{ID: "01JB2Z6V9K3M4N5P6Q7R8S9T70", Dir: DirIn, Size: 1000, ThumbLen: 24, State: AttStored, CW: true}
		m.st.attach().Entries["01JB2Z6V9K3M4N5P6Q7R8S9T71"] = &AttEntry{ID: "01JB2Z6V9K3M4N5P6Q7R8S9T71", Dir: DirIn, Size: 500, ThumbLen: 10, State: AttFailed, Reason: ReasonBad}
	})
	app := d.self()
	id := d.sendAs(app, "vault.status", `{}`)
	r := find(d.inbox(app)["dev1"], reply(id))
	o, _ := strictjson.ParseObject(r.Body)
	a, err := o.Object("attachments")
	if err != nil {
		t.Fatalf("no attachments: %s", r.Body)
	}
	if n, _ := a.Uint("count", 0, 1<<40); n != 2 {
		t.Fatal("count")
	}
	if n, _ := a.Uint("bytes", 0, 1<<40); n != 1034 { // a failed one's content is not counted
		t.Fatalf("bytes %d", n)
	}
	if n, _ := a.Uint("max_bytes", 0, 1<<40); n != attwire.StorageMax {
		t.Fatal("max_bytes")
	}
	ag := d.addDevice(t, "ag1", KindAgent, 0x63)
	d.withLock(func(m *Manager) { m.grantAccess(m.st.Devices["ag1"], 3600, "dev1", time.Now()) })
	id = d.sendAs(ag, "vault.status", `{}`)
	if r := find(d.inbox(ag)["ag1"], reply(id)); r == nil || json.Valid(r.Body) && strictjson.NewBuilder() == nil || containsKey(r.Body, "attachments") {
		t.Fatalf("agent's vault.status: %+v", r)
	}
}

func containsKey(b []byte, k string) bool {
	o, err := strictjson.ParseObject(b)
	return err == nil && o.Has(k)
}

// §12.5 (0.32.0): the vault's own deletion erases every written
// attachment object at its recorded version, before the state.
func TestDeletionErasesAttachments(t *testing.T) {
	d := newDevFixture(t)
	ctx := context.Background()
	vid := d.vid
	ids := []string{"01JB2Z6V9K3M4N5P6Q7R8S9T70", "01JB2Z6V9K3M4N5P6Q7R8S9T71"}
	d.withLock(func(m *Manager) {
		for _, id := range ids {
			cv, err := m.opt.Store.Put(ctx, attwire.ContentKey(vid, id), []byte("c"), "")
			if err != nil {
				t.Fatal(err)
			}
			tv, _ := m.opt.Store.Put(ctx, attwire.ThumbKey(vid, id), []byte("t"), "")
			m.st.attach().Entries[id] = &AttEntry{ID: id, Dir: DirIn, State: AttStored, CW: true, CVer: cv, TW: true, TVer: tv}
		}
	})
	if err := d.m.Delete(ctx); err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		for _, k := range []string{attwire.ContentKey(vid, id), attwire.ThumbKey(vid, id)} {
			if _, _, err := d.store.Get(ctx, k); err == nil {
				t.Fatalf("%s left after the deletion", k)
			}
		}
	}
}

// §12.5 "Convergence" (0.32.0): an unlock or a recovery request that finds
// a header recording deleting finishes the erase and reports `deleted`, so
// that the parent sweeps the attachment objects (VAULT-HOST-PROTOCOL P15).
func TestConvergenceReportsDeleted(t *testing.T) {
	for _, path := range []string{"unlock", "recovery"} {
		t.Run(path, func(t *testing.T) {
			f := newFixture(t)
			vid := f.m.VaultID()
			f.m.opt.Hooks.AfterFlush = func() error { return fmt.Errorf("crash") }
			f.m.mu.Lock()
			f.m.beginDelete("app", time.Now())
			f.m.mu.Unlock()
			_ = f.m.ProcessBatch(context.Background(), &fakeCollector{}, nil)
			var events []string
			o := f.opts
			o.Lifecycle = func(ev LifecycleEvent) {
				if ev.VaultID == vid {
					events = append(events, ev.Event)
				}
			}
			switch path {
			case "unlock":
				_, out := UnlockAlt(context.Background(), AltUnlockParams{Options: o, VaultID: vid, PIN: testPIN, pinOnly: true})
				for _, ev := range out.Events {
					events = append(events, ev.Event)
				}
			case "recovery":
				_, _, _ = RecoveryRequest(context.Background(), HeaderParams{Options: o, VaultID: vid, UserGUID: "u1"}, "01JB2Z6V9K3M4N5P6Q7R8S9T0V", RecoveryDelay)
			}
			if len(events) != 1 || events[0] != "deleted" {
				t.Fatalf("events %v", events)
			}
		})
	}
}
