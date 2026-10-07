package vault

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
)

// nameFeature stands in for the credential feature's account.name.set
// (its checks are tested there): it records the request.
type nameFeature struct{ recSink }

func (*nameFeature) Types() []TypeSpec {
	return []TypeSpec{{Type: TypeAccountNameSet, Request: true, From: []string{KindApp}}}
}

func (*nameFeature) Handle(_ context.Context, s *Session, in *envelope.Inner) (json.RawMessage, error) {
	o, _ := strictjson.ParseObject(in.Body)
	first, _ := o.String("first_name")
	last, _ := o.String("last_name")
	r, err := s.RequestAccountName(first, last)
	if err != nil {
		return nil, err
	}
	return strictjson.NewBuilder().Raw("request", r).Bytes(), nil
}

// §10.8, §11.5 (0.18.0): a name request gets the next seq, is stored as
// pending (replacing one still pending), is audited without names, tells
// the other owner devices (account.changed) and is reported to the parent
// as account_name after the flush that stored it; account.get returns it.
// A snapshot whose name_change.last names its seq settles it (audited),
// a higher seq refuses it with "account", and a newer snapshot's names
// are the vault's names.
func TestNameRequest(t *testing.T) {
	d := newDevFixture(t)
	nf := &nameFeature{}
	d.m.addFeature(nf)
	app := d.self()
	desk := d.addDevice(t, "desk1", KindDesktop, 0x60)
	desk.peer.Access = &AccessSession{ID: "s", Expires: time.Now().Add(time.Hour)}
	var evs []LifecycleEvent
	d.m.opt.Lifecycle = func(ev LifecycleEvent) {
		if ev.Event == EventAccountName {
			evs = append(evs, ev)
		}
	}
	id := d.sendAs(app, TypeAccountNameSet, `{"first_name":"Ada","last_name":"King"}`)
	in := d.inbox(app, desk)
	r := find(in["dev1"], reply(id))
	if r == nil || !strings.HasPrefix(string(r.Body), `{"request":{"seq":1,"first_name":"Ada","last_name":"King","requested_at":"`) ||
		!strings.HasSuffix(string(r.Body), `","state":"pending"}}`) {
		t.Fatalf("answer %+v", r)
	}
	if ev := find(in["desk1"], ofType("sync.event")); ev == nil || string(ev.Body) != `{"kind":"account.changed","version":1}` {
		t.Fatalf("desktop: %+v", in["desk1"])
	}
	if find(in["dev1"], ofType("sync.event")) != nil {
		t.Fatal("the sender got its own sync.event")
	}
	if len(evs) != 1 || *evs[0].Name != (NameChange{Seq: 1, FirstName: "Ada", LastName: "King"}) || evs[0].VaultID != d.m.VaultID() {
		t.Fatalf("account_name events %+v", evs)
	}
	if !nf.has("account.name_requested") {
		t.Fatal("not audited")
	}
	for _, a := range nf.got {
		if a.Kind == "account.name_requested" && a.Ref != "1" {
			t.Fatalf("audit ref %q", a.Ref)
		}
	}
	// A second request replaces the first (seq 2).
	d.sendAs(app, TypeAccountNameSet, `{"first_name":"Ada","last_name":"Byron"}`)
	d.inbox(app, desk)
	if len(evs) != 2 || evs[1].Name.Seq != 2 || d.m.st.NameRequest.LastName != "Byron" {
		t.Fatalf("second request %+v", evs)
	}
	// An outcome for the older seq settles nothing; the matching one does.
	now := time.Now()
	nf.got = nil
	if err := d.m.SetAccount(context.Background(), snapshotNamed(now, "Ada", "Lovelace", `{"allowed_after":null,"last":{"seq":1,"status":"refused","reason":"too_soon"}}`, "")); err != nil {
		t.Fatal(err)
	}
	if d.m.st.NameRequest.State != NamePending || nf.has("account.name_refused") {
		t.Fatal("settled by an older seq")
	}
	if err := d.m.SetAccount(context.Background(), snapshotNamed(now.Add(time.Second), "Ada", "Byron",
		`{"allowed_after":"`+envelope.FormatTS(now.Add(NameChangeInterval))+`","last":{"seq":2,"status":"applied"}}`, "")); err != nil {
		t.Fatal(err)
	}
	if r := d.m.st.NameRequest; r.State != NameApplied || r.Reason != "" || !nf.has("account.name_applied") {
		t.Fatalf("applied: %+v", r)
	}
	if f, l, ok := d.m.accountNames(); !ok || f != "Ada" || l != "Byron" || !d.m.st.Account.AllowedAfter.Equal(now.Add(NameChangeInterval).Truncate(time.Millisecond)) {
		t.Fatalf("names %q %q, allowed_after %v", f, l, d.m.st.Account.AllowedAfter)
	}
	d.inbox(app, desk)
	id = d.sendAs(app, "account.get", `{}`)
	g := find(d.inbox(app)["dev1"], reply(id))
	if g == nil || !strings.Contains(string(g.Body), `"name_request":{"seq":2,"first_name":"Ada","last_name":"Byron","requested_at":`) ||
		!strings.Contains(string(g.Body), `"state":"applied"}`) {
		t.Fatalf("account.get %+v", g)
	}
	// A pending request overtaken by a higher seq is refused ("account").
	d.sendAs(app, TypeAccountNameSet, `{"first_name":"Al","last_name":"Byron"}`)
	d.inbox(app, desk)
	nf.got = nil
	_ = d.m.SetAccount(context.Background(), snapshotNamed(now.Add(2*time.Second), "Ada", "Byron", `{"allowed_after":null,"last":{"seq":9,"status":"applied"}}`, ""))
	if r := d.m.st.NameRequest; r.Seq != 3 || r.State != NameRefused || r.Reason != "account" || !nf.has("account.name_refused") {
		t.Fatalf("overtaken: %+v", r)
	}
}

// §11.5: a failed flush reports no account_name.
func TestNameRequestNotReportedWithoutFlush(t *testing.T) {
	d := newDevFixture(t)
	d.m.addFeature(&nameFeature{})
	var evs []LifecycleEvent
	d.m.opt.Lifecycle = func(ev LifecycleEvent) { evs = append(evs, ev) }
	d.m.mu.Lock()
	d.m.requestAccountName("Ada", "King", "", time.Now())
	d.m.mu.Unlock()
	if len(evs) != 0 {
		t.Fatal("reported before the flush")
	}
	_ = d.m.ProcessBatch(context.Background(), &fakeCollector{}, nil)
	if len(evs) != 1 || evs[0].Event != EventAccountName {
		t.Fatalf("after the flush %+v", evs)
	}
}

// §6.2 (0.18.0): a connection hs.init whose profile lacks the account's
// names is dropped (drop.profile_malformed); the invitation stays usable.
func TestHandshakeProfileRequired(t *testing.T) {
	d := newDevFixture(t)
	inv := d.invite(t, KindConnection, 10*time.Minute)
	n := newNewcomer(t, 0x50)
	n.noProfile = true
	n.hsInit(t, d.m, handshake.PurposeConnection, inv.ID, "m1")
	if !d.audited("profile_malformed") || d.firstContact() != 0 || d.m.st.Invites[inv.ID].Used {
		t.Fatalf("hs.init without names: audited %v, contacts %d", d.audited("profile_malformed"), d.firstContact())
	}
	n2 := newNewcomer(t, 0x58)
	n2.hsInit(t, d.m, handshake.PurposeConnection, inv.ID, "m2")
	if d.firstContact() != 1 {
		t.Fatal("hs.init with names not answered")
	}
}

// §10.8 (0.18.0): a vault without the account's names sends no hs.init
// (profile.core_missing).
func TestAcceptWithoutNames(t *testing.T) {
	a, b := newVaultPair(t)
	rs := &recSink{}
	b.m.addFeature(rs)
	b.m.st.Account = nil
	_, link := a.linkFor(t, time.Hour)
	r, _ := b.request(t, "connection.invite.accept", `{"link":"`+link+`"}`)
	if errCode(r) != "internal" || !rs.has("profile.core_missing") || len(b.m.st.Outgoing) != 0 {
		t.Fatalf("accept without names: %+v", r)
	}
}

// §10.8 (0.18.0): after an ik rotation a connection's current epoch
// predates the new ik (RotationPending) until a new epoch is made.
func TestRotationPending(t *testing.T) {
	d := newDevFixture(t)
	p := &Peer{ID: "c1", Kind: KindConnection, State: PeerActive, OwnChainAtEpoch: len(d.m.st.Rotations)}
	d.m.st.Connections[p.ID] = p
	h := managerHost{d.m}
	if c, _ := h.Connection("c1"); c.RotationPending {
		t.Fatal("pending before a rotation")
	}
	d.m.mu.Lock()
	err := d.m.rotateIdentity(time.Now())
	d.m.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if c, _ := h.Connection("c1"); !c.RotationPending {
		t.Fatal("not pending after the rotation")
	}
	if cs := h.Connections(); len(cs) != 1 || !cs[0].RotationPending {
		t.Fatalf("connections %+v", cs)
	}
	p.OwnChainAtEpoch = len(d.m.st.Rotations) // the epoch under the new ik
	if c, _ := h.Connection("c1"); c.RotationPending {
		t.Fatal("still pending in the new epoch")
	}
}

func TestNormalizeRequestedName(t *testing.T) {
	for in, want := range map[string]string{"  Ada ": "Ada", "O’Brien": "O’Brien", "Jean-Luc": "Jean-Luc", "St. John": "St. John",
		"Zoë": "Zoë", "李": "李", "d'Arc": "d'Arc", strings.Repeat("é", 40): strings.Repeat("é", 40)} {
		if got, ok := NormalizeRequestedName(in); !ok || got != want {
			t.Errorf("%q: %q %v", in, got, ok)
		}
	}
	for _, in := range []string{"", " ", "-Ada", "Ada1", "Ada!", "A\tB", strings.Repeat("a", 41), strings.Repeat("😀", 1), "a" + strings.Repeat("𝒜", 20)} {
		if got, ok := NormalizeRequestedName(in); ok {
			t.Errorf("%q accepted as %q", in, got)
		}
	}
	if !ValidAccountName("Ada") || ValidAccountName("") || ValidAccountName("A ") || ValidAccountName("A\u009f") ||
		ValidAccountName(strings.Repeat("x", 161)) || ValidAccountName("\xff") || !ValidAccountName(strings.Repeat("x", 160)) {
		t.Fatal("ValidAccountName")
	}
}

// §6.6, §8.6: a deposit waiting for a fresh standing token holds back the
// later deposits on the standing token, but not the reconnect's hs.init,
// which carries its own token (every activation now sends profile.update,
// 0.18.0, so such a deposit is common after a crash).
func TestAwaitTokenDoesNotBlockReconnect(t *testing.T) {
	d := newDevFixture(t)
	now := time.Now()
	mb := "mbox-peer"
	d.m.st.Outbox = append(d.m.st.Outbox,
		&OutboxEntry{ID: "o1", Op: OpDeposit, PeerID: "dev1", RelayURL: "https://relay.example.org", Mailbox: mb, Payload: []byte("old"),
			NotBefore: now.Add(time.Hour), AwaitToken: true},
		&OutboxEntry{ID: "o2", Op: OpDeposit, PeerID: "dev1", RelayURL: "https://relay.example.org", Mailbox: mb, Payload: []byte("later")},
		&OutboxEntry{ID: "o3", Op: OpDeposit, RelayURL: "https://relay.example.org", Mailbox: mb, Token: "reconnect-token", Payload: []byte("hs.init")})
	d.m.mu.Lock()
	d.m.drainOutbox(context.Background())
	d.m.mu.Unlock()
	d.relay.mu.Lock()
	defer d.relay.mu.Unlock()
	var got []string
	for _, dep := range d.relay.deposits {
		if dep.mailbox == mb {
			got = append(got, string(dep.payload))
		}
	}
	if strings.Join(got, ",") != "hs.init" {
		t.Fatalf("deposits %v", got)
	}
}
