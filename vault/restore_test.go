package vault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"
	"github.com/vettid/vettid-relay/relayclient"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Reconnect after a restore (VAULT-MESSAGING 0.72.0, 0.72.1; §6.6, §15 item
// 45). svcFx stands in for a service vault: a peer with its own identity,
// KEM and relay keys that runs real handshakes against the member vault, and
// keeps the epochs it holds, so that a restored copy and a copy that kept
// running can both be played.

type svcFx struct {
	t      *testing.T
	d      *devFixture
	p      *Peer
	n      *newcomer
	sink   *recSink
	base   time.Time
	off    time.Duration
	epochs map[string]*handshake.Epoch // the service's epochs by id
	cur    *handshake.Epoch            // the service's current epoch
	ids    [][]byte                    // the epoch ids in order, the fabricated first one included
	stJTI  string                      // jti of a standing token the vault issued to the service
	msg    int
}

func (f *svcFx) now() time.Time { return f.base.Add(f.off) }

func (f *svcFx) vaultPK() ed25519.PublicKey { return f.d.m.keys.relay.Public().(ed25519.PublicKey) }

// newSvcFx makes a member vault with one connection of the given peer_kind
// ("service", or "" for a person), whose first epoch e0 is a fabricated id.
func newSvcFx(t *testing.T, kind string) *svcFx {
	t.Helper()
	d := newDevFixture(t)
	f := &svcFx{t: t, d: d, n: newNewcomer(t, 0x70), sink: &recSink{}, base: time.Now().UTC().Truncate(time.Millisecond),
		epochs: map[string]*handshake.Epoch{}}
	d.m.features = append(d.m.features, f.sink)
	d.m.now = f.now
	e0 := bytes.Repeat([]byte{0xe0}, suite.EpochIDSize)
	f.ids = [][]byte{e0}
	p := &Peer{ID: "c1", Kind: KindConnection, Name: "VettID Member Service", State: PeerActive, CreatedAt: f.base,
		IK: f.n.ik.Public().(ed25519.PublicKey), KEM: f.n.kem.Public().Bytes(), LastEpochID: e0, PeerKind: kind,
		Relay:    PeerRelay{URL: f.n.addr.URL, Mailbox: f.n.addr.Mailbox, PK: f.n.addr.PK},
		Standing: HeldToken{Token: "v4.public.VEVTVA", Exp: f.base.Add(200 * 24 * time.Hour)}}
	if kind == "service" {
		p.History = []EpochRecord{{ID: e0, Activated: f.base}}
	}
	d.m.mu.Lock()
	d.m.st.Connections[p.ID] = p
	d.m.mu.Unlock()
	f.p = p
	return f
}

func (f *svcFx) at(off time.Duration) { f.off = off }

func (f *svcFx) mint() string {
	f.t.Helper()
	rc := relayclient.New(f.n.addr.URL, f.n.relay)
	tok, err := rc.MintToken(relayauth.EncodeKey(f.vaultPK()), f.n.addr.URL, relayclient.TokenOptions{TTL: 300 * 24 * time.Hour})
	if err != nil {
		f.t.Fatal(err)
	}
	return tok
}

// initiate builds the service's reconnect hs.init naming ctx, with inner ts
// at, sending rotations rot.
func (f *svcFx) initiate(ctx []byte, at time.Time, rot []*handshake.Rotation) *handshake.Initiator {
	f.t.Helper()
	m := f.d.m
	id, _ := envelope.NewULID(at)
	ini, err := handshake.NewInitiator(handshake.InitiatorConfig{
		Purpose: handshake.PurposeReconnect, Ctx: handshake.EpochCtx(epochIDOf(ctx)),
		Identity: f.n.ik, StaticKEM: f.n.kem.Public(), Relay: f.n.addr, Token: f.mint(), ReconnectToken: f.mint(),
		Rotations:   rot,
		ResponderIK: m.keys.ik.Public().(ed25519.PublicKey), ResponderEK: m.keys.kem.Public(), ResponderRelayKey: f.vaultPK(),
		Policy: policyFor(KindConnection), Now: at, ID: id,
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return ini
}

// deliver hands the vault one message from the service on the token whose
// jti is jti ("" counts as a reconnect-token deposit, §6.6).
func (f *svcFx) deliver(payload []byte, jti string) {
	f.t.Helper()
	f.msg++
	_ = f.d.m.ProcessBatch(context.Background(), &fakeCollector{},
		[]Message{{MsgID: fmt.Sprintf("svc-%d", f.msg), Sender: relayauth.EncodeKey(f.n.addr.PK), JTI: jti, Payload: payload}})
}

func (f *svcFx) jtiOf(tok string, issuer ed25519.PublicKey) string {
	c, err := relayauth.ParseToken(tok, issuer)
	if err != nil {
		f.t.Fatal(err)
	}
	return c.Jti
}

// takeFor removes and returns the vault's deposit to the service mailbox
// that match accepts, or nil.
func (f *svcFx) takeFor(match func(env *envelope.Envelope) bool) []byte {
	f.d.relay.mu.Lock()
	defer f.d.relay.mu.Unlock()
	for i, dep := range f.d.relay.deposits {
		env, err := envelope.Parse(dep.payload)
		if err == nil && dep.mailbox == f.n.addr.Mailbox && match(env) {
			f.d.relay.deposits = append(f.d.relay.deposits[:i:i], f.d.relay.deposits[i+1:]...)
			return dep.payload
		}
	}
	return nil
}

// complete takes the vault's hs.resp for ini, finishes the handshake and
// sends hs.fin, as the service would. It returns the result (nil when the
// vault did not answer).
func (f *svcFx) complete(ini *handshake.Initiator) *handshake.Result {
	f.t.Helper()
	res := f.respOf(ini)
	if res == nil {
		return nil
	}
	f.deliver(res.Fin, f.stJTI)
	return res
}

// respOf takes the vault's hs.resp for ini and verifies it; the service
// holds the epoch from then on, and the hs.fin is left to the caller.
func (f *svcFx) respOf(ini *handshake.Initiator) *handshake.Result {
	f.t.Helper()
	resp := f.takeFor(func(env *envelope.Envelope) bool {
		return env.Mode() == envelope.ModeSealed && env.RecipientKid().Equal(ini.EphKid())
	})
	if resp == nil {
		return nil
	}
	res, err := ini.HandleResp(resp, f.vaultPK(), f.now())
	if err != nil {
		f.t.Fatalf("hs.resp: %v", err)
	}
	f.stJTI = f.jtiOf(res.Resp.Token, f.vaultPK())
	id := res.Epoch.ID()
	f.epochs[string(id[:])] = res.Epoch
	f.cur = res.Epoch
	f.ids = append(f.ids, id[:])
	return res
}

// reconnect is initiate, delivery and complete: the service reconnects
// naming ctx with its inner ts at the fixture's time.
func (f *svcFx) reconnect(ctx []byte) *handshake.Result {
	f.t.Helper()
	ini := f.initiate(ctx, f.now(), nil)
	f.deliver(ini.Envelope(), "")
	return f.complete(ini)
}

// build makes n more epochs, one every hour from the fixture's time, each by
// a reconnect naming the last.
func (f *svcFx) build(n int) {
	f.t.Helper()
	for i := 0; i < n; i++ {
		f.off += time.Hour
		if f.reconnect(f.p.LastEpochID) == nil {
			f.t.Fatalf("epoch %d: not answered", i+1)
		}
	}
}

func (f *svcFx) awaiting() int {
	f.d.m.mu.Lock()
	defer f.d.m.mu.Unlock()
	return len(f.d.m.st.Awaiting)
}

func (f *svcFx) outgoingReconnects() int {
	f.d.m.mu.Lock()
	defer f.d.m.mu.Unlock()
	n := 0
	for _, og := range f.d.m.st.Outgoing {
		if og.Purpose == handshake.PurposeReconnect {
			n++
		}
	}
	return n
}

// sendUnder delivers a session-mode message the service seals under ep with
// inner ts ts.
func (f *svcFx) sendUnder(ep *handshake.Epoch, typ string, ts time.Time) string {
	f.t.Helper()
	id, _ := envelope.NewULID(ts)
	raw, err := ep.Seal(&envelope.Inner{ID: id, Type: typ, TS: ts, Body: []byte(`{}`)})
	if err != nil {
		f.t.Fatal(err)
	}
	f.deliver(raw, f.stJTI)
	return id
}

func (f *svcFx) epochByID(id []byte) *handshake.Epoch { return f.epochs[string(id)] }

func (f *svcFx) feedFor(kind string) *Activity {
	for i := range f.sink.got {
		if f.sink.got[i].Kind == kind {
			return &f.sink.got[i]
		}
	}
	return nil
}

func (f *svcFx) revoked(jti string) bool {
	f.d.relay.mu.Lock()
	defer f.d.relay.mu.Unlock()
	for _, r := range f.d.relay.revoked {
		if r == "jti:"+jti {
			return true
		}
	}
	return false
}

// --- tests ---

// An older epoch from a service is accepted (§6.6 "Accepting ctx"); the
// connection ends on a new epoch, is told as a restore, and nothing was
// changed before hs.fin (§6.6 "Replay").
func TestRestoredServiceReconnectAccepted(t *testing.T) {
	f := newSvcFx(t, "service")
	f.build(3) // e0 (fabricated), e1, e2, e3
	e1, e3 := f.ids[1], f.ids[3]
	if !bytes.Equal(f.p.LastEpochID, e3) || len(f.p.History) != 4 {
		t.Fatalf("setup: last=%x history=%d", f.p.LastEpochID, len(f.p.History))
	}
	e1At := f.p.History[1].Activated
	f.sink.got = nil // the reconnects that built the line

	// The service is restored at e1 and reconnects naming it.
	f.at(10 * time.Hour)
	at := f.now()
	ini := f.initiate(e1, at, nil)
	before := *f.p
	f.deliver(ini.Envelope(), "")
	if f.awaiting() != 1 {
		t.Fatal("the older epoch of a service was not answered")
	}
	// Answered, but nothing changed before sig_I (hs.fin).
	if !bytes.Equal(f.p.LastEpochID, e3) || f.p.Standing != before.Standing || f.p.Reconnect != before.Reconnect ||
		f.p.State != PeerActive || f.p.Watch != nil || len(f.p.History) != 4 || f.sink.has("connection.restored_reconnect") {
		t.Fatal("state changed before hs.fin")
	}
	res := f.complete(ini)
	if res == nil {
		t.Fatal("no hs.resp")
	}
	newID := res.Epoch.ID()
	if bytes.Equal(f.p.LastEpochID, e3) || !bytes.Equal(f.p.LastEpochID, newID[:]) {
		t.Fatal("the connection did not end on the restored line's new epoch")
	}
	if len(f.p.History) != 5 || !f.p.History[3].Superseded.Equal(f.now()) || !f.p.History[4].Superseded.IsZero() {
		t.Fatalf("history after the restore: %+v", f.p.History)
	}
	// The line it replaced is watched: the epochs after the named one.
	if f.p.Watch == nil || len(f.p.Watch.Replaced) != 2 || !bytes.Equal(f.p.Watch.Replaced[0], f.ids[2]) ||
		!bytes.Equal(f.p.Watch.Replaced[1], e3) || !f.p.Watch.TS.Equal(at) {
		t.Fatalf("watch: %+v", f.p.Watch)
	}
	// Told to the member: audited with the named epoch's activation time,
	// History only (no feed item), in place of connection.reconnected.
	a := f.feedFor("connection.restored_reconnect")
	if a == nil || !a.Audit || a.Feed || a.ConnectionID != "c1" || a.Ref != envelope.FormatTS(e1At) {
		t.Fatalf("restored_reconnect: %+v", a)
	}
	if f.sink.has("connection.reconnected") || f.sink.has("connection.fork_suspected") || f.p.Fork != nil {
		t.Fatal("told as an ordinary reconnect, or suspended")
	}
}

// A person connection keeps the exact match and no history: the older epoch
// is refused, also when the same epoch sequence is built (§6.6 "Accepting
// ctx"). The same refusals hold on a service for a ctx not in the history
// and one past the window.
func TestRestoredReconnectRefusedFromPerson(t *testing.T) {
	f := newSvcFx(t, "")
	f.build(2)
	e1 := f.ids[1]
	if len(f.p.History) != 0 {
		t.Fatal("a person connection kept an epoch history")
	}
	f.at(10 * time.Hour)
	ini := f.initiate(e1, f.now(), nil)
	f.deliver(ini.Envelope(), "")
	if f.awaiting() != 0 || !f.d.audited("reconnect_refused") {
		t.Fatal("a person's older epoch was answered, or not audited")
	}
	// The last epoch is still accepted.
	if f.reconnect(f.p.LastEpochID) == nil {
		t.Fatal("a person's last epoch was refused")
	}
	// An unmarked connection that is not a service has no marker to change:
	// the reconnect did not give it one.
	if f.p.PeerKind != "" || len(f.p.History) != 0 || f.p.Watch != nil {
		t.Fatal("a person connection gained service state")
	}
}

func TestRestoredReconnectRefusals(t *testing.T) {
	t.Run("an epoch the connection never had", func(t *testing.T) {
		f := newSvcFx(t, "service")
		f.build(2)
		ini := f.initiate(bytes.Repeat([]byte{0x77}, suite.EpochIDSize), f.now(), nil)
		f.deliver(ini.Envelope(), "")
		if f.awaiting() != 0 || !f.d.audited("reconnect_refused") {
			t.Fatal("an unknown ctx was answered")
		}
	})
	t.Run("past the window", func(t *testing.T) {
		f := newSvcFx(t, "service")
		f.build(2) // e1 superseded at +2h
		e1 := f.ids[1]
		f.at(2*time.Hour + EpochHistoryWindow - time.Minute)
		if k, _ := classifyCtx(f.p, handshake.EpochCtx(epochIDOf(e1)), f.now()); k != ctxOlder {
			t.Fatalf("inside the window: %v", k)
		}
		f.at(2*time.Hour + EpochHistoryWindow)
		if k, _ := classifyCtx(f.p, handshake.EpochCtx(epochIDOf(e1)), f.now()); k != ctxNone {
			t.Fatalf("at the window: %v", k)
		}
		ini := f.initiate(e1, f.now(), nil)
		f.deliver(ini.Envelope(), "")
		if f.awaiting() != 0 || !f.d.audited("reconnect_refused") {
			t.Fatal("an epoch past the window was answered")
		}
	})
	t.Run("another sender", func(t *testing.T) {
		f := newSvcFx(t, "service")
		f.build(2)
		ini := f.initiate(f.ids[1], f.now(), nil)
		f.p.Relay.PK = newNewcomer(t, 0x90).addr.PK // the record names another relay key
		f.deliver(ini.Envelope(), "")
		if f.awaiting() != 0 || f.p.Fork != nil {
			t.Fatal("a reconnect from a key not on record was answered")
		}
	})
}

// The epoch history is pruned 35 days after an epoch was superseded, capped
// at 512 ids with the oldest dropped first, and the current epoch is never
// dropped (§6.6 "Epoch history").
func TestEpochHistoryPrunedAfter35Days(t *testing.T) {
	f := newSvcFx(t, "service")
	f.build(3) // e1 superseded at +2h, e2 at +3h
	f.at(2*time.Hour + EpochHistoryWindow - time.Second)
	f.d.m.mu.Lock()
	f.d.m.pruneHistories(f.now())
	f.d.m.mu.Unlock()
	// e0 was superseded at +1h, so it is past 35 days; e1 (+2h) is one second short.
	if len(f.p.History) != 3 || !bytes.Equal(f.p.History[0].ID, f.ids[1]) {
		t.Fatalf("pruned wrongly just inside the window: %d", len(f.p.History))
	}
	f.at(2*time.Hour + EpochHistoryWindow)
	f.d.m.mu.Lock()
	f.d.m.housekeeping(f.now()) // the runtime prunes with every batch
	f.d.m.mu.Unlock()
	// e0 (superseded at +1h) and e1 (at +2h) are past 35 days; e2 and e3 stay.
	if len(f.p.History) != 2 || !bytes.Equal(f.p.History[0].ID, f.ids[2]) || !bytes.Equal(f.p.History[1].ID, f.ids[3]) {
		t.Fatalf("history after 35 days: %d entries", len(f.p.History))
	}
	f.at(3*time.Hour + EpochHistoryWindow + 24*time.Hour)
	f.d.m.mu.Lock()
	pruneHistory(f.p, f.now())
	f.d.m.mu.Unlock()
	if len(f.p.History) != 1 || !bytes.Equal(f.p.History[0].ID, f.ids[3]) || !f.p.History[0].Superseded.IsZero() {
		t.Fatal("the current epoch was dropped, or an old one kept")
	}
	// The cap.
	p := &Peer{Kind: KindConnection, PeerKind: "service"}
	m := f.d.m
	now := f.base
	for i := 0; i < EpochHistoryMax+88; i++ {
		id := make([]byte, suite.EpochIDSize)
		id[0], id[1] = byte(i>>8), byte(i)
		m.recordEpoch(p, id, 0, now.Add(time.Duration(i)*time.Second))
	}
	if len(p.History) != EpochHistoryMax || p.History[0].ID[1] != 88 || !p.History[len(p.History)-1].Superseded.IsZero() {
		t.Fatalf("cap: %d entries, first %x", len(p.History), p.History[0].ID[:2])
	}
}

// A reconnect hs.init already answered is refused by th1 first, whatever
// its ctx now names; the marks are kept 16 days + 5 minutes and held in the
// state (§6.6 "Replay").
func TestReconnectReplayRefused(t *testing.T) {
	f := newSvcFx(t, "service")
	f.build(2)
	f.at(5 * time.Hour)
	e1 := f.ids[1]
	ini := f.initiate(e1, f.now(), nil)
	env := ini.Envelope()
	f.deliver(env, "")
	res := f.complete(ini)
	if res == nil {
		t.Fatal("not answered")
	}
	last := append([]byte(nil), f.p.LastEpochID...)
	nAudit := len(f.d.m.Audit())
	// The same bytes again (a deposit retried, or replayed by the carrier):
	// dropped without an answer, audited, nothing changed. Its older ctx
	// would otherwise still be accepted.
	f.deliver(env, "")
	if f.awaiting() != 0 || f.takeFor(func(*envelope.Envelope) bool { return true }) != nil ||
		!bytes.Equal(f.p.LastEpochID, last) || len(f.d.m.Audit()) != nAudit+1 || !f.d.audited("reconnect_refused") {
		t.Fatal("a replayed reconnect hs.init was answered")
	}
	// Also while it is awaiting its hs.fin: one answer only.
	f.at(6 * time.Hour)
	ini2 := f.initiate(f.p.LastEpochID, f.now(), nil)
	f.deliver(ini2.Envelope(), "")
	f.deliver(ini2.Envelope(), "")
	if f.awaiting() != 1 {
		t.Fatalf("answered %d times", f.awaiting())
	}
	// The mark is held in the state and pruned after 16 days + 5 minutes.
	raw, err := json.Marshal(f.d.m.st)
	if err != nil || !strings.Contains(string(raw), `"seen_init"`) {
		t.Fatal("the th1 marks are not part of the state")
	}
	th1 := ini.Th1()
	f.d.m.mu.Lock()
	defer f.d.m.mu.Unlock()
	if !f.d.m.initAnswered(th1) {
		t.Fatal("no mark")
	}
	f.at(5*time.Hour + InitMarkRetention - time.Second)
	f.d.m.prune()
	if !f.d.m.initAnswered(th1) {
		t.Fatal("mark pruned early")
	}
	if InitMarkRetention != 16*24*time.Hour+5*time.Minute {
		t.Fatal("retention is not 16 days + 5 minutes")
	}
	f.at(5*time.Hour + InitMarkRetention + time.Second)
	f.d.m.prune()
	if f.d.m.initAnswered(th1) {
		t.Fatal("mark kept past 16 days + 5 minutes")
	}
}

// A reconnect hs.init changes no state until sig_I verifies: junk or a forged
// hs.fin leaves the connection as it was, and the hs.fin that verifies
// applies the held rotation links (§6.6 "Replay", §3.4).
func TestReconnectChangesNothingBeforeFin(t *testing.T) {
	k0, k1 := rcKey(t, 0x10), rcKey(t, 0x20)
	r1 := rcLink(t, k0, k1)
	f := newSvcFx(t, "service")
	f.n.ik, f.n.kem = k0.ik, k0.kem // the service starts at k0 ...
	f.p.IK, f.p.KEM = k0.ik.Public().(ed25519.PublicKey), k0.kem.Public().Bytes()
	// ... and reconnects as k1, having rotated.
	f.n.ik, f.n.kem = k1.ik, k1.kem
	ini := f.initiate(f.p.LastEpochID, f.now(), []*handshake.Rotation{r1})
	f.deliver(ini.Envelope(), "")
	if f.awaiting() != 1 {
		t.Fatal("not answered")
	}
	if !bytes.Equal(f.p.IK, k0.ik.Public().(ed25519.PublicKey)) || len(f.p.Chain) != 0 || f.p.Reconnect.Token != "" {
		t.Fatal("followed the rotation before hs.fin")
	}
	// A forged hs.fin (random bytes of a session envelope) changes nothing.
	f.deliver(bytes.Repeat([]byte{0x01}, 64), f.jtiOf(f.mint(), f.n.addr.PK))
	if !bytes.Equal(f.p.IK, k0.ik.Public().(ed25519.PublicKey)) || len(f.p.Chain) != 0 || f.awaiting() != 1 {
		t.Fatal("junk changed the connection")
	}
	if f.complete(ini) == nil {
		t.Fatal("no hs.resp")
	}
	if !bytes.Equal(f.p.IK, k1.ik.Public().(ed25519.PublicKey)) || len(f.p.Chain) != 1 || f.p.Reconnect.Token == "" ||
		!bytes.Equal(f.p.KEM, k1.kem.Public().Bytes()) {
		t.Fatal("the verified hs.fin did not apply the rotation and the tokens")
	}
}

// A reconnect's rotations from the vault run from the own chain count
// recorded with the epoch the ctx names, not since the last epoch (§6.6
// "Responder rotations").
func TestResponderRotationsFromNamedEpoch(t *testing.T) {
	f := newSvcFx(t, "service")
	m := f.d.m
	vk0 := rcKey(t, 0xa0)
	vault := rcKeys{ik: m.keys.ik, kem: m.keys.kem}
	mid := rcKey(t, 0xb0)
	r0, r1 := rcLink(t, vk0, mid), rcLink(t, mid, vault)
	f.build(3) // e1, e2, e3
	m.mu.Lock()
	m.st.Rotations = rawLinks(r0, r1)
	// e1 was signed before both rotations, e2 after the first, and the
	// last epoch after both.
	f.p.History[1].OwnChain, f.p.History[2].OwnChain = 0, 1
	f.p.History[3].OwnChain = 2
	f.p.OwnChainAtEpoch = 2
	m.mu.Unlock()
	f.at(20 * time.Hour)
	for _, c := range []struct {
		name  string
		ctx   []byte
		want  int
		known ed25519.PublicKey // the identity key the service knows the vault by
	}{
		{"e1", f.ids[1], 2, vk0.ik.Public().(ed25519.PublicKey)},
		{"e2", f.ids[2], 1, mid.ik.Public().(ed25519.PublicKey)},
	} {
		ini, err := handshake.NewInitiator(handshake.InitiatorConfig{
			Purpose: handshake.PurposeReconnect, Ctx: handshake.EpochCtx(epochIDOf(c.ctx)),
			Identity: f.n.ik, StaticKEM: f.n.kem.Public(), Relay: f.n.addr, Token: f.mint(), ReconnectToken: f.mint(),
			ResponderIK: c.known, ResponderEK: m.keys.kem.Public(), ResponderRelayKey: f.vaultPK(),
			Policy: policyFor(KindConnection), Now: f.now(),
		})
		if err != nil {
			t.Fatal(err)
		}
		f.deliver(ini.Envelope(), "")
		resp := f.takeFor(func(env *envelope.Envelope) bool { return env.RecipientKid().Equal(ini.EphKid()) })
		if resp == nil {
			t.Fatalf("%s: not answered", c.name)
		}
		res, err := ini.HandleResp(resp, f.vaultPK(), f.now())
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if len(res.Resp.Rotations) != c.want {
			t.Fatalf("%s: %d rotations, want %d", c.name, len(res.Resp.Rotations), c.want)
		}
	}
}

// Fork detection (§6.6): after an older reconnect was accepted, an
// authenticated sign of the line it replaced with a later ts suspends the
// connection and tells the member; traffic the restored peer sent before its
// crash (earlier ts) is processed normally; a genuine restore alone never
// triggers it.
func TestForkDetectionSuspends(t *testing.T) {
	setup := func(t *testing.T) (*svcFx, *handshake.Epoch) {
		f := newSvcFx(t, "service")
		f.build(3)
		e3 := f.cur // the copy that kept running holds e3
		f.at(10 * time.Hour)
		ini := f.initiate(f.ids[1], f.now(), nil)
		f.deliver(ini.Envelope(), "")
		if f.complete(ini) == nil {
			t.Fatal("restore not answered")
		}
		if f.p.Fork != nil || f.sink.has("connection.fork_suspected") {
			t.Fatal("a genuine restore suspended the connection")
		}
		f.sink.got = nil // what built the line and the restore
		return f, e3
	}
	t.Run("a message under the replaced line, later ts", func(t *testing.T) {
		f, e3 := setup(t)
		f.at(11 * time.Hour)
		f.sendUnder(e3, "x.test", f.now())
		if f.p.Fork == nil {
			t.Fatal("not suspended")
		}
		a := f.feedFor("connection.fork_suspected")
		if a == nil || !a.Audit || !a.Feed || a.Priority != "high" || a.ConnectionID != "c1" {
			t.Fatalf("connection.fork_suspected: %+v", a)
		}
		// It sends nothing and accepts nothing.
		f.d.m.mu.Lock()
		sent := f.d.m.sendTo(f.p, "profile.update", []byte(`{}`), f.now())
		f.d.m.startReconnect(f.p, f.now())
		f.d.m.startRekey(f.p, f.now())
		f.d.m.mu.Unlock()
		f.p.Reconnect = HeldToken{Token: f.mint(), Exp: f.now().Add(24 * time.Hour)}
		f.d.m.mu.Lock()
		f.d.m.startReconnect(f.p, f.now())
		f.d.m.mu.Unlock()
		if sent != "" || f.outgoingReconnects() != 0 {
			t.Fatal("a suspended connection sent something")
		}
		f.sendUnder(f.cur, "x.test", f.now().Add(time.Minute))
		if !f.d.audited("fork_suspended_drop") {
			t.Fatal("a suspended connection accepted a message")
		}
		ini := f.initiate(f.p.LastEpochID, f.now(), nil)
		f.deliver(ini.Envelope(), "")
		if f.awaiting() != 0 {
			t.Fatal("a suspended connection answered a reconnect")
		}
		// connection.rotation.resolve has no candidates for it.
		f.d.m.mu.Lock()
		s := f.d.m.session(f.now())
		s.from = PeerInfo{ID: "app1", Kind: KindApp}
		_, err := f.d.m.hRotationResolve(context.Background(), s, testInner(`{"connection_id":"c1","new_ik":"`+b64(f.p.IK)+`"}`))
		f.d.m.mu.Unlock()
		if !errors.Is(err, errNotFound) {
			t.Fatalf("resolve: %v", err)
		}
		// A new invitation is the way out: it is not refused as a known peer.
		inv := f.d.invite(t, KindConnection, time.Hour)
		cini, err := handshake.NewInitiator(handshake.InitiatorConfig{
			Purpose: handshake.PurposeConnection, Ctx: inv.ID, Identity: f.n.ik, StaticKEM: f.n.kem.Public(), Relay: f.n.addr,
			Token: f.mint(), ResponderIK: f.d.m.keys.ik.Public().(ed25519.PublicKey), ResponderEK: f.d.m.keys.kem.Public(),
			ResponderRelayKey: f.vaultPK(), Policy: policyFor(KindConnection), Now: f.now(),
			Profile: json.RawMessage(`{"first_name":"Svc","last_name":"Service"}`),
		})
		if err != nil {
			t.Fatal(err)
		}
		f.deliver(cini.Envelope(), inv.OpenJTI)
		if f.d.audited("hs_init_from_known_peer") || f.d.firstContact() == 0 {
			t.Fatal("a new invitation was refused on a fork-suspended connection")
		}
	})
	t.Run("a message under the replaced line, earlier ts", func(t *testing.T) {
		f, e3 := setup(t)
		f.at(11 * time.Hour)
		id := f.sendUnder(e3, "x.test", f.base.Add(9*time.Hour+30*time.Minute)) // before the restore's hs.init (10 h)
		if f.p.Fork != nil || f.sink.has("connection.fork_suspected") {
			t.Fatal("late traffic from before the crash suspended the connection")
		}
		if _, seen := f.d.m.st.SeenInner["c1|"+id]; !seen {
			t.Fatal("late traffic from before the crash was not processed")
		}
	})
	t.Run("the same ts is not later", func(t *testing.T) {
		f, e3 := setup(t)
		f.sendUnder(e3, "x.test", f.p.Watch.TS)
		if f.p.Fork != nil {
			t.Fatal("a ts that is not later counted")
		}
	})
	t.Run("a rekey under the replaced line", func(t *testing.T) {
		f, e3 := setup(t)
		f.at(11 * time.Hour)
		ini, err := handshake.NewInitiator(handshake.InitiatorConfig{
			Purpose: handshake.PurposeRekey, Identity: f.n.ik, StaticKEM: f.n.kem.Public(), Relay: f.n.addr,
			ResponderIK: f.d.m.keys.ik.Public().(ed25519.PublicKey), ResponderRelayKey: f.vaultPK(), Current: e3,
			Policy: policyFor(KindConnection), Now: f.now(),
		})
		if err != nil {
			t.Fatal(err)
		}
		f.deliver(ini.Envelope(), f.stJTI)
		if f.p.Fork == nil {
			t.Fatal("a rekey under the replaced line did not suspend")
		}
	})
	t.Run("a reconnect naming the replaced line, later ts: judged at hs.fin", func(t *testing.T) {
		f, e3 := setup(t)
		last := append([]byte(nil), f.p.LastEpochID...)
		f.at(12 * time.Hour)
		ini := f.initiate(f.ids[3], f.now(), nil) // the copy that kept running, still at e3
		f.deliver(ini.Envelope(), "")
		if f.awaiting() != 1 || f.p.Fork != nil {
			t.Fatal("answered or suspended wrongly before hs.fin")
		}
		f.complete(ini)
		if f.p.Fork == nil || !bytes.Equal(f.p.LastEpochID, last) || f.sink.has("connection.reconnected") ||
			f.feedFor("connection.fork_suspected") == nil {
			t.Fatal("a verified hs.fin on the replaced line did not suspend instead of activating")
		}
		_ = e3
	})
	t.Run("a reconnect naming the replaced line, ts not later: refused unanswered", func(t *testing.T) {
		f, _ := setup(t)
		f.at(12 * time.Hour)
		ini := f.initiate(f.ids[3], f.base.Add(9*time.Hour), nil) // before the restore's hs.init (10 h)
		f.deliver(ini.Envelope(), "")
		if f.awaiting() != 0 || f.p.Fork != nil || !f.d.audited("reconnect_refused") {
			t.Fatal("an earlier reconnect on the replaced line was answered or suspended")
		}
	})
	t.Run("a second restore from a backup before the first is another restore", func(t *testing.T) {
		f, _ := setup(t)
		f.at(12 * time.Hour)
		ini := f.initiate(f.ids[0], f.now(), nil) // e0 is before the named e1
		f.deliver(ini.Envelope(), "")
		if f.complete(ini) == nil || f.p.Fork != nil {
			t.Fatal("not accepted as a restore")
		}
	})
	t.Run("the corner case: a second restore from a newer backup is two copies", func(t *testing.T) {
		f, _ := setup(t)
		f.at(12 * time.Hour)
		ini := f.initiate(f.ids[2], f.now(), nil) // e2 is after the named e1
		f.deliver(ini.Envelope(), "")
		f.complete(ini)
		if f.p.Fork == nil {
			t.Fatal("not reported")
		}
	})
}

// A fork suspension survives the state being written and read back.
func TestForkStateRoundTrip(t *testing.T) {
	f := newSvcFx(t, "service")
	f.build(2)
	f.d.m.mu.Lock()
	f.d.m.setWatch(f.p, f.ids[1], f.now(), f.now())
	f.d.m.suspendFork(f.p, f.now())
	raw, err := json.Marshal(f.p)
	f.d.m.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	var q Peer
	if err := json.Unmarshal(raw, &q); err != nil {
		t.Fatal(err)
	}
	if q.Fork == nil || q.Watch == nil || len(q.History) != 3 || q.PeerKind != "service" || !q.suspended() || !q.replaceable() {
		t.Fatalf("round trip: %+v", q)
	}
}

// Crossing reconnects (§6.6, 0.72.1): the member always answers the
// service's; each side completes at most one; both end on one epoch.
func TestCrossingReconnects(t *testing.T) {
	// ownStart makes the vault start its own reconnect; it returns the
	// hs.init envelope it queued.
	ownStart := func(t *testing.T, f *svcFx) (*OutgoingHS, []byte) {
		t.Helper()
		m := f.d.m
		m.mu.Lock()
		defer m.mu.Unlock()
		f.p.Reconnect = HeldToken{Token: f.mint(), Exp: f.now().Add(24 * time.Hour)}
		m.startReconnect(f.p, f.now())
		var og *OutgoingHS
		for _, o := range m.st.Outgoing {
			if o.Purpose == handshake.PurposeReconnect {
				og = o
			}
		}
		if og == nil {
			t.Fatal("no reconnect of the vault's own")
		}
		for _, e := range m.st.Outbox {
			if e.ID == og.InitOutbox {
				return og, e.Payload
			}
		}
		t.Fatal("the hs.init is not in the outbox")
		return nil, nil
	}
	// answer is the service answering the vault's own hs.init.
	answer := func(t *testing.T, f *svcFx, env []byte) (*handshake.Responder, []byte, *handshake.PendingInit) {
		t.Helper()
		pi, err := handshake.OpenInit(env, func(kid suite.Kid) *suite.PrivateKey {
			if kid.Equal(f.n.kem.Public().Kid()) {
				return f.n.kem
			}
			return nil
		}, f.now())
		if err != nil {
			t.Fatal(err)
		}
		r, renv, err := pi.Respond(handshake.ResponderConfig{Identity: f.n.ik, Token: f.mint(), ReconnectToken: f.mint(),
			Policy: policyFor(KindConnection), CollectSender: f.vaultPK(), RecordRelayKey: f.vaultPK(),
			KnownInitiatorIK: f.d.m.keys.ik.Public().(ed25519.PublicKey), ExpectedCtx: pi.Init().Ctx, Now: f.now()})
		if err != nil {
			t.Fatal(err)
		}
		return r, renv, pi
	}
	vaultHasDeposit := func(f *svcFx, kid suite.Kid) bool {
		f.d.relay.mu.Lock()
		defer f.d.relay.mu.Unlock()
		for _, dep := range f.d.relay.deposits {
			if env, err := envelope.Parse(dep.payload); err == nil && dep.mailbox == f.n.addr.Mailbox &&
				env.Mode() == envelope.ModeSealed && env.RecipientKid().Equal(kid) {
				return true
			}
		}
		return false
	}

	t.Run("the service's verifies first: the vault's own is abandoned", func(t *testing.T) {
		f := newSvcFx(t, "service")
		f.build(2)
		f.at(10 * time.Hour)
		// The service's reconnect is answered; its hs.fin is on the way.
		ini := f.initiate(f.p.LastEpochID, f.now(), nil)
		f.deliver(ini.Envelope(), "")
		res := f.respOf(ini)
		if res == nil {
			t.Fatal("the service's reconnect was not answered")
		}
		// The vault starts its own reconnect before the hs.fin arrives.
		og, ownEnv := ownStart(t, f)
		ownIssued := og.Issued
		f.deliver(res.Fin, f.stJTI) // the verified hs.fin establishes the service's
		nid := res.Epoch.ID()
		if !bytes.Equal(f.p.LastEpochID, nid[:]) {
			t.Fatal("not on the service's epoch")
		}
		if f.outgoingReconnects() != 0 {
			t.Fatal("the vault's own reconnect stayed open")
		}
		if len(ownIssued) == 0 {
			t.Fatal("setup: no tokens in the vault's hs.init")
		}
		for _, tk := range ownIssued {
			if !f.revoked(tk.JTI) {
				t.Fatal("a token of the abandoned hs.init was not revoked")
			}
		}
		if vaultHasDeposit(f, f.n.kem.Public().Kid()) {
			t.Fatal("the abandoned hs.init was deposited")
		}
		// A later hs.resp to it is dropped and audited.
		_, renv, pi := answer(t, f, ownEnv)
		f.deliver(renv, f.jtiOf(pi.Init().Token, f.vaultPK()))
		if !bytes.Equal(f.p.LastEpochID, nid[:]) || !f.d.audited("unknown_kid") || f.outgoingReconnects() != 0 {
			t.Fatal("a late hs.resp to the abandoned reconnect changed the connection or was not audited")
		}
	})

	t.Run("the vault's own completes first: its answer to the service's is dropped", func(t *testing.T) {
		f := newSvcFx(t, "service")
		f.build(2)
		f.at(10 * time.Hour)
		// The service's reconnect: answered by the vault, hs.fin held back.
		ini := f.initiate(f.p.LastEpochID, f.now(), nil)
		f.deliver(ini.Envelope(), "")
		svcRes := f.respOf(ini)
		stJTI := f.stJTI
		var answered []IssuedToken
		for _, a := range f.d.m.st.Awaiting {
			answered = a.Issued
		}
		if len(answered) == 0 {
			t.Fatal("setup: nothing awaiting")
		}

		// The vault's own reconnect completes first.
		_, ownEnv := ownStart(t, f)
		r, renv, pi := answer(t, f, ownEnv)
		f.deliver(renv, f.jtiOf(pi.Init().Token, f.vaultPK()))
		fin := f.takeFor(func(env *envelope.Envelope) bool { return env.Mode() == envelope.ModeSession })
		if fin == nil {
			t.Fatal("the vault sent no hs.fin")
		}
		fr, err := r.HandleFin(fin, f.vaultPK(), f.now())
		if err != nil {
			t.Fatal(err)
		}
		own := fr.Epoch.ID()
		if !bytes.Equal(f.p.LastEpochID, own[:]) {
			t.Fatal("the vault did not end on its own epoch")
		}
		if f.awaiting() != 0 {
			t.Fatal("the pending answer to the service's hs.init was kept")
		}
		for _, tk := range answered {
			if !f.revoked(tk.JTI) {
				t.Fatal("a token of the dropped hs.resp was not revoked")
			}
		}
		// The service's hs.fin for its reconnect is acked and dropped, and is
		// no evidence for fork detection.
		f.deliver(svcRes.Fin, stJTI)
		if !bytes.Equal(f.p.LastEpochID, own[:]) || f.p.Fork != nil || f.p.Watch != nil || f.sink.has("connection.fork_suspected") {
			t.Fatal("the late hs.fin changed the connection")
		}
	})
}

// An ordinary connection refuses a new invitation from its peer; only a
// stale one or one suspended on fork evidence is made afresh.
func TestNewInvitationOnlyReplacesStaleOrFork(t *testing.T) {
	try := func(t *testing.T, f *svcFx) {
		inv := f.d.invite(t, KindConnection, time.Hour)
		cini, err := handshake.NewInitiator(handshake.InitiatorConfig{
			Purpose: handshake.PurposeConnection, Ctx: inv.ID, Identity: f.n.ik, StaticKEM: f.n.kem.Public(), Relay: f.n.addr,
			Token: f.mint(), ResponderIK: f.d.m.keys.ik.Public().(ed25519.PublicKey), ResponderEK: f.d.m.keys.kem.Public(),
			ResponderRelayKey: f.vaultPK(), Policy: policyFor(KindConnection), Now: f.now(),
			Profile: json.RawMessage(`{"first_name":"Svc","last_name":"Service"}`),
		})
		if err != nil {
			t.Fatal(err)
		}
		f.deliver(cini.Envelope(), inv.OpenJTI)
	}
	f := newSvcFx(t, "service")
	try(t, f)
	if !f.d.audited("hs_init_from_known_peer") || f.d.firstContact() != 0 {
		t.Fatal("an active connection took a new invitation")
	}
	f2 := newSvcFx(t, "service")
	f2.d.m.mu.Lock()
	f2.d.m.suspendFork(f2.p, f2.now())
	f2.d.m.mu.Unlock()
	try(t, f2)
	if f2.d.audited("hs_init_from_known_peer") || f2.d.firstContact() == 0 {
		t.Fatal("a fork-suspended connection refused a new invitation")
	}
}

// The check for a second successor comes after the replay check (§6.6
// "Replay", 0.72.1): a reconnect hs.init already answered is dropped before
// its rotations are looked at.
func TestRotationConflictAfterReplayCheck(t *testing.T) {
	k0, k1, kb := rcKey(t, 0x10), rcKey(t, 0x20), rcKey(t, 0x40)
	r1, rb := rcLink(t, k0, k1), rcLink(t, k0, kb)
	setup := func(t *testing.T) (*svcFx, *handshake.Initiator) {
		f := newSvcFx(t, "service")
		f.p.IK, f.p.KEM, f.p.Chain = k1.ik.Public().(ed25519.PublicKey), k1.kem.Public().Bytes(), rawLinks(r1)
		f.n.ik, f.n.kem = kb.ik, kb.kem // the other copy rotated to kb
		return f, f.initiate(f.p.LastEpochID, f.now(), []*handshake.Rotation{rb})
	}
	f, ini := setup(t)
	f.deliver(ini.Envelope(), "")
	if f.p.Conflict == nil || f.awaiting() != 0 || !f.sink.has("identity.rotate_conflict") {
		t.Fatal("a second successor in a reconnect did not suspend at once, unanswered")
	}
	f, ini = setup(t)
	f.d.m.mu.Lock()
	f.d.m.markInit(ini.Th1(), f.now()) // already answered
	f.d.m.mu.Unlock()
	f.deliver(ini.Envelope(), "")
	if f.p.Conflict != nil || f.awaiting() != 0 || !f.d.audited("reconnect_refused") {
		t.Fatal("the conflict check ran before the replay check")
	}
}

// A reconnect open at a restart keeps its stored initiator state: starting
// one again sends no new hs.init and uses no try; the hs.init is the one
// queued, with the same bytes (§6.6 "After a restore", 0.72.1).
func TestOpenReconnectKeptAcrossStart(t *testing.T) {
	f := newSvcFx(t, "service")
	m := f.d.m
	m.mu.Lock()
	f.p.Reconnect = HeldToken{Token: f.mint(), Exp: f.now().Add(24 * time.Hour)}
	m.startReconnect(f.p, f.now())
	var first *OutgoingHS
	for _, og := range m.st.Outgoing {
		first = og
	}
	var payload []byte
	for _, e := range m.st.Outbox {
		if e.ID == first.InitOutbox {
			payload = append(payload, e.Payload...)
		}
	}
	// The state is written and read back, as a restart does, and the
	// reconnects owed at the start are started again.
	raw, err := json.Marshal(m.st.Outgoing)
	if err != nil {
		t.Fatal(err)
	}
	m.startReconnect(f.p, f.now())
	m.reconnectExpired(f.now().Add(400 * 24 * time.Hour))
	n := len(m.st.Outgoing)
	same := len(m.st.Outbox) == 1 && bytes.Equal(m.st.Outbox[0].Payload, payload)
	m.mu.Unlock()
	var back map[string]*OutgoingHS
	if err := json.Unmarshal(raw, &back); err != nil || back[first.ID] == nil || back[first.ID].InitOutbox != first.InitOutbox {
		t.Fatal("the open reconnect is not part of the state")
	}
	if n != 1 || !same {
		t.Fatalf("a second hs.init was made: %d outgoing, same outbox=%v", n, same)
	}
}

// Rekeys open when a restore is accepted were made on the replaced line
// (§6.6). They stay, marked, and block no new rekey; a verified hs.resp or
// hs.fin of one with a ts later than the accepted reconnect's is evidence of
// a second copy and suspends; an earlier one activates nothing.
func TestOpenRekeysAtRestore(t *testing.T) {
	restore := func(f *svcFx) {
		f.at(10 * time.Hour)
		ini := f.initiate(f.ids[1], f.now(), nil)
		f.deliver(ini.Envelope(), "")
		if f.complete(ini) == nil {
			t.Fatal("restore not answered")
		}
	}
	// The vault's own rekey, answered by the copy that kept running (e3).
	own := func(t *testing.T, copyTS time.Duration, wantFork bool) {
		f := newSvcFx(t, "service")
		f.build(3)
		e3 := f.cur
		f.at(4 * time.Hour)
		m := f.d.m
		m.mu.Lock()
		m.startRekey(f.p, f.now())
		m.drainOutbox(context.Background())
		m.mu.Unlock()
		raw := f.takeFor(func(env *envelope.Envelope) bool { return env.Mode() == envelope.ModeSession })
		if raw == nil {
			t.Fatal("no rekey hs.init")
		}
		restore(f)
		last := append([]byte(nil), f.p.LastEpochID...)
		marked := 0
		m.mu.Lock()
		for _, og := range m.st.Outgoing {
			if og.Purpose == handshake.PurposeRekey && og.Replaced {
				marked++
			}
		}
		blocked := m.hasOutgoing(f.p.ID, handshake.PurposeRekey)
		m.mu.Unlock()
		if marked != 1 || blocked {
			t.Fatalf("open rekey after the restore: marked=%d blocks=%v", marked, blocked)
		}
		at := f.base.Add(copyTS)
		pi, err := handshake.OpenRekeyInit(raw, e3, at)
		if err != nil {
			t.Fatal(err)
		}
		_, renv, err := pi.Respond(handshake.ResponderConfig{Identity: f.n.ik, Policy: policyFor(KindConnection),
			CollectSender: f.vaultPK(), RecordRelayKey: f.vaultPK(), KnownInitiatorIK: m.keys.ik.Public().(ed25519.PublicKey), Now: at})
		if err != nil {
			t.Fatal(err)
		}
		f.at(12 * time.Hour)
		f.deliver(renv, f.stJTI)
		if (f.p.Fork != nil) != wantFork || !bytes.Equal(f.p.LastEpochID, last) {
			t.Fatalf("fork=%v last unchanged=%v", f.p.Fork != nil, bytes.Equal(f.p.LastEpochID, last))
		}
		if wantFork && f.feedFor("connection.fork_suspected") == nil {
			t.Fatal("no feed item")
		}
	}
	t.Run("hs.resp of the vault's rekey from the second copy suspends", func(t *testing.T) { own(t, 11*time.Hour, true) })
	t.Run("an earlier hs.resp activates nothing", func(t *testing.T) { own(t, 9*time.Hour+30*time.Minute, false) })

	// A rekey the vault answered; its hs.fin comes after the restore.
	answered := func(t *testing.T, finTS time.Duration, wantFork bool) {
		f := newSvcFx(t, "service")
		f.build(3)
		e3 := f.cur
		f.at(9 * time.Hour)
		ini, err := handshake.NewInitiator(handshake.InitiatorConfig{
			Purpose: handshake.PurposeRekey, Identity: f.n.ik, StaticKEM: f.n.kem.Public(), Relay: f.n.addr,
			ResponderIK: f.d.m.keys.ik.Public().(ed25519.PublicKey), ResponderRelayKey: f.vaultPK(), Current: e3,
			Policy: policyFor(KindConnection), Now: f.now(),
		})
		if err != nil {
			t.Fatal(err)
		}
		f.deliver(ini.Envelope(), f.stJTI)
		resp := f.takeFor(func(env *envelope.Envelope) bool {
			return env.Mode() == envelope.ModeSealed && env.RecipientKid().Equal(ini.EphKid())
		})
		if resp == nil {
			t.Fatal("rekey not answered")
		}
		res, err := ini.HandleResp(resp, f.vaultPK(), f.base.Add(finTS))
		if err != nil {
			t.Fatal(err)
		}
		restore(f)
		last := append([]byte(nil), f.p.LastEpochID...)
		f.at(12 * time.Hour)
		f.deliver(res.Fin, f.stJTI)
		if (f.p.Fork != nil) != wantFork || !bytes.Equal(f.p.LastEpochID, last) || f.awaiting() != 0 {
			t.Fatalf("fork=%v last unchanged=%v awaiting=%d", f.p.Fork != nil, bytes.Equal(f.p.LastEpochID, last), f.awaiting())
		}
	}
	t.Run("a late hs.fin from the second copy suspends", func(t *testing.T) { answered(t, 11*time.Hour, true) })
	t.Run("a late hs.fin from before the crash activates nothing", func(t *testing.T) { answered(t, 9*time.Hour+10*time.Minute, false) })
}

// Two person vaults reconnecting at once: no tie-break is specified for
// persons, so the release-23 behaviour stays and neither side abandons its
// own: both complete, and each can read what the other sends (receive keys
// of earlier epochs are kept).
func TestPersonCrossingReconnectsReadable(t *testing.T) {
	a, b := newVaultPair(t)
	_, link := a.linkFor(t, time.Hour)
	r, _ := b.request(t, "connection.invite.accept", `{"link":"`+link+`"}`)
	cid := bodyStr(t, r, "connection_id")
	pump(t, b, a)
	pump(t, a, b)
	b.appInbox()
	pump(t, b, a)
	aPend := event(a.appInbox(), "connection.request.pending")
	a.request(t, "connection.approve", `{"pending_id":"`+bodyStr(t, aPend, "pending_id")+`"}`)
	pump(t, a, b)
	b.request(t, "connection.approve", `{"connection_id":"`+cid+`"}`)
	pump(t, b, a)
	pb := b.m.st.Connections[cid]
	var pa *Peer
	for _, p := range a.m.st.Connections {
		pa = p
	}
	if pa == nil || pb == nil || pa.State != PeerActive || pb.State != PeerActive {
		t.Fatal("not connected")
	}
	for _, d := range []*devFixture{a, b} {
		d.appInbox()
	}
	for _, x := range []struct {
		d *devFixture
		p *Peer
	}{{a, pa}, {b, pb}} {
		x.d.m.mu.Lock()
		x.d.m.startReconnect(x.p, x.d.m.now())
		x.d.m.mu.Unlock()
	}
	for i := 0; i < 8; i++ {
		pump(t, a, b)
		pump(t, b, a)
	}
	if a.m.hasOutgoing(pa.ID, handshake.PurposeReconnect) || b.m.hasOutgoing(pb.ID, handshake.PurposeReconnect) {
		t.Fatal("a reconnect is still open")
	}
	for _, x := range []struct {
		from, to *devFixture
		p, q     *Peer
	}{{a, b, pa, pb}, {b, a, pb, pa}} {
		nAudit := len(x.to.m.Audit())
		x.from.m.mu.Lock()
		id := x.from.m.sendTo(x.p, "x.test", []byte(`{}`), x.from.m.now())
		x.from.m.mu.Unlock()
		if id == "" {
			t.Fatal("nothing sent")
		}
		pump(t, x.from, x.to)
		_, seen := x.to.m.st.SeenInner[x.q.ID+"|"+id]
		if !seen || len(x.to.m.Audit()) != nAudit {
			t.Fatalf("a message after crossing reconnects was not read (audit: %v)", x.to.m.Audit()[nAudit:])
		}
	}
}

// An expired reconnect answer denylists the tokens it issued (§6.6).
func TestExpiredReconnectAnswerRevokesTokens(t *testing.T) {
	f := newSvcFx(t, "service")
	f.build(1)
	ini := f.initiate(f.p.LastEpochID, f.now(), nil)
	f.deliver(ini.Envelope(), "")
	var issued []IssuedToken
	for _, a := range f.d.m.st.Awaiting {
		issued = a.Issued
	}
	if len(issued) != 2 {
		t.Fatal("setup")
	}
	f.at(f.off + HandshakeTTL + time.Hour)
	f.d.m.mu.Lock()
	f.d.m.housekeeping(f.now())
	f.d.m.drainOutbox(context.Background())
	f.d.m.mu.Unlock()
	if f.awaiting() != 0 {
		t.Fatal("answer kept")
	}
	for _, tk := range issued {
		if !f.revoked(tk.JTI) {
			t.Fatal("a token of the expired answer is still valid")
		}
	}
}

// A rotation the connection followed between hs.init and hs.fin (from
// identity.rotate) does not refuse the reconnect: the links to follow are
// worked out again at hs.fin and the followed one is skipped.
func TestRotationFollowedBetweenInitAndFin(t *testing.T) {
	k0, k1 := rcKey(t, 0x10), rcKey(t, 0x20)
	r1 := rcLink(t, k0, k1)
	f := newSvcFx(t, "service")
	f.p.IK, f.p.KEM = k0.ik.Public().(ed25519.PublicKey), k0.kem.Public().Bytes()
	f.n.ik, f.n.kem = k1.ik, k1.kem
	ini := f.initiate(f.p.LastEpochID, f.now(), []*handshake.Rotation{r1})
	f.deliver(ini.Envelope(), "")
	if f.awaiting() != 1 {
		t.Fatal("not answered")
	}
	f.d.m.mu.Lock() // identity.rotate arrives and is followed
	f.p.IK, f.p.KEM, f.p.Chain = k1.ik.Public().(ed25519.PublicKey), k1.kem.Public().Bytes(), rawLinks(r1)
	f.d.m.mu.Unlock()
	last := append([]byte(nil), f.p.LastEpochID...)
	if f.complete(ini) == nil || bytes.Equal(f.p.LastEpochID, last) || len(f.p.Chain) != 1 ||
		!bytes.Equal(f.p.IK, k1.ik.Public().(ed25519.PublicKey)) || f.d.audited("reconnect_refused") {
		t.Fatal("the reconnect was refused, or the link followed twice")
	}
}

// The held reconnect survives a restart: the state is written, the vault
// unlocked again, and the hs.fin that arrives applies it (§6.6 "Replay").
func TestPendingReconnectSurvivesRestart(t *testing.T) {
	f := newSvcFx(t, "service")
	f.build(2)
	f.at(10 * time.Hour)
	ini := f.initiate(f.ids[1], f.now(), nil)
	f.deliver(ini.Envelope(), "")
	res := f.respOf(ini)
	if res == nil {
		t.Fatal("not answered")
	}
	if err := f.d.m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	m2, _, err := f.d.unlock(testPIN, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	m2.now = f.now
	m2.features = append(m2.features, f.sink)
	f.d.m = m2
	f.p = m2.st.Connections["c1"]
	aw := (*AwaitingHS)(nil)
	for _, a := range m2.st.Awaiting {
		aw = a
	}
	if aw == nil || aw.Reconnect == nil || !aw.Reconnect.Older || aw.Reconnect.Standing.Token == "" || !m2.initAnswered(ini.Th1()) {
		t.Fatalf("the held reconnect or the th1 mark did not survive: %+v", aw)
	}
	f.sink.got = nil
	f.deliver(res.Fin, f.stJTI)
	nid := res.Epoch.ID()
	if !bytes.Equal(f.p.LastEpochID, nid[:]) || f.p.Watch == nil || len(f.p.Watch.Replaced) != 1 || !f.sink.has("connection.restored_reconnect") {
		t.Fatal("the hs.fin after the restart did not apply the reconnect")
	}
}
