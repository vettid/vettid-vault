package vault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"
	"github.com/vettid/vettid-relay/relayclient"

	"github.com/vettid/vettid-vault/vault/store"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/suite"
)

// testSealer is a test-only sealer (the real dev sealer lives behind the
// devenclave tag).
type testSealer struct{ key []byte }

func (s testSealer) Seal(_ context.Context, pt, aad []byte) ([]byte, error) {
	n, _ := suite.NewNonce()
	ct, err := suite.SealX(s.key, n, aad, pt)
	return append(n, ct...), err
}

func (s testSealer) Unseal(_ context.Context, b, aad []byte) ([]byte, error) {
	if len(b) < 40 {
		return nil, errors.New("short")
	}
	return suite.OpenX(s.key, b[:24], aad, b[24:])
}

// stubRelay records deposits and signs tokens like a relay client, with no
// network.
type stubRelay struct {
	mu       sync.Mutex
	base     string
	key      ed25519.PrivateKey
	deposits []stubDeposit
	revoked  []string
	failWith error
	// mailboxDeleted counts DeleteMailbox calls; deleteErr fails them.
	mailboxDeleted int
	deleteErr      error
}

type stubDeposit struct {
	mailbox, token string
	payload        []byte
}

func (r *stubRelay) BaseURL() string { return r.base }
func (r *stubRelay) Register(context.Context) (Limits, error) {
	return Limits{MaxTokenLifetimeSeconds: 400 * 86400, OpenTokenMaxLifetimeSeconds: 7 * 86400, ClaimTTLSeconds: 7 * 86400}, nil
}
func (r *stubRelay) Collector(context.Context, bool) (Collector, error) {
	return nil, errors.New("no collect")
}
func (r *stubRelay) Deposit(_ context.Context, _, mailbox, token string, payload []byte) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failWith != nil {
		return "", r.failWith
	}
	r.deposits = append(r.deposits, stubDeposit{mailbox, token, append([]byte(nil), payload...)})
	return fmt.Sprintf("m%d", len(r.deposits)), nil
}
func (r *stubRelay) Revoke(_ context.Context, kind, value string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.revoked = append(r.revoked, kind+":"+value)
	return nil
}
func (r *stubRelay) PutClaim(context.Context, []byte, time.Duration) (string, time.Time, error) {
	return "abcdefghijklmnopqrstuvwxyz", time.Now().Add(time.Hour), nil
}
func (r *stubRelay) GetClaim(context.Context, string, string) ([]byte, error) {
	return nil, errors.New("none")
}
func (r *stubRelay) DeleteClaim(context.Context, string) error { return nil }
func (r *stubRelay) DeleteMailbox(context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.deleteErr != nil {
		return r.deleteErr
	}
	r.mailboxDeleted++
	return nil
}
func (r *stubRelay) client() *relayclient.Client {
	c := relayclient.New(r.base, r.key)
	return c
}
func (r *stubRelay) MintToken(sub ed25519.PublicKey, ttl time.Duration, jti string, q *relayauth.Quota) (string, error) {
	return r.client().MintToken(relayauth.EncodeKey(sub), r.base, relayclient.TokenOptions{TTL: ttl, JTI: jti, Quota: q})
}
func (r *stubRelay) MintOpenToken(ttl time.Duration, jti string) (string, error) {
	return r.client().MintOpenToken(r.base, ttl, jti)
}

type fakeCollector struct {
	mu    sync.Mutex
	acked []string
}

func (c *fakeCollector) Next(context.Context) ([]Message, error) { return nil, nil }
func (c *fakeCollector) Ack(_ context.Context, id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.acked = append(c.acked, id)
	return nil
}
func (c *fakeCollector) Close() error { return nil }

const testPIN = "1234"

var testRelease = Release{PCR0: "dev", Number: 1}

type fixture struct {
	t     testing.TB
	store store.Store
	opts  Options
	relay *stubRelay
	m     *Manager
	vid   string
}

func newFixture(t testing.TB) *fixture {
	t.Helper()
	f := &fixture{t: t, store: store.NewMemory()}
	f.opts = Options{Store: f.store, Sealer: testSealer{key: bytes.Repeat([]byte{7}, 32)}, Release: testRelease,
		Relay: func(base string, key ed25519.PrivateKey) Relay {
			f.relay = &stubRelay{base: base, key: key}
			return f.relay
		}}
	k, err := MinKDF()
	if err != nil {
		t.Fatal(err)
	}
	m, err := Create(context.Background(), CreateParams{Options: f.opts, UserGUID: "u1", PIN: testPIN, KDF: k, RelayURL: "https://relay.example.org"})
	if err != nil {
		t.Fatal(err)
	}
	f.m = m
	f.vid = m.VaultID()
	return f
}

func (f *fixture) unlock(pin string, minState, minHeader uint64) (*Manager, UnlockResult, error) {
	return Unlock(context.Background(), UnlockParams{Options: f.opts, VaultID: f.vid, PIN: pin, MinStateSeq: minState, MinHeaderSeq: minHeader})
}

func TestCreateUnlock(t *testing.T) {
	f := newFixture(t)
	if err := f.m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	m, res, err := f.unlock(testPIN, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if res.StateSeq < 2 || res.HeaderSeq < 2 {
		t.Fatalf("seqs %+v", res)
	}
	if m.Locked() {
		t.Fatal("locked after unlock")
	}
}

// §11.8: failures are counted in the header and back off after 3; they
// never wipe the vault; success resets.
func TestBadPINBackoff(t *testing.T) {
	f := newFixture(t)
	vid := f.vid
	f.m.Crash()
	now := time.Now()
	f.opts.Now = func() time.Time { return now }
	var last uint64
	for i := 1; i <= 3; i++ {
		_, res, err := f.unlock("9999", 0, 0)
		if !errors.Is(err, ErrBadPIN) {
			t.Fatalf("attempt %d: %v", i, err)
		}
		if res.HeaderSeq <= last {
			t.Fatal("header_seq did not increase on failure (§13.2)")
		}
		last = res.HeaderSeq
	}
	if _, _, err := f.unlock(testPIN, 0, 0); !errors.Is(err, ErrBackoff) {
		t.Fatalf("no backoff after 3 failures: %v", err)
	}
	now = now.Add(31 * time.Second)
	m, _, err := f.unlock(testPIN, 0, 0)
	if err != nil || m.VaultID() != vid {
		t.Fatalf("unlock after backoff: %v", err)
	}
	if m.hdr.Backoff.Failures != 0 {
		t.Fatal("backoff not reset")
	}
}

// §13.2 rollback rules.
func TestRollbackRefused(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	vid := f.vid
	old, oldVer, _ := f.store.Get(ctx, store.StateKey(vid))
	f.m.mu.Lock()
	if err := f.m.persist(ctx, false); err != nil {
		t.Fatal(err)
	}
	f.m.mu.Unlock()
	f.m.Crash()
	_ = oldVer
	// Serve the older state object with the newer header.
	_, cur, _ := f.store.Get(ctx, store.StateKey(vid))
	if _, err := f.store.Put(ctx, store.StateKey(vid), old, cur); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.unlock(testPIN, 0, 0); !errors.Is(err, ErrRollback) {
		t.Fatalf("state behind header: %v", err)
	}
	g := newFixture(t)
	g.m.Crash()
	if _, _, err := g.unlock(testPIN, 1000, 0); !errors.Is(err, ErrRollback) {
		t.Fatal("min_state_seq not enforced")
	}
	if _, _, err := g.unlock(testPIN, 0, 1000); !errors.Is(err, ErrRollback) {
		t.Fatal("min_header_seq not enforced")
	}
}

// §12.3 split-brain guard: a conditional write that finds a newer version
// zeroizes immediately, without acking.
func TestSplitBrainZeroizes(t *testing.T) {
	f := newFixture(t)
	second, _, err := f.unlock(testPIN, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.m.mu.Lock()
	if err := f.m.persist(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	f.m.mu.Unlock()
	c := &fakeCollector{}
	err = second.ProcessBatch(context.Background(), c, []Message{{MsgID: "x", Sender: "AAAA", Payload: []byte{1}}})
	if !errors.Is(err, ErrSplitBrain) || !second.Locked() {
		t.Fatalf("err %v locked %v", err, second.Locked())
	}
	if len(c.acked) != 0 {
		t.Fatal("acked after split brain")
	}
	if second.dek != nil || second.keys != nil || second.st != nil {
		t.Fatal("not zeroized")
	}
}

func TestStateBlobBinding(t *testing.T) {
	dek := bytes.Repeat([]byte{1}, 32)
	blob, err := encryptState(dek, "v1", 7, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, seq, err := decryptState(dek, "v1", blob); err != nil || seq != 7 {
		t.Fatal("round trip")
	}
	if _, _, err := decryptState(dek, "v2", blob); err == nil {
		t.Fatal("state of another vault accepted")
	}
	b := bytes.Clone(blob)
	b[8] ^= 1 // state_seq
	if _, _, err := decryptState(dek, "v1", b); err == nil {
		t.Fatal("tampered state_seq accepted")
	}
}

func TestKDF(t *testing.T) {
	k, _ := MinKDF()
	pep := bytes.Repeat([]byte{2}, 32)
	a, err := deriveDEK("1234", k, pep, "v1")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := deriveDEK("1234", k, pep, "v1")
	c, _ := deriveDEK("1235", k, pep, "v1")
	d, _ := deriveDEK("1234", k, bytes.Repeat([]byte{3}, 32), "v1")
	if !bytes.Equal(a, b) || bytes.Equal(a, c) || bytes.Equal(a, d) {
		t.Fatal("DEK derivation")
	}
	bad := k
	bad.MemoryKiB = 1024
	if _, err := deriveDEK("1234", bad, pep, "v1"); !errors.Is(err, ErrKDF) {
		t.Fatal("weak params accepted")
	}
}

// The sealed header never carries the relay key, session keys or feature
// data (§3.3).
func TestHeaderContents(t *testing.T) {
	f := newFixture(t)
	b, err := json.Marshal(f.m.hdr)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range [][]byte{f.m.st.Relay.Seed, f.m.st.IdentitySeed, f.m.st.KEMSeed} {
		if bytes.Contains(b, secret) || bytes.Contains(b, []byte(fmt.Sprintf("%q", secret))) {
			t.Fatal("header holds a key")
		}
	}
	var o map[string]json.RawMessage
	_ = json.Unmarshal(b, &o)
	keys := make([]string, 0, len(o))
	for k := range o {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	want := "[backoff created_at header_seq kdf manifest_serial pepper provisional sealed_release state_seq unlock_keys user_guid v vault_id]"
	if fmt.Sprint(keys) != want {
		t.Fatalf("header members %v", keys)
	}
}

// --- a paired device in-process, for routing and handler tests ---

type devFixture struct {
	*fixture
	dev     ed25519.PrivateKey
	devKey  ed25519.PrivateKey
	devPeer *Peer
	ep      *handshake.Epoch // device side
	seq     int
}

func newDevFixture(t testing.TB) *devFixture {
	f := newFixture(t)
	m := f.m
	devIK := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x31}, 32))
	devRelay := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x32}, 32))
	devKEM, _ := suite.NewPrivateKey(bytes.Repeat([]byte{0x33}, 32))
	pk := devRelay.Public().(ed25519.PublicKey)
	addr := handshake.RelayAddr{URL: "https://relay.example.org", Mailbox: relayauth.MailboxID(pk), PK: pk}
	now := time.Now()
	// Run a real pairing handshake directly between device and vault keys.
	ini, err := handshake.NewInitiator(handshake.InitiatorConfig{Purpose: handshake.PurposeApp, Ctx: "01JB2Z6V9K3M4N5P6Q7R8S9T0V",
		Identity: devIK, StaticKEM: devKEM.Public(), Relay: addr, Token: "v4.public.VEVTVA",
		ResponderIK: m.keys.ik.Public().(ed25519.PublicKey), ResponderEK: m.keys.kem.Public(), ResponderRelayKey: m.keys.relay.Public().(ed25519.PublicKey),
		Policy: handshake.PolicyVaultToDevice, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	pi, err := handshake.OpenInit(ini.Envelope(), m.lookupKEM, now)
	if err != nil {
		t.Fatal(err)
	}
	resp, renv, err := pi.Respond(handshake.ResponderConfig{Identity: m.keys.ik, Token: "v4.public.VEVTVA", Policy: handshake.PolicyVaultToDevice, CollectSender: pk, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	res, err := ini.HandleResp(renv, m.keys.relay.Public().(ed25519.PublicKey), now)
	if err != nil {
		t.Fatal(err)
	}
	vep, _, err := resp.HandleFin(res.Fin, pk, now)
	if err != nil {
		t.Fatal(err)
	}
	p := &Peer{ID: "dev1", Kind: KindApp, State: PeerActive, IK: devIK.Public().(ed25519.PublicKey), KEM: devKEM.Public().Bytes(),
		Relay: PeerRelay{URL: addr.URL, Mailbox: addr.Mailbox, PK: pk}, Standing: HeldToken{Token: "v4.public.VEVTVA", Exp: now.Add(20 * 24 * time.Hour)}}
	m.st.Devices[p.ID] = p
	m.st.Issued = append(m.st.Issued, IssuedToken{JTI: "j1", Kind: TokStanding, Sub: relayauth.EncodeKey(pk), PeerID: p.ID, Exp: now.Add(20 * 24 * time.Hour)})
	m.sessions[p.ID] = &handshake.Keyring{}
	m.sessions[p.ID].Activate(vep, now)
	return &devFixture{fixture: f, dev: devIK, devKey: devRelay, devPeer: p, ep: res.Epoch}
}

// send seals a message from the device and runs it through ProcessBatch.
func (d *devFixture) send(typ string, body []byte) error {
	d.seq++
	id, _ := envelope.NewULID(time.Now())
	raw, err := d.ep.Seal(&envelope.Inner{ID: id, Type: typ, TS: time.Now(), Body: body})
	if err != nil {
		return err
	}
	msg := Message{MsgID: fmt.Sprintf("r%d", d.seq), Sender: relayauth.EncodeKey(d.devPeer.Relay.PK), Payload: raw}
	return d.m.ProcessBatch(context.Background(), &fakeCollector{}, []Message{msg})
}

// responses decrypts the vault's deposits to the device.
func (d *devFixture) responses(t testing.TB) []*envelope.Inner {
	var out []*envelope.Inner
	d.relay.mu.Lock()
	defer d.relay.mu.Unlock()
	for _, dep := range d.relay.deposits {
		env, err := envelope.Parse(dep.payload)
		if err != nil || env.Mode() != envelope.ModeSession {
			continue
		}
		var kr handshake.Keyring
		kr.Activate(d.ep, time.Now())
		if in, _, err := kr.Open(env, time.Now()); err == nil {
			out = append(out, in)
		}
	}
	d.relay.deposits = nil
	return out
}

func TestRequestResponseAndDedupe(t *testing.T) {
	d := newDevFixture(t)
	if err := d.send("vault.status", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	rs := d.responses(t)
	if len(rs) != 1 || rs[0].Status != envelope.StatusOK || rs[0].Type != "vault.status" {
		t.Fatalf("responses %v", rs)
	}
	// Unknown type: unsupported_type (§5.3).
	_ = d.send("nope.nope", []byte(`{}`))
	rs = d.responses(t)
	if len(rs) != 1 || rs[0].Error == nil || rs[0].Error.Code != "unsupported_type" {
		t.Fatalf("unknown type: %+v", rs)
	}
	// A type the device role may not send: forbidden.
	_ = d.send("connection.removed", []byte(`{}`))
	if rs = d.responses(t); len(rs) != 0 {
		t.Fatal("event type from wrong principal answered")
	}
	// Same relay msg_id again: deduped, no response.
	id, _ := envelope.NewULID(time.Now())
	raw, _ := d.ep.Seal(&envelope.Inner{ID: id, Type: "vault.status", TS: time.Now(), Body: []byte(`{}`)})
	msg := Message{MsgID: "same", Sender: relayauth.EncodeKey(d.devPeer.Relay.PK), Payload: raw}
	_ = d.m.ProcessBatch(context.Background(), &fakeCollector{}, []Message{msg})
	_ = d.m.ProcessBatch(context.Background(), &fakeCollector{}, []Message{msg})
	if rs = d.responses(t); len(rs) != 1 {
		t.Fatalf("msg_id dedupe: %d responses", len(rs))
	}
	// Same inner id in a new envelope: cached response, same answer.
	raw2, _ := d.ep.Seal(&envelope.Inner{ID: id, Type: "vault.status", TS: time.Now(), Body: []byte(`{}`)})
	_ = d.m.ProcessBatch(context.Background(), &fakeCollector{}, []Message{{MsgID: "other", Sender: msg.Sender, Payload: raw2}})
	if rs = d.responses(t); len(rs) != 1 || rs[0].Re != id {
		t.Fatalf("inner dedupe: %+v", rs)
	}
}

// §6.3 / §13.6: a message whose collect sender is not the principal of the
// session that would decrypt it is not processed.
func TestSenderMismatchDropped(t *testing.T) {
	d := newDevFixture(t)
	id, _ := envelope.NewULID(time.Now())
	raw, _ := d.ep.Seal(&envelope.Inner{ID: id, Type: "vault.status", TS: time.Now(), Body: []byte(`{}`)})
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x77}, 32)).Public().(ed25519.PublicKey)
	_ = d.m.ProcessBatch(context.Background(), &fakeCollector{}, []Message{{MsgID: "z", Sender: relayauth.EncodeKey(other), Payload: raw}})
	if rs := d.responses(t); len(rs) != 0 {
		t.Fatal("processed a message from the wrong sender")
	}
	if a := d.m.Audit(); len(a) == 0 {
		t.Fatal("not audited")
	}
}

// §8.4: future and stale timestamps are rejected.
func TestTimestampWindow(t *testing.T) {
	d := newDevFixture(t)
	for _, ts := range []time.Time{time.Now().Add(10 * time.Minute), time.Now().Add(-17 * 24 * time.Hour)} {
		id, _ := envelope.NewULID(time.Now())
		raw, _ := d.ep.Seal(&envelope.Inner{ID: id, Type: "vault.status", TS: ts, Body: []byte(`{}`)})
		_ = d.m.ProcessBatch(context.Background(), &fakeCollector{}, []Message{{MsgID: id, Sender: relayauth.EncodeKey(d.devPeer.Relay.PK), Payload: raw}})
	}
	if rs := d.responses(t); len(rs) != 0 {
		t.Fatal("out-of-window message processed")
	}
}

// §8.5: ephemeral types need exp, are acked at once, and are deduped in
// memory.
func TestEphemeralClass(t *testing.T) {
	d := newDevFixture(t)
	var calls int
	d.m.register(TypeSpec{Type: "presence.test", Ephemeral: true, From: []string{KindApp}},
		HandlerFunc(func(context.Context, *Session, *envelope.Inner) (json.RawMessage, error) { calls++; return nil, nil }))
	id, _ := envelope.NewULID(time.Now())
	mk := func(exp time.Time) []byte {
		raw, _ := d.ep.Seal(&envelope.Inner{ID: id, Type: "presence.test", TS: time.Now(), Exp: exp, Body: []byte(`{}`)})
		return raw
	}
	c := &fakeCollector{}
	sender := relayauth.EncodeKey(d.devPeer.Relay.PK)
	_ = d.m.ProcessBatch(context.Background(), c, []Message{{MsgID: "e0", Sender: sender, Payload: mk(time.Time{})}})
	if calls != 0 {
		t.Fatal("ephemeral without exp handled")
	}
	_ = d.m.ProcessBatch(context.Background(), c, []Message{{MsgID: "e1", Sender: sender, Payload: mk(time.Now().Add(30 * time.Second))}})
	_ = d.m.ProcessBatch(context.Background(), c, []Message{{MsgID: "e2", Sender: sender, Payload: mk(time.Now().Add(30 * time.Second))}})
	if calls != 1 {
		t.Fatalf("ephemeral handled %d times", calls)
	}
}

// §7.3: more than 60 durable messages per minute from a peer are dropped.
func TestPeerRateLimit(t *testing.T) {
	m := &Manager{rates: map[string]*rateWindow{}}
	now := time.Now()
	n := 0
	for range 100 {
		if m.rateAllow("p", now) {
			n++
		}
	}
	if n != PeerRateLimit || !m.rateAllow("p", now.Add(time.Minute)) {
		t.Fatalf("allowed %d", n)
	}
}

// §8.6 error table on deposits.
func TestDepositErrors(t *testing.T) {
	d := newDevFixture(t)
	d.relay.failWith = &relayclient.Error{Status: 403, Code: CodeTokenRevoked}
	_ = d.send("vault.status", []byte(`{}`))
	if d.devPeer.State != PeerStale {
		t.Fatal("token_revoked did not mark the principal stale")
	}
	for _, e := range d.m.st.Outbox {
		if !e.Done {
			t.Fatal("entries for a revoked mailbox kept")
		}
	}
}

// FuzzDeviceMessage feeds arbitrary bodies of every registered type, from a
// paired device, through the full inbound path (§13.6: parsers fuzzed).
func FuzzDeviceMessage(f *testing.F) {
	d := newDevFixture(f)
	types := make([]string, 0, len(d.m.registry))
	for t := range d.m.registry {
		types = append(types, t)
	}
	sort.Strings(types)
	f.Add(uint8(0), []byte(`{}`))
	f.Add(uint8(3), []byte(`{"role":"desktop"}`))
	f.Add(uint8(9), []byte(`{"connection_id":"x","text":"hi"}`))
	f.Fuzz(func(t *testing.T, ti uint8, body []byte) {
		if _, err := envelope.Pad(body); err != nil || len(body) == 0 || body[0] != '{' {
			return
		}
		typ := types[int(ti)%len(types)]
		if typ == "vault.lock" || typ == "device.unlink" {
			return // these change the fixture itself
		}
		_ = d.send(typ, body)
		d.responses(t)
		if d.m.Locked() {
			t.Fatal("vault locked by a message")
		}
	})
}

// Deposits to one mailbox stay in order: an entry waiting for a retry
// holds back later deposits to the same mailbox (an hs.fin must precede
// traffic in its epoch), while other mailboxes proceed.
func TestOutboxOrderPerMailbox(t *testing.T) {
	f := newFixture(t)
	now := time.Now()
	f.m.mu.Lock()
	defer f.m.mu.Unlock()
	f.m.now = func() time.Time { return now }
	q := func(mb, tag string) {
		f.m.queueDeposit(&OutboxEntry{RelayURL: "https://r", Mailbox: mb, Token: "t", Payload: []byte(tag)}, now)
	}
	q("a", "a1")
	q("a", "a2")
	q("b", "b1")
	f.m.st.Outbox[len(f.m.st.Outbox)-3].NotBefore = now.Add(time.Second) // a1 waits for a retry
	f.m.drainOutbox(context.Background())                                // a2 must not overtake it
	var got []string
	for _, d := range f.relay.deposits {
		got = append(got, string(d.payload))
	}
	if fmt.Sprint(got) != "[b1]" {
		t.Fatalf("deposits before the retry: %v", got)
	}
	now = now.Add(time.Minute)
	f.m.drainOutbox(context.Background())
	got = nil
	for _, d := range f.relay.deposits {
		got = append(got, string(d.payload))
	}
	if fmt.Sprint(got) != "[b1 a1 a2]" {
		t.Fatalf("deposits: %v", got)
	}
}
