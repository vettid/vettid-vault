package vault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"
	"github.com/vettid/vettid-relay/relayclient"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/suite"
)

// VAULT-MESSAGING §3.4 "The order of a relay-key rotation" and "Resending
// the new address", §12.2 "On unlock" step 3, §10.2 vault.status `relay`.

// completeRelayKey stores the state and runs the relay-key step, as the
// flush of a batch does (§3.4): the relay's rotate, then the second write.
// The caller holds m.mu.
func completeRelayKey(m *Manager) error {
	if err := m.persist(context.Background(), false); err != nil {
		return err
	}
	m.relayKeyStep(context.Background(), false)
	if m.locked {
		return m.lockedErr()
	}
	return nil
}

// kinds returns the recorded activities of a kind.
func (r *recSink) kinds(kind string) []Activity {
	var out []Activity
	for _, a := range r.got {
		if a.Kind == kind {
			out = append(out, a)
		}
	}
	return out
}

// rkFixture is a vault with an app, a desktop and a connection, each
// holding a real standing token issued to the vault's relay key, a
// scripted relay (stubRot) kept across unlocks and a clock.
type rkFixture struct {
	*devFixture
	t     *testing.T
	rot   *stubRot
	sink  *recSink
	desk  *tdev
	conn  *tdev
	peers map[string]*tdev
	keys  map[string]ed25519.PrivateKey // each peer's relay key
	clock time.Time
}

const rkBase = "https://relay.example.org"

func newRKFixture(t *testing.T) *rkFixture {
	t.Helper()
	d := newDevFixture(t)
	sink := sinkOf(d)
	d.opts.Features = append(d.opts.Features, sink)
	r := &rkFixture{devFixture: d, t: t, rot: &stubRot{}, sink: sink, clock: time.Now().UTC()}
	d.relay.rot = r.rot
	d.opts.Relay = func(base string, key ed25519.PrivateKey) Relay {
		d.relay = &stubRelay{base: base, key: key, rot: r.rot, now: func() time.Time { return r.clock }}
		return d.relay
	}
	d.opts.Now = func() time.Time { return r.clock }
	d.m.now = d.opts.Now
	r.desk = d.addDevice(t, "dk1", KindDesktop, 0x5a)
	r.conn = d.asConnection(t, "c1", 0x51)
	r.peers = map[string]*tdev{"dev1": d.self(), "dk1": r.desk, "c1": r.conn}
	r.keys = map[string]ed25519.PrivateKey{"dev1": d.devKey, "dk1": seedKey(0x5b), "c1": seedKey(0x52)}
	d.m.mu.Lock()
	for id := range r.peers {
		p := d.m.peer(id)
		p.Standing = r.tokenFrom(id, pubOf(d.m.keys.relay), 20*24*time.Hour)
	}
	d.m.mu.Unlock()
	return r
}

func seedKey(b byte) ed25519.PrivateKey { return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{b}, 32)) }

// tokenFrom is a standing token peer id issued to the vault key sub.
func (r *rkFixture) tokenFrom(id string, sub ed25519.PublicKey, ttl time.Duration) HeldToken {
	c := relayclient.New(rkBase, r.keys[id])
	c.Now = func() time.Time { return r.clock }
	tok, err := c.MintToken(relayauth.EncodeKey(sub), rkBase, relayclient.TokenOptions{TTL: ttl})
	if err != nil {
		r.t.Fatal(err)
	}
	return HeldToken{Token: tok, Exp: r.clock.Truncate(time.Second).Add(-time.Minute).Add(ttl)}
}

func (r *rkFixture) advance(d time.Duration) { r.clock = r.clock.Add(d) }

// lockUnlock locks (or crashes) the vault and unlocks it again, without
// starting it.
func (r *rkFixture) lockUnlock(crash bool) {
	r.t.Helper()
	if crash {
		r.m.Crash()
	} else if err := r.m.Lock(context.Background()); err != nil {
		r.t.Fatal(err)
	}
	m, _, err := r.unlock(testPIN, 0, 0)
	if err != nil {
		r.t.Fatal(err)
	}
	r.fixture.m = m
}

func (r *rkFixture) start() {
	r.t.Helper()
	if err := r.m.Start(context.Background()); err != nil {
		r.t.Fatal(err)
	}
}

// rotate makes a rotation in memory: the member's credential.rotate
// (byCredential), or a recovery's or a transfer's.
func (r *rkFixture) rotate(byCredential bool) {
	r.t.Helper()
	r.m.mu.Lock()
	defer r.m.mu.Unlock()
	if err := r.m.rotateKeys(r.m.now(), byCredential); err != nil {
		r.t.Fatal(err)
	}
}

// flushStep is a batch's flush: the write, then the relay-key step, then
// the drain.
func (r *rkFixture) flushStep() {
	r.t.Helper()
	r.m.mu.Lock()
	defer r.m.mu.Unlock()
	if err := completeRelayKey(r.m); err != nil {
		r.t.Fatal(err)
	}
	r.m.drainOutbox(context.Background())
	if err := r.m.flushIfDirty(context.Background()); err != nil {
		r.t.Fatal(err)
	}
}

func (r *rkFixture) with(f func(m *Manager)) {
	r.m.mu.Lock()
	defer r.m.mu.Unlock()
	f(r.m)
}

func (r *rkFixture) pending() *PendingRelay {
	var pr *PendingRelay
	r.with(func(m *Manager) { pr = m.st.Relay.Pending })
	return pr
}

func (r *rkFixture) relayPub() ed25519.PublicKey {
	var pk ed25519.PublicKey
	r.with(func(m *Manager) { pk = append(ed25519.PublicKey(nil), pubOf(m.keys.relay)...) })
	return pk
}

func (r *rkFixture) rotated() []string {
	r.rot.mu.Lock()
	defer r.rot.mu.Unlock()
	return append([]string(nil), r.rot.rotated...)
}

func (r *rkFixture) registered() []string {
	r.rot.mu.Lock()
	defer r.rot.mu.Unlock()
	return append([]string(nil), r.rot.registered...)
}

// seen is one decrypted deposit to a peer.
type seen struct {
	in     *envelope.Inner
	sender ed25519.PublicKey
	token  string
}

// deposits decrypts (and clears) the vault's deposits to each peer.
func (r *rkFixture) deposits() map[string][]seen {
	out := map[string][]seen{}
	rel := r.relay.top()
	rel.mu.Lock()
	defer rel.mu.Unlock()
	for _, dep := range rel.deposits {
		env, err := envelope.Parse(dep.payload)
		if err != nil || env.Mode() != envelope.ModeSession {
			continue
		}
		for id, td := range r.peers {
			if dep.mailbox != td.peer.Relay.Mailbox {
				continue
			}
			var kr handshake.Keyring
			kr.Activate(td.ep, r.clock)
			if in, _, err := kr.Open(env, r.clock); err == nil {
				out[id] = append(out[id], seen{in, dep.sender, dep.token})
			}
		}
	}
	rel.deposits = nil
	return out
}

func updatesOf(ss []seen) []seen {
	var out []seen
	for _, s := range ss {
		if s.in.Type == TypeAddressUpdate {
			out = append(out, s)
		}
	}
	return out
}

// parseUpdate reads relay.address.update's body.
func parseUpdate(t *testing.T, body []byte) (mailbox string, pk []byte, token, reconnect string) {
	t.Helper()
	o, err := strictjson.ParseObject(body)
	if err != nil {
		t.Fatal(err)
	}
	ro, err := o.Object("relay")
	if err != nil {
		t.Fatal(err)
	}
	mailbox, _ = ro.String("mailbox")
	pk, _ = ro.Base64("pk", 32)
	token, _ = o.String("token")
	reconnect, _, _ = o.OptString("reconnect_token")
	return
}

// sendFrom sends a message from a peer, deposited with jti.
func (r *rkFixture) sendFrom(id, typ, body, jti string) {
	r.t.Helper()
	td := r.peers[id]
	r.seq++
	iid, _ := envelope.NewULID(r.clock)
	raw, err := td.ep.Seal(&envelope.Inner{ID: iid, Type: typ, TS: r.clock, Body: []byte(body)})
	if err != nil {
		r.t.Fatal(err)
	}
	if jti == "" && td.peer.Kind == KindConnection {
		jti = "standing-" + id
	}
	msg := Message{MsgID: fmt.Sprintf("rk%d", r.seq), Sender: relayauth.EncodeKey(td.peer.Relay.PK), Payload: raw, JTI: jti}
	if err := r.m.ProcessBatch(context.Background(), &fakeCollector{}, []Message{msg}); err != nil {
		r.t.Fatal(err)
	}
}

// issueToVault is the peer's relay.token.issued for the vault's current key.
func (r *rkFixture) issueToVault(id string) {
	tok := r.tokenFrom(id, r.relayPub(), 30*24*time.Hour).Token
	r.sendFrom(id, "relay.token.issued", `{"kind":"standing","token":"`+tok+`"}`, "")
}

// statusRelay is vault.status's `relay` member for a peer ("" absent).
func (r *rkFixture) statusRelay(id string) string {
	r.t.Helper()
	_ = r.deposits()
	r.sendFrom(id, "vault.status", `{}`, "")
	for _, s := range r.deposits()[id] {
		if s.in.Type == "vault.status" && s.in.Status == envelope.StatusOK {
			o, err := strictjson.ParseObject(s.in.Body)
			if err != nil {
				r.t.Fatal(err)
			}
			v, _, _ := o.OptString("relay")
			return v
		}
	}
	r.t.Fatalf("no vault.status answer to %s", id)
	return ""
}

// Step 1, 2, 3: the rotation's write stores the new key as pending with
// held tokens and nothing announced; the rotate (signed by the current key,
// with the pending key) follows the write; the second write makes the key
// current, sends each recipient relay.address.update with the old key on
// its token for the old key, and audits identity.rotated there, not at the
// first write.
func TestRelayKeyOrderOfARotation(t *testing.T) {
	r := newRKFixture(t)
	oldPub := r.relayPub()
	_ = r.deposits()
	r.rotate(true)
	pr := r.pending()
	if pr == nil || len(pr.Tokens) != 3 || pr.Tokens["c1"].Reconnect == "" || pr.Tokens["dk1"].Reconnect != "" {
		t.Fatalf("pending %+v", pr)
	}
	if !bytes.Equal(r.relayPub(), oldPub) || len(r.rotated()) != 0 || len(r.sink.kinds("identity.rotated")) != 0 {
		t.Fatal("the key changed, the relay was called or the rotation audited before the write")
	}
	var queued int
	r.with(func(m *Manager) {
		for _, e := range m.st.Outbox {
			if e.AddressUpdate {
				queued++
			}
		}
	})
	if queued != 0 {
		t.Fatal("an update queued at the first write")
	}
	newMailbox := mailboxOf(ed25519.NewKeyFromSeed(pr.Seed))
	r.flushStep()
	if got := r.rotated(); len(got) != 1 || got[0] != newMailbox {
		t.Fatalf("rotates %v, want %s", got, newMailbox)
	}
	if r.pending() != nil || r.m.st.Relay.Mailbox != newMailbox || len(r.m.st.Relay.Old) != 1 {
		t.Fatal("the key is not current after the second write")
	}
	if a := r.sink.kinds("identity.rotated"); len(a) != 1 || a[0].Ref != "" {
		t.Fatalf("identity.rotated %+v", a)
	}
	deps := r.deposits()
	for id := range r.peers {
		ups := updatesOf(deps[id])
		if len(ups) != 1 || !bytes.Equal(ups[0].sender, oldPub) {
			t.Fatalf("%s: %d updates, or not with the old key", id, len(ups))
		}
		mb, pk, tok, rc := parseUpdate(t, ups[0].in.Body)
		if mb != newMailbox || !bytes.Equal(pk, r.relayPub()) || tok == "" || (id == "c1") != (rc != "") {
			t.Fatalf("%s: update %s %x %q %q", id, mb, pk, tok, rc)
		}
		c, err := relayauth.ParseToken(tok, r.relayPub())
		if err != nil || c.Iss != newMailbox || c.Sub != relayauth.EncodeKey(r.peers[id].peer.Relay.PK) {
			t.Fatalf("%s: token %v %+v", id, err, c)
		}
	}
}

// A run that ends before the rotate, between the rotate and the second
// write, or after the second write: the next unlock completes the same key
// with a repeated rotate (the same new key, a new request), never a second
// key, and sends the updates once.
func TestRelayKeyCrashes(t *testing.T) {
	t.Run("before the rotate", func(t *testing.T) {
		r := newRKFixture(t)
		r.rotate(true)
		r.with(func(m *Manager) {
			if err := m.persist(context.Background(), false); err != nil {
				t.Fatal(err)
			}
		})
		seed := append([]byte(nil), r.pending().Seed...)
		r.lockUnlock(true)
		if pr := r.pending(); pr == nil || !bytes.Equal(pr.Seed, seed) {
			t.Fatal("the stored state lost the pending key")
		}
		_ = r.deposits()
		r.start()
		if got := r.rotated(); len(got) != 1 || got[0] != mailboxOf(ed25519.NewKeyFromSeed(seed)) || r.pending() != nil {
			t.Fatalf("rotates %v, pending %v", got, r.pending() != nil)
		}
		if n := len(updatesOf(r.deposits()["c1"])); n != 1 {
			t.Fatalf("%d updates", n)
		}
	})
	t.Run("after the rotate, before the second write", func(t *testing.T) {
		r := newRKFixture(t)
		r.rotate(true)
		r.with(func(m *Manager) {
			if err := m.persist(context.Background(), false); err != nil {
				t.Fatal(err)
			}
		})
		seed := append([]byte(nil), r.pending().Seed...)
		fs := failWrites(r.devFixture, 0)
		r.rot.rotate = func(string) error { fs.mu.Lock(); fs.failState = 1; fs.mu.Unlock(); return nil }
		_ = r.deposits()
		r.with(func(m *Manager) {
			m.relayKeyStep(context.Background(), false)
			m.drainOutbox(context.Background())
		})
		if n := len(updatesOf(r.deposits()["c1"])); n != 0 {
			t.Fatal("an update was sent without the second write")
		}
		r.rot.rotate = nil
		r.lockUnlock(true)
		if pr := r.pending(); pr == nil || !bytes.Equal(pr.Seed, seed) {
			t.Fatal("the stored state lost the pending key")
		}
		r.start()
		got := r.rotated()
		if len(got) != 2 || got[0] != got[1] || r.pending() != nil {
			t.Fatalf("rotates %v: not repeated with the same key", got)
		}
		if n := len(updatesOf(r.deposits()["dk1"])); n != 1 {
			t.Fatalf("%d updates", n)
		}
	})
	t.Run("after the second write", func(t *testing.T) {
		r := newRKFixture(t)
		r.rotate(true)
		r.with(func(m *Manager) {
			if err := completeRelayKey(m); err != nil {
				t.Fatal(err)
			}
		})
		_ = r.deposits() // nothing was drained: the crash comes first
		r.lockUnlock(true)
		r.start()
		if len(r.rotated()) != 1 || r.pending() != nil {
			t.Fatal("rotated again")
		}
		// The stored updates are drained once; no resend within the hour.
		if n := len(updatesOf(r.deposits()["dev1"])); n != 1 {
			t.Fatalf("%d updates", n)
		}
		if a := r.sink.kinds("identity.rotated"); len(a) != 1 {
			t.Fatalf("identity.rotated %d times", len(a))
		}
	})
}

// No definite answer (a 5xx, a timeout, 429 rate_limited): the key stays
// pending, retried sooner with full jitter, always with the same key; a
// running retry_after is stored with the key, honored across a lock and at
// the unlock (no attempt; identity.rotation_failed once), and dropped when
// the key becomes current.
func TestRelayKeyNoAnswerAndRetryAfter(t *testing.T) {
	r := newRKFixture(t)
	r.rot.rotate = func(string) error { return &relayclient.Error{Status: 503, Code: "internal"} }
	r.rotate(true)
	r.flushStep()
	if r.pending() == nil || len(r.rotated()) != 1 {
		t.Fatal("not attempted, or not pending")
	}
	next := r.m.rk.next
	if next.Before(r.clock) || next.After(r.clock.Add(time.Minute)) {
		t.Fatalf("first retry at %v", next.Sub(r.clock))
	}
	r.m.rk.next = r.clock.Add(time.Minute) // the most the draw can give
	r.flushStep()
	if len(r.rotated()) != 1 {
		t.Fatal("retried before its time")
	}
	r.rot.rotate = func(string) error {
		return &relayclient.Error{Status: 429, Code: "rate_limited", RetryAfter: 3600}
	}
	r.advance(time.Minute + time.Second)
	r.flushStep()
	if len(r.rotated()) != 2 || r.pending().RetryAfter.IsZero() {
		t.Fatal("retry_after not stored")
	}
	if len(r.sink.kinds("identity.rotation_failed")) != 0 {
		t.Fatal("a key made in this run is audited as failed")
	}
	r.rot.rotate = nil
	r.lockUnlock(false)
	r.advance(10 * time.Minute)
	r.start()
	if len(r.rotated()) != 2 || r.pending() == nil {
		t.Fatal("an attempt was made while retry_after runs")
	}
	if a := r.sink.kinds("identity.rotation_failed"); len(a) != 1 || !a[0].Feed || a[0].Priority != "high" {
		t.Fatalf("identity.rotation_failed %+v", a)
	}
	r.flushStep()
	r.flushStep()
	if n := len(r.sink.kinds("identity.rotation_failed")); n != 1 {
		t.Fatalf("audited %d times in one unlock", n)
	}
	r.lockUnlock(false)
	r.advance(time.Hour)
	r.start()
	if len(r.rotated()) != 3 || r.pending() != nil {
		t.Fatal("not completed after the retry_after")
	}
	if n := len(r.sink.kinds("identity.rotation_failed")); n != 1 {
		t.Fatal("an unlock that completes the key audits rotation_failed")
	}
}

// The sooner retries' waits: random from 0 to min(1 h, 1 min × 2^(n−1)).
func TestRelayRetryWait(t *testing.T) {
	for n := 1; n <= 12; n++ {
		bound := min(time.Hour, time.Minute<<(n-1))
		for range 200 {
			if w := relayRetryWait(n); w < 0 || w > bound {
				t.Fatalf("n=%d: %v > %v", n, w, bound)
			}
		}
	}
}

// What is a definite refusal (§3.4).
func TestRelayDefiniteRefusal(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{&relayclient.Error{Status: 400, Code: "bad_request"}, true},
		{&relayclient.Error{Status: 401, Code: "signature_invalid"}, true},
		{&relayclient.Error{Status: 429, Code: "quota_exceeded"}, true},
		{&relayclient.Error{Status: 404, Code: CodeMailboxUnknown}, true}, // of the registration
		{&relayclient.Error{Status: 429, Code: "rate_limited"}, false},
		{&relayclient.Error{Status: 401, Code: CodeTimestampStale}, false},
		{&relayclient.Error{Status: 401, Code: "replay_detected"}, false},
		{&relayclient.Error{Status: 500, Code: "internal"}, false},
		{&relayclient.Error{Status: 403, Code: "http_403"}, false}, // no relay error body: a proxy's

		{context.DeadlineExceeded, false},
	}
	for _, c := range cases {
		if got := definiteRefusal(c.err); got != c.want {
			t.Errorf("%v: %v", c.err, got)
		}
	}
}

// After the grace the rotate is answered mailbox_unknown and the vault
// registers the stored pending key: a 200 (an earlier rotate made the
// mailbox) keeps the held tokens; a 201 (a fresh mailbox) re-mints every
// held token with iat now, not backdated.
func TestRelayKeyAfterTheGrace(t *testing.T) {
	for _, created := range []bool{false, true} {
		t.Run(fmt.Sprintf("created=%v", created), func(t *testing.T) {
			r := newRKFixture(t)
			r.rotate(true)
			r.with(func(m *Manager) {
				if err := m.persist(context.Background(), false); err != nil {
					t.Fatal(err)
				}
			})
			held := r.pending().Tokens["c1"].Standing
			pending := mailboxOf(ed25519.NewKeyFromSeed(r.pending().Seed))
			r.lockUnlock(false)
			r.advance(8 * 24 * time.Hour)
			r.rot.rotate = func(string) error { return &relayclient.Error{Status: 404, Code: CodeMailboxUnknown} }
			r.rot.register = func(string) (bool, error) { return created, nil }
			_ = r.deposits()
			r.start()
			if reg := r.registered(); r.pending() != nil || len(reg) == 0 || reg[0] != pending {
				t.Fatalf("the stored pending key was not registered: %v", reg)
			}
			ups := updatesOf(r.deposits()["c1"])
			if len(ups) != 1 {
				t.Fatalf("%d updates", len(ups))
			}
			_, _, tok, _ := parseUpdate(t, ups[0].in.Body)
			c, err := relayauth.ParseToken(tok, r.relayPub())
			if err != nil {
				t.Fatal(err)
			}
			if created {
				if tok == held || !c.Iat.Equal(r.clock.Truncate(time.Second)) {
					t.Fatalf("201: not re-minted with iat now (iat %v, now %v)", c.Iat, r.clock)
				}
			} else if tok != held {
				t.Fatal("200: a held token with days left was re-minted")
			}
		})
	}
}

// A definite refusal puts the key in the refused state (stored, with its
// code), audited at once; vault.status tells the app (only) `relay:
// "refused"`; one attempt per unlock and no sooner retries; a recovery's
// or a transfer's rotation keeps the refused key and owes a relay-key
// rotation; the member's credential.rotate is the only way out: a new key,
// the refused one discarded, and the notice goes.
func TestRelayKeyRefusedState(t *testing.T) {
	r := newRKFixture(t)
	r.rot.rotate = func(string) error { return &relayclient.Error{Status: 400, Code: "bad_request"} }
	r.rotate(true)
	refusedSeed := append([]byte(nil), r.pending().Seed...)
	r.flushStep()
	pr := r.pending()
	if pr == nil || pr.Refused != "bad_request" {
		t.Fatalf("not refused: %+v", pr)
	}
	if n := len(r.sink.kinds("identity.rotation_failed")); n != 1 {
		t.Fatalf("audited %d times", n)
	}
	if v := r.statusRelay("dev1"); v != "refused" {
		t.Fatalf("app status relay %q", v)
	}
	if v := r.statusRelay("dk1"); v != "" {
		t.Fatalf("desktop status relay %q", v)
	}
	r.advance(2 * time.Hour)
	r.flushStep()
	if len(r.rotated()) != 1 {
		t.Fatal("a sooner retry in the refused state")
	}
	r.lockUnlock(false)
	if pr := r.pending(); pr == nil || pr.Refused == "" {
		t.Fatal("the refused state is not stored")
	}
	r.start()
	r.flushStep()
	if len(r.rotated()) != 2 {
		t.Fatalf("%d attempts: not one per unlock", len(r.rotated()))
	}
	// The unlock's refused attempt is audited once in that unlock.
	if n := len(r.sink.kinds("identity.rotation_failed")); n != 2 {
		t.Fatalf("identity.rotation_failed %d times over two unlocks", n)
	}
	// A transfer's rotation keeps the refused key and owes a relay-key
	// rotation.
	r.rotate(false)
	if pr := r.pending(); !bytes.Equal(pr.Seed, refusedSeed) || r.m.st.RotationOwed == nil || !r.m.st.RotationOwed.RelayKey {
		t.Fatal("a transfer's rotation replaced the refused key")
	}
	// The way out.
	r.rot.rotate = nil
	r.rotate(true)
	if pr := r.pending(); pr == nil || bytes.Equal(pr.Seed, refusedSeed) || pr.Refused != "" || r.m.st.RotationOwed != nil {
		t.Fatalf("credential.rotate did not replace the refused key: %+v, owed %+v", pr, r.m.st.RotationOwed)
	}
	r.flushStep()
	if r.pending() != nil {
		t.Fatal("the new key is not current")
	}
	if v := r.statusRelay("dev1"); v != "" {
		t.Fatalf("status relay %q after the way out", v)
	}
}

// A rotation R2 made while R1's key K1 is pending keeps K1 and owes a
// relay-key rotation; K1's second write audits R1 (its marks' ref), stores
// the next key K2 in the same write (the relay-key mark met and cleared,
// the other marks still owed), and K2's rotate is signed by K1; K2's second
// write audits R2 with the marks R1's audit did not name, clears them, and
// mints no further key. The owed mark's retry while K1 is pending is the
// completion, not a new rotation of ik.
func TestRelayKeyRotationWhilePending(t *testing.T) {
	r := newRKFixture(t)
	r.with(func(m *Manager) { m.st.RotationOwed = &RotationOwed{Recovery: "rec1"} })
	r.rot.rotate = func(string) error { return &relayclient.Error{Status: 503, Code: "internal"} }
	r.rotate(false) // R1: a recovery's
	r.flushStep()
	k1 := mailboxOf(ed25519.NewKeyFromSeed(r.pending().Seed))
	r.with(func(m *Manager) {
		rot := len(m.st.Rotations)
		m.retryOwedRotation(m.now())
		if len(m.st.Rotations) != rot {
			t.Fatal("the owed mark's retry rotated ik again while the key is pending")
		}
		m.owe("t1", m.dekVersion(), m.now())
	})
	r.rotate(false) // R2: a transfer's
	if mailboxOf(ed25519.NewKeyFromSeed(r.pending().Seed)) != k1 || !r.m.st.RotationOwed.RelayKey {
		t.Fatal("R2 did not keep K1 with a relay-key rotation owed")
	}
	r.rot.rotate = nil
	// Stop after K1's second write to see the stored next key.
	var signedBy []string
	r.rot.rotate = func(string) error { signedBy = append(signedBy, mailboxOf(r.m.keys.relay)); return nil }
	r.with(func(m *Manager) {
		if err := m.persist(context.Background(), false); err != nil {
			t.Fatal(err)
		}
		m.rk.next = time.Time{}
		if !m.relayKeyAttempt(context.Background(), false) {
			t.Fatal("K1 not completed")
		}
	})
	o := r.m.st.RotationOwed
	if o == nil || o.RelayKey || o.Recovery != "rec1" || o.Transfer != "t1" || r.pending() == nil || !r.m.rk.stored {
		t.Fatalf("after K1: owed %+v, next key %v", o, r.pending() != nil)
	}
	if a := r.sink.kinds("identity.rotated"); len(a) != 1 || a[0].Ref != "recovery" {
		t.Fatalf("K1's audit %+v", a)
	}
	r.with(func(m *Manager) {
		if !m.relayKeyAttempt(context.Background(), false) {
			t.Fatal("K2 not completed")
		}
	})
	if len(signedBy) != 2 || signedBy[1] != k1 {
		t.Fatalf("K2's rotate not signed by K1: %v", signedBy)
	}
	if r.pending() != nil || r.m.st.RotationOwed != nil || len(r.m.st.Relay.Old) != 2 {
		t.Fatalf("after K2: pending %v, owed %+v, %d old keys", r.pending() != nil, r.m.st.RotationOwed, len(r.m.st.Relay.Old))
	}
	if a := r.sink.kinds("identity.rotated"); len(a) != 2 || a[1].Ref != "t1" {
		t.Fatalf("audits %+v", a)
	}
}

// The second write takes the recipients again: one added since the first
// write gets tokens and an update minted then; the tokens of one removed
// since are dropped. Held tokens near their end are re-minted.
func TestRelayKeyRecipientsAtTheSecondWrite(t *testing.T) {
	r := newRKFixture(t)
	r.rot.rotate = func(string) error { return &relayclient.Error{Status: 503, Code: "internal"} }
	r.rotate(true)
	r.flushStep()
	deskJTIs := map[string]bool{}
	for _, it := range r.pending().Issued {
		if it.PeerID == "dk1" {
			deskJTIs[it.JTI] = true
		}
	}
	agent := r.addDevice(t, "ag1", KindAgent, 0x61)
	r.peers["ag1"] = agent
	r.keys["ag1"] = seedKey(0x62)
	r.with(func(m *Manager) {
		agent.peer.Standing = r.tokenFrom("ag1", pubOf(m.keys.relay), 30*24*time.Hour)
		delete(m.st.Devices, "dk1")
	})
	delete(r.peers, "dk1")
	heldDev := r.pending().Tokens["dev1"].Standing
	r.rot.rotate = nil
	r.advance(25 * 24 * time.Hour) // the held standing tokens have < 10 days left
	r.with(func(m *Manager) {
		m.relayKeyStep(context.Background(), true)
		m.drainOutbox(context.Background())
	})
	deps := r.deposits()
	if len(updatesOf(deps["ag1"])) != 1 {
		t.Fatal("the agent added since the first write got no update")
	}
	if _, ok := r.m.st.Relay.Updates["dk1"]; ok {
		t.Fatal("the removed desktop is still a recipient")
	}
	for _, it := range r.m.st.Issued {
		if deskJTIs[it.JTI] {
			t.Fatal("the removed desktop's held tokens were kept")
		}
	}
	ups := updatesOf(deps["dev1"])
	if len(ups) != 1 {
		t.Fatal("no update to the app")
	}
	if _, _, tok, _ := parseUpdate(t, ups[0].in.Body); tok == heldDev {
		t.Fatal("a held token near its end was not re-minted")
	}
}

// Deposits after the second write go with the old key on a recipient's
// token for the old key, and with the new one once it issued a token to
// it; that token, or a deposit on a new token, acknowledges the address.
// A peer that refuses the old key (token_revoked) is not marked stale.
func TestRelayKeyDepositsAndAcknowledgement(t *testing.T) {
	r := newRKFixture(t)
	oldPub := r.relayPub()
	r.rotate(true)
	r.flushStep()
	_ = r.deposits()
	notify := func() {
		r.with(func(m *Manager) {
			m.notifyDevices("sync.event", json.RawMessage(`{"kind":"test"}`), "", m.now())
			_ = m.flushThenDrain(context.Background())
		})
	}
	notify()
	ss := r.deposits()["dev1"]
	if len(ss) == 0 {
		t.Fatal("nothing deposited")
	}
	for _, s := range ss {
		if !bytes.Equal(s.sender, oldPub) {
			t.Fatal("deposited with the new key on a token for the old one")
		}
	}
	r.issueToVault("dev1")
	if u := r.m.st.Relay.Updates["dev1"]; u == nil || !u.Acked {
		t.Fatal("relay.token.issued for the new key did not acknowledge")
	}
	_ = r.deposits()
	notify()
	for _, s := range r.deposits()["dev1"] {
		if !bytes.Equal(s.sender, r.relayPub()) {
			t.Fatal("deposited with the old key after the new token")
		}
	}
	// A token for the old key is kept, but is no acknowledgement.
	old := r.tokenFrom("dk1", oldPub, 30*24*time.Hour).Token
	r.sendFrom("dk1", "relay.token.issued", `{"kind":"standing","token":"`+old+`"}`, "")
	if r.m.st.Relay.Updates["dk1"].Acked || audited(r.devFixture, "bad_issued_token") {
		t.Fatal("a token for the old key acknowledged, or was refused")
	}
	// A deposit to the new mailbox alone is no acknowledgement (owner
	// decision 2026-11-05): the old key stays in use for that recipient.
	jti := r.m.st.Relay.Updates["c1"].JTIs[0]
	r.sendFrom("c1", "profile.get", `{}`, jti)
	if r.m.st.Relay.Updates["c1"].Acked || r.m.st.Relay.Old[0].Retired {
		t.Fatal("a deposit on a new token counted as following the address")
	}
	// A peer refuses the old key: the deposit waits for its token, the
	// peer is not marked stale.
	r.relay.top().failWith = &relayclient.Error{Status: 403, Code: CodeTokenRevoked}
	r.with(func(m *Manager) {
		m.sendTo(m.st.Devices["dk1"], "sync.event", json.RawMessage(`{"kind":"test"}`), m.now())
		_ = m.flushThenDrain(context.Background())
	})
	r.relay.top().failWith = nil
	if p := r.m.st.Devices["dk1"]; p.State != PeerActive {
		t.Fatal("a peer that refused the old key was marked stale")
	}
}

// Resending (§3.4 (b)): at each unlock, to a recipient that has not
// acknowledged and holds a valid standing token for the old key, with the
// old key and that token: at most one per recipient per unlock and one
// per hour; none to one that acknowledged; a definite refusal ends them;
// nothing while a key is pending.
func TestRelayKeyResend(t *testing.T) {
	r := newRKFixture(t)
	oldPub := r.relayPub()
	r.rotate(true)
	r.flushStep()
	r.issueToVault("dev1") // acknowledged
	_ = r.deposits()
	r.lockUnlock(false)
	r.advance(30 * time.Minute)
	r.start()
	if n := len(updatesOf(r.deposits()["dk1"])); n != 0 {
		t.Fatal("resent within the hour")
	}
	r.lockUnlock(false)
	r.advance(time.Hour)
	r.start()
	deps := r.deposits()
	if ups := updatesOf(deps["dk1"]); len(ups) != 1 || !bytes.Equal(ups[0].sender, oldPub) {
		t.Fatalf("desktop resend %d", len(ups))
	}
	if len(updatesOf(deps["dev1"])) != 0 {
		t.Fatal("resent to a recipient that acknowledged")
	}
	r.with(func(m *Manager) { m.resendAddressUpdates(m.now().Add(2 * time.Hour)) })
	r.flushStep()
	if len(updatesOf(r.deposits()["dk1"])) != 0 {
		t.Fatal("two resends in one unlock")
	}
	// A definite refusal ends the resends to that recipient.
	r.lockUnlock(false)
	r.advance(2 * time.Hour)
	r.relay.failMailbox = map[string]error{r.desk.peer.Relay.Mailbox: &relayclient.Error{Status: 401, Code: CodeTokenExpired}}
	r.start()
	if u := r.m.st.Relay.Updates["dk1"]; u == nil || !u.Ended {
		t.Fatal("a definite refusal did not end the resends")
	}
	// Nothing is resent while a key is pending.
	r.relay.failMailbox = nil
	r.rot.rotate = func(string) error { return &relayclient.Error{Status: 503, Code: "internal"} }
	r.rotate(true)
	r.flushStep()
	r.lockUnlock(false)
	r.advance(2 * time.Hour)
	_ = r.deposits()
	r.start()
	if len(updatesOf(r.deposits()["c1"])) != 0 {
		t.Fatal("resent while a key is pending")
	}
}

// The old key is deleted when every recipient has acknowledged, or when
// their standing tokens for it expired, and not while a notice to a
// removed device holds a valid token for it.
func TestRelayKeyOldKeyDeleted(t *testing.T) {
	t.Run("all followed, not before the notice, kept to collect until gone", func(t *testing.T) {
		r := newRKFixture(t)
		oldPub := r.relayPub()
		r.rotate(true)
		r.flushStep()
		// A removed phone's notice on its token for the old key.
		gone := seedKey(0x71)
		c := relayclient.New(rkBase, gone)
		c.Now = func() time.Time { return r.clock }
		tok, _ := c.MintToken(relayauth.EncodeKey(oldPub), rkBase, relayclient.TokenOptions{TTL: 10 * 24 * time.Hour})
		r.with(func(m *Manager) {
			m.st.PendingUnlink = &PendingUnlink{RelayURL: rkBase, Mailbox: relayauth.MailboxID(pubOf(gone)), Token: tok,
				TokenExp: r.clock.Add(10 * 24 * time.Hour), TransferID: "t9", At: r.clock, Payload: []byte("x")}
		})
		for id := range r.peers {
			r.issueToVault(id)
		}
		if o := r.m.st.Relay.Old; len(o) != 1 || o[0].Retired {
			t.Fatal("its use ended while a removed device's notice holds a token for it")
		}
		r.with(func(m *Manager) { m.st.PendingUnlink = nil })
		r.sendFrom("dev1", "vault.status", `{}`, "")
		o := r.m.st.Relay.Old
		if len(o) != 1 || !o[0].Retired || r.m.st.Relay.Updates != nil {
			t.Fatal("its use did not end when every recipient followed")
		}
		// Kept, deposit-only no more, to collect its mailbox in the grace.
		if r.m.onOldKey(r.tokenFrom("c1", oldPub, time.Hour).Token) {
			t.Fatal("a retired key still deposits")
		}
		var extra int
		r.with(func(m *Manager) {
			if mc, ok := m.withOldCollectors(context.Background(), &listCollector{}).(*multiCollector); ok {
				extra = len(mc.extra)
				_ = mc.Close()
			}
		})
		if extra != 1 {
			t.Fatal("the retired key's mailbox is not collected in the grace")
		}
		r.m.oldMailboxGone(o[0].Mailbox)
		r.sendFrom("dev1", "vault.status", `{}`, "")
		if len(r.m.st.Relay.Old) != 0 {
			t.Fatal("not deleted once its mailbox is gone")
		}
	})
	t.Run("a device not followed in 30 days", func(t *testing.T) {
		r := newRKFixture(t)
		r.rotate(true)
		r.flushStep()
		r.issueToVault("dev1")
		r.issueToVault("c1")
		_ = r.deposits()
		r.advance(UnfollowedAfter + time.Minute)
		r.sendFrom("dev1", "vault.status", `{}`, "")
		if r.m.st.Devices["dk1"].State != PeerStale || len(r.sink.kinds("device.stale")) != 1 {
			t.Fatal("the stale desktop has no member notice")
		}
		var sync bool
		for _, s := range r.deposits()["dev1"] {
			if s.in.Type == "sync.event" && bodyStr(t, s.in, "kind") == "device.stale" {
				sync = true
			}
		}
		if !sync {
			t.Fatal("the app was not sent sync.event{device.stale}")
		}
	})
	t.Run("not followed in 30 days", func(t *testing.T) {
		r := newRKFixture(t)
		r.rotate(true)
		r.flushStep()
		r.issueToVault("dev1")
		r.issueToVault("dk1")
		// The connection only deposits to the new mailbox: no follow.
		r.sendFrom("c1", "profile.get", `{}`, r.m.st.Relay.Updates["c1"].JTIs[0])
		r.advance(UnfollowedAfter - time.Minute)
		r.sendFrom("dev1", "vault.status", `{}`, "")
		if r.m.st.Relay.Old[0].Retired || r.m.st.Connections["c1"].State != PeerActive {
			t.Fatal("ended before 30 days")
		}
		_ = r.deposits()
		r.advance(2 * time.Minute)
		r.sendFrom("dev1", "vault.status", `{}`, "")
		if r.m.st.Connections["c1"].State != PeerStale || !r.m.st.Relay.Old[0].Retired {
			t.Fatal("not shown as needing reconnecting after 30 days")
		}
		if len(r.sink.kinds("connection.stale")) != 1 {
			t.Fatal("no connection.stale feed item")
		}
		var ev bool
		for _, s := range r.deposits()["dev1"] {
			if s.in.Type == "connection.event" && bodyStr(t, s.in, "event") == "stale" {
				ev = true
			}
		}
		if !ev {
			t.Fatal("the app was not sent connection.event{stale}")
		}

	})
}

// §12.2 step 3: a key pending at the unlock is completed before the
// drain, and the unlock does not register the current key while a key is
// pending (it calls the rotate instead).
func TestRelayKeyUnlockDoesNotRegisterTheCurrentKey(t *testing.T) {
	r := newRKFixture(t)
	r.rot.rotate = func(string) error { return &relayclient.Error{Status: 503, Code: "internal"} }
	r.rotate(true)
	r.flushStep()
	r.lockUnlock(false)
	if !r.m.rk.fromStorage {
		t.Fatal("the unlock did not find the key pending")
	}
	cur := mailboxOf(r.m.keys.relay)
	r.rot.rotate = nil
	r.start()
	if r.pending() != nil {
		t.Fatal("not completed at the unlock")
	}
	for _, mb := range r.registered() {
		if mb == cur {
			t.Fatal("registered the current key while a key was pending")
		}
	}
}

// The collect loop's mailbox_unknown starts the rotate (then the
// registration) of a pending key that is not refused.
func TestRelayKeyMailboxUnknownStartsTheRotate(t *testing.T) {
	r := newRKFixture(t)
	r.rot.rotate = func(string) error { return &relayclient.Error{Status: 503, Code: "internal"} }
	r.rotate(true)
	r.flushStep()
	r.rot.rotate = func(string) error { return &relayclient.Error{Status: 404, Code: CodeMailboxUnknown} }
	r.advance(time.Hour + time.Second)
	if err := r.m.relayMailboxUnknown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.pending() != nil || len(r.registered()) == 0 {
		t.Fatal("mailbox_unknown did not lead to the registration")
	}
}

// Collecting from the old mailbox during the grace: its messages are
// collected and acked on it; its mailbox_unknown ends that.
func TestMultiCollector(t *testing.T) {
	main, old := &listCollector{}, &listCollector{batches: [][]Message{{{MsgID: "o1"}}}}
	var goneMB string
	c := &multiCollector{main: main, extra: []oldCollector{{c: old, mailbox: "mbold"}}, gone: func(mb string) { goneMB = mb }, from: map[string]Collector{}}
	msgs, err := c.Next(context.Background())
	if err != nil || len(msgs) != 1 || msgs[0].MsgID != "o1" {
		t.Fatalf("%v %v", msgs, err)
	}
	_ = c.Ack(context.Background(), "o1")
	if len(old.acked) != 1 || len(main.acked) != 0 {
		t.Fatal("acked on the wrong mailbox")
	}
	old.err = &relayclient.Error{Status: 404, Code: CodeMailboxUnknown}
	main.batches = [][]Message{{{MsgID: "m1"}}}
	msgs, _ = c.Next(context.Background())
	if goneMB != "mbold" || len(msgs) != 1 || msgs[0].MsgID != "m1" {
		t.Fatal("the old mailbox's end was not noticed")
	}
}

type listCollector struct {
	batches [][]Message
	err     error
	acked   []string
}

func (l *listCollector) Next(context.Context) ([]Message, error) {
	if l.err != nil {
		return nil, l.err
	}
	if len(l.batches) == 0 {
		return nil, nil
	}
	b := l.batches[0]
	l.batches = l.batches[1:]
	return b, nil
}
func (l *listCollector) Ack(_ context.Context, id string) error {
	l.acked = append(l.acked, id)
	return nil
}
func (l *listCollector) Close() error { return nil }

// A key stored while there was no recipient (a recovery removed the only
// app) and read back gets the recipients added since at its second
// write; nothing is attempted while a recovered phone has not paired (its
// first handshake checks the address the vault_bundle gave).
func TestRelayKeyNoRecipientsThenRecoveredPhone(t *testing.T) {
	r := newRKFixture(t)
	r.with(func(m *Manager) {
		m.st.Devices, m.st.Connections = map[string]*Peer{}, map[string]*Peer{}
		m.st.Invites["rec1"] = &Invite{ID: "rec1", Kind: KindApp, CreatedBy: inviteByRecovery, Exp: r.clock.Add(time.Hour)}
	})
	r.rotate(false)
	r.with(func(m *Manager) { m.st.Relay.Pending.Recovery = "rec1" }) // as the recovery's open marks its own key
	r.flushStep()
	if len(r.rotated()) != 0 || r.pending() == nil {
		t.Fatal("attempted while the recovered phone has not paired")
	}
	r.lockUnlock(false)
	r.start()
	if len(r.rotated()) != 0 || len(r.sink.kinds("identity.rotation_failed")) != 0 {
		t.Fatal("attempted, or audited as failed, before the pairing")
	}
	// The phone pairs (the invite goes, the device is added).
	app := r.addDevice(t, "app2", KindApp, 0x81)
	r.peers = map[string]*tdev{"app2": app}
	r.keys["app2"] = seedKey(0x82)
	r.with(func(m *Manager) {
		app.peer.Standing = r.tokenFrom("app2", pubOf(m.keys.relay), 30*24*time.Hour)
		delete(m.st.Invites, "rec1")
	})
	_ = r.deposits()
	r.flushStep()
	if r.pending() != nil || len(updatesOf(r.deposits()["app2"])) != 1 {
		t.Fatal("the recovered phone got no update at the second write")
	}
}

// openWithPending is a recovery fixture whose vault has a relay key pending
// since before the recovery (its rotate got no answer), on a relay the test
// scripts.
func openWithPending(t *testing.T) (*openFixture, *stubRot, string) {
	rot := &stubRot{rotate: func(string) error { return &relayclient.Error{Status: 503, Code: "internal"} }}
	var current string
	f := newOpenFixtureWith(t, func(f *openFixture) {
		f.opts.Relay = func(base string, key ed25519.PrivateKey) Relay { return &stubRelay{base: base, key: key, rot: rot} }
		f.m.mu.Lock()
		defer f.m.mu.Unlock()
		f.m.relay.(*stubRelay).rot = rot
		cpk := pubOf(seedKey(0x91))
		f.m.st.Connections["c9"] = &Peer{ID: "c9", Kind: KindConnection, State: PeerActive,
			Relay: PeerRelay{URL: rkBase, Mailbox: relayauth.MailboxID(cpk), PK: cpk}}
		if err := f.m.rotateKeys(f.m.now(), true); err != nil {
			t.Fatal(err)
		}
		if err := completeRelayKey(f.m); err != nil {
			t.Fatal(err)
		}
		if f.m.st.Relay.Pending == nil {
			t.Fatal("not pending")
		}
		current = f.m.st.Relay.Mailbox
		f.heldIssued = append([]IssuedToken(nil), f.m.st.Relay.Pending.Issued...)
	})
	return f, rot, current
}

// §11.14.6 with §3.4: a relay key pending since before the recovery is
// completed by the open before the phone is given the vault's address, so
// the vault_bundle carries the current one; the recovery's own new key
// waits for the phone's pairing.
func TestRelayKeyRecoveryCompletesTheStoredKey(t *testing.T) {
	f, rot, before := openWithPending(t)
	rot.rotate = nil
	m, out := f.open(testPIN, rPW)
	if m == nil || !out.OK {
		t.Fatalf("open: %+v", out)
	}
	defer m.Crash()
	if m.st.Relay.Mailbox == before || len(m.st.Relay.Old) != 1 || m.st.Relay.Old[0].Mailbox != before {
		t.Fatal("the stored pending key was not made current by the open")
	}
	if !bytes.Contains(out.VaultBundle, []byte(m.st.Relay.Mailbox)) || bytes.Contains(out.VaultBundle, []byte(before)) {
		t.Fatal("the vault_bundle does not carry the current address")
	}
	if pr := m.st.Relay.Pending; pr == nil || pr.Recovery != recID {
		t.Fatal("the recovery's own relay key is not pending, marked as the recovery's")
	}
}

// If the stored key cannot be completed now, the open answers retry.
func TestRelayKeyRecoveryRetryWhenTheStoredKeyCannotComplete(t *testing.T) {
	f, _, _ := openWithPending(t)
	if m, out := f.open(testPIN, rPW); m != nil || out.Code != OpenRetry {
		t.Fatalf("open: %+v", out)
	}
}

// The relay's limits are kept in the state: an unlock that does not
// register (a key pending, its attempt unanswered) still makes invitations
// and offers attachments.
func TestRelayKeyLimitsKeptWhilePending(t *testing.T) {
	r := newRKFixture(t)
	blob, ttl := int64(8<<20), int64(7*86400)
	r.rot.limits = &Limits{MaxTokenLifetimeSeconds: 400 * 86400, OpenTokenMaxLifetimeSeconds: 7 * 86400, ClaimTTLSeconds: 7 * 86400,
		MaxBlobBytes: &blob, BlobTTLSeconds: &ttl}
	r.lockUnlock(false) // a registration: the limits are stored
	r.start()
	r.rot.rotate = func(string) error { return &relayclient.Error{Status: 503, Code: "internal"} }
	r.rotate(true)
	r.flushStep()
	r.lockUnlock(false)
	r.start()
	if r.pending() == nil {
		t.Fatal("not pending")
	}
	r.with(func(m *Manager) {
		if m.attMaxContent() == 0 {
			t.Fatal("attachments not offered while a key is pending")
		}
	})
	r.linkFor(t, time.Hour) // an invitation within the relay's limits
}

// Blobs in the old-key window: an upload to a recipient holding a token
// for the old key is signed with it; a blob a peer left in the old mailbox
// is fetched and deleted with the old key.
func TestRelayKeyBlobsInTheOldKeyWindow(t *testing.T) {
	r := newRKFixture(t)
	oldPub := r.relayPub()
	oldMB := r.m.st.Relay.Mailbox
	r.relay.blobs = &stubBlobs{}
	r.rotate(true)
	r.flushStep()
	// The upload: the connection's token is still for the old key.
	if _, _, err := r.m.PutBlobTo(context.Background(), "c1", []byte("blob")); err != nil {
		t.Fatal(err)
	}
	b := r.relay.blobs
	b.mu.Lock()
	var sender string
	for _, x := range b.byID {
		sender = x.sender
	}
	b.mu.Unlock()
	if sender != relayauth.EncodeKey(oldPub) {
		t.Fatal("the upload was not signed with the key the token was issued to")
	}
	// A blob in the old mailbox.
	b.mu.Lock()
	b.byID["01JB2Z6V9K3M4N5P6Q7R8SOLD1"] = stubBlob{mailbox: oldMB, data: []byte("old")}
	b.mu.Unlock()
	data, err := r.m.getBlob(context.Background(), "01JB2Z6V9K3M4N5P6Q7R8SOLD1")
	if err != nil || string(data) != "old" {
		t.Fatalf("a blob in the old mailbox: %v", err)
	}
	_ = r.m.deleteBlob(context.Background(), "01JB2Z6V9K3M4N5P6Q7R8SOLD1")
	b.mu.Lock()
	_, still := b.byID["01JB2Z6V9K3M4N5P6Q7R8SOLD1"]
	b.mu.Unlock()
	if still {
		t.Fatal("a blob in the old mailbox was not deleted")
	}
}

// A deletion also deletes a pending key's mailbox (its rotate may have
// made it); a refusal there is retried like the current one's.
func TestRelayKeyDeletionDeletesThePendingMailbox(t *testing.T) {
	r := newRKFixture(t)
	r.rot.rotate = func(string) error { return &relayclient.Error{Status: 503, Code: "internal"} }
	r.rotate(true)
	r.flushStep()
	pend := mailboxOf(ed25519.NewKeyFromSeed(r.pending().Seed))
	cur := r.m.st.Relay.Mailbox
	r.rot.deleteErr = map[string]error{pend: &relayclient.Error{Status: 503, Code: "internal"}}
	r.with(func(m *Manager) { m.deleteMailbox(context.Background()) })
	if slices.Contains(r.rot.deleted, cur) {
		t.Fatal("the current mailbox was deleted though the pending one's deletion failed")
	}
	r.rot.deleteErr = nil
	r.with(func(m *Manager) { m.deleteMailbox(context.Background()) })
	if !slices.Contains(r.rot.deleted, pend) || !slices.Contains(r.rot.deleted, cur) {
		t.Fatalf("deleted %v", r.rot.deleted)
	}
}

// A 201 is stored with the pending key before the second write: when that
// write fails and a later run completes the key (its registration then
// answers 200), every held token is still re-minted.
func TestRelayKeyCreatedSurvivesAFailedSecondWrite(t *testing.T) {
	r := newRKFixture(t)
	r.rotate(true)
	r.with(func(m *Manager) {
		if err := m.persist(context.Background(), false); err != nil {
			t.Fatal(err)
		}
	})
	held := r.pending().Tokens["c1"].Standing
	r.rot.rotate = func(string) error { return &relayclient.Error{Status: 404, Code: CodeMailboxUnknown} }
	fs := failWrites(r.devFixture, 0)
	r.rot.register = func(string) (bool, error) {
		fs.mu.Lock()
		fs.passState, fs.failState = 1, 1 // the 201's own write goes through; the second write fails
		fs.mu.Unlock()
		return true, nil
	}
	r.with(func(m *Manager) { m.relayKeyStep(context.Background(), false) })
	r.lockUnlock(true)
	if pr := r.pending(); pr == nil || !pr.Created {
		t.Fatal("the 201 was not stored with the key")
	}
	r.rot.register = func(string) (bool, error) { return false, nil } // now 200
	_ = r.deposits()
	r.start()
	ups := updatesOf(r.deposits()["c1"])
	if len(ups) != 1 {
		t.Fatalf("%d updates", len(ups))
	}
	if _, _, tok, _ := parseUpdate(t, ups[0].in.Body); tok == held {
		t.Fatal("a held token was not re-minted for the fresh mailbox")
	}
}

// The old collectors sign with copies of their own: deleting the key
// leaves the copy until the collector is closed, then it is wiped.
func TestRelayKeyCollectorOwnKeyCopies(t *testing.T) {
	r := newRKFixture(t)
	r.rotate(true)
	r.flushStep()
	var mc *multiCollector
	r.with(func(m *Manager) {
		mc, _ = m.withOldCollectors(context.Background(), &listCollector{}).(*multiCollector)
	})
	if mc == nil || len(mc.keys) != 1 {
		t.Fatal("no old collector")
	}
	k := mc.keys[0]
	r.with(func(m *Manager) {
		if &k[0] == &m.keys.oldRelay[0][0] {
			t.Fatal("the collector shares the vault's key")
		}
		suite.Wipe(m.keys.oldRelay[0]) // the vault deletes it
	})
	if bytes.Equal(k, make([]byte, len(k))) {
		t.Fatal("the collector's copy went with the vault's key")
	}
	_ = mc.Close()
	if !bytes.Equal(k, make([]byte, len(k))) {
		t.Fatal("the copy was not wiped at the close")
	}
}

// N2 (review): an inherited pending key whose rotate the relay refused no
// longer blocks every recovery open: the current mailbox lives, so the
// open goes on with it and the key stays pending in the refused state,
// the recovery's rotation owing a relay-key rotation (§3.4).
func TestReviewRecoveryRefusedDeadlock(t *testing.T) {
	f, rot, before := openWithPending(t)
	rot.rotate = func(string) error { return &relayclient.Error{Status: 400, Code: "bad_request"} }
	m, out := f.open(testPIN, rPW)
	if m == nil || !out.OK {
		t.Fatalf("the recovery does not open while the pending key is refused: %+v", out)
	}
	defer m.Crash()
	pr := m.st.Relay.Pending
	if pr == nil || pr.Refused != "bad_request" || pr.Recovery != "" || m.st.RotationOwed == nil || !m.st.RotationOwed.RelayKey {
		t.Fatalf("not kept refused with a relay-key rotation owed: %+v, owed %+v", pr, m.st.RotationOwed)
	}
	if m.st.Relay.Mailbox != before || !bytes.Contains(out.VaultBundle, []byte(before)) {
		t.Fatal("the vault_bundle does not carry the live mailbox")
	}
}

// A refused registration past the grace (no live mailbox): the recovery
// replaces the refused key with a fresh one, registered, made current
// (recoveryReplacesRefusedKey, owner decision (a) 2026-11-05).
func TestRelayKeyRecoveryReplacesARefusedRegistration(t *testing.T) {
	f, rot, before := openWithPending(t)
	var refusedMB string
	rot.rotate = func(string) error { return &relayclient.Error{Status: 404, Code: CodeMailboxUnknown} }
	rot.register = func(mb string) (bool, error) {
		if refusedMB == "" {
			refusedMB = mb
			return false, &relayclient.Error{Status: 400, Code: "bad_request"}
		}
		return true, nil
	}
	m, out := f.open(testPIN, rPW)
	if m == nil || !out.OK {
		t.Fatalf("open: %+v", out)
	}
	defer m.Crash()
	cur := m.st.Relay.Mailbox
	if cur == before || cur == refusedMB || len(m.st.Relay.Old) != 1 || m.st.Relay.Old[0].Mailbox != before {
		t.Fatal("the refused key was not replaced by a fresh, current key")
	}
	if !bytes.Contains(out.VaultBundle, []byte(cur)) {
		t.Fatal("the vault_bundle does not carry the fresh mailbox")
	}
}

// N3: a key completed in the open re-mints every held token (a 201 there
// would be lost with an open that fails later), even when the relay
// answers 200.
func TestRelayKeyRecoveryRemintsEveryHeldToken(t *testing.T) {
	f, rot, _ := openWithPending(t)
	var held []string
	for _, it := range f.heldIssued {
		held = append(held, it.JTI)
	}
	if len(held) == 0 {
		t.Fatal("no held tokens to check")
	}
	rot.rotate = nil
	m, out := f.open(testPIN, rPW)
	if m == nil || !out.OK {
		t.Fatalf("open: %+v", out)
	}
	defer m.Crash()
	for _, it := range m.st.Issued {
		if slices.Contains(held, it.JTI) {
			t.Fatal("a held token was not re-minted")
		}
	}
}

// N6, N7: the lockless uploads sign with the published copies, not the
// vault's live keys; a replaced set's copies are wiped once no transfer
// uses it.
func TestRelayKeyPublishedCopies(t *testing.T) {
	r := newRKFixture(t)
	oldPub := r.relayPub()
	r.relay.blobs = &stubBlobs{}
	r.rotate(true)
	r.flushStep()
	// A set nobody uses is wiped when replaced.
	idle := r.m.rk.set.Load()
	idleKey := idle.keys[1] // [0] is the current key's copy
	r.with(func(m *Manager) { m.publishRelays() })
	if !bytes.Equal(idleKey, make([]byte, len(idleKey))) {
		t.Fatal("an unused replaced set kept its copies")
	}
	held := r.m.acquireRelays()
	if len(held.keys) != 2 || &held.keys[0][0] == &r.m.keys.relay[0] || !bytes.Equal(held.keys[0], r.m.keys.relay) {
		t.Fatal("no copies published, or the current key's bytes shared")
	}
	copyKey := held.keys[1]
	r.with(func(m *Manager) {
		suite.Wipe(m.keys.oldRelay[0]) // the vault's own bytes: not what an upload signs with
	})
	if _, _, err := r.m.PutBlobTo(context.Background(), "c1", []byte("blob")); err != nil {
		t.Fatal(err)
	}
	b := r.relay.blobs
	b.mu.Lock()
	var sender string
	for _, x := range b.byID {
		sender = x.sender
	}
	b.mu.Unlock()
	if sender != relayauth.EncodeKey(oldPub) {
		t.Fatal("the upload signed with the vault's live key bytes")
	}
	r.with(func(m *Manager) { m.publishRelays() }) // replaced while in use
	if bytes.Equal(copyKey, make([]byte, len(copyKey))) {
		t.Fatal("a set in use was wiped")
	}
	held.release()
	if !bytes.Equal(copyKey, make([]byte, len(copyKey))) {
		t.Fatal("a replaced set's copies outlived its last use")
	}
}

// Round 5, L2: a refusal of the recovery's fresh key too is a definite
// answer: the open fails with relay_refused, noted in the recovery log.
func TestRelayKeyRecoveryFreshKeyRefused(t *testing.T) {
	f, rot, _ := openWithPending(t)
	rot.rotate = func(string) error { return &relayclient.Error{Status: 404, Code: CodeMailboxUnknown} }
	rot.register = func(string) (bool, error) { return false, &relayclient.Error{Status: 400, Code: "bad_request"} }
	m, out := f.open(testPIN, rPW)
	if m != nil || out.Code != OpenRelayRefused {
		t.Fatalf("open: %+v", out)
	}
	var noted bool
	for _, e := range f.storedHeader().RecoveryLog {
		noted = noted || strings.Contains(e.Ref, OpenRelayRefused)
	}
	if !noted {
		t.Fatal("not noted in the recovery log")
	}
}

// Round 5, L4: a 429 with a retry_after on the recovery path is told to
// the phone (the open stores nothing).
func TestRelayKeyRecoveryRetryAfter(t *testing.T) {
	f, rot, _ := openWithPending(t)
	rot.rotate = func(string) error { return &relayclient.Error{Status: 429, Code: "rate_limited", RetryAfter: 3600} }
	m, out := f.open(testPIN, rPW)
	if m != nil || out.Code != OpenRetry || out.RetryAt.Sub(f.clock) < 59*time.Minute {
		t.Fatalf("open: %+v", out)
	}
}

// Round 4/5, R6: the vault re-sends to a device (a reference-client
// recipient) what it refuses from an earlier key, once the device issues a
// token for the current key.
func TestRelayKeyDeviceGetsKeyChangesAgain(t *testing.T) {
	r := newRKFixture(t)
	r.rotate(true)
	r.flushStep()
	r.issueToVault("dk1") // follows K1
	r.rotate(true)        // K2: its update and R2's key change go out with the token for K1
	r.flushStep()
	_ = r.deposits()
	r.with(func(m *Manager) {
		p := m.st.Devices["dk1"]
		p.OwnChainAtEpoch = 1 // R2's link is not in its epoch
	})
	r.issueToVault("dk1") // a token for K2: R2's identity.rotate again, a rekey, a fresh token
	r.with(func(m *Manager) { _ = m.flushThenDrain(context.Background()) })
	var rot, tok bool
	for _, s := range r.deposits()["dk1"] {
		if !bytes.Equal(s.sender, r.relayPub()) {
			continue
		}
		rot = rot || s.in.Type == "identity.rotate"
		tok = tok || s.in.Type == "relay.token.issued"
	}
	if !rot || !tok {
		t.Fatalf("the device was not sent again (identity.rotate %v, token %v)", rot, tok)
	}
}
