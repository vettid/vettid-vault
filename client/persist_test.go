package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"
	"github.com/vettid/vettid-relay/relayclient"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Config.Persist (save before acknowledging, VAULT-MESSAGING §8.3 as a
// device applies it), against an in-memory relay and a stand-in for the
// vault built from the handshake package.

// fakeRelay is a TEST-ONLY relay: mailboxes keyed by mailbox id, the
// caller identified by its X-VettID-Key header (signatures and tokens are
// not checked). A collected message stays in the mailbox until it is
// acknowledged and is returned by every collect until then, like a relay
// whose visibility timeout has passed.
type fakeRelay struct {
	t   *testing.T
	srv *httptest.Server

	mu    sync.Mutex
	boxes map[string][]relayclient.Message
	n     int
	log   []string // "deposit <mailbox>", "ack <msg_id>", and what tests add
	// failAck answers every ack 400; failDeposit answers the next
	// failDeposit deposits with depositStatus.
	failAck       bool
	failDeposit   int
	depositStatus int
	depositCode   string // "" : "injected"
	// lease hides a collected, unacknowledged message from later collects
	// (a relay's visibility timeout that has not passed) until release.
	lease  bool
	leased map[string]bool
}

func newFakeRelay(t *testing.T) *fakeRelay {
	r := &fakeRelay{t: t, boxes: map[string][]relayclient.Message{}}
	r.srv = httptest.NewServer(r)
	t.Cleanup(r.srv.Close)
	return r
}

func (r *fakeRelay) url() string { return r.srv.URL }

func (r *fakeRelay) note(s string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.log = append(r.log, s)
}

func (r *fakeRelay) entries() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.log...)
}

// put deposits payload into mailbox from sender (no HTTP; the vault's
// side of the test uses it).
func (r *fakeRelay) put(mailbox string, sender ed25519.PublicKey, payload []byte) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.putLocked(mailbox, relayauth.EncodeKey(sender), payload)
}

func (r *fakeRelay) putLocked(mailbox, sender string, payload []byte) string {
	r.n++
	id := "m" + strconv.Itoa(r.n)
	r.boxes[mailbox] = append(r.boxes[mailbox], relayclient.Message{MsgID: id, Sender: sender,
		Payload: append([]byte(nil), payload...), DepositedAt: time.Now().UTC().Format(time.RFC3339Nano)})
	return id
}

// take removes and returns everything in mailbox.
func (r *fakeRelay) take(mailbox string) []relayclient.Message {
	r.mu.Lock()
	defer r.mu.Unlock()
	m := r.boxes[mailbox]
	delete(r.boxes, mailbox)
	return m
}

// pending returns the msg_ids waiting in mailbox.
func (r *fakeRelay) pending(mailbox string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var ids []string
	for _, m := range r.boxes[mailbox] {
		ids = append(ids, m.MsgID)
	}
	return ids
}

func (r *fakeRelay) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := req.Header.Get(relayauth.HeaderKey)
	pk, ok := relayauth.DecodeKey(key)
	if !ok {
		http.Error(w, `{"code":"signature_invalid"}`, http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	switch {
	case req.Method == http.MethodPost && strings.HasPrefix(req.URL.Path, "/v1/mailbox/"):
		if r.failDeposit > 0 {
			r.failDeposit--
			code := r.depositCode
			if code == "" {
				code = "injected"
			}
			w.WriteHeader(r.depositStatus)
			_, _ = w.Write([]byte(`{"code":"` + code + `"}`))
			return
		}
		var body struct {
			Payload []byte `json:"payload"`
		}
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		mb := strings.TrimPrefix(req.URL.Path, "/v1/mailbox/")
		id := r.putLocked(mb, key, body.Payload)
		r.log = append(r.log, "deposit "+mb)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"msg_id": id})
	case req.Method == http.MethodGet && req.URL.Path == "/v1/mailbox":
		var msgs []relayclient.Message
		for _, m := range r.boxes[relayauth.MailboxID(pk)] {
			if len(msgs) == 32 {
				break
			}
			if r.lease {
				if r.leased[m.MsgID] {
					continue
				}
				if r.leased == nil {
					r.leased = map[string]bool{}
				}
				r.leased[m.MsgID] = true
			}
			msgs = append(msgs, m)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"messages": append([]relayclient.Message{}, msgs...)})
	case req.Method == http.MethodDelete && strings.HasPrefix(req.URL.Path, "/v1/mailbox/"):
		if r.failAck {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"code":"injected"}`))
			return
		}
		id := strings.TrimPrefix(req.URL.Path, "/v1/mailbox/")
		mb := relayauth.MailboxID(pk)
		box := r.boxes[mb]
		for i, m := range box {
			if m.MsgID == id {
				r.boxes[mb] = append(box[:i:i], box[i+1:]...)
				break
			}
		}
		r.log = append(r.log, "ack "+id)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// fakeVault is a TEST-ONLY stand-in for the vault's side of one device's
// session: the first handshake (as the vault answers the first app,
// vault.respondFirst), sealed messages, and rekeys (vault.startRekey and
// handleResp). Like the vault, it finishes a rekey on the first valid
// hs.resp and drops later ones, and it records the inner ids it received
// so that a test sees duplicates.
type fakeVault struct {
	t        *testing.T
	r        *fakeRelay
	ik       ed25519.PrivateKey
	kem      *suite.PrivateKey
	relayKey ed25519.PrivateKey
	rc       *relayclient.Client
	kr       *handshake.Keyring
	resp     *handshake.Responder
	rekey    *handshake.Initiator
	dev      handshake.RelayAddr
	devIK    ed25519.PublicKey

	rekeyResps    int            // hs.resp that finished a rekey
	droppedResps  int            // hs.resp with no rekey outstanding
	received      map[string]int // inner id -> times received
	receivedTypes []string
}

const testVaultID = "vault-1"

func newFakeVault(t *testing.T, r *fakeRelay) *fakeVault {
	t.Helper()
	seed := func() []byte {
		b, err := suite.RandomBytes(32)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	kem, err := suite.NewPrivateKey(seed())
	if err != nil {
		t.Fatal(err)
	}
	v := &fakeVault{t: t, r: r, ik: ed25519.NewKeyFromSeed(seed()), kem: kem, relayKey: ed25519.NewKeyFromSeed(seed()),
		kr: &handshake.Keyring{}, received: map[string]int{}}
	v.rc = relayclient.New(r.url(), v.relayKey)
	return v
}

func (v *fakeVault) relayPK() ed25519.PublicKey { return v.relayKey.Public().(ed25519.PublicKey) }

func (v *fakeVault) mailbox() string { return handshake.MailboxID(v.relayPK()) }

func (v *fakeVault) addr() handshake.RelayAddr {
	return handshake.RelayAddr{URL: v.r.url(), Mailbox: v.mailbox(), PK: v.relayPK()}
}

// token mints a standing token for the device's mailbox, as the vault's
// relay client does.
func (v *fakeVault) token(ttl time.Duration) string {
	v.t.Helper()
	tok, err := v.rc.MintToken(relayauth.EncodeKey(v.dev.PK), v.dev.URL, relayclient.TokenOptions{TTL: ttl})
	if err != nil {
		v.t.Fatal(err)
	}
	return tok
}

// send seals a message to the device in the current epoch and deposits it.
func (v *fakeVault) send(typ string, body []byte) string {
	v.t.Helper()
	now := time.Now()
	id, _ := envelope.NewULID(now)
	raw, err := v.kr.Current().Seal(&envelope.Inner{ID: id, Type: typ, TS: now, Body: body})
	if err != nil {
		v.t.Fatal(err)
	}
	return v.r.put(v.dev.Mailbox, v.relayPK(), raw)
}

// startRekey sends a rekey hs.init in the current epoch (§6.5).
func (v *fakeVault) startRekey() string {
	v.t.Helper()
	ini, err := handshake.NewInitiator(handshake.InitiatorConfig{
		Purpose: handshake.PurposeRekey, Identity: v.ik, StaticKEM: v.kem.Public(), Relay: v.addr(),
		ResponderIK: v.devIK, ResponderRelayKey: v.dev.PK, Current: v.kr.Current(), PinnedSuite: v.kr.Current().Suite(),
		Policy: handshake.PolicyVaultToDevice, Now: time.Now(),
	})
	if err != nil {
		v.t.Fatal(err)
	}
	v.rekey = ini
	return v.r.put(v.dev.Mailbox, v.relayPK(), ini.Envelope())
}

// process handles everything in the vault's mailbox.
func (v *fakeVault) process() {
	v.t.Helper()
	now := time.Now()
	for _, m := range v.r.take(v.mailbox()) {
		env, err := envelope.Parse(m.Payload)
		if err != nil {
			v.t.Fatalf("vault: %v", err)
		}
		if env.Mode() == envelope.ModeSealed {
			if v.rekey == nil || !env.RecipientKid().Equal(v.rekey.EphKid()) {
				v.droppedResps++ // no handshake waits for it (vault.handleResp)
				continue
			}
			res, err := v.rekey.HandleResp(m.Payload, v.dev.PK, now)
			if err != nil {
				v.t.Fatalf("vault: hs.resp: %v", err)
			}
			v.rekey = nil
			v.rekeyResps++
			v.r.put(v.dev.Mailbox, v.relayPK(), res.Fin)
			v.kr.Activate(res.Epoch, now)
			continue
		}
		if v.resp != nil {
			if fr, err := v.resp.HandleFin(m.Payload, v.dev.PK, now); err == nil {
				v.resp = nil
				v.kr.Activate(fr.Epoch, now)
				continue
			}
		}
		in, _, err := v.kr.Open(env, now)
		if err != nil {
			v.t.Fatalf("vault: open: %v", err)
		}
		v.received[in.ID]++
		v.receivedTypes = append(v.receivedTypes, in.Type)
	}
}

// pair runs the device's first handshake with the vault (purpose app,
// ctx the vault id, as after enrollment) without Persist, and returns
// the device with an active session, no device id yet.
func pair(t *testing.T) (*fakeRelay, *fakeVault, *Device) {
	t.Helper()
	r, v, d := startPair(t)
	if err := d.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	v.process()
	if v.kr.Current() == nil || d.keyring.Current() == nil {
		t.Fatal("no session")
	}
	return r, v, d
}

// startPair runs pair up to the vault's hs.resp waiting in the device's
// mailbox.
func startPair(t *testing.T) (*fakeRelay, *fakeVault, *Device) {
	t.Helper()
	r := newFakeRelay(t)
	v := newFakeVault(t, r)
	d, err := Generate(Config{Role: "app", Name: "phone", RelayURL: r.url(), HTTP: r.srv.Client(), PollWait: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	v.dev, v.devIK = d.RelayAddr(), d.IdentityKey()
	d.mu.Lock()
	d.st.VaultID = testVaultID
	d.st.Vault = &VaultRecord{IK: v.ik.Public().(ed25519.PublicKey), KEM: v.kem.Public().Bytes(), RelayURL: r.url(), Mailbox: v.mailbox(), RelayPK: v.relayPK()}
	tok := v.token(30 * 24 * time.Hour)
	if d.st.Vault.TokenExp, err = d.heldFromVault(tok); err != nil {
		t.Fatal(err)
	}
	d.st.Vault.Token = tok
	err = d.startInit(handshake.PurposeApp, testVaultID, tok, nil)
	d.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	in := r.take(v.mailbox())
	if len(in) != 1 {
		t.Fatalf("hs.init: %d messages", len(in))
	}
	now := time.Now()
	pi, err := handshake.OpenInit(in[0].Payload, func(k suite.Kid) *suite.PrivateKey {
		if k.Equal(v.kem.Public().Kid()) {
			return v.kem
		}
		return nil
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	resp, env, err := pi.Respond(handshake.ResponderConfig{Identity: v.ik, Policy: handshake.PolicyVaultToDevice,
		CollectSender: v.dev.PK, Token: v.token(30 * 24 * time.Hour), Now: now})
	if err != nil {
		t.Fatal(err)
	}
	v.resp = resp
	r.put(v.dev.Mailbox, v.relayPK(), env)
	return r, v, d
}

// reload is a restart: a new Device from saved state, with persist.
func reload(t *testing.T, r *fakeRelay, saved []byte, persist func([]byte) error) *Device {
	t.Helper()
	d, err := Load(Config{HTTP: r.srv.Client(), PollWait: time.Second, Persist: persist}, saved)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

var errCrash = errors.New("simulated crash")

// crashes runs f and reports whether it stopped at a simulated crash (a
// panic(errCrash)): nothing after that point of f runs, as when the
// process dies there.
func crashes(f func()) (crashed bool) {
	defer func() {
		if p := recover(); p != nil {
			if p != errCrash {
				panic(p)
			}
			crashed = true
		}
	}()
	f()
	return false
}

// keep returns a Persist that keeps a copy of each state in *saved.
func keep(saved *[]byte, r *fakeRelay) func([]byte) error {
	return func(b []byte) error {
		*saved = append([]byte(nil), b...)
		if r != nil {
			r.note("persist")
		}
		return nil
	}
}

// pairedBody is device.paired for the device (§10.3), with a token.
func pairedBody(tok string) []byte {
	return strictjson.NewBuilder().String("device_id", "dev-1").String("role", "app").String("vault_id", testVaultID).
		String("token", tok).Bytes()
}

func tokenBody(tok string) []byte {
	return strictjson.NewBuilder().String("kind", "standing").String("token", tok).Bytes()
}

// sendBatch deposits device.paired (token t1), relay.token.issued (t2,
// later expiry) and a rekey hs.init, and returns their msg_ids.
func sendBatch(v *fakeVault) (ids []string, t1, t2 string) {
	t1, t2 = v.token(29*24*time.Hour), v.token(30*24*time.Hour)
	ids = append(ids, v.send("device.paired", pairedBody(t1)))
	ids = append(ids, v.send("relay.token.issued", tokenBody(t2)))
	ids = append(ids, v.startRekey())
	return ids, t1, t2
}

// checkRekeyed finishes the rekey on both sides and checks that the new
// epoch carries messages both ways.
func checkRekeyed(t *testing.T, r *fakeRelay, v *fakeVault, d *Device) {
	t.Helper()
	ctx := context.Background()
	v.process() // the device's hs.resp: the vault activates the new epoch and sends hs.fin
	if v.rekeyResps != 1 {
		t.Fatalf("rekeys finished by the vault: %d", v.rekeyResps)
	}
	before := v.kr.Current().ID()
	if err := d.Poll(ctx); err != nil { // hs.fin
		t.Fatal(err)
	}
	if got := d.keyring.Current().ID(); got != before {
		t.Fatal("device did not activate the rekeyed epoch")
	}
	v.send("test.ping", []byte(`{}`))
	if err := d.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range d.Events() {
		found = found || e.Type == "test.ping"
	}
	if !found {
		t.Fatal("device did not get a message in the new epoch")
	}
	if _, err := d.Send(ctx, "vault.status", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	v.process()
	if n := len(v.receivedTypes); n == 0 || v.receivedTypes[n-1] != "vault.status" {
		t.Fatalf("vault did not get the device's message in the new epoch: %v", v.receivedTypes)
	}
}

func loadState(t *testing.T, b []byte) State {
	t.Helper()
	var st State
	if err := json.Unmarshal(b, &st); err != nil {
		t.Fatal(err)
	}
	return st
}

// Nil Persist: as before, each message is acknowledged right after it
// is handled and the rekey's hs.resp is deposited while it is handled;
// nothing goes to the outbox.
func TestPersistNilUnchanged(t *testing.T) {
	r, v, d := pair(t)
	id := v.startRekey()
	mark := len(r.entries())
	if err := d.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := r.entries()[mark:]
	want := []string{"deposit " + v.mailbox(), "ack " + id}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("relay calls %v, want %v", got, want)
	}
	if d.st.Outbox != nil {
		t.Fatal("outbox used without Persist")
	}
	checkRekeyed(t, r, v, d)
}

// With Persist, a batch is handled, then saved, then its deposits are
// made, then it is acknowledged; the saved state holds the batch's
// effects, its msg_ids and the deposits.
func TestPersistBeforeAck(t *testing.T) {
	r, v, d := pair(t)
	var saved []byte
	d.cfg.Persist = keep(&saved, r)
	ids, _, t2 := sendBatch(v)
	mark := len(r.entries())
	if err := d.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := r.entries()[mark:]
	want := []string{"persist", "deposit " + v.mailbox(), "ack " + ids[0], "ack " + ids[1], "ack " + ids[2]}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("relay calls %v, want %v", got, want)
	}
	st := loadState(t, saved)
	if st.DeviceID != "dev-1" || st.Vault.Token != t2 || len(st.Awaiting) != 1 || len(st.Outbox) != 1 {
		t.Fatalf("saved: device %q, token new %v, awaiting %d, outbox %d", st.DeviceID, st.Vault.Token == t2, len(st.Awaiting), len(st.Outbox))
	}
	for _, id := range ids {
		if _, ok := st.Seen[id]; !ok {
			t.Fatalf("saved state lacks msg_id %s", id)
		}
	}
	if d.st.Outbox != nil {
		t.Fatal("outbox not emptied after the deposit")
	}
	checkRekeyed(t, r, v, d)
}

// A Persist error: Poll returns it, nothing of the batch is acknowledged
// or deposited, and the next Poll collects the batch again, saves,
// deposits once and acknowledges.
func TestPersistErrorLeavesBatchUnacked(t *testing.T) {
	r, v, d := pair(t)
	errDisk := errors.New("disk full")
	var saved []byte
	fail := true
	d.cfg.Persist = func(b []byte) error {
		if fail {
			return errDisk
		}
		return keep(&saved, r)(b)
	}
	ids, _, t2 := sendBatch(v)
	mark := len(r.entries())
	if err := d.Poll(context.Background()); !errors.Is(err, errDisk) {
		t.Fatalf("Poll: %v, want the Persist error", err)
	}
	if got := r.entries()[mark:]; len(got) != 0 {
		t.Fatalf("relay calls after a Persist error: %v", got)
	}
	if got := r.pending(v.dev.Mailbox); strings.Join(got, ",") != strings.Join(ids, ",") {
		t.Fatalf("waiting at the relay %v, want %v", got, ids)
	}
	// Another Persist error: the hs.resp from the first attempt is still
	// not saved, so it is not deposited either.
	if err := d.Poll(context.Background()); !errors.Is(err, errDisk) {
		t.Fatalf("Poll: %v, want the Persist error", err)
	}
	if got := r.entries()[mark:]; len(got) != 0 {
		t.Fatalf("relay calls after a Persist error: %v", got)
	}
	fail = false
	mark = len(r.entries())
	if err := d.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := r.entries()[mark:]
	want := []string{"persist", "deposit " + v.mailbox(), "ack " + ids[0], "ack " + ids[1], "ack " + ids[2]}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("relay calls %v, want %v", got, want)
	}
	st := loadState(t, saved)
	if st.DeviceID != "dev-1" || st.Vault.Token != t2 || len(st.Awaiting) != 1 {
		t.Fatal("the retried batch's effects are not in the saved state")
	}
	checkRekeyed(t, r, v, d) // exactly one hs.resp reached the vault
	if v.droppedResps != 0 {
		t.Fatalf("%d extra hs.resp", v.droppedResps)
	}
}

// The process dies in Persist, before anything is written: no ack, no
// deposit (in particular no hs.resp, which the vault would take as the
// rekey's answer). After a restart from the last saved state the relay
// delivers the batch again, and device.paired, the newer token and the
// rekey all take effect.
func TestCrashBeforePersistLosesNothing(t *testing.T) {
	r, v, d := pair(t)
	saved, err := d.Save()
	if err != nil {
		t.Fatal(err)
	}
	d.cfg.Persist = func([]byte) error { panic(errCrash) }
	ids, _, t2 := sendBatch(v)
	mark := len(r.entries())
	if !crashes(func() { _ = d.Poll(context.Background()) }) {
		t.Fatal("no crash")
	}
	if got := r.entries()[mark:]; len(got) != 0 {
		t.Fatalf("relay calls before Persist: %v", got)
	}
	if got := r.pending(v.dev.Mailbox); len(got) != len(ids) {
		t.Fatalf("waiting at the relay: %v", got)
	}

	d2 := reload(t, r, saved, keep(&saved, r))
	if d2.DeviceID() != "" {
		t.Fatal("device id before the batch was handled")
	}
	if err := d2.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if d2.DeviceID() != "dev-1" || d2.st.Vault.Token != t2 {
		t.Fatal("device.paired or the token was lost")
	}
	checkRekeyed(t, r, v, d2)
	// What was saved opens in the new epoch after another restart.
	d3 := reload(t, r, saved, keep(&saved, r))
	if d3.DeviceID() != "dev-1" || d3.st.Vault.Token != t2 {
		t.Fatal("saved state lost device.paired or the token")
	}
	v.send("test.ping", []byte(`{}`))
	if err := d3.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if ev := d3.Events(); len(ev) != 1 || ev[0].Type != "test.ping" {
		t.Fatal("restarted device cannot open the new epoch")
	}
}

// The process dies right after Persist: the deposits and acks never
// happen. After a restart the outbox goes out first, and the batch the
// relay delivers again is skipped by its msg_ids, which were saved with
// its effects: no handler runs again (no second hs.resp, no change to
// the state), and the batch is acknowledged.
func TestCrashAfterPersistReplaysHarmlessly(t *testing.T) {
	r, v, d := pair(t)
	var saved []byte
	d.cfg.Persist = func(b []byte) error {
		_ = keep(&saved, nil)(b)
		panic(errCrash)
	}
	ids, _, t2 := sendBatch(v)
	mark := len(r.entries())
	if !crashes(func() { _ = d.Poll(context.Background()) }) {
		t.Fatal("no crash")
	}
	if got := r.entries()[mark:]; len(got) != 0 {
		t.Fatalf("relay calls after a crash in Persist: %v", got)
	}
	atCrash := loadState(t, saved)
	if atCrash.DeviceID != "dev-1" || atCrash.Vault.Token != t2 || len(atCrash.Outbox) != 1 {
		t.Fatal("saved state lacks the batch")
	}

	var saved2 []byte
	d2 := reload(t, r, saved, keep(&saved2, r))
	mark = len(r.entries())
	if err := d2.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := r.entries()[mark:]
	want := []string{"deposit " + v.mailbox(), "ack " + ids[0], "ack " + ids[1], "ack " + ids[2]}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("relay calls %v, want %v (the outbox, then the replayed batch acknowledged with no deposit and nothing to save)", got, want)
	}
	if ev := d2.Events(); len(ev) != 0 {
		t.Fatalf("replayed batch handled again: %d events", len(ev))
	}
	// The state after the replay is the state at the crash, outbox sent.
	if saved2 != nil {
		t.Fatal("a batch of messages already saved was saved again")
	}
	now, err := d2.Save()
	if err != nil {
		t.Fatal(err)
	}
	after := loadState(t, now)
	atCrash.Outbox = nil
	a, _ := json.Marshal(atCrash)
	b, _ := json.Marshal(after)
	if !bytes.Equal(a, b) {
		t.Fatalf("replay changed the state:\n%s\n%s", a, b)
	}
	checkRekeyed(t, r, v, d2)
	if v.droppedResps != 0 {
		t.Fatalf("%d extra hs.resp", v.droppedResps)
	}
}

// The process dies after the deposits and before the acks (here: the
// acks fail and the device is dropped). The outbox removal was not
// saved, so the restarted device deposits the hs.resp again; the vault
// finishes the rekey with the first and drops the second, and the
// replayed batch is skipped and acknowledged.
func TestCrashBeforeAckDepositsAgain(t *testing.T) {
	r, v, d := pair(t)
	var saved []byte
	d.cfg.Persist = keep(&saved, r)
	ids, _, t2 := sendBatch(v)
	r.mu.Lock()
	r.failAck = true
	r.mu.Unlock()
	if err := d.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := r.pending(v.dev.Mailbox); len(got) != len(ids) {
		t.Fatalf("waiting at the relay: %v", got)
	}
	r.mu.Lock()
	r.failAck = false
	r.mu.Unlock()

	d2 := reload(t, r, saved, keep(&saved, r))
	if err := d2.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := r.pending(v.dev.Mailbox); len(got) != 0 {
		t.Fatalf("still waiting: %v", got)
	}
	if ev := d2.Events(); len(ev) != 0 {
		t.Fatalf("replayed batch handled again: %d events", len(ev))
	}
	if d2.DeviceID() != "dev-1" || d2.st.Vault.Token != t2 {
		t.Fatal("state lost")
	}
	checkRekeyed(t, r, v, d2)
	if v.droppedResps != 1 {
		t.Fatalf("second hs.resp: %d dropped, want 1", v.droppedResps)
	}
}

// An outbox entry whose deposit fails transiently stays for the next
// Poll; one the relay refuses with a client error is dropped, as a
// failed deposit is without Persist.
func TestPersistOutboxRetry(t *testing.T) {
	r, v, d := pair(t)
	var saved []byte
	d.cfg.Persist = keep(&saved, r)
	v.startRekey()
	r.mu.Lock()
	// More failures than the relay client's own attempts (3).
	r.failDeposit, r.depositStatus = 3, http.StatusServiceUnavailable
	r.mu.Unlock()
	if err := d.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(d.st.Outbox) != 1 || len(r.pending(v.mailbox())) != 0 {
		t.Fatal("a transient failure dropped the entry")
	}
	d.cfg.Now = func() time.Time { return time.Now().Add(time.Minute) } // past the backoff
	if err := d.Poll(context.Background()); err != nil {                // nothing to collect; the outbox goes out
		t.Fatal(err)
	}
	if d.st.Outbox != nil {
		t.Fatal("entry not sent at the next Poll")
	}
	checkRekeyed(t, r, v, d)

	v.startRekey()
	r.mu.Lock()
	r.failDeposit, r.depositStatus = 1, http.StatusForbidden
	r.mu.Unlock()
	if err := d.Poll(context.Background()); !errors.Is(err, ErrOutboxDropped) {
		t.Fatalf("Poll: %v, want ErrOutboxDropped", err)
	}
	if d.st.Outbox != nil || len(r.pending(v.mailbox())) != 0 {
		t.Fatal("a refused entry was kept")
	}
}
