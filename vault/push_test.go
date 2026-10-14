package vault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/pushwire"
)

// VAULT-MESSAGING 0.24.0 §14: push.register, push.confirm (PUSH-GATEWAY
// 0.5.0), push.unregister, push.token-needed, the wake rules and their
// outcomes, against a fake gateway.

type fakeGW struct {
	mu         sync.Mutex
	regs       []pushwire.Registration
	regKeys    []ed25519.PublicKey
	regErr     error
	pendings   map[string]fakePending // pending registration -> its challenge
	codes      []string               // the challenges' codes, in order
	confirms   int                    // confirmations that reached the gateway
	confirmErr error
	wakes      []string // blobs
	wakeKeys   []ed25519.PublicKey
	wakeErrs   []error // answers of the next wakes
	reseal     string
	n          int
	wakeDelay  time.Duration
	woke       chan struct{}
}

type fakePending struct {
	code string
	key  ed25519.PublicKey
}

func newFakeGW() *fakeGW {
	return &fakeGW{woke: make(chan struct{}, 64), pendings: map[string]fakePending{}}
}

// Register answers a pending registration and records the challenge code
// it "sent" to the token (PUSH-GATEWAY 0.5.0 §5.1).
func (g *fakeGW) Register(_ context.Context, k ed25519.PrivateKey, r pushwire.Registration) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.regErr != nil {
		return "", g.regErr
	}
	g.regs = append(g.regs, r)
	pub := append(ed25519.PublicKey(nil), k.Public().(ed25519.PublicKey)...)
	g.regKeys = append(g.regKeys, pub)
	g.n++
	pending, code := "UEVORElORy"+strings.Repeat("A", g.n), "Q09ERS"+strings.Repeat("B", g.n)
	g.pendings[pending] = fakePending{code: code, key: pub}
	g.codes = append(g.codes, code)
	return pending, nil
}

// Confirm issues the blob for the pending registration's code and key;
// anything else is 403 challenge_invalid.
func (g *fakeGW) Confirm(_ context.Context, k ed25519.PrivateKey, pending, code string) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.confirms++
	if g.confirmErr != nil {
		return "", g.confirmErr
	}
	fp, ok := g.pendings[pending]
	if !ok || fp.code != code || !fp.key.Equal(k.Public()) {
		return "", &pushwire.Error{Status: 403, Code: pushwire.CodeChallengeInvalid}
	}
	return "QkxPQi" + strings.Repeat("A", g.n) + strings.Repeat("C", g.confirms), nil
}

// lastCode is the latest challenge's code: what the app would receive.
func (g *fakeGW) lastCode() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.codes) == 0 {
		return ""
	}
	return g.codes[len(g.codes)-1]
}

// registerPush registers in both steps, playing the app: push.register
// (answered pending), then push.confirm with the challenge's code.
func (d *devFixture) registerPush(t *testing.T, g *fakeGW, body string) *envelope.Inner {
	t.Helper()
	r, _ := d.request(t, "push.register", body)
	if st, _ := pushState(t, r).String("state"); st == PushStateActive {
		return r // idempotent: nothing to confirm
	} else if st != PushStatePending {
		t.Fatalf("push.register state %q", st)
	}
	r, _ = d.request(t, "push.confirm", `{"code":"`+g.lastCode()+`"}`)
	if st, _ := pushState(t, r).String("state"); st != PushStateActive {
		t.Fatalf("push.confirm state %q", st)
	}
	return r
}

func (g *fakeGW) Wake(ctx context.Context, k ed25519.PrivateKey, blob string) (string, error) {
	if g.wakeDelay > 0 {
		select {
		case <-time.After(g.wakeDelay):
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.wakes = append(g.wakes, blob)
	g.wakeKeys = append(g.wakeKeys, append(ed25519.PublicKey(nil), k.Public().(ed25519.PublicKey)...))
	var err error
	if len(g.wakeErrs) > 0 {
		err, g.wakeErrs = g.wakeErrs[0], g.wakeErrs[1:]
	}
	r := ""
	if err == nil {
		r, g.reseal = g.reseal, ""
	}
	g.woke <- struct{}{}
	return r, err
}

func (g *fakeGW) wakeCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.wakes)
}

// waitWakes waits until n wakes were made.
func (g *fakeGW) waitWakes(t *testing.T, n int) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for g.wakeCount() < n {
		select {
		case <-g.woke:
		case <-deadline:
			t.Fatalf("%d wakes, want %d", g.wakeCount(), n)
		}
	}
}

// noWake checks that no wake beyond n happens within d.
func (g *fakeGW) noWake(t *testing.T, n int, d time.Duration) {
	t.Helper()
	time.Sleep(d)
	if c := g.wakeCount(); c != n {
		t.Fatalf("%d wakes, want %d", c, n)
	}
}

var fastPush = &PushTiming{Debounce: 40 * time.Millisecond, Retries: []time.Duration{30 * time.Millisecond, 30 * time.Millisecond, 30 * time.Millisecond},
	Jitter: 0, LockBudget: 500 * time.Millisecond, RetryAfter: 30 * time.Millisecond}

func pushFixture(t *testing.T) (*devFixture, *fakeGW) {
	d := newDevFixture(t)
	g := newFakeGW()
	d.m.opt.Push, d.m.opt.PushTiming = g, fastPush
	t.Cleanup(func() { d.m.Crash() })
	return d, g
}

const fcmReg = `{"platform":"fcm","token":"fcm-token-0001:APA91b","app_id":"com.vettid.app"}`

func pushState(t *testing.T, r *envelope.Inner) strictjson.Object {
	t.Helper()
	if r.Error != nil {
		t.Fatalf("error %+v %s", r.Error, r.Body)
	}
	o, err := strictjson.ParseObject(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	p, err := o.Object("push")
	if err != nil {
		t.Fatalf("no push in %s", r.Body)
	}
	return p
}

func (d *devFixture) withLock(f func(m *Manager)) {
	d.m.mu.Lock()
	defer d.m.mu.Unlock()
	f(d.m)
}

func (d *devFixture) audits(kind string) []Activity {
	var out []Activity
	for _, a := range sinkOf(d).got {
		if a.Kind == kind {
			out = append(out, a)
		}
	}
	return out
}

func TestPushRegister(t *testing.T) {
	d, g := pushFixture(t)
	d.m.addFeature(&recSink{})
	// PUSH-GATEWAY 0.5.0: the gateway answers a pending registration and
	// sends a challenge to the token; the vault answers state pending and
	// keeps it, with its wake key, until push.confirm.
	r, _ := d.request(t, "push.register", fcmReg)
	pp := pushState(t, r)
	if st, _ := pp.String("state"); st != PushStatePending || !pp.Has("registered_at") {
		t.Fatalf("pending push state %v", pp)
	}
	if d.m.st.Push != nil || d.m.st.PushPending == nil || len(d.m.st.PushPending.WakeSeed) != 32 || d.m.st.PushPending.DeviceID != d.devPeer.ID {
		t.Fatalf("pending %+v, registration %+v", d.m.st.PushPending, d.m.st.Push)
	}
	if len(d.audits("push.registered")) != 0 || len(d.m.st.PushRegs) != 1 {
		t.Fatal("a pending registration was audited, or not counted")
	}
	r, _ = d.request(t, "device.list", `{}`)
	if strings.Contains(string(r.Body), `"push"`) {
		t.Fatalf("device.list shows a pending registration: %s", r.Body)
	}
	r, _ = d.request(t, "push.confirm", `{"code":"`+g.lastCode()+`"}`)
	ps := pushState(t, r)
	if d.m.st.PushPending != nil || len(d.m.st.PushRegs) != 1 || g.confirms != 1 {
		t.Fatal("pending kept after confirmation, or the confirmation counted")
	}
	for k, want := range map[string]string{"platform": "fcm", "app_id": "com.vettid.app", "state": "active"} {
		if v, _ := ps.String(k); v != want {
			t.Fatalf("%s = %q", k, v)
		}
	}
	if ps.Has("environment") || !ps.Has("registered_at") || ps.Has("last_wake_at") || ps.Has("last_result") {
		t.Fatalf("push state %v", ps)
	}
	if len(g.regs) != 1 || g.regs[0].Token != "fcm-token-0001:APA91b" {
		t.Fatalf("gateway registrations %+v", g.regs)
	}
	// The token is never stored; the registration and its key are.
	st, _ := json.Marshal(d.m.st)
	if bytes.Contains(st, []byte("fcm-token-0001")) {
		t.Fatal("token in vault state")
	}
	cur := d.m.st.Push
	if cur == nil || cur.DeviceID != d.devPeer.ID || len(cur.WakeSeed) != 32 || cur.WakeBlob == "" || len(cur.TokenHash) != 32 {
		t.Fatalf("registration %+v", cur)
	}
	if !ed25519.NewKeyFromSeed(cur.WakeSeed).Public().(ed25519.PublicKey).Equal(g.regKeys[0]) {
		t.Fatal("stored key is not the registered one")
	}
	if a := d.audits("push.registered"); len(a) != 1 || a[0].DeviceID != d.devPeer.ID || a[0].Ref != "fcm" || !a[0].Audit || a[0].Feed {
		t.Fatalf("audit %+v", a)
	}
	// device.list shows it on the app's entry.
	r, _ = d.request(t, "device.list", `{}`)
	if !strings.Contains(string(r.Body), `"push":{"platform":"fcm","app_id":"com.vettid.app","state":"active"`) {
		t.Fatalf("device.list %s", r.Body)
	}

	// Idempotence: the same registration contacts no one.
	r, _ = d.request(t, "push.register", fcmReg)
	pushState(t, r)
	if len(g.regs) != 1 || len(d.audits("push.registered")) != 1 {
		t.Fatal("a repeated registration reached the gateway")
	}
	// A token rotation: a new key and blob replace the old ones, once
	// confirmed; until then the old registration stays in force.
	old := d.m.st.Push.WakeBlob
	r, _ = d.request(t, "push.register", `{"platform":"fcm","token":"rotated","app_id":"com.vettid.app"}`)
	if st, _ := pushState(t, r).String("state"); st != PushStatePending || d.m.st.Push.WakeBlob != old {
		t.Fatal("rotation: the registration in force changed before the confirmation")
	}
	d.request(t, "push.confirm", `{"code":"`+g.lastCode()+`"}`)
	if len(g.regs) != 2 || g.regKeys[0].Equal(g.regKeys[1]) || d.m.st.Push.WakeBlob == old {
		t.Fatal("rotation did not replace key and blob")
	}
	// APNs needs its environment.
	r = d.registerPush(t, g, `{"platform":"apns","token":"`+strings.Repeat("0a", 32)+`","app_id":"com.vettid.app","environment":"sandbox"}`)
	if e, _ := pushState(t, r).String("environment"); e != "sandbox" {
		t.Fatal("environment")
	}
}

func TestPushRegisterChecks(t *testing.T) {
	d, g := pushFixture(t)
	for _, b := range []string{`{}`, `{"platform":"fcm","token":"x","app_id":"a","environment":"production"}`,
		`{"platform":"apns","token":"x","app_id":"a","environment":"sandbox"}`, `{"platform":"fcm","token":"x","app_id":"a","x":1}`} {
		if c := d.errorCode(t, "push.register", b); c != "bad_request" {
			t.Fatalf("%s: %s", b, c)
		}
	}
	if len(g.regs) != 0 {
		t.Fatal("bad body reached the gateway")
	}
	// Only the holder: a desktop is forbidden.
	desk := d.addDevice(t, "desk1", KindDesktop, 0x60)
	desk.peer.Access = &AccessSession{ID: "s1", Expires: time.Now().Add(time.Hour)}
	id := d.sendAs(desk, "push.register", fcmReg)
	if r := find(d.inbox(desk)["desk1"], reply(id)); r == nil || r.Error == nil || r.Error.Code != "forbidden" {
		t.Fatalf("desktop: %+v", r)
	}
	// A recovering app is forbidden too.
	d.devPeer.Recovering = true
	if c := d.errorCode(t, "push.register", fcmReg); c != "forbidden" {
		t.Fatalf("recovering: %s", c)
	}
	d.devPeer.Recovering = false
	// No gateway in the release: unavailable.
	d.m.opt.Push = nil
	if c := d.errorCode(t, "push.register", fcmReg); c != "unavailable" {
		t.Fatalf("no gateway: %s", c)
	}
	d.m.opt.Push = g

	// Gateway answers: the previous registration stays.
	d.registerPush(t, g, fcmReg)
	prev := d.m.st.Push.WakeBlob
	for _, c := range []struct {
		err  error
		code string
		msg  string
		body string
	}{
		{&pushwire.Error{Status: 400, Code: "token_invalid"}, "bad_request", "token_invalid", ""},
		{&pushwire.Error{Status: 400, Code: "app_invalid"}, "bad_request", "app_invalid", ""},
		{&pushwire.Error{Status: 403, Code: "attestation_invalid"}, "gateway_error", "", `{}`},
		{&pushwire.Error{Status: 429, Code: "rate_limited", RetryAfter: 30}, "gateway_error", "", `{"retry_after":30}`},
		{&pushwire.Error{Status: 502, Code: "provider_unavailable", RetryAfter: 7}, "gateway_error", "", `{"retry_after":7}`},
		{&pushwire.Error{Status: 500, Code: "internal", RetryAfter: 7}, "gateway_error", "", `{}`},
		{pushwire.ErrTransport, "gateway_error", "", `{}`},
		{context.DeadlineExceeded, "gateway_error", "", `{}`},
	} {
		g.regErr = c.err
		r, _ := d.request(t, "push.register", `{"platform":"fcm","token":"other","app_id":"com.vettid.app"}`)
		if r.Error == nil || r.Error.Code != c.code || r.Error.Message != c.msg || c.body != "" && string(r.Body) != c.body {
			t.Fatalf("%v: %+v %s", c.err, r.Error, r.Body)
		}
		if d.m.st.Push == nil || d.m.st.Push.WakeBlob != prev || d.m.st.PushPending != nil {
			t.Fatal("a failed registration changed the registration")
		}
	}
	g.regErr = nil
}

// §14.1 check 5: 20 registrations that reached the gateway in 24 hours.
// Every HTTP answer counts, an unparsable or oversized one included
// (0.24.1, owner decision 2026-10-10); a timeout or no connection does not.
func TestPushRegistrationLimit(t *testing.T) {
	d, g := pushFixture(t)
	for _, c := range []struct {
		err     error
		counted bool
	}{
		{&pushwire.Error{Status: 403, Code: "attestation_invalid"}, true},
		{&pushwire.Error{Status: 401, Code: "signature_invalid"}, true},
		{pushwire.ErrResponse, true},
		{pushwire.ErrOversized, true},
		{pushwire.ErrTransport, false},
		{context.DeadlineExceeded, false},
	} {
		n := len(d.m.st.PushRegs)
		g.regErr = c.err
		if code := d.errorCode(t, "push.register", fcmReg); code != "gateway_error" {
			t.Fatalf("%v: %s", c.err, code)
		}
		if got := len(d.m.st.PushRegs) - n; got != map[bool]int{true: 1, false: 0}[c.counted] {
			t.Fatalf("%v: counted %d", c.err, got)
		}
	}
	g.regErr = nil
	used := len(d.m.st.PushRegs)
	if used != 4 {
		t.Fatalf("counted %d", used)
	}
	for i := used; i < MaxPushRegistrations; i++ {
		if c := d.errorCode(t, "push.register", `{"platform":"fcm","token":"t`+strings.Repeat("x", i)+`","app_id":"a"}`); c != "" {
			t.Fatalf("%d: %s", i, c)
		}
	}
	// The last one is confirmed (the confirmation does not count).
	if c := d.errorCode(t, "push.confirm", `{"code":"`+g.lastCode()+`"}`); c != "" || len(d.m.st.PushRegs) != MaxPushRegistrations {
		t.Fatal(c, len(d.m.st.PushRegs))
	}
	r, _ := d.request(t, "push.register", `{"platform":"fcm","token":"one-more","app_id":"a"}`)
	if r.Error == nil || r.Error.Code != "limit" || LimitName(&HandlerError{Code: "limit", Body: r.Body}) != "push_registrations" {
		t.Fatalf("21st: %+v %s", r.Error, r.Body)
	}
	// The same token is still answered (idempotence comes first).
	if c := d.errorCode(t, "push.register", `{"platform":"fcm","token":"t`+strings.Repeat("x", MaxPushRegistrations-1)+`","app_id":"a"}`); c != "" {
		t.Fatal(c)
	}
	// The window rolls.
	for i := range d.m.st.PushRegs {
		d.m.st.PushRegs[i] = d.m.st.PushRegs[i].Add(-25 * time.Hour)
	}
	if c := d.errorCode(t, "push.register", `{"platform":"fcm","token":"later","app_id":"a"}`); c != "" {
		t.Fatal(c)
	}
}

func TestPushUnregister(t *testing.T) {
	d, g := pushFixture(t)
	d.m.addFeature(&recSink{})
	r, _ := d.request(t, "push.unregister", `{}`)
	if r.Error != nil || string(r.Body) != `{}` || len(d.audits("push.unregistered")) != 0 {
		t.Fatalf("without a registration: %+v", r)
	}
	if c := d.errorCode(t, "push.unregister", `{"x":1}`); c != "bad_request" {
		t.Fatal(c)
	}
	d.registerPush(t, g, fcmReg)
	seed := d.m.st.Push.WakeSeed
	r, _ = d.request(t, "push.unregister", `{}`)
	if r.Error != nil || d.m.st.Push != nil || !bytes.Equal(seed, make([]byte, 32)) {
		t.Fatal("not erased and wiped")
	}
	if a := d.audits("push.unregistered"); len(a) != 1 || a[0].Ref != "app" || a[0].DeviceID != d.devPeer.ID {
		t.Fatalf("audit %+v", a)
	}
	r, _ = d.request(t, "device.list", `{}`)
	if strings.Contains(string(r.Body), `"push"`) {
		t.Fatal("device.list still shows push")
	}
}

// A transfer or a recovery that removes the app erases its registration
// (ref transferred or replaced).
func TestPushErasedWithApp(t *testing.T) {
	for _, reason := range []string{"transferred", "replaced"} {
		d, g := pushFixture(t)
		d.m.addFeature(&recSink{})
		d.registerPush(t, g, fcmReg)
		d.withLock(func(m *Manager) { m.removeApp(d.devPeer, reason, time.Now()) })
		if d.m.st.Push != nil {
			t.Fatal("registration kept")
		}
		if a := d.audits("push.unregistered"); len(a) != 1 || a[0].Ref != reason {
			t.Fatalf("%s: %+v", reason, a)
		}
	}
}

// deliver sends one durable message to the app as a feature would.
func (d *devFixture) deliver(typ, body string) {
	d.withLock(func(m *Manager) {
		m.sendTo(d.devPeer, typ, json.RawMessage(body), time.Now())
		m.drainOutbox(context.Background())
	})
}

// §14.2: what wakes and what does not.
func TestPushWakeTriggers(t *testing.T) {
	d, g := pushFixture(t)
	d.registerPush(t, g, fcmReg)
	n := 0
	for _, c := range []struct {
		typ, body string
		wakes     bool
	}{
		{"feed.event", `{"item_id":"a","kind":"message.received","priority":"normal"}`, true},
		{"feed.event", `{"item_id":"b","kind":"connection.request","priority":"high"}`, true},
		{"feed.event", `{"item_id":"c","kind":"credential.alarm","priority":"urgent"}`, true},
		{"feed.event", `{"item_id":"d","kind":"message.received","priority":"low"}`, false},
		{"feed.event", `{"item_id":"e","kind":"guide","priority":"high"}`, false},
		{"vault.held", `{"deadline":"2026-10-10T00:00:00.000Z","waiting":{}}`, true},
		{"credential.alarm", `{"alarm_id":"x"}`, true},
		{"message.new", `{}`, false},
		{"sync.event", `{"kind":"feed.updated"}`, false},
		{"connection.event", `{}`, false},
	} {
		d.deliver(c.typ, c.body)
		if c.wakes {
			n++
			g.waitWakes(t, n)
		} else {
			g.noWake(t, n, 120*time.Millisecond)
		}
		time.Sleep(50 * time.Millisecond) // past the debounce
	}
	// The wake is signed by the registration's key and carries its blob.
	if !g.wakeKeys[0].Equal(g.regKeys[0]) || g.wakes[0] != d.m.st.Push.WakeBlob {
		t.Fatal("wake key or blob")
	}
	// Desktops are never woken, and responses do not wake.
	desk := d.addDevice(t, "desk1", KindDesktop, 0x60)
	desk.peer.Access = &AccessSession{ID: "s1", Expires: time.Now().Add(time.Hour)}
	d.withLock(func(m *Manager) {
		m.sendTo(desk.peer, "feed.event", json.RawMessage(`{"kind":"message.received","priority":"high"}`), time.Now())
		m.drainOutbox(context.Background())
	})
	d.request(t, "vault.status", `{}`)
	g.noWake(t, n, 150*time.Millisecond)
	// Nothing wakes without a registration.
	d.request(t, "push.unregister", `{}`)
	d.deliver("vault.held", `{}`)
	g.noWake(t, n, 150*time.Millisecond)
}

// A wake follows the relay's acceptance of the deposit only.
func TestPushWakeAfterDepositOnly(t *testing.T) {
	d, g := pushFixture(t)
	d.registerPush(t, g, fcmReg)
	d.relay.mu.Lock()
	d.relay.failWith = &pushwire.Error{Status: 503} // any error: the deposit is not accepted
	d.relay.mu.Unlock()
	d.deliver("vault.held", `{}`)
	g.noWake(t, 0, 150*time.Millisecond)
	d.relay.mu.Lock()
	d.relay.failWith = nil
	d.relay.mu.Unlock()
	d.withLock(func(m *Manager) {
		for _, e := range m.st.Outbox {
			e.NotBefore = time.Time{}
		}
		m.drainOutbox(context.Background())
	})
	g.waitWakes(t, 1)
}

// Triggers within the debounce merge into one wake.
func TestPushDebounceMerges(t *testing.T) {
	d, g := pushFixture(t)
	d.m.opt.PushTiming = &PushTiming{Debounce: 300 * time.Millisecond}
	d.registerPush(t, g, fcmReg)
	d.deliver("vault.held", `{}`)
	g.waitWakes(t, 1)
	for i := 0; i < 5; i++ {
		d.deliver("feed.event", `{"kind":"message.received","priority":"normal"}`)
	}
	g.noWake(t, 1, 150*time.Millisecond)
	g.waitWakes(t, 2)
	g.noWake(t, 2, 400*time.Millisecond)
}

func TestPushOutcomes(t *testing.T) {
	d, g := pushFixture(t)
	d.m.addFeature(&recSink{})
	d.registerPush(t, g, fcmReg)
	d.appInbox()

	// 202 with a reseal: the blob is replaced (at the next flush) and the
	// next wake uses it.
	g.reseal = "UkVTRUFM"
	d.deliver("vault.held", `{}`)
	g.waitWakes(t, 1)
	waitFor(t, func() bool {
		var ok bool
		d.withLock(func(m *Manager) { ok = m.st.Push.WakeBlob == "UkVTRUFM" && m.st.Push.LastResult == PushSent && m.dirty })
		return ok
	})
	r, _ := d.request(t, "device.list", `{}`)
	if !strings.Contains(string(r.Body), `"last_result":"sent"`) || !strings.Contains(string(r.Body), `"last_wake_at"`) {
		t.Fatalf("device.list %s", r.Body)
	}
	time.Sleep(50 * time.Millisecond)
	d.deliver("vault.held", `{}`)
	g.waitWakes(t, 2)
	if g.wakes[1] != "UkVTRUFM" {
		t.Fatal("reseal not used")
	}

	// 5xx: retried, then dropped; gateway_error.
	time.Sleep(50 * time.Millisecond)
	e502 := &pushwire.Error{Status: 502, Code: "provider_unavailable"}
	g.wakeErrs = []error{e502, e502, e502, e502}
	d.deliver("vault.held", `{}`)
	g.waitWakes(t, 6)
	g.noWake(t, 6, 200*time.Millisecond)
	waitFor(t, func() bool {
		var ok bool
		d.withLock(func(m *Manager) { ok = m.st.Push.LastResult == PushGatewayError })
		return ok
	})
	if len(d.audits("push.token_gone")) != 0 {
		t.Fatal("5xx audited")
	}

	// 429: waits retry_after, then sends.
	g.wakeErrs = []error{&pushwire.Error{Status: 429, Code: "rate_limited"}}
	d.deliver("vault.held", `{}`)
	g.waitWakes(t, 8)

	// A dead token: erased, audited, push.token-needed to the app.
	for _, code := range []struct {
		status int
		code   string
	}{{410, "token_gone"}, {400, "token_invalid"}, {410, "blob_invalid"}} {
		if d.m.st.Push == nil {
			d.registerPush(t, g, `{"platform":"fcm","token":"`+code.code+`","app_id":"com.vettid.app"}`)
		}
		d.appInbox()
		time.Sleep(50 * time.Millisecond)
		g.wakeErrs = []error{&pushwire.Error{Status: code.status, Code: code.code}}
		n := g.wakeCount()
		d.deliver("vault.held", `{}`)
		g.waitWakes(t, n+1)
		waitFor(t, func() bool {
			var ok bool
			d.withLock(func(m *Manager) { ok = m.st.Push == nil })
			return ok
		})
		if a := d.audits("push.token_gone"); len(a) == 0 || a[len(a)-1].Ref != code.code || a[len(a)-1].DeviceID != d.devPeer.ID {
			t.Fatalf("%s: audit %+v", code.code, a)
		}
		var ev *envelope.Inner
		waitFor(t, func() bool { ev = find(d.appInbox(), ofType(TypePushTokenNeeded)); return ev != nil })
		if string(ev.Body) != `{"reason":"`+code.code+`"}` {
			t.Fatalf("token_needed %s", ev.Body)
		}
		g.noWake(t, n+1, 100*time.Millisecond) // push.token-needed does not wake: there is no registration
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// §14.2 trigger 3: vault.locking wakes before the vault zeroizes, except
// for the app's own vault.lock.
func TestPushLockWake(t *testing.T) {
	d, g := pushFixture(t)
	d.registerPush(t, g, fcmReg)
	if err := d.m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	if g.wakeCount() != 1 {
		t.Fatalf("host lock: %d wakes", g.wakeCount())
	}

	d, g = pushFixture(t)
	d.registerPush(t, g, fcmReg)
	if err := d.send("vault.lock", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if !d.m.Locked() {
		t.Fatal("not locked")
	}
	g.noWake(t, 0, 100*time.Millisecond)

	// A lock never waits longer than the budget for a slow gateway.
	d, g = pushFixture(t)
	d.registerPush(t, g, fcmReg)
	g.wakeDelay = 5 * time.Second
	start := time.Now()
	_ = d.m.Lock(context.Background())
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("lock took %v", el)
	}
}

// §3.6.3: push.register, push.confirm and push.unregister are on the
// holder's allow list while held, and push.token-needed still reaches the
// app.
func TestPushWhileHeld(t *testing.T) {
	f := newOCFixture(t)
	g := newFakeGW()
	f.m.opt.Push, f.m.opt.PushTiming = g, fastPush
	t.Cleanup(func() { f.m.Crash() })
	f.pastDeadline()
	if st := f.status(t, f.app); func() string { s, _ := st.String("state"); return s }() != OwnerCheckHeld {
		t.Fatal("not held")
	}
	r := f.req(t, f.app, "push.register", fcmReg)
	pushState(t, r)
	r = f.req(t, f.app, "push.confirm", `{"code":"`+g.lastCode()+`"}`)
	if st, _ := pushState(t, r).String("state"); st != PushStateActive {
		t.Fatalf("confirm while held: %s", st)
	}
	r = f.req(t, f.app, "device.list", `{}`)
	if r.Error == nil || r.Error.Code != "owner_check_required" {
		t.Fatalf("device.list while held: %+v", r.Error)
	}
	f.withLock(func(m *Manager) {
		if !m.holdDelivers(f.devPeer, TypePushTokenNeeded, json.RawMessage(`{}`), time.Now()) ||
			m.holdDelivers(f.devPeer, "feed.event", json.RawMessage(`{"kind":"message.received","priority":"high"}`), time.Now()) {
			t.Error("hold delivery rules")
		}
	})
	r = f.req(t, f.app, "push.unregister", `{}`)
	if r.Error != nil {
		t.Fatalf("unregister while held: %+v", r.Error)
	}
}

// PUSH-GATEWAY 0.5.0 §5.1: push.confirm{code} confirms the latest pending
// registration with the challenge code the app received; its refusals.
func TestPushConfirm(t *testing.T) {
	d, g := pushFixture(t)
	d.m.addFeature(&recSink{})
	noPending := func(body string) {
		t.Helper()
		r, _ := d.request(t, "push.confirm", body)
		if r.Error == nil || r.Error.Code != "bad_request" || r.Error.Message != "no_pending_registration" {
			t.Fatalf("no pending: %+v", r.Error)
		}
	}
	// No pending registration: bad_request, nothing sent.
	noPending(`{"code":"Q09ERQ"}`)
	// Bodies.
	for _, b := range []string{`{}`, `{"code":""}`, `{"code":"a b"}`, `{"code":"a="}`, `{"code":1}`,
		`{"code":"Q09ERQ","x":1}`, `{"code":"` + strings.Repeat("a", 65) + `"}`} {
		if c := d.errorCode(t, "push.confirm", b); c != "bad_request" {
			t.Fatalf("%s: %s", b, c)
		}
	}
	if g.confirms != 0 {
		t.Fatal("a refused confirmation reached the gateway")
	}

	// A registration in force, then a renewal pending: a wrong code is
	// gateway_error challenge_invalid, the pending registration is dropped
	// (wiped) and the registration in force stays.
	d.registerPush(t, g, fcmReg)
	prev := d.m.st.Push.WakeBlob
	d.request(t, "push.register", `{"platform":"fcm","token":"next","app_id":"com.vettid.app"}`)
	seed := d.m.st.PushPending.WakeSeed
	r, _ := d.request(t, "push.confirm", `{"code":"V1JPTkc"}`)
	if r.Error == nil || r.Error.Code != "gateway_error" || r.Error.Message != pushwire.CodeChallengeInvalid {
		t.Fatalf("wrong code: %+v", r.Error)
	}
	if d.m.st.PushPending != nil || !bytes.Equal(seed, make([]byte, 32)) || d.m.st.Push == nil || d.m.st.Push.WakeBlob != prev {
		t.Fatal("wrong code: pending kept, or the registration in force changed")
	}
	noPending(`{"code":"` + g.lastCode() + `"}`)

	// Expired: 10 minutes after the registration the vault refuses
	// without calling the gateway, and drops the pending registration.
	d.request(t, "push.register", `{"platform":"fcm","token":"next","app_id":"com.vettid.app"}`)
	d.m.st.PushPending.StartedAt = d.m.st.PushPending.StartedAt.Add(-PushChallengeLife)
	n := g.confirms
	r, _ = d.request(t, "push.confirm", `{"code":"`+g.lastCode()+`"}`)
	if r.Error == nil || r.Error.Code != "gateway_error" || r.Error.Message != "challenge_expired" || g.confirms != n || d.m.st.PushPending != nil {
		t.Fatalf("expired: %+v (gateway calls %d)", r.Error, g.confirms-n)
	}

	// A replaced pending registration: a second push.register replaces
	// the first (its key wiped); the first challenge's code is refused,
	// the second's confirms.
	d.request(t, "push.register", `{"platform":"fcm","token":"first","app_id":"com.vettid.app"}`)
	first, firstSeed := g.lastCode(), d.m.st.PushPending.WakeSeed
	d.request(t, "push.register", `{"platform":"fcm","token":"second","app_id":"com.vettid.app"}`)
	if !bytes.Equal(firstSeed, make([]byte, 32)) {
		t.Fatal("replaced pending registration not wiped")
	}
	if c := d.errorCode(t, "push.confirm", `{"code":"`+first+`"}`); c != "gateway_error" {
		t.Fatalf("older code: %s", c)
	}
	d.request(t, "push.register", `{"platform":"fcm","token":"second","app_id":"com.vettid.app"}`)

	// A gateway that may recover (5xx, 429, no connection) keeps the
	// pending registration: the same code can be tried again.
	for _, e := range []error{&pushwire.Error{Status: 502, Code: "provider_unavailable", RetryAfter: 4},
		&pushwire.Error{Status: 429, Code: "rate_limited", RetryAfter: 9}, pushwire.ErrTransport} {
		g.confirmErr = e
		r, _ := d.request(t, "push.confirm", `{"code":"`+g.lastCode()+`"}`)
		if r.Error == nil || r.Error.Code != "gateway_error" || r.Error.Message != "" || d.m.st.PushPending == nil {
			t.Fatalf("%v: %+v, pending %v", e, r.Error, d.m.st.PushPending != nil)
		}
		if ge, ok := e.(*pushwire.Error); ok && string(r.Body) != fmt.Sprintf(`{"retry_after":%d}`, ge.RetryAfter) {
			t.Fatalf("%v: body %s", e, r.Body)
		}
	}
	// An answer that does not parse ends it.
	g.confirmErr = pushwire.ErrResponse
	if c := d.errorCode(t, "push.confirm", `{"code":"`+g.lastCode()+`"}`); c != "gateway_error" || d.m.st.PushPending != nil {
		t.Fatalf("unparsable: %s", c)
	}
	g.confirmErr = nil
	d.request(t, "push.register", `{"platform":"fcm","token":"second","app_id":"com.vettid.app"}`)
	pend := *d.m.st.PushPending
	pendKey := ed25519.NewKeyFromSeed(pend.WakeSeed).Public().(ed25519.PublicKey)
	r, _ = d.request(t, "push.confirm", `{"code":"`+g.lastCode()+`"}`)
	if st, _ := pushState(t, r).String("state"); st != PushStateActive {
		t.Fatal(st)
	}
	cur := d.m.st.Push
	if cur.WakeBlob == prev || !ed25519.NewKeyFromSeed(cur.WakeSeed).Public().(ed25519.PublicKey).Equal(pendKey) ||
		!bytes.Equal(cur.TokenHash, pend.TokenHash) || d.m.st.PushPending != nil {
		t.Fatal("the confirmed registration is not the pending one")
	}
	if a := d.audits("push.registered"); len(a) != 2 {
		t.Fatalf("push.registered audits %d", len(a))
	}
	// Wakes use the new key and blob.
	d.deliver("vault.held", `{}`)
	g.waitWakes(t, 1)
	if g.wakes[0] != cur.WakeBlob || !g.wakeKeys[0].Equal(pendKey) {
		t.Fatal("wake not with the confirmed registration")
	}

	// Only the holder; a release without a gateway.
	desk := d.addDevice(t, "desk1", KindDesktop, 0x60)
	desk.peer.Access = &AccessSession{ID: "s1", Expires: time.Now().Add(time.Hour)}
	id := d.sendAs(desk, "push.confirm", `{"code":"Q09ERQ"}`)
	if r := find(d.inbox(desk)["desk1"], reply(id)); r == nil || r.Error == nil || r.Error.Code != "forbidden" {
		t.Fatalf("desktop: %+v", r)
	}
	// A recovering app is forbidden too.
	d.devPeer.Recovering = true
	if c := d.errorCode(t, "push.confirm", `{"code":"Q09ERQ"}`); c != "forbidden" {
		t.Fatalf("recovering: %s", c)
	}
	d.devPeer.Recovering = false
	d.m.opt.Push = nil
	if c := d.errorCode(t, "push.confirm", `{"code":"Q09ERQ"}`); c != "unavailable" {
		t.Fatalf("no gateway: %s", c)
	}
	d.m.opt.Push = g

	// push.unregister drops a pending registration too.
	d.request(t, "push.register", `{"platform":"fcm","token":"third","app_id":"com.vettid.app"}`)
	d.request(t, "push.unregister", `{}`)
	if d.m.st.PushPending != nil || d.m.st.Push != nil {
		t.Fatal("unregister kept a registration")
	}
	// So does removing the app.
	d.request(t, "push.register", `{"platform":"fcm","token":"fourth","app_id":"com.vettid.app"}`)
	d.withLock(func(m *Manager) { m.removeApp(d.devPeer, "replaced", time.Now()) })
	if d.m.st.PushPending != nil {
		t.Fatal("pending registration kept with the app removed")
	}
}

// PUSH-GATEWAY 0.5.0 §4: a blob is honoured 90 days from its confirmation,
// so push.register with the same token renews through the gateway once the
// registration is 30 days old, instead of answering from state; until the
// renewal is confirmed the registration in force stays.
func TestPushRenewal(t *testing.T) {
	d, g := pushFixture(t)
	d.registerPush(t, g, fcmReg)
	old := *d.m.st.Push
	// Under 30 days: answered from state.
	d.m.st.Push.RegisteredAt = old.RegisteredAt.Add(-PushRenewAfter + time.Minute)
	r, _ := d.request(t, "push.register", fcmReg)
	if st, _ := pushState(t, r).String("state"); st != PushStateActive || len(g.regs) != 1 || d.m.st.PushPending != nil {
		t.Fatalf("under 30 days: state %s, %d gateway registrations", st, len(g.regs))
	}
	// At 30 days: a new registration and challenge.
	d.m.st.Push.RegisteredAt = old.RegisteredAt.Add(-PushRenewAfter)
	r, _ = d.request(t, "push.register", fcmReg)
	if st, _ := pushState(t, r).String("state"); st != PushStatePending || len(g.regs) != 2 || len(d.m.st.PushRegs) != 2 {
		t.Fatalf("at 30 days: state %s, %d gateway registrations", st, len(g.regs))
	}
	if d.m.st.Push == nil || d.m.st.Push.WakeBlob != old.WakeBlob {
		t.Fatal("the registration in force changed before the renewal was confirmed")
	}
	r, _ = d.request(t, "push.confirm", `{"code":"`+g.lastCode()+`"}`)
	pushState(t, r)
	cur := d.m.st.Push
	if cur.WakeBlob == old.WakeBlob || bytes.Equal(cur.WakeSeed, old.WakeSeed) || time.Since(cur.RegisteredAt) > time.Minute {
		t.Fatal("renewal did not replace key, blob and registered_at")
	}
	// Renewed: answered from state again.
	if r, _ := d.request(t, "push.register", fcmReg); r.Error != nil || len(g.regs) != 2 {
		t.Fatal("renewed registration not idempotent")
	}
}

// A blob the gateway refuses as invalid or expired (410 blob_invalid, also
// past its 90 days) drops the registration and asks the app for a fresh
// push.register; a pending registration is not affected.
func TestPushBlobExpiredKeepsPending(t *testing.T) {
	d, g := pushFixture(t)
	d.registerPush(t, g, fcmReg)
	d.request(t, "push.register", `{"platform":"fcm","token":"rotated","app_id":"com.vettid.app"}`)
	d.appInbox()
	g.wakeErrs = []error{&pushwire.Error{Status: 410, Code: pushwire.CodeBlobInvalid}}
	d.deliver("vault.held", `{}`)
	g.waitWakes(t, 1)
	var ev *envelope.Inner
	waitFor(t, func() bool { ev = find(d.appInbox(), ofType(TypePushTokenNeeded)); return ev != nil })
	if string(ev.Body) != `{"reason":"blob_invalid"}` {
		t.Fatal(string(ev.Body))
	}
	var pending bool
	d.withLock(func(m *Manager) { pending = m.st.Push == nil && m.st.PushPending != nil })
	if !pending {
		t.Fatal("registration kept or pending dropped")
	}
	if r, _ := d.request(t, "push.confirm", `{"code":"`+g.lastCode()+`"}`); r.Error != nil {
		t.Fatalf("confirm after blob_invalid: %+v", r.Error)
	}
}

// A push.register of the same token while its pending registration is
// within the challenge's life answers that pending registration: no new
// challenge, no replacement, its code still confirms. After the window a
// new challenge is made.
func TestPushPendingReused(t *testing.T) {
	d, g := pushFixture(t)
	r, _ := d.request(t, "push.register", fcmReg)
	if st, _ := pushState(t, r).String("state"); st != PushStatePending {
		t.Fatal(st)
	}
	first, code := d.m.st.PushPending.Pending, g.lastCode()
	d.m.st.PushPending.StartedAt = d.m.st.PushPending.StartedAt.Add(-PushChallengeLife + time.Minute)
	r, _ = d.request(t, "push.register", fcmReg)
	if st, _ := pushState(t, r).String("state"); st != PushStatePending || len(g.regs) != 1 || len(d.m.st.PushRegs) != 1 ||
		d.m.st.PushPending.Pending != first || g.lastCode() != code {
		t.Fatalf("within the window: state %s, %d gateway registrations, replaced %v", st, len(g.regs), d.m.st.PushPending.Pending != first)
	}
	// Another token is a new registration, replacing the pending one.
	d.request(t, "push.register", `{"platform":"fcm","token":"other","app_id":"com.vettid.app"}`)
	if len(g.regs) != 2 {
		t.Fatal("another token did not reach the gateway")
	}
	d.request(t, "push.register", fcmReg)
	code = g.lastCode()
	d.request(t, "push.register", fcmReg)
	if len(g.regs) != 3 {
		t.Fatalf("%d gateway registrations", len(g.regs))
	}
	if r, _ := d.request(t, "push.confirm", `{"code":"`+code+`"}`); r.Error != nil {
		t.Fatalf("the kept pending registration's code: %+v", r.Error)
	}

	// After the window: a new challenge.
	d2, g2 := pushFixture(t)
	d2.request(t, "push.register", fcmReg)
	old := d2.m.st.PushPending.Pending
	d2.m.st.PushPending.StartedAt = d2.m.st.PushPending.StartedAt.Add(-PushChallengeLife)
	r, _ = d2.request(t, "push.register", fcmReg)
	if st, _ := pushState(t, r).String("state"); st != PushStatePending || len(g2.regs) != 2 || d2.m.st.PushPending.Pending == old {
		t.Fatalf("after the window: state %s, %d gateway registrations", st, len(g2.regs))
	}
	if r, _ := d2.request(t, "push.confirm", `{"code":"`+g2.lastCode()+`"}`); r.Error != nil {
		t.Fatalf("new challenge's code: %+v", r.Error)
	}
}
