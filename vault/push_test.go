package vault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/pushwire"
)

// VAULT-MESSAGING 0.24.0 §14: push.register, push.unregister,
// push.token-needed, the wake rules and their outcomes, against a fake
// gateway.

type fakeGW struct {
	mu        sync.Mutex
	regs      []pushwire.Registration
	regKeys   []ed25519.PublicKey
	regErr    error
	wakes     []string // blobs
	wakeKeys  []ed25519.PublicKey
	wakeErrs  []error // answers of the next wakes
	reseal    string
	n         int
	wakeDelay time.Duration
	woke      chan struct{}
}

func newFakeGW() *fakeGW { return &fakeGW{woke: make(chan struct{}, 64)} }

func (g *fakeGW) Register(_ context.Context, k ed25519.PrivateKey, r pushwire.Registration) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.regErr != nil {
		return "", g.regErr
	}
	g.regs = append(g.regs, r)
	g.regKeys = append(g.regKeys, append(ed25519.PublicKey(nil), k.Public().(ed25519.PublicKey)...))
	g.n++
	return "QkxPQi" + strings.Repeat("A", g.n), nil
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
	r, _ := d.request(t, "push.register", fcmReg)
	ps := pushState(t, r)
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
	// A token rotation: a new key and blob replace the old ones.
	old := d.m.st.Push.WakeBlob
	r, _ = d.request(t, "push.register", `{"platform":"fcm","token":"rotated","app_id":"com.vettid.app"}`)
	pushState(t, r)
	if len(g.regs) != 2 || g.regKeys[0].Equal(g.regKeys[1]) || d.m.st.Push.WakeBlob == old {
		t.Fatal("rotation did not replace key and blob")
	}
	// APNs needs its environment.
	r, _ = d.request(t, "push.register", `{"platform":"apns","token":"`+strings.Repeat("0a", 32)+`","app_id":"com.vettid.app","environment":"sandbox"}`)
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
	if c := d.errorCode(t, "push.register", fcmReg); c != "" {
		t.Fatal(c)
	}
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
		if d.m.st.Push == nil || d.m.st.Push.WakeBlob != prev {
			t.Fatal("a failed registration changed the registration")
		}
	}
	g.regErr = nil
}

// §14.1 check 5: 20 registrations that reached the gateway in 24 hours.
func TestPushRegistrationLimit(t *testing.T) {
	d, g := pushFixture(t)
	g.regErr = &pushwire.Error{Status: 403, Code: "attestation_invalid"} // reached: counted
	d.errorCode(t, "push.register", fcmReg)
	g.regErr = pushwire.ErrTransport // never reached: not counted
	d.errorCode(t, "push.register", fcmReg)
	g.regErr = nil
	if n := len(d.m.st.PushRegs); n != 1 {
		t.Fatalf("counted %d", n)
	}
	for i := 1; i < MaxPushRegistrations; i++ {
		if c := d.errorCode(t, "push.register", `{"platform":"fcm","token":"t`+strings.Repeat("x", i)+`","app_id":"a"}`); c != "" {
			t.Fatalf("%d: %s", i, c)
		}
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
	d, _ := pushFixture(t)
	d.m.addFeature(&recSink{})
	r, _ := d.request(t, "push.unregister", `{}`)
	if r.Error != nil || string(r.Body) != `{}` || len(d.audits("push.unregistered")) != 0 {
		t.Fatalf("without a registration: %+v", r)
	}
	if c := d.errorCode(t, "push.unregister", `{"x":1}`); c != "bad_request" {
		t.Fatal(c)
	}
	d.request(t, "push.register", fcmReg)
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
		d, _ := pushFixture(t)
		d.m.addFeature(&recSink{})
		d.request(t, "push.register", fcmReg)
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
	d.request(t, "push.register", fcmReg)
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
	d.request(t, "push.register", fcmReg)
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
	d.request(t, "push.register", fcmReg)
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
	d.request(t, "push.register", fcmReg)
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
			d.request(t, "push.register", `{"platform":"fcm","token":"`+code.code+`","app_id":"com.vettid.app"}`)
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
	d.request(t, "push.register", fcmReg)
	if err := d.m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	if g.wakeCount() != 1 {
		t.Fatalf("host lock: %d wakes", g.wakeCount())
	}

	d, g = pushFixture(t)
	d.request(t, "push.register", fcmReg)
	if err := d.send("vault.lock", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if !d.m.Locked() {
		t.Fatal("not locked")
	}
	g.noWake(t, 0, 100*time.Millisecond)

	// A lock never waits longer than the budget for a slow gateway.
	d, g = pushFixture(t)
	d.request(t, "push.register", fcmReg)
	g.wakeDelay = 5 * time.Second
	start := time.Now()
	_ = d.m.Lock(context.Background())
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("lock took %v", el)
	}
}

// §3.6.3: push.register and push.unregister are on the holder's allow
// list while held, and push.token-needed still reaches the app.
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
