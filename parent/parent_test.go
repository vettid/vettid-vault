package parent_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/hostproto"
	"github.com/vettid/vettid-vault/internal/parenttest"
	"github.com/vettid/vettid-vault/parent"
)

var pcr = strings.Repeat("a3", 48)

const (
	vaultID = "0123456789abcdef0123456789abcdef"
	reqID   = "01JZZZZZZZZZZZZZZZZZZZZZZZ"
)

type harness struct {
	t      *testing.T
	p      *parent.Parent
	objs   *parenttest.Objects
	queues *parenttest.Queues
	tables *parenttest.Tables
	ctl    string
	egress string
	cancel context.CancelFunc
	done   chan struct{}
	logs   *bytes.Buffer
	logMu  sync.Mutex
	queue  string
	echo   string
}

func listen(t *testing.T) net.Listener {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func newHarness(t *testing.T, tweak func(*parent.Config)) *harness {
	h := &harness{t: t, objs: parenttest.NewObjects(), queues: parenttest.NewQueues(), tables: parenttest.NewTables(), logs: &bytes.Buffer{}}
	cl, el := listen(t), listen(t)
	h.ctl, h.egress = cl.Addr().String(), el.Addr().String()
	echo := listen(t)
	h.echo = echo.Addr().String()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	t.Cleanup(func() { echo.Close() })
	cfg := parent.Config{InstanceID: "i-test", QueuePrefix: "test-vault-control-", ControlListener: cl, EgressListener: el,
		Allow: parent.DefaultAllow("relay.example.org", "us-east-1"), Resolve: map[string]string{"relay.example.org": h.echo, "android.googleapis.com": "127.0.0.1:1"},
		Objects: h.objs, Queues: h.queues, Tables: h.tables, Creds: parenttest.StaticCreds{AccessKeyID: "AK", SecretAccessKey: "SK", SessionToken: "ST"},
		Heartbeat: 100 * time.Millisecond, LeaseRenew: 100 * time.Millisecond, LeaseLength: 3 * time.Second, SweepInterval: -1,
		RequestTimeout: 5 * time.Second,
		Logger:         slog.New(slog.NewJSONHandler(lockedWriter{&h.logMu, h.logs}, nil))}
	if tweak != nil {
		tweak(&cfg)
	}
	p, err := parent.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h.p = p
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel, h.done = cancel, make(chan struct{})
	go func() { defer close(h.done); _ = p.Run(ctx) }()
	h.queue = "http://sqs.test/000000000000/test-vault-control-i-test"
	t.Cleanup(h.stop)
	return h
}

type lockedWriter struct {
	mu *sync.Mutex
	w  io.Writer
}

func (l lockedWriter) Write(b []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(b)
}

func (h *harness) stop() {
	if h.cancel != nil {
		h.cancel()
		<-h.done
		h.cancel = nil
	}
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// fakeEnclave is the enclave's side of the control connection.
type fakeEnclave struct {
	conn   *hostproto.Conn
	mu     sync.Mutex
	queued [][]byte
	lost   []string
	answer func(msg []byte) []byte
	shut   int
}

func (h *harness) connect(boot string, answer func([]byte) []byte) *fakeEnclave {
	h.t.Helper()
	c, err := net.Dial("tcp", h.ctl)
	if err != nil {
		h.t.Fatal(err)
	}
	e := &fakeEnclave{answer: answer}
	e.conn = hostproto.NewConn(c, func(_ context.Context, f *hostproto.Frame) [][]byte {
		e.mu.Lock()
		defer e.mu.Unlock()
		switch f.Kind {
		case hostproto.KindQueue:
			e.queued = append(e.queued, f.Fields[0])
			var resp []byte
			if e.answer != nil {
				resp = e.answer(f.Fields[0])
			}
			return [][]byte{[]byte(hostproto.StatusOK), resp}
		case hostproto.KindLeaseLost:
			e.lost = append(e.lost, string(f.Fields[0]))
			return hostproto.Strings(hostproto.StatusOK)
		case hostproto.KindPing:
			return hostproto.Strings(hostproto.StatusOK, "1")
		case hostproto.KindShutdown:
			e.shut++
			return hostproto.Strings(hostproto.StatusOK)
		}
		return nil
	}, nil)
	h.t.Cleanup(e.conn.Close)
	r, err := e.conn.Call(context.Background(), hostproto.KindHello, []byte(pcr), []byte(boot))
	if err != nil || string(r[0]) != hostproto.StatusOK || string(r[1]) != "i-test" {
		h.t.Fatalf("hello: %v %q", err, r)
	}
	return e
}

func (e *fakeEnclave) descriptor() {
	_ = e.conn.Notify(hostproto.KindDescriptor, []byte(pcr), []byte(`{"v":1}`), []byte{1, 2, 3})
}

func (e *fakeEnclave) lifecycle(ev string) {
	_ = e.conn.Notify(hostproto.KindLifecycle, hostproto.Strings(ev, vaultID, pcr, pcr, "1")...)
}

func queueMsg(op, rid string) string {
	return `{"v":1,"op":"` + op + `","vault_id":"` + vaultID + `","user_guid":"u1","request_id":"` + rid + `","enqueued_at":"2026-10-02T12:00:00.000Z"}`
}

func response(rid, status string, env []byte) []byte {
	m := map[string]any{"v": 1, "request_id": rid, "status": status}
	if env != nil {
		m["envelope"] = base64.StdEncoding.EncodeToString(env)
	}
	b, _ := json.Marshal(m)
	return b
}

func TestRegistryAndStore(t *testing.T) {
	h := newHarness(t, nil)
	e := h.connect("boot-1", nil)
	if !h.queues.Exists(h.queue) {
		t.Fatal("queue not created")
	}
	if r, _ := e.conn.Call(context.Background(), hostproto.KindHello, []byte(pcr), []byte("boot-1")); string(r[2]) != "resume" {
		t.Fatalf("second hello: %q", r)
	}
	e.descriptor()
	waitFor(t, "registry row", func() bool { _, ok := h.tables.Instance("i-test"); return ok })
	row, _ := h.tables.Instance("i-test")
	if row.Release != pcr || row.QueueURL != h.queue || string(row.Descriptor) != `{"v":1}` || row.Load != 1 {
		t.Fatalf("registry row %+v", row)
	}
	ctx := context.Background()
	call := func(k hostproto.Kind, f ...string) []string {
		r, err := e.conn.Call(ctx, k, hostproto.Strings(f...)...)
		if err != nil {
			t.Fatal(err)
		}
		out := make([]string, len(r))
		for i, x := range r {
			out[i] = string(x)
		}
		return out
	}
	// Create-only, version-matched, prefixes.
	r := call(hostproto.KindStorePut, "vaults/v/state", "one", "")
	if r[0] != "ok" {
		t.Fatalf("put: %v", r)
	}
	v1 := r[1]
	if r := call(hostproto.KindStorePut, "vaults/v/state", "two", ""); r[0] != "conflict" {
		t.Fatalf("create-only: %v", r)
	}
	if r := call(hostproto.KindStorePut, "vaults/v/state", "two", v1); r[0] != "ok" {
		t.Fatalf("matched put: %v", r)
	}
	if r := call(hostproto.KindStoreGet, "vaults/v/state"); r[0] != "ok" || r[1] != "two" {
		t.Fatalf("get: %v", r)
	}
	for _, k := range []string{"other/x", "vaults/../x", "vaults/A", "vaults//x", ""} {
		if r := call(hostproto.KindStoreGet, k); r[0] != "invalid" {
			t.Errorf("key %q: %v", k, r)
		}
	}
	if r := call(hostproto.KindStoreGet, "users/abc/vault"); r[0] != "not_found" {
		t.Fatalf("missing: %v", r)
	}
	if r := call(hostproto.KindCredentials); r[0] != "ok" || r[1] != "AK" || r[3] != "ST" {
		t.Fatalf("credentials: %v", r)
	}
	// Disconnect withdraws the instance at once.
	e.conn.Close()
	waitFor(t, "registry row removed", func() bool { _, ok := h.tables.Instance("i-test"); return !ok })
	if h.p.Health().Enclave {
		t.Fatal("health still connected")
	}
	// Shutdown deletes the queue.
	h.stop()
	if h.queues.Exists(h.queue) {
		t.Fatal("queue not deleted at shutdown")
	}
}

func TestRequestsAndLeases(t *testing.T) {
	h := newHarness(t, nil)
	h.tables.PutVault(parenttest.VaultRow{VaultID: vaultID, UserGUID: "u1", State: "locked"})
	env := bytes.Repeat([]byte{7}, 5252)
	var e *fakeEnclave
	e = h.connect("boot-1", func(msg []byte) []byte {
		var m struct {
			Op        string `json:"op"`
			RequestID string `json:"request_id"`
		}
		_ = json.Unmarshal(msg, &m)
		switch m.RequestID {
		case "01JAAAAAAAAAAAAAAAAAAAAAAA": // opens the vault
			e.lifecycle("unlocked")
			return response(m.RequestID, "done", env)
		case "01JBBBBBBBBBBBBBBBBBBBBBBB":
			return response(m.RequestID, "etk_unknown", nil)
		case "01JCCCCCCCCCCCCCCCCCCCCCCC": // a refused unlock: the vault stays closed
			return response(m.RequestID, "done", env)
		case "01JDDDDDDDDDDDDDDDDDDDDDDD":
			return nil // unparsable for the enclave
		}
		return response(m.RequestID, "done", nil)
	})
	e.descriptor()
	waitFor(t, "ready", func() bool { return h.p.Health().Release == pcr })

	send := func(op, rid string) parenttest.SlotRow {
		t.Helper()
		h.tables.PutSlot(rid, "i-test")
		h.queues.Send(h.queue, queueMsg(op, rid))
		var s parenttest.SlotRow
		waitFor(t, "slot "+rid, func() bool { s, _ = h.tables.Slot(rid); return s.Status != "queued" })
		return s
	}
	// An unlock that opens the vault: lease taken, slot answered, lifecycle written.
	if s := send("unlock", "01JAAAAAAAAAAAAAAAAAAAAAAA"); s.Status != "done" || len(s.Envelope) != 5252 {
		t.Fatalf("slot %+v", s)
	}
	if r, _ := h.tables.Vault(vaultID); r.LeaseInstance != "i-test" || r.State != "unlocked" {
		t.Fatalf("vault %+v", r)
	}
	// The lease is renewed while the vault runs.
	r0, _ := h.tables.Vault(vaultID)
	waitFor(t, "renewal", func() bool { r, _ := h.tables.Vault(vaultID); return r.LeaseExpires > r0.LeaseExpires })
	// etk_unknown becomes a host code without an envelope.
	if s := send("unlock", "01JBBBBBBBBBBBBBBBBBBBBBBB"); s.Status != "done" || s.Code != "etk_unknown" || s.Envelope != nil {
		t.Fatalf("etk_unknown slot %+v", s)
	}
	// A message the enclave could not parse expires.
	if s := send("unlock", "01JDDDDDDDDDDDDDDDDDDDDDDD"); s.Status != "expired" {
		t.Fatalf("unparsable slot %+v", s)
	}
	waitFor(t, "queue drained", func() bool { return h.queues.Pending(h.queue) == 0 })

	// Lock: the lifecycle event releases the lease.
	e.lifecycle("locked")
	waitFor(t, "lease released", func() bool { r, _ := h.tables.Vault(vaultID); return r.LeaseInstance == "" && r.State == "locked" })
	// A refused unlock (the vault does not open) gives the lease back.
	send("unlock", "01JCCCCCCCCCCCCCCCCCCCCCCC")
	waitFor(t, "lease returned", func() bool { r, _ := h.tables.Vault(vaultID); return r.LeaseInstance == "" })

	// A lease held by another live instance: the request expires without
	// reaching the enclave.
	h.tables.SetLease(vaultID, "i-other", time.Now().Add(time.Minute).Unix())
	n := len(e.queued)
	if s := send("unlock", "01JEEEEEEEEEEEEEEEEEEEEEEE"); s.Status != "expired" {
		t.Fatalf("foreign lease slot %+v", s)
	}
	if len(e.queued) != n {
		t.Fatal("request forwarded despite a foreign lease")
	}

	// Lease lost: another instance takes the lease of a running vault.
	h.tables.SetLease(vaultID, "", 0)
	send("unlock", "01JAAAAAAAAAAAAAAAAAAAAAAA")
	waitFor(t, "running", func() bool { return len(h.p.RunningVaults()) == 1 })
	h.tables.SetLease(vaultID, "i-other", time.Now().Add(time.Minute).Unix())
	waitFor(t, "lease lost", func() bool { e.mu.Lock(); defer e.mu.Unlock(); return len(e.lost) == 1 && e.lost[0] == vaultID })
	if len(h.p.RunningVaults()) != 0 || h.p.Health().LeasesLost != 1 {
		t.Fatalf("health after lease loss %+v", h.p.Health())
	}
	// The loser's lifecycle event does not overwrite the holder's row.
	e.lifecycle("locked")
	time.Sleep(200 * time.Millisecond)
	if r, _ := h.tables.Vault(vaultID); r.LeaseInstance != "i-other" {
		t.Fatalf("loser released the winner's lease: %+v", r)
	}
	// No envelope bytes in the logs.
	h.logMu.Lock()
	logs := h.logs.String()
	h.logMu.Unlock()
	if strings.Contains(logs, base64.StdEncoding.EncodeToString(env[:30])) {
		t.Fatal("envelope logged")
	}
}

func TestEnclaveRestartReleasesLeases(t *testing.T) {
	h := newHarness(t, nil)
	h.tables.PutVault(parenttest.VaultRow{VaultID: vaultID, UserGUID: "u1"})
	e := h.connect("boot-1", nil)
	e.descriptor()
	h.tables.SetLease(vaultID, "i-test", time.Now().Add(time.Minute).Unix())
	e.lifecycle("unlocked")
	waitFor(t, "running", func() bool { return len(h.p.RunningVaults()) == 1 })
	e.conn.Close()
	// The enclave comes back with another boot id: its vaults are gone.
	e2 := h.connect("boot-2", nil)
	_ = e2
	waitFor(t, "lease released", func() bool { r, _ := h.tables.Vault(vaultID); return r.LeaseInstance == "" })
	if len(h.p.RunningVaults()) != 0 {
		t.Fatal("stale running set")
	}
}

func TestFreshParentLocksVaults(t *testing.T) {
	h := newHarness(t, nil)
	c, err := net.Dial("tcp", h.ctl)
	if err != nil {
		t.Fatal(err)
	}
	conn := hostproto.NewConn(c, nil, nil)
	defer conn.Close()
	r, err := conn.Call(context.Background(), hostproto.KindHello, []byte(pcr), []byte("boot-1"))
	if err != nil || string(r[2]) != "fresh" {
		t.Fatalf("hello to a fresh parent: %q %v", r, err)
	}
	// Bad hellos are refused.
	if r, _ := conn.Call(context.Background(), hostproto.KindHello, []byte("zz"), []byte("b")); string(r[0]) != hostproto.StatusInvalid {
		t.Fatalf("bad hello: %q", r)
	}
}

func TestForwarder(t *testing.T) {
	h := newHarness(t, nil)
	dial := func(host string, port uint16) (net.Conn, error) {
		c, err := net.Dial("tcp", h.egress)
		if err != nil {
			return nil, err
		}
		if err := hostproto.OpenEgress(c, host, port); err != nil {
			c.Close()
			return nil, err
		}
		return c, nil
	}
	c, err := dial("relay.example.org", 443)
	if err != nil {
		t.Fatal(err)
	}
	msg := bytes.Repeat([]byte("x"), 100_000)
	go func() { _, _ = c.Write(msg) }()
	got := make([]byte, len(msg))
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("splice: %v", err)
	}
	c.Close()
	for _, d := range []struct {
		host string
		port uint16
	}{{"relay.example.org", 80}, {"evil.example.org", 443}, {"kms.eu-west-1.amazonaws.com", 443}} {
		if _, err := dial(d.host, d.port); err != hostproto.ErrEgressRefused {
			t.Errorf("%s:%d: %v", d.host, d.port, err)
		}
	}
	// Allowed but unreachable.
	if _, err := dial("android.googleapis.com", 443); err != hostproto.ErrEgressFailed {
		t.Errorf("unreachable host: %v", err)
	}
}

func TestConfig(t *testing.T) {
	if _, err := parent.New(parent.Config{InstanceID: "bad id"}); err == nil {
		t.Fatal("bad instance id")
	}
	if _, err := parent.New(parent.Config{InstanceID: "ok", QueuePrefix: "p-", Allow: []string{"Not A Host"}}); err == nil {
		t.Fatal("bad host")
	}
}
