//go:build devenclave && e2e

package e2e

import (
	"context"
	"crypto/ecdh"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/client"
	"github.com/vettid/vettid-vault/enclave"
	"github.com/vettid/vettid-vault/enclave/awskms"
	"github.com/vettid/vettid-vault/enclave/supervisor"
	"github.com/vettid/vettid-vault/enclave/vaultproc"
	"github.com/vettid/vettid-vault/internal/enclavetest"
	"github.com/vettid/vettid-vault/internal/parenttest"
	"github.com/vettid/vettid-vault/internal/relaytest"
	"github.com/vettid/vettid-vault/internal/selftest"
	"github.com/vettid/vettid-vault/parent"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/altchan"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// The host stack in process (VAULT-PLAN V3): parent (in-memory AWS
// backends) and supervisor (dev build: fake NSM, test roots) talking over
// TCP; the enclave's TLS, egress and SigV4 KMS client run unchanged
// against a TLS front of the real relay and a fake KMS endpoint. The
// LocalStack run is ./integration.
const hostRelay = "https://relay.vettid.test"

type hostStack struct {
	t       *testing.T
	encBin  string
	w       *enclavetest.World
	objs    *parenttest.Objects
	queues  *parenttest.Queues
	tables  *parenttest.Tables
	resolve map[string]string
	appHTTP *http.Client
	// recClock, if set, is the enclave's recovery clock file
	// (enclavetest.DevRecoveryClock), for instances started after it is set.
	recClock string
}

type hostInstance struct {
	encBin   string
	id       string
	p        *parent.Parent
	sup      *supervisor.Supervisor
	in       chan *enclave.Instance
	stopP    context.CancelFunc
	stopS    context.CancelFunc
	pdone    chan struct{}
	sdone    chan struct{}
	ctl      string
	egr      string
	queue    string
	release  uint64
	recClock string
}

func tlsFront(t *testing.T, h http.Handler, h2 bool, name string) string {
	s := httptest.NewUnstartedServer(h)
	s.EnableHTTP2 = h2
	s.TLS = &tls.Config{Certificates: []tls.Certificate{enclavetest.ServerCert(name)}}
	s.Config.ErrorLog = log.New(io.Discard, "", 0)
	s.StartTLS()
	t.Cleanup(s.Close)
	return s.Listener.Addr().String()
}

func newHostStack(t *testing.T) *hostStack {
	hs := &hostStack{t: t, objs: parenttest.NewObjects(), queues: parenttest.NewQueues(), tables: parenttest.NewTables(), resolve: map[string]string{}}
	// Vault processes are the dev enclave binary re-executed (D4).
	hs.encBin = filepath.Join(t.TempDir(), "vault-enclave")
	if out, err := exec.Command("go", "build", "-tags", "devenclave", "-o", hs.encBin, "../cmd/vault-enclave").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	hs.w = enclavetest.NewWorld(time.Now, hostRelay)
	hs.w.AddRelease(enclavetest.Spec(3, "active"))
	r := relaytest.Start(t, relaytest.Options{"RELAY_BASE_URL": hostRelay})
	target, _ := url.Parse(r.URL)
	hs.resolve["relay.vettid.test"] = tlsFront(t, &httputil.ReverseProxy{Rewrite: func(p *httputil.ProxyRequest) { p.SetURL(target); p.Out.Host = p.In.Host },
		FlushInterval: -1, ErrorLog: log.New(io.Discard, "", 0)}, true, "relay.vettid.test")
	kms := enclavetest.NewKMSServer(hs.w.KMS, enclavetest.KMSRegion, awskms.Credentials{AccessKeyID: "AK", SecretAccessKey: "SK", SessionToken: "ST"})
	hs.resolve["kms.us-east-1.amazonaws.com"] = tlsFront(t, kms, false, "kms.us-east-1.amazonaws.com")
	hs.resolve["android.googleapis.com"] = tlsFront(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"entries":{}}`)
	}), true, "android.googleapis.com")
	roots := x509.NewCertPool()
	roots.AddCert(enclavetest.TestTLSCA().Cert)
	relayAddr := hs.resolve["relay.vettid.test"]
	hs.appHTTP = &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}, ForceAttemptHTTP2: true,
		DialContext: func(ctx context.Context, n, a string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, n, relayAddr)
		}}}
	return hs
}

func listenTCP(t *testing.T) net.Listener {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// start runs a parent and a supervisor of release n.
func (hs *hostStack) start(id string, n uint64, maxVaults int) *hostInstance {
	t := hs.t
	cl, el := listenTCP(t), listenTCP(t)
	hi := &hostInstance{encBin: hs.encBin, id: id, ctl: cl.Addr().String(), egr: el.Addr().String(), release: n, recClock: hs.recClock,
		queue: "http://sqs.test/000000000000/test-vault-control-" + id, in: make(chan *enclave.Instance, 4)}
	p, err := parent.New(parent.Config{InstanceID: id, QueuePrefix: "test-vault-control-", ControlListener: cl, EgressListener: el,
		Allow: parent.DefaultAllow("relay.vettid.test", "us-east-1"), Resolve: hs.resolve,
		Objects: hs.objs, Queues: hs.queues, Tables: hs.tables, Creds: parenttest.StaticCreds{AccessKeyID: "AK", SecretAccessKey: "SK", SessionToken: "ST"},
		Heartbeat: 200 * time.Millisecond, LeaseRenew: 300 * time.Millisecond, SweepInterval: -1,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	hi.p = p
	pctx, pcancel := context.WithCancel(context.Background())
	hi.stopP, hi.pdone = pcancel, make(chan struct{})
	go func() { defer close(hi.pdone); _ = p.Run(pctx) }()
	hi.startEnclave(t, maxVaults)
	t.Cleanup(hi.stop)
	deadline := time.Now().Add(30 * time.Second)
	for !p.Health().OK {
		if time.Now().After(deadline) {
			t.Fatalf("instance %s not healthy: %+v", id, p.Health())
		}
		time.Sleep(50 * time.Millisecond)
	}
	return hi
}

func (hi *hostInstance) startEnclave(t *testing.T, maxVaults int) {
	cfg, err := enclavetest.DevSupervisor(enclavetest.DevOptions{Release: hi.release, Control: hi.ctl, Egress: hi.egr, RelayURL: hostRelay,
		VaultExec: append(append([]string{hi.encBin, vaultproc.Arg}, enclavetest.DevVaultArgs(hi.release, hostRelay)...),
			enclavetest.DevVaultRecoveryClockArgs(hi.recClock)...),
		RecoveryClock: hi.recClock, MaxVaults: maxVaults, LogLevel: slog.LevelError, OnReady: func(in *enclave.Instance) { hi.in <- in }})
	if err != nil {
		t.Fatal(err)
	}
	s, err := supervisor.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	hi.sup = s
	sctx, scancel := context.WithCancel(context.Background())
	hi.stopS, hi.sdone = scancel, make(chan struct{})
	go func() { defer close(hi.sdone); _ = s.Run(sctx) }()
}

func (hi *hostInstance) stopEnclave() {
	if hi.stopS != nil {
		hi.stopS()
		<-hi.sdone
		hi.stopS = nil
	}
}

func (hi *hostInstance) stop() {
	if hi.stopP != nil {
		hi.stopP()
		<-hi.pdone
		hi.stopP = nil
	}
	hi.stopEnclave()
}

// --- the member API's part, over the in-memory tables ---

type hostApp struct {
	hs   *hostStack
	guid string
	dev  *client.Device
	att  client.Attester
}

func (hs *hostStack) newApp(guid string, seed byte) *hostApp {
	ctx := ctxT(hs.t, 30*time.Second)
	t := hs.w.Trust()
	d, err := client.New(ctx, client.Config{Role: vault.KindApp, Name: guid, RelayURL: hostRelay, HTTP: hs.appHTTP, PollWait: time.Second, Trust: &t})
	if err != nil {
		hs.t.Fatal(err)
	}
	return &hostApp{hs: hs, guid: guid, dev: d, att: enclavetest.NewAndroidAttester(seed, enclavetest.AndroidOptions{})}
}

// post sends a sealed request to an instance's queue as the API would and
// waits for its slot.
func (hs *hostStack) post(hi *hostInstance, op, vaultID, guid string, r *client.Request) parenttest.SlotRow {
	hs.t.Helper()
	hs.tables.PutSlot(r.RequestID, hi.id)
	m := map[string]any{"v": 1, "op": op, "vault_id": vaultID, "user_guid": guid, "request_id": r.RequestID,
		"etk_kid": r.ETKKid, "envelope": r.Envelope, "enqueued_at": time.Now().UTC().Format(time.RFC3339Nano)}
	if op == "enroll" || op == "unlock" {
		// 0.10.0: the request names its manifest by hash; the publish
		// step has put the document in the bucket, where the parent
		// reads it.
		m["manifest_sha256"] = r.ManifestSHA256
		if doc := hs.w.ManifestDoc(r.ManifestSHA256); doc != nil {
			_, _ = hs.objs.Put(context.Background(), "manifests/"+r.ManifestSHA256+".json", doc, "")
		}
	}
	if op == "enroll" || op == "recovery_register" {
		m["app_key"] = r.AppKey // 0.15.0: the key the API checked the signature with
	}
	b, _ := json.Marshal(m)
	if !hs.queues.Send(hi.queue, string(b)) {
		hs.t.Fatal("no queue")
	}
	return hs.waitSlot(r.RequestID)
}

func (hs *hostStack) waitSlot(rid string) parenttest.SlotRow {
	hs.t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for {
		if s, _ := hs.tables.Slot(rid); s.Status != "queued" {
			return s
		}
		if time.Now().After(deadline) {
			hs.t.Fatalf("slot %s not answered", rid)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (hs *hostStack) enclaveOf(hi *hostInstance, d *client.Device, enroll bool) (*client.Enclave, []byte) {
	hs.t.Helper()
	row, ok := hs.tables.Instance(hi.id)
	if !ok {
		hs.t.Fatal("instance not registered")
	}
	_, m, err := d.VerifyManifest(hs.w.Served(), hs.w.Trust())
	if err != nil {
		hs.t.Fatal(err)
	}
	e, err := client.VerifyEnclave(row.Descriptor, row.Attestation, m, enroll, hs.w.Trust(), time.Now())
	if err != nil {
		hs.t.Fatalf("descriptor: %v", err)
	}
	return e, hs.w.Served()
}

func (a *hostApp) enroll(hi *hostInstance, vaultID string) {
	hs := a.hs
	hs.t.Helper()
	hs.tables.PutVault(parenttest.VaultRow{VaultID: vaultID, UserGUID: a.guid, State: "enrolling"})
	e, raw := hs.enclaveOf(hi, a.dev, true)
	_, m, err := a.dev.VerifyManifest(raw, hs.w.Trust())
	if err != nil {
		hs.t.Fatal(err)
	}
	req, err := a.dev.BuildEnroll(a.guid, pin, e, m, a.att)
	if err != nil {
		hs.t.Fatal(err)
	}
	s := hs.post(hi, enclave.OpEnroll, vaultID, a.guid, req)
	r, err := a.dev.OpenEnrollResult(s.Envelope, req.RequestID)
	if err != nil || !r.OK {
		hs.t.Fatalf("enroll: %v %+v", err, r)
	}
	ctx := ctxT(hs.t, 60*time.Second)
	if err := a.dev.AwaitEnrolled(ctx); err != nil {
		hs.t.Fatal(err)
	}
	if err := a.dev.CompleteEnrollment(ctx); err != nil {
		hs.t.Fatal(err)
	}
	if err := a.dev.CredentialCreate(ctx, credPW); err != nil {
		hs.t.Fatalf("credential.create: %v", err)
	}
	if rr, err := a.dev.Request(ctx, "vault.enroll.confirm", json.RawMessage(`{}`)); err != nil || !rr.OK() {
		hs.t.Fatalf("confirm: %v", err)
	}
}

func (a *hostApp) unlock(hi *hostInstance) (*client.UnlockOutcome, parenttest.SlotRow) {
	hs := a.hs
	hs.t.Helper()
	e, raw := hs.enclaveOf(hi, a.dev, false)
	_, m, err := a.dev.VerifyManifest(raw, hs.w.Trust())
	if err != nil {
		hs.t.Fatal(err)
	}
	req, err := a.dev.BuildUnlock(a.guid, pin, e, m, a.att, client.UnlockOptions{})
	if err != nil {
		hs.t.Fatal(err)
	}
	s := hs.post(hi, enclave.OpUnlock, a.dev.VaultID(), a.guid, req)
	if s.Code != "" {
		return &client.UnlockOutcome{Code: s.Code}, s
	}
	r, err := a.dev.OpenUnlockResult(s.Envelope)
	if err != nil {
		hs.t.Fatalf("unlock result: %v", err)
	}
	return &client.UnlockOutcome{OK: r.OK, Code: r.Code}, s
}

func (a *hostApp) lock(hi *hostInstance) {
	rid, _ := envelope.NewULID(time.Now())
	a.hs.tables.PutSlot(rid, hi.id)
	b, _ := json.Marshal(map[string]any{"v": 1, "op": "lock", "vault_id": a.dev.VaultID(), "user_guid": a.guid, "request_id": rid,
		"enqueued_at": time.Now().UTC().Format(time.RFC3339Nano)})
	a.hs.queues.Send(hi.queue, string(b))
	if s := a.hs.waitSlot(rid); s.Status != "done" {
		a.hs.t.Fatalf("lock slot %+v", s)
	}
}

func (a *hostApp) status() bool {
	r, err := a.dev.Request(ctxT(a.hs.t, 30*time.Second), "vault.status", json.RawMessage(`{}`))
	return err == nil && r.OK()
}

func waitUntil(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestHostStack(t *testing.T) {
	base := vault.Unlocked() // managers other tests left in this process
	hs := newHostStack(t)
	a := hs.start("i-a", 3, 1) // at most one running vault

	m1 := hs.newApp("member-1", 0x61)
	m1.enroll(a, "11111111111111111111111111111111")
	if !m1.status() {
		t.Fatal("vault.status through the enclave's TLS egress")
	}
	// The vault runs in its own process: the supervisor (this test
	// process) holds no manager and no DEK (§12.4).
	pid1 := a.sup.VaultPid("11111111111111111111111111111111")
	if pid1 == 0 || pid1 == os.Getpid() || vault.Unlocked() != base {
		t.Fatalf("vault process %d; DEK-holding managers in the supervisor: %d", pid1, vault.Unlocked()-base)
	}
	if r, _ := hs.tables.Vault("11111111111111111111111111111111"); r.LeaseInstance != "i-a" || r.State != "unlocked" {
		t.Fatalf("row %+v", r)
	}
	// State and header live in the bucket under vaults/<id>/.
	keys := strings.Join(hs.objs.Keys(), " ")
	if !strings.Contains(keys, "vaults/11111111111111111111111111111111/state") || !strings.Contains(keys, "vaults/11111111111111111111111111111111/header/") {
		t.Fatalf("objects %s", keys)
	}

	// 0.15.0 (§11.5): the parent wrote the app key the enclave reported.
	_, akDER, _ := m1.dev.AppKey()
	if r, _ := hs.tables.Vault("11111111111111111111111111111111"); r.AppKeyID != parent.AppKeyID(akDER) || r.AppKeySeq != 1 {
		t.Fatalf("app key on the row: %+v", r)
	}
	// §11.13: the queue op account reaches the vault's process.
	rid, _ := envelope.NewULID(time.Now())
	hs.tables.PutSlot(rid, a.id)
	acct := `{"v":1,"as_of":"` + envelope.FormatTS(time.Now()) + `","email_hint":"m***@example.org","state":"member"}`
	b, _ := json.Marshal(map[string]any{"v": 1, "op": "account", "vault_id": "11111111111111111111111111111111", "user_guid": "member-1",
		"request_id": rid, "account": json.RawMessage(acct), "enqueued_at": time.Now().UTC().Format(time.RFC3339Nano)})
	hs.queues.Send(a.queue, string(b))
	if s := hs.waitSlot(rid); s.Status != "done" || s.Envelope != nil {
		t.Fatalf("account slot %+v", s)
	}
	if _, err := m1.dev.WaitEvent(ctxT(t, 30*time.Second), "sync.event", func(b json.RawMessage) bool {
		return strings.Contains(string(b), `"account.changed"`)
	}); err != nil {
		t.Fatal(err)
	}
	if r, err := m1.dev.Request(ctxT(t, 30*time.Second), "account.get", json.RawMessage(`{}`)); err != nil || !strings.Contains(string(r.Body()), `"email_hint":"m***@example.org"`) {
		t.Fatalf("account.get: %v", err)
	}

	// Lock and unlock again; the lock ends the vault's process.
	m1.lock(a)
	waitUntil(t, "lock", func() bool { return len(a.p.RunningVaults()) == 0 })
	waitUntil(t, "vault process exited", func() bool { return syscall.Kill(pid1, 0) != nil })
	if u, _ := m1.unlock(a); !u.OK {
		t.Fatalf("unlock: %+v", u)
	}
	if !m1.status() {
		t.Fatal("status after unlock")
	}
	// The member's own lock (vault.lock from the app): the vault process
	// ends by itself, and its lifecycle "locked" reaches the parent before
	// the process's channel closes; the row says locked.
	pid1 = a.sup.VaultPid("11111111111111111111111111111111")
	nev := len(hs.tables.LifecycleEvents("11111111111111111111111111111111"))
	if r, err := m1.dev.Request(ctxT(t, 30*time.Second), "vault.lock", json.RawMessage(`{}`)); err != nil || !r.OK() {
		t.Fatalf("vault.lock: %+v %v", r, err)
	}
	waitUntil(t, "app lock", func() bool { return len(a.p.RunningVaults()) == 0 })
	waitUntil(t, "vault process exited after the app lock", func() bool { return syscall.Kill(pid1, 0) != nil })
	waitUntil(t, "lifecycle locked", func() bool {
		ev := hs.tables.LifecycleEvents("11111111111111111111111111111111")
		return len(ev) > nev && slices.Contains(ev[nev:], "locked")
	})
	waitUntil(t, "row locked", func() bool {
		r, _ := hs.tables.Vault("11111111111111111111111111111111")
		return r.State == "locked" && r.LeaseInstance == ""
	})
	if u, _ := m1.unlock(a); !u.OK {
		t.Fatalf("unlock after the app lock: %+v", u)
	}
	if !m1.status() {
		t.Fatal("status after unlock")
	}

	// Vault cap (§12.3 memory pressure): a second vault evicts the least
	// recently active one, which locks like an owner request.
	m2 := hs.newApp("member-2", 0x62)
	m2.enroll(a, "22222222222222222222222222222222")
	waitUntil(t, "eviction", func() bool {
		r, _ := hs.tables.Vault("11111111111111111111111111111111")
		return r.State == "locked" && r.LeaseInstance == ""
	})
	if got := a.p.RunningVaults(); len(got) != 1 || got[0] != "22222222222222222222222222222222" {
		t.Fatalf("running %v", got)
	}

	// An unknown ETK (a request sealed to a descriptor of a previous
	// enclave run) gets the etk_unknown host code; after the enclave
	// restarts, the parent releases the leases its vaults held.
	e, raw := hs.enclaveOf(a, m1.dev, false)
	a.stopEnclave()
	waitUntil(t, "registry withdrawn", func() bool { _, ok := hs.tables.Instance("i-a"); return !ok })
	a.startEnclave(t, 1)
	waitUntil(t, "lease released after the enclave restart", func() bool {
		r, _ := hs.tables.Vault("22222222222222222222222222222222")
		return r.LeaseInstance == ""
	})
	waitUntil(t, "re-registered", func() bool { return a.p.Health().OK })
	_, m, _ := m1.dev.VerifyManifest(raw, hs.w.Trust())
	req, err := m1.dev.BuildUnlock(m1.guid, pin, e, m, m1.att, client.UnlockOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if s := hs.post(a, enclave.OpUnlock, m1.dev.VaultID(), m1.guid, req); s.Status != "done" || s.Code != "etk_unknown" || len(s.Envelope) != 0 {
		t.Fatalf("stale ETK slot %+v", s)
	}
	if u, _ := m1.unlock(a); !u.OK {
		t.Fatalf("unlock after the restart: %+v", u)
	}
	if !m1.status() {
		t.Fatal("status after the restart")
	}

	// A parent shutdown (§12.3 "if signalled") locks the enclave's vaults
	// and withdraws the instance and its queue.
	a.stopP()
	<-a.pdone
	a.stopP = nil
	if r, _ := hs.tables.Vault("11111111111111111111111111111111"); r.State != "locked" || r.LeaseInstance != "" {
		t.Fatalf("row after the parent shutdown %+v", r)
	}
	if hs.queues.Exists(a.queue) {
		t.Fatal("queue left behind")
	}
}

// Killing one vault's process leaves the others running, and is reported
// to the parent (the lease goes back).
func TestVaultProcessIsolation(t *testing.T) {
	base := vault.Unlocked()
	hs := newHostStack(t)
	a := hs.start("i-a", 3, 0)
	m1 := hs.newApp("member-1", 0x61)
	m1.enroll(a, "11111111111111111111111111111111")
	m2 := hs.newApp("member-2", 0x62)
	m2.enroll(a, "22222222222222222222222222222222")
	p1, p2 := a.sup.VaultPid("11111111111111111111111111111111"), a.sup.VaultPid("22222222222222222222222222222222")
	if p1 == 0 || p2 == 0 || p1 == p2 {
		t.Fatalf("pids %d %d", p1, p2)
	}
	if vault.Unlocked() != base {
		t.Fatal("a DEK in the supervisor")
	}
	// Vault processes are not dumpable: even their own user cannot read
	// their memory or environment through /proc.
	for _, pid := range []int{p1, p2} {
		if _, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/environ"); err == nil {
			t.Fatalf("vault process %d is dumpable", pid)
		}
	}
	if !a.sup.KillVault("11111111111111111111111111111111") {
		t.Fatal("kill")
	}
	if !m2.status() {
		t.Fatal("the other vault stopped with the killed one")
	}
	if a.sup.VaultPid("22222222222222222222222222222222") != p2 {
		t.Fatal("the other vault's process changed")
	}
	// The killed vault opens again in a new process.
	if u, _ := m1.unlock(a); !u.OK {
		t.Fatalf("unlock after kill: %+v", u)
	}
	if !m1.status() {
		t.Fatal("status after kill")
	}
}

type selftestResult struct {
	rep *selftest.Report
	err error
}

// runSelftestE2E runs the self-test (parent, dev supervisor, re-executed
// vault processes) against the fake KMS with a deletable-style test key.
func runSelftestE2E(t *testing.T, capacity *selftest.CapacityRequest) (*hostStack, *selftest.Report) {
	t.Helper()
	hs := newHostStack(t)
	arn := enclavetest.KeyARN(9)
	admin := `{"Sid":"Admin","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::` + enclavetest.KMSAccount + `:root"},"Action":"kms:*","Resource":"*"}`
	pcr0 := enclavetest.Spec(3, "").PCR0Hex()
	good := enclavetest.GoodPolicy(pcr0, []string{pcr0})
	hs.w.KMS.AddKey(arn, good[:len(good)-2]+","+admin+"]}")

	cl, el := listenTCP(t), listenTCP(t)
	ctx := ctxT(t, 5*time.Minute)
	done := make(chan selftestResult, 1)
	go func() {
		rep, err := parent.RunSelftest(ctx, parent.SelftestConfig{ControlListener: cl, EgressListener: el,
			Allow: parent.DefaultAllow("relay.vettid.test", enclavetest.KMSRegion), Resolve: hs.resolve, Objects: hs.objs,
			Creds:   parenttest.StaticCreds{AccessKeyID: "AK", SecretAccessKey: "SK", SessionToken: "ST"},
			Request: selftest.Request{RunID: "run-1", KeyARN: arn, Account: enclavetest.KMSAccount, Region: enclavetest.KMSRegion, Capacity: capacity},
			Logger:  slog.New(slog.NewTextHandler(io.Discard, nil))})
		done <- selftestResult{rep, err}
	}()
	cfg, err := enclavetest.DevSupervisor(enclavetest.DevOptions{Release: 3, Control: cl.Addr().String(), Egress: el.Addr().String(),
		RelayURL: hostRelay, LogLevel: slog.LevelError,
		VaultExec: append([]string{hs.encBin, vaultproc.Arg}, enclavetest.DevVaultArgs(3, hostRelay)...)})
	if err != nil {
		t.Fatal(err)
	}
	cfg.Harden = true // as the binaries do (this test process becomes non-dumpable)
	sup, err := supervisor.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := sup.Run(ctx); err != nil {
		t.Fatalf("supervisor: %v", err)
	}
	r := <-done
	if r.err != nil {
		t.Fatal(r.err)
	}
	return hs, r.rep
}

// The capacity measurement off hardware, with a tiny N (docs/SMOKE.md):
// synthetic vault processes spawned like real ones, unlock latency,
// steady state, teardown; the rest of the self-test still passes.
func TestSelftestCapacity(t *testing.T) {
	_, rep := runSelftestE2E(t, &selftest.CapacityRequest{MaxVaults: 3, StateKiB: 256, UnlockConcurrency: []int{1, 2}, UnlockSamples: 2,
		SettleSeconds: 1, IdleSeconds: 2, StepEvery: 1})
	c := rep.Capacity
	if c == nil {
		t.Fatal("no capacity section")
	}
	for _, l := range c.Lines() {
		t.Log(l)
	}
	if bad := parent.SelftestVerdict(rep, 6); len(bad) != 0 {
		t.Fatalf("unexpected: %v", bad)
	}
	if c.Held != 3 || c.StopReason != "max_vaults" || !c.TornDown {
		t.Fatalf("held %d stop %s torn down %v notes %v", c.Held, c.StopReason, c.TornDown, c.Notes)
	}
	if len(c.Unlock) != 2 || c.Unlock[0].Samples != 2 || c.Unlock[1].Samples != 2 || c.Unlock[0].KDFP50Ms <= 0 || c.Unlock[1].P50Ms < c.Unlock[1].KDFP50Ms {
		t.Fatalf("unlock %+v", c.Unlock)
	}
	if c.VaultRSS.N != 3 || c.VaultRSS.Mean == 0 || c.VaultPeakRSS < 64<<20 || c.MemTotal == 0 || c.FloorBytes < c.MemTotal*15/100 ||
		c.BaselineSupervisorRSS == 0 || len(c.Steps) < 4 {
		t.Fatalf("report %+v", c)
	}
	ok := map[string]bool{}
	for _, ch := range rep.Checks {
		ok[ch.Name] = ch.OK
	}
	if !ok["capacity.measured"] || !ok["capacity.torn_down"] || !ok["capacity.unlock_latency"] {
		t.Fatalf("checks %+v", rep.Checks)
	}
}

// The hardware smoke test's plumbing off hardware (docs/SMOKE.md): the
// parent in self-test mode, the dev supervisor and a re-executed vault
// process, against the fake KMS with a deletable-style test key whose
// admin statement the §11.10.7 check must refuse (check 6).
func TestSelftest(t *testing.T) {
	hs, rep := runSelftestE2E(t, nil)
	for _, c := range rep.Checks {
		t.Logf("%v %v %s %s", c.OK, c.Required, c.Name, c.Detail)
	}
	if bad := parent.SelftestVerdict(rep, 6); len(bad) != 0 {
		t.Fatalf("unexpected: %v", bad)
	}
	if rep.Capacity != nil {
		t.Fatal("capacity measured without being asked")
	}
	want := map[string]bool{}
	for _, c := range rep.Checks {
		want[c.Name] = c.OK
	}
	for _, n := range []string{"nsm.attestation_verifies", "egress.relay_healthz", "egress.relay_http2", "egress.google_status_list",
		"kms.policy_check_rejects_test_key", "kms.policy_check_passes_without_admin", "vault_process.kms_recipient_round_trip",
		"vault_process.seccomp_refuses_socket_vsock", "vault_process.not_dumpable", "s3.stale_if_match_refused", "vault_process.argon2id_default"} {
		if !want[n] {
			t.Errorf("%s not OK", n)
		}
	}
	if rep.PCR0 != enclavetest.Spec(3, "").PCR0Hex() || rep.VaultPeakRSS < 64<<20 {
		t.Fatalf("pcr0 %s, vault peak RSS %d", rep.PCR0, rep.VaultPeakRSS)
	}
	// The report carries no secret: no credentials, nothing key-sized in base64.
	b, _ := json.Marshal(rep)
	if strings.Contains(string(b), "SK") && strings.Contains(string(b), `"SK"`) {
		t.Fatal("credentials in the report")
	}
	// Only smoke/<run_id>/ was touched; the object was deleted again.
	for _, k := range hs.objs.Keys() {
		t.Fatalf("object left behind: %s", k)
	}
}

// §11.11 through the parent and a vault process: the request locks the
// running vault (vault.locking{recovery} over the process channel), the
// code comes back sealed to the browser key in the response slot, a
// register before the delay is refused, the cancel clears the recovery.
func TestHostRecovery(t *testing.T) {
	hs := newHostStack(t)
	hs.recClock = filepath.Join(t.TempDir(), "recovery-clock")
	if err := os.WriteFile(hs.recClock, []byte("0s"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := hs.start("i-r", 3, 0)
	m := hs.newApp("member-rec", 0x6a)
	vid := "33333333333333333333333333333333"
	m.enroll(a, vid)
	bk, err := ecdh.P256().GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	type slot struct {
		parenttest.SlotRow
		RequestID string
	}
	send := func(op string, extra map[string]any) slot {
		rid, _ := envelope.NewULID(time.Now())
		hs.tables.PutSlot(rid, a.id)
		msg := map[string]any{"v": 1, "op": op, "vault_id": vid, "user_guid": m.guid, "request_id": rid,
			"enqueued_at": time.Now().UTC().Format(time.RFC3339Nano)}
		for k, v := range extra {
			msg[k] = v
		}
		b, _ := json.Marshal(msg)
		hs.queues.Send(a.queue, string(b))
		return slot{hs.waitSlot(rid), rid}
	}
	s := send("recovery", map[string]any{"browser_key": bk.PublicKey().Bytes()})
	if s.Status != "done" || len(s.Envelope) != altchan.ResultEnvelopeSize {
		t.Fatalf("recovery slot %+v", s)
	}
	code, err := altchan.OpenRecoveryCode(bk, s.Envelope, vid, s.RequestID)
	if err != nil {
		t.Fatalf("sealed code: %v", err)
	}
	waitEvent(t, m.dev, "vault.locking", has("reason", "recovery"))
	if u, _ := m.unlock(a); u.OK || u.Code != vault.CodeRecoveryPending {
		t.Fatalf("unlock during recovery: %+v", u)
	}
	// A new app before the 24 h delay.
	n := hs.newApp(m.guid, 0x6b)
	e, _ := hs.enclaveOf(a, n.dev, false)
	req, err := n.dev.BuildRecoveryRegister(n.guid, code, e, n.att)
	if err != nil {
		t.Fatal(err)
	}
	rs := hs.post(a, enclave.OpRecoveryRegister, vid, n.guid, req)
	if rr, err := n.dev.OpenRecoveryResult(rs.Envelope); err != nil || rr.Code != vault.CodeRecoveryEarly || rs.Code != "" {
		t.Fatalf("early register: %v %+v %q", err, rr, rs.Code)
	}
	// After the delay: the register succeeds, and the vault process's
	// answer reaches the slot with the clear marker (§11.5, 0.10.6).
	if err := os.WriteFile(hs.recClock, []byte("24h1m"), 0o600); err != nil {
		t.Fatal(err)
	}
	n2 := hs.newApp(m.guid, 0x6c)
	e2, _ := hs.enclaveOf(a, n2.dev, false)
	req2, err := n2.dev.BuildRecoveryRegister(n2.guid, code, e2, n2.att)
	if err != nil {
		t.Fatal(err)
	}
	rs2 := hs.post(a, enclave.OpRecoveryRegister, vid, n2.guid, req2)
	if rr, err := n2.dev.OpenRecoveryResult(rs2.Envelope); err != nil || !rr.OK || rs2.Status != "done" || rs2.Code != enclave.CodeRecoveryRegistered {
		t.Fatalf("register: %v %+v %+v", err, rr, rs2)
	}
	if s := send("recovery_cancel", nil); s.Status != "done" {
		t.Fatalf("cancel slot %+v", s)
	}
	if u, _ := m.unlock(a); !u.OK {
		t.Fatalf("unlock after cancel: %+v", u)
	}
}
