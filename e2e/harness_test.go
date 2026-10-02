//go:build devenclave && e2e

// Package e2e runs the vault runtime against the real vettid-relay binary
// (VAULT-PLAN V2 exit criteria). Run with:
//
//	go test -race -tags 'devenclave e2e' ./e2e/
package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/client"
	"github.com/vettid/vettid-vault/devenclave"
	"github.com/vettid/vettid-vault/features/messaging"
	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vault/store"
	"github.com/vettid/vettid-vault/vms/envelope"
)

const pin = "424242"

// testVault is one vault plus its first app, with the manager running in
// the background.
type testVault struct {
	t       *testing.T
	name    string
	relay   string
	store   store.Store
	sealer  *devenclave.Sealer
	opts    vault.Options
	vaultID string
	app     *client.Device

	mu       sync.Mutex
	m        *vault.Manager
	msg      *messaging.Feature
	cancel   context.CancelFunc
	done     chan error
	finished chan struct{}
}

func ctxT(t *testing.T, d time.Duration) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}

func newTestVault(t *testing.T, relayURL, name string, tweak func(*vault.Options)) *testVault {
	t.Helper()
	ctx := ctxT(t, 60*time.Second)
	st, err := store.NewDir(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := devenclave.NewSealer(bytes.Repeat([]byte{0x5e}, 32)) // test-only dev key
	if err != nil {
		t.Fatal(err)
	}
	tv := &testVault{t: t, name: name, relay: relayURL, store: st, sealer: sealer}
	tv.opts = vault.Options{Store: st, Sealer: sealer, PollWait: time.Second}
	if tweak != nil {
		tweak(&tv.opts)
	}
	app, err := client.New(ctx, client.Config{Role: vault.KindApp, Name: name + "-app", RelayURL: relayURL, PollWait: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	tv.app = app
	open, err := app.OpenToken()
	if err != nil {
		t.Fatal(err)
	}
	ra := app.RelayAddr()
	tv.msg = messaging.New()
	o := tv.opts
	o.Features = []vault.Feature{tv.msg}
	m, err := devenclave.Create(ctx, vault.CreateParams{
		Options: o, UserGUID: "user-" + name, PIN: pin, RelayURL: relayURL, Provisional: true,
		App: &vault.EnrollApp{Name: name + "-app", IK: app.IdentityKey(), KEM: app.KEMKey(),
			Relay: vault.PeerRelay{URL: ra.URL, Mailbox: ra.Mailbox, PK: ra.PK}, OpenToken: open},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	tv.vaultID = m.VaultID()
	tv.start(m)
	if err := app.AwaitEnrolled(ctx); err != nil {
		t.Fatalf("enrolled: %v", err)
	}
	if err := app.CompleteEnrollment(ctx); err != nil {
		t.Fatalf("enroll handshake: %v", err)
	}
	r := tv.request(app, "vault.enroll.confirm", `{}`)
	if !r.OK() {
		t.Fatalf("confirm: %s", r.ErrorCode())
	}
	t.Cleanup(func() {
		if t.Failed() {
			if m := tv.manager(); m != nil {
				for _, a := range m.Audit() {
					t.Logf("%s audit: %s %s", name, a.Event, a.PeerID)
				}
			}
		}
		tv.stop()
	})
	return tv
}

func (tv *testVault) start(m *vault.Manager) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	finished := make(chan struct{})
	tv.mu.Lock()
	tv.m, tv.cancel, tv.done, tv.finished = m, cancel, done, finished
	tv.mu.Unlock()
	go func() {
		done <- m.Run(ctx)
		close(finished)
	}()
}

// stop stops the run loop (the manager stays unlocked in memory).
func (tv *testVault) stop() error {
	tv.mu.Lock()
	cancel, finished := tv.cancel, tv.finished
	tv.cancel = nil
	tv.mu.Unlock()
	if cancel == nil {
		return nil
	}
	cancel()
	select {
	case <-finished:
		return nil
	case <-time.After(30 * time.Second):
		tv.t.Fatal("run loop did not stop")
		return nil
	}
}

func (tv *testVault) manager() *vault.Manager {
	tv.mu.Lock()
	defer tv.mu.Unlock()
	return tv.m
}

// unlock opens a new manager for this vault from the store.
func (tv *testVault) unlock(ctx context.Context, tweak func(*vault.Options)) (*vault.Manager, *messaging.Feature, error) {
	f := messaging.New()
	o := tv.opts
	o.Features = []vault.Feature{f}
	if tweak != nil {
		tweak(&o)
	}
	m, _, err := devenclave.Unlock(ctx, vault.UnlockParams{Options: o, VaultID: tv.vaultID, PIN: pin})
	return m, f, err
}

// restart crashes the running manager (no flush) and unlocks a new one.
func (tv *testVault) restart() {
	tv.t.Helper()
	tv.stop()
	tv.manager().Crash()
	m, f, err := tv.unlock(ctxT(tv.t, 30*time.Second), nil)
	if err != nil {
		tv.t.Fatalf("unlock: %v", err)
	}
	tv.mu.Lock()
	tv.msg = f
	tv.mu.Unlock()
	tv.start(m)
}

func (tv *testVault) request(d *client.Device, typ, body string) *client.Response {
	tv.t.Helper()
	r, err := d.Request(ctxT(tv.t, 30*time.Second), typ, json.RawMessage(body))
	if err != nil {
		tv.t.Fatalf("%s: %v", typ, err)
	}
	return r
}

func mustOK(t *testing.T, r *client.Response) strictjson.Object {
	t.Helper()
	if !r.OK() {
		t.Fatalf("%s: error %s", r.Inner.Type, r.ErrorCode())
	}
	o, err := strictjson.ParseObject(r.Body())
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func field(t *testing.T, raw json.RawMessage, name string) string {
	t.Helper()
	o, err := strictjson.ParseObject(raw)
	if err != nil {
		t.Fatal(err)
	}
	v, err := o.String(name)
	if err != nil {
		t.Fatalf("missing %s in %s", name, raw)
	}
	return v
}

func waitEvent(t *testing.T, d *client.Device, typ string, pred func(json.RawMessage) bool) *envelope.Inner {
	t.Helper()
	in, err := d.WaitEvent(ctxT(t, 30*time.Second), typ, pred)
	if err != nil {
		t.Fatalf("waiting for %s: %v", typ, err)
	}
	return in
}

func has(name, value string) func(json.RawMessage) bool {
	return func(b json.RawMessage) bool {
		o, err := strictjson.ParseObject(b)
		if err != nil {
			return false
		}
		v, _ := o.String(name)
		return v == value
	}
}

// connect connects a and b by a remote invite from a (open token + claim,
// §6.4) and returns each side's connection id.
func connect(t *testing.T, a, b *testVault, ttl int) (aConn, bConn string) {
	t.Helper()
	inv := mustOK(t, a.request(a.app, "connection.invite.create", `{"ttl_seconds":`+itoa(ttl)+`}`))
	link, _ := inv.String("link")
	remote, _ := inv.Bool("remote")
	if remote != (ttl > 600) {
		t.Fatalf("remote = %v for ttl %d", remote, ttl)
	}
	acc := mustOK(t, b.request(b.app, "connection.invite.accept", `{"link":"`+link+`"}`))
	bConn, _ = acc.String("connection_id")
	pend := waitEvent(t, a.app, "connection.request.pending", nil)
	po, _ := strictjson.ParseObject(pend.Body)
	if r, _ := po.Bool("remote"); r != remote {
		t.Fatal("pending remote flag")
	}
	if sas, _ := po.String("sas"); len(sas) != 6 {
		t.Fatal("no SAS")
	}
	pid, _ := po.String("pending_id")
	mustOK(t, a.request(a.app, "connection.approve", `{"pending_id":"`+pid+`"}`))
	waitEvent(t, b.app, "connection.event", has("event", "added"))
	ev := waitEvent(t, a.app, "connection.event", has("event", "added"))
	aConn = field(t, ev.Body, "connection_id")
	return aConn, bConn
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func sendText(t *testing.T, tv *testVault, d *client.Device, conn, text string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"connection_id": conn, "text": text})
	r := mustOK(t, tv.request(d, "message.send", string(body)))
	id, _ := r.String("message_id")
	return id
}
