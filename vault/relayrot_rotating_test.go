package vault

import (
	"context"
	"crypto/ed25519"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"
	"github.com/vettid/vettid-relay/relayclient"
)

// The vault rotating its own relay key (VAULT-MESSAGING §3.4 "The order of
// a relay-key rotation"): the test relay and the fixture.

// rotWorld is the relay as the rotation sees it: the live mailboxes, the
// scripted answers, and a log of the calls.
type rotWorld struct {
	mu   sync.Mutex
	live map[string]bool
	// rotate and register are the answers to the next calls, in order
	// (nil: as the relay would answer); onRotate runs at each rotate.
	rotate, register []error
	onRotate         func()
	// rotates are "old>new" per rotate call; registers the mailbox of each
	// registration (Register and RegisterCreated); signers the mailbox of
	// the key that signed each deposit; deleted the mailboxes deleted.
	rotates, registers, signers, deleted []string
}

func newRotWorld() *rotWorld { return &rotWorld{live: map[string]bool{}} }

func (w *rotWorld) pop(q *[]error) error {
	if len(*q) == 0 {
		return nil
	}
	err := (*q)[0]
	*q = (*q)[1:]
	return err
}

func (w *rotWorld) log() (rotates, registers []string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]string(nil), w.rotates...), append([]string(nil), w.registers...)
}

// rotRelay is a stubRelay for one of the vault's relay keys that can
// rotate (RelayRotator).
type rotRelay struct {
	*stubRelay
	key ed25519.PrivateKey
	w   *rotWorld
}

var _ RelayRotator = (*rotRelay)(nil)

func (r *rotRelay) Register(ctx context.Context) (Limits, error) {
	r.w.mu.Lock()
	r.w.registers = append(r.w.registers, mailboxOf(r.key))
	r.w.live[mailboxOf(r.key)] = true
	r.w.mu.Unlock()
	return r.stubRelay.Register(ctx)
}

func (r *rotRelay) RegisterCreated(ctx context.Context) (Limits, bool, error) {
	r.w.mu.Lock()
	mb := mailboxOf(r.key)
	r.w.registers = append(r.w.registers, mb)
	if err := r.w.pop(&r.w.register); err != nil {
		r.w.mu.Unlock()
		return Limits{}, false, err
	}
	created := !r.w.live[mb]
	r.w.live[mb] = true
	r.w.mu.Unlock()
	l, err := r.stubRelay.Register(ctx)
	return l, created, err
}

func (r *rotRelay) Rotate(_ context.Context, newKey ed25519.PrivateKey) (string, error) {
	r.w.mu.Lock()
	old, nw := mailboxOf(r.key), mailboxOf(newKey)
	r.w.rotates = append(r.w.rotates, old+">"+nw)
	hook := r.w.onRotate
	err := r.w.pop(&r.w.rotate)
	if err == nil && !r.w.live[old] {
		err = &relayclient.Error{Status: 404, Code: CodeMailboxUnknown}
	}
	if err == nil {
		r.w.live[nw] = true
	}
	r.w.mu.Unlock()
	if hook != nil {
		hook()
	}
	if err != nil {
		return "", err
	}
	return nw, nil
}

func (r *rotRelay) WithKey(k ed25519.PrivateKey) Relay {
	return &rotRelay{stubRelay: r.stubRelay, key: k, w: r.w}
}

func (r *rotRelay) Deposit(ctx context.Context, url, mailbox, token string, payload []byte) (string, error) {
	r.w.mu.Lock()
	r.w.signers = append(r.w.signers, mailboxOf(r.key))
	r.w.mu.Unlock()
	return r.stubRelay.Deposit(ctx, url, mailbox, token, payload)
}

func (r *rotRelay) MintToken(sub ed25519.PublicKey, ttl time.Duration, jti string, q *relayauth.Quota, ownerDevice bool) (string, error) {
	return relayclient.New(r.base, r.key).MintToken(relayauth.EncodeKey(sub), r.base, relayclient.TokenOptions{TTL: ttl, JTI: jti, Quota: q, OwnerDevice: ownerDevice})
}

func (r *rotRelay) DeleteMailbox(context.Context) error {
	r.w.mu.Lock()
	defer r.w.mu.Unlock()
	r.w.deleted = append(r.w.deleted, mailboxOf(r.key))
	return nil
}

// rotFx is a vault with its app (dev1) and a connection (c1), run with
// Options.RelayKeyRotation on a relay that can rotate, on its own clock.
type rotFx struct {
	*devFixture
	t    *testing.T
	w    *rotWorld
	sink *recSink
	fs   *faultStore
	clk  time.Time
	conn *tdev
}

func newRotFx(t *testing.T) *rotFx {
	d := newDevFixture(t)
	fx := &rotFx{devFixture: d, t: t, w: newRotWorld(), sink: &recSink{}, clk: time.Now().UTC()}
	fx.conn = d.asConnection(t, "c1", 0x70)
	o := &d.fixture.opts
	o.Features = append(o.Features, fx.sink)
	o.RelayKeyRotation = true
	o.Now = func() time.Time { return fx.clk }
	o.Relay = func(base string, key ed25519.PrivateKey) Relay {
		d.fixture.relay = &stubRelay{base: base, key: key}
		return &rotRelay{stubRelay: d.fixture.relay, key: key, w: fx.w}
	}
	fx.fs = &faultStore{Store: d.fixture.store}
	o.Store = fx.fs
	fx.w.live[fx.mailbox()] = true
	fx.restart()
	return fx
}

// do runs f under the vault's lock.
func (fx *rotFx) do(f func(m *Manager)) {
	fx.t.Helper()
	fx.m.mu.Lock()
	defer fx.m.mu.Unlock()
	f(fx.m)
}

func (fx *rotFx) mailbox() string {
	var mb string
	fx.do(func(m *Manager) { mb = m.st.Relay.Mailbox })
	return mb
}

func (fx *rotFx) pending() *PendingRelay {
	var pr *PendingRelay
	fx.do(func(m *Manager) { pr = m.st.Relay.Pending })
	return pr
}

func (fx *rotFx) pendingMailbox() string {
	var mb string
	fx.do(func(m *Manager) { mb = m.pendingMailbox() })
	return mb
}

func (fx *rotFx) ik() string {
	var s string
	fx.do(func(m *Manager) { s = relayauth.EncodeKey(pubOf(m.keys.ik)) })
	return s
}

// open unlocks the vault from its store and starts it (§12.2).
func (fx *rotFx) open() {
	fx.t.Helper()
	m, _, err := fx.unlock(testPIN, 0, 0)
	if err != nil {
		fx.t.Fatal(err)
	}
	fx.m = m
	if err := m.Start(context.Background()); err != nil {
		fx.t.Fatal(err)
	}
}

// restart locks the vault and opens it again; crash discards it unwritten
// (a process death) and opens it again.
func (fx *rotFx) restart() {
	fx.t.Helper()
	_ = fx.m.Lock(context.Background())
	fx.open()
}

func (fx *rotFx) crash() {
	fx.t.Helper()
	fx.m.Crash()
	fx.open()
}

// credRotate is credential.rotate's rotation (§3.5.5), as its handler and
// the batch end make it: the host's rotation, the batch's write, then the
// relay key's step 2.
func (fx *rotFx) credRotate() error {
	var err error
	fx.do(func(m *Manager) {
		if err = (managerHost{m}).RotateIdentity(m.now()); err != nil {
			return
		}
		if err = m.persist(context.Background(), false); err != nil {
			return
		}
		m.relayKeyStep(context.Background(), false)
	})
	return err
}

// batch is an empty batch (the collect loop's turn): its end makes the
// sooner retries that are due.
func (fx *rotFx) batch() {
	fx.t.Helper()
	if err := fx.m.ProcessBatch(context.Background(), &fakeCollector{}, nil); err != nil && !errors.Is(err, ErrLocked) {
		fx.t.Fatal(err)
	}
}

func (fx *rotFx) acts(kind string) []Activity {
	var out []Activity
	fx.do(func(m *Manager) {
		for _, a := range fx.sink.got {
			if a.Kind == kind {
				out = append(out, a)
			}
		}
	})
	return out
}

func relayErr(status int, code string) error { return &relayclient.Error{Status: status, Code: code} }

// parseOwnToken verifies a token the vault minted on its current key.
func parseOwnToken(m *Manager, tok string) (relayauth.Claims, error) {
	return relayauth.ParseToken(tok, pubOf(m.keys.relay))
}
