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
	// now is the vault's clock, which the relay client mints tokens by.
	now func() time.Time
	// blobSigners: the mailbox of the key that signed each blob upload;
	// blobs the blobs of each mailbox; blobDeletes "mailbox/id" per
	// deletion; revokes "mailbox:kind:value" per revocation; wsAsked the
	// websocket flag of each Collector asked for.
	blobSigners []string
	blobs       map[string]map[string][]byte
	blobDeletes []string
	revokes     []string
	wsAsked     map[string]bool
	blobInfo    map[string]BlobEntry // "mailbox/id": sender, created_at
	// queue are the messages waiting in each mailbox, given once each
	// (inflight) until acked; collectErr answers a mailbox's collects;
	// collects logs the mailbox of each collect, acks each ack.
	queue      map[string][]Message
	inflight   map[string]bool
	collectErr map[string]error
	collects   []string
	acks       []string
}

func newRotWorld() *rotWorld {
	return &rotWorld{live: map[string]bool{}, queue: map[string][]Message{}, inflight: map[string]bool{}, collectErr: map[string]error{},
		blobs: map[string]map[string][]byte{}, wsAsked: map[string]bool{}, blobInfo: map[string]BlobEntry{}}
}

// put queues a message in mailbox mb, deposited at at.
func (w *rotWorld) put(mb, id string, at time.Time, payload []byte) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.queue[mb] = append(w.queue[mb], Message{MsgID: id, DepositedAt: at.UTC().Format(time.RFC3339Nano), Payload: payload})
}

// rotCollector collects one mailbox of the rotWorld.
type rotCollector struct {
	w  *rotWorld
	mb string
}

func (c *rotCollector) Next(context.Context) ([]Message, error) {
	c.w.mu.Lock()
	defer c.w.mu.Unlock()
	c.w.collects = append(c.w.collects, c.mb)
	if err := c.w.collectErr[c.mb]; err != nil {
		return nil, err
	}
	var out []Message
	for _, msg := range c.w.queue[c.mb] {
		if !c.w.inflight[msg.MsgID] && len(out) < MaxBatch {
			c.w.inflight[msg.MsgID] = true
			out = append(out, msg)
		}
	}
	return out, nil
}

func (c *rotCollector) Ack(_ context.Context, id string) error {
	c.w.mu.Lock()
	defer c.w.mu.Unlock()
	c.w.acks = append(c.w.acks, c.mb+"/"+id)
	q := c.w.queue[c.mb][:0]
	for _, msg := range c.w.queue[c.mb] {
		if msg.MsgID != id {
			q = append(q, msg)
		}
	}
	c.w.queue[c.mb] = q
	return nil
}

func (c *rotCollector) Close() error { return nil }

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

func (r *rotRelay) Collector(_ context.Context, ws bool) (Collector, error) {
	r.w.mu.Lock()
	r.w.wsAsked[mailboxOf(r.key)] = ws
	r.w.mu.Unlock()
	return &rotCollector{w: r.w, mb: mailboxOf(r.key)}, nil
}

func (r *rotRelay) GetBlob(_ context.Context, id string) ([]byte, error) {
	r.w.mu.Lock()
	defer r.w.mu.Unlock()
	if b, ok := r.w.blobs[mailboxOf(r.key)][id]; ok {
		return append([]byte(nil), b...), nil
	}
	return nil, errStubNoBlob
}

func (r *rotRelay) DeleteBlob(_ context.Context, id string) error {
	r.w.mu.Lock()
	defer r.w.mu.Unlock()
	r.w.blobDeletes = append(r.w.blobDeletes, mailboxOf(r.key)+"/"+id)
	delete(r.w.blobs[mailboxOf(r.key)], id)
	return nil
}

func (r *rotRelay) ListBlobs(context.Context) (BlobList, error) {
	r.w.mu.Lock()
	defer r.w.mu.Unlock()
	var out BlobList
	for id, b := range r.w.blobs[mailboxOf(r.key)] {
		e := r.w.blobInfo[mailboxOf(r.key)+"/"+id]
		e.BlobID, e.Size = id, int64(len(b))
		out.Blobs = append(out.Blobs, e)
	}
	out.MaxBytes = 64 << 20
	return out, nil
}

func (r *rotRelay) Revoke(_ context.Context, kind, value string) error {
	r.w.mu.Lock()
	defer r.w.mu.Unlock()
	r.w.revokes = append(r.w.revokes, mailboxOf(r.key)+":"+kind+":"+value)
	return nil
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

func (r *rotRelay) PutBlob(ctx context.Context, url, mailbox, token string, data []byte) (string, time.Time, error) {
	r.w.mu.Lock()
	r.w.blobSigners = append(r.w.blobSigners, mailboxOf(r.key))
	r.w.mu.Unlock()
	return "01JB2Z6V9K3M4N5P6Q7R8S0001", time.Now().Add(time.Hour), nil
}

func (r *rotRelay) MintToken(sub ed25519.PublicKey, ttl time.Duration, jti string, q *relayauth.Quota, ownerDevice bool) (string, error) {
	c := relayclient.New(r.base, r.key)
	if r.w.now != nil {
		c.Now = r.w.now
	}
	return c.MintToken(relayauth.EncodeKey(sub), r.base, relayclient.TokenOptions{TTL: ttl, JTI: jti, Quota: q, OwnerDevice: ownerDevice})
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
	clk  time.Time // the test's reading; set with setClk
	conn *tdev
	cmu  sync.Mutex
	vclk time.Time // the vault's (its attachment run reads it unlocked)
}

func (fx *rotFx) setClk(t time.Time) {
	fx.cmu.Lock()
	defer fx.cmu.Unlock()
	fx.clk, fx.vclk = t, t
}

func newRotFx(t *testing.T) *rotFx {
	d := newDevFixture(t)
	fx := &rotFx{devFixture: d, t: t, w: newRotWorld(), sink: &recSink{}}
	fx.setClk(time.Now().UTC())
	fx.conn = d.asConnection(t, "c1", 0x70)
	o := &d.fixture.opts
	o.Features = append(o.Features, fx.sink)
	o.RelayKeyRotation, o.RelayKeyRotationUnfinished = true, true
	o.PollWait = 10 * time.Millisecond // an idle collect returns at once
	o.Now = func() time.Time {
		fx.cmu.Lock()
		defer fx.cmu.Unlock()
		return fx.vclk
	}
	fx.w.now = o.Now
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

// setFail fails the next n state writes (under the store's lock: the
// attachment run writes from its own goroutine).
func (f *faultStore) setFail(n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failState = n
}
