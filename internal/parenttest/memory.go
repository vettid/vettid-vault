// Package parenttest provides TEST-ONLY in-memory stand-ins for the
// parent's AWS backends (S3, SQS, DynamoDB), with the same conditional
// semantics as package parent's AWS implementation, so the parent and the
// enclave can be exercised without LocalStack.
package parenttest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/vettid/vettid-vault/parent"
)

// Objects is an in-memory bucket with ETag versions.
type Objects struct {
	mu   sync.Mutex
	objs map[string]obj
	// Puts counts successful writes.
	Puts int
}

type obj struct {
	data []byte
	etag string
}

func etag() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return `"` + hex.EncodeToString(b) + `"`
}

// NewObjects returns an empty bucket.
func NewObjects() *Objects { return &Objects{objs: map[string]obj{}} }

// Get implements parent.Objects.
func (o *Objects) Get(_ context.Context, key string) ([]byte, string, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	x, ok := o.objs[key]
	if !ok {
		return nil, "", parent.ErrNotFound
	}
	return append([]byte(nil), x.data...), x.etag, nil
}

// Put implements parent.Objects.
func (o *Objects) Put(_ context.Context, key string, data []byte, ifMatch string) (string, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	x, ok := o.objs[key]
	if ifMatch == "" && ok || ifMatch != "" && (!ok || x.etag != ifMatch) {
		return "", parent.ErrConflict
	}
	e := etag()
	o.objs[key] = obj{data: append([]byte(nil), data...), etag: e}
	o.Puts++
	return e, nil
}

// Delete implements parent.Objects.
func (o *Objects) Delete(_ context.Context, key, ifMatch string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	x, ok := o.objs[key]
	if !ok {
		return parent.ErrNotFound
	}
	if x.etag != ifMatch {
		return parent.ErrConflict
	}
	delete(o.objs, key)
	return nil
}

// Keys returns the stored keys.
func (o *Objects) Keys() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	var ks []string
	for k := range o.objs {
		ks = append(ks, k)
	}
	return ks
}

// Queues is an in-memory SQS with visibility timeouts.
type Queues struct {
	mu      sync.Mutex
	queues  map[string]*queue
	created map[string]time.Time
	// Visibility is the visibility timeout (default 2 s).
	Visibility time.Duration
	// Base is the URL prefix (default http://sqs.test/000000000000/).
	Base string
	// DeletedRecently, if set, refuses to recreate a queue for that long
	// after its deletion, as SQS does for 60 s
	// (parent.ErrQueueDeletedRecently).
	DeletedRecently time.Duration
	// CreateRefusals counts the creates refused that way.
	CreateRefusals int
	deleted        map[string]time.Time
}

type queue struct {
	msgs   []*msg
	notify chan struct{}
}

type msg struct {
	id, body, receipt string
	hiddenUntil       time.Time
	receives          int
}

// NewQueues returns an empty SQS.
func NewQueues() *Queues {
	return &Queues{queues: map[string]*queue{}, created: map[string]time.Time{}, Visibility: 2 * time.Second, Base: "http://sqs.test/000000000000/"}
}

// Create implements parent.Queues.
func (q *Queues) Create(_ context.Context, name string) (string, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	u := q.Base + name
	if at, ok := q.deleted[u]; ok && time.Since(at) < q.DeletedRecently {
		q.CreateRefusals++
		return "", fmt.Errorf("%w: sqs create: AWS.SimpleQueueService.QueueDeletedRecently", parent.ErrQueueDeletedRecently)
	}
	if q.queues[u] == nil {
		q.queues[u] = &queue{notify: make(chan struct{}, 1)}
		q.created[u] = time.Now()
	}
	return u, nil
}

// Send enqueues a message (the member API's side).
func (q *Queues) Send(url, body string) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	qq := q.queues[url]
	if qq == nil {
		return false
	}
	qq.msgs = append(qq.msgs, &msg{id: etag(), body: body})
	select {
	case qq.notify <- struct{}{}:
	default:
	}
	return true
}

// Receive implements parent.Queues (waits up to 1 s).
func (q *Queues) Receive(ctx context.Context, url string) ([]parent.QueueMessage, error) {
	deadline := time.Now().Add(time.Second)
	for {
		q.mu.Lock()
		qq := q.queues[url]
		if qq == nil {
			q.mu.Unlock()
			return nil, parent.ErrNotFound
		}
		var out []parent.QueueMessage
		now := time.Now()
		for _, m := range qq.msgs {
			if len(out) == 10 || now.Before(m.hiddenUntil) || m.receives >= 3 {
				continue
			}
			m.receives++
			m.hiddenUntil = now.Add(q.Visibility)
			m.receipt = etag()
			out = append(out, parent.QueueMessage{ID: m.id, Body: []byte(m.body), Receipt: m.receipt})
		}
		ch := qq.notify
		q.mu.Unlock()
		if len(out) > 0 || time.Now().After(deadline) {
			return out, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ch:
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// DeleteMessage implements parent.Queues.
func (q *Queues) DeleteMessage(_ context.Context, url, receipt string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	qq := q.queues[url]
	if qq == nil {
		return parent.ErrNotFound
	}
	for i, m := range qq.msgs {
		if m.receipt == receipt {
			qq.msgs = append(qq.msgs[:i], qq.msgs[i+1:]...)
			return nil
		}
	}
	return nil
}

// Destroy implements parent.Queues.
func (q *Queues) Destroy(_ context.Context, url string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	delete(q.queues, url)
	delete(q.created, url)
	if q.deleted == nil {
		q.deleted = map[string]time.Time{}
	}
	q.deleted[url] = time.Now()
	return nil
}

// List implements parent.Queues.
func (q *Queues) List(_ context.Context, prefix string) (map[string]time.Time, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := map[string]time.Time{}
	for u, t := range q.created {
		if len(u) >= len(q.Base)+len(prefix) && u[len(q.Base):len(q.Base)+len(prefix)] == prefix {
			out[u] = t
		}
	}
	return out, nil
}

// Exists reports whether a queue exists.
func (q *Queues) Exists(url string) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.queues[url] != nil
}

// Pending returns the number of messages in a queue.
func (q *Queues) Pending(url string) int {
	q.mu.Lock()
	defer q.mu.Unlock()
	if qq := q.queues[url]; qq != nil {
		return len(qq.msgs)
	}
	return 0
}

// VaultRow is a vault-table item.
type VaultRow struct {
	VaultID, UserGUID, State                  string
	LeaseInstance                             string
	LeaseExpires                              int64
	SealedRelease, VaultVersion, StateVersion string
	UpdatedAt                                 string
	// The host alarm (§11.5): alarm {kind, alarm_id, at}, alarm_pending.
	AlarmKind, AlarmID string
	AlarmAt            int64
	AlarmPending       bool
	Alarms             int
	// The app key the enclave reported (0.15.0, §11.5): SPKI DER, akid,
	// seq; written by the parent whatever the lease.
	AppKey    []byte
	AppKeyID  string
	AppKeySeq uint64
	// CredentialBackup is the reported backup bit (0.16.0, §11.5).
	CredentialBackup *bool
	// NameChange and NameChangePending are the member's name request as
	// the host wrote it (0.18.0, §11.5); NameChangeAt its Unix seconds.
	NameChange        *parent.NameChange
	NameChangeAt      int64
	NameChangePending bool
}

// SlotRow is a response slot.
type SlotRow struct {
	Status, Code, InstanceID string
	Envelope                 []byte
}

// Tables is in-memory DynamoDB with the parent's conditions.
type Tables struct {
	mu        sync.Mutex
	vaults    map[string]*VaultRow
	instances map[string]parent.InstanceRow
	slots     map[string]*SlotRow
	ids       int
	events    map[string][]string
}

// LifecycleEvents returns the lifecycle events the parent wrote for a
// vault, in order (whether or not they applied).
func (t *Tables) LifecycleEvents(vaultID string) []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]string(nil), t.events[vaultID]...)
}

// NewTables returns empty tables.
func NewTables() *Tables {
	return &Tables{vaults: map[string]*VaultRow{}, instances: map[string]parent.InstanceRow{}, slots: map[string]*SlotRow{}}
}

// PutVault creates a vault row (the API's side).
func (t *Tables) PutVault(r VaultRow) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.vaults[r.VaultID] = &r
}

// Vault returns a copy of a vault row.
func (t *Tables) Vault(id string) (VaultRow, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	r, ok := t.vaults[id]
	if !ok {
		return VaultRow{}, false
	}
	return *r, true
}

// SetLease overwrites a lease (tests that force a split brain).
func (t *Tables) SetLease(id, instance string, expires int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if r := t.vaults[id]; r != nil {
		r.LeaseInstance, r.LeaseExpires = instance, expires
	}
}

// PutSlot creates a queued slot (the API's side).
func (t *Tables) PutSlot(requestID, instanceID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.slots[requestID] = &SlotRow{Status: "queued", InstanceID: instanceID}
}

// Slot returns a copy of a slot.
func (t *Tables) Slot(requestID string) (SlotRow, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	s, ok := t.slots[requestID]
	if !ok {
		return SlotRow{}, false
	}
	return *s, true
}

// Instance returns an instance row.
func (t *Tables) Instance(id string) (parent.InstanceRow, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	r, ok := t.instances[id]
	return r, ok
}

// PutInstance implements parent.Tables.
func (t *Tables) PutInstance(_ context.Context, r parent.InstanceRow) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.instances[r.InstanceID] = r
	return nil
}

// DeleteInstance implements parent.Tables.
func (t *Tables) DeleteInstance(_ context.Context, id string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.instances, id)
	return nil
}

// InstanceHeartbeat implements parent.Tables.
func (t *Tables) InstanceHeartbeat(_ context.Context, id string) (int64, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	r, ok := t.instances[id]
	if !ok {
		return 0, parent.ErrNotFound
	}
	return r.HeartbeatAt, nil
}

// AcquireLease implements parent.Tables.
func (t *Tables) AcquireLease(_ context.Context, vaultID, me string, now, expires int64) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	r := t.vaults[vaultID]
	if r == nil || !(r.LeaseInstance == "" || r.LeaseExpires <= now || r.LeaseInstance == me) {
		return parent.ErrLeaseHeld
	}
	r.LeaseInstance, r.LeaseExpires = me, expires
	return nil
}

// Lease implements parent.Tables.
func (t *Tables) Lease(_ context.Context, vaultID string) (string, int64, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	r := t.vaults[vaultID]
	if r == nil {
		return "", 0, nil
	}
	return r.LeaseInstance, r.LeaseExpires, nil
}

// TakeoverLease implements parent.Tables.
func (t *Tables) TakeoverLease(_ context.Context, vaultID, me, old string, oldExp, expires int64) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	r := t.vaults[vaultID]
	if r == nil || r.LeaseInstance != old || r.LeaseExpires != oldExp {
		return parent.ErrLeaseHeld
	}
	r.LeaseInstance, r.LeaseExpires = me, expires
	return nil
}

// PutInstanceRow sets a registry row (tests of liveness).
func (t *Tables) PutInstanceRow(r parent.InstanceRow) {
	t.mu.Lock()
	t.instances[r.InstanceID] = r
	t.mu.Unlock()
}

// RenewLease implements parent.Tables.
func (t *Tables) RenewLease(_ context.Context, vaultID, me string, expires int64) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	r := t.vaults[vaultID]
	if r == nil || r.LeaseInstance != me {
		return parent.ErrLeaseHeld
	}
	r.LeaseExpires = expires
	return nil
}

// ReleaseLease implements parent.Tables.
func (t *Tables) ReleaseLease(_ context.Context, vaultID, me string, now time.Time) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	r := t.vaults[vaultID]
	if r == nil || r.LeaseInstance != me {
		return parent.ErrLeaseHeld
	}
	r.LeaseInstance, r.LeaseExpires = "", 0
	if r.State == "unlocked" {
		r.State = "locked" // as parent.AWS: a vault that stopped without a lifecycle "locked"
	}
	return nil
}

// Lifecycle implements parent.Tables.
func (t *Tables) Lifecycle(_ context.Context, ev parent.Lifecycle, me string, now time.Time) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.events == nil {
		t.events = map[string][]string{}
	}
	t.events[ev.VaultID] = append(t.events[ev.VaultID], ev.Event)
	r := t.vaults[ev.VaultID]
	if r != nil && ev.Event == parent.EventAlarmCredentialClone {
		// Not lease-conditioned: an alarm is never lost to a lease race.
		t.ids++
		r.AlarmKind, r.AlarmID, r.AlarmAt, r.AlarmPending = "credential_clone", strconv.Itoa(t.ids), now.Unix(), true
		r.Alarms++
		r.UpdatedAt = now.UTC().Format(time.RFC3339)
		return nil
	}
	if ev.Event == parent.EventAccountName {
		// Not lease-conditioned: only by seq, as parent.AWS.
		if r != nil && ev.Name != nil && (r.NameChange == nil || ev.Name.Seq > r.NameChange.Seq) {
			n := *ev.Name
			r.NameChange, r.NameChangeAt, r.NameChangePending = &n, now.Unix(), true
			r.UpdatedAt = now.UTC().Format(time.RFC3339)
		}
		return nil
	}
	if r != nil && len(ev.AppKey) > 0 && (ev.Event == "enrolled" || ev.AppKeySeq > r.AppKeySeq) {
		// Not lease-conditioned: only by seq (enrolled: always), as parent.AWS.
		r.AppKey, r.AppKeyID, r.AppKeySeq = append([]byte(nil), ev.AppKey...), parent.AppKeyID(ev.AppKey), ev.AppKeySeq
	}
	if ev.Event == parent.EventAppKey {
		return nil
	}
	if r == nil || !(r.LeaseInstance == "" || r.LeaseInstance == me) {
		return nil
	}
	if ev.CredentialBackup != nil {
		b := *ev.CredentialBackup
		r.CredentialBackup = &b
	}
	if ev.Event == parent.EventCredentialBackup {
		return nil
	}
	r.VaultVersion, r.StateVersion, r.UpdatedAt = ev.VaultVersion, strconv.Itoa(ev.StateVersion), now.UTC().Format(time.RFC3339)
	switch ev.Event {
	case "enrolled", "moved":
		r.SealedRelease = ev.Release
	case "unlocked":
		r.State = "unlocked"
	case "locked", "deleted":
		r.State = ev.Event
		if !(ev.Event == "locked" && ev.KeepLease) {
			r.LeaseInstance, r.LeaseExpires = "", 0
		}
	}
	if ev.Event == "deleted" {
		t.ids++
		r.AlarmKind, r.AlarmID, r.AlarmAt, r.AlarmPending = "vault_deleted", strconv.Itoa(t.ids), now.Unix(), true
		r.Alarms++
	}
	return nil
}

// WriteSlot implements parent.Tables.
func (t *Tables) WriteSlot(_ context.Context, requestID string, s parent.Slot) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	r := t.slots[requestID]
	if r == nil || r.Status != "queued" {
		return nil
	}
	r.Status, r.Code = s.Status, s.Code
	r.Envelope = append([]byte(nil), s.Envelope...)
	return nil
}

// StaticCreds hands out fixed credentials.
type StaticCreds parent.Credentials

// Retrieve implements parent.CredentialSource.
func (c StaticCreds) Retrieve(context.Context) (parent.Credentials, error) {
	return parent.Credentials(c), nil
}
