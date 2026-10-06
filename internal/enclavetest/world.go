package enclavetest

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"errors"
	"sync"
	"time"

	"github.com/vettid/vettid-vault/client"
	"github.com/vettid/vettid-vault/enclave"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vault/store"
	"github.com/vettid/vettid-vault/vms/devattest"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/manifest"
	"github.com/vettid/vettid-vault/vms/suite"
)

// ManifestKey returns the TEST-ONLY manifest signing key (the §16 vector
// key: P-256 scalar 32 x 0x21).
func ManifestKey() *ecdsa.PrivateKey { return TestKey(elliptic.P256(), 0x21) }

// ReleaseSpec describes a test release: its number, PCR bytes and status.
type ReleaseSpec struct {
	Number           uint64
	PCR0, PCR1, PCR2 byte
	Status           string
}

// PCR0Hex returns the release's PCR0.
func (r ReleaseSpec) PCR0Hex() string { return PCRHex(r.PCR0) }

// World is a TEST-ONLY in-process stand-in for everything around the
// enclave (VAULT-PLAN §6): the member API's routing and response slots,
// the per-instance queues and the parent, the vault data bucket, a fake
// KMS with one sealing key per release, and the signed release manifest.
// Instances of several releases run side by side (§11.10.5).
type World struct {
	// Account, if set, is the account snapshot the API puts in each
	// unlock (0.15.0, §11.13).
	Account  func(userGUID string) []byte
	Now      func() time.Time
	Store    store.Store
	KMS      *FakeKMS
	Key      *ecdsa.PrivateKey
	Relays   *MemRelays
	Features func() []vault.Feature
	// VaultOptions is the template for vaults (relay transport etc.).
	VaultOptions vault.Options
	// Stopped is passed to instances (run loops that end).
	Stopped  func(vaultID string, err error)
	RelayURL string
	// Withhold makes the parent stand-in supply no manifest document;
	// Substitute, if set, is supplied instead of the named one (a
	// dishonest or broken host). Set them between requests.
	Withhold   bool
	Substitute []byte

	mu       sync.Mutex
	releases []ReleaseSpec
	served   *manifest.Served
	manifest *manifest.Manifest
	// docs are the published documents by manifest_sha256: the vault
	// data bucket's manifests/<sha256>.json (0.10.0).
	docs      map[string][]byte
	serial    uint64
	instances map[string]*enclave.Instance
	sealedTo  map[string]string // vault_id -> sealed_release (from lifecycle events)
	events    []vault.LifecycleEvent
	list      *devattest.StatusList
	nextInst  int
}

// NewWorld returns a world with a fresh store and fake KMS.
func NewWorld(now func() time.Time, relayURL string) *World {
	if now == nil {
		now = time.Now
	}
	w := &World{Now: now, Store: store.NewMemory(), Key: ManifestKey(), Relays: &MemRelays{}, RelayURL: relayURL,
		instances: map[string]*enclave.Instance{}, sealedTo: map[string]string{}, docs: map[string][]byte{}}
	w.KMS = NewFakeKMS("world", TestNitroCA().Roots(), now)
	w.list = EmptyStatusList(now())
	return w
}

// Trust is the client trust configuration for the world.
func (w *World) Trust() client.Trust {
	return client.Trust{NitroRoots: TestNitroCA().Roots(), ManifestKeys: []*ecdsa.PublicKey{&w.Key.PublicKey}}
}

// AddRelease adds a release: its KMS key (with the §11.10.7 policy shape,
// admitting the releases published before it to seal) and a manifest
// entry. The manifest is republished with a higher serial.
func (w *World) AddRelease(r ReleaseSpec) {
	w.mu.Lock()
	w.releases = append(w.releases, r)
	var gdk []string
	for _, x := range w.releases {
		if x.Number <= r.Number {
			gdk = append(gdk, x.PCR0Hex())
		}
	}
	w.mu.Unlock()
	w.KMS.AddKey(KeyARN(r.Number), GoodPolicy(r.PCR0Hex(), gdk))
	w.Publish()
}

// SetStatus changes a release's status and republishes.
func (w *World) SetStatus(n uint64, status string) {
	w.mu.Lock()
	for i := range w.releases {
		if w.releases[i].Number == n {
			w.releases[i].Status = status
		}
	}
	w.mu.Unlock()
	w.Publish()
}

// Publish signs the manifest with the next serial.
func (w *World) Publish() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.serial++
	var rs []manifest.Release
	for _, r := range w.releases {
		rs = append(rs, manifest.Release{Number: r.Number, PCR0: r.PCR0Hex(), PCR1: PCRHex(r.PCR1), PCR2: PCRHex(r.PCR2),
			SealKey: KeyARN(r.Number), Status: r.Status, PublishedAt: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC),
			Notes: "https://vettid.org/releases/test"})
	}
	b := manifest.Build(w.serial, w.Now().UTC().Truncate(time.Second), rs)
	s, err := manifest.Sign(w.Key, b)
	if err != nil {
		panic(err)
	}
	m, err := manifest.Parse(b)
	if err != nil {
		panic(err)
	}
	w.served, w.manifest = s, m
	w.docs[manifest.SHA256Hex(b)] = s.Marshal()
}

// ManifestDoc returns the published document with the given
// manifest_sha256, as the parent reads it from the bucket.
func (w *World) ManifestDoc(sha256Hex string) []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.Withhold {
		return nil
	}
	if w.Substitute != nil {
		return w.Substitute
	}
	return w.docs[sha256Hex]
}

// Served returns the served manifest document bytes.
func (w *World) Served() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.served.Marshal()
}

// ServedAt returns a manifest signed with an explicit serial (stale
// manifest tests).
func (w *World) ServedAt(serial uint64) []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	b := manifest.Build(serial, w.Now().UTC().Truncate(time.Second), w.manifest.Releases)
	s, _ := manifest.Sign(w.Key, b)
	w.docs[manifest.SHA256Hex(b)] = s.Marshal() // it was published once
	return s.Marshal()
}

func (w *World) spec(n uint64) (ReleaseSpec, bool) {
	for _, r := range w.releases {
		if r.Number == n {
			return r, true
		}
	}
	return ReleaseSpec{}, false
}

// Config returns an instance configuration for release n.
func (w *World) Config(n uint64, id string) enclave.Config {
	return enclave.Config{InstanceID: id, ReleaseNumber: n, ManifestKeys: []*ecdsa.PublicKey{&w.Key.PublicKey},
		SealAccount: KMSAccount, SealRegion: KMSRegion,
		RetirementPrincipal: RetirementRole, RetirementWindowDays: RetirementWindow, DeviceAttest: Policy(), RelayURL: w.RelayURL, KDF: vault.MinKDF}
}

// Start starts an instance of release n (one per release).
func (w *World) Start(n uint64) (*enclave.Instance, error) {
	return w.StartWith(n, nil)
}

// StartWith starts an instance with its config adjusted.
func (w *World) StartWith(n uint64, tweak func(*enclave.Config)) (*enclave.Instance, error) {
	w.mu.Lock()
	r, ok := w.spec(n)
	w.nextInst++
	id := "i-test-" + string(rune('0'+w.nextInst%10))
	w.mu.Unlock()
	if !ok {
		return nil, errors.New("enclavetest: unknown release")
	}
	cfg := w.Config(n, id)
	if tweak != nil {
		tweak(&cfg)
	}
	vo := w.VaultOptions
	if vo.Relay == nil {
		vo.Relay = func(base string, key ed25519.PrivateKey) vault.Relay { return w.Relays.New(base, key) }
	}
	in, err := enclave.New(enclave.Options{Config: cfg, NSM: NewFakeNSM(r.PCR0, r.PCR1, r.PCR2, w.Now), KMS: w.KMS,
		Store: w.Store, StatusList: w.StatusList, Vault: vo, Features: w.Features, Lifecycle: w.record, Stopped: w.Stopped, Now: w.Now})
	if err != nil {
		return nil, err
	}
	w.mu.Lock()
	if old := w.instances[r.PCR0Hex()]; old != nil {
		w.mu.Unlock()
		old.Close(context.Background())
		w.mu.Lock()
	}
	w.instances[r.PCR0Hex()] = in
	w.mu.Unlock()
	return in, nil
}

// Instance returns the running instance of a release.
func (w *World) Instance(n uint64) *enclave.Instance {
	w.mu.Lock()
	defer w.mu.Unlock()
	r, _ := w.spec(n)
	return w.instances[r.PCR0Hex()]
}

// SetStatusList replaces the cached attestation status list.
func (w *World) SetStatusList(l *devattest.StatusList) {
	w.mu.Lock()
	w.list = l
	w.mu.Unlock()
}

// StatusList is the instances' status-list source.
func (w *World) StatusList() *devattest.StatusList {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.list
}

func (w *World) record(ev vault.LifecycleEvent) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.events = append(w.events, ev)
	switch ev.Event {
	case "enrolled", "moved":
		w.sealedTo[ev.VaultID] = ev.Release
	}
}

// Events returns the lifecycle events so far.
func (w *World) Events() []vault.LifecycleEvent {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]vault.LifecycleEvent(nil), w.events...)
}

// SealedRelease is the routing value the parent wrote (§11.10.5).
func (w *World) SealedRelease(vaultID string) string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.sealedTo[vaultID]
}

// ErrReleaseStarting is the API's 503 release_starting (§11.10.5).
var ErrReleaseStarting = errors.New("enclavetest: release_starting")

// Enclave answers GET /api/vault/enclave: the instance of the vault's
// sealed_release (or, with release set, of that release; for enrollment
// vaultID is "" and an active release's instance answers).
func (w *World) Enclave(vaultID, release string) (desc, att []byte, in *enclave.Instance, err error) {
	w.mu.Lock()
	if release == "" && vaultID != "" {
		release = w.sealedTo[vaultID]
	}
	if release == "" {
		for i := len(w.releases) - 1; i >= 0; i-- {
			if w.releases[i].Status == manifest.StatusActive && w.instances[w.releases[i].PCR0Hex()] != nil {
				release = w.releases[i].PCR0Hex()
				break
			}
		}
	}
	in = w.instances[release]
	w.mu.Unlock()
	if in == nil {
		return nil, nil, nil, ErrReleaseStarting
	}
	desc, att = in.Descriptor()
	return desc, att, in, nil
}

// Post plays POST /api/vault/{enroll,unlock} through the queue and parent
// to the instance and returns the response slot's envelope.
func (w *World) Post(ctx context.Context, in *enclave.Instance, op, vaultID, userGUID string, r *client.Request) (*enclave.Response, error) {
	kid, err := suite.ParseKidHex(r.ETKKid)
	if err != nil {
		return nil, err
	}
	q := &enclave.QueueMessage{Op: op, VaultID: vaultID, UserGUID: userGUID, RequestID: r.RequestID, ETKKid: kid,
		Envelope: r.Envelope, EnqueuedAt: w.Now()}
	if op == enclave.OpEnroll || op == enclave.OpRecoveryRegister {
		q.AppKey = r.AppKey // the key the API checked the request's signature with (0.15.0)
	}
	if op == enclave.OpUnlock && w.Account != nil {
		q.Account = w.Account(userGUID) // §11.13
	}
	var doc []byte
	if op == enclave.OpEnroll || op == enclave.OpUnlock {
		q.ManifestSHA256 = r.ManifestSHA256
		doc = w.ManifestDoc(r.ManifestSHA256)
	}
	raw := in.ProcessRaw(ctx, q.Marshal(), doc)
	if raw == nil {
		return nil, enclave.ErrMalformed
	}
	return enclave.ParseResponse(raw)
}

// Lock plays POST /api/vault/lock.
func (w *World) Lock(ctx context.Context, in *enclave.Instance, vaultID, userGUID string) {
	rid, _ := envelope.NewULID(w.Now())
	q := &enclave.QueueMessage{Op: enclave.OpLock, VaultID: vaultID, UserGUID: userGUID, RequestID: rid, EnqueuedAt: w.Now()}
	in.Process(ctx, q, nil)
}

// Close stops every instance.
func (w *World) Close() {
	w.mu.Lock()
	ins := make([]*enclave.Instance, 0, len(w.instances))
	for _, in := range w.instances {
		ins = append(ins, in)
	}
	w.mu.Unlock()
	for _, in := range ins {
		in.Close(context.Background())
	}
}

// SetSerial sets the serial the next Publish increments from (tools that
// publish across processes keep serials increasing).
func (w *World) SetSerial(n uint64) {
	w.mu.Lock()
	w.serial = n
	w.mu.Unlock()
}

// SetSealedRelease records a routing value (as the parent would from a
// lifecycle event).
func (w *World) SetSealedRelease(vaultID, release string) {
	w.mu.Lock()
	w.sealedTo[vaultID] = release
	w.mu.Unlock()
}

// Spec returns the test release spec of release n: PCR bytes derived from
// the number (TEST ONLY).
func Spec(n uint64, status string) ReleaseSpec {
	return ReleaseSpec{Number: n, PCR0: byte(0xa0 + n), PCR1: byte(0x10 + n), PCR2: byte(0x20 + n), Status: status}
}

// Recovery plays POST /api/vault/recovery: the API's request id is the
// recovery id; the response slot holds the code sealed to browserKey.
func (w *World) Recovery(ctx context.Context, in *enclave.Instance, vaultID, userGUID string, browserKey []byte) (string, *enclave.Response) {
	rid, _ := envelope.NewULID(w.Now())
	q := &enclave.QueueMessage{Op: enclave.OpRecovery, VaultID: vaultID, UserGUID: userGUID, RequestID: rid, EnqueuedAt: w.Now(),
		BrowserKey: browserKey}
	return rid, in.Process(ctx, q, nil)
}

// RecoveryCancel plays a cancel from the portal or the email link: it ends
// whatever recovery is in progress.
func (w *World) RecoveryCancel(ctx context.Context, in *enclave.Instance, vaultID, userGUID string) {
	rid, _ := envelope.NewULID(w.Now())
	q := &enclave.QueueMessage{Op: enclave.OpRecoveryCancel, VaultID: vaultID, UserGUID: userGUID, RequestID: rid, EnqueuedAt: w.Now()}
	in.Process(ctx, q, nil)
}
