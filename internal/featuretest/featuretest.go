// Package featuretest is a test harness for feature packages: a fake
// vault.Host that records what a handler did, and Call, which applies the
// same sender-kind authorization as the vault runtime before Handle. It is
// test-only and must never be linked into release packages (make
// check-tcb).
package featuretest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/callwire"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/leashwire"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Sent is one message a handler queued.
type Sent struct {
	To   string // connection or device id, or "devices"/"devices-except:<id>"
	Type string
	Body json.RawMessage
	Opt  vault.SendOptions
}

// Host is a fake vault.Host.
type Host struct {
	ID         string
	Conns      map[string]vault.PeerInfo
	Sent       []Sent
	Activities []vault.Activity
	Profiles   map[string]json.RawMessage
	Rotations  int
	RotateErr  error
	Set        vault.Settings
	Sinks      []vault.ActivitySink
	ids        int
	DownConns  map[string]bool // SendToConnection fails for these
	Completed  []string        // CompleteRecovery calls
	Devices    map[string]vault.PeerInfo
	IK         ed25519.PublicKey
	// Identity is the fake vault's identity key (IK is its public half).
	Identity ed25519.PrivateKey
	// Introductions' invitations (§10.15).
	IntroInvites  []IntroInvite
	AcceptedLinks []string
	Cancelled     []string
	InviteErr     error
	// The fake vault's identity rotation chain (RotationsFrom).
	ChainFrom []byte
	Chain     []json.RawMessage
	// LastActive is OwnerLastActive's answer (§9.2 presence).
	LastActive time.Time
	// One app per vault (vault.CredentialHost, §6.7.1, §3.5.9): the PIN
	// VerifyPIN accepts, the transfer in progress, the transfers ended
	// (id:reason) and the host alarms reported.
	PIN       string
	Xfer      *vault.TransferInfo
	XferEnded []string
	Alarms    []string
	// Deletions are the vault deletions started (vault.DeleteHost), by via.
	Deletions []string
	// The daily owner check (vault.OwnerCheckHost, §3.6): the state
	// OwnerCheckState reports ("" = ok), the checks passed (with their
	// hold changes, nil for none), the failures by ref, and how often the
	// clock was started at enrollment.
	Hold        string
	Passed      []*vault.HoldChange
	PassedAudit []bool
	CheckFailed []string
	Enrolled    int
	CheckInfo   vault.OwnerCheckInfo
	// The account's names (vault.ProfileHost, 0.18.0, §10.8; "" for
	// none: NewHost sets Ada Lovelace), the peers' earlier identity keys
	// by connection id, the snapshot's name_change.allowed_after and the
	// name requests recorded (vault.NameRequestHost).
	FirstName, LastName string
	PriorIKs            map[string][][]byte
	AllowedAfter        time.Time
	NameRequests        []vault.NameChange
	// Asks from connections (vault.AskHost, §10.4.1, 0.23.0): with AsksOn
	// the host keeps each connection's state as the vault does
	// (vault.CheckAsk); OtherPending are the asks other features hold per
	// connection, AskRand the delay's draw (nil: crypto/rand). Without
	// AsksOn every ask passes.
	AsksOn       bool
	Asks         map[string]*vault.AskState
	OtherPending map[string]int
	AskRand      func(n int64) int64
	// AskSources are the features whose pending asks count, by name (the
	// asking feature's own are skipped, as the vault does).
	AskSources map[string]vault.AskSource
}

func (h *Host) askState(conn string) *vault.AskState {
	if h.Asks == nil {
		h.Asks = map[string]*vault.AskState{}
	}
	st := h.Asks[conn]
	if st == nil {
		st = &vault.AskState{}
		h.Asks[conn] = st
	}
	return st
}

// Ask implements vault.AskHost.
func (h *Host) Ask(conn string, a vault.Ask, now time.Time) vault.AskVerdict {
	if !h.AsksOn {
		return vault.AskVerdict{Cooled: make([]bool, len(a.Idents))}
	}
	others := h.OtherPending[conn]
	for name, src := range h.AskSources {
		if name != a.Source {
			others += src.PendingAsks(conn, now)
		}
	}
	return vault.CheckAsk(h.askState(conn), conn, a, others, now, vault.AskDelay(h.AskRand),
		func(x vault.Activity) { h.Record(x, now) })
}

// AskDeclined implements vault.AskHost.
func (h *Host) AskDeclined(conn string, idents []string, now time.Time) {
	if !h.AsksOn {
		return
	}
	if vault.DeclineAsk(h.askState(conn), idents, now) {
		h.Record(vault.Activity{Kind: "connection.asks_paused", ConnectionID: conn, Audit: true, Feed: true, Priority: "high"}, now)
	}
}

// ReleaseAsks sends the held neutral answers due at now, as the vault's
// housekeeping does, and returns them.
func (h *Host) ReleaseAsks(now time.Time) []vault.HeldAnswer {
	var out []vault.HeldAnswer
	conns := make([]string, 0, len(h.Asks))
	for c := range h.Asks {
		conns = append(conns, c)
	}
	sort.Strings(conns)
	for _, c := range conns {
		for _, a := range vault.DueAnswers(h.Asks[c], now) {
			_ = h.SendToConnection(c, a.Type, a.Body, now)
			out = append(out, a)
		}
	}
	return out
}

// AccountNames implements vault.ProfileHost.
func (h *Host) AccountNames() (string, string, bool) {
	return h.FirstName, h.LastName, h.FirstName != "" && h.LastName != ""
}

// PriorIdentity implements vault.ProfileHost.
func (h *Host) PriorIdentity(id string, ik []byte) bool {
	for _, k := range h.PriorIKs[id] {
		if bytes.Equal(k, ik) {
			return true
		}
	}
	return false
}

// AccountAllowedAfter implements vault.NameRequestHost.
func (h *Host) AccountAllowedAfter() time.Time { return h.AllowedAfter }

// RequestAccountName implements vault.NameRequestHost: the request is
// recorded with the next seq.
func (h *Host) RequestAccountName(first, last, _ string, now time.Time) json.RawMessage {
	n := vault.NameChange{Seq: uint64(len(h.NameRequests) + 1), FirstName: first, LastName: last}
	h.NameRequests = append(h.NameRequests, n)
	r := &vault.NameRequest{Seq: n.Seq, FirstName: first, LastName: last, RequestedAt: now.UTC().Truncate(time.Millisecond), State: vault.NamePending}
	return r.JSON()
}

// OwnerCheckState implements vault.OwnerCheckHost.
func (h *Host) OwnerCheckState(time.Time) string {
	if h.Hold == "" {
		return vault.OwnerCheckOK
	}
	return h.Hold
}

// OwnerCheckPassed implements vault.OwnerCheckHost.
func (h *Host) OwnerCheckPassed(c *vault.HoldChange, audit bool, _ string, now time.Time) vault.OwnerCheckInfo {
	h.Passed = append(h.Passed, c)
	h.PassedAudit = append(h.PassedAudit, audit)
	h.Hold = ""
	i := h.CheckInfo
	if i.Interval == 0 {
		i.Interval = vault.DefaultOwnerCheckInterval
	}
	i.Deadline = now.Add(i.Interval)
	i.Hold = c == nil || c.On
	if c != nil && !c.On && !c.Until.IsZero() {
		u := c.Until
		i.HoldOffUntil = &u
	}
	return i
}

// OwnerCheckFailed implements vault.OwnerCheckHost.
func (h *Host) OwnerCheckFailed(ref string, _ time.Time) { h.CheckFailed = append(h.CheckFailed, ref) }

// OwnerCheckEnrolled implements vault.OwnerCheckHost.
func (h *Host) OwnerCheckEnrolled(time.Time) { h.Enrolled++ }

// DeleteVault implements vault.DeleteHost.
func (h *Host) DeleteVault(via string, _ time.Time) error {
	h.Deletions = append(h.Deletions, via)
	return nil
}

// VerifyPIN implements vault.CredentialHost.
func (h *Host) VerifyPIN(pin string, _ time.Time) error {
	if h.PIN == "" || pin != h.PIN {
		return vault.NewError("bad_pin", "")
	}
	return nil
}

// CreateTransfer implements vault.CredentialHost.
func (h *Host) CreateTransfer(_ context.Context, by string, now time.Time) (string, string, time.Time, error) {
	if h.Xfer != nil {
		return "", "", time.Time{}, vault.NewError("exists", "")
	}
	id, _ := envelope.NewULID(now)
	h.Xfer = &vault.TransferInfo{ID: id, OldDevice: by, State: vault.TransferOpen, Exp: now.Add(10 * time.Minute)}
	return id, "https://vettid.org/i#test", h.Xfer.Exp, nil
}

// Transfer implements vault.CredentialHost.
func (h *Host) Transfer() (vault.TransferInfo, bool) {
	if h.Xfer == nil {
		return vault.TransferInfo{}, false
	}
	return *h.Xfer, true
}

// ApproveTransfer implements vault.CredentialHost. The runtime completes
// the transfer after the handler returns (0.10.3); the test calls
// TransferCompleted itself.
func (h *Host) ApproveTransfer(_ context.Context, id string, now time.Time) error {
	if h.Xfer == nil || h.Xfer.ID != id || !h.Xfer.Scanned {
		return vault.NewError("not_found", "")
	}
	h.Xfer.State = vault.TransferApproved
	return nil
}

// EndTransfer implements vault.CredentialHost.
func (h *Host) EndTransfer(id, reason string, _ time.Time) error {
	if h.Xfer == nil || h.Xfer.ID != id {
		return vault.NewError("not_found", "")
	}
	h.Xfer = nil
	h.XferEnded = append(h.XferEnded, id+":"+reason)
	return nil
}

// ReportAlarm implements vault.CredentialHost.
func (h *Host) ReportAlarm(kind string) { h.Alarms = append(h.Alarms, kind) }

// NewHost returns a fake host with no connections.
func NewHost() *Host {
	id := ed25519.NewKeyFromSeed(identitySeed())
	ik := id.Public().(ed25519.PublicKey)
	return &Host{Identity: id, ID: "test-vault", Conns: map[string]vault.PeerInfo{}, Profiles: map[string]json.RawMessage{}, DownConns: map[string]bool{},
		Devices: map[string]vault.PeerInfo{}, IK: ik, FirstName: "Ada", LastName: "Lovelace"}
}

// SetIdentity gives the fake vault the identity key of seed byte b.
func (h *Host) SetIdentity(b byte) {
	h.Identity = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{b}, 32))
	h.IK = h.Identity.Public().(ed25519.PublicKey)
}

// DeviceKey is the deterministic identity key of a test device id.
func DeviceKey(id string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("featuretest-device|" + id))
	return ed25519.NewKeyFromSeed(seed[:])
}

// AddDevice adds an active owner device (id "dev-<kind>" is what Call
// uses) with the identity key DeviceKey(id).
func (h *Host) AddDevice(id, kind string) {
	h.Devices[id] = vault.PeerInfo{ID: id, Kind: kind, State: vault.PeerActive, IK: DeviceKey(id).Public().(ed25519.PublicKey)}
}

func (h *Host) IdentityKey() ed25519.PublicKey { return h.IK }

// identitySeed is the fake vault's identity key seed (all zero).
func identitySeed() []byte { return make([]byte, 32) }

func (h *Host) SignICEConfig(config []byte) ([]byte, error) {
	if _, err := callwire.ParseICEConfig(config); err != nil {
		return nil, err
	}
	return callwire.SignICE(h.Identity, config)
}

func (h *Host) VouchCallShare(deviceIK ed25519.PublicKey, m []byte) ([]byte, error) {
	if len(deviceIK) != ed25519.PublicKeySize || !callwire.ValidShareMessage(m) {
		return nil, errors.New("not a share")
	}
	return suite.Sign(h.Identity, callwire.LabelVouch, callwire.VouchMessage(deviceIK, m))
}

func (h *Host) Device(id string) (vault.PeerInfo, bool) {
	p, ok := h.Devices[id]
	return p, ok
}

// IntroInvite is a recorded CreateIntroInvite call.
type IntroInvite struct {
	ID, Link, IntroBy string
	ExpectIK          []byte
}

func (h *Host) CreateIntroInvite(_ context.Context, ik []byte, by string, now time.Time) (string, string, error) {
	if h.InviteErr != nil {
		return "", "", h.InviteErr
	}
	id := h.NewID(now)
	inv := IntroInvite{ID: id, Link: "vettid://invite/" + id, IntroBy: by, ExpectIK: append([]byte(nil), ik...)}
	h.IntroInvites = append(h.IntroInvites, inv)
	return inv.ID, inv.Link, nil
}

func (h *Host) AcceptInviteLink(_ context.Context, link, _ string, now time.Time) (string, error) {
	if h.InviteErr != nil {
		return "", h.InviteErr
	}
	h.AcceptedLinks = append(h.AcceptedLinks, link)
	return h.NewID(now), nil
}

func (h *Host) CancelInvite(id string, _ time.Time) { h.Cancelled = append(h.Cancelled, id) }

func (h *Host) SignLeashStatus(statement []byte) ([]byte, error) {
	return leashwire.SignStatus(h.Identity, statement)
}

// Chain is the fake vault's rotation chain for RotationsFrom: statements
// from the key ChainFrom to the current IK.
func (h *Host) RotationsFrom(ik []byte) ([]json.RawMessage, bool) {
	if bytes.Equal(ik, h.IK) {
		return nil, true
	}
	if h.ChainFrom != nil && bytes.Equal(ik, h.ChainFrom) {
		return h.Chain, true
	}
	return nil, false
}

func (h *Host) OwnerLastActive() time.Time { return h.LastActive }

// ListedDevice implements vault.DeviceLister: any device in Devices.
func (h *Host) ListedDevice(id string) (vault.PeerInfo, bool) {
	p, ok := h.Devices[id]
	return p, ok
}

func (h *Host) PairedDevice(id string) (vault.PeerInfo, bool) {
	p, ok := h.Devices[id]
	return p, ok
}

func (h *Host) Send(to, typ string, body json.RawMessage, o vault.SendOptions, _ time.Time) error {
	_, conn := h.Conns[to]
	_, dev := h.Devices[to]
	if !conn && !dev || h.DownConns[to] {
		return vault.ErrNoSession
	}
	h.Sent = append(h.Sent, Sent{To: to, Type: typ, Body: append(json.RawMessage(nil), body...), Opt: o})
	return nil
}

func (h *Host) NotifyDevicesWith(typ string, body json.RawMessage, except string, o vault.SendOptions, _ time.Time) {
	to := "devices"
	if except != "" {
		to = "devices-except:" + except
	}
	h.Sent = append(h.Sent, Sent{To: to, Type: typ, Body: append(json.RawMessage(nil), body...), Opt: o})
}

// AddConnection adds an active connection.
func (h *Host) AddConnection(id string) {
	ik := ed25519.NewKeyFromSeed(append(make([]byte, 31), byte(len(h.Conns)+1))).Public().(ed25519.PublicKey)
	h.Conns[id] = vault.PeerInfo{ID: id, Kind: vault.KindConnection, State: vault.PeerActive, IK: ik}
}

func (h *Host) VaultID() string { return h.ID }

func (h *Host) Connection(id string) (vault.PeerInfo, bool) {
	p, ok := h.Conns[id]
	return p, ok
}

func (h *Host) Connections() []vault.PeerInfo {
	var out []vault.PeerInfo
	for _, p := range h.Conns {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (h *Host) SendToConnection(id, typ string, body json.RawMessage, _ time.Time) error {
	if _, ok := h.Conns[id]; !ok || h.DownConns[id] {
		return vault.ErrNoSession
	}
	h.Sent = append(h.Sent, Sent{To: id, Type: typ, Body: append(json.RawMessage(nil), body...)})
	return nil
}

func (h *Host) NotifyDevices(typ string, body json.RawMessage, except string, _ time.Time) {
	to := "devices"
	if except != "" {
		to = "devices-except:" + except
	}
	h.Sent = append(h.Sent, Sent{To: to, Type: typ, Body: append(json.RawMessage(nil), body...)})
}

func (h *Host) NewID(now time.Time) string {
	h.ids++
	id, _ := envelope.NewULID(now.Add(time.Duration(h.ids) * time.Millisecond))
	return id
}

func (h *Host) Record(a vault.Activity, now time.Time) {
	h.Activities = append(h.Activities, a)
	for _, s := range h.Sinks {
		s.RecordActivity(vault.NewSession(context.Background(), h, vault.PeerInfo{}, now, nil), a)
	}
}

func (h *Host) SetConnectionProfile(id string, p json.RawMessage, _ time.Time) error {
	if _, ok := h.Conns[id]; !ok {
		return errors.New("no connection")
	}
	h.Profiles[id] = append(json.RawMessage(nil), p...)
	return nil
}

func (h *Host) RotateIdentity(time.Time) error {
	if h.RotateErr != nil {
		return h.RotateErr
	}
	h.Rotations++
	return nil
}

func (h *Host) CompleteRecovery(id string, _ time.Time) error {
	h.Completed = append(h.Completed, id)
	return nil
}

func (h *Host) Settings() vault.Settings     { return h.Set }
func (h *Host) SetSettings(s vault.Settings) { h.Set = s }

// Reset forgets recorded messages and activities.
func (h *Host) Reset() { h.Sent, h.Activities = nil, nil }

// SentOfType returns the recorded messages of a type.
func (h *Host) SentOfType(typ string) []Sent {
	var out []Sent
	for _, s := range h.Sent {
		if s.Type == typ {
			out = append(out, s)
		}
	}
	return out
}

// HasActivity reports whether an activity of kind was recorded.
func (h *Host) HasActivity(kind string) bool {
	for _, a := range h.Activities {
		if a.Kind == kind {
			return true
		}
	}
	return false
}

// Result is the outcome of Call.
type Result struct {
	Body json.RawMessage
	Code string // "" for success
}

// OK reports success.
func (r Result) OK() bool { return r.Code == "" }

// Obj parses the body.
func (r Result) Obj(t testing.TB) strictjson.Object {
	t.Helper()
	b := r.Body
	if b == nil {
		b = json.RawMessage(`{}`)
	}
	o, err := strictjson.ParseObject(b)
	if err != nil {
		t.Fatalf("response body: %v", err)
	}
	return o
}

// Clock is a settable clock for Call.
type Clock struct{ T time.Time }

// Advance moves the clock.
func (c *Clock) Advance(d time.Duration) { c.T = c.T.Add(d) }

// Call sends a message of typ with body from a principal of kind (id
// "dev-<kind>" or the connection id for "connection:<id>") to f, applying
// the runtime's authorization (§10.1): an unknown type is
// unsupported_type, a sender kind not in TypeSpec.From is forbidden.
func Call(f vault.Feature, h *Host, now time.Time, kind, typ, body string) Result {
	id, _ := envelope.NewULID(now)
	return CallID(f, h, now, kind, typ, id, body)
}

// CallID is Call with a chosen inner id (payloads bound to it, §3.5.4).
func CallID(f vault.Feature, h *Host, now time.Time, kind, typ, id, body string) Result {
	return CallInner(f, h, now, kind, &envelope.Inner{ID: id, Type: typ, TS: now, Body: json.RawMessage(body)})
}

// CallExp is Call with an inner `exp` (offers, ephemeral types).
func CallExp(f vault.Feature, h *Host, now, exp time.Time, kind, typ, body string) Result {
	id, _ := envelope.NewULID(now)
	return CallInner(f, h, now, kind, &envelope.Inner{ID: id, Type: typ, TS: now, Exp: exp, Body: json.RawMessage(body)})
}

// CallInner delivers a complete inner plaintext from a principal of kind.
func CallInner(f vault.Feature, h *Host, now time.Time, kind string, in *envelope.Inner) Result {
	typ := in.Type
	var spec *vault.TypeSpec
	for _, ts := range f.Types() {
		if ts.Type == typ {
			ts := ts
			spec = &ts
		}
	}
	if spec == nil {
		return Result{Code: "unsupported_type"}
	}
	from := vault.PeerInfo{ID: "dev-" + kind, Kind: kind, State: vault.PeerActive, IK: DeviceKey("dev-" + kind).Public().(ed25519.PublicKey)}
	if kind == "app2" { // another app device (one app per vault: a clone's presenter, §3.5.9)
		from = vault.PeerInfo{ID: "dev-app2", Kind: vault.KindApp, State: vault.PeerActive}
	}
	if kind == "recovering-app" { // an app registered by recovery (§11.11.5)
		from = vault.PeerInfo{ID: "dev-recovering", Kind: vault.KindApp, State: vault.PeerActive, Recovering: true}
	}
	if len(kind) > 11 && kind[:11] == "connection:" {
		from = vault.PeerInfo{ID: kind[11:], Kind: vault.KindConnection, State: vault.PeerActive}
		if c, ok := h.Conns[from.ID]; ok {
			from.IK = c.IK // the pinned ik (§10.8 profile.update's check)
		}
	}
	if !spec.Allows(from.Kind) {
		return Result{Code: "forbidden"}
	}
	s := vault.NewSession(context.Background(), h, from, now, in)
	out, err := f.Handle(context.Background(), s, in)
	if err != nil {
		var he *vault.HandlerError
		if errors.As(err, &he) {
			return Result{Code: he.Code, Body: he.Body}
		}
		return Result{Code: "internal"}
	}
	return Result{Body: out}
}

// RoundTrip saves f's state and loads it into g (a fresh instance), as a
// flush and unlock would.
func RoundTrip(t testing.TB, f, g vault.Feature) {
	t.Helper()
	raw, err := f.Save()
	if err != nil {
		t.Fatal(err)
	}
	if err := g.Load(raw); err != nil {
		t.Fatal(err)
	}
}
