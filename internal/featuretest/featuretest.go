// Package featuretest is a test harness for feature packages: a fake
// vault.Host that records what a handler did, and Call, which applies the
// same sender-kind authorization as the vault runtime before Handle. It is
// test-only and must never be linked into release packages (make
// check-tcb).
package featuretest

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// Sent is one message a handler queued.
type Sent struct {
	To   string // connection id, or "devices"/"devices-except:<id>"
	Type string
	Body json.RawMessage
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
}

// NewHost returns a fake host with no connections.
func NewHost() *Host {
	return &Host{ID: "test-vault", Conns: map[string]vault.PeerInfo{}, Profiles: map[string]json.RawMessage{}, DownConns: map[string]bool{}}
}

// AddConnection adds an active connection.
func (h *Host) AddConnection(id string) {
	h.Conns[id] = vault.PeerInfo{ID: id, Kind: vault.KindConnection, State: vault.PeerActive}
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
	from := vault.PeerInfo{ID: "dev-" + kind, Kind: kind, State: vault.PeerActive}
	if kind == "recovering-app" { // an app registered by recovery (§11.11.5)
		from = vault.PeerInfo{ID: "dev-recovering", Kind: vault.KindApp, State: vault.PeerActive, Recovering: true}
	}
	if len(kind) > 11 && kind[:11] == "connection:" {
		from = vault.PeerInfo{ID: kind[11:], Kind: vault.KindConnection, State: vault.PeerActive}
	}
	if !spec.Allows(from.Kind) {
		return Result{Code: "forbidden"}
	}
	in := &envelope.Inner{ID: id, Type: typ, TS: now, Body: json.RawMessage(body)}
	s := vault.NewSession(context.Background(), h, from, now, in)
	out, err := f.Handle(context.Background(), s, in)
	if err != nil {
		var he *vault.HandlerError
		if errors.As(err, &he) {
			return Result{Code: he.Code}
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
