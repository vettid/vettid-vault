// Package calls is 1:1 call signalling between connections and to the
// owner's devices (VAULT-MESSAGING §10.10, CALLING-SERVICE §6, §7, §9).
//
// Offers, answers and hang-ups are durable messages; trickle ICE and
// ringing are ephemeral (memory-only, with `exp`). The vault issues its own
// devices a signed ICE configuration for each call. The media key is
// agreed between the two devices (vms/callwire): the vaults relay the
// caller device's ephemeral KEM key and the answering device's `enc`, and
// never hold k_call.
//
// Ported from vettid.dev's calls.go: the X25519 key pair the vault held
// per call (and the shared secret it forwarded to the app) is replaced by
// the device-to-device hybrid KEM; the separate initiate/accept/reject/
// cancel/offer/answer/candidate/busy/blocked peer events collapse into
// offer, answer, ice, ringing and end with a reason; the vault's TURN
// proxy (Cloudflare via the parent) becomes the ICEIssuer interface.
package calls

import (
	"context"
	"crypto/hmac"
	"crypto/sha1" // coturn use-auth-secret is HMAC-SHA1 (CALLING-SERVICE §5)
	"encoding/base64"
	"encoding/json"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/callwire"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// Limits and times (§10.10).
const (
	OfferTTL        = 45 * time.Second
	EphemeralTTL    = 30 * time.Second
	ICETTL          = 6 * time.Hour  // ICE credentials and the configuration's exp
	MaxCallDuration = 12 * time.Hour // an active call older than this no longer counts as busy
	MaxSDP          = 32 * 1024
	MaxCandidate    = 1024
	MaxCandidates   = 16
	MaxICEPerCall   = 256
	MaxHistory      = 200
	DefaultLimit    = 50
)

// Directions, states and end reasons.
const (
	DirIn  = "in"
	DirOut = "out"

	StateRinging = "ringing"
	StateActive  = "active"
	StateEnded   = "ended"
)

// Reasons are the call.end reasons.
var Reasons = map[string]bool{"hangup": true, "decline": true, "busy": true, "timeout": true,
	"answered_elsewhere": true, "unavailable": true, "failed": true}

// ICEIssuer issues a call's ICE servers and short-lived credentials
// (CALLING-SERVICE §5). It is the only provider-specific code in the call
// path.
type ICEIssuer interface {
	Issue(ctx context.Context, callID string, ttl time.Duration) ([]callwire.ICEServer, error)
}

// NoServers issues an empty list: devices use host and server-reflexive
// candidates only. It is the default until a calling service exists.
type NoServers struct{}

// Issue implements ICEIssuer.
func (NoServers) Issue(context.Context, string, time.Duration) ([]callwire.ICEServer, error) {
	return nil, nil
}

// Coturn issues coturn `use-auth-secret` credentials: username =
// "<expiry>:<call_id>", credential = base64(HMAC-SHA1(secret, username)).
// STUN entries carry no credentials.
type Coturn struct {
	STUN   []string
	TURN   []string
	Secret []byte
	Now    func() time.Time
}

// Issue implements ICEIssuer.
func (c Coturn) Issue(_ context.Context, callID string, ttl time.Duration) ([]callwire.ICEServer, error) {
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	var out []callwire.ICEServer
	if len(c.STUN) > 0 {
		out = append(out, callwire.ICEServer{URLs: c.STUN})
	}
	if len(c.TURN) > 0 && len(c.Secret) > 0 {
		user := strconv.FormatInt(now().Add(ttl).Unix(), 10) + ":" + callID
		mac := hmac.New(sha1.New, c.Secret)
		mac.Write([]byte(user))
		out = append(out, callwire.ICEServer{URLs: c.TURN, Username: user, Credential: base64.StdEncoding.EncodeToString(mac.Sum(nil))})
	}
	return out, nil
}

// Call is one call record.
type Call struct {
	ID       string    `json:"id"`
	Conn     string    `json:"conn"`
	Dir      string    `json:"dir"`
	Media    string    `json:"media"`
	State    string    `json:"state"`
	Device   string    `json:"device,omitempty"` // the local device of the call
	Reason   string    `json:"reason,omitempty"`
	Created  time.Time `json:"created"`
	Exp      time.Time `json:"exp"` // the offer's exp
	Answered time.Time `json:"answered,omitempty"`
	Ended    time.Time `json:"ended,omitempty"`
	Rang     bool      `json:"rang,omitempty"`
	ICE      int       `json:"ice,omitempty"`
}

func (c *Call) live(now time.Time) bool {
	switch c.State {
	case StateRinging:
		return now.Before(c.Exp)
	case StateActive:
		return now.Sub(c.Answered) < MaxCallDuration
	}
	return false
}

// Options configure the feature.
type Options struct {
	// ICE issues ICE servers; nil means NoServers.
	ICE ICEIssuer
}

// Feature implements vault.Feature and vault.ConnectionRemovedObserver.
type Feature struct {
	mu     sync.Mutex
	issuer ICEIssuer
	calls  map[string]*Call
}

// New returns the feature.
func New(o Options) *Feature {
	if o.ICE == nil {
		o.ICE = NoServers{}
	}
	return &Feature{issuer: o.ICE, calls: map[string]*Call{}}
}

var (
	owners = []string{vault.KindApp, vault.KindDesktop}
	both   = []string{vault.KindApp, vault.KindDesktop, vault.KindConnection}
	conns  = []string{vault.KindConnection}
)

// Name implements vault.Feature.
func (f *Feature) Name() string { return "calls" }

// Types implements vault.Feature.
func (f *Feature) Types() []vault.TypeSpec {
	return []vault.TypeSpec{
		{Type: "call.start", Request: true, From: owners},
		{Type: "call.list", Request: true, From: owners},
		{Type: "call.offer", From: conns},
		{Type: "call.answer", From: both},
		{Type: "call.end", From: both},
		{Type: "call.ice", Ephemeral: true, From: both},
		{Type: "call.ringing", Ephemeral: true, From: both},
	}
}

// Load implements vault.Feature.
func (f *Feature) Load(data json.RawMessage) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := map[string]*Call{}
	if err := json.Unmarshal(data, &c); err != nil {
		return err
	}
	f.calls = c
	return nil
}

// Save implements vault.Feature.
func (f *Feature) Save() (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return json.Marshal(f.calls)
}

var (
	errBad      = vault.NewError("bad_request", "")
	errNotFound = vault.NewError("not_found", "")
	errBusy     = vault.NewError("busy", "")
	errConn     = vault.NewError("connection_unavailable", "")
	errInternal = vault.NewError("internal", "")
)

// Handle implements vault.Handler.
func (f *Feature) Handle(ctx context.Context, s *vault.Session, in *envelope.Inner) (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fromConn := s.From().Kind == vault.KindConnection
	switch in.Type {
	case "call.start":
		return f.start(ctx, s, in.Body)
	case "call.list":
		return f.list(in.Body)
	case "call.offer":
		return nil, f.offer(ctx, s, in)
	case "call.answer":
		if fromConn {
			return nil, f.answerFromPeer(s, in.Body)
		}
		return nil, f.answerFromDevice(s, in.Body)
	case "call.end":
		return nil, f.end(s, in.Body, fromConn)
	case "call.ice":
		return nil, f.ice(s, in.Body, fromConn)
	case "call.ringing":
		return nil, f.ringing(s, in.Body, fromConn)
	}
	return nil, vault.NewError("unsupported_type", "")
}

func (f *Feature) busy(now time.Time) bool {
	for _, c := range f.calls {
		if c.live(now) {
			return true
		}
	}
	return false
}

// prune keeps the newest MaxHistory calls (live calls always kept).
func (f *Feature) prune(now time.Time) {
	if len(f.calls) <= MaxHistory {
		return
	}
	ids := f.sorted()
	for _, id := range ids[MaxHistory:] {
		if !f.calls[id].live(now) {
			delete(f.calls, id)
		}
	}
}

// sorted returns call ids newest first.
func (f *Feature) sorted() []string {
	ids := make([]string, 0, len(f.calls))
	for id := range f.calls {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		a, b := f.calls[ids[i]], f.calls[ids[j]]
		if !a.Created.Equal(b.Created) {
			return a.Created.After(b.Created)
		}
		return ids[i] > ids[j]
	})
	return ids
}

// iceFor issues and signs this vault's ICE configuration for a call.
func (f *Feature) iceFor(ctx context.Context, s *vault.Session, callID string) (cfg, sig []byte, err error) {
	servers, err := f.issuer.Issue(ctx, callID, ICETTL)
	if err != nil {
		return nil, nil, err
	}
	c := &callwire.ICEConfig{CallID: callID, Exp: s.Now().Add(ICETTL).UTC().Truncate(time.Second), Servers: servers}
	if cfg, err = c.Marshal(); err != nil {
		return nil, nil, err
	}
	if sig, err = s.SignICEConfig(cfg); err != nil {
		return nil, nil, err
	}
	return cfg, sig, nil
}

// Start is a parsed call.start body.
type Start struct {
	ConnectionID string
	Media        string
	SDP          string
	EK           []byte
}

func sdp(o strictjson.Object) (string, error) {
	v, err := o.String("sdp")
	if err != nil || v == "" || len(v) > MaxSDP {
		return "", errBad
	}
	return v, nil
}

func media(o strictjson.Object) (string, error) {
	v, err := o.String("media")
	if err != nil || v != "audio" && v != "video" {
		return "", errBad
	}
	return v, nil
}

// ParseStart parses a call.start body strictly.
func ParseStart(body []byte) (*Start, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	st := &Start{}
	if st.ConnectionID, err = o.String("connection_id"); err != nil || st.ConnectionID == "" {
		return nil, errBad
	}
	if st.Media, err = media(o); err != nil {
		return nil, err
	}
	if st.SDP, err = sdp(o); err != nil {
		return nil, err
	}
	if st.EK, err = o.Base64("ek", callwire.EKSize); err != nil {
		return nil, errBad
	}
	return st, nil
}

// start: a device places a call (D→V request). The vault sends the offer
// to the connection and answers with the call id and its ICE
// configuration.
func (f *Feature) start(ctx context.Context, s *vault.Session, body []byte) (json.RawMessage, error) {
	st, err := ParseStart(body)
	if err != nil {
		return nil, err
	}
	if p, ok := s.Connection(st.ConnectionID); !ok || p.State != vault.PeerActive {
		return nil, errNotFound
	}
	now := s.Now()
	if f.busy(now) {
		return nil, errBusy
	}
	id := s.NewID()
	exp := now.Add(OfferTTL).UTC().Truncate(time.Millisecond)
	cfg, sig, err := f.iceFor(ctx, s, id)
	if err != nil {
		return nil, errInternal
	}
	offer := strictjson.NewBuilder().String("call_id", id).String("media", st.Media).String("sdp", st.SDP).Base64("ek", st.EK).Bytes()
	if err := s.Send(st.ConnectionID, "call.offer", offer, vault.SendOptions{Exp: exp}); err != nil {
		return nil, errConn
	}
	f.calls[id] = &Call{ID: id, Conn: st.ConnectionID, Dir: DirOut, Media: st.Media, State: StateRinging, Device: s.From().ID,
		Created: now, Exp: exp}
	f.prune(now)
	s.Record(vault.Activity{Kind: "call.outgoing", ConnectionID: st.ConnectionID, Ref: id, Direction: DirOut, Audit: true})
	return strictjson.NewBuilder().String("call_id", id).String("exp", envelope.FormatTS(exp)).
		Base64("ice_config", cfg).Base64("ice_sig", sig).Bytes(), nil
}

// Offer is a parsed call.offer body (from a peer vault, which may be
// malicious).
type Offer struct {
	CallID string
	Media  string
	SDP    string
	EK     []byte
}

// ParseOffer parses a call.offer body strictly.
func ParseOffer(body []byte) (*Offer, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	of := &Offer{}
	if of.CallID, err = o.String("call_id"); err != nil || !envelope.ValidULID(of.CallID) {
		return nil, errBad
	}
	if of.Media, err = media(o); err != nil {
		return nil, err
	}
	if of.SDP, err = sdp(o); err != nil {
		return nil, err
	}
	if of.EK, err = o.Base64("ek", callwire.EKSize); err != nil {
		return nil, errBad
	}
	return of, nil
}

// offer: a connection calls (V↔V). Busy vaults answer busy; otherwise the
// owner's apps and desktops ring, each with this vault's ICE
// configuration.
func (f *Feature) offer(ctx context.Context, s *vault.Session, in *envelope.Inner) error {
	of, err := ParseOffer(in.Body)
	if err != nil {
		return err
	}
	now := s.Now()
	conn := s.From().ID
	if in.Exp.IsZero() || in.Exp.Sub(now) > 2*OfferTTL {
		return errBad // offers carry exp (45 s by default)
	}
	if _, dup := f.calls[of.CallID]; dup {
		return nil // idempotent by call_id
	}
	c := &Call{ID: of.CallID, Conn: conn, Dir: DirIn, Media: of.Media, State: StateRinging, Created: now, Exp: in.Exp}
	f.calls[of.CallID] = c
	f.prune(now)
	s.Record(vault.Activity{Kind: "call.incoming", ConnectionID: conn, Ref: c.ID, Direction: DirIn, Audit: true})
	if f.busyExcept(c.ID, now) {
		f.finish(s, c, "busy")
		_ = s.SendToConnection(conn, "call.end", endJSON(c.ID, "busy"))
		f.missed(s, c)
		return nil
	}
	cfg, sig, err := f.iceFor(ctx, s, c.ID)
	if err != nil {
		f.finish(s, c, "failed")
		_ = s.SendToConnection(conn, "call.end", endJSON(c.ID, "failed"))
		return nil
	}
	ev := strictjson.NewBuilder().String("call_id", c.ID).String("connection_id", conn).String("media", c.Media).
		String("sdp", of.SDP).Base64("ek", of.EK).String("exp", envelope.FormatTS(c.Exp)).
		Base64("ice_config", cfg).Base64("ice_sig", sig).Bytes()
	s.NotifyDevicesWith("call.offer", ev, "", vault.SendOptions{Exp: c.Exp})
	return nil
}

func (f *Feature) busyExcept(id string, now time.Time) bool {
	for cid, c := range f.calls {
		if cid != id && c.live(now) {
			return true
		}
	}
	return false
}

func (f *Feature) finish(s *vault.Session, c *Call, reason string) {
	c.State, c.Reason, c.Ended = StateEnded, reason, s.Now()
	s.Record(vault.Activity{Kind: "call.ended", ConnectionID: c.Conn, Ref: c.ID, Direction: c.Dir, Audit: true})
}

// missed records an incoming call that was never answered in the feed.
func (f *Feature) missed(s *vault.Session, c *Call) {
	s.Record(vault.Activity{Kind: "call.missed", ConnectionID: c.Conn, Ref: c.ID, Direction: DirIn, Feed: true, Priority: "high"})
}

func endJSON(id, reason string) []byte {
	return strictjson.NewBuilder().String("call_id", id).String("reason", reason).Bytes()
}

// Answer is a parsed call.answer body.
type Answer struct {
	CallID string
	SDP    string
	Enc    []byte
}

// ParseAnswer parses a call.answer body strictly.
func ParseAnswer(body []byte) (*Answer, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	a := &Answer{}
	if a.CallID, err = o.String("call_id"); err != nil || !envelope.ValidULID(a.CallID) {
		return nil, errBad
	}
	if a.SDP, err = sdp(o); err != nil {
		return nil, err
	}
	if a.Enc, err = o.Base64("enc", callwire.EncSize); err != nil {
		return nil, errBad
	}
	return a, nil
}

// unavailable tells a device that a call it acted on is gone.
func unavailable(s *vault.Session, id string) error {
	_ = s.Send(s.From().ID, "call.end", endJSON(id, "unavailable"), vault.SendOptions{})
	return nil
}

// answerFromDevice: an owner device answers an incoming call; it becomes
// the call's device, the others stop ringing.
func (f *Feature) answerFromDevice(s *vault.Session, body []byte) error {
	a, err := ParseAnswer(body)
	if err != nil {
		return err
	}
	c := f.calls[a.CallID]
	now := s.Now()
	if c == nil || c.Dir != DirIn || c.State != StateRinging || !now.Before(c.Exp) {
		return unavailable(s, a.CallID)
	}
	out := strictjson.NewBuilder().String("call_id", c.ID).String("sdp", a.SDP).Base64("enc", a.Enc).Bytes()
	if err := s.SendToConnection(c.Conn, "call.answer", out); err != nil {
		f.finish(s, c, "unavailable")
		return unavailable(s, a.CallID)
	}
	c.State, c.Device, c.Answered = StateActive, s.From().ID, now
	s.NotifyDevicesWith("call.end", endJSON(c.ID, "answered_elsewhere"), s.From().ID, vault.SendOptions{})
	s.Record(vault.Activity{Kind: "call.answered", ConnectionID: c.Conn, Ref: c.ID, Direction: DirIn, Audit: true})
	return nil
}

// answerFromPeer: the callee answered our call; its answer goes to the
// calling device.
func (f *Feature) answerFromPeer(s *vault.Session, body []byte) error {
	a, err := ParseAnswer(body)
	if err != nil {
		return err
	}
	c := f.calls[a.CallID]
	if c == nil || c.Conn != s.From().ID || c.Dir != DirOut || c.State != StateRinging {
		return nil
	}
	c.State, c.Answered = StateActive, s.Now()
	_ = s.Send(c.Device, "call.answer", strictjson.NewBuilder().String("call_id", c.ID).String("sdp", a.SDP).
		Base64("enc", a.Enc).Bytes(), vault.SendOptions{})
	s.Record(vault.Activity{Kind: "call.answered", ConnectionID: c.Conn, Ref: c.ID, Direction: DirOut, Audit: true})
	return nil
}

// End is a parsed call.end body.
type End struct {
	CallID string
	Reason string
}

// ParseEnd parses a call.end body strictly.
func ParseEnd(body []byte) (*End, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	e := &End{}
	if e.CallID, err = o.String("call_id"); err != nil || !envelope.ValidULID(e.CallID) {
		return nil, errBad
	}
	if e.Reason, err = o.String("reason"); err != nil || !Reasons[e.Reason] {
		return nil, errBad
	}
	return e, nil
}

// end: a hang-up, decline, busy or timeout, from a device or the peer.
func (f *Feature) end(s *vault.Session, body []byte, fromConn bool) error {
	e, err := ParseEnd(body)
	if err != nil {
		return err
	}
	c := f.calls[e.CallID]
	if c == nil || c.State == StateEnded {
		return nil
	}
	ringing := c.State == StateRinging
	if fromConn {
		if c.Conn != s.From().ID {
			return nil
		}
		f.finish(s, c, e.Reason)
		s.NotifyDevicesWith("call.end", endJSON(c.ID, e.Reason), "", vault.SendOptions{})
		if c.Dir == DirIn && ringing {
			f.missed(s, c)
		}
		return nil
	}
	// A device: the call's device, or any owner device declining an
	// incoming call that is still ringing.
	if c.Device != s.From().ID && !(c.Dir == DirIn && ringing) {
		return nil
	}
	f.finish(s, c, e.Reason)
	_ = s.SendToConnection(c.Conn, "call.end", endJSON(c.ID, e.Reason))
	s.NotifyDevicesWith("call.end", endJSON(c.ID, e.Reason), s.From().ID, vault.SendOptions{})
	return nil
}

// ICE is a parsed call.ice body.
type ICE struct {
	CallID     string
	Candidates json.RawMessage // canonical re-encoding
}

// ParseICE parses a call.ice body strictly: 1–16 candidates
// {candidate, sdp_mid?, sdp_mline_index?}.
func ParseICE(body []byte) (*ICE, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	ic := &ICE{}
	if ic.CallID, err = o.String("call_id"); err != nil || !envelope.ValidULID(ic.CallID) {
		return nil, errBad
	}
	arr, err := o.Array("candidates")
	if err != nil || len(arr) == 0 || len(arr) > MaxCandidates {
		return nil, errBad
	}
	out := []byte{'['}
	for i, raw := range arr {
		co, err := strictjson.AsObject(raw)
		if err != nil {
			return nil, errBad
		}
		cand, err := co.String("candidate")
		if err != nil || len(cand) > MaxCandidate {
			return nil, errBad
		}
		b := strictjson.NewBuilder().String("candidate", cand)
		if mid, present, err := co.OptString("sdp_mid"); err != nil || len(mid) > 64 {
			return nil, errBad
		} else if present {
			b.String("sdp_mid", mid)
		}
		if idx, present, err := co.OptUint("sdp_mline_index", 0, 1023); err != nil {
			return nil, errBad
		} else if present {
			b.Uint("sdp_mline_index", idx)
		}
		if i > 0 {
			out = append(out, ',')
		}
		out = append(out, b.Bytes()...)
	}
	ic.Candidates = append(out, ']')
	return ic, nil
}

func eph(now time.Time) vault.SendOptions {
	return vault.SendOptions{Exp: now.Add(EphemeralTTL), MemoryOnly: true}
}

// ice forwards trickle ICE candidates (ephemeral, memory-only).
func (f *Feature) ice(s *vault.Session, body []byte, fromConn bool) error {
	ic, err := ParseICE(body)
	if err != nil {
		return err
	}
	c := f.calls[ic.CallID]
	now := s.Now()
	if c == nil || !c.live(now) || c.ICE >= MaxICEPerCall {
		return nil
	}
	out := strictjson.NewBuilder().String("call_id", c.ID).Raw("candidates", ic.Candidates).Bytes()
	if fromConn {
		if c.Conn != s.From().ID {
			return nil
		}
		c.ICE++
		if c.Device != "" {
			_ = s.Send(c.Device, "call.ice", out, eph(now))
		} else {
			s.NotifyDevicesWith("call.ice", out, "", eph(now))
		}
		return nil
	}
	if c.Device != s.From().ID {
		return nil
	}
	c.ICE++
	_ = s.Send(c.Conn, "call.ice", out, eph(now))
	return nil
}

func callIDOnly(body []byte) (string, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return "", errBad
	}
	id, err := o.String("call_id")
	if err != nil || !envelope.ValidULID(id) {
		return "", errBad
	}
	return id, nil
}

// ringing: a callee device rings; the caller's device hears it once.
func (f *Feature) ringing(s *vault.Session, body []byte, fromConn bool) error {
	id, err := callIDOnly(body)
	if err != nil {
		return err
	}
	c := f.calls[id]
	now := s.Now()
	if c == nil || c.State != StateRinging || !now.Before(c.Exp) || c.Rang {
		return nil
	}
	out := strictjson.NewBuilder().String("call_id", id).Bytes()
	if fromConn {
		if c.Conn != s.From().ID || c.Dir != DirOut {
			return nil
		}
		c.Rang = true
		_ = s.Send(c.Device, "call.ringing", out, eph(now))
		return nil
	}
	if c.Dir != DirIn {
		return nil
	}
	c.Rang = true
	_ = s.Send(c.Conn, "call.ringing", out, eph(now))
	return nil
}

// list: the call history, newest first.
func (f *Feature) list(body []byte) (json.RawMessage, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	limit, present, err := o.OptUint("limit", 1, MaxHistory)
	if err != nil {
		return nil, errBad
	}
	if !present {
		limit = DefaultLimit
	}
	ids := f.sorted()
	if len(ids) > int(limit) {
		ids = ids[:limit]
	}
	arr := []byte{'['}
	for i, id := range ids {
		c := f.calls[id]
		b := strictjson.NewBuilder().String("call_id", c.ID).String("connection_id", c.Conn).String("direction", c.Dir).
			String("media", c.Media).String("state", c.State).String("started_at", envelope.FormatTS(c.Created))
		if c.Reason != "" {
			b.String("reason", c.Reason)
		}
		if !c.Answered.IsZero() {
			b.String("answered_at", envelope.FormatTS(c.Answered))
		}
		if !c.Ended.IsZero() {
			b.String("ended_at", envelope.FormatTS(c.Ended))
		}
		if i > 0 {
			arr = append(arr, ',')
		}
		arr = append(arr, b.Bytes()...)
	}
	return strictjson.NewBuilder().Raw("calls", append(arr, ']')).Bytes(), nil
}

// ConnectionRemoved implements vault.ConnectionRemovedObserver: live calls
// with the connection end.
func (f *Feature) ConnectionRemoved(s *vault.Session, id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if c.Conn == id && c.State != StateEnded {
			f.finish(s, c, "unavailable")
			s.NotifyDevicesWith("call.end", endJSON(c.ID, "unavailable"), "", vault.SendOptions{})
		}
	}
}

// Get returns a copy of a call record (tests, tools).
func (f *Feature) Get(id string) (Call, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.calls[id]
	if !ok {
		return Call{}, false
	}
	return *c, true
}
