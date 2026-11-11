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
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha1" // coturn use-auth-secret is HMAC-SHA1 (CALLING-SERVICE §5)
	"encoding/base64"
	"encoding/json"
	"errors"
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
	// Watched: its device said it sends call.keepalive (keepalive: true in
	// its call.start or call.answer, C2): the 90 s rule applies to it.
	Watched bool `json:"watched,omitempty"`
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
	// alive is when each watched active call's device last showed it was
	// alive (liveness.go): memory only, never in the state.
	alive map[string]time.Time
	// lastTick is the previous housekeeping (memory only), to see a gap in
	// collecting (CollectGap).
	lastTick time.Time
	// Permission and limits (permission.go), DEK state: the connections
	// whose calls are off, each connection's unanswered incoming calls,
	// and the connections last announced as limited.
	off         map[string]bool
	unanswered  map[string][]time.Time
	limitedSent map[string]bool
}

// New returns the feature.
func New(o Options) *Feature {
	if o.ICE == nil {
		o.ICE = NoServers{}
	}
	return &Feature{issuer: o.ICE, calls: map[string]*Call{}, alive: map[string]time.Time{},
		off: map[string]bool{}, unanswered: map[string][]time.Time{}, limitedSent: map[string]bool{}}
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
		{Type: "call.keepalive", Ephemeral: true, From: owners},
		{Type: "call.permission.set", Request: true, From: owners},
		{Type: "call.permission.list", Request: true, From: owners},
	}
}

// Load implements vault.Feature.
func (f *Feature) Load(data json.RawMessage) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	st, err := loadState(data)
	if err != nil {
		return err
	}
	f.calls = st.Calls
	f.off, f.unanswered, f.limitedSent = orEmpty(st.Off), st.Unanswered, orEmpty(st.Limited)
	if f.unanswered == nil {
		f.unanswered = map[string][]time.Time{}
	}
	f.alive = map[string]time.Time{} // memory only: counted again from the first look after the unlock
	f.lastTick = time.Time{}
	return nil
}

// Save implements vault.Feature.
func (f *Feature) Save() (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return json.Marshal(&state{V: stateVersion, Calls: f.calls, Off: f.off, Unanswered: f.unanswered, Limited: f.limitedSent})
}

func orEmpty(m map[string]bool) map[string]bool {
	if m == nil {
		return map[string]bool{}
	}
	return m
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
		return f.list(s, in.Body)
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
	case "call.keepalive":
		return nil, f.keepalive(s, in.Body)
	case "call.permission.set":
		return f.setPermission(s, in.Body)
	case "call.permission.list":
		return f.listPermissions(s, in.Body)
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
	CallID       string // chosen by the calling device (a ULID)
	Media        string
	SDP          string
	EK           []byte
	EKSig        []byte // the device's signature over the share
	Keepalive    bool   // (C2) its device sends call.keepalive
	// (C2) Form 2: the offered media suites and the device's signature
	// over m2 ("Call forms"); both or neither.
	Suites []int
	EKSig2 []byte
}

func sig(o strictjson.Object, name string) ([]byte, error) {
	b, err := o.Base64(name, ed25519.SignatureSize)
	if err != nil {
		return nil, errBad
	}
	return b, nil
}

func callID(o strictjson.Object) (string, error) {
	id, err := o.String("call_id")
	if err != nil || !envelope.ValidULID(id) {
		return "", errBad
	}
	return id, nil
}

// Vouched are the signatures a peer vault passes on with a share.
type Vouched struct {
	DeviceIK  []byte
	DeviceSig []byte
	VaultSig  []byte
}

func vouched(o strictjson.Object) (Vouched, error) {
	var v Vouched
	var err error
	if v.DeviceIK, err = o.Base64("device_ik", ed25519.PublicKeySize); err != nil {
		return v, errBad
	}
	if v.DeviceSig, err = sig(o, "device_sig"); err != nil {
		return v, err
	}
	v.VaultSig, err = sig(o, "vault_sig")
	return v, err
}

func (v Vouched) add(b *strictjson.Builder) *strictjson.Builder {
	return b.Base64("device_ik", v.DeviceIK).Base64("device_sig", v.DeviceSig).Base64("vault_sig", v.VaultSig)
}

// suiteList reads an optional suites or offered list (C2): 1 to 8 integers
// 1–65,535, none repeated.
func suiteList(o strictjson.Object, name string) ([]int, bool, error) {
	raw, present, err := o.OptArray(name)
	if err != nil {
		return nil, false, errBad
	}
	if !present {
		return nil, false, nil
	}
	if len(raw) == 0 || len(raw) > callwire.MaxSuites {
		return nil, false, errBad // before parsing any element
	}
	out := make([]int, len(raw))
	for i, r := range raw {
		v, err := strictjson.AsUint(r, 1, callwire.MaxSuite)
		if err != nil {
			return nil, false, errBad
		}
		out[i] = int(v)
	}
	if callwire.ValidSuites(out) != nil {
		return nil, false, errBad
	}
	return out, true, nil
}

func suitesJSON(list []int) []byte {
	b := []byte{'['}
	for i, s := range list {
		if i > 0 {
			b = append(b, ',')
		}
		b = strconv.AppendInt(b, int64(s), 10)
	}
	return append(b, ']')
}

// form2 are an answer's form 2 members (C2): the chosen suite, the offered
// list as the answering device read it, and the key confirmation.
type form2 struct {
	Suite   int
	Offered []int
	Confirm []byte
}

// answerForm2 reads an answer's form 2 members: all of suite, offered and
// confirm, or none (an answer is in exactly one form).
func answerForm2(o strictjson.Object) (*form2, error) {
	_, hasSuite := o["suite"]
	offered, hasOffered, err := suiteList(o, "offered")
	if err != nil {
		return nil, err
	}
	_, hasConfirm := o["confirm"]
	if !hasSuite && !hasOffered && !hasConfirm {
		return nil, nil
	}
	if !hasSuite || !hasOffered || !hasConfirm {
		return nil, errBad
	}
	s, err := o.Uint("suite", 1, callwire.MaxSuite)
	if err != nil {
		return nil, errBad
	}
	c, err := o.Base64("confirm", callwire.ConfirmSize)
	if err != nil {
		return nil, errBad
	}
	return &form2{Suite: int(s), Offered: offered, Confirm: c}, nil
}

func (f2 *form2) add(b *strictjson.Builder) *strictjson.Builder {
	if f2 == nil {
		return b
	}
	return b.Uint("suite", uint64(f2.Suite)).Raw("offered", suitesJSON(f2.Offered)).Base64("confirm", f2.Confirm)
}

// parties are a call's two members as this vault names them in form 2
// (0.88.16), from its own records: its own identity key, and conn's
// pinned one; dir is the call's direction here.
//
// ok is false when either key is missing (the connection is gone): the
// caller then treats the share as one that doesn't verify.
func parties(s *vault.Session, conn, dir string) (callwire.Parties, bool) {
	own := s.IdentityKey()
	var peer ed25519.PublicKey
	if p, ok := s.Connection(conn); ok {
		peer = p.IK
	}
	pp := callwire.Parties{Caller: peer, Callee: own}
	if dir == DirOut {
		pp = callwire.Parties{Caller: own, Callee: peer}
	}
	return pp, pp.Valid()
}

// answerMessage is the signed bytes of an answer in its form.
func answerMessage(callID string, f2 *form2, p callwire.Parties, enc []byte) []byte {
	if f2 != nil {
		return callwire.AnswerMessage2(callID, f2.Suite, f2.Offered, p, enc)
	}
	return callwire.ShareMessage(callwire.RoleAnswer, callID, "", enc)
}

// vouch checks a share from one of our devices against its paired record
// and signs it for the peer vault.
func vouch(s *vault.Session, m, deviceSig []byte) (Vouched, error) {
	dev := ed25519.PublicKey(s.From().IK)
	if callwire.VerifyDeviceShare(dev, m, deviceSig) != nil {
		return Vouched{}, vault.NewError("bad_request", "share signature")
	}
	vs, err := s.VouchCallShare(dev, m)
	if err != nil {
		var he *vault.HandlerError
		if errors.As(err, &he) && he.Code == "bad_request" {
			return Vouched{}, err // a share the vault won't vouch for (form 2 naming another vault)
		}
		return Vouched{}, errInternal
	}
	return Vouched{DeviceIK: append([]byte(nil), dev...), DeviceSig: deviceSig, VaultSig: vs}, nil
}

// checkPeerShare verifies a share from a connection: its vault's signature
// under the connection's pinned ik and its device's signature.
func checkPeerShare(s *vault.Session, m []byte, v Vouched) bool {
	p, ok := s.Connection(s.From().ID)
	if !ok || callwire.VerifyShare(p.IK, v.DeviceIK, m, v.DeviceSig, v.VaultSig) != nil {
		s.Record(vault.Activity{Kind: "drop.call_share", ConnectionID: s.From().ID, Audit: true})
		return false
	}
	return true
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
	if st.CallID, err = callID(o); err != nil {
		return nil, err
	}
	if st.EKSig, err = sig(o, "ek_sig"); err != nil {
		return nil, err
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
	if st.Keepalive, err = keepaliveFlag(o); err != nil {
		return nil, err
	}
	suites, hasSuites, err := suiteList(o, "suites")
	if err != nil {
		return nil, err
	}
	_, hasSig2 := o["ek_sig2"]
	if hasSuites != hasSig2 {
		return nil, errBad // suites without ek_sig2, or the reverse
	}
	if hasSuites {
		st.Suites = suites
		if st.EKSig2, err = sig(o, "ek_sig2"); err != nil {
			return nil, err
		}
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
	if f.off[st.ConnectionID] {
		return nil, errCallsOff
	}
	now := s.Now()
	if f.busy(now) {
		return nil, errBusy
	}
	id := st.CallID
	if _, dup := f.calls[id]; dup {
		return nil, vault.NewError("exists", "")
	}
	v, err := vouch(s, callwire.ShareMessage(callwire.RoleOffer, id, st.Media, st.EK), st.EKSig)
	if err != nil {
		return nil, err
	}
	var v2 Vouched
	if st.Suites != nil {
		// Form 2 is vouched only after the device's signature of it verified.
		pp, ok := parties(s, st.ConnectionID, DirOut)
		if !ok {
			return nil, errNotFound
		}
		if v2, err = vouch(s, callwire.OfferMessage2(id, st.Media, st.Suites, pp, st.EK), st.EKSig2); err != nil {
			return nil, err
		}
	}
	exp := now.Add(OfferTTL).UTC().Truncate(time.Millisecond)
	cfg, isig, err := f.iceFor(ctx, s, id)
	if err != nil {
		return nil, errInternal
	}
	ob := v.add(strictjson.NewBuilder().String("call_id", id).String("media", st.Media).String("sdp", st.SDP).Base64("ek", st.EK))
	if st.Suites != nil {
		ob.Raw("suites", suitesJSON(st.Suites)).Base64("device_sig2", v2.DeviceSig).Base64("vault_sig2", v2.VaultSig)
	}
	offer := ob.Bytes()
	if err := s.Send(st.ConnectionID, "call.offer", offer, vault.SendOptions{Exp: exp}); err != nil {
		return nil, errConn
	}
	f.calls[id] = &Call{ID: id, Conn: st.ConnectionID, Dir: DirOut, Media: st.Media, State: StateRinging, Device: s.From().ID,
		Created: now, Exp: exp, Watched: st.Keepalive}
	f.prune(now)
	s.Record(vault.Activity{Kind: "call.outgoing", ConnectionID: st.ConnectionID, Ref: id, Direction: DirOut, Audit: true})
	f.clearUnanswered(s, st.ConnectionID, now) // a call the member places clears the counts
	return strictjson.NewBuilder().String("call_id", id).String("exp", envelope.FormatTS(exp)).
		Base64("ice_config", cfg).Base64("ice_sig", isig).Bytes(), nil
}

// Offer is a parsed call.offer body (from a peer vault, which may be
// malicious).
type Offer struct {
	CallID string
	Media  string
	SDP    string
	EK     []byte
	Vouched
	// (C2) Form 2: the suites and their signatures. Form2Bad: the offer
	// carries part of form 2 (it is dropped, drop.call_share).
	Suites                []int
	DeviceSig2, VaultSig2 []byte
	Form2Bad              bool
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
	if of.Vouched, err = vouched(o); err != nil {
		return nil, err
	}
	suites, hasSuites, err := suiteList(o, "suites")
	_, hasD2 := o["device_sig2"]
	_, hasV2 := o["vault_sig2"]
	switch {
	case err != nil, hasSuites != hasD2, hasSuites != hasV2:
		of.Form2Bad = true
	case hasSuites:
		of.Suites = suites
		of.DeviceSig2, err = sig(o, "device_sig2")
		if err == nil {
			of.VaultSig2, err = sig(o, "vault_sig2")
		}
		of.Form2Bad = err != nil
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
	if !checkPeerShare(s, callwire.ShareMessage(callwire.RoleOffer, of.CallID, of.Media, of.EK), of.Vouched) {
		return nil // a swapped or unsigned share: no ringing
	}
	// (C2) Every form an offer carries is checked: form 2 incomplete or
	// not verifying drops the offer.
	pp, okP := parties(s, conn, DirIn)
	if of.Form2Bad || of.Suites != nil && (!okP || !checkPeerShare(s, callwire.OfferMessage2(of.CallID, of.Media, of.Suites, pp, of.EK),
		Vouched{DeviceIK: of.DeviceIK, DeviceSig: of.DeviceSig2, VaultSig: of.VaultSig2})) {
		if of.Form2Bad || !okP { // (checkPeerShare audits a share that doesn't verify)
			s.Record(vault.Activity{Kind: "drop.call_share", ConnectionID: conn, Audit: true})
		}
		return nil
	}
	if f.off[conn] {
		// Calls from this connection are off: no ringing, no answer, no
		// record, no missed call, no wake (§10.10, V5).
		s.Record(vault.Activity{Kind: "drop.call_off", ConnectionID: conn, Ref: of.CallID, Audit: true})
		return nil
	}
	// Glare comes before the held check: a held vault has no ringing call
	// of its own (the hold's start ends them, and call.start is refused
	// while held), so the order changes nothing there.
	if !f.glare(s, conn, of.CallID, now) {
		return nil // our own call to this connection wins
	}
	c := &Call{ID: of.CallID, Conn: conn, Dir: DirIn, Media: of.Media, State: StateRinging, Created: now, Exp: in.Exp}
	f.calls[of.CallID] = c
	f.prune(now)
	s.Record(vault.Activity{Kind: "call.incoming", ConnectionID: conn, Ref: c.ID, Direction: DirIn, Audit: true})
	if s.OwnerHeld() {
		// A held vault rings no device and does not answer, not even busy:
		// the caller times out as with a locked callee (§3.6.3, §10.10).
		// The missed call doesn't count toward the limits: the member
		// couldn't have answered it (owner decision 2026-11-11).
		f.finish(s, c, "unavailable")
		recordMissed(s, c)
		return nil
	}
	if f.limited(conn, now) {
		// Too many unanswered calls from this connection: no ringing, no
		// answer; an ended call and a missed call (§10.10, V5).
		s.Record(vault.Activity{Kind: "drop.call_rate", ConnectionID: conn, Ref: c.ID, Audit: true})
		f.finish(s, c, "unavailable")
		f.missed(s, c)
		return nil
	}
	if f.busyExcept(c.ID, now) {
		f.finish(s, c, "busy")
		_ = s.SendToConnection(conn, "call.end", endJSON(c.ID, "busy"))
		f.missed(s, c)
		return nil
	}
	cfg, isig, err := f.iceFor(ctx, s, c.ID)
	if err != nil {
		f.finish(s, c, "failed")
		_ = s.SendToConnection(conn, "call.end", endJSON(c.ID, "failed"))
		return nil
	}
	peer, _ := s.Connection(conn)
	eb := of.Vouched.add(strictjson.NewBuilder().String("call_id", c.ID).String("connection_id", conn).String("media", c.Media).
		String("sdp", of.SDP).Base64("ek", of.EK).String("exp", envelope.FormatTS(c.Exp)).
		Base64("ice_config", cfg).Base64("ice_sig", isig)).Base64("peer_ik", peer.IK)
	if of.Suites != nil {
		eb.Raw("suites", suitesJSON(of.Suites)).Base64("device_sig2", of.DeviceSig2).Base64("vault_sig2", of.VaultSig2)
	}
	ev := eb.Bytes()
	s.NotifyDevicesWith("call.offer", ev, "", vault.SendOptions{Exp: c.Exp})
	return nil
}

// glare settles two members calling each other at once (§10.10 "Glare",
// CALLS-PLAN V6, D21): an offer y from conn while this vault's own call
// to conn still rings. The lower call_id (its 26 ASCII bytes) wins, so
// both vaults agree. Ours wins: y is dropped (no ringing, no answer, no
// record, no missed call), audited drop.call_glare; false. Theirs wins:
// ours ends busy, the owner devices are told with superseded_by = y, the
// peer vault call.end{busy} for ours (one that dropped it ignores it; one
// whose own call had ended or expired when ours arrived, and so rings for
// it, stops ringing, a missed call; owner decision 2026-11-11), and
// y is handled as any offer; true. With no such call of ours: true.
func (f *Feature) glare(s *vault.Session, conn, y string, now time.Time) bool {
	for _, id := range f.sorted() {
		x := f.calls[id]
		if x.Conn != conn || x.Dir != DirOut || x.State != StateRinging || !x.live(now) {
			continue
		}
		if callwire.LowerWins(x.ID, y) {
			s.Record(vault.Activity{Kind: "drop.call_glare", ConnectionID: conn, Ref: y, Audit: true})
			return false
		}
		f.finish(s, x, "busy")
		_ = s.SendToConnection(conn, "call.end", endJSON(x.ID, "busy"))
		body := strictjson.NewBuilder().String("call_id", x.ID).String("reason", "busy").String("superseded_by", y).Bytes()
		except := ""
		if x.Device != "" {
			_ = s.SendCallSignal(x.Device, "call.end", body, vault.SendOptions{})
			except = x.Device
		}
		s.NotifyDevicesWith("call.end", body, except, vault.SendOptions{})
		return true // one own ringing call at most (start refuses while busy)
	}
	return true
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
	delete(f.alive, c.ID)
	s.Record(vault.Activity{Kind: "call.ended", ConnectionID: c.Conn, Ref: c.ID, Direction: c.Dir, Audit: true})
}

// missed records an incoming call that was never answered in the feed.
//
// A missed call counts toward the connection's unanswered-call limit
// (§10.10, V5), as a declined one does (end); an incoming call the vault
// ends for its own reasons (no ICE configuration, an answer it couldn't
// forward) does not, nor one missed because of the vault hold or ended
// because calls were turned off (recordMissed).
func (f *Feature) missed(s *vault.Session, c *Call) {
	f.noteUnanswered(s, c.Conn, s.Now())
	recordMissed(s, c)
}

// recordMissed records a missed call in the feed without counting it: a
// call the member couldn't answer because of the vault hold, or one ended
// because calls with the connection were turned off (§10.10, owner
// decision 2026-11-11).
func recordMissed(s *vault.Session, c *Call) {
	s.Record(vault.Activity{Kind: "call.missed", ConnectionID: c.Conn, Ref: c.ID, Direction: DirIn, Feed: true, Priority: "high",
		Batch: MissedMergeWindow, BatchWhileActive: true}) // missed calls merge (§10.10, V5)
}

// endToDevices tells the owner devices that c ended: its call device
// directly, which may be a desktop whose access session has ended (the
// call outlives it, §6.8, 0.88.13), and the others as usual, except
// `except` (the device that ended it).
func endToDevices(s *vault.Session, c *Call, reason, except string) {
	body := endJSON(c.ID, reason)
	if c.Device != "" && c.Device != except {
		_ = s.SendCallSignal(c.Device, "call.end", body, vault.SendOptions{})
		if except == "" {
			except = c.Device
		}
	}
	s.NotifyDevicesWith("call.end", body, except, vault.SendOptions{})
}

// endToLiveDevice is endToDevices for a call that was live; a stale record
// (past its exp or 12 h) ends with the usual fan-out only, so nothing goes
// past a desktop's expired session for it.
func endToLiveDevice(s *vault.Session, c *Call, reason string, live bool) {
	if live {
		endToDevices(s, c, reason, "")
		return
	}
	s.NotifyDevicesWith("call.end", endJSON(c.ID, reason), "", vault.SendOptions{})
}

func endJSON(id, reason string) []byte {
	return strictjson.NewBuilder().String("call_id", id).String("reason", reason).Bytes()
}

// Answer is a parsed call.answer body.
type Answer struct {
	CallID string
	SDP    string
	Enc    []byte
	EncSig []byte // from a device
	// Keepalive: (C2) a device's answer says it sends call.keepalive.
	Keepalive bool
	Vouched
	// Form2: (C2) the answer is in form 2 (its signatures are over m2).
	// Form2Bad: it carries part of form 2, or a form 2 member malformed;
	// it is treated as a share that doesn't verify (drop.call_share).
	Form2    *form2
	Form2Bad bool
}

// ParseAnswer parses a call.answer body strictly: from a device it carries
// enc_sig; from a peer vault the vouched signatures.
func ParseAnswer(body []byte, fromPeer bool) (*Answer, error) {
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
	a.Form2, err = answerForm2(o)
	a.Form2Bad = err != nil
	if fromPeer {
		a.Vouched, err = vouched(o)
	} else {
		a.EncSig, err = sig(o, "enc_sig")
		if err == nil {
			a.Keepalive, err = keepaliveFlag(o)
		}
	}
	if err != nil {
		return nil, err
	}
	return a, nil
}

// unavailable tells a device that a call it acted on is gone.
func unavailable(s *vault.Session, id string) error {
	_ = s.SendCallSignal(s.From().ID, "call.end", endJSON(id, "unavailable"), vault.SendOptions{})
	return nil
}

// answerFromDevice: an owner device answers an incoming call; it becomes
// the call's device, the others stop ringing.
func (f *Feature) answerFromDevice(s *vault.Session, body []byte) error {
	a, err := ParseAnswer(body, false)
	if err != nil {
		return err
	}
	c := f.calls[a.CallID]
	now := s.Now()
	if c == nil || c.Dir != DirIn || c.State != StateRinging || !now.Before(c.Exp) {
		return unavailable(s, a.CallID)
	}
	if a.Form2Bad {
		s.Record(vault.Activity{Kind: "drop.call_share", DeviceID: s.From().ID, Audit: true})
		return unavailable(s, a.CallID)
	}
	pp, ok := parties(s, c.Conn, DirIn)
	if a.Form2 != nil && !ok {
		s.Record(vault.Activity{Kind: "drop.call_share", DeviceID: s.From().ID, Audit: true})
		return unavailable(s, a.CallID) // the connection is gone: nothing to name
	}
	v, err := vouch(s, answerMessage(c.ID, a.Form2, pp, a.Enc), a.EncSig)
	if err != nil {
		s.Record(vault.Activity{Kind: "drop.call_share", DeviceID: s.From().ID, Audit: true})
		return unavailable(s, a.CallID)
	}
	// The vault doesn't judge the choice or confirm: that is for the calling
	// device, which alone knows what it offered (§10.10 "Call forms").
	out := a.Form2.add(v.add(strictjson.NewBuilder().String("call_id", c.ID).String("sdp", a.SDP).Base64("enc", a.Enc))).Bytes()
	if err := s.SendToConnection(c.Conn, "call.answer", out); err != nil {
		f.finish(s, c, "unavailable")
		return unavailable(s, a.CallID)
	}
	c.State, c.Device, c.Answered, c.Watched = StateActive, s.From().ID, now, a.Keepalive
	f.clearUnanswered(s, c.Conn, now) // an answered call from the connection clears the counts
	f.alive[c.ID] = now               // the 90 s count from the answer until the first keep-alive
	s.NotifyDevicesWith("call.end", endJSON(c.ID, "answered_elsewhere"), s.From().ID, vault.SendOptions{})
	s.Record(vault.Activity{Kind: "call.answered", ConnectionID: c.Conn, Ref: c.ID, Direction: DirIn, Audit: true})
	return nil
}

// answerFromPeer: the callee answered our call; its answer goes to the
// calling device.
func (f *Feature) answerFromPeer(s *vault.Session, body []byte) error {
	a, err := ParseAnswer(body, true)
	if err != nil {
		return err
	}
	c := f.calls[a.CallID]
	if c == nil || c.Conn != s.From().ID || c.Dir != DirOut || c.State != StateRinging {
		return nil
	}
	if a.Form2Bad {
		s.Record(vault.Activity{Kind: "drop.call_share", ConnectionID: c.Conn, Audit: true})
		return nil // as a share that doesn't verify: the call keeps ringing
	}
	pp, ok := parties(s, c.Conn, DirOut)
	if a.Form2 != nil && !ok {
		s.Record(vault.Activity{Kind: "drop.call_share", ConnectionID: c.Conn, Audit: true})
		return nil
	}
	if !checkPeerShare(s, answerMessage(c.ID, a.Form2, pp, a.Enc), a.Vouched) {
		return nil // the call keeps ringing until it times out or ends
	}
	if s.OwnerHeld() {
		// Answered after the hold began, so after the deadline: it does
		// not continue (§3.6.3, 0.88.13). Ended, the peer and the devices
		// told, rather than left to 90 s of silence.
		f.finish(s, c, "unavailable")
		_ = s.SendToConnection(c.Conn, "call.end", endJSON(c.ID, "unavailable"))
		endToDevices(s, c, "unavailable", "")
		return nil
	}
	peer, _ := s.Connection(c.Conn)
	if err := s.Send(c.Device, "call.answer", a.Form2.add(a.Vouched.add(strictjson.NewBuilder().String("call_id", c.ID).String("sdp", a.SDP).
		Base64("enc", a.Enc)).Base64("peer_ik", peer.IK)).Bytes(), vault.SendOptions{}); err != nil {
		// Its device can't receive the answer (a desktop whose session
		// ended, an app gated past the deadline, a suspended or removed
		// device): the call can't go on.
		f.finish(s, c, "unavailable")
		_ = s.SendToConnection(c.Conn, "call.end", endJSON(c.ID, "unavailable"))
		endToDevices(s, c, "unavailable", "")
		return nil
	}
	c.State, c.Answered = StateActive, s.Now()
	f.alive[c.ID] = c.Answered // the 90 s count from the answer until the first keep-alive
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
		live := c.live(s.Now())
		f.finish(s, c, e.Reason)
		endToLiveDevice(s, c, e.Reason, live)
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
	if c.Dir == DirIn && ringing {
		f.noteUnanswered(s, c.Conn, c.Ended) // declined: counts toward the limit (§10.10, V5)
	}
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
			_ = s.SendCallSignal(c.Device, "call.ice", out, eph(now))
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
func (f *Feature) list(s *vault.Session, body []byte) (json.RawMessage, error) {
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
		// (C2) exp, the offer's, and the call's device (absent while an
		// incoming call rings).
		b.String("exp", envelope.FormatTS(c.Exp))
		if c.Device != "" {
			b.String("device_id", c.Device)
		}
		if i > 0 {
			arr = append(arr, ',')
		}
		arr = append(arr, b.Bytes()...)
	}
	// (C2) v: 2 tells a device its vault's level ("Mixed releases"); now is
	// the vault's clock.
	return strictjson.NewBuilder().Uint("v", 2).String("now", envelope.FormatTS(s.Now())).Raw("calls", append(arr, ']')).Bytes(), nil
}

// ConnectionRemoved implements vault.ConnectionRemovedObserver: live calls
// with the connection end.
func (f *Feature) ConnectionRemoved(s *vault.Session, id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if c.Conn == id && c.State != StateEnded {
			live := c.live(s.Now())
			f.finish(s, c, "unavailable")
			endToLiveDevice(s, c, "unavailable", live)
		}
	}
	f.dropConnection(id)
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
