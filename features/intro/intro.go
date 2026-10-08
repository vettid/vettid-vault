// Package intro is introductions started by the member (VAULT-MESSAGING
// §10.15): member B introduces two of its connections, A and C, to each
// other. Each is asked, with only what B chooses to show; only when both
// accept does A's vault make a remote invitation bound to C's identity
// key, which B relays to C; A and C then approve each other as for any
// remote invitation (§6.4). A connection never sees, lists or asks for the
// member's other connections: there is no request to be introduced.
//
// vettid.dev had a peer-invoked `connection.handoff` action ("introduce me
// to one of your connections"); it is gone: only the member starts an
// introduction.
package intro

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"sort"
	"sync"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// Limits (§10.15).
const (
	TTL                    = 7 * 24 * time.Hour
	MaxOpen                = 16 // introductions a member has open
	MaxOffersPerIntroducer = 4  // open offers held per introducer
	MaxOffers              = 16 // open offers held in all
	MaxName                = 128
	MaxNote                = 256
	MaxLink                = 4096
	Retention              = 30 * 24 * time.Hour // ended records kept for intro.list
)

// States.
const (
	StateOffered    = "offered"    // introducer: waiting for answers
	StatePending    = "pending"    // party: waiting for the member's answer
	StateAccepted   = "accepted"   // party: accepted, waiting
	StateConnecting = "connecting" // both accepted; the invitation is on its way
	StateLinked     = "linked"     // introducer: the link was relayed
	StateClosed     = "closed"
)

const (
	answerAccept  = "accept"
	answerDecline = "decline"
)

// Peer is what the introducer shows a party about the other one.
type Peer struct {
	Name string `json:"name"`
	Note string `json:"note,omitempty"`
}

// Made is an introduction this vault (the introducer) made.
type Made struct {
	ID       string            `json:"id"`
	A        string            `json:"a"`
	C        string            `json:"c"`
	ToA      Peer              `json:"to_a"`
	ToC      Peer              `json:"to_c"`
	Answers  map[string]string `json:"answers,omitempty"` // connection id -> accept | decline
	State    string            `json:"state"`
	Exp      time.Time         `json:"exp"`
	ClosedAt time.Time         `json:"closed_at,omitempty"`
}

// Received is an introduction offered to this vault.
type Received struct {
	ID       string    `json:"id"`
	Conn     string    `json:"conn"` // the introducer
	Peer     Peer      `json:"peer"`
	State    string    `json:"state"`
	Exp      time.Time `json:"exp"`
	InviteID string    `json:"invite_id,omitempty"` // the invitation this vault made (party A)
	Linked   bool      `json:"linked,omitempty"`    // the link was used (party C)
	ClosedAt time.Time `json:"closed_at,omitempty"`
}

type data struct {
	Made     map[string]*Made     `json:"made"`
	Received map[string]*Received `json:"received"`
}

// Feature implements vault.Feature and vault.ConnectionRemovedObserver.
type Feature struct {
	mu sync.Mutex
	d  data
}

// New returns the feature.
func New() *Feature {
	return &Feature{d: data{Made: map[string]*Made{}, Received: map[string]*Received{}}}
}

var (
	owners = []string{vault.KindApp, vault.KindDesktop}
	conns  = []string{vault.KindConnection}
)

// Name implements vault.Feature.
func (f *Feature) Name() string { return "intro" }

// Types implements vault.Feature.
func (f *Feature) Types() []vault.TypeSpec {
	return []vault.TypeSpec{
		// Starting an introduction and accepting one open new connection
		// paths: desktops only with an app's approval (§6.8).
		{Type: "intro.create", Request: true, From: owners, DesktopApproval: true},
		{Type: "intro.cancel", Request: true, From: owners},
		{Type: "intro.list", Request: true, From: owners},
		{Type: "intro.accept", Request: true, From: owners, DesktopApproval: true},
		{Type: "intro.decline", Request: true, From: owners},
		{Type: "intro.offer", From: conns},
		{Type: "intro.answer", From: conns},
		{Type: "intro.connect", From: conns},
		{Type: "intro.invite", From: conns},
		{Type: "intro.link", From: conns},
		{Type: "intro.closed", From: conns},
	}
}

// Load implements vault.Feature.
func (f *Feature) Load(raw json.RawMessage) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	d := data{}
	if err := json.Unmarshal(raw, &d); err != nil {
		return err
	}
	if d.Made == nil {
		d.Made = map[string]*Made{}
	}
	if d.Received == nil {
		d.Received = map[string]*Received{}
	}
	f.d = d
	return nil
}

// Save implements vault.Feature.
func (f *Feature) Save() (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return json.Marshal(f.d)
}

var (
	errBad      = vault.NewError("bad_request", "")
	errNotFound = vault.NewError("not_found", "")
	errExists   = vault.NewError("exists", "")
	errConn     = vault.NewError("connection_unavailable", "")
)

// --- parsers ---

func ulid(o strictjson.Object, name string) (string, error) {
	v, err := o.String(name)
	if err != nil || !envelope.ValidULID(v) {
		return "", errBad
	}
	return v, nil
}

func parsePeer(o strictjson.Object, name string) (Peer, error) {
	po, err := o.Object(name)
	if err != nil {
		return Peer{}, errBad
	}
	var p Peer
	if p.Name, err = po.String("name"); err != nil || p.Name == "" || len(p.Name) > MaxName {
		return Peer{}, errBad
	}
	if n, present, err := po.OptString("note"); err != nil || len(n) > MaxNote {
		return Peer{}, errBad
	} else if present {
		p.Note = n
	}
	return p, nil
}

func (p Peer) json() []byte {
	b := strictjson.NewBuilder().String("name", p.Name)
	if p.Note != "" {
		b.String("note", p.Note)
	}
	return b.Bytes()
}

// Create is a parsed intro.create body.
type Create struct {
	A, C     string
	ToA, ToC Peer
}

func connID(o strictjson.Object, name string) (string, error) {
	v, err := o.String(name)
	if err != nil || v == "" || len(v) > 64 {
		return "", errBad
	}
	return v, nil
}

// ParseCreate parses an intro.create body strictly.
func ParseCreate(body []byte) (*Create, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	c := &Create{}
	if c.A, err = connID(o, "a"); err != nil {
		return nil, err
	}
	if c.C, err = connID(o, "c"); err != nil {
		return nil, err
	}
	if c.A == c.C {
		return nil, errBad
	}
	if c.ToA, err = parsePeer(o, "to_a"); err != nil {
		return nil, err
	}
	if c.ToC, err = parsePeer(o, "to_c"); err != nil {
		return nil, err
	}
	return c, nil
}

// Offer is a parsed intro.offer body.
type Offer struct {
	ID   string
	Peer Peer
	Exp  time.Time
}

// ParseOffer parses an intro.offer body strictly.
func ParseOffer(body []byte) (*Offer, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	of := &Offer{}
	if of.ID, err = ulid(o, "intro_id"); err != nil {
		return nil, err
	}
	if of.Peer, err = parsePeer(o, "peer"); err != nil {
		return nil, err
	}
	es, err := o.String("exp")
	if err != nil {
		return nil, errBad
	}
	if of.Exp, err = envelope.ParseTS(es); err != nil {
		return nil, errBad
	}
	return of, nil
}

// ParseAnswer parses an intro.answer body strictly.
func ParseAnswer(body []byte) (id string, accept bool, err error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return "", false, errBad
	}
	if id, err = ulid(o, "intro_id"); err != nil {
		return "", false, err
	}
	if accept, err = o.Bool("accept"); err != nil {
		return "", false, errBad
	}
	return id, accept, nil
}

// ParseConnect parses an intro.connect body strictly.
func ParseConnect(body []byte) (id string, ik []byte, err error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return "", nil, errBad
	}
	if id, err = ulid(o, "intro_id"); err != nil {
		return "", nil, err
	}
	if ik, err = o.Base64("peer_ik", ed25519.PublicKeySize); err != nil {
		return "", nil, errBad
	}
	return id, ik, nil
}

// ParseLink parses an intro.invite or intro.link body strictly.
func ParseLink(body []byte) (id, link string, err error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return "", "", errBad
	}
	if id, err = ulid(o, "intro_id"); err != nil {
		return "", "", err
	}
	if link, err = o.String("link"); err != nil || link == "" || len(link) > MaxLink {
		return "", "", errBad
	}
	return id, link, nil
}

// ParseID parses a body holding only intro_id (intro.closed, intro.accept,
// intro.decline, intro.cancel).
func ParseID(body []byte) (string, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return "", errBad
	}
	return ulid(o, "intro_id")
}

// --- helpers ---

func (f *Feature) openMade() int {
	n := 0
	for _, m := range f.d.Made {
		if m.State == StateOffered || m.State == StateConnecting {
			n++
		}
	}
	return n
}

func (f *Feature) openOffers(from string) (byIntroducer, total int) {
	for _, r := range f.d.Received {
		if r.State == StateClosed {
			continue
		}
		total++
		if r.Conn == from {
			byIntroducer++
		}
	}
	return
}

func changed(s *vault.Session, id, state string) {
	s.SyncEvent("intro.changed", strictjson.NewBuilder().String("intro_id", id).String("state", state).Bytes())
}

func event(s *vault.Session, id, ev, conn string) {
	b := strictjson.NewBuilder().String("intro_id", id).String("event", ev)
	if conn != "" {
		b.String("connection_id", conn)
	}
	s.NotifyAllDevices("intro.event", b.Bytes())
}

func drop(s *vault.Session, kind string) {
	s.Record(vault.Activity{Kind: kind, ConnectionID: s.From().ID, Audit: true})
}

func idBody(id string) []byte { return strictjson.NewBuilder().String("intro_id", id).Bytes() }

// closeMade ends an introduction on the introducer's side and tells each
// party offered, except skip, without a reason (§10.15).
func (f *Feature) closeMade(s *vault.Session, m *Made, skip string) {
	if m.State == StateClosed {
		return
	}
	for _, p := range []string{m.A, m.C} {
		if p != skip {
			_ = s.SendToConnection(p, "intro.closed", idBody(m.ID))
		}
	}
	m.State, m.ClosedAt = StateClosed, s.Now().UTC()
	s.Record(vault.Activity{Kind: "intro.closed", Ref: m.ID, Audit: true})
	event(s, m.ID, "closed", "")
	changed(s, m.ID, StateClosed)
}

// closeReceived ends an offer on a party's side; an invitation it made and
// that was not used is cancelled.
func (f *Feature) closeReceived(s *vault.Session, r *Received, notify bool) {
	if r.State == StateClosed {
		return
	}
	if r.InviteID != "" && r.State != StateConnecting {
		s.CancelInvite(r.InviteID)
	}
	r.State, r.ClosedAt = StateClosed, s.Now().UTC()
	s.Record(vault.Activity{Kind: "intro.closed", ConnectionID: r.Conn, Ref: r.ID, Audit: true})
	if notify {
		event(s, r.ID, "closed", r.Conn)
		changed(s, r.ID, StateClosed)
	}
}

// expire closes what has passed its expiry and prunes old records.
func (f *Feature) expire(s *vault.Session) {
	now := s.Now()
	for _, id := range sortedKeys(f.d.Made) {
		m := f.d.Made[id]
		switch {
		case m.State == StateClosed || m.State == StateLinked:
			if now.Sub(m.ClosedAt) > Retention {
				delete(f.d.Made, id)
			}
		case !now.Before(m.Exp):
			f.closeMade(s, m, "")
		}
	}
	for _, id := range sortedKeys(f.d.Received) {
		r := f.d.Received[id]
		switch {
		case r.State == StateClosed:
			if now.Sub(r.ClosedAt) > Retention {
				delete(f.d.Received, id)
			}
		case r.State == StateConnecting:
			if now.Sub(r.Exp) > Retention {
				delete(f.d.Received, id)
			}
		case !now.Before(r.Exp):
			f.closeReceived(s, r, true)
		}
	}
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Handle implements vault.Handler.
func (f *Feature) Handle(_ context.Context, s *vault.Session, in *envelope.Inner) (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.expire(s)
	switch in.Type {
	case "intro.create":
		return f.create(s, in.Body)
	case "intro.cancel":
		id, err := ParseID(in.Body)
		if err != nil {
			return nil, err
		}
		m := f.d.Made[id]
		if m == nil || m.State == StateClosed {
			return nil, errNotFound
		}
		f.closeMade(s, m, "")
		return nil, nil
	case "intro.list":
		if _, err := strictjson.ParseObject(in.Body); err != nil {
			return nil, errBad
		}
		return f.list(), nil
	case "intro.accept", "intro.decline":
		return f.answer(s, in.Type == "intro.accept", in.Body)
	case "intro.offer":
		f.offer(s, in.Body)
	case "intro.answer":
		f.answered(s, in.Body)
	case "intro.connect":
		f.connect(s, in.Body)
	case "intro.invite":
		f.invite(s, in.Body)
	case "intro.link":
		f.link(s, in.Body)
	case "intro.closed":
		f.closed(s, in.Body)
	default:
		return nil, vault.NewError("unsupported_type", "")
	}
	return nil, nil
}

// --- the introducer (B) ---

func (f *Feature) create(s *vault.Session, body []byte) (json.RawMessage, error) {
	c, err := ParseCreate(body)
	if err != nil {
		return nil, err
	}
	for _, id := range []string{c.A, c.C} {
		if p, ok := s.Connection(id); !ok || p.State != vault.PeerActive {
			return nil, errNotFound
		}
	}
	for _, m := range f.d.Made {
		if (m.State == StateOffered || m.State == StateConnecting) && (m.A == c.A && m.C == c.C || m.A == c.C && m.C == c.A) {
			return nil, errExists // one open introduction per pair
		}
	}
	if f.openMade() >= MaxOpen {
		return nil, vault.LimitError("introductions", MaxOpen)
	}
	now := s.Now().UTC().Truncate(time.Millisecond)
	m := &Made{ID: s.NewID(), A: c.A, C: c.C, ToA: c.ToA, ToC: c.ToC, Answers: map[string]string{}, State: StateOffered, Exp: now.Add(TTL)}
	exp := envelope.FormatTS(m.Exp)
	// A is shown C as B describes C (to_a), and C is shown A (to_c).
	offA := strictjson.NewBuilder().String("intro_id", m.ID).Raw("peer", m.ToA.json()).String("exp", exp).Bytes()
	offC := strictjson.NewBuilder().String("intro_id", m.ID).Raw("peer", m.ToC.json()).String("exp", exp).Bytes()
	if s.SendToConnection(m.A, "intro.offer", offA) != nil {
		return nil, errConn
	}
	if s.SendToConnection(m.C, "intro.offer", offC) != nil {
		_ = s.SendToConnection(m.A, "intro.closed", idBody(m.ID))
		return nil, errConn
	}
	f.d.Made[m.ID] = m
	s.Record(vault.Activity{Kind: "intro.created", Ref: m.ID, Audit: true})
	changed(s, m.ID, StateOffered)
	return strictjson.NewBuilder().String("intro_id", m.ID).String("exp", exp).Bytes(), nil
}

// answered: a party's answer reaches the introducer.
func (f *Feature) answered(s *vault.Session, body []byte) {
	from := s.From().ID
	id, accept, err := ParseAnswer(body)
	if err != nil {
		drop(s, "drop.intro")
		return
	}
	m := f.d.Made[id]
	if m == nil || from != m.A && from != m.C {
		drop(s, "drop.intro")
		return
	}
	if m.State != StateOffered || m.Answers[from] != "" {
		return // already answered or ended: a repeat changes nothing
	}
	if !accept {
		m.Answers[from] = answerDecline
		s.Record(vault.Activity{Kind: "intro.declined", ConnectionID: from, Ref: id, Direction: "in", Audit: true})
		event(s, id, "declined", from)
		f.closeMade(s, m, from)
		return
	}
	m.Answers[from] = answerAccept
	s.Record(vault.Activity{Kind: "intro.accepted", ConnectionID: from, Ref: id, Direction: "in", Audit: true})
	event(s, id, "accepted", from)
	if m.Answers[m.A] != answerAccept || m.Answers[m.C] != answerAccept {
		changed(s, id, StateOffered)
		return
	}
	// Both accepted: A makes an invitation bound to C's identity key as
	// this vault has it on record.
	pc, ok := s.Connection(m.C)
	if !ok || len(pc.IK) != ed25519.PublicKeySize {
		f.closeMade(s, m, "")
		return
	}
	if s.SendToConnection(m.A, "intro.connect", strictjson.NewBuilder().String("intro_id", id).Base64("peer_ik", pc.IK).Bytes()) != nil {
		f.closeMade(s, m, "")
		return
	}
	m.State = StateConnecting
	s.Record(vault.Activity{Kind: "intro.connecting", Ref: id, Audit: true})
	event(s, id, "connecting", "")
	changed(s, id, StateConnecting)
}

// invite: A's invitation reaches the introducer, which relays it to C.
func (f *Feature) invite(s *vault.Session, body []byte) {
	id, link, err := ParseLink(body)
	if err != nil {
		drop(s, "drop.intro")
		return
	}
	m := f.d.Made[id]
	if m == nil || s.From().ID != m.A {
		drop(s, "drop.intro")
		return
	}
	if m.State != StateConnecting {
		return
	}
	if s.SendToConnection(m.C, "intro.link", strictjson.NewBuilder().String("intro_id", id).String("link", link).Bytes()) != nil {
		f.closeMade(s, m, "")
		return
	}
	m.State, m.ClosedAt = StateLinked, s.Now().UTC()
	changed(s, id, StateLinked)
}

// --- a party (A or C) ---

func (f *Feature) offer(s *vault.Session, body []byte) {
	from := s.From().ID
	of, err := ParseOffer(body)
	if err != nil {
		drop(s, "drop.intro")
		return
	}
	if _, dup := f.d.Received[of.ID]; dup {
		return // a repeated id is ignored, whoever sent it
	}
	if _, mine := f.d.Made[of.ID]; mine {
		drop(s, "drop.intro")
		return
	}
	by, total := f.openOffers(from)
	if by >= MaxOffersPerIntroducer || total >= MaxOffers {
		drop(s, "drop.intro_limit")
		return
	}
	now := s.Now().UTC().Truncate(time.Millisecond)
	exp := now.Add(TTL)
	if of.Exp.Before(exp) {
		exp = of.Exp
	}
	if !now.Before(exp) {
		return
	}
	r := &Received{ID: of.ID, Conn: from, Peer: of.Peer, State: StatePending, Exp: exp}
	f.d.Received[r.ID] = r
	s.NotifyAllDevices("intro.pending", strictjson.NewBuilder().String("intro_id", r.ID).String("connection_id", from).
		Raw("peer", r.Peer.json()).String("exp", envelope.FormatTS(exp)).Bytes())
	s.Record(vault.Activity{Kind: "intro.offered", ConnectionID: from, Ref: r.ID, Direction: "in", Audit: true})
	s.Record(vault.Activity{Kind: "intro.request", ConnectionID: from, Ref: r.ID, Feed: true, Priority: "high"})
	changed(s, r.ID, StatePending)
}

// answer: the member accepts or declines an offer.
func (f *Feature) answer(s *vault.Session, accept bool, body []byte) (json.RawMessage, error) {
	id, err := ParseID(body)
	if err != nil {
		return nil, err
	}
	r := f.d.Received[id]
	if r == nil || r.State != StatePending {
		return nil, errNotFound
	}
	if err := s.SendToConnection(r.Conn, "intro.answer", strictjson.NewBuilder().String("intro_id", id).Bool("accept", accept).Bytes()); err != nil {
		return nil, errConn
	}
	if accept {
		r.State = StateAccepted
		s.Record(vault.Activity{Kind: "intro.accepted", ConnectionID: r.Conn, Ref: id, Direction: "out", Audit: true})
		changed(s, id, StateAccepted)
		return nil, nil
	}
	s.Record(vault.Activity{Kind: "intro.declined", ConnectionID: r.Conn, Ref: id, Direction: "out", Audit: true})
	f.closeReceived(s, r, false)
	changed(s, id, StateClosed)
	return nil, nil
}

// fromIntroducer returns the offer id names if its introducer sent this.
func (f *Feature) fromIntroducer(s *vault.Session, id string) *Received {
	r := f.d.Received[id]
	if r == nil || r.Conn != s.From().ID {
		return nil
	}
	return r
}

func (f *Feature) connecting(s *vault.Session, r *Received) {
	r.State = StateConnecting
	s.Record(vault.Activity{Kind: "intro.connecting", ConnectionID: r.Conn, Ref: r.ID, Audit: true})
	event(s, r.ID, "connecting", r.Conn)
	changed(s, r.ID, StateConnecting)
}

// connect: both accepted; this vault (A) makes the invitation.
func (f *Feature) connect(s *vault.Session, body []byte) {
	id, ik, err := ParseConnect(body)
	if err != nil {
		drop(s, "drop.intro")
		return
	}
	r := f.fromIntroducer(s, id)
	if r == nil || r.State != StateAccepted && r.State != StateConnecting {
		drop(s, "drop.intro")
		return
	}
	if r.State != StateAccepted || r.InviteID != "" {
		return // already done
	}
	invID, link, err := s.CreateIntroInvite(ik, r.Conn)
	if err != nil {
		f.closeReceived(s, r, true)
		return
	}
	r.InviteID = invID
	_ = s.SendToConnection(r.Conn, "intro.invite", strictjson.NewBuilder().String("intro_id", id).String("link", link).Bytes())
	f.connecting(s, r)
}

// link: this vault (C) accepts A's invitation, once.
func (f *Feature) link(s *vault.Session, body []byte) {
	id, link, err := ParseLink(body)
	if err != nil {
		drop(s, "drop.intro")
		return
	}
	r := f.fromIntroducer(s, id)
	if r == nil || r.State != StateAccepted && r.State != StateConnecting {
		drop(s, "drop.intro")
		return
	}
	if r.State != StateAccepted || r.Linked || r.InviteID != "" {
		return // once only, and never on the side that made the invitation
	}
	r.Linked = true
	if _, err := s.AcceptInviteLink(link); err != nil {
		f.closeReceived(s, r, true)
		return
	}
	f.connecting(s, r)
}

// closed: the introducer ended the introduction (no reason given).
func (f *Feature) closed(s *vault.Session, body []byte) {
	id, err := ParseID(body)
	if err != nil {
		drop(s, "drop.intro")
		return
	}
	r := f.fromIntroducer(s, id)
	if r == nil {
		drop(s, "drop.intro")
		return
	}
	f.closeReceived(s, r, true)
}

func (f *Feature) list() []byte {
	made := []byte{'['}
	for i, id := range sortedKeys(f.d.Made) {
		m := f.d.Made[id]
		if i > 0 {
			made = append(made, ',')
		}
		made = append(made, strictjson.NewBuilder().String("intro_id", m.ID).String("a", m.A).String("c", m.C).
			String("state", m.State).String("exp", envelope.FormatTS(m.Exp)).Bytes()...)
	}
	recv := []byte{'['}
	for i, id := range sortedKeys(f.d.Received) {
		r := f.d.Received[id]
		if i > 0 {
			recv = append(recv, ',')
		}
		recv = append(recv, strictjson.NewBuilder().String("intro_id", r.ID).String("connection_id", r.Conn).
			Raw("peer", r.Peer.json()).String("state", r.State).String("exp", envelope.FormatTS(r.Exp)).Bytes()...)
	}
	return strictjson.NewBuilder().Raw("made", append(made, ']')).Raw("received", append(recv, ']')).Bytes()
}

// ConnectionRemoved implements vault.ConnectionRemovedObserver: the
// introductions the connection takes part in are closed (the other party
// told); offers from it as introducer are dropped without notice.
func (f *Feature) ConnectionRemoved(s *vault.Session, conn string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, id := range sortedKeys(f.d.Made) {
		m := f.d.Made[id]
		if (m.A == conn || m.C == conn) && (m.State == StateOffered || m.State == StateConnecting) {
			f.closeMade(s, m, conn)
		}
	}
	for _, id := range sortedKeys(f.d.Received) {
		if r := f.d.Received[id]; r.Conn == conn {
			if r.InviteID != "" && r.State != StateConnecting && r.State != StateClosed {
				s.CancelInvite(r.InviteID)
			}
			delete(f.d.Received, id)
		}
	}
}

// MadeList returns a copy of the introductions made (tests, tools).
func (f *Feature) MadeList() []Made {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []Made
	for _, id := range sortedKeys(f.d.Made) {
		out = append(out, *f.d.Made[id])
	}
	return out
}

// ReceivedList returns a copy of the offers received (tests, tools).
func (f *Feature) ReceivedList() []Received {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []Received
	for _, id := range sortedKeys(f.d.Received) {
		out = append(out, *f.d.Received[id])
	}
	return out
}
