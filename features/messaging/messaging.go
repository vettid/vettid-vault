// Package messaging is the first vault feature: 1:1 messages between
// connections (VAULT-MESSAGING §10, body schemas in §10.5).
package messaging

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// Limits.
const (
	MaxText      = 16 * 1024 // larger content travels as a claim-check blob (§5.5)
	DefaultLimit = 100
	MaxLimit     = 500
)

// Directions.
const (
	DirIn  = "in"
	DirOut = "out"
)

// Message is one stored message.
type Message struct {
	ID        string    `json:"id"`
	Dir       string    `json:"dir"`
	Text      string    `json:"text"`
	SentAt    time.Time `json:"sent_at"`
	Delivered bool      `json:"delivered,omitempty"`
	Read      bool      `json:"read,omitempty"`
}

// Feature implements vault.Feature.
type Feature struct {
	mu    sync.Mutex
	convs map[string][]*Message // connection id -> messages, in arrival order
}

// New returns an empty messaging feature.
func New() *Feature { return &Feature{convs: map[string][]*Message{}} }

var (
	owners = []string{vault.KindApp, vault.KindDesktop}
	conns  = []string{vault.KindConnection}
)

// Name implements vault.Feature.
func (f *Feature) Name() string { return "messaging" }

// Types implements vault.Feature.
func (f *Feature) Types() []vault.TypeSpec {
	return []vault.TypeSpec{
		{Type: "message.send", Request: true, From: owners},
		{Type: "message.list", Request: true, From: owners},
		{Type: "message.get", Request: true, From: owners},
		{Type: "message.read", Request: true, From: owners},
		{Type: "message.delete", Request: true, From: owners},
		{Type: "message.deliver", From: conns},
		{Type: "message.receipt", From: conns},
	}
}

// Load implements vault.Feature.
func (f *Feature) Load(data json.RawMessage) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := map[string][]*Message{}
	if err := json.Unmarshal(data, &c); err != nil {
		return err
	}
	f.convs = c
	return nil
}

// Save implements vault.Feature.
func (f *Feature) Save() (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return json.Marshal(f.convs)
}

var errBad = vault.NewError("bad_request", "")
var errNotFound = vault.NewError("not_found", "")

// Handle implements vault.Handler.
func (f *Feature) Handle(_ context.Context, s *vault.Session, in *envelope.Inner) (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	o, err := strictjson.ParseObject(in.Body)
	if err != nil {
		return nil, errBad
	}
	switch in.Type {
	case "message.send":
		return f.send(s, o)
	case "message.deliver":
		return nil, f.deliver(s, in.Body)
	case "message.receipt":
		return nil, f.receipt(s, in.Body)
	case "message.list":
		return f.list(o)
	case "message.get":
		return f.get(o)
	case "message.read":
		return f.read(s, o)
	case "message.delete":
		return f.del(o)
	}
	return nil, vault.NewError("unsupported_type", "")
}

func (f *Feature) find(conn, id string) *Message {
	for _, m := range f.convs[conn] {
		if m.ID == id {
			return m
		}
	}
	return nil
}

func msgJSON(conn string, m *Message) []byte {
	return strictjson.NewBuilder().String("connection_id", conn).String("message_id", m.ID).String("direction", m.Dir).
		String("text", m.Text).String("sent_at", envelope.FormatTS(m.SentAt)).Bool("delivered", m.Delivered).
		Bool("read", m.Read).Bytes()
}

func activeConn(s *vault.Session, o strictjson.Object) (string, error) {
	id, err := o.String("connection_id")
	if err != nil {
		return "", errBad
	}
	if _, ok := s.Connection(id); !ok {
		return "", errNotFound
	}
	return id, nil
}

// send: D→V request {connection_id, text} → {message_id, sent_at}.
func (f *Feature) send(s *vault.Session, o strictjson.Object) (json.RawMessage, error) {
	conn, err := activeConn(s, o)
	if err != nil {
		return nil, err
	}
	text, err := o.String("text")
	if err != nil || text == "" || len(text) > MaxText {
		return nil, errBad
	}
	m := &Message{ID: s.NewID(), Dir: DirOut, Text: text, SentAt: s.Now().UTC().Truncate(time.Millisecond)}
	body := strictjson.NewBuilder().String("message_id", m.ID).String("text", text).
		String("sent_at", envelope.FormatTS(m.SentAt)).Bytes()
	if err := s.SendToConnection(conn, "message.deliver", body); err != nil {
		return nil, vault.NewError("connection_unavailable", "")
	}
	f.convs[conn] = append(f.convs[conn], m)
	s.NotifyDevices("message.new", msgJSON(conn, m))
	s.Record(vault.Activity{Kind: "message.sent", ConnectionID: conn, Ref: m.ID, Direction: DirOut, Audit: true})
	return strictjson.NewBuilder().String("message_id", m.ID).String("sent_at", envelope.FormatTS(m.SentAt)).Bytes(), nil
}

// Deliver is a parsed message.deliver body.
type Deliver struct {
	MessageID string
	Text      string
	SentAt    time.Time
}

// ParseDeliver parses a message.deliver body (from a peer vault, which may
// be malicious) strictly.
func ParseDeliver(body []byte) (*Deliver, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	d := &Deliver{}
	if d.MessageID, err = o.String("message_id"); err != nil || !envelope.ValidULID(d.MessageID) {
		return nil, errBad
	}
	if d.Text, err = o.String("text"); err != nil || d.Text == "" || len(d.Text) > MaxText {
		return nil, errBad
	}
	sa, err := o.String("sent_at")
	if err != nil {
		return nil, errBad
	}
	if d.SentAt, err = envelope.ParseTS(sa); err != nil {
		return nil, errBad
	}
	return d, nil
}

// deliver: V↔V event {message_id, text, sent_at}. Idempotent by message_id.
func (f *Feature) deliver(s *vault.Session, body []byte) error {
	conn := s.From().ID
	d, err := ParseDeliver(body)
	if err != nil {
		return err
	}
	if f.find(conn, d.MessageID) == nil {
		m := &Message{ID: d.MessageID, Dir: DirIn, Text: d.Text, SentAt: d.SentAt}
		f.convs[conn] = append(f.convs[conn], m)
		s.NotifyAllDevices("message.new", msgJSON(conn, m))
		s.Record(vault.Activity{Kind: "message.received", ConnectionID: conn, Ref: m.ID, Direction: DirIn, Audit: true, Feed: true})
	}
	return s.SendToConnection(conn, "message.receipt", receiptJSON(d.MessageID, "delivered", s.Now()))
}

func receiptJSON(id, kind string, at time.Time) []byte {
	return strictjson.NewBuilder().String("message_id", id).String("receipt", kind).String("at", envelope.FormatTS(at)).Bytes()
}

// Receipt is a parsed message.receipt body.
type Receipt struct {
	MessageID string
	Kind      string // "delivered" or "read"
	At        time.Time
}

// ParseReceipt parses a message.receipt body strictly.
func ParseReceipt(body []byte) (*Receipt, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	r := &Receipt{}
	if r.MessageID, err = o.String("message_id"); err != nil || !envelope.ValidULID(r.MessageID) {
		return nil, errBad
	}
	if r.Kind, err = o.String("receipt"); err != nil || (r.Kind != "delivered" && r.Kind != "read") {
		return nil, errBad
	}
	at, err := o.String("at")
	if err != nil {
		return nil, errBad
	}
	if r.At, err = envelope.ParseTS(at); err != nil {
		return nil, errBad
	}
	return r, nil
}

// receipt: V↔V event {message_id, receipt: delivered|read, at}.
func (f *Feature) receipt(s *vault.Session, body []byte) error {
	conn := s.From().ID
	r, err := ParseReceipt(body)
	if err != nil {
		return err
	}
	m := f.find(conn, r.MessageID)
	if m == nil || m.Dir != DirOut {
		return nil
	}
	m.Delivered = true
	if r.Kind == "read" {
		m.Read = true
	}
	s.NotifyAllDevices("sync.event", strictjson.NewBuilder().String("kind", "message.receipt").
		String("connection_id", conn).String("message_id", r.MessageID).String("receipt", r.Kind).Bytes())
	return nil
}

// list: {connection_id, limit?} → {messages: [...]}, oldest first, the
// most recent `limit`.
func (f *Feature) list(o strictjson.Object) (json.RawMessage, error) {
	conn, err := o.String("connection_id")
	if err != nil {
		return nil, errBad
	}
	limit, present, err := o.OptUint("limit", 1, MaxLimit)
	if err != nil {
		return nil, errBad
	}
	if !present {
		limit = DefaultLimit
	}
	ms := f.convs[conn]
	if len(ms) > int(limit) {
		ms = ms[len(ms)-int(limit):]
	}
	arr := []byte{'['}
	for i, m := range ms {
		if i > 0 {
			arr = append(arr, ',')
		}
		arr = append(arr, msgJSON(conn, m)...)
	}
	return strictjson.NewBuilder().Raw("messages", append(arr, ']')).Bytes(), nil
}

func (f *Feature) get(o strictjson.Object) (json.RawMessage, error) {
	conn, err1 := o.String("connection_id")
	id, err2 := o.String("message_id")
	if err1 != nil || err2 != nil {
		return nil, errBad
	}
	m := f.find(conn, id)
	if m == nil {
		return nil, errNotFound
	}
	return msgJSON(conn, m), nil
}

// read marks an incoming message read and sends a read receipt.
func (f *Feature) read(s *vault.Session, o strictjson.Object) (json.RawMessage, error) {
	conn, err1 := o.String("connection_id")
	id, err2 := o.String("message_id")
	if err1 != nil || err2 != nil {
		return nil, errBad
	}
	m := f.find(conn, id)
	if m == nil || m.Dir != DirIn {
		return nil, errNotFound
	}
	if !m.Read {
		m.Read = true
		_ = s.SendToConnection(conn, "message.receipt", receiptJSON(id, "read", s.Now()))
		s.NotifyDevices("sync.event", strictjson.NewBuilder().String("kind", "message.read").
			String("connection_id", conn).String("message_id", id).Bytes())
	}
	return nil, nil
}

func (f *Feature) del(o strictjson.Object) (json.RawMessage, error) {
	conn, err1 := o.String("connection_id")
	id, err2 := o.String("message_id")
	if err1 != nil || err2 != nil {
		return nil, errBad
	}
	ms := f.convs[conn]
	for i, m := range ms {
		if m.ID == id {
			f.convs[conn] = append(ms[:i:i], ms[i+1:]...)
			return nil, nil
		}
	}
	return nil, errNotFound
}

// Conversation returns a copy of a conversation (tests, tools).
func (f *Feature) Conversation(conn string) []Message {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]Message, 0, len(f.convs[conn]))
	for _, m := range f.convs[conn] {
		out = append(out, *m)
	}
	return out
}
