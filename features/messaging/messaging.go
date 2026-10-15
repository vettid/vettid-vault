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
	"github.com/vettid/vettid-vault/vms/attwire"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// Limits.
const (
	MaxText      = 16 * 1024 // larger content travels as a claim-check blob (§5.5)
	DefaultLimit = 100
	MaxLimit     = 500
	// PageBytes bounds a message.list response's body (§10.5.2, 0.32.0):
	// room under §5.5's 245,760-byte padded inner plaintext for the
	// members around it.
	PageBytes = 131072
)

// pageBytes is PageBytes; tests lower it.
var pageBytes = PageBytes

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
	// AttID names the message's attachment in the runtime's index
	// (§10.5.1; 0.32.0, release A).
	AttID string `json:"att_id,omitempty"`
	// Refused is an incoming attachment refused on arrival, which has no
	// index entry: its device view, failed with its reason.
	Refused *RefusedAtt `json:"refused,omitempty"`
}

// RefusedAtt is what is kept of an attachment refused on arrival.
type RefusedAtt struct {
	AttID  string `json:"att_id"`
	Kind   string `json:"kind"`
	Size   int    `json:"size"`
	Width  int    `json:"w"`
	Height int    `json:"h"`
	Reason string `json:"reason"`
}

// hasAttachment reports whether the message has an attachment.
func (m *Message) hasAttachment() bool { return m.AttID != "" || m.Refused != nil }

// hiddenFromAgents: to an agent a message with an attachment is its
// caption alone, and one without a caption does not exist (§10.5.1
// "Agents").
func (m *Message) hiddenFromAgents() bool { return m.hasAttachment() && m.Text == "" }

// Feature implements vault.Feature.
type Feature struct {
	mu    sync.Mutex
	convs map[string][]*Message // connection id -> messages, in arrival order
}

// New returns an empty messaging feature.
func New() *Feature { return &Feature{convs: map[string][]*Message{}} }

var (
	owners = []string{vault.KindApp, vault.KindDesktop}
	apps   = []string{vault.KindApp}
	conns  = []string{vault.KindConnection}
)

// Name implements vault.Feature.
func (f *Feature) Name() string { return "messaging" }

// Types implements vault.Feature.
func (f *Feature) Types() []vault.TypeSpec {
	return []vault.TypeSpec{
		{Type: "message.send", Request: true, From: owners},
		// Reads whose answers are large: volatile, never cached in vault
		// state (§8.2, §10.5.2; 0.32.0).
		{Type: "message.list", Request: true, Volatile: true, From: owners},
		{Type: "message.get", Request: true, Volatile: true, From: owners},
		{Type: "message.read", Request: true, From: owners},
		{Type: "message.delete", Request: true, From: owners},
		{Type: "message.deliver", From: conns},
		{Type: "message.receipt", From: conns},
		// Attachments (§10.5.1; 0.32.0, release A): app-only; both parts of
		// message.attachment.get are volatile, and its shape is checked
		// before the hold (the app's availability probe).
		{Type: vault.TypeAttGet, Request: true, Volatile: true, From: apps, Shape: getShapeOK},
		{Type: vault.TypeAttDiscard, Request: true, From: apps},
		{Type: vault.TypeAttDeliver, From: conns},
		{Type: vault.TypeAttStatus, From: conns},
	}
}

// AppOnly implements vault.AppOnlyForms: message.send with an attachment
// is the app's alone; a desktop or an agent is answered forbidden whatever
// its grants (§10.5.1 "Desktops", "Agents").
func (f *Feature) AppOnly(typ string, body json.RawMessage) bool {
	if typ != "message.send" {
		return false
	}
	o, err := strictjson.ParseObject(body)
	return err == nil && o.Has("attachment")
}

// getShape parses message.attachment.get's body.
func getShape(o strictjson.Object) (conn, msg, part string, ok bool) {
	conn, err1 := o.String("connection_id")
	msg, err2 := o.String("message_id")
	part, has, err3 := o.OptString("part")
	if !has {
		part = attwire.PartContent
	}
	switch part {
	case "content":
		part = attwire.PartContent
	case "thumb":
		part = attwire.PartThumb
	default:
		if has {
			return "", "", "", false
		}
	}
	if err1 != nil || err2 != nil || err3 != nil || conn == "" || msg == "" || len(conn) > 4096 || len(msg) > 64 {
		return "", "", "", false
	}
	return conn, msg, part, true
}

func getShapeOK(body []byte) bool {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return false
	}
	_, _, _, ok := getShape(o)
	return ok
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
		return f.listFor(s, o)
	case "message.get":
		return f.get(s, o)
	case "message.read":
		return f.read(s, o)
	case "message.delete":
		return f.del(s, o)
	case vault.TypeAttGet:
		return f.attGet(s, o)
	case vault.TypeAttDiscard:
		return f.attDiscard(s, o)
	case vault.TypeAttDeliver:
		return nil, f.attDeliver(s, o)
	case vault.TypeAttStatus:
		if ah := s.Attachments(); ah != nil {
			return nil, ah.AttachStatus(s, in.Body)
		}
		return nil, nil
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

func msgJSON(conn string, m *Message) []byte { return msgView(conn, m, nil) }

// msgView renders a message.new body; att, if set, is its attachment's
// device view (§10.5.1).
func msgView(conn string, m *Message, att []byte) []byte {
	b := strictjson.NewBuilder().String("connection_id", conn).String("message_id", m.ID).String("direction", m.Dir).
		String("text", m.Text).String("sent_at", envelope.FormatTS(m.SentAt)).Bool("delivered", m.Delivered).
		Bool("read", m.Read)
	if att != nil {
		b.Raw("attachment", att)
	}
	return b.Bytes()
}

// viewer is who a message is rendered for.
type viewer int

const (
	viewApp viewer = iota
	viewDesktop
	viewAgent
)

func viewerOf(s *vault.Session) viewer {
	if s == nil {
		return viewApp
	}
	switch s.From().Kind {
	case vault.KindDesktop:
		return viewDesktop
	case vault.KindAgent:
		return viewAgent
	}
	return viewApp
}

// attView is a message's attachment view for v, nil for an agent or a
// message without one. thumb, if set, is added for the app (message.new).
func attView(s *vault.Session, m *Message, v viewer, thumb []byte) []byte {
	if v == viewAgent || !m.hasAttachment() {
		return nil
	}
	if m.Refused != nil {
		r := m.Refused
		return vault.AttView{AttID: r.AttID, Kind: r.Kind, Size: r.Size, Width: r.Width, Height: r.Height,
			State: vault.AttFailed, Reason: r.Reason}.JSON(false, v == viewDesktop)
	}
	var ah vault.AttachmentHost
	if s != nil {
		ah = s.Attachments()
	}
	if ah == nil {
		return nil
	}
	av, ok := ah.AttachView(m.AttID)
	if !ok {
		return nil
	}
	av.Thumb = thumb
	return av.JSON(thumb != nil, v == viewDesktop)
}

// render is a message for v: an agent gets the caption alone (§10.5.1).
func render(s *vault.Session, conn string, m *Message, v viewer, thumb []byte) []byte {
	return msgView(conn, m, attView(s, m, v, thumb))
}

// notifyNew sends message.new to the owner's devices (except the sender
// of the current message when exceptSender): the app with the thumbnail,
// a desktop without thumbnail and name (§10.5.1); agents never get it.
func notifyNew(s *vault.Session, conn string, m *Message, thumb []byte, exceptSender bool) {
	except := ""
	if exceptSender {
		except = s.From().ID
	}
	if !m.hasAttachment() {
		s.NotifyDevicesWith("message.new", msgJSON(conn, m), except, vault.SendOptions{})
		return
	}
	s.NotifyDevicesWith("message.new", render(s, conn, m, viewApp, thumb), except, vault.SendOptions{Kind: vault.KindApp})
	s.NotifyDevicesWith("message.new", render(s, conn, m, viewDesktop, nil), except, vault.SendOptions{Kind: vault.KindDesktop})
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

// send: D→V request {connection_id, text} → {message_id, sent_at}; with
// an attachment (§10.5.1) {connection_id, text?, attachment} → {message_id,
// sent_at, att_id}.
func (f *Feature) send(s *vault.Session, o strictjson.Object) (json.RawMessage, error) {
	conn, err := activeConn(s, o)
	if err != nil {
		if o.Has("attachment") {
			refuseBlob(s, o)
		}
		return nil, err
	}
	if o.Has("attachment") {
		return f.sendAttachment(s, conn, o)
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

// refuseBlob deletes the blob a refused message.send names (§10.5.1).
func refuseBlob(s *vault.Session, o strictjson.Object) {
	ah := s.Attachments()
	if ah == nil {
		return
	}
	a, err := o.Object("attachment")
	if err != nil {
		return
	}
	b, err := a.Object("blob")
	if err != nil {
		return
	}
	if id, err := b.String("id"); err == nil {
		ah.AttachRefusedSend(s, id)
	}
}

// sendAttachment: sending steps 3 and 4 (§10.5.1). The message is stored
// and answered once its checks pass; the transfer follows in the
// background and its progress as sync.event{message.attachment}.
func (f *Feature) sendAttachment(s *vault.Session, conn string, o strictjson.Object) (json.RawMessage, error) {
	ah := s.Attachments()
	if s.From().Kind != vault.KindApp {
		refuseBlob(s, o)
		return nil, vault.NewError("forbidden", "")
	}
	if ah == nil || ah.AttachMaxContent() == 0 {
		refuseBlob(s, o)
		return nil, vault.NewError("unavailable", "") // the relay advertises no blobs (§1.2)
	}
	text, _, err := o.OptString("text")
	if err != nil || len(text) > MaxText {
		refuseBlob(s, o)
		return nil, errBad
	}
	a, err := o.Object("attachment")
	if err != nil {
		refuseBlob(s, o)
		return nil, errBad
	}
	d, err := attwire.ParseDeviceSend(a, ah.AttachMaxContent())
	if err != nil {
		refuseBlob(s, o)
		return nil, errBad
	}
	if p, ok := s.Connection(conn); !ok || p.State != vault.PeerActive {
		ah.AttachRefusedSend(s, d.Blob.ID)
		return nil, vault.NewError("connection_unavailable", "")
	}
	m := &Message{ID: s.NewID(), Dir: DirOut, Text: text, SentAt: s.Now().UTC().Truncate(time.Millisecond)}
	attID, err := ah.AttachSend(s, conn, m.ID, m.SentAt, text, o.Has("text"), d)
	if err != nil {
		return nil, err
	}
	m.AttID = attID
	f.convs[conn] = append(f.convs[conn], m)
	notifyNew(s, conn, m, d.Thumb, true)
	return strictjson.NewBuilder().String("message_id", m.ID).String("sent_at", envelope.FormatTS(m.SentAt)).
		String("att_id", attID).Bytes(), nil
}

// attDeliver: message.attachment.deliver from a connection (§10.5.1
// "Receiving"): a new message with an attachment, or a fresh upload of a
// known one. A malformed one is dropped and audited.
func (f *Feature) attDeliver(s *vault.Session, o strictjson.Object) error {
	conn := s.From().ID
	ah := s.Attachments()
	if ah == nil {
		return nil
	}
	drop := func() error {
		s.Record(vault.Activity{Kind: "drop.attachment_malformed", ConnectionID: conn, Audit: true})
		return nil
	}
	id, err := o.String("message_id")
	if err != nil || !envelope.ValidULID(id) {
		return drop()
	}
	text, _, err := o.OptString("text")
	if err != nil || len(text) > MaxText {
		return drop()
	}
	sa, err := o.String("sent_at")
	if err != nil {
		return drop()
	}
	sentAt, err := envelope.ParseTS(sa)
	if err != nil {
		return drop()
	}
	a, err := o.Object("attachment")
	if err != nil {
		return drop()
	}
	max := ah.AttachMaxContent()
	if max == 0 {
		max = attwire.ReferenceMaxContent // checked for shape; refused below
	}
	v, err := attwire.ParsePeerView(a, max)
	if err != nil {
		return drop()
	}
	if m := f.find(conn, id); m != nil {
		if m.AttID != "" {
			ah.AttachRedeliver(s, id, v)
		} else if v.Blob != nil {
			ah.AttachRefusedSend(s, v.Blob.ID)
		}
		return nil // idempotent by message_id (§10)
	}
	m := &Message{ID: id, Dir: DirIn, Text: text, SentAt: sentAt}
	var thumb []byte
	if ah.AttachMaxContent() == 0 {
		m.Refused = &RefusedAtt{AttID: s.NewID(), Kind: v.Kind, Size: v.Size, Width: v.Width, Height: v.Height, Reason: vault.ReasonFull}
	} else if attID, refused := ah.AttachReceive(s, id, v); refused != nil {
		m.Refused = &RefusedAtt{AttID: s.NewID(), Kind: refused.Kind, Size: refused.Size, Width: refused.Width, Height: refused.Height, Reason: refused.Reason}
	} else {
		m.AttID, thumb = attID, v.Thumb
	}
	f.convs[conn] = append(f.convs[conn], m)
	notifyNew(s, conn, m, thumb, false)
	s.Record(vault.Activity{Kind: "message.received", ConnectionID: conn, Ref: m.ID, Direction: DirIn, Audit: true, Feed: true})
	return s.SendToConnection(conn, "message.receipt", receiptJSON(id, "delivered", s.Now()))
}

// attGet: message.attachment.get (§10.5.1 "Fetching").
func (f *Feature) attGet(s *vault.Session, o strictjson.Object) (json.RawMessage, error) {
	conn, id, part, ok := getShape(o)
	if !ok {
		return nil, errBad
	}
	m := f.find(conn, id)
	if m == nil || !m.hasAttachment() {
		return nil, errNotFound
	}
	if m.Refused != nil {
		return nil, vault.NewError("unavailable", "")
	}
	ah := s.Attachments()
	if ah == nil {
		return nil, errNotFound
	}
	return ah.AttachGet(s, conn, id, m.AttID, part)
}

// attDiscard: message.attachment.discard{blob_id} → {} in every case.
func (f *Feature) attDiscard(s *vault.Session, o strictjson.Object) (json.RawMessage, error) {
	id, err := o.String("blob_id")
	if err != nil {
		return nil, errBad
	}
	if ah := s.Attachments(); ah != nil {
		ah.AttachDiscard(s, id)
	}
	return nil, nil
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

// list: {connection_id, limit?, before?} → {messages: [...], next_before?}
// (§10.5, §10.5.2). The page ends before `before` (a position in arrival
// order, exclusive) or with the newest message; it holds at most `limit`
// messages and stops before the message whose addition would make the
// body exceed PageBytes, but always holds one message when one is older.
// It is returned oldest first; next_before, the id of its oldest message,
// is present only when older messages remain.
func (f *Feature) list(o strictjson.Object) (json.RawMessage, error) { return f.listFor(nil, o) }

func (f *Feature) listFor(s *vault.Session, o strictjson.Object) (json.RawMessage, error) {
	v := viewerOf(s)
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
	before, hasBefore, err := o.OptString("before")
	if err != nil {
		return nil, errBad
	}
	ms := f.convs[conn]
	if v == viewAgent {
		// What the agent is not given is not there for it: its paging and
		// budget count only what it sees (§10.5.1 "Agents").
		vis := make([]*Message, 0, len(ms))
		for _, m := range ms {
			if !m.hiddenFromAgents() {
				vis = append(vis, m)
			}
		}
		ms = vis
	}
	end := len(ms)
	if hasBefore {
		end = -1
		for i, m := range ms {
			if m.ID == before {
				end = i
				break
			}
		}
		if end < 0 {
			return nil, errNotFound // unknown, or deleted since: the app starts again from the newest
		}
	}
	// Newest first from end, within the limit and the byte budget.
	size := len(`{"messages":[]}`)
	var items [][]byte
	start := end
	for start > 0 && len(items) < int(limit) {
		item := render(s, conn, ms[start-1], v, nil)
		n := size + len(item)
		if len(items) > 0 {
			n++ // the comma
		}
		if start-1 > 0 {
			n += nextBeforeLen(ms[start-1].ID) // older messages would remain
		}
		if len(items) > 0 && n > pageBytes {
			break
		}
		items = append(items, item)
		size += len(item)
		if len(items) > 1 {
			size++
		}
		start--
	}
	arr := []byte{'['}
	for i := len(items) - 1; i >= 0; i-- {
		if i < len(items)-1 {
			arr = append(arr, ',')
		}
		arr = append(arr, items[i]...)
	}
	b := strictjson.NewBuilder().Raw("messages", append(arr, ']'))
	if start > 0 {
		b.String("next_before", ms[start].ID)
	}
	return b.Bytes(), nil
}

// nextBeforeLen is the length that the next_before member adds to a body.
func nextBeforeLen(id string) int {
	return len(strictjson.NewBuilder().String("next_before", id).Bytes()) - len(`{}`) + len(`,`)
}

func (f *Feature) get(s *vault.Session, o strictjson.Object) (json.RawMessage, error) {
	conn, err1 := o.String("connection_id")
	id, err2 := o.String("message_id")
	if err1 != nil || err2 != nil {
		return nil, errBad
	}
	m := f.find(conn, id)
	v := viewerOf(s)
	if m == nil || v == viewAgent && m.hiddenFromAgents() {
		return nil, errNotFound
	}
	return render(s, conn, m, v, nil), nil
}

// read marks an incoming message read and sends a read receipt.
func (f *Feature) read(s *vault.Session, o strictjson.Object) (json.RawMessage, error) {
	conn, err1 := o.String("connection_id")
	id, err2 := o.String("message_id")
	if err1 != nil || err2 != nil {
		return nil, errBad
	}
	m := f.find(conn, id)
	if m == nil || m.Dir != DirIn || viewerOf(s) == viewAgent && m.hiddenFromAgents() {
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

func (f *Feature) del(s *vault.Session, o strictjson.Object) (json.RawMessage, error) {
	conn, err1 := o.String("connection_id")
	id, err2 := o.String("message_id")
	if err1 != nil || err2 != nil {
		return nil, errBad
	}
	ms := f.convs[conn]
	for i, m := range ms {
		if m.ID == id {
			if viewerOf(s) == viewAgent && m.hiddenFromAgents() {
				return nil, errNotFound // not there for an agent (§10.5.1 "Agents")
			}
			f.convs[conn] = append(ms[:i:i], ms[i+1:]...)
			if m.AttID != "" && s != nil {
				// §10.5.1 "Deletion": its stored attachment is erased.
				if ah := s.Attachments(); ah != nil {
					ah.AttachErase(s, m.AttID)
				}
			}
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
