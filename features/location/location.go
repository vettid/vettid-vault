// Package location is 1:1 location sharing with connections
// (VAULT-MESSAGING §10.16): the member starts a share to one connection,
// once or continuously until an expiry, at a chosen precision and
// cadence; the member's device sends samples to its own vault, which
// reduces them to the share's precision and forwards them, from memory
// only, to the connection's vault. The receiving vault keeps the latest
// sample (and, if the sharer allowed it, the trail) only while the share
// is active. Either side can stop a share; a connection can ask the
// member to share.
//
// Ported from vettid.dev's location.go: the member's own location
// history, its compaction and retention settings, the per-connection
// sharing toggle without expiry and the automatic fulfilment of requests
// are dropped (the vault is not a location log; every share is an
// explicit, expiring consent); precision, which was a no-op there, is
// applied by the sending vault.
package location

import (
	"context"
	"encoding/json"
	"sort"
	"sync"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// Outgoing is a share this vault makes to a connection. It holds no
// sample: samples are forwarded from memory.
type Outgoing struct {
	ID        string    `json:"id"`
	Conn      string    `json:"conn"`
	Mode      string    `json:"mode"`
	Precision string    `json:"precision"`
	Interval  int64     `json:"interval,omitempty"` // seconds (continuous)
	History   bool      `json:"history,omitempty"`
	Device    string    `json:"device"` // the source device
	Started   time.Time `json:"started"`
	Expires   time.Time `json:"expires"`
	LastSent  time.Time `json:"last_sent,omitempty"`
}

// Incoming is a share a connection makes to this vault.
type Incoming struct {
	ID        string    `json:"id"`
	Conn      string    `json:"conn"`
	Mode      string    `json:"mode"`
	Precision string    `json:"precision"`
	Interval  int64     `json:"interval,omitempty"`
	History   bool      `json:"history,omitempty"`
	Started   time.Time `json:"started"`
	Expires   time.Time `json:"expires"`
	Last      *Sample   `json:"last,omitempty"`
	Trail     []Sample  `json:"trail,omitempty"`
	// Snapshot is the sharer's log snapshot (location.snapshot), kept
	// with the share.
	Snapshot []Sample `json:"snapshot,omitempty"`
}

// InRequest is a connection's request that the member share.
type InRequest struct {
	ID   string    `json:"id"`
	Conn string    `json:"conn"`
	Note string    `json:"note,omitempty"`
	Exp  time.Time `json:"exp"`
}

type data struct {
	Out      map[string]*Outgoing  `json:"out"`
	In       map[string]*Incoming  `json:"in"`
	Requests map[string]*InRequest `json:"requests"`
	// SentReq and RecvReq: the last request made to / accepted from each
	// connection (rate limits).
	SentReq map[string]time.Time `json:"sent_req"`
	RecvReq map[string]time.Time `json:"recv_req"`
	// Ended holds ended incoming share ids until their expiry, so a
	// repeated location.shared does not revive them.
	Ended map[string]time.Time `json:"ended"`
	// Log is the member's own location log (§10.16), oldest first.
	Log          []LogPoint `json:"log,omitempty"`
	LogCompacted time.Time  `json:"log_compacted,omitempty"`
}

func (d *data) init() {
	if d.Out == nil {
		d.Out = map[string]*Outgoing{}
	}
	if d.In == nil {
		d.In = map[string]*Incoming{}
	}
	if d.Requests == nil {
		d.Requests = map[string]*InRequest{}
	}
	if d.SentReq == nil {
		d.SentReq = map[string]time.Time{}
	}
	if d.RecvReq == nil {
		d.RecvReq = map[string]time.Time{}
	}
	if d.Ended == nil {
		d.Ended = map[string]time.Time{}
	}
}

// Feature implements vault.Feature and vault.ConnectionRemovedObserver.
type Feature struct {
	mu sync.Mutex
	d  data
}

// New returns the feature.
func New() *Feature {
	f := &Feature{}
	f.d.init()
	return f
}

var (
	owners = []string{vault.KindApp, vault.KindDesktop}
	conns  = []string{vault.KindConnection}
	all    = []string{vault.KindApp, vault.KindDesktop, vault.KindConnection}
)

// Name implements vault.Feature.
func (f *Feature) Name() string { return "location" }

// Types implements vault.Feature.
func (f *Feature) Types() []vault.TypeSpec {
	return []vault.TypeSpec{
		// Starting a share discloses data to a connection: desktops only
		// with an app's approval (§6.8).
		{Type: "location.share.start", Request: true, From: owners, DesktopApproval: true},
		{Type: "location.share.stop", Request: true, From: owners},
		{Type: "location.share.list", Request: true, From: owners},
		{Type: "location.get", Request: true, From: owners},
		{Type: "location.request", Request: true, From: owners},
		// Samples are ephemeral in both directions (§8.5): never in vault
		// state on the sending side.
		{Type: "location.update", Ephemeral: true, From: all},
		{Type: "location.shared", From: conns},
		{Type: "location.stopped", From: conns},
		{Type: "location.requested", From: conns},
		{Type: "location.snapshot", From: conns},
		// The member's own log: apps; desktops with an app's approval
		// (§6.8), as it reveals where the member has been.
		{Type: "location.history.list", Request: true, From: owners, DesktopApproval: true},
		{Type: "location.history.delete", Request: true, From: owners, DesktopApproval: true},
		{Type: "location.history.share", Request: true, From: owners, DesktopApproval: true},
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
	d.init()
	f.d = d
	return nil
}

// Save implements vault.Feature.
func (f *Feature) Save() (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return json.Marshal(f.d)
}

// Handle implements vault.Handler.
func (f *Feature) Handle(_ context.Context, s *vault.Session, in *envelope.Inner) (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sweep(s)
	peer := s.From().Kind == vault.KindConnection
	switch in.Type {
	case "location.share.start":
		return f.start(s, in.Body)
	case "location.share.stop":
		return f.stop(s, in.Body)
	case "location.share.list":
		if err := emptyObject(in.Body); err != nil {
			return nil, err
		}
		return f.list(), nil
	case "location.get":
		return f.get(s, in.Body)
	case "location.request":
		return f.request(s, in.Body)
	case "location.update":
		if peer {
			f.peerUpdate(s, in)
		} else {
			f.deviceUpdate(s, in.Body)
		}
	case "location.shared":
		f.shared(s, in.Body)
	case "location.stopped":
		f.stopped(s, in.Body)
	case "location.requested":
		f.requested(s, in.Body)
	case "location.snapshot":
		f.snapshot(s, in.Body)
	case "location.history.list":
		return f.historyList(s, in.Body)
	case "location.history.delete":
		return f.historyDelete(s, in.Body)
	case "location.history.share":
		return f.historyShare(s, in.Body)
	default:
		return nil, vault.NewError("unsupported_type", "")
	}
	return nil, nil
}

func ts(t time.Time) time.Time { return t.UTC().Truncate(time.Millisecond) }

func (f *Feature) drop(s *vault.Session, kind string) {
	s.Record(vault.Activity{Kind: kind, ConnectionID: s.From().ID, Audit: true})
}

func (f *Feature) syncShare(s *vault.Session, id, state string) {
	s.SyncEvent("location.share.changed", strictjson.NewBuilder().String("share_id", id).String("state", state).Bytes())
}

func event(ev, dir, conn, id string) *strictjson.Builder {
	return strictjson.NewBuilder().String("event", ev).String("direction", dir).String("connection_id", conn).String("share_id", id)
}

// sweep ends expired shares and requests (§10.16).
func (f *Feature) sweep(s *vault.Session) {
	now := s.Now()
	for _, id := range sortedKeys(f.d.Out) {
		if o := f.d.Out[id]; !now.Before(o.Expires) {
			delete(f.d.Out, id)
			f.syncShare(s, id, "ended")
		}
	}
	for _, id := range sortedKeys(f.d.In) {
		if sh := f.d.In[id]; !now.Before(sh.Expires) {
			f.endIncoming(s, sh)
		}
	}
	for id, r := range f.d.Requests {
		if !now.Before(r.Exp) {
			delete(f.d.Requests, id)
		}
	}
	for id, exp := range f.d.Ended {
		if !now.Before(exp) {
			delete(f.d.Ended, id)
		}
	}
	for c, t := range f.d.SentReq {
		if now.Sub(t) >= RequestEvery {
			delete(f.d.SentReq, c)
		}
	}
	for c, t := range f.d.RecvReq {
		if now.Sub(t) >= RequestEvery {
			delete(f.d.RecvReq, c)
		}
	}
}

// endIncoming deletes an incoming share with its samples.
func (f *Feature) endIncoming(s *vault.Session, sh *Incoming) {
	delete(f.d.In, sh.ID)
	f.d.Ended[sh.ID] = sh.Expires
	s.Record(vault.Activity{Kind: "location.share.ended", ConnectionID: sh.Conn, Ref: sh.ID, Direction: "in", Audit: true})
}

func (f *Feature) start(s *vault.Session, body []byte) (json.RawMessage, error) {
	st, err := ParseStart(body)
	if err != nil {
		return nil, err
	}
	c, ok := s.Connection(st.ConnectionID)
	if !ok {
		return nil, errNotFound
	}
	if c.State != vault.PeerActive {
		return nil, errConn
	}
	var old *Outgoing
	for _, o := range f.d.Out {
		if o.Conn == st.ConnectionID {
			old = o
		}
	}
	if old == nil && len(f.d.Out) >= MaxOutgoing {
		return nil, errLimit
	}
	now := s.Now()
	o := &Outgoing{ID: s.NewID(), Conn: st.ConnectionID, Mode: st.Mode, Precision: st.Precision,
		Interval: int64(st.Interval / time.Second), History: st.History, Device: s.From().ID,
		Started: ts(now), Expires: ts(now.Add(st.Duration))}
	if old != nil {
		_ = s.SendToConnection(old.Conn, "location.stopped", strictjson.NewBuilder().String("share_id", old.ID).Bytes())
		delete(f.d.Out, old.ID)
		f.syncShare(s, old.ID, "ended")
	}
	b := strictjson.NewBuilder().String("share_id", o.ID).String("mode", o.Mode).String("precision", o.Precision)
	if o.Mode == Continuous {
		b.Uint("interval_seconds", uint64(o.Interval))
	}
	b.Bool("history", o.History).String("expires_at", envelope.FormatTS(o.Expires))
	if err := s.SendToConnection(o.Conn, "location.shared", b.Bytes()); err != nil {
		return nil, errConn
	}
	f.d.Out[o.ID] = o
	if r := f.d.Requests[st.RequestID]; r != nil && r.Conn == o.Conn {
		delete(f.d.Requests, r.ID)
	}
	f.syncShare(s, o.ID, "active")
	s.Record(vault.Activity{Kind: "location.share.started", ConnectionID: o.Conn, Ref: o.ID, Direction: "out", Audit: true})
	return strictjson.NewBuilder().String("share_id", o.ID).String("expires_at", envelope.FormatTS(o.Expires)).Bytes(), nil
}

// fresh reports whether a sample's time is acceptable now.
func fresh(sm *Sample, now time.Time) bool {
	return !sm.At.After(now.Add(MaxFuture)) && !sm.At.Before(now.Add(-MaxAge))
}

// deviceUpdate forwards a device's sample to the shares it feeds,
// reduced to their precision, from memory only (§10.16).
func (f *Feature) deviceUpdate(s *vault.Session, body []byte) {
	_, sm, err := ParseSample(body, false)
	now := s.Now()
	if err != nil || !fresh(sm, now) {
		f.drop(s, "drop.location_malformed")
		return
	}
	f.record(s, sm) // the member's own log, if enabled
	for _, id := range sortedKeys(f.d.Out) {
		o := f.d.Out[id]
		if o.Device != s.From().ID {
			continue
		}
		iv := time.Duration(o.Interval) * time.Second
		if o.Mode == Continuous && !o.LastSent.IsZero() && now.Sub(o.LastSent) < iv*9/10 {
			continue // cadence
		}
		exp := o.Expires
		if o.Mode == Continuous {
			if e := now.Add(max(2*iv, time.Minute)); e.Before(exp) {
				exp = e
			}
		}
		out := Reduce(sm, o.Precision).json("", o.ID, false)
		if err := s.Send(o.Conn, "location.update", out, vault.SendOptions{Exp: ts(exp), MemoryOnly: true}); err != nil {
			continue
		}
		o.LastSent = ts(now)
		if o.Mode == Once {
			delete(f.d.Out, o.ID) // its one sample is on its way
			f.syncShare(s, o.ID, "ended")
		}
	}
}

// peerUpdate takes a connection's sample for an incoming share.
func (f *Feature) peerUpdate(s *vault.Session, in *envelope.Inner) {
	now := s.Now()
	conn := s.From().ID
	id, sm, err := ParseSample(in.Body, true)
	if err != nil || in.Exp.IsZero() || in.Exp.After(now.Add(MaxUpdateExpSkew)) || !fresh(sm, now) {
		f.drop(s, "drop.location_malformed")
		return
	}
	sh := f.d.In[id]
	if sh == nil || sh.Conn != conn {
		f.drop(s, "drop.location")
		return
	}
	if sh.Last != nil {
		gap := max(MinPeerGap, time.Duration(sh.Interval)*time.Second/2)
		if sh.Mode == Once || now.Sub(sh.Last.Received) < gap {
			f.drop(s, "drop.location_rate")
			return
		}
	}
	sm.Received = ts(now)
	sh.Last = sm
	if sh.History {
		sh.Trail = append(sh.Trail, *sm)
		if len(sh.Trail) > MaxHistory {
			sh.Trail = append([]Sample(nil), sh.Trail[len(sh.Trail)-MaxHistory:]...)
		}
	}
	s.NotifyDevicesWith("location.update", sm.json(conn, sh.ID, false), "", vault.SendOptions{Exp: ts(now.Add(time.Minute)), MemoryOnly: true})
}

func (f *Feature) stop(s *vault.Session, body []byte) (json.RawMessage, error) {
	id, err := ParseShareID(body)
	if err != nil {
		return nil, err
	}
	stopped := strictjson.NewBuilder().String("share_id", id).Bytes()
	if o := f.d.Out[id]; o != nil {
		delete(f.d.Out, id)
		_ = s.SendToConnection(o.Conn, "location.stopped", stopped)
		f.syncShare(s, id, "ended")
		s.Record(vault.Activity{Kind: "location.share.stopped", ConnectionID: o.Conn, Ref: id, Direction: "out", Audit: true})
		return json.RawMessage(`{}`), nil
	}
	if sh := f.d.In[id]; sh != nil {
		delete(f.d.In, id)
		f.d.Ended[id] = sh.Expires
		_ = s.SendToConnection(sh.Conn, "location.stopped", stopped) // asks the sharer to stop
		f.syncShare(s, id, "ended")
		s.Record(vault.Activity{Kind: "location.share.stopped", ConnectionID: sh.Conn, Ref: id, Direction: "in", Audit: true})
		return json.RawMessage(`{}`), nil
	}
	return nil, errNotFound
}

func (o *Outgoing) json() []byte {
	b := strictjson.NewBuilder().String("share_id", o.ID).String("connection_id", o.Conn).String("mode", o.Mode).String("precision", o.Precision)
	if o.Mode == Continuous {
		b.Uint("interval_seconds", uint64(o.Interval))
	}
	b.Bool("history", o.History).String("device_id", o.Device).String("started_at", envelope.FormatTS(o.Started)).
		String("expires_at", envelope.FormatTS(o.Expires))
	if !o.LastSent.IsZero() {
		b.String("last_sent_at", envelope.FormatTS(o.LastSent))
	}
	return b.Bytes()
}

func (sh *Incoming) json() []byte {
	b := strictjson.NewBuilder().String("share_id", sh.ID).String("connection_id", sh.Conn).String("mode", sh.Mode).String("precision", sh.Precision)
	if sh.Mode == Continuous {
		b.Uint("interval_seconds", uint64(sh.Interval))
	}
	b.Bool("history", sh.History).String("started_at", envelope.FormatTS(sh.Started)).String("expires_at", envelope.FormatTS(sh.Expires))
	if sh.Last != nil {
		b.Raw("last", sh.Last.json("", "", true))
	}
	return b.Bytes()
}

func (f *Feature) list() json.RawMessage {
	out := []byte{'['}
	for i, id := range sortedKeys(f.d.Out) {
		if i > 0 {
			out = append(out, ',')
		}
		out = append(out, f.d.Out[id].json()...)
	}
	in := []byte{'['}
	for i, id := range sortedKeys(f.d.In) {
		if i > 0 {
			in = append(in, ',')
		}
		in = append(in, f.d.In[id].json()...)
	}
	return strictjson.NewBuilder().Raw("outgoing", append(out, ']')).Raw("incoming", append(in, ']')).Bytes()
}

func (f *Feature) get(_ *vault.Session, body []byte) (json.RawMessage, error) {
	g, err := ParseGet(body)
	if err != nil {
		return nil, err
	}
	for _, id := range sortedKeys(f.d.In) {
		sh := f.d.In[id]
		if sh.Conn != g.ConnectionID {
			continue
		}
		b := strictjson.NewBuilder().String("share_id", sh.ID).String("mode", sh.Mode).String("precision", sh.Precision).
			String("expires_at", envelope.FormatTS(sh.Expires))
		if sh.Last != nil {
			b.Raw("last", sh.Last.json("", "", true))
		}
		if g.History && sh.History {
			arr := []byte{'['}
			for i := range sh.Trail {
				if i > 0 {
					arr = append(arr, ',')
				}
				arr = append(arr, sh.Trail[i].json("", "", true)...)
			}
			b.Raw("history", append(arr, ']'))
		}
		if len(sh.Snapshot) > 0 {
			arr := []byte{'['}
			for i := range sh.Snapshot {
				if i > 0 {
					arr = append(arr, ',')
				}
				arr = append(arr, sh.Snapshot[i].json("", "", true)...)
			}
			b.Raw("snapshot", append(arr, ']'))
		}
		return b.Bytes(), nil
	}
	return nil, errNotFound
}

func (f *Feature) request(s *vault.Session, body []byte) (json.RawMessage, error) {
	r, err := ParseRequest(body, false)
	if err != nil {
		return nil, err
	}
	if _, ok := s.Connection(r.ConnectionID); !ok {
		return nil, errNotFound
	}
	if _, recent := f.d.SentReq[r.ConnectionID]; recent {
		return nil, errLimit
	}
	id := s.NewID()
	b := strictjson.NewBuilder().String("request_id", id)
	if r.Note != "" {
		b.String("note", r.Note)
	}
	if err := s.SendToConnection(r.ConnectionID, "location.requested", b.Bytes()); err != nil {
		return nil, errConn
	}
	f.d.SentReq[r.ConnectionID] = ts(s.Now())
	s.Record(vault.Activity{Kind: "location.requested", ConnectionID: r.ConnectionID, Ref: id, Direction: "out", Audit: true})
	return strictjson.NewBuilder().String("request_id", id).Bytes(), nil
}

func (f *Feature) requested(s *vault.Session, body []byte) {
	conn := s.From().ID
	r, err := ParseRequest(body, true)
	if err != nil {
		f.drop(s, "drop.location_malformed")
		return
	}
	if _, dup := f.d.Requests[r.RequestID]; dup {
		return
	}
	if _, recent := f.d.RecvReq[conn]; recent || len(f.d.Requests) >= MaxRequestsIn {
		f.drop(s, "drop.location_rate")
		return
	}
	now := s.Now()
	q := &InRequest{ID: r.RequestID, Conn: conn, Note: r.Note, Exp: ts(now.Add(RequestTTL))}
	f.d.Requests[q.ID] = q
	f.d.RecvReq[conn] = ts(now)
	b := strictjson.NewBuilder().String("request_id", q.ID).String("connection_id", conn)
	if q.Note != "" {
		b.String("note", q.Note)
	}
	s.NotifyAllDevices("location.request.pending", b.String("exp", envelope.FormatTS(q.Exp)).Bytes())
	s.Record(vault.Activity{Kind: "location.requested", ConnectionID: conn, Ref: q.ID, Direction: "in", Audit: true})
	s.Record(vault.Activity{Kind: "location.request", ConnectionID: conn, Ref: q.ID, Feed: true})
}

func (f *Feature) shared(s *vault.Session, body []byte) {
	conn := s.From().ID
	now := s.Now()
	sh, err := ParseShared(body)
	if err != nil || !sh.Expires.After(now) || sh.Expires.After(now.Add(MaxDuration*time.Second+MaxFuture)) {
		f.drop(s, "drop.location_malformed")
		return
	}
	if _, dup := f.d.In[sh.ShareID]; dup {
		return
	}
	if _, ended := f.d.Ended[sh.ShareID]; ended {
		return
	}
	for _, id := range sortedKeys(f.d.In) {
		if old := f.d.In[id]; old.Conn == conn {
			delete(f.d.In, id) // replaced, with its samples
			f.d.Ended[id] = old.Expires
		}
	}
	if len(f.d.In) >= MaxIncoming {
		f.drop(s, "drop.location_limit")
		return
	}
	in := &Incoming{ID: sh.ShareID, Conn: conn, Mode: sh.Mode, Precision: sh.Precision, Interval: int64(sh.Interval / time.Second),
		History: sh.History, Started: ts(now), Expires: ts(sh.Expires)}
	f.d.In[in.ID] = in
	s.NotifyAllDevices("location.event", event("started", "in", conn, in.ID).String("mode", in.Mode).
		String("precision", in.Precision).String("expires_at", envelope.FormatTS(in.Expires)).Bytes())
	s.Record(vault.Activity{Kind: "location.share.received", ConnectionID: conn, Ref: in.ID, Direction: "in", Audit: true})
	s.Record(vault.Activity{Kind: "location.shared", ConnectionID: conn, Ref: in.ID, Feed: true})
}

func (f *Feature) stopped(s *vault.Session, body []byte) {
	conn := s.From().ID
	id, err := ParseShareID(body)
	if err != nil {
		f.drop(s, "drop.location_malformed")
		return
	}
	if sh := f.d.In[id]; sh != nil && sh.Conn == conn {
		f.endIncoming(s, sh)
		s.NotifyAllDevices("location.event", event("stopped", "in", conn, id).Bytes())
		return
	}
	if o := f.d.Out[id]; o != nil && o.Conn == conn {
		delete(f.d.Out, id) // the receiver asked us to stop
		s.NotifyAllDevices("location.event", event("stopped", "out", conn, id).Bytes())
		s.Record(vault.Activity{Kind: "location.share.ended", ConnectionID: conn, Ref: id, Direction: "out", Audit: true})
	}
}

// ConnectionRemoved implements vault.ConnectionRemovedObserver (§7.4).
func (f *Feature) ConnectionRemoved(_ *vault.Session, conn string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for id, o := range f.d.Out {
		if o.Conn == conn {
			delete(f.d.Out, id)
		}
	}
	for id, sh := range f.d.In {
		if sh.Conn == conn {
			delete(f.d.In, id)
		}
	}
	for id, r := range f.d.Requests {
		if r.Conn == conn {
			delete(f.d.Requests, id)
		}
	}
	delete(f.d.SentReq, conn)
	delete(f.d.RecvReq, conn)
}

// Shares returns the ids of the outgoing and incoming shares (tests).
func (f *Feature) Shares() (out, in []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return sortedKeys(f.d.Out), sortedKeys(f.d.In)
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
