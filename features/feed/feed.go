// Package feed is the owner's activity feed and the app's guides
// (VAULT-MESSAGING §10.9). Items are created from vault activity and from
// guide.sync; read and archive state is shared by the owner's devices
// through sync.event.
//
// Ported from vettid.dev's event handler (events.go, events_types.go) and
// guide handler: the same statuses, priorities and guide versioning; items
// carry a kind and references instead of vault-composed titles (apps
// render them), and feed.sync is feed.list with after_seq.
package feed

import (
	"context"
	"encoding/json"
	"regexp"
	"sort"
	"sync"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// Limits (§10.9).
const (
	MaxItems        = 1000
	DefaultLimit    = 100
	MaxLimit        = 500
	MaxGuides       = 64
	MaxGuideTitle   = 256
	MaxGuideMessage = 4096
	MaxGuideVersion = 1 << 31
)

// Statuses.
const (
	StatusActive   = "active"
	StatusRead     = "read"
	StatusArchived = "archived"
	StatusDeleted  = "deleted"
)

var priorities = map[string]bool{"low": true, "normal": true, "high": true, "urgent": true}

// Item is one feed item.
type Item struct {
	ID           string    `json:"id"`
	Seq          uint64    `json:"seq"`
	Kind         string    `json:"kind"`
	At           time.Time `json:"at"`
	Status       string    `json:"status"`
	Priority     string    `json:"priority"`
	ConnectionID string    `json:"connection_id,omitempty"`
	DeviceID     string    `json:"device_id,omitempty"`
	Ref          string    `json:"ref,omitempty"`
	Title        string    `json:"title,omitempty"`
	Body         string    `json:"body,omitempty"`
	// Count is the number of asks a batch's item stands for (§10.4.1,
	// 0.23.0); 0 or 1 is not sent.
	Count int `json:"count,omitempty"`
}

// Batch is a connection's open batch of asks (§10.4.1): the feed item
// that stands for it and when its first ask reached the member.
type Batch struct {
	ItemID string    `json:"item_id"`
	Start  time.Time `json:"start"`
}

type state struct {
	Seq    uint64            `json:"seq"`
	Items  []*Item           `json:"items"`
	Guides map[string]uint64 `json:"guides,omitempty"` // guide_id -> version seen
	// Batches are the open batches of asks, by connection id.
	Batches map[string]*Batch `json:"batches,omitempty"`
}

// Feature implements vault.Feature and vault.ActivitySink.
type Feature struct {
	mu sync.Mutex
	st state
}

// New returns an empty feed.
func New() *Feature { return &Feature{st: state{Guides: map[string]uint64{}}} }

var owners = []string{vault.KindApp, vault.KindDesktop}

// Name implements vault.Feature.
func (f *Feature) Name() string { return "feed" }

// Types implements vault.Feature.
func (f *Feature) Types() []vault.TypeSpec {
	return []vault.TypeSpec{
		{Type: "feed.list", Request: true, From: owners},
		{Type: "feed.get", Request: true, From: owners},
		{Type: "feed.update", Request: true, From: owners},
		{Type: "feed.delete", Request: true, From: owners},
		{Type: "guide.sync", Request: true, From: owners},
	}
}

// Load implements vault.Feature.
func (f *Feature) Load(data json.RawMessage) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	var st state
	if err := json.Unmarshal(data, &st); err != nil {
		return err
	}
	if st.Guides == nil {
		st.Guides = map[string]uint64{}
	}
	f.st = st
	return nil
}

// Save implements vault.Feature.
func (f *Feature) Save() (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return json.Marshal(f.st)
}

// RecordActivity implements vault.ActivitySink.
func (f *Feature) RecordActivity(s *vault.Session, a vault.Activity) {
	if !a.Feed {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	p := a.Priority
	if !priorities[p] {
		p = "normal"
	}
	if a.AskBatch && a.ConnectionID != "" && f.batched(s, a.ConnectionID) {
		return
	}
	it := &Item{Kind: a.Kind, Priority: p, ConnectionID: a.ConnectionID, DeviceID: a.DeviceID, Ref: a.Ref}
	f.add(s, it)
	if a.AskBatch && a.ConnectionID != "" {
		if f.st.Batches == nil {
			f.st.Batches = map[string]*Batch{}
		}
		f.st.Batches[a.ConnectionID] = &Batch{ItemID: it.ID, Start: it.At}
	}
}

// batched counts an ask into its connection's open batch (§10.4.1): an
// ask within 10 minutes of the batch's first updates the batch's item (a
// new seq, the same item_id, count) instead of creating one; it reports
// false when no batch is open (none, ended, or its item deleted).
func (f *Feature) batched(s *vault.Session, conn string) bool {
	now := s.Now()
	for c, b := range f.st.Batches {
		if !now.Before(b.Start.Add(vault.AskBatchWindow)) {
			delete(f.st.Batches, c)
		}
	}
	b := f.st.Batches[conn]
	if b == nil {
		return false
	}
	it := f.find(b.ItemID)
	if it == nil || it.Status == StatusDeleted {
		delete(f.st.Batches, conn)
		return false
	}
	if it.Count < 1 {
		it.Count = 1
	}
	it.Count++
	f.st.Seq++
	it.Seq = f.st.Seq
	s.NotifyAllDevices("sync.event", strictjson.NewBuilder().String("kind", "feed.updated").String("item_id", it.ID).
		Uint("seq", it.Seq).Bytes())
	return true
}

// add stores a new item and sends feed.event to every owner device.
func (f *Feature) add(s *vault.Session, it *Item) {
	now := s.Now().UTC().Truncate(time.Millisecond)
	f.st.Seq++
	it.ID, it.Seq, it.At, it.Status = s.NewID(), f.st.Seq, now, StatusActive
	f.st.Items = append(f.st.Items, it)
	f.prune(now, s.Settings().FeedRetention())
	s.NotifyAllDevices("feed.event", ItemJSON(it))
}

func (f *Feature) prune(now time.Time, keep time.Duration) {
	i := 0
	for i < len(f.st.Items) && (len(f.st.Items)-i > MaxItems || now.Sub(f.st.Items[i].At) > keep) {
		i++
	}
	if i > 0 {
		f.st.Items = append([]*Item(nil), f.st.Items[i:]...)
	}
}

// ItemJSON is an item's wire form (§10.9).
func ItemJSON(it *Item) []byte {
	b := strictjson.NewBuilder().String("item_id", it.ID).Uint("seq", it.Seq).String("kind", it.Kind).
		String("at", envelope.FormatTS(it.At)).String("status", it.Status).String("priority", it.Priority)
	if it.ConnectionID != "" {
		b.String("connection_id", it.ConnectionID)
	}
	if it.DeviceID != "" {
		b.String("device_id", it.DeviceID)
	}
	if it.Ref != "" {
		b.String("ref", it.Ref)
	}
	if it.Count >= 2 {
		b.Uint("count", uint64(it.Count))
	}
	if it.Status != StatusDeleted {
		if it.Title != "" {
			b.String("title", it.Title)
		}
		if it.Body != "" {
			b.String("body", it.Body)
		}
	}
	return b.Bytes()
}

var (
	errBad      = vault.NewError("bad_request", "")
	errNotFound = vault.NewError("not_found", "")
)

// Handle implements vault.Handler.
func (f *Feature) Handle(_ context.Context, s *vault.Session, in *envelope.Inner) (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch in.Type {
	case "feed.list":
		q, err := ParseList(in.Body)
		if err != nil {
			return nil, err
		}
		return f.list(q), nil
	case "feed.get":
		id, err := itemID(in.Body)
		if err != nil {
			return nil, err
		}
		it := f.find(id)
		if it == nil || it.Status == StatusDeleted {
			return nil, errNotFound
		}
		return ItemJSON(it), nil
	case "feed.update":
		u, err := ParseUpdate(in.Body)
		if err != nil {
			return nil, err
		}
		it := f.find(u.ItemID)
		if it == nil || it.Status == StatusDeleted {
			return nil, errNotFound
		}
		if u.Status != "" {
			it.Status = u.Status
		}
		if u.Priority != "" {
			it.Priority = u.Priority
		}
		f.st.Seq++
		it.Seq = f.st.Seq
		s.SyncEvent("feed.updated", strictjson.NewBuilder().String("item_id", it.ID).Uint("seq", it.Seq).Bytes())
		return ItemJSON(it), nil
	case "feed.delete":
		id, err := itemID(in.Body)
		if err != nil {
			return nil, err
		}
		it := f.find(id)
		if it == nil || it.Status == StatusDeleted {
			return nil, errNotFound
		}
		f.st.Seq++
		it.Status, it.Seq, it.Title, it.Body = StatusDeleted, f.st.Seq, "", ""
		s.SyncEvent("feed.deleted", strictjson.NewBuilder().String("item_id", it.ID).Uint("seq", it.Seq).Bytes())
		return nil, nil
	case "guide.sync":
		gs, err := ParseGuides(in.Body)
		if err != nil {
			return nil, err
		}
		var created, updated uint64
		for _, g := range gs {
			seen, ok := f.st.Guides[g.ID]
			if ok && g.Version <= seen {
				continue
			}
			if ok {
				updated++
			} else {
				created++
			}
			f.st.Guides[g.ID] = g.Version
			f.add(s, &Item{Kind: "guide", Priority: g.Priority, Ref: g.ID, Title: g.Title, Body: g.Message})
		}
		return strictjson.NewBuilder().Uint("created", created).Uint("updated", updated).Bytes(), nil
	}
	return nil, vault.NewError("unsupported_type", "")
}

func (f *Feature) find(id string) *Item {
	for _, it := range f.st.Items {
		if it.ID == id {
			return it
		}
	}
	return nil
}

func itemID(body []byte) (string, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return "", errBad
	}
	id, err := o.String("item_id")
	if err != nil || !envelope.ValidULID(id) {
		return "", errBad
	}
	return id, nil
}

// ListQuery is a parsed feed.list request.
type ListQuery struct {
	Status   string // "all" or a status
	AfterSeq uint64
	After    bool
	Limit    int
}

// ParseList parses a feed.list body strictly.
func ParseList(body []byte) (*ListQuery, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	q := &ListQuery{Status: "all", Limit: DefaultLimit}
	if st, present, err := o.OptString("status"); err != nil {
		return nil, errBad
	} else if present {
		if st != "all" && st != StatusActive && st != StatusRead && st != StatusArchived {
			return nil, errBad
		}
		q.Status = st
	}
	if a, present, err := o.OptUint("after_seq", 0, strictjson.MaxSafeInteger); err != nil {
		return nil, errBad
	} else if present {
		q.AfterSeq, q.After = a, true
	}
	if l, present, err := o.OptUint("limit", 1, MaxLimit); err != nil {
		return nil, errBad
	} else if present {
		q.Limit = int(l)
	}
	return q, nil
}

func (f *Feature) list(q *ListQuery) []byte {
	var sel []*Item
	if q.After {
		for _, it := range f.st.Items {
			if it.Seq > q.AfterSeq && (q.Status == "all" || it.Status == q.Status || it.Status == StatusDeleted) {
				sel = append(sel, it)
			}
		}
		sort.Slice(sel, func(i, j int) bool { return sel[i].Seq < sel[j].Seq })
	} else {
		for i := len(f.st.Items) - 1; i >= 0; i-- {
			it := f.st.Items[i]
			if it.Status != StatusDeleted && (q.Status == "all" || it.Status == q.Status) {
				sel = append(sel, it)
			}
		}
	}
	if len(sel) > q.Limit {
		sel = sel[:q.Limit]
	}
	arr := []byte{'['}
	for i, it := range sel {
		if i > 0 {
			arr = append(arr, ',')
		}
		arr = append(arr, ItemJSON(it)...)
	}
	return strictjson.NewBuilder().Raw("items", append(arr, ']')).Uint("seq", f.st.Seq).Bytes()
}

// Update is a parsed feed.update request.
type Update struct {
	ItemID   string
	Status   string
	Priority string
}

// ParseUpdate parses a feed.update body strictly.
func ParseUpdate(body []byte) (*Update, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	u := &Update{}
	if u.ItemID, err = o.String("item_id"); err != nil || !envelope.ValidULID(u.ItemID) {
		return nil, errBad
	}
	st, sp, err := o.OptString("status")
	if err != nil || (sp && st != StatusActive && st != StatusRead && st != StatusArchived) {
		return nil, errBad
	}
	pr, pp, err := o.OptString("priority")
	if err != nil || (pp && !priorities[pr]) || (!sp && !pp) {
		return nil, errBad
	}
	u.Status, u.Priority = st, pr
	return u, nil
}

// Guide is one guide of a guide.sync request.
type Guide struct {
	ID       string
	Version  uint64
	Title    string
	Message  string
	Priority string
}

var guideIDRE = regexp.MustCompile(`^[a-z0-9_.-]{1,64}$`)

// ParseGuides parses a guide.sync body strictly.
func ParseGuides(body []byte) ([]Guide, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	arr, err := o.Array("guides")
	if err != nil || len(arr) > MaxGuides {
		return nil, errBad
	}
	seen := map[string]bool{}
	out := make([]Guide, 0, len(arr))
	for _, raw := range arr {
		g, err := strictjson.AsObject(raw)
		if err != nil {
			return nil, errBad
		}
		var x Guide
		if x.ID, err = g.String("guide_id"); err != nil || !guideIDRE.MatchString(x.ID) || seen[x.ID] {
			return nil, errBad
		}
		seen[x.ID] = true
		if x.Version, err = g.Uint("version", 1, MaxGuideVersion); err != nil {
			return nil, errBad
		}
		if x.Title, err = g.String("title"); err != nil || x.Title == "" || len(x.Title) > MaxGuideTitle {
			return nil, errBad
		}
		if x.Message, err = g.String("message"); err != nil || len(x.Message) > MaxGuideMessage {
			return nil, errBad
		}
		x.Priority = "normal"
		if p, present, err := g.OptString("priority"); err != nil || (present && !priorities[p]) {
			return nil, errBad
		} else if present {
			x.Priority = p
		}
		out = append(out, x)
	}
	return out, nil
}

// Items returns a copy of the feed (tests, tools).
func (f *Feature) Items() []Item {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]Item, len(f.st.Items))
	for i, it := range f.st.Items {
		out[i] = *it
	}
	return out
}
