// Package audit is the vault's audit log (VAULT-MESSAGING §10.9): an
// append-only, hash-chained record of security-relevant activity, kept in
// DEK state. It holds no content, secret values or keys.
//
// Ported from vettid.dev's per-connection audit trail (audit_log.go) and
// the audit side of its event table: one log with a connection filter
// replaces both, the chain hash covers a fixed binary encoding instead of
// a formatted string, and the per-entry signatures under a derived audit
// key are dropped (the log never leaves the E2E session; see V4-NOTES).
package audit

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// Limits (§10.9).
const (
	MaxEntries = 10000
	// Retention is fixed (§10.9): the log is append-only and no principal
	// can shorten it.
	Retention = 730 * 24 * time.Hour
	// DropsPerHour bounds drop.* entries per principal and kind, so that a
	// peer cannot flush the log with refused messages.
	DropsPerHour = 60
	DefaultLimit = 100
	MaxLimit     = 500
	MaxKinds     = 16
	MaxKindLen   = 64
	// MaxQ bounds q, in bytes (0.20.0).
	MaxQ = 128
	// SearchBudget is how many entries a request with q evaluates at
	// most (0.20.0): those that pass the other filters.
	SearchBudget = 2000
)

const label = "vettid/vms/2/audit"

// Entry is one audit entry.
type Entry struct {
	ID           string    `json:"id"`
	Seq          uint64    `json:"seq"`
	At           time.Time `json:"at"`
	Kind         string    `json:"kind"`
	ConnectionID string    `json:"connection_id,omitempty"`
	DeviceID     string    `json:"device_id,omitempty"`
	Ref          string    `json:"ref,omitempty"`
	Direction    string    `json:"direction,omitempty"`
	Prev         []byte    `json:"prev"`
	Hash         []byte    `json:"hash"`
}

type state struct {
	Seq     uint64   `json:"seq"`
	Head    []byte   `json:"head,omitempty"`
	Entries []*Entry `json:"entries"`
}

// Feature implements vault.Feature and vault.ActivitySink.
type Feature struct {
	mu    sync.Mutex
	st    state
	drops map[string]*dropWindow // memory only
	items ItemNames
}

// ItemNames is the items feature: an item's current name for the search
// (§10.9, 0.20.0); ok is false for an item that does not exist. It must
// not call back into this feature.
type ItemNames interface {
	ItemName(itemID string) (name string, ok bool)
}

type dropWindow struct {
	start time.Time
	n     int
}

// New returns an empty audit log.
func New() *Feature { return &Feature{drops: map[string]*dropWindow{}} }

// SetItems connects the items feature (at construction), whose item
// names the search reads; without it entries are found by their kind,
// connection and device only.
func (f *Feature) SetItems(it ItemNames) { f.items = it }

var owners = []string{vault.KindApp, vault.KindDesktop}

// Name implements vault.Feature.
func (f *Feature) Name() string { return "audit" }

// Types implements vault.Feature.
func (f *Feature) Types() []vault.TypeSpec {
	return []vault.TypeSpec{
		{Type: "audit.list", Request: true, From: owners},
		{Type: "connection.audit.list", Request: true, From: owners},
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
	f.st = st
	return nil
}

// Save implements vault.Feature.
func (f *Feature) Save() (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return json.Marshal(f.st)
}

// Hash computes an entry's chain hash (§10.9).
func Hash(prev []byte, e *Entry) []byte {
	h := sha256.New()
	h.Write([]byte(label))
	h.Write(prev)
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], e.Seq)
	h.Write(n[:])
	binary.BigEndian.PutUint64(n[:], uint64(e.At.UnixMilli()))
	h.Write(n[:])
	for _, s := range []string{e.Kind, e.ConnectionID, e.DeviceID, e.Ref, e.Direction} {
		var l [2]byte
		binary.BigEndian.PutUint16(l[:], uint16(len(s)))
		h.Write(l[:])
		h.Write([]byte(s))
	}
	return h.Sum(nil)
}

// RecordActivity implements vault.ActivitySink.
func (f *Feature) RecordActivity(s *vault.Session, a vault.Activity) {
	if !a.Audit {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	now := s.Now().UTC().Truncate(time.Millisecond)
	if strings.HasPrefix(a.Kind, "drop.") {
		key := a.Kind + "|" + a.ConnectionID + "|" + a.DeviceID
		w := f.drops[key]
		if w == nil || now.Sub(w.start) >= time.Hour {
			w = &dropWindow{start: now}
			f.drops[key] = w
		}
		w.n++
		switch {
		case w.n == DropsPerHour+1:
			a = vault.Activity{Kind: "drop.suppressed", ConnectionID: a.ConnectionID, DeviceID: a.DeviceID, Ref: a.Kind, Audit: true}
		case w.n > DropsPerHour:
			return
		}
	}
	f.append(s, now, a)
}

func (f *Feature) append(s *vault.Session, now time.Time, a vault.Activity) {
	prev := f.st.Head
	if len(prev) != sha256.Size {
		prev = make([]byte, sha256.Size)
	}
	e := &Entry{ID: s.NewID(), Seq: f.st.Seq + 1, At: now, Kind: clip(a.Kind, MaxKindLen),
		ConnectionID: a.ConnectionID, DeviceID: a.DeviceID, Ref: a.Ref, Direction: a.Direction, Prev: prev}
	e.Hash = Hash(prev, e)
	f.st.Seq, f.st.Head = e.Seq, e.Hash
	f.st.Entries = append(f.st.Entries, e)
	f.prune(now, Retention)
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func (f *Feature) prune(now time.Time, keep time.Duration) {
	i := 0
	for i < len(f.st.Entries) && (len(f.st.Entries)-i > MaxEntries || now.Sub(f.st.Entries[i].At) > keep) {
		i++
	}
	if i > 0 {
		f.st.Entries = append([]*Entry(nil), f.st.Entries[i:]...)
	}
}

// Query is a parsed audit.list / connection.audit.list request.
type Query struct {
	ConnectionID string
	Kinds        []string
	BeforeSeq    uint64 // 0: from the newest
	AfterSeq     uint64 // with After: oldest first, entries with seq > AfterSeq
	After        bool
	Limit        int
	// Q is the search string, lower-cased (strings.ToLower); "" for none
	// (0.20.0).
	Q string
	// Since and Until bound at in Unix milliseconds, inclusive and
	// exclusive, when HasSince / HasUntil (0.20.0).
	Since, Until       int64
	HasSince, HasUntil bool
}

var errBad = vault.NewError("bad_request", "")

// ParseQuery parses a request body strictly. needConn requires
// connection_id (connection.audit.list).
func ParseQuery(body []byte, needConn bool) (*Query, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	q := &Query{Limit: DefaultLimit}
	c, present, err := o.OptString("connection_id")
	if err != nil || (present && (c == "" || len(c) > 64)) || (needConn && !present) {
		return nil, errBad
	}
	q.ConnectionID = c
	if ks, present, err := o.OptArray("kinds"); err != nil {
		return nil, errBad
	} else if present {
		if len(ks) == 0 || len(ks) > MaxKinds {
			return nil, errBad
		}
		for _, raw := range ks {
			var k string
			if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &k) != nil || k == "" || len(k) > MaxKindLen {
				return nil, errBad
			}
			q.Kinds = append(q.Kinds, k)
		}
	}
	if b, present, err := o.OptUint("before_seq", 1, strictjson.MaxSafeInteger); err != nil {
		return nil, errBad
	} else if present {
		q.BeforeSeq = b
	}
	if a, present, err := o.OptUint("after_seq", 0, strictjson.MaxSafeInteger); err != nil || present && q.BeforeSeq != 0 {
		return nil, errBad
	} else if present {
		q.AfterSeq, q.After = a, true
	}
	if l, present, err := o.OptUint("limit", 1, MaxLimit); err != nil {
		return nil, errBad
	} else if present {
		q.Limit = int(l)
	}
	if s, present, err := o.OptString("q"); err != nil || present && !ValidQ(s) {
		return nil, errBad
	} else if present {
		q.Q = strings.ToLower(s)
	}
	var err2 error
	if q.Since, q.HasSince, err2 = optTime(o, "since"); err2 != nil {
		return nil, errBad
	}
	if q.Until, q.HasUntil, err2 = optTime(o, "until"); err2 != nil {
		return nil, errBad
	}
	if q.HasSince && q.HasUntil && q.Since >= q.Until {
		return nil, errBad
	}
	return q, nil
}

// ValidQ reports whether s is a search string (§10.9, 0.20.0): 1–128
// bytes of UTF-8, without control characters (C0, DEL, C1), not only
// white space.
func ValidQ(s string) bool {
	if s == "" || len(s) > MaxQ || !utf8.ValidString(s) {
		return false
	}
	blank := true
	for _, r := range s {
		if r < 0x20 || r >= 0x7f && r <= 0x9f {
			return false
		}
		if !unicode.IsSpace(r) {
			blank = false
		}
	}
	return !blank
}

// optTime parses an optional RFC 3339 member (any offset) into Unix
// milliseconds.
func optTime(o strictjson.Object, k string) (int64, bool, error) {
	s, present, err := o.OptString(k)
	if err != nil || !present {
		return 0, present, err
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return 0, true, err
	}
	return t.UnixMilli(), true, nil
}

func (q *Query) match(e *Entry) bool {
	if q.ConnectionID != "" && e.ConnectionID != q.ConnectionID {
		return false
	}
	if q.BeforeSeq != 0 && e.Seq >= q.BeforeSeq {
		return false
	}
	if q.After && e.Seq <= q.AfterSeq {
		return false
	}
	if at := e.At.UnixMilli(); q.HasSince && at < q.Since || q.HasUntil && at >= q.Until {
		return false
	}
	if len(q.Kinds) == 0 {
		return true
	}
	for _, k := range q.Kinds {
		if e.Kind == k || strings.HasPrefix(e.Kind, k+".") {
			return true
		}
	}
	return false
}

// EntryJSON is an entry's wire form (§10.9).
func EntryJSON(e *Entry) []byte {
	b := strictjson.NewBuilder().String("entry_id", e.ID).Uint("seq", e.Seq).String("at", envelope.FormatTS(e.At)).
		String("kind", e.Kind)
	if e.ConnectionID != "" {
		b.String("connection_id", e.ConnectionID)
	}
	if e.DeviceID != "" {
		b.String("device_id", e.DeviceID)
	}
	if e.Ref != "" {
		b.String("ref", e.Ref)
	}
	if e.Direction != "" {
		b.String("direction", e.Direction)
	}
	return b.Base64("prev", e.Prev).Base64("hash", e.Hash).Bytes()
}

// Handle implements vault.Handler. With q (0.20.0) it evaluates at most
// SearchBudget entries that pass the other filters; a page the budget cut
// short carries partial and the cursor of the last entry evaluated.
func (f *Feature) Handle(_ context.Context, s *vault.Session, in *envelope.Inner) (json.RawMessage, error) {
	q, err := ParseQuery(in.Body, in.Type == "connection.audit.list")
	if err != nil {
		return nil, err
	}
	// Entries never change once appended; the search reads names from
	// other features and the host without this feature's lock.
	f.mu.Lock()
	order := make([]*Entry, 0, len(f.st.Entries))
	if q.After {
		order = append(order, f.st.Entries...)
	} else {
		for i := len(f.st.Entries) - 1; i >= 0; i-- {
			order = append(order, f.st.Entries[i])
		}
	}
	head, seq := f.st.Head, f.st.Seq
	f.mu.Unlock()
	var names *searchNames
	if q.Q != "" {
		names = newSearchNames(s, f.items)
	}
	arr := []byte{'['}
	n, evaluated := 0, 0
	var last, lastEval, next uint64
	more, partial := false, false
	for _, e := range order {
		if !q.match(e) {
			continue
		}
		if names != nil {
			if evaluated == SearchBudget {
				// Entries remain that the budget does not reach.
				if n < q.Limit {
					next, partial = lastEval, true
				} else {
					next = last
				}
				more = true
				break
			}
			evaluated++
			lastEval = e.Seq
			if !names.match(e, q.Q) {
				continue
			}
		}
		if n == q.Limit {
			next, more = last, true // more remain: the next page continues from the last one returned
			break
		}
		if n > 0 {
			arr = append(arr, ',')
		}
		arr = append(arr, EntryJSON(e)...)
		n++
		last = e.Seq
	}
	b := strictjson.NewBuilder().Raw("entries", append(arr, ']'))
	if len(head) == 0 {
		head = make([]byte, sha256.Size)
	}
	b.Base64("head", head)
	b.Uint("seq", seq)
	switch {
	case more && q.After:
		b.Uint("next_after_seq", next)
	case more:
		b.Uint("next_before_seq", next)
	}
	if partial {
		b.Bool("partial", true)
	}
	return b.Bytes(), nil
}

// Entries returns a copy of the log (tests, tools).
func (f *Feature) Entries() []Entry {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]Entry, len(f.st.Entries))
	for i, e := range f.st.Entries {
		out[i] = *e
	}
	return out
}
