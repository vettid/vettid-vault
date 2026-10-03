// Package profile is the owner's profile (VAULT-MESSAGING §10.8): one set
// of fields, which also holds what vettid.dev called personal data, a
// display name, a photo, and the list of fields shared with connections.
// The shared view reaches connections only as E2E profile.update messages
// (§9.3); there is no published or retained profile.
//
// Ported from vettid.dev's profile and personal-data handlers (profile.go,
// personal_data.go): fields with labels (the old aliases) and sort order;
// profile.publish/.broadcast/.get-published and the public settings become
// `shared` plus profile.update; registration "system" fields become
// ordinary fields set by the app.
package profile

import (
	"bytes"
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

// Limits (§10.8).
const (
	MaxFields = 200
	MaxValue  = 4096
	MaxLabel  = 64
	MaxName   = 128
	MaxPhoto  = 65536
)

var keyRE = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,63}$`)

// Field is one profile field.
type Field struct {
	Value     string    `json:"value"`
	Label     string    `json:"label,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
}

type state struct {
	Version uint64            `json:"version"`
	Name    string            `json:"name"`
	Fields  map[string]*Field `json:"fields"`
	Shared  []string          `json:"shared"`
	Order   []string          `json:"order"`
	Photo   []byte            `json:"photo,omitempty"`
	// Peers is the highest profile.update version seen per connection.
	Peers map[string]uint64 `json:"peers,omitempty"`
}

// Feature implements vault.Feature, vault.ConnectionObserver and
// vault.HandshakeProfiler.
type Feature struct {
	mu sync.Mutex
	st state
}

// New returns an empty profile.
func New() *Feature {
	return &Feature{st: state{Fields: map[string]*Field{}, Peers: map[string]uint64{}}}
}

var (
	owners = []string{vault.KindApp, vault.KindDesktop}
	conns  = []string{vault.KindConnection}
)

// Name implements vault.Feature.
func (f *Feature) Name() string { return "profile" }

// Types implements vault.Feature.
func (f *Feature) Types() []vault.TypeSpec {
	return []vault.TypeSpec{
		{Type: "profile.get", Request: true, From: owners},
		{Type: "profile.set", Request: true, From: owners},
		{Type: "profile.update", From: conns},
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
	if st.Fields == nil {
		st.Fields = map[string]*Field{}
	}
	if st.Peers == nil {
		st.Peers = map[string]uint64{}
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

// DisplayName implements vault.HandshakeProfiler.
func (f *Feature) DisplayName() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.st.Name
}

// ConnectionAdded implements vault.ConnectionObserver: the new connection
// gets the current shared profile (§9.3).
func (f *Feature) ConnectionAdded(s *vault.Session, id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.st.Version > 0 {
		_ = s.SendToConnection(id, "profile.update", f.sharedView())
	}
}

// sharedView is the profile.update body.
func (f *Feature) sharedView() []byte {
	fields := strictjson.NewBuilder()
	keys := append([]string(nil), f.st.Shared...)
	sort.Strings(keys)
	for _, k := range keys {
		fl := f.st.Fields[k]
		if fl == nil {
			continue
		}
		fb := strictjson.NewBuilder().String("value", fl.Value)
		if fl.Label != "" {
			fb.String("label", fl.Label)
		}
		fields.Raw(k, fb.Bytes())
	}
	b := strictjson.NewBuilder().Uint("version", f.st.Version).String("name", f.st.Name).Raw("fields", fields.Bytes())
	if len(f.st.Photo) > 0 {
		b.Base64("photo", f.st.Photo)
	}
	return b.Bytes()
}

var (
	errBad      = vault.NewError("bad_request", "")
	errConflict = vault.NewError("conflict", "")
	errLimit    = vault.NewError("limit", "")
)

// Set is a parsed profile.set body.
type Set struct {
	Version  uint64
	Name     *string
	SetF     map[string]Field
	Delete   []string
	Shared   []string
	HasShare bool
	Order    []string
	HasOrder bool
	Photo    []byte
	HasPhoto bool
}

func keyList(o strictjson.Object, name string) ([]string, bool, error) {
	arr, present, err := o.OptArray(name)
	if err != nil {
		return nil, false, errBad
	}
	if !present {
		return nil, false, nil
	}
	if len(arr) > MaxFields {
		return nil, false, errBad
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(arr))
	for _, raw := range arr {
		var k string
		if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &k) != nil || !keyRE.MatchString(k) || seen[k] {
			return nil, false, errBad
		}
		seen[k] = true
		out = append(out, k)
	}
	return out, true, nil
}

func parseFields(o strictjson.Object, name string, required bool) (map[string]Field, error) {
	fo, err := o.Object(name)
	if err != nil {
		if !required && err == strictjson.ErrMissing {
			return nil, nil
		}
		return nil, errBad
	}
	if len(fo) > MaxFields {
		return nil, errBad
	}
	out := make(map[string]Field, len(fo))
	for k, raw := range fo {
		if !keyRE.MatchString(k) {
			return nil, errBad
		}
		v, err := strictjson.AsObject(raw)
		if err != nil {
			return nil, errBad
		}
		var fl Field
		if fl.Value, err = v.String("value"); err != nil || fl.Value == "" || len(fl.Value) > MaxValue {
			return nil, errBad
		}
		if l, present, err := v.OptString("label"); err != nil || len(l) > MaxLabel {
			return nil, errBad
		} else if present {
			fl.Label = l
		}
		out[k] = fl
	}
	return out, nil
}

func photo(o strictjson.Object, allowEmpty bool) ([]byte, bool, error) {
	s, present, err := o.OptString("photo")
	if err != nil {
		return nil, false, errBad
	}
	if !present {
		return nil, false, nil
	}
	if s == "" {
		if !allowEmpty {
			return nil, false, errBad
		}
		return nil, true, nil
	}
	b, err := strictjson.DecodeStd(s, -1)
	if err != nil || len(b) > MaxPhoto || !isImage(b) {
		return nil, false, errBad
	}
	return b, true, nil
}

// isImage accepts JPEG and PNG by their signatures.
func isImage(b []byte) bool {
	return bytes.HasPrefix(b, []byte{0xff, 0xd8, 0xff}) || bytes.HasPrefix(b, []byte("\x89PNG\r\n\x1a\n"))
}

// ParseSet parses a profile.set body strictly.
func ParseSet(body []byte) (*Set, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	p := &Set{}
	if p.Version, err = o.Uint("version", 0, strictjson.MaxSafeInteger); err != nil {
		return nil, errBad
	}
	if n, present, err := o.OptString("name"); err != nil || len(n) > MaxName {
		return nil, errBad
	} else if present {
		p.Name = &n
	}
	if p.SetF, err = parseFields(o, "set", false); err != nil {
		return nil, err
	}
	if p.Delete, _, err = keyList(o, "delete"); err != nil {
		return nil, err
	}
	if p.Shared, p.HasShare, err = keyList(o, "shared"); err != nil {
		return nil, err
	}
	if p.Order, p.HasOrder, err = keyList(o, "order"); err != nil {
		return nil, err
	}
	if p.Photo, p.HasPhoto, err = photo(o, true); err != nil {
		return nil, err
	}
	return p, nil
}

// Update is a parsed profile.update body.
type Update struct {
	Version uint64
	Name    string
	Fields  map[string]Field
	Photo   []byte
}

// ParseUpdate parses a profile.update body (from a peer, which may be
// malicious) strictly.
func ParseUpdate(body []byte) (*Update, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	u := &Update{}
	if u.Version, err = o.Uint("version", 1, strictjson.MaxSafeInteger); err != nil {
		return nil, errBad
	}
	if u.Name, err = o.String("name"); err != nil || len(u.Name) > MaxName {
		return nil, errBad
	}
	if u.Fields, err = parseFields(o, "fields", true); err != nil {
		return nil, err
	}
	if u.Photo, _, err = photo(o, false); err != nil {
		return nil, err
	}
	return u, nil
}

// Marshal re-encodes a parsed update canonically (what the vault stores).
func (u *Update) Marshal() []byte {
	keys := make([]string, 0, len(u.Fields))
	for k := range u.Fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fb := strictjson.NewBuilder()
	for _, k := range keys {
		x := strictjson.NewBuilder().String("value", u.Fields[k].Value)
		if u.Fields[k].Label != "" {
			x.String("label", u.Fields[k].Label)
		}
		fb.Raw(k, x.Bytes())
	}
	b := strictjson.NewBuilder().Uint("version", u.Version).String("name", u.Name).Raw("fields", fb.Bytes())
	if len(u.Photo) > 0 {
		b.Base64("photo", u.Photo)
	}
	return b.Bytes()
}

// Handle implements vault.Handler.
func (f *Feature) Handle(_ context.Context, s *vault.Session, in *envelope.Inner) (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch in.Type {
	case "profile.get":
		if _, err := strictjson.ParseObject(in.Body); err != nil {
			return nil, errBad
		}
		return f.get(), nil
	case "profile.set":
		p, err := ParseSet(in.Body)
		if err != nil {
			return nil, err
		}
		return f.set(s, p)
	case "profile.update":
		u, err := ParseUpdate(in.Body)
		if err != nil {
			return nil, err
		}
		conn := s.From().ID
		if u.Version <= f.st.Peers[conn] {
			return nil, nil // older or repeated (§8.4)
		}
		if err := s.SetConnectionProfile(conn, u.Marshal()); err != nil {
			return nil, err
		}
		f.st.Peers[conn] = u.Version
		f.prunePeers(s)
		s.NotifyAllDevices("connection.event", strictjson.NewBuilder().String("connection_id", conn).
			String("event", "profile").Bytes())
		return nil, nil
	}
	return nil, vault.NewError("unsupported_type", "")
}

func (f *Feature) prunePeers(s *vault.Session) {
	for id := range f.st.Peers {
		if _, ok := s.Connection(id); !ok {
			delete(f.st.Peers, id)
		}
	}
}

func (f *Feature) get() []byte {
	keys := make([]string, 0, len(f.st.Fields))
	for k := range f.st.Fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fb := strictjson.NewBuilder()
	for _, k := range keys {
		fl := f.st.Fields[k]
		x := strictjson.NewBuilder().String("value", fl.Value)
		if fl.Label != "" {
			x.String("label", fl.Label)
		}
		fb.Raw(k, x.String("updated_at", envelope.FormatTS(fl.UpdatedAt)).Bytes())
	}
	b := strictjson.NewBuilder().Uint("version", f.st.Version).String("name", f.st.Name).Raw("fields", fb.Bytes()).
		Raw("shared", strList(f.st.Shared)).Raw("order", strList(f.st.Order))
	if len(f.st.Photo) > 0 {
		b.Base64("photo", f.st.Photo)
	}
	return b.Bytes()
}

func strList(l []string) []byte {
	out := []byte{'['}
	for i, s := range l {
		if i > 0 {
			out = append(out, ',')
		}
		out = append(out, strictjson.MarshalString(s)...)
	}
	return append(out, ']')
}

func without(l []string, gone map[string]bool) []string {
	out := l[:0:0]
	for _, k := range l {
		if !gone[k] {
			out = append(out, k)
		}
	}
	return out
}

func (f *Feature) set(s *vault.Session, p *Set) (json.RawMessage, error) {
	now := s.Now().UTC().Truncate(time.Millisecond)
	before := f.sharedView()
	next := state{Version: f.st.Version, Name: f.st.Name, Fields: map[string]*Field{}, Photo: f.st.Photo, Peers: f.st.Peers,
		Shared: append([]string(nil), f.st.Shared...), Order: append([]string(nil), f.st.Order...)}
	for k, v := range f.st.Fields {
		c := *v
		next.Fields[k] = &c
	}
	gone := map[string]bool{}
	for _, k := range p.Delete {
		delete(next.Fields, k)
		gone[k] = true
	}
	for k, v := range p.SetF {
		v.UpdatedAt = now
		v := v
		next.Fields[k] = &v
		delete(gone, k)
	}
	next.Shared, next.Order = without(next.Shared, gone), without(next.Order, gone)
	if p.HasShare {
		next.Shared = p.Shared
	}
	if p.HasOrder {
		next.Order = p.Order
	}
	for _, l := range [][]string{next.Shared, next.Order} {
		for _, k := range l {
			if next.Fields[k] == nil {
				return nil, errBad
			}
		}
	}
	if len(next.Fields) > MaxFields {
		return nil, errLimit
	}
	if p.Name != nil {
		next.Name = *p.Name
	}
	if p.HasPhoto {
		next.Photo = p.Photo
	}
	if p.Version != f.st.Version {
		return nil, errConflict
	}
	next.Version++
	f.st = next
	s.SyncEvent("profile.changed", strictjson.NewBuilder().Uint("version", next.Version).Bytes())
	// Compare the shared view without its version member.
	after := f.sharedView()
	if !bytes.Equal(stripVersion(before), stripVersion(after)) {
		for _, c := range s.Connections() {
			if c.State == vault.PeerActive {
				_ = s.SendToConnection(c.ID, "profile.update", after)
			}
		}
	}
	return strictjson.NewBuilder().Uint("version", next.Version).Bytes(), nil
}

// stripVersion drops the leading "version" member of a shared view.
func stripVersion(b []byte) []byte {
	if i := bytes.IndexByte(b, ','); i > 0 {
		return b[i:]
	}
	return b
}
