package vault

import (
	"context"
	"encoding/json"
	"regexp"
	"sort"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Connection metadata and the block list (VAULT-MESSAGING §7.4, §10.4).
const (
	MaxBlocks    = 1000
	MaxAlias     = 128
	MaxNote      = 1024
	MaxTags      = 16
	maxBlockNote = 256
)

var tagRE = regexp.MustCompile(`^[a-z0-9_.-]{1,32}$`)

// desktopApproval are the core types a desktop sends only with an app's
// approval (§6.8 step-up).
var desktopApproval = []string{"settings.set", "connection.remove", "connection.invite.create",
	"connection.invite.accept", "block.remove"}

func (m *Manager) registerConnections() {
	r := func(t string, h HandlerFunc) {
		m.register(TypeSpec{Type: t, Request: true, From: owners}, h)
	}
	r("connection.update", m.hConnUpdate)
	r("block.add", m.hBlockAdd)
	r("block.remove", m.hBlockRemove)
	r("block.list", m.hBlockList)
	for _, t := range desktopApproval {
		m.registry[t].spec.DesktopApproval = true
	}
}

// MetaUpdate is a parsed connection.update body.
type MetaUpdate struct {
	ConnectionID string
	Version      uint64
	Alias        *string
	Note         *string
	Tags         []string
	SetTags      bool
	Favorite     *bool
	Archived     *bool
}

// ParseMetaUpdate parses a connection.update body strictly (exported for
// fuzzing).
func ParseMetaUpdate(body []byte) (*MetaUpdate, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBadRequest
	}
	u := &MetaUpdate{}
	if u.ConnectionID, err = str(o, "connection_id"); err != nil {
		return nil, err
	}
	if u.Version, err = o.Uint("version", 0, strictjson.MaxSafeInteger); err != nil {
		return nil, errBadRequest
	}
	optStr := func(name string, max int) (*string, error) {
		v, present, err := o.OptString(name)
		if err != nil || len(v) > max {
			return nil, errBadRequest
		}
		if !present {
			return nil, nil
		}
		return &v, nil
	}
	if u.Alias, err = optStr("alias", MaxAlias); err != nil {
		return nil, err
	}
	if u.Note, err = optStr("note", MaxNote); err != nil {
		return nil, err
	}
	if arr, present, err := o.OptArray("tags"); err != nil {
		return nil, errBadRequest
	} else if present {
		if len(arr) > MaxTags {
			return nil, errBadRequest
		}
		u.SetTags = true
		seen := map[string]bool{}
		for _, raw := range arr {
			var t string
			if err := json.Unmarshal(raw, &t); err != nil || !tagRE.MatchString(t) || seen[t] {
				return nil, errBadRequest
			}
			seen[t] = true
			u.Tags = append(u.Tags, t)
		}
	}
	optBool := func(name string) (*bool, error) {
		if !o.Has(name) {
			return nil, nil
		}
		v, err := o.Bool(name)
		if err != nil {
			return nil, errBadRequest
		}
		return &v, nil
	}
	if u.Favorite, err = optBool("favorite"); err != nil {
		return nil, err
	}
	if u.Archived, err = optBool("archived"); err != nil {
		return nil, err
	}
	if u.Alias == nil && u.Note == nil && !u.SetTags && u.Favorite == nil && u.Archived == nil {
		return nil, errBadRequest
	}
	return u, nil
}

// hConnUpdate changes the owner's own metadata about a connection; it is
// never sent to the peer. Versioned as one object (§10.1).
func (m *Manager) hConnUpdate(_ context.Context, s *Session, in *envelope.Inner) (json.RawMessage, error) {
	u, err := ParseMetaUpdate(in.Body)
	if err != nil {
		return nil, err
	}
	p := m.st.Connections[u.ConnectionID]
	if p == nil {
		return nil, errNotFound
	}
	cur := PeerMeta{}
	if p.Meta != nil {
		cur = *p.Meta
	}
	if u.Version != cur.Version {
		return nil, NewError("conflict", "")
	}
	if u.Alias != nil {
		cur.Alias = *u.Alias
	}
	if u.Note != nil {
		cur.Note = *u.Note
	}
	if u.SetTags {
		cur.Tags = u.Tags
	}
	if u.Favorite != nil {
		cur.Favorite = *u.Favorite
	}
	if u.Archived != nil {
		cur.Archived = *u.Archived
	}
	cur.Version++
	p.Meta = &cur
	m.dirty = true
	s.SyncEvent("connection.changed", strictjson.NewBuilder().String("connection_id", p.ID).Uint("version", cur.Version).Bytes())
	return strictjson.NewBuilder().Uint("version", cur.Version).Bytes(), nil
}

// blockedIdentity reports whether an identity key or relay key is on the
// block list.
func (m *Manager) blockedIdentity(ik, relayPK []byte) bool {
	for _, b := range m.st.Blocks {
		if suite.EqualPublic(b.IK, ik) || len(relayPK) > 0 && suite.EqualPublic(b.RelayPK, relayPK) {
			return true
		}
	}
	return false
}

// hBlockAdd blocks a connection (§7.4 "Peer blocked": as for a removal,
// plus a block entry on its identity) or a pending connection request
// (declined, and its identity blocked).
func (m *Manager) hBlockAdd(_ context.Context, s *Session, in *envelope.Inner) (json.RawMessage, error) {
	o, err := obj(in)
	if err != nil {
		return nil, err
	}
	note, _, err := o.OptString("note")
	if err != nil || len(note) > maxBlockNote {
		return nil, errBadRequest
	}
	cid, hasConn, err1 := o.OptString("connection_id")
	pid, hasPend, err2 := o.OptString("pending_id")
	if err1 != nil || err2 != nil || hasConn == hasPend {
		return nil, errBadRequest
	}
	if len(m.st.Blocks) >= MaxBlocks {
		return nil, NewError("limit", "")
	}
	b := &Block{ID: m.newID(s.now), Note: note, CreatedAt: s.now.UTC().Truncate(time.Millisecond)}
	if hasConn {
		p := m.st.Connections[cid]
		if p == nil {
			return nil, errNotFound
		}
		b.IK, b.RelayPK, b.Name, b.ConnectionID = append([]byte(nil), p.IK...), append([]byte(nil), p.Relay.PK...), p.Name, p.ID
		if m.blockedIdentity(b.IK, nil) {
			return nil, NewError("exists", "")
		}
		m.removeConnection(p, "out", s.now)
	} else {
		r, _ := m.connRequest(pid, ReqIn)
		if r == nil {
			return nil, errNotFound
		}
		b.IK = append([]byte(nil), r.Peer.IK...)
		b.RelayPK = append([]byte(nil), r.Peer.Relay.PK...)
		b.Name = r.Peer.Name
		if m.blockedIdentity(b.IK, nil) {
			return nil, NewError("exists", "")
		}
		m.dropRequest(r, s.now) // declined (§10.4)
		m.notifyDevices("sync.event", m.requestSync(r, requestStateDeclined), s.peer.ID, s.now)
	}
	m.st.Blocks[b.ID] = b
	m.dirty = true
	m.record(Activity{Kind: "connection.blocked", ConnectionID: b.ConnectionID, Ref: b.ID, Audit: true}, s.now)
	s.SyncEvent("block.added", strictjson.NewBuilder().String("block_id", b.ID).Bytes())
	return strictjson.NewBuilder().String("block_id", b.ID).Bytes(), nil
}

// removeConnection applies §7.4 "Connection removed" for p (dir "out": by
// the owner; "in": the peer's notice).
func (m *Manager) removeConnection(p *Peer, dir string, now time.Time) {
	notice := "connection.removed"
	if dir == "in" {
		p.State = PeerStale // so removePeer sends no notice back
		notice = ""
	}
	m.removePeer(p, notice, now)
	m.record(Activity{Kind: "connection.removed", ConnectionID: p.ID, Direction: dir, Audit: true, Feed: dir == "in"}, now)
	m.notifyDevices("connection.event", connEvent(p.ID, "removed"), "", now)
	s := m.session(now)
	for _, f := range m.features {
		if o, ok := f.(ConnectionRemovedObserver); ok {
			o.ConnectionRemoved(s, p.ID)
		}
	}
}

func (m *Manager) hBlockRemove(_ context.Context, s *Session, in *envelope.Inner) (json.RawMessage, error) {
	o, err := obj(in)
	if err != nil {
		return nil, err
	}
	id, err := str(o, "block_id")
	if err != nil {
		return nil, err
	}
	if m.st.Blocks[id] == nil {
		return nil, errNotFound
	}
	delete(m.st.Blocks, id)
	m.dirty = true
	m.record(Activity{Kind: "connection.unblocked", Ref: id, Audit: true}, s.now)
	s.SyncEvent("block.removed", strictjson.NewBuilder().String("block_id", id).Bytes())
	return nil, nil
}

func (m *Manager) hBlockList(context.Context, *Session, *envelope.Inner) (json.RawMessage, error) {
	ids := make([]string, 0, len(m.st.Blocks))
	for id := range m.st.Blocks {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	arr := []byte{'['}
	for i, id := range ids {
		if i > 0 {
			arr = append(arr, ',')
		}
		b := m.st.Blocks[id]
		e := strictjson.NewBuilder().String("block_id", b.ID).Base64("ik", b.IK).String("created_at", envelope.FormatTS(b.CreatedAt))
		if b.Name != "" {
			e.String("name", b.Name)
		}
		if b.Note != "" {
			e.String("note", b.Note)
		}
		arr = append(arr, e.Bytes()...)
	}
	return strictjson.NewBuilder().Raw("blocks", append(arr, ']')).Bytes(), nil
}

// peerJSON renders a device or connection for the listings (§10.3, §10.4).
func peerJSON(p *Peer, now time.Time) []byte {
	b := strictjson.NewBuilder().String("id", p.ID).String("kind", p.Kind).String("state", p.State).String("name", p.Name).
		Base64("ik", p.IK)
	if len(p.Profile) > 0 {
		b.Raw("profile", p.Profile)
	}
	if !p.CreatedAt.IsZero() {
		b.String("created_at", envelope.FormatTS(p.CreatedAt))
	}
	if !p.LastActiveAt.IsZero() {
		b.String("last_active_at", envelope.FormatTS(p.LastActiveAt))
	}
	if p.Kind == KindConnection {
		meta := PeerMeta{}
		if p.Meta != nil {
			meta = *p.Meta
		}
		b.Uint("version", meta.Version)
		if meta.Alias != "" {
			b.String("alias", meta.Alias)
		}
		if meta.Note != "" {
			b.String("note", meta.Note)
		}
		if len(meta.Tags) > 0 {
			tags, _ := json.Marshal(meta.Tags)
			b.Raw("tags", tags)
		}
		b.Bool("favorite", meta.Favorite).Bool("archived", meta.Archived)
	}
	if needsAccess(p.Kind) && p.Access != nil && now.Before(p.Access.Expires) {
		b.String("session_expires_at", envelope.FormatTS(p.Access.Expires))
	}
	return b.Bytes()
}

func peersJSON(name string, ps map[string]*Peer, now time.Time) json.RawMessage {
	ids := make([]string, 0, len(ps))
	for id := range ps {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	arr := []byte{'['}
	for i, id := range ids {
		if i > 0 {
			arr = append(arr, ',')
		}
		arr = append(arr, peerJSON(ps[id], now)...)
	}
	arr = append(arr, ']')
	return strictjson.NewBuilder().Raw(name, arr).Bytes()
}

// replaceOlderConnections drops other records of the same peer (same
// identity or relay key) when a fresh connection with it activates: a
// stale record left by a removal the peer made, or by refused deposits.
// Their tokens are denylisted by jti; no notice is sent.
func (m *Manager) replaceOlderConnections(p *Peer, now time.Time) {
	for _, o := range m.allPeers() {
		if o.Kind != KindConnection || o.ID == p.ID ||
			!(suite.EqualPublic(o.IK, p.IK) || suite.EqualPublic(o.Relay.PK, p.Relay.PK)) {
			continue
		}
		o.State = PeerStale
		m.removePeer(o, "", now)
		m.notifyDevices("connection.event", connEvent(o.ID, "removed"), "", now)
		s := m.session(now)
		for _, f := range m.features {
			if ob, ok := f.(ConnectionRemovedObserver); ok {
				ob.ConnectionRemoved(s, o.ID)
			}
		}
	}
}
