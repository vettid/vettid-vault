package grants

import (
	"time"

	"github.com/vettid/vettid-vault/features/itemspec"
	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
)

// Grants made on behalf of other features: share rules (the items
// feature, §10.12) and built-in actions (items.share, §10.14). They are
// ordinary grants, with the same records, audit, sync events, fetches
// and revocation as grants the member decided.

// IssueRuleGrants implements items.RuleGrants: it gives conn one grant
// per item (all fields) for a share rule and tells the connection in one
// data.shared. It must not call back into the items feature.
func (f *Feature) IssueRuleGrants(s *vault.Session, conn, ruleID string, metas []itemspec.Meta, uses uint64, expires time.Time) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(metas) == 0 || len(metas) > MaxShared {
		return nil, errBad
	}
	if countActive(f.d.Given)+len(metas) > MaxGiven {
		return nil, vault.LimitError("grants_given", MaxGiven)
	}
	now := s.Now().UTC().Truncate(time.Millisecond)
	ids := make([]string, len(metas))
	ds := make([]Descriptor, len(metas))
	for i, m := range metas {
		g := &Grant{ID: s.NewID(), Conn: conn, Direction: "given", RequestID: ruleID, Kind: KindItem, Ref: m.ItemID,
			RuleID: ruleID, Name: m.Name, Category: m.Category, Uses: uses, Expires: expires, State: StateActive, Created: now}
		f.d.Given[g.ID] = g
		ids[i], ds[i] = g.ID, g.descriptor(m)
		s.Record(vault.Activity{Kind: "grant.issued", ConnectionID: conn, Ref: g.ID, Direction: "out", Audit: true})
		syncChanged(s, g)
	}
	// One message per change, split to stay within a message (§10.12).
	var chunk []Descriptor
	size := 0
	flush := func() {
		if len(chunk) > 0 {
			_ = s.SendToConnection(conn, "data.shared", strictjson.NewBuilder().Raw("grants", descriptorsJSON(chunk)).Bytes())
		}
		chunk, size = nil, 0
	}
	for i := range ds {
		n := len(ds[i].JSON())
		if len(chunk) > 0 && size+n > MaxSharedBytes {
			flush()
		}
		chunk = append(chunk, ds[i])
		size += n + 1
	}
	flush()
	return ids, nil
}

// RevokeRuleGrant implements items.RuleGrants: a withdrawn item's grant
// is revoked and the connection told (§10.12).
func (f *Feature) RevokeRuleGrant(s *vault.Session, grantID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	g := f.d.Given[grantID]
	if g == nil || g.State == StateRevoked {
		return
	}
	f.revokeGrant(s, g)
}

// GivenRoom implements items.RuleGrants.
func (f *Feature) GivenRoom() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return MaxGiven - countActive(f.d.Given)
}

// Available reports whether an item resolves now (a readable item with
// those fields).
func (f *Feature) Available(it Item) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return it.Kind == KindItem && f.available(it)
}

// IssueForAction gives connection conn one grant per readable item, with
// uses and ttl, recorded against the invocation. It returns the grants'
// descriptors (none if no item is readable, or `limit`).
func (f *Feature) IssueForAction(s *vault.Session, conn, invocationID string, items []Item, uses uint64, ttl time.Duration) ([]Descriptor, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := s.Now().UTC().Truncate(time.Millisecond)
	var made []*Grant
	var metas []itemspec.Meta
	for _, it := range items {
		if it.Kind != KindItem {
			continue
		}
		meta, ok := f.items.Readable(it.Ref, it.Fields)
		if !ok {
			continue
		}
		made = append(made, &Grant{ID: s.NewID(), Conn: conn, Direction: "given", RequestID: invocationID, Kind: KindItem, Ref: it.Ref,
			Fields: it.Fields, Name: meta.Name, Category: meta.Category, Uses: uses, Expires: now.Add(ttl), State: StateActive, Created: now})
		metas = append(metas, meta)
	}
	if countActive(f.d.Given)+len(made) > MaxGiven {
		return nil, vault.LimitError("grants_given", MaxGiven)
	}
	out := make([]Descriptor, 0, len(made))
	for i, g := range made {
		f.d.Given[g.ID] = g
		s.Record(vault.Activity{Kind: "grant.issued", ConnectionID: g.Conn, Ref: g.ID, Direction: "out", Audit: true})
		syncChanged(s, g)
		out = append(out, g.descriptor(metas[i]))
	}
	return out, nil
}

// ReceiveFromAction records grants an action of connection conn gave
// this vault, so that grant.fetch works for them. Grants already held or
// beyond the limit are skipped.
func (f *Feature) ReceiveFromAction(s *vault.Session, conn, invocationID string, descs []Descriptor) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.receive(s, conn, invocationID, descs)
}
