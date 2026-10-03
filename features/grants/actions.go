package grants

import (
	"time"

	"github.com/vettid/vettid-vault/vault"
)

// Grants made by built-in actions (VAULT-MESSAGING §10.14):
// profile.fields.read and secrets.share give the invoking connection
// one-use grants through this feature, with the same records, audit,
// sync events, fetches and revocation as grants the member decided
// (§10.12).

// Desc describes a grant an action made, as carried in action.result.
type Desc struct {
	GrantID string
	Kind    string
	Ref     string
	Uses    uint64
	Expires time.Time
}

// Available reports whether an item resolves now (an existing field, a
// cataloged vault-held secret).
func (f *Feature) Available(it Item) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.available(it)
}

// IssueForAction gives connection conn one grant per available item,
// with uses and ttl, recorded against the invocation. It returns the
// grants made (none if no item is available, or `limit`).
func (f *Feature) IssueForAction(s *vault.Session, conn, invocationID string, items []Item, uses uint64, ttl time.Duration) ([]Desc, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := s.Now().UTC().Truncate(time.Millisecond)
	var made []*Grant
	for _, it := range items {
		if !f.available(it) {
			continue
		}
		made = append(made, &Grant{ID: s.NewID(), Conn: conn, Direction: "given", RequestID: invocationID, Kind: it.Kind, Ref: it.Ref,
			Uses: uses, Expires: now.Add(ttl), State: StateActive, Created: now})
	}
	if countActive(f.d.Given)+len(made) > MaxGiven {
		return nil, errLimit
	}
	out := make([]Desc, 0, len(made))
	for _, g := range made {
		f.d.Given[g.ID] = g
		s.Record(vault.Activity{Kind: "grant.issued", ConnectionID: g.Conn, Ref: g.ID, Direction: "out", Audit: true})
		syncChanged(s, g)
		out = append(out, Desc{GrantID: g.ID, Kind: g.Kind, Ref: g.Ref, Uses: g.Uses, Expires: g.Expires})
	}
	return out, nil
}

// ReceiveFromAction records grants an action of connection conn gave
// this vault, so that grant.fetch works for them. Grants already held or
// beyond the limit are skipped.
func (f *Feature) ReceiveFromAction(s *vault.Session, conn, invocationID string, descs []Desc) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := s.Now().UTC().Truncate(time.Millisecond)
	for _, d := range descs {
		key := conn + "|" + d.GrantID
		if f.d.Received[key] != nil || countActive(f.d.Received) >= MaxReceived || d.Kind != KindField && d.Kind != KindSecret {
			continue
		}
		g := &Grant{ID: d.GrantID, Conn: conn, Direction: "received", RequestID: invocationID, Kind: d.Kind, Ref: d.Ref,
			Uses: d.Uses, Expires: d.Expires, State: StateActive, Created: now}
		f.d.Received[key] = g
		s.Record(vault.Activity{Kind: "grant.received", ConnectionID: conn, Ref: g.ID, Direction: "in", Audit: true})
		syncChanged(s, g)
	}
}
