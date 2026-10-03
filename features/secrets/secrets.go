// Package secrets is the vault-held ("minor") secrets of VAULT-MESSAGING
// §10.7: values the owner reads without the password, kept in DEK state.
// Critical secrets belong in the Protean Credential (package credential).
//
// Ported from vettid.dev's secrets handler (secrets.go): add and update
// become secret.put with explicit versions (§8.4), retrieve is secret.get,
// and the catalog republish to peers is gone (grants, a later batch, will
// read `discoverability`).
package secrets

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

// Limits (§10.7).
const (
	MaxSecrets = 500
	MaxName    = 128
	MaxValue   = 16384
	MaxDesc    = 1024
)

// Discoverability values.
const (
	Private   = "private"
	Cataloged = "cataloged"
)

// Secret is one stored secret.
type Secret struct {
	ID              string    `json:"id"`
	Version         uint64    `json:"version"`
	Name            string    `json:"name"`
	Value           string    `json:"value"`
	Category        string    `json:"category"`
	Description     string    `json:"description,omitempty"`
	Discoverability string    `json:"discoverability"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// Feature implements vault.Feature.
type Feature struct {
	mu sync.Mutex
	m  map[string]*Secret
}

// New returns an empty store.
func New() *Feature { return &Feature{m: map[string]*Secret{}} }

var owners = []string{vault.KindApp, vault.KindDesktop}

// Name implements vault.Feature.
func (f *Feature) Name() string { return "secrets" }

// Types implements vault.Feature.
func (f *Feature) Types() []vault.TypeSpec {
	return []vault.TypeSpec{
		// A desktop reads or changes a value only with an app's approval
		// (§6.8); listing (no values) needs none.
		{Type: "secret.put", Request: true, From: owners, DesktopApproval: true},
		{Type: "secret.get", Request: true, From: owners, DesktopApproval: true},
		{Type: "secret.list", Request: true, From: owners},
		{Type: "secret.delete", Request: true, From: owners, DesktopApproval: true},
	}
}

// Load implements vault.Feature.
func (f *Feature) Load(data json.RawMessage) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	m := map[string]*Secret{}
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	f.m = m
	return nil
}

// Save implements vault.Feature.
func (f *Feature) Save() (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return json.Marshal(f.m)
}

var (
	errBad      = vault.NewError("bad_request", "")
	errNotFound = vault.NewError("not_found", "")
	errConflict = vault.NewError("conflict", "")
	errLimit    = vault.NewError("limit", "")
	categoryRE  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
)

// Put is a parsed secret.put body.
type Put struct {
	SecretID        string
	Version         uint64
	Name            string
	Value           string
	Category        string
	Description     string
	Discoverability string
}

// ParsePut parses a secret.put body strictly.
func ParsePut(body []byte) (*Put, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	p := &Put{Category: "other", Discoverability: Private}
	id, hasID, err := o.OptString("secret_id")
	if err != nil || (hasID && !envelope.ValidULID(id)) {
		return nil, errBad
	}
	v, hasV, err := o.OptUint("version", 1, strictjson.MaxSafeInteger)
	if err != nil || hasID != hasV {
		return nil, errBad
	}
	p.SecretID, p.Version = id, v
	if p.Name, err = o.String("name"); err != nil || p.Name == "" || len(p.Name) > MaxName {
		return nil, errBad
	}
	if p.Value, err = o.String("value"); err != nil || p.Value == "" || len(p.Value) > MaxValue {
		return nil, errBad
	}
	if c, present, err := o.OptString("category"); err != nil || (present && !categoryRE.MatchString(c)) {
		return nil, errBad
	} else if present {
		p.Category = c
	}
	if d, present, err := o.OptString("description"); err != nil || len(d) > MaxDesc {
		return nil, errBad
	} else if present {
		p.Description = d
	}
	if d, present, err := o.OptString("discoverability"); err != nil || (present && d != Private && d != Cataloged) {
		return nil, errBad
	} else if present {
		p.Discoverability = d
	}
	return p, nil
}

func secretID(body []byte) (string, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return "", errBad
	}
	id, err := o.String("secret_id")
	if err != nil || !envelope.ValidULID(id) {
		return "", errBad
	}
	return id, nil
}

func secretJSON(s *Secret, withValue bool) []byte {
	b := strictjson.NewBuilder().String("secret_id", s.ID).Uint("version", s.Version).String("name", s.Name)
	if withValue {
		b.String("value", s.Value)
	}
	b.String("category", s.Category)
	if s.Description != "" {
		b.String("description", s.Description)
	}
	return b.String("discoverability", s.Discoverability).String("created_at", envelope.FormatTS(s.CreatedAt)).
		String("updated_at", envelope.FormatTS(s.UpdatedAt)).Bytes()
}

// Handle implements vault.Handler.
func (f *Feature) Handle(_ context.Context, s *vault.Session, in *envelope.Inner) (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := s.Now().UTC().Truncate(time.Millisecond)
	switch in.Type {
	case "secret.put":
		p, err := ParsePut(in.Body)
		if err != nil {
			return nil, err
		}
		var sec *Secret
		kind := "secret.updated"
		if p.SecretID == "" {
			if len(f.m) >= MaxSecrets {
				return nil, errLimit
			}
			sec = &Secret{ID: s.NewID(), CreatedAt: now}
			kind = "secret.added"
		} else {
			cur, ok := f.m[p.SecretID]
			if !ok {
				return nil, errNotFound
			}
			if cur.Version != p.Version {
				return nil, errConflict
			}
			c := *cur
			sec = &c
		}
		sec.Version++
		sec.Name, sec.Value, sec.Category, sec.Description, sec.Discoverability, sec.UpdatedAt =
			p.Name, p.Value, p.Category, p.Description, p.Discoverability, now
		f.m[sec.ID] = sec
		s.SyncEvent("secret.changed", strictjson.NewBuilder().String("secret_id", sec.ID).Uint("version", sec.Version).Bytes())
		s.Record(vault.Activity{Kind: kind, Ref: sec.ID, Audit: true})
		return strictjson.NewBuilder().String("secret_id", sec.ID).Uint("version", sec.Version).
			String("updated_at", envelope.FormatTS(now)).Bytes(), nil
	case "secret.get":
		id, err := secretID(in.Body)
		if err != nil {
			return nil, err
		}
		sec, ok := f.m[id]
		if !ok {
			return nil, errNotFound
		}
		return secretJSON(sec, true), nil
	case "secret.list":
		if _, err := strictjson.ParseObject(in.Body); err != nil {
			return nil, errBad
		}
		all := make([]*Secret, 0, len(f.m))
		for _, sec := range f.m {
			all = append(all, sec)
		}
		sort.Slice(all, func(i, j int) bool {
			if all[i].Name != all[j].Name {
				return all[i].Name < all[j].Name
			}
			return all[i].ID < all[j].ID
		})
		arr := []byte{'['}
		for i, sec := range all {
			if i > 0 {
				arr = append(arr, ',')
			}
			arr = append(arr, secretJSON(sec, false)...)
		}
		return strictjson.NewBuilder().Raw("secrets", append(arr, ']')).Bytes(), nil
	case "secret.delete":
		id, err := secretID(in.Body)
		if err != nil {
			return nil, err
		}
		if _, ok := f.m[id]; !ok {
			return nil, errNotFound
		}
		delete(f.m, id)
		s.SyncEvent("secret.deleted", strictjson.NewBuilder().String("secret_id", id).Bytes())
		s.Record(vault.Activity{Kind: "secret.deleted", Ref: id, Audit: true})
		return nil, nil
	}
	return nil, vault.NewError("unsupported_type", "")
}
