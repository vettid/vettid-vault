package audit

import (
	"strings"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
)

// The search text of an entry (VAULT-MESSAGING 0.20.0, §10.9): its kind,
// the kind with ".", "_" and "-" read as spaces, and the current names of
// the connection, device and item it refers to, as the vault holds them
// when it answers. Each field is matched separately: q, lower-cased, is a
// substring of the field mapped through strings.ToLower (no Unicode
// normalisation). Nothing else is read: no field labels or values, no
// message text, tags, notes, keys or the account snapshot.

// itemRefKinds are the kinds whose ref is an item_id (a wallet's id is its
// critical item's).
var itemRefKinds = map[string]bool{
	"item.added": true, "item.updated": true, "item.deleted": true, "item.sensitivity_changed": true, "item.revealed": true,
	"share.included": true, "share.declined": true, "share.withdrawn": true,
	"wallet.created": true, "wallet.deleted": true, "wallet.address_issued": true,
}

var kindSpaces = strings.NewReplacer(".", " ", "_", " ", "-", " ")

// searchNames resolves and caches an entry's names for one request, each
// already lower-cased; a removed connection, device or item has none.
type searchNames struct {
	s     *vault.Session
	items ItemNames
	conns map[string][]string
	devs  map[string]string
	its   map[string]string
}

func newSearchNames(s *vault.Session, items ItemNames) *searchNames {
	return &searchNames{s: s, items: items, conns: map[string][]string{}, devs: map[string]string{}, its: map[string]string{}}
}

// match reports whether q (lower-cased) is in one of e's fields.
func (r *searchNames) match(e *Entry, q string) bool {
	if hit(strings.ToLower(e.Kind), q) || hit(strings.ToLower(kindSpaces.Replace(e.Kind)), q) {
		return true
	}
	if e.ConnectionID != "" {
		for _, n := range r.connection(e.ConnectionID) {
			if hit(n, q) {
				return true
			}
		}
	}
	if e.DeviceID != "" && hit(r.device(e.DeviceID), q) {
		return true
	}
	return e.Ref != "" && itemRefKinds[e.Kind] && hit(r.item(e.Ref), q)
}

// hit: an empty field never matches.
func hit(field, q string) bool { return field != "" && strings.Contains(field, q) }

// connection returns a connection's names as connection.list shows them
// (§10.4, §10.8): its name, alias, its profile's first_name, last_name and
// display name, and "First Last".
func (r *searchNames) connection(id string) []string {
	if ns, ok := r.conns[id]; ok {
		return ns
	}
	var ns []string
	if p, ok := r.s.Connection(id); ok {
		ns = append(ns, p.Name, p.Alias)
		if o, err := strictjson.ParseObject(p.Profile); err == nil {
			first, _, _ := o.OptString("first_name")
			last, _, _ := o.OptString("last_name")
			display, _, _ := o.OptString("name")
			ns = append(ns, first, last, display)
			if first != "" && last != "" {
				ns = append(ns, first+" "+last)
			}
		}
		for i := range ns {
			ns[i] = strings.ToLower(ns[i])
		}
	}
	r.conns[id] = ns
	return ns
}

// device returns an owner device's name as device.list shows it (§10.3).
func (r *searchNames) device(id string) string {
	if n, ok := r.devs[id]; ok {
		return n
	}
	var n string
	if p, ok := r.s.ListedDevice(id); ok {
		n = strings.ToLower(p.Name)
	}
	r.devs[id] = n
	return n
}

// item returns an item's current name (§10.7).
func (r *searchNames) item(id string) string {
	if n, ok := r.its[id]; ok {
		return n
	}
	var n string
	if r.items != nil {
		if name, ok := r.items.ItemName(id); ok {
			n = strings.ToLower(name)
		}
	}
	r.its[id] = n
	return n
}
