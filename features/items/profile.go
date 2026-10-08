package items

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"strings"

	"github.com/vettid/vettid-vault/features/itemspec"
	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// The profile (§10.8): the shared profile every active connection
// receives in profile.update (§9.3) is a read-only core (0.18.0: the
// account's first_name and last_name from the snapshot and the vault's
// ik) plus the optional extras: the profile object's display name and
// photo, and the data items tagged @profile.

// Core is the shared profile's core (§10.8, 0.18.0), as last counted in
// the shared profile's version.
type Core struct {
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	IK        []byte `json:"ik"`
}

func (c *Core) equal(o *Core) bool {
	return c != nil && o != nil && c.FirstName == o.FirstName && c.LastName == o.LastName && bytes.Equal(c.IK, o.IK)
}

// currentCore is the core now: the snapshot's names and the current ik;
// nil without the names.
func currentCore(s *vault.Session) *Core {
	first, last, ok := s.AccountNames()
	if !ok {
		return nil
	}
	return &Core{FirstName: first, LastName: last, IK: append([]byte(nil), s.IdentityKey()...)}
}

// DisplayName implements vault.HandshakeProfiler.
func (f *Feature) DisplayName() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.st.Profile.Name
}

// ConnectionAdded implements vault.ConnectionObserver: a new connection
// gets the current shared profile, with its core (§9.3, §10.8).
func (f *Feature) ConnectionAdded(s *vault.Session, id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.syncCore(s) {
		return // sent to every active connection, this one included
	}
	f.sendTo(s, id)
}

// ProfileCoreChanged implements vault.ProfileObserver: a stored snapshot
// whose names differ from the ones last sent, or a new ik, changes the
// shared profile (§10.8). After an ik rotation the connections whose
// epoch predates it get the update in their epoch under the new ik
// (ConnectionRotated).
func (f *Feature) ProfileCoreChanged(s *vault.Session) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.syncCore(s)
}

// ConnectionRotated implements vault.ProfileObserver: the update with
// the vault's new ik goes to the peer in the epoch under it (§10.8).
func (f *Feature) ConnectionRotated(s *vault.Session, id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.syncCore(s) {
		return
	}
	f.sendTo(s, id)
}

// syncCore counts a changed core as a change of the shared profile and
// sends it (§10.8); it reports whether it did.
func (f *Feature) syncCore(s *vault.Session) bool {
	c := currentCore(s)
	if c == nil || c.equal(f.st.Profile.Core) {
		return false
	}
	f.st.Profile.Core = c
	f.st.Profile.Shared++
	f.sendAll(s)
	return true
}

// sendTo sends the current shared profile to one connection.
func (f *Feature) sendTo(s *vault.Session, id string) {
	body, ok := f.updateBody(s, f.st.Profile.Shared)
	if !ok {
		s.Record(vault.Activity{Kind: "profile.core_missing", Audit: true})
		return
	}
	if f.st.Profile.Shared == 0 {
		return // not reached: syncCore counted the core
	}
	_ = s.SendToConnection(id, "profile.update", body)
}

// sendAll sends the current shared profile to every active connection,
// except those whose epoch predates the vault's latest ik rotation: they
// get it in the epoch under the new ik (§10.8). Without the complete core
// it sends none and audits profile.core_missing.
func (f *Feature) sendAll(s *vault.Session) {
	body, ok := f.updateBody(s, f.st.Profile.Shared)
	if !ok {
		s.Record(vault.Activity{Kind: "profile.core_missing", Audit: true})
		return
	}
	for _, c := range s.Connections() {
		if c.State == vault.PeerActive && !c.RotationPending {
			_ = s.SendToConnection(c.ID, "profile.update", body)
		}
	}
}

// profileItems are the data items tagged @profile, sorted by id.
func (f *Feature) profileItems() []*itemspec.Item {
	var out []*itemspec.Item
	for _, it := range f.sortedItems() {
		if it.Sensitivity == itemspec.Data && itemspec.HasTag(it.Tags, itemspec.ProfileTag) {
			out = append(out, it)
		}
	}
	return out
}

func profileItemJSON(it *itemspec.Item) []byte {
	arr := []byte{'['}
	for i, fl := range it.Fields {
		if i > 0 {
			arr = append(arr, ',')
		}
		arr = append(arr, strictjson.NewBuilder().String("field_id", fl.ID).String("label", fl.Label).String("kind", fl.Kind).
			Raw("value", fl.Value).Bytes()...)
	}
	return strictjson.NewBuilder().String("item_id", it.ID).String("name", it.Name).String("category", it.Category).
		Raw("fields", append(arr, ']')).Bytes()
}

// sharedBody is the shared profile's extras ({name?, photo?, items}):
// what decides, with the core, whether a profile.update is due.
func (f *Feature) sharedBody() []byte {
	b := strictjson.NewBuilder()
	if f.st.Profile.Name != "" {
		b.String("name", f.st.Profile.Name)
	}
	if len(f.st.Profile.Photo) > 0 {
		b.Base64("photo", f.st.Profile.Photo)
	}
	arr := []byte{'['}
	for i, it := range f.profileItems() {
		if i > 0 {
			arr = append(arr, ',')
		}
		arr = append(arr, profileItemJSON(it)...)
	}
	return b.Raw("items", append(arr, ']')).Bytes()
}

// bodyWith is a profile.update body with version v and core c:
// {version, first_name, last_name, ik, name?, photo?, items} (§10.8).
func (f *Feature) bodyWith(c *Core, v uint64) []byte {
	rest := f.sharedBody()
	b := strictjson.NewBuilder().Uint("version", v).String("first_name", c.FirstName).String("last_name", c.LastName).
		Base64("ik", c.IK).Bytes()
	return append(append(b[:len(b)-1], ','), rest[1:]...)
}

// updateBody is the profile.update body with version v and the current
// core; ok is false without the core (§10.8: none is sent then).
func (f *Feature) updateBody(s *vault.Session, v uint64) ([]byte, bool) {
	c := currentCore(s)
	if c == nil {
		return nil, false
	}
	return f.bodyWith(c, v), true
}

// worstName is a name at its largest encoding (§10.8, 0.19.0): 160 bytes
// that each escape to two (`"`), 322 bytes as a JSON string with its
// quotes. The encoder (strictjson.MarshalString) writes names as raw UTF-8
// and escapes only `"` and `\` in them, since names have no control
// characters, U+2028 or U+2029 (vault.ValidAccountName).
var worstName = strings.Repeat(`"`, vault.MaxAccountName)

// checkProfile checks the shared profile's limits (§10.8) whenever the
// display name, the photo or the @profile items change: at most 32 items,
// and (0.19.0) the profile.update body at most 196,608 bytes with
// maximum-length names, so that a later name change never brings it over
// the limit.
func (f *Feature) checkProfile() error {
	c := &Core{FirstName: worstName, LastName: worstName, IK: make([]byte, 32)}
	if len(f.profileItems()) > MaxProfileItems {
		return vault.LimitError("profile_items", MaxProfileItems)
	}
	if n := len(f.bodyWith(c, strictjson.MaxSafeInteger)); n > MaxProfileUpdate {
		return vault.LimitSizeError("profile_size", MaxProfileUpdate, n)
	}
	return nil
}

// broadcastIfChanged sends profile.update to every active connection if
// the shared profile (its extras or its core) differs from before (§9.3).
func (f *Feature) broadcastIfChanged(s *vault.Session, before []byte) {
	if c := currentCore(s); c != nil && !c.equal(f.st.Profile.Core) {
		f.st.Profile.Core = c
	} else if bytes.Equal(before, f.sharedBody()) {
		return
	}
	f.st.Profile.Shared++
	f.sendAll(s)
}

// profileGet answers {version, name?, photo?, first_name, last_name, ik}
// (§10.8): the profile object and the read-only core.
func (f *Feature) profileGet(s *vault.Session, body []byte) (json.RawMessage, error) {
	if _, err := strictjson.ParseObject(body); err != nil {
		return nil, errBad
	}
	b := strictjson.NewBuilder().Uint("version", f.st.Profile.Version)
	if f.st.Profile.Name != "" {
		b.String("name", f.st.Profile.Name)
	}
	if len(f.st.Profile.Photo) > 0 {
		b.Base64("photo", f.st.Profile.Photo)
	}
	if first, last, ok := s.AccountNames(); ok {
		b.String("first_name", first).String("last_name", last)
	}
	return b.Base64("ik", s.IdentityKey()).Bytes(), nil
}

func isImage(b []byte) bool {
	return bytes.HasPrefix(b, []byte{0xff, 0xd8, 0xff}) || bytes.HasPrefix(b, []byte("\x89PNG\r\n\x1a\n"))
}

func parsePhoto(o strictjson.Object, allowEmpty bool) ([]byte, bool, error) {
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

func (f *Feature) profileSet(s *vault.Session, body []byte) (json.RawMessage, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	ver, err := o.Uint("version", 0, strictjson.MaxSafeInteger)
	if err != nil {
		return nil, errBad
	}
	if o.Has("first_name") || o.Has("last_name") || o.Has("ik") {
		return nil, errBad // §10.8 (0.18.0): the core is read-only
	}
	name, hasName, err := o.OptString("name")
	if err != nil || !itemspec.ValidText(name, MaxDisplayName) {
		return nil, errBad
	}
	photo, hasPhoto, err := parsePhoto(o, true)
	if err != nil {
		return nil, err
	}
	if ver != f.st.Profile.Version {
		return nil, errConflict
	}
	before := f.sharedBody()
	old := f.st.Profile
	if hasName {
		f.st.Profile.Name = name
	}
	if hasPhoto {
		f.st.Profile.Photo = photo
	}
	if err := f.checkProfile(); err != nil {
		f.st.Profile = old
		return nil, err
	}
	f.st.Profile.Version++
	s.SyncEvent("profile.changed", strictjson.NewBuilder().Uint("version", f.st.Profile.Version).Bytes())
	f.broadcastIfChanged(s, before)
	return strictjson.NewBuilder().Uint("version", f.st.Profile.Version).Bytes(), nil
}

// Update is a parsed profile.update body (from a peer, which may be
// malicious).
type Update struct {
	Version uint64
	// The core (§10.8, 0.18.0); Malformed when a core member is missing
	// or breaks its rules (the receiver drops it after the version check).
	FirstName string
	LastName  string
	IK        []byte
	Malformed bool
	Name      string // "" when absent
	Photo     []byte
	Items     []*itemspec.Item
}

// ParseUpdate parses a profile.update body strictly (§10.8): the field
// rules of §10.7, at most 32 items. The core's members are checked too,
// but reported in Malformed rather than as an error, since §10.8 drops
// such an update only after the version check.
func ParseUpdate(body []byte) (*Update, error) {
	if len(body) > MaxProfileUpdate {
		return nil, errBad
	}
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	u := &Update{}
	if u.Version, err = o.Uint("version", 1, strictjson.MaxSafeInteger); err != nil {
		return nil, errBad
	}
	u.FirstName, err = o.String("first_name")
	u.Malformed = err != nil || !vault.ValidAccountName(u.FirstName)
	u.LastName, err = o.String("last_name")
	u.Malformed = u.Malformed || err != nil || !vault.ValidAccountName(u.LastName)
	u.IK, err = o.Base64("ik", ed25519.PublicKeySize)
	u.Malformed = u.Malformed || err != nil
	if u.Name, _, err = o.OptString("name"); err != nil || !itemspec.ValidText(u.Name, MaxDisplayName) {
		return nil, errBad
	}
	if u.Photo, _, err = parsePhoto(o, false); err != nil {
		return nil, err
	}
	arr, err := o.Array("items")
	if err != nil || len(arr) > MaxProfileItems {
		return nil, errBad
	}
	seen := map[string]bool{}
	for _, raw := range arr {
		io, err := strictjson.AsObject(raw)
		if err != nil {
			return nil, errBad
		}
		it := &itemspec.Item{Sensitivity: itemspec.Data}
		if it.ID, err = io.String("item_id"); err != nil || !envelope.ValidULID(it.ID) || seen[it.ID] {
			return nil, errBad
		}
		seen[it.ID] = true
		if it.Name, err = io.String("name"); err != nil || !itemspec.ValidName(it.Name) {
			return nil, errBad
		}
		if it.Category, err = io.String("category"); err != nil || !itemspec.ValidCategory(it.Category) {
			return nil, errBad
		}
		c, err := itemspec.ParseContent(strictjson.Object{"name": io["name"], "fields": io["fields"]})
		if err != nil || !c.HasFields {
			return nil, errBad
		}
		ids := map[string]bool{}
		for _, fl := range c.Fields {
			if fl.ID == "" || ids[fl.ID] || fl.Keep {
				return nil, errBad // every value is present (no kept values here)
			}
			ids[fl.ID] = true
			it.Fields = append(it.Fields, itemspec.Field{ID: fl.ID, Label: fl.Label, Kind: fl.Kind, Value: fl.Value})
		}
		u.Items = append(u.Items, it)
	}
	return u, nil
}

// Marshal re-encodes a parsed update canonically (what the vault stores
// as the connection's profile): {version, first_name, last_name, ik,
// name?, photo?, items}.
func (u *Update) Marshal() []byte {
	b := strictjson.NewBuilder().Uint("version", u.Version).String("first_name", u.FirstName).String("last_name", u.LastName).
		Base64("ik", u.IK)
	if u.Name != "" {
		b.String("name", u.Name)
	}
	if len(u.Photo) > 0 {
		b.Base64("photo", u.Photo)
	}
	arr := []byte{'['}
	for i, it := range u.Items {
		if i > 0 {
			arr = append(arr, ',')
		}
		arr = append(arr, profileItemJSON(it)...)
	}
	return b.Raw("items", append(arr, ']')).Bytes()
}

// profileUpdate keeps a peer's profile.update (§10.8 "Receiving"): after
// the strict parse it ignores an update that is not newer, drops one
// without a complete core (drop.profile_malformed), ignores one with an
// earlier ik of the peer's rotation chain, drops one with any other ik
// (drop.profile_ik_mismatch), and keeps the rest.
func (f *Feature) profileUpdate(s *vault.Session, body []byte) error {
	u, err := ParseUpdate(body)
	if err != nil {
		return err
	}
	from := s.From()
	conn := from.ID
	if u.Version <= f.st.Profile.Peers[conn] {
		return nil // older or repeated (§8.4)
	}
	if u.Malformed {
		s.Record(vault.Activity{Kind: "drop.profile_malformed", ConnectionID: conn, Ref: conn, Audit: true})
		return nil
	}
	if !bytes.Equal(u.IK, from.IK) {
		if !s.PriorIdentity(conn, u.IK) {
			s.Record(vault.Activity{Kind: "drop.profile_ik_mismatch", ConnectionID: conn, Ref: conn, Audit: true})
		}
		return nil // sent before a rotation the vault has followed (§10.8 step 3)
	}
	if err := s.SetConnectionProfile(conn, u.Marshal()); err != nil {
		return err
	}
	f.st.Profile.Peers[conn] = u.Version
	for id := range f.st.Profile.Peers {
		if _, ok := s.Connection(id); !ok {
			delete(f.st.Profile.Peers, id)
		}
	}
	s.NotifyAllDevices("connection.event", strictjson.NewBuilder().String("connection_id", conn).String("event", "profile").Bytes())
	return nil
}
