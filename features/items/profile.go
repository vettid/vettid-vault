package items

import (
	"bytes"
	"encoding/json"

	"github.com/vettid/vettid-vault/features/itemspec"
	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// The profile (§10.8): a display name and photo, plus the data items
// tagged @profile, which together are the shared profile every active
// connection receives in profile.update (§9.3).

// DisplayName implements vault.HandshakeProfiler.
func (f *Feature) DisplayName() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.st.Profile.Name
}

// ConnectionAdded implements vault.ConnectionObserver: a new connection
// gets the current shared profile (§9.3).
func (f *Feature) ConnectionAdded(s *vault.Session, id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.st.Profile.Shared > 0 {
		_ = s.SendToConnection(id, "profile.update", f.updateBody(f.st.Profile.Shared))
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

// sharedBody is the shared profile without its version: what decides
// whether a profile.update is due.
func (f *Feature) sharedBody() []byte {
	b := strictjson.NewBuilder().String("name", f.st.Profile.Name)
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

// updateBody is a profile.update body with version v.
func (f *Feature) updateBody(v uint64) []byte {
	rest := f.sharedBody()
	b := strictjson.NewBuilder().Uint("version", v).Bytes()
	return append(append(b[:len(b)-1], ','), rest[1:]...)
}

// checkProfile checks the shared profile's limits (§10.8).
func (f *Feature) checkProfile() error {
	if len(f.profileItems()) > MaxProfileItems || len(f.updateBody(strictjson.MaxSafeInteger)) > MaxProfileUpdate {
		return errLimit
	}
	return nil
}

// broadcastIfChanged sends profile.update to every active connection if
// the shared profile differs from before (§9.3).
func (f *Feature) broadcastIfChanged(s *vault.Session, before []byte) {
	if bytes.Equal(before, f.sharedBody()) {
		return
	}
	f.st.Profile.Shared++
	body := f.updateBody(f.st.Profile.Shared)
	for _, c := range s.Connections() {
		if c.State == vault.PeerActive {
			_ = s.SendToConnection(c.ID, "profile.update", body)
		}
	}
}

func (f *Feature) profileGet(body []byte) (json.RawMessage, error) {
	if _, err := strictjson.ParseObject(body); err != nil {
		return nil, errBad
	}
	b := strictjson.NewBuilder().Uint("version", f.st.Profile.Version).String("name", f.st.Profile.Name)
	if len(f.st.Profile.Photo) > 0 {
		b.Base64("photo", f.st.Profile.Photo)
	}
	return b.Bytes(), nil
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
	Name    string
	Photo   []byte
	Items   []*itemspec.Item
}

// ParseUpdate parses a profile.update body strictly (§10.8): the field
// rules of §10.7, at most 32 items.
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
	if u.Name, err = o.String("name"); err != nil || !itemspec.ValidText(u.Name, MaxDisplayName) {
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
			if fl.ID == "" || ids[fl.ID] {
				return nil, errBad
			}
			ids[fl.ID] = true
			it.Fields = append(it.Fields, itemspec.Field(fl))
		}
		u.Items = append(u.Items, it)
	}
	return u, nil
}

// Marshal re-encodes a parsed update canonically (what the vault stores
// as the connection's profile).
func (u *Update) Marshal() []byte {
	b := strictjson.NewBuilder().Uint("version", u.Version).String("name", u.Name)
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

func (f *Feature) profileUpdate(s *vault.Session, body []byte) error {
	u, err := ParseUpdate(body)
	if err != nil {
		return err
	}
	conn := s.From().ID
	if u.Version <= f.st.Profile.Peers[conn] {
		return nil // older or repeated (§8.4)
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
