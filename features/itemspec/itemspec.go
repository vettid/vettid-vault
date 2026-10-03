// Package itemspec is the shape of the member's items (VAULT-MESSAGING
// §10.7, §10.8, §10.12): field kinds and their value checks, tag
// normalisation, share-rule terms and matching, and the canonical
// encodings the vault returns and seals. It holds no state; the items,
// grants, leash, critical and actions features share it so that every
// one of them parses and encodes items the same way.
package itemspec

import (
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// Sensitivities (§10.7).
const (
	Data     = "data"
	Secret   = "secret"
	Critical = "critical"
)

// Field kinds (§10.7). KindFile is reserved and refused.
const (
	KindText      = "text"
	KindMultiline = "multiline"
	KindNumber    = "number"
	KindDate      = "date"
	KindEmail     = "email"
	KindPhone     = "phone"
	KindURL       = "url"
	KindPassword  = "password"
	KindOTP       = "otp"
	KindAddress   = "address"
	KindFile      = "file"
)

// Limits (§10.7, §10.8).
const (
	MaxName        = 128
	MaxNotes       = 16384
	MaxFields      = 64
	MaxLabel       = 64
	MaxValue       = 16384
	MaxItemBytes   = 65536
	MaxItems       = 2000
	MaxCritFields  = 16
	MaxCritBytes   = 8192
	MaxCritItems   = 64
	MaxTags        = 16
	MaxTagLen      = 32
	MaxTemplate    = 64
	MaxAddressPart = 256
	MaxURL         = 2048
	MaxEmail       = 254
	MaxPhone       = 32
	// ProfileTag is the reserved tag of the shared profile (§10.8).
	ProfileTag = "@profile"
)

// ErrInvalid is the only error of this package: the input does not have
// the required shape (answered as bad_request).
var ErrInvalid = errors.New("itemspec: invalid")

var (
	categoryRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	templateRE = regexp.MustCompile(`^[a-z0-9_.-]{1,64}$`)
	fieldIDRE  = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)
	tagRE      = regexp.MustCompile(`^[a-z0-9][a-z0-9 _-]{0,31}$`)
	numberRE   = regexp.MustCompile(`^-?[0-9]{1,32}(\.[0-9]{1,32})?$`)
	countryRE  = regexp.MustCompile(`^[A-Z]{2}$`)
)

// RecommendedCategories are the categories the apps offer first (§10.7).
var RecommendedCategories = []string{"identity_document", "login", "payment_card", "bank_account", "medical",
	"insurance", "vehicle", "contact", "note", "crypto_wallet", "other"}

// ValidCategory reports whether s is a category.
func ValidCategory(s string) bool { return categoryRE.MatchString(s) }

// ValidSensitivity reports whether s is a sensitivity.
func ValidSensitivity(s string) bool { return s == Data || s == Secret || s == Critical }

// ValidFieldID reports whether s has the shape of a field id.
func ValidFieldID(s string) bool { return fieldIDRE.MatchString(s) }

// Kinds lists the accepted field kinds (file is reserved).
var kinds = map[string]bool{KindText: true, KindMultiline: true, KindNumber: true, KindDate: true, KindEmail: true,
	KindPhone: true, KindURL: true, KindPassword: true, KindOTP: true, KindAddress: true}

// ValidKind reports whether s is an accepted field kind.
func ValidKind(s string) bool { return kinds[s] }

// --- text ---

// cleanText reports whether s has no control characters, except line
// feed and tab when multi is set (§10.7).
func cleanText(s string, multi bool) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			if multi && (r == '\n' || r == '\t') {
				continue
			}
			return false
		}
	}
	return true
}

// ValidText reports whether s is at most max bytes of text without
// control characters (§10.7).
func ValidText(s string, max int) bool { return len(s) <= max && cleanText(s, false) }

// ValidName reports whether s is an item name.
func ValidName(s string) bool { return s != "" && len(s) <= MaxName && cleanText(s, false) }

// ValidNotes reports whether s is an item's notes.
func ValidNotes(s string) bool { return len(s) <= MaxNotes && cleanText(s, true) }

// ValidLabel reports whether s is a field label.
func ValidLabel(s string) bool { return s != "" && len(s) <= MaxLabel && cleanText(s, false) }

// --- values ---

var addressParts = []string{"street", "street2", "city", "region", "postal_code", "country"}

// ParseValue checks a field value of kind and returns its canonical JSON
// encoding (a string, or an address object with its non-empty members in
// a fixed order).
func ParseValue(kind string, raw json.RawMessage) (json.RawMessage, error) {
	if kind == KindAddress {
		o, err := strictjson.AsObject(raw)
		if err != nil {
			return nil, ErrInvalid
		}
		for k := range o {
			if !contains(addressParts, k) {
				return nil, ErrInvalid
			}
		}
		b := strictjson.NewBuilder()
		for _, k := range addressParts {
			v, present, err := o.OptString(k)
			if err != nil || len(v) > MaxAddressPart || !cleanText(v, false) {
				return nil, ErrInvalid
			}
			if k == "country" && v != "" && !countryRE.MatchString(v) {
				return nil, ErrInvalid
			}
			if present && v != "" {
				b.String(k, v)
			}
		}
		return b.Bytes(), nil
	}
	s, err := strictjson.AsString(raw)
	if err != nil || !validString(kind, s) {
		return nil, ErrInvalid
	}
	return strictjson.MarshalString(s), nil
}

func validString(kind, s string) bool {
	if len(s) > MaxValue {
		return false
	}
	switch kind {
	case KindMultiline, KindPassword:
		return cleanText(s, true)
	}
	if !cleanText(s, false) {
		return false
	}
	if s == "" {
		return kinds[kind]
	}
	switch kind {
	case KindText:
		return true
	case KindNumber:
		return numberRE.MatchString(s)
	case KindDate:
		return validDate(s)
	case KindEmail:
		return validEmail(s)
	case KindPhone:
		return validPhone(s)
	case KindURL:
		return validURL(s)
	case KindOTP:
		return validOTP(s)
	}
	return false
}

func validDate(s string) bool {
	switch len(s) {
	case 10:
		t, err := time.Parse("2006-01-02", s)
		return err == nil && t.Format("2006-01-02") == s
	case 7:
		t, err := time.Parse("2006-01", s)
		return err == nil && t.Format("2006-01") == s
	}
	return false
}

func noSpace(s string) bool { return !strings.ContainsAny(s, " \t\n\r") }

func validEmail(s string) bool {
	if len(s) > MaxEmail || !noSpace(s) || strings.Count(s, "@") != 1 {
		return false
	}
	at := strings.IndexByte(s, '@')
	return at > 0 && at < len(s)-1
}

func validPhone(s string) bool {
	if len(s) > MaxPhone {
		return false
	}
	digit := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			digit = true
		case strings.IndexByte(" +-().", c) >= 0:
		default:
			return false
		}
	}
	return digit
}

func validURL(s string) bool {
	if len(s) > MaxURL || !noSpace(s) {
		return false
	}
	u, err := url.Parse(s)
	return err == nil && u.Scheme != "" && u.IsAbs()
}

func validOTP(s string) bool {
	if strings.HasPrefix(s, "otpauth://") {
		return validURL(s)
	}
	t := strings.TrimRight(s, "=")
	if len(s)-len(t) > 6 || len(t) < 16 || len(t) > 256 {
		return false
	}
	for i := 0; i < len(t); i++ {
		c := t[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '2' && c <= '7') {
			return false
		}
	}
	return true
}

// ValueString returns a string value's text; ok is false for an address.
func ValueString(v json.RawMessage) (string, bool) {
	s, err := strictjson.AsString(v)
	return s, err == nil
}

// --- tags (§10.8) ---

// NormalizeTag normalises a tag: leading and trailing spaces removed,
// A–Z lowered, runs of spaces collapsed. The result must match the tag
// pattern, or be a reserved tag (only @profile) when reserved is set.
func NormalizeTag(s string, reserved bool) (string, error) {
	if len(s) > 4*MaxTagLen {
		return "", ErrInvalid
	}
	t := strings.Trim(s, " ")
	var b strings.Builder
	space := false
	for i := 0; i < len(t); i++ {
		c := t[i]
		if c == ' ' {
			if !space {
				b.WriteByte(c)
			}
			space = true
			continue
		}
		space = false
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b.WriteByte(c)
	}
	n := b.String()
	if n == ProfileTag {
		if !reserved {
			return "", ErrInvalid
		}
		return n, nil
	}
	if !tagRE.MatchString(n) {
		return "", ErrInvalid
	}
	return n, nil
}

// ValidTag reports whether s is a normalised, unreserved tag.
func ValidTag(s string) bool { return tagRE.MatchString(s) }

// ParseTags parses a list of at most max tags (0 < min ≤ len), normalises
// them and returns them sorted without duplicates.
func ParseTags(raw []json.RawMessage, min, max int, reserved bool) ([]string, error) {
	if len(raw) < min || len(raw) > max {
		return nil, ErrInvalid
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(raw))
	for _, r := range raw {
		s, err := strictjson.AsString(r)
		if err != nil {
			return nil, ErrInvalid
		}
		t, err := NormalizeTag(s, reserved)
		if err != nil {
			return nil, err
		}
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	sort.Strings(out)
	return out, nil
}

// HasTag reports whether tags (sorted or not) contains t.
func HasTag(tags []string, t string) bool { return contains(tags, t) }

func contains(l []string, s string) bool {
	for _, v := range l {
		if v == s {
			return true
		}
	}
	return false
}

// --- items ---

// Field is one field of an item. Value is its canonical JSON; it is nil
// where the vault does not hold it in DEK state (a critical item).
type Field struct {
	ID    string          `json:"id"`
	Label string          `json:"label"`
	Kind  string          `json:"kind"`
	Value json.RawMessage `json:"value,omitempty"`
}

// Item is an item as the vault keeps it in DEK state (§10.7). A critical
// item keeps no values and no notes here (HasNotes tells whether the
// credential holds notes).
type Item struct {
	ID          string    `json:"id"`
	Version     uint64    `json:"version"`
	Name        string    `json:"name"`
	Category    string    `json:"category"`
	Sensitivity string    `json:"sensitivity"`
	Template    string    `json:"template,omitempty"`
	Tags        []string  `json:"tags,omitempty"`
	Fields      []Field   `json:"fields,omitempty"`
	Notes       string    `json:"notes,omitempty"`
	HasNotes    bool      `json:"has_notes,omitempty"`
	Created     time.Time `json:"created"`
	Updated     time.Time `json:"updated"`
	// NextField numbers the next new field (f1, f2, ...; never reused).
	NextField uint64 `json:"next_field"`
}

// Clone returns a deep copy.
func (it *Item) Clone() *Item {
	c := *it
	c.Tags = append([]string(nil), it.Tags...)
	c.Fields = make([]Field, len(it.Fields))
	for i, f := range it.Fields {
		f.Value = append(json.RawMessage(nil), f.Value...)
		c.Fields[i] = f
	}
	return &c
}

// Field returns a field by id.
func (it *Item) Field(id string) (*Field, bool) {
	for i := range it.Fields {
		if it.Fields[i].ID == id {
			return &it.Fields[i], true
		}
	}
	return nil, false
}

// HasFields reports whether every id names a field of the item.
func (it *Item) HasFields(ids []string) bool {
	for _, id := range ids {
		if _, ok := it.Field(id); !ok {
			return false
		}
	}
	return true
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

// StrList encodes a list of strings.
func StrList(l []string) []byte { return strList(l) }

// JSON is the item's wire form (§10.7): with values (item.get of a data
// item, item.reveal) or without (item.list, and item.get of a secret or
// critical item, which carries has_notes instead of notes). For a
// critical item the caller supplies values to include them.
func (it *Item) JSON(values bool) []byte {
	b := strictjson.NewBuilder().String("item_id", it.ID).Uint("version", it.Version).String("name", it.Name).
		String("category", it.Category).String("sensitivity", it.Sensitivity)
	if it.Template != "" {
		b.String("template", it.Template)
	}
	b.Raw("tags", strList(nonNil(it.Tags)))
	b.Raw("fields", fieldsJSON(it.Fields, nil, values, true))
	if values {
		if it.Notes != "" {
			b.String("notes", it.Notes)
		}
	} else {
		b.Bool("has_notes", it.Notes != "" || it.HasNotes)
	}
	return b.String("created_at", envelope.FormatTS(it.Created)).String("updated_at", envelope.FormatTS(it.Updated)).Bytes()
}

func nonNil(l []string) []string {
	if l == nil {
		return []string{}
	}
	return l
}

// fieldsJSON encodes fields (only those in only, if non-nil), with their
// values when values is set, and with their ids when ids is set.
func fieldsJSON(fs []Field, only []string, values, ids bool) []byte {
	arr := []byte{'['}
	n := 0
	for _, f := range fs {
		if only != nil && !contains(only, f.ID) {
			continue
		}
		if n > 0 {
			arr = append(arr, ',')
		}
		n++
		b := strictjson.NewBuilder()
		if ids {
			b.String("field_id", f.ID)
		}
		b.String("label", f.Label).String("kind", f.Kind)
		if values && f.Value != nil {
			b.Raw("value", f.Value)
		}
		arr = append(arr, b.Bytes()...)
	}
	return append(arr, ']')
}

// Size is the length of the item's encoding with its values: the size
// the limits of §10.7 bound.
func (it *Item) Size() int { return len(it.JSON(true)) }

// Content is the shareable content of an item (§10.12, §10.11): what a
// grant fetch seals and what an agent's item.get returns.
//
//	{"item_id","version","name","category","fields":[{field_id,label,kind,value}],"notes"?}
//
// restricted to the fields in only (nil: all, with the notes).
func (it *Item) Content(only []string) []byte {
	b := strictjson.NewBuilder().String("item_id", it.ID).Uint("version", it.Version).String("name", it.Name).
		String("category", it.Category).Raw("fields", fieldsJSON(it.Fields, only, true, true))
	if only == nil && it.Notes != "" {
		b.String("notes", it.Notes)
	}
	return b.Bytes()
}

// --- metadata shown to connections and agents ---

// Label is a field's metadata: its id, label and kind, never its value.
type Label struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Kind  string `json:"kind"`
}

// Meta is what a connection or agent may see of an item it may read or
// use: its id, name, category and the labels of the fields it may see;
// never its tags, sensitivity or values.
type Meta struct {
	ItemID   string  `json:"item_id"`
	Name     string  `json:"name"`
	Category string  `json:"category"`
	Labels   []Label `json:"labels"`
}

// MetaOf returns the metadata of an item restricted to the fields in only
// (nil: all).
func MetaOf(it *Item, only []string) Meta {
	m := Meta{ItemID: it.ID, Name: it.Name, Category: it.Category, Labels: []Label{}}
	for _, f := range it.Fields {
		if only == nil || contains(only, f.ID) {
			m.Labels = append(m.Labels, Label{ID: f.ID, Label: f.Label, Kind: f.Kind})
		}
	}
	return m
}

// LabelsJSON encodes labels as [{field_id,label,kind}].
func LabelsJSON(ls []Label) []byte {
	arr := []byte{'['}
	for i, l := range ls {
		if i > 0 {
			arr = append(arr, ',')
		}
		arr = append(arr, strictjson.NewBuilder().String("field_id", l.ID).String("label", l.Label).String("kind", l.Kind).Bytes()...)
	}
	return append(arr, ']')
}

// ParseLabels parses [{field_id,label,kind}] (from a peer) strictly.
func ParseLabels(raw json.RawMessage) ([]Label, error) {
	arr, err := strictjson.AsArray(raw)
	if err != nil || len(arr) > MaxFields {
		return nil, ErrInvalid
	}
	out := make([]Label, 0, len(arr))
	seen := map[string]bool{}
	for _, r := range arr {
		o, err := strictjson.AsObject(r)
		if err != nil {
			return nil, ErrInvalid
		}
		var l Label
		if l.ID, err = o.String("field_id"); err != nil || !ValidFieldID(l.ID) || seen[l.ID] {
			return nil, ErrInvalid
		}
		seen[l.ID] = true
		if l.Label, err = o.String("label"); err != nil || !ValidLabel(l.Label) {
			return nil, ErrInvalid
		}
		if l.Kind, err = o.String("kind"); err != nil || !ValidKind(l.Kind) {
			return nil, ErrInvalid
		}
		out = append(out, l)
	}
	return out, nil
}

// MetaJSON encodes metadata as {item_id,name,category,labels}.
func (m Meta) JSON() []byte {
	return strictjson.NewBuilder().String("item_id", m.ItemID).String("name", m.Name).String("category", m.Category).
		Raw("labels", LabelsJSON(m.Labels)).Bytes()
}

// --- content in requests (item.put, the sealed critical item) ---

// FieldIn is a field of an item.put: an existing field (ID set) or a new
// one.
type FieldIn struct {
	ID    string
	Label string
	Kind  string
	Value json.RawMessage
}

// Content is a parsed item content.
type ContentIn struct {
	Name        string
	Category    string
	Template    string
	Fields      []FieldIn
	Notes       string
	HasFields   bool
	NotesGiven  bool
	ValuesGiven bool
}

// ParseContent parses an item's content members (name, category?,
// template?, fields?, notes?) from o strictly: names, labels, kinds and
// values as §10.7 says. Field ids, if present, must have the shape of one
// and be distinct; whether they exist is the caller's check.
func ParseContent(o strictjson.Object) (*ContentIn, error) {
	c := &ContentIn{Category: "other"}
	var err error
	if c.Name, err = o.String("name"); err != nil || !ValidName(c.Name) {
		return nil, ErrInvalid
	}
	if v, present, err := o.OptString("category"); err != nil || present && !ValidCategory(v) {
		return nil, ErrInvalid
	} else if present {
		c.Category = v
	}
	if v, present, err := o.OptString("template"); err != nil || present && !templateRE.MatchString(v) {
		return nil, ErrInvalid
	} else if present {
		c.Template = v
	}
	if v, present, err := o.OptString("notes"); err != nil || !ValidNotes(v) {
		return nil, ErrInvalid
	} else if present {
		c.Notes, c.NotesGiven = v, true
	}
	arr, present, err := o.OptArray("fields")
	if err != nil || len(arr) > MaxFields {
		return nil, ErrInvalid
	}
	c.HasFields = present
	seen := map[string]bool{}
	for _, raw := range arr {
		fo, err := strictjson.AsObject(raw)
		if err != nil {
			return nil, ErrInvalid
		}
		var f FieldIn
		if id, present, err := fo.OptString("field_id"); err != nil || present && (!ValidFieldID(id) || seen[id]) {
			return nil, ErrInvalid
		} else if present {
			f.ID = id
			seen[id] = true
		}
		if f.Label, err = fo.String("label"); err != nil || !ValidLabel(f.Label) {
			return nil, ErrInvalid
		}
		if f.Kind, err = fo.String("kind"); err != nil || !ValidKind(f.Kind) {
			return nil, ErrInvalid
		}
		rv, ok := fo["value"]
		if !ok {
			return nil, ErrInvalid
		}
		if f.Value, err = ParseValue(f.Kind, rv); err != nil {
			return nil, err
		}
		c.Fields = append(c.Fields, f)
	}
	return c, nil
}

// Apply builds the item's next fields from c: fields with an id keep it
// (they must exist in cur, nil for a new item), new fields take the next
// ids. It returns false if c names a field the item does not have.
func (c *ContentIn) Apply(it *Item, cur *Item) bool {
	next := it.NextField
	if next == 0 {
		next = 1
	}
	out := make([]Field, 0, len(c.Fields))
	for _, f := range c.Fields {
		id := f.ID
		if id != "" {
			if cur == nil {
				return false
			}
			if _, ok := cur.Field(id); !ok {
				return false
			}
		} else {
			id = "f" + strconv.FormatUint(next, 10)
			next++
		}
		out = append(out, Field{ID: id, Label: f.Label, Kind: f.Kind, Value: f.Value})
	}
	it.Name, it.Category, it.Template, it.Fields, it.Notes, it.NextField = c.Name, c.Category, c.Template, out, c.Notes, next
	return true
}

// --- share rules (§10.12) ---

// Match values.
const (
	MatchAny = "any"
	MatchAll = "all"
)

// Modes and access.
const (
	ModeAsk    = "ask"
	ModeAuto   = "auto"
	AccessRead = "read"
)

// Rule limits.
const (
	MaxRuleUses   = 10000
	MaxRuleExpiry = 3650 * 24 * time.Hour
)

// Terms are a share rule's matching and inclusion terms, common to
// connection and agent rules.
type Terms struct {
	Tags            []string  `json:"tags"`
	Match           string    `json:"match"`
	Access          string    `json:"access"`
	Mode            string    `json:"mode"`
	Uses            uint64    `json:"uses,omitempty"`
	Expires         time.Time `json:"expires,omitempty"`
	IncludeExisting bool      `json:"include_existing"`
}

// ParseTerms parses a rule's terms from o strictly (defaults applied).
func ParseTerms(o strictjson.Object, now time.Time) (*Terms, error) {
	t := &Terms{Match: MatchAny, Access: AccessRead, Mode: ModeAsk, IncludeExisting: true}
	arr, err := o.Array("tags")
	if err != nil {
		return nil, ErrInvalid
	}
	if t.Tags, err = ParseTags(arr, 1, MaxTags, false); err != nil {
		return nil, ErrInvalid
	}
	if v, present, err := o.OptString("match"); err != nil || present && v != MatchAny && v != MatchAll {
		return nil, ErrInvalid
	} else if present {
		t.Match = v
	}
	if v, present, err := o.OptString("access"); err != nil || present && v != AccessRead {
		return nil, ErrInvalid
	}
	if v, present, err := o.OptString("mode"); err != nil || present && v != ModeAsk && v != ModeAuto {
		return nil, ErrInvalid
	} else if present {
		t.Mode = v
	}
	if t.Uses, _, err = o.OptUint("uses", 1, MaxRuleUses); err != nil {
		return nil, ErrInvalid
	}
	if s, present, err := o.OptString("expires_at"); err != nil {
		return nil, ErrInvalid
	} else if present {
		e, err := envelope.ParseTS(s)
		if err != nil || !e.After(now) || e.Sub(now) > MaxRuleExpiry {
			return nil, ErrInvalid
		}
		t.Expires = e.UTC()
	}
	if o.Has("include_existing") {
		if t.IncludeExisting, err = o.Bool("include_existing"); err != nil {
			return nil, ErrInvalid
		}
	}
	return t, nil
}

// InForce reports whether the terms have not expired.
func (t *Terms) InForce(now time.Time) bool { return t.Expires.IsZero() || now.Before(t.Expires) }

// TagsMatch reports whether an item's tags meet the terms' tags and match.
func (t *Terms) TagsMatch(tags []string) bool {
	if t.Match == MatchAll {
		for _, rt := range t.Tags {
			if !contains(tags, rt) {
				return false
			}
		}
		return len(t.Tags) > 0
	}
	for _, rt := range t.Tags {
		if contains(tags, rt) {
			return true
		}
	}
	return false
}

// GainedTag reports whether after carries one of the terms' tags that
// before did not.
func (t *Terms) GainedTag(before, after []string) bool {
	for _, rt := range t.Tags {
		if contains(after, rt) && !contains(before, rt) {
			return true
		}
	}
	return false
}

// JSONMembers adds the terms' members to a share rule's encoding.
func (t *Terms) JSONMembers(b *strictjson.Builder) {
	b.Raw("tags", strList(t.Tags)).String("match", t.Match).String("access", t.Access).String("mode", t.Mode)
	if t.Uses > 0 {
		b.Uint("uses", t.Uses)
	}
	if !t.Expires.IsZero() {
		b.String("expires_at", envelope.FormatTS(t.Expires))
	}
	b.Bool("include_existing", t.IncludeExisting)
}

// AgentRule is a share rule whose subject is an agent: a LEASH grant of
// scope items.read (§10.11), kept by the leash feature.
type AgentRule struct {
	ID        string
	Version   uint64
	AgentID   string
	Terms     Terms
	PerHour   uint64
	PerDay    uint64
	StatusTTL time.Duration
	Created   time.Time
	Updated   time.Time
	// The signed delegation (§10.11).
	Delegation    []byte
	DelegationSig []byte
	Key           []byte
}
