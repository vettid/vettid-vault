// Package items is the member's data (VAULT-MESSAGING §10.7, §10.8,
// §10.12): one item model with typed fields, free-form tags and a
// sensitivity (data, secret, critical), the tag registry, the profile (a
// display name and photo plus the items tagged @profile), and share
// rules that make tagged items readable (or, for critical items, usable)
// by a connection or an agent, asking the member for each new item in
// `ask` mode. Critical items keep their values inside the Protean
// Credential (package credential); their metadata is here.
//
// It replaces 0.6.0's vault-held secrets (secret.*), critical secrets
// (credential.secret.*) and profile fields (VAULT-ITEMS, owner decisions
// of 2026-10-03). Readable inclusions are ordinary grants of the grants
// feature; agent rules are LEASH grants of scope items.read, signed and
// kept by the leash feature.
//
// Lock order: this feature calls the credential, grants and leash
// features while holding its lock; none of them calls back into it from
// those calls. They call into it (Readable, AgentRead, ...) only from
// their own handlers, and those entry points call nothing outside. The
// audit feature calls ItemName from its search (§10.9), without holding
// its own lock.
package items

import (
	"context"
	"encoding/json"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/vettid/vettid-vault/features/credential"
	"github.com/vettid/vettid-vault/features/itemspec"
	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// Limits (§10.8, §10.12).
const (
	MaxRegistry      = 512
	MaxRulesPerSubj  = 64
	MaxRules         = 512
	MaxPending       = 4096
	MaxProfileItems  = 32
	MaxProfileUpdate = 196608
	MaxListLimit     = 500
	DefaultListLimit = 100
	MaxListBytes     = 131072
	// MaxMessageBytes bounds the lists the feature sends in one message
	// (share.pending, previews, pages).
	MaxMessageBytes  = 131072
	DefaultRuleLimit = 50
	MaxRuleLimit     = 500
	DefaultTagLimit  = 500
	MaxTagLimit      = 1000
	MaxDecide        = 500
	MaxPhoto         = 65536
	MaxDisplayName   = 128
	MaxTagDesc       = 256
	MaxMergeFrom     = 16
	// MaxGivenGrants is the grants feature's bound on active given grants
	// (grants.MaxGiven), named in the grants_given limit (§10.1).
	MaxGivenGrants = 1000
)

// Inclusion states (§10.12).
const (
	StatePending  = "pending"
	StateIncluded = "included"
	StateDeclined = "declined"
)

// Credential is the credential feature: critical items are credential
// operations (§3.5.3).
type Credential interface {
	Operate(s *vault.Session, in *envelope.Inner, need int, check func(*credential.Payload) error,
		op func(*credential.Inner, *credential.Payload) error) (*credential.OpResult, error)
}

// RuleGrants is the grants feature: the grants behind readable
// inclusions for connections (§10.12). It must not call back into this
// feature from these methods.
type RuleGrants interface {
	// IssueRuleGrants gives conn one grant per item (all fields) for a
	// rule and tells the connection (data.shared); it returns the grant
	// ids in order.
	IssueRuleGrants(s *vault.Session, conn, ruleID string, metas []itemspec.Meta, uses uint64, expires time.Time) ([]string, error)
	// RevokeRuleGrant revokes a grant and tells the connection.
	RevokeRuleGrant(s *vault.Session, grantID string)
	// GivenRoom is how many more active grants may be given.
	GivenRoom() int
}

// AgentRules is the leash feature: agent share rules are LEASH grants of
// scope items.read (§10.11). It must not call back into this feature from
// these methods.
type AgentRules interface {
	// SetAgentRule creates (Version 0) or replaces a rule: it checks the
	// agent and the version, signs the delegation (credential_locked
	// outside the unlock window), stores the rule and tells the agent.
	SetAgentRule(s *vault.Session, r *itemspec.AgentRule) (*itemspec.AgentRule, error)
	// DeleteAgentRule deletes a rule and tells the agent.
	DeleteAgentRule(s *vault.Session, id string) bool
	// AgentRules lists the rules in force.
	AgentRules(now time.Time) []itemspec.AgentRule
}

// Rule is a share rule with a connection as subject.
type Rule struct {
	ID      string         `json:"id"`
	Version uint64         `json:"version"`
	Conn    string         `json:"conn"`
	Terms   itemspec.Terms `json:"terms"`
	Created time.Time      `json:"created"`
	Updated time.Time      `json:"updated"`
}

// Inclusion is one item's state for one rule (§10.12).
type Inclusion struct {
	State   string    `json:"state"`
	Conn    string    `json:"conn,omitempty"`
	Agent   string    `json:"agent,omitempty"`
	GrantID string    `json:"grant_id,omitempty"`
	Used    uint64    `json:"used,omitempty"` // agent reads (uses)
	At      time.Time `json:"at"`
}

// TagInfo is a tag's registry entry (§10.8).
type TagInfo struct {
	Color       string `json:"color,omitempty"`
	Icon        string `json:"icon,omitempty"`
	Description string `json:"description,omitempty"`
}

// Profile is the profile object and the shared view's counter (§10.8).
type Profile struct {
	Version uint64 `json:"version"`
	Name    string `json:"name"`
	Photo   []byte `json:"photo,omitempty"`
	// Shared is the shared profile's counter (profile.update's version).
	Shared uint64 `json:"shared"`
	// Core is the core last counted in Shared (0.18.0, §10.8).
	Core *Core `json:"core,omitempty"`
	// Peers is the highest profile.update version seen per connection.
	Peers map[string]uint64 `json:"peers,omitempty"`
}

type state struct {
	Items       map[string]*itemspec.Item        `json:"items"`
	TagsVersion uint64                           `json:"tags_version"`
	Registry    map[string]*TagInfo              `json:"registry,omitempty"`
	Profile     Profile                          `json:"profile"`
	Rules       map[string]*Rule                 `json:"rules,omitempty"`
	Incl        map[string]map[string]*Inclusion `json:"incl,omitempty"` // rule_id → item_id
}

func (st *state) init() {
	if st.Items == nil {
		st.Items = map[string]*itemspec.Item{}
	}
	if st.Registry == nil {
		st.Registry = map[string]*TagInfo{}
	}
	if st.Rules == nil {
		st.Rules = map[string]*Rule{}
	}
	if st.Incl == nil {
		st.Incl = map[string]map[string]*Inclusion{}
	}
	if st.Profile.Peers == nil {
		st.Profile.Peers = map[string]uint64{}
	}
}

// Feature implements vault.Feature, vault.ConnectionObserver,
// vault.ProfileObserver,
// vault.ConnectionRemovedObserver, vault.DeviceRemovedObserver,
// vault.HandshakeProfiler and credential.DeleteObserver.
type Feature struct {
	mu     sync.Mutex
	cred   Credential
	grants RuleGrants
	agents AgentRules
	guard  ItemGuard
	st     state
}

// New returns the feature. cred performs critical items' operations;
// SetGrants and SetAgents connect the grants and leash features.
func New(cred Credential) *Feature {
	f := &Feature{cred: cred}
	f.st.init()
	return f
}

// SetGrants connects the grants feature (at construction).
func (f *Feature) SetGrants(g RuleGrants) { f.grants = g }

// SetAgents connects the leash feature (at construction).
func (f *Feature) SetAgents(a AgentRules) { f.agents = a }

var (
	owners = []string{vault.KindApp, vault.KindDesktop}
	conns  = []string{vault.KindConnection}
)

// Name implements vault.Feature.
func (f *Feature) Name() string { return "items" }

// Types implements vault.Feature. Desktops are held for an app's approval
// (§6.8) on every type that reveals a secret item's values, changes items
// or the tags sharing depends on, or discloses data; critical forms are
// app-only (checked by the handlers).
func (f *Feature) Types() []vault.TypeSpec {
	r := func(t string, stepUp bool) vault.TypeSpec {
		return vault.TypeSpec{Type: t, Request: true, From: owners, DesktopApproval: stepUp}
	}
	return []vault.TypeSpec{
		r("item.put", true), r("item.get", false), r("item.reveal", true), r("item.list", false),
		r("item.tag", true), r("item.sensitivity", true), r("item.delete", true),
		r("tag.list", false), r("tag.set", false), r("tag.delete", true), r("tag.merge", true),
		r("profile.get", false), r("profile.set", true),
		r("share.rule.set", true), r("share.rule.list", false), r("share.rule.delete", false), r("share.decide", true),
		r("share.pending.list", false),
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
	st.init()
	f.st = st
	return nil
}

// Save implements vault.Feature.
func (f *Feature) Save() (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return json.Marshal(f.st)
}

var (
	errBad       = vault.NewError("bad_request", "")
	errNotFound  = vault.NewError("not_found", "")
	errConflict  = vault.NewError("conflict", "")
	errForbidden = vault.NewError("forbidden", "")
	errInUse     = vault.NewError("in_use", "")
	errInternal  = vault.NewError("internal", "")
)

func now(s *vault.Session) time.Time { return s.Now().UTC().Truncate(time.Millisecond) }

// Handle implements vault.Handler.
func (f *Feature) Handle(_ context.Context, s *vault.Session, in *envelope.Inner) (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.expire(s)
	switch in.Type {
	case "item.put":
		return f.put(s, in)
	case "item.get":
		return f.get(in.Body)
	case "item.reveal":
		return f.reveal(s, in)
	case "item.list":
		return f.list(in.Body)
	case "item.tag":
		return f.tag(s, in.Body)
	case "item.sensitivity":
		return f.sensitivity(s, in)
	case "item.delete":
		return f.delete(s, in)
	case "tag.list":
		return f.tagList(s, in.Body)
	case "tag.set":
		return f.tagSet(s, in.Body)
	case "tag.delete":
		return f.tagDelete(s, in.Body)
	case "tag.merge":
		return f.tagMerge(s, in.Body)
	case "profile.get":
		return f.profileGet(s, in.Body)
	case "profile.set":
		return f.profileSet(s, in.Body)
	case "profile.update":
		return nil, f.profileUpdate(s, in.Body)
	case "share.rule.set":
		return f.ruleSet(s, in.Body)
	case "share.rule.list":
		return f.ruleList(s, in.Body)
	case "share.rule.delete":
		return f.ruleDelete(s, in.Body)
	case "share.decide":
		return f.decide(s, in.Body)
	case "share.pending.list":
		return f.pendingList(s, in.Body)
	}
	return nil, vault.NewError("unsupported_type", "")
}

// --- items (§10.7) ---

func parseItemID(o strictjson.Object, name string) (string, error) {
	id, err := o.String(name)
	if err != nil || !envelope.ValidULID(id) {
		return "", errBad
	}
	return id, nil
}

func optTags(o strictjson.Object) ([]string, bool, error) {
	arr, present, err := o.OptArray("tags")
	if err != nil {
		return nil, false, errBad
	}
	if !present {
		return nil, false, nil
	}
	t, err := itemspec.ParseTags(arr, 0, itemspec.MaxTags, true)
	if err != nil {
		return nil, false, errBad
	}
	return t, true, nil
}

// checkProfileTag refuses @profile on anything but a data item.
func checkProfileTag(it *itemspec.Item) error {
	if itemspec.HasTag(it.Tags, itemspec.ProfileTag) && it.Sensitivity != itemspec.Data {
		return errBad
	}
	return nil
}

func (f *Feature) put(s *vault.Session, in *envelope.Inner) (json.RawMessage, error) {
	o, err := strictjson.ParseObject(in.Body)
	if err != nil {
		return nil, errBad
	}
	sens, hasSens, err := o.OptString("sensitivity")
	if err != nil || hasSens && !itemspec.ValidSensitivity(sens) {
		return nil, errBad
	}
	if dry, err := dryRun(o); err != nil {
		return nil, err
	} else if dry {
		return f.putDryRun(s, o, sens, hasSens)
	}
	if sens == itemspec.Critical {
		return f.putCritical(s, in, o)
	}
	if o.Has("credential") || o.Has("sealed") {
		return nil, errBad
	}
	id, hasID, err := o.OptString("item_id")
	if err != nil || hasID && !envelope.ValidULID(id) {
		return nil, errBad
	}
	ver, hasVer, err := o.OptUint("version", 1, strictjson.MaxSafeInteger)
	if err != nil || hasID != hasVer {
		return nil, errBad
	}
	c, err := itemspec.ParseContent(o)
	if err != nil {
		return nil, errBad
	}
	tags, hasTags, err := optTags(o)
	if err != nil {
		return nil, err
	}
	t := now(s)
	var cur, it *itemspec.Item
	if !hasID {
		if len(f.st.Items) >= itemspec.MaxItems {
			return nil, vault.LimitError("items", itemspec.MaxItems)
		}
		if !hasSens {
			sens = itemspec.Data
		}
		it = &itemspec.Item{ID: s.NewID(), Sensitivity: sens, Created: t, NextField: 1}
	} else {
		cur = f.st.Items[id]
		if cur == nil {
			return nil, errNotFound
		}
		if cur.Version != ver {
			return nil, errConflict
		}
		if cur.Sensitivity == itemspec.Critical || hasSens && sens != cur.Sensitivity {
			return nil, errBad // a critical item changes through its credential form; sensitivity through item.sensitivity
		}
		it = cur.Clone()
	}
	// Kept values (0.21.0, §10.7): a field sent without value keeps the
	// value cur holds in DEK state, keep_notes the notes. For a secret
	// item this is not a reveal: nothing leaves the vault and the change
	// is recorded as item.updated only.
	if !c.Apply(it, cur) {
		return nil, errBad
	}
	if hasTags {
		it.Tags = tags
	}
	it.Version++
	it.Updated = t
	if err := checkProfileTag(it); err != nil {
		return nil, err
	}
	if n := it.Size(); n > itemspec.MaxItemBytes {
		return nil, vault.LimitSizeError("item_size", itemspec.MaxItemBytes, n)
	}
	ch, err := f.prepare(s, cur, it, nil)
	if err != nil {
		return nil, err
	}
	kind := "item.updated"
	if cur == nil {
		kind = "item.added"
	}
	f.finish(s, ch, kind)
	return strictjson.NewBuilder().String("item_id", it.ID).Uint("version", it.Version).
		String("updated_at", envelope.FormatTS(t)).Bytes(), nil
}

func (f *Feature) get(body []byte) (json.RawMessage, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	id, err := parseItemID(o, "item_id")
	if err != nil {
		return nil, err
	}
	it := f.st.Items[id]
	if it == nil {
		return nil, errNotFound
	}
	enc := it.JSON(it.Sensitivity == itemspec.Data)
	// size (0.21.0, §10.7): the member's own devices only; a critical
	// item last written before 0.21.0 has none until its values open.
	if n, ok := it.CurrentSize(); ok {
		enc = append(enc[:len(enc)-1], `,"size":`...)
		enc = append(strconv.AppendInt(enc, int64(n), 10), '}')
	}
	return enc, nil
}

func idList(o strictjson.Object, name string, max int, valid func(string) bool) ([]string, bool, error) {
	arr, present, err := o.OptArray(name)
	if err != nil || present && (len(arr) == 0 || len(arr) > max) {
		return nil, false, errBad
	}
	seen := map[string]bool{}
	var out []string
	for _, r := range arr {
		v, err := strictjson.AsString(r)
		if err != nil || !valid(v) || seen[v] {
			return nil, false, errBad
		}
		seen[v] = true
		out = append(out, v)
	}
	return out, present, nil
}

func (f *Feature) reveal(s *vault.Session, in *envelope.Inner) (json.RawMessage, error) {
	o, err := strictjson.ParseObject(in.Body)
	if err != nil {
		return nil, errBad
	}
	id, err := parseItemID(o, "item_id")
	if err != nil {
		return nil, err
	}
	it := f.st.Items[id]
	if it == nil {
		return nil, errNotFound
	}
	switch it.Sensitivity {
	case itemspec.Critical:
		return f.revealCritical(s, in, o, it)
	case itemspec.Data:
		if o.Has("credential") || o.Has("fields") {
			return nil, errBad
		}
		return it.JSON(true), nil
	}
	if o.Has("credential") {
		return nil, errBad
	}
	fields, present, err := idList(o, "fields", itemspec.MaxFields, itemspec.ValidFieldID)
	if err != nil {
		return nil, err
	}
	out := it
	if present {
		if !it.HasFields(fields) {
			return nil, errNotFound
		}
		out = it.Clone()
		out.Notes = ""
		kept := out.Fields[:0]
		for _, fl := range out.Fields {
			if itemspec.HasTag(fields, fl.ID) {
				kept = append(kept, fl)
			}
		}
		out.Fields = kept
	}
	s.Record(vault.Activity{Kind: "item.revealed", Ref: it.ID, Audit: true})
	return out.JSON(true), nil
}

func (f *Feature) list(body []byte) (json.RawMessage, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	var filter itemspec.Terms
	if arr, present, err := o.OptArray("tags"); err != nil {
		return nil, errBad
	} else if present {
		if filter.Tags, err = itemspec.ParseTags(arr, 1, itemspec.MaxTags, true); err != nil {
			return nil, errBad
		}
	}
	filter.Match = itemspec.MatchAny
	if m, present, err := o.OptString("match"); err != nil || present && m != itemspec.MatchAny && m != itemspec.MatchAll {
		return nil, errBad
	} else if present {
		filter.Match = m
	}
	cat, hasCat, err := o.OptString("category")
	if err != nil || hasCat && !itemspec.ValidCategory(cat) {
		return nil, errBad
	}
	sens, hasSens, err := o.OptString("sensitivity")
	if err != nil || hasSens && !itemspec.ValidSensitivity(sens) {
		return nil, errBad
	}
	after, _, err := o.OptString("after")
	if err != nil || after != "" && !envelope.ValidULID(after) {
		return nil, errBad
	}
	limit := uint64(DefaultListLimit)
	if v, present, err := o.OptUint("limit", 1, MaxListLimit); err != nil {
		return nil, errBad
	} else if present {
		limit = v
	}
	ids := make([]string, 0, len(f.st.Items))
	for id := range f.st.Items {
		if id > after {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	arr := []byte{'['}
	n, last, more := uint64(0), "", false
	for _, id := range ids {
		it := f.st.Items[id]
		if filter.Tags != nil && !filter.TagsMatch(it.Tags) || hasCat && it.Category != cat || hasSens && it.Sensitivity != sens {
			continue
		}
		enc := it.JSON(false)
		if n >= limit || len(arr)+len(enc)+64 > MaxListBytes {
			more = true
			break
		}
		if n > 0 {
			arr = append(arr, ',')
		}
		arr = append(arr, enc...)
		n++
		last = id
	}
	b := strictjson.NewBuilder().Raw("items", append(arr, ']'))
	if more {
		b.String("next", last)
	}
	return b.Bytes(), nil
}

func (f *Feature) tag(s *vault.Session, body []byte) (json.RawMessage, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	id, err := parseItemID(o, "item_id")
	if err != nil {
		return nil, err
	}
	ver, err := o.Uint("version", 1, strictjson.MaxSafeInteger)
	if err != nil {
		return nil, errBad
	}
	tags, has, err := optTags(o)
	if err != nil || !has {
		return nil, errBad
	}
	dry, err := dryRun(o)
	if err != nil {
		return nil, err
	}
	cur := f.st.Items[id]
	if cur == nil {
		return nil, errNotFound
	}
	if cur.Version != ver {
		return nil, errConflict
	}
	it := cur.Clone()
	it.Tags, it.Version, it.Updated = tags, it.Version+1, now(s)
	if err := checkProfileTag(it); err != nil {
		return nil, err
	}
	if dry {
		return f.dryRunAnswer(s, cur, it)
	}
	if n := it.Size(); it.Sensitivity != itemspec.Critical && n > itemspec.MaxItemBytes {
		return nil, vault.LimitSizeError("item_size", itemspec.MaxItemBytes, n)
	}
	ch, err := f.prepare(s, cur, it, nil)
	if err != nil {
		return nil, err
	}
	f.finish(s, ch, "item.updated")
	return strictjson.NewBuilder().Uint("version", it.Version).Bytes(), nil
}

func (f *Feature) sensitivity(s *vault.Session, in *envelope.Inner) (json.RawMessage, error) {
	o, err := strictjson.ParseObject(in.Body)
	if err != nil {
		return nil, errBad
	}
	id, err := parseItemID(o, "item_id")
	if err != nil {
		return nil, err
	}
	ver, err := o.Uint("version", 1, strictjson.MaxSafeInteger)
	if err != nil {
		return nil, errBad
	}
	sens, err := o.String("sensitivity")
	if err != nil || !itemspec.ValidSensitivity(sens) {
		return nil, errBad
	}
	cur := f.st.Items[id]
	if cur == nil {
		return nil, errNotFound
	}
	if cur.Version != ver {
		return nil, errConflict
	}
	if sens == cur.Sensitivity {
		return nil, errBad
	}
	if f.guarded(cur.ID) {
		return nil, errInUse // a wallet's item stays critical (§10.18)
	}
	if itemspec.HasTag(cur.Tags, itemspec.ProfileTag) {
		return nil, errBad // @profile only on data items (§10.8)
	}
	if sens == itemspec.Critical || cur.Sensitivity == itemspec.Critical {
		return f.sensitivityCritical(s, in, cur, sens)
	}
	if o.Has("credential") {
		return nil, errBad
	}
	it := cur.Clone()
	it.Sensitivity, it.Version, it.Updated = sens, it.Version+1, now(s)
	ch, err := f.prepare(s, cur, it, nil)
	if err != nil {
		return nil, err
	}
	f.finish(s, ch, "item.sensitivity_changed")
	return strictjson.NewBuilder().Uint("version", it.Version).Bytes(), nil
}

func (f *Feature) delete(s *vault.Session, in *envelope.Inner) (json.RawMessage, error) {
	o, err := strictjson.ParseObject(in.Body)
	if err != nil {
		return nil, errBad
	}
	id, err := parseItemID(o, "item_id")
	if err != nil {
		return nil, err
	}
	cur := f.st.Items[id]
	if cur == nil {
		return nil, errNotFound
	}
	if cur.Sensitivity == itemspec.Critical {
		return f.deleteCritical(s, in, cur)
	}
	if o.Has("credential") {
		return nil, errBad
	}
	ch, err := f.prepare(s, cur, nil, nil)
	if err != nil {
		return nil, err
	}
	f.finish(s, ch, "item.deleted")
	return nil, nil
}

// --- changes: install, check, then apply (§10.7, §10.12) ---

// change is a prepared change of one item: installed tentatively (undo
// restores), with its share-rule plan and the shared profile before it.
type change struct {
	before, after *itemspec.Item
	plan          []action
	viewBefore    []byte
	undo          func()
}

// prepare installs after (nil: delete) in place of before (nil: new),
// checks the profile limits and plans the share rules (§10.12); cross
// forces a move across critical (withdraw from every rule, then gain).
// On error nothing has changed.
func (f *Feature) prepare(s *vault.Session, before, after *itemspec.Item, cross *bool) (*change, error) {
	ch := &change{before: before, after: after, viewBefore: f.sharedBody()}
	id := ""
	if after != nil {
		id = after.ID
	} else {
		id = before.ID
	}
	prev, had := f.st.Items[id]
	ch.undo = func() {
		if had {
			f.st.Items[id] = prev
		} else {
			delete(f.st.Items, id)
		}
	}
	if after != nil {
		f.st.Items[id] = after
	} else {
		delete(f.st.Items, id)
	}
	if err := f.checkProfile(); err != nil {
		ch.undo()
		return nil, err
	}
	crossing := before != nil && after != nil && (before.Sensitivity == itemspec.Critical) != (after.Sensitivity == itemspec.Critical)
	if cross != nil {
		crossing = *cross
	}
	rules := f.rules(s)
	for i := range rules {
		r := &rules[i]
		if crossing {
			ch.plan = append(ch.plan, f.planPair(s, r, r, before, nil, true, true)...)
			ch.plan = append(ch.plan, f.planFresh(s, r, after)...)
			continue
		}
		ch.plan = append(ch.plan, f.planPair(s, r, r, before, after, true, true)...)
	}
	if err := f.checkPlan(ch.plan); err != nil {
		ch.undo()
		return nil, err
	}
	return ch, nil
}

// finish applies a prepared change: the share plan, the notices, the
// audit entry (kind) and the shared profile.
func (f *Feature) finish(s *vault.Session, ch *change, kind string) {
	f.apply(s, ch.plan, "tagged")
	if ch.after != nil {
		s.SyncEvent("item.changed", strictjson.NewBuilder().String("item_id", ch.after.ID).Uint("version", ch.after.Version).Bytes())
		s.Record(vault.Activity{Kind: kind, Ref: ch.after.ID, Audit: true})
	} else {
		id := ch.before.ID
		for rid, m := range f.st.Incl {
			delete(m, id)
			if len(m) == 0 {
				delete(f.st.Incl, rid)
			}
		}
		s.SyncEvent("item.deleted", strictjson.NewBuilder().String("item_id", id).Bytes())
		s.Record(vault.Activity{Kind: kind, Ref: id, Audit: true})
	}
	f.broadcastIfChanged(s, ch.viewBefore)
}

// Items returns copies of the items (tests and tools).
func (f *Feature) Items() []itemspec.Item {
	f.mu.Lock()
	defer f.mu.Unlock()
	ids := make([]string, 0, len(f.st.Items))
	for id := range f.st.Items {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]itemspec.Item, 0, len(ids))
	for _, id := range ids {
		out = append(out, *f.st.Items[id].Clone())
	}
	return out
}
