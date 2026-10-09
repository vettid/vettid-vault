package items

import (
	"encoding/json"
	"regexp"
	"sort"
	"strconv"

	"github.com/vettid/vettid-vault/features/itemspec"
	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
)

// The tag registry and bulk tag changes (§10.8).

var (
	colorRE = regexp.MustCompile(`^#[0-9a-f]{6}$`)
	iconRE  = regexp.MustCompile(`^[a-z0-9_.-]{1,64}$`)
)

func parseTag(o strictjson.Object, name string, reserved bool) (string, error) {
	v, err := o.String(name)
	if err != nil {
		return "", errBad
	}
	t, err := itemspec.NormalizeTag(v, reserved)
	if err != nil {
		return "", errBad
	}
	return t, nil
}

func (f *Feature) tagVersion(o strictjson.Object) error {
	v, err := o.Uint("version", 0, strictjson.MaxSafeInteger)
	if err != nil {
		return errBad
	}
	if v != f.st.TagsVersion {
		return errConflict
	}
	return nil
}

func dryRun(o strictjson.Object) (bool, error) {
	if !o.Has("dry_run") {
		return false, nil
	}
	d, err := o.Bool("dry_run")
	if err != nil {
		return false, errBad
	}
	return d, nil
}

// tagUse returns, per tag, the number of items carrying it and the rules
// naming it.
func (f *Feature) tagUse(s *vault.Session) (map[string]int, map[string][]string) {
	items, rules := map[string]int{}, map[string][]string{}
	for _, it := range f.st.Items {
		for _, t := range it.Tags {
			items[t]++
		}
	}
	for _, r := range f.rules(s) {
		for _, t := range r.Terms.Tags {
			rules[t] = append(rules[t], r.ID)
		}
	}
	return items, rules
}

func (f *Feature) tagList(s *vault.Session, body []byte) (json.RawMessage, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	after, _, err := o.OptString("after")
	if err != nil || len(after) > 4*itemspec.MaxTagLen {
		return nil, errBad
	}
	limit := uint64(DefaultTagLimit)
	if v, present, err := o.OptUint("limit", 1, MaxTagLimit); err != nil {
		return nil, errBad
	} else if present {
		limit = v
	}
	items, rules := f.tagUse(s)
	all := map[string]bool{}
	for t := range f.st.Registry {
		all[t] = true
	}
	for t := range items {
		all[t] = true
	}
	for t := range rules {
		all[t] = true
	}
	arr := []byte{'['}
	n, last, more := uint64(0), "", false
	for _, t := range sortedKeys(all) {
		if t <= after {
			continue
		}
		b := strictjson.NewBuilder().String("tag", t)
		if e := f.st.Registry[t]; e != nil {
			if e.Color != "" {
				b.String("color", e.Color)
			}
			if e.Icon != "" {
				b.String("icon", e.Icon)
			}
			if e.Description != "" {
				b.String("description", e.Description)
			}
		}
		rs := rules[t]
		sort.Strings(rs)
		enc := b.Uint("items", uint64(items[t])).Raw("rules", itemspec.StrList(nonNil(rs))).Bytes()
		if n >= limit || n > 0 && len(arr)+len(enc)+64 > MaxMessageBytes {
			more = true
			break
		}
		if n > 0 {
			arr = append(arr, ',')
		}
		arr = append(arr, enc...)
		n++
		last = t
	}
	out := strictjson.NewBuilder().Uint("version", f.st.TagsVersion).Raw("tags", append(arr, ']'))
	if more {
		out.String("next", last)
	}
	return out.Bytes(), nil
}

func (f *Feature) tagsChanged(s *vault.Session) {
	f.st.TagsVersion++
	s.SyncEvent("tag.changed", strictjson.NewBuilder().Uint("version", f.st.TagsVersion).Bytes())
	s.Record(vault.Activity{Kind: "tag.changed", Ref: strconv.FormatUint(f.st.TagsVersion, 10), Audit: true})
}

func (f *Feature) tagSet(s *vault.Session, body []byte) (json.RawMessage, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	tag, err := parseTag(o, "tag", true)
	if err != nil {
		return nil, err
	}
	e := &TagInfo{}
	if e.Color, _, err = o.OptString("color"); err != nil || e.Color != "" && !colorRE.MatchString(e.Color) {
		return nil, errBad
	}
	if e.Icon, _, err = o.OptString("icon"); err != nil || e.Icon != "" && !iconRE.MatchString(e.Icon) {
		return nil, errBad
	}
	if e.Description, _, err = o.OptString("description"); err != nil || !itemspec.ValidText(e.Description, MaxTagDesc) {
		return nil, errBad
	}
	if err := f.tagVersion(o); err != nil {
		return nil, err
	}
	if f.st.Registry[tag] == nil && len(f.st.Registry) >= MaxRegistry {
		return nil, vault.LimitError("tag_registry", MaxRegistry)
	}
	f.st.Registry[tag] = e
	f.tagsChanged(s)
	return strictjson.NewBuilder().Uint("version", f.st.TagsVersion).Bytes(), nil
}

func (f *Feature) tagDelete(s *vault.Session, body []byte) (json.RawMessage, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	tag, err := parseTag(o, "tag", false)
	if err != nil {
		return nil, err
	}
	dry, err := dryRun(o)
	if err != nil {
		return nil, err
	}
	if err := f.tagVersion(o); err != nil {
		return nil, err
	}
	_, rules := f.tagUse(s)
	if len(rules[tag]) > 0 {
		return nil, errInUse // removing it from a rule could widen what the rule shares
	}
	var changed []*itemspec.Item
	for _, it := range f.sortedItems() {
		if itemspec.HasTag(it.Tags, tag) {
			changed = append(changed, it)
		}
	}
	if dry {
		return strictjson.NewBuilder().Uint("version", f.st.TagsVersion).Uint("items", uint64(len(changed))).Bytes(), nil
	}
	t := now(s)
	rs := f.rules(s)
	var plan []action
	for _, cur := range changed {
		it := cur.Clone()
		kept := it.Tags[:0]
		for _, x := range it.Tags {
			if x != tag {
				kept = append(kept, x)
			}
		}
		it.Tags, it.Version, it.Updated = kept, it.Version+1, t
		for i := range rs {
			plan = append(plan, f.planPair(s, &rs[i], &rs[i], cur, it, true, true)...)
		}
		f.st.Items[it.ID] = it
	}
	plan = f.resolve(s, plan, rs) // ask wins (0.23.0, §10.12)
	f.apply(s, plan, "tagged")
	delete(f.st.Registry, tag)
	f.tagsChanged(s)
	return strictjson.NewBuilder().Uint("version", f.st.TagsVersion).Uint("items", uint64(len(changed))).Bytes(), nil
}

func (f *Feature) tagMerge(s *vault.Session, body []byte) (json.RawMessage, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	arr, err := o.Array("from")
	if err != nil {
		return nil, errBad
	}
	from, err := itemspec.ParseTags(arr, 1, MaxMergeFrom, false)
	if err != nil {
		return nil, errBad
	}
	into, err := parseTag(o, "into", false)
	if err != nil {
		return nil, err
	}
	kept := from[:0]
	for _, t := range from {
		if t != into {
			kept = append(kept, t)
		}
	}
	from = kept
	if len(from) == 0 {
		return nil, errBad
	}
	dry, err := dryRun(o)
	if err != nil {
		return nil, err
	}
	if err := f.tagVersion(o); err != nil {
		return nil, err
	}
	mapTags := func(tags []string) ([]string, bool) {
		changed := false
		set := map[string]bool{}
		for _, t := range tags {
			if itemspec.HasTag(from, t) {
				t, changed = into, true
			}
			set[t] = true
		}
		if !changed {
			return tags, false
		}
		return sortedKeys(set), true
	}
	// Rules: connection rules are rewritten; an agent rule's tags are in
	// its signed delegation, so a merge that touches one is refused.
	oldRules := f.rules(s)
	newRules := make([]ruleView, len(oldRules))
	var touched []string
	for i, r := range oldRules {
		newRules[i] = r
		nt, ch := mapTags(r.Terms.Tags)
		if !ch {
			continue
		}
		if r.Agent != "" {
			return nil, errInUse
		}
		newRules[i].Terms.Tags = nt
		newRules[i].Version++
		touched = append(touched, r.ID)
	}
	t := now(s)
	var plan []action
	var changedItems []*itemspec.Item
	for _, cur := range f.sortedItems() {
		it := cur
		if nt, ch := mapTags(cur.Tags); ch {
			it = cur.Clone()
			it.Tags, it.Version, it.Updated = nt, it.Version+1, t
			changedItems = append(changedItems, it)
		}
		for i := range oldRules {
			plan = append(plan, f.planPair(s, &oldRules[i], &newRules[i], cur, it, false, true)...)
		}
	}
	plan = f.resolve(s, plan, newRules) // ask wins, over the rules after the merge (0.23.0)
	shares := []byte{'['}
	n := 0
	for _, a := range plan {
		if a.op == opWithdraw {
			continue
		}
		n++
		eb := strictjson.NewBuilder().String("rule_id", a.rule.ID).String("item_id", a.item.ID).String("mode", a.rule.Terms.Mode)
		if a.askRule != "" {
			// An ask rule of the subject holds it: a merge can leave an
			// auto entry pending (0.23.1, as item.put and item.tag).
			eb.String("ask_rule_id", a.askRule)
		}
		e := eb.Bytes()
		if len(shares)+len(e)+2 > MaxMessageBytes {
			continue // counted in shares_total, not listed
		}
		if len(shares) > 1 {
			shares = append(shares, ',')
		}
		shares = append(shares, e...)
	}
	shares = append(shares, ']')
	resp := func() []byte {
		return strictjson.NewBuilder().Uint("version", f.st.TagsVersion).Uint("items", uint64(len(changedItems))).
			Uint("rules", uint64(len(touched))).Raw("shares", shares).Uint("shares_total", uint64(n)).Bytes()
	}
	if dry {
		return resp(), nil
	}
	if err := f.checkPlan(plan); err != nil {
		return nil, err
	}
	for _, it := range changedItems {
		f.st.Items[it.ID] = it
	}
	for i, r := range newRules {
		if cr := f.st.Rules[r.ID]; cr != nil && oldRules[i].Version != r.Version {
			cr.Terms.Tags, cr.Version, cr.Updated = r.Terms.Tags, r.Version, t
		}
	}
	f.apply(s, plan, "tagged")
	var first *TagInfo
	for _, t := range from {
		if e := f.st.Registry[t]; e != nil && first == nil {
			first = e
		}
		delete(f.st.Registry, t)
	}
	if f.st.Registry[into] == nil && first != nil {
		f.st.Registry[into] = first
	}
	for _, id := range touched {
		s.SyncEvent("share.rule.changed", strictjson.NewBuilder().String("rule_id", id).Uint("version", f.st.Rules[id].Version).Bytes())
	}
	f.tagsChanged(s)
	return resp(), nil
}
