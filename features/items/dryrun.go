package items

import (
	"encoding/json"
	"sort"

	"github.com/vettid/vettid-vault/features/itemspec"
	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// Dry runs of item.put and item.tag (§10.7, 0.21.0): the vault plans the
// change as the real request would (the rules in force, match, earlier
// declines, items already pending) and answers what it would do to
// sharing, without changing, recording or sending anything.
//
//	{version?, shares: [{rule_id, subject, mode, usable?}],
//	 withdrawals: [{rule_id, subject, state}]}

// putDryRun answers item.put{dry_run: true, item_id?, version?,
// sensitivity?, tags?}. The content members are ignored; the critical
// form's credential, utk_id and sealed must be absent.
func (f *Feature) putDryRun(s *vault.Session, o strictjson.Object, sens string, hasSens bool) (json.RawMessage, error) {
	if o.Has("credential") || o.Has("utk_id") || o.Has("sealed") {
		return nil, errBad // a dry run never opens the credential
	}
	id, hasID, err := o.OptString("item_id")
	if err != nil || hasID && !envelope.ValidULID(id) {
		return nil, errBad
	}
	ver, hasVer, err := o.OptUint("version", 1, strictjson.MaxSafeInteger)
	if err != nil || hasID != hasVer {
		return nil, errBad
	}
	tags, hasTags, err := optTags(o)
	if err != nil {
		return nil, err
	}
	var cur, it *itemspec.Item
	if !hasID {
		if !hasSens {
			sens = itemspec.Data
		}
		it = &itemspec.Item{Sensitivity: sens, Tags: tags}
	} else {
		cur = f.st.Items[id]
		if cur == nil {
			return nil, errNotFound
		}
		if cur.Version != ver {
			return nil, errConflict
		}
		if hasSens && sens != cur.Sensitivity {
			return nil, errBad // a replacement keeps the sensitivity
		}
		it = cur.Clone()
		if hasTags {
			it.Tags = tags
		}
	}
	if it.Sensitivity == itemspec.Critical {
		if err := appOnly(s); err != nil {
			return nil, err // critical items stay app-only
		}
	}
	if err := checkProfileTag(it); err != nil {
		return nil, err
	}
	return f.dryRunAnswer(s, cur, it)
}

// dryRunAnswer plans before → after (before nil: a new item) over every
// rule in force, checks the sharing and profile limits the change would
// reach (share_pending, grants_given, profile_items; not the content) and
// encodes the answer.
func (f *Feature) dryRunAnswer(s *vault.Session, before, after *itemspec.Item) (json.RawMessage, error) {
	n := 0
	for _, x := range f.profileItems() {
		if before == nil || x.ID != before.ID {
			n++
		}
	}
	if after.Sensitivity == itemspec.Data && itemspec.HasTag(after.Tags, itemspec.ProfileTag) {
		n++
	}
	if n > MaxProfileItems {
		return nil, vault.LimitError("profile_items", MaxProfileItems)
	}
	var plan []action
	rules := f.rules(s)
	for i := range rules {
		plan = append(plan, f.planPair(s, &rules[i], &rules[i], before, after, true, true)...)
	}
	if err := f.checkPlan(plan); err != nil {
		return nil, err
	}
	sort.SliceStable(plan, func(i, j int) bool { return plan[i].rule.ID < plan[j].rule.ID })
	shares, withdrawals := []byte{'['}, []byte{'['}
	for _, a := range plan {
		b := strictjson.NewBuilder().String("rule_id", a.rule.ID).Raw("subject", subjectJSON(&a.rule))
		if a.op == opWithdraw {
			state := StateIncluded
			if inc := f.incl(a.rule.ID, a.item.ID); inc != nil {
				state = inc.State
			}
			if len(withdrawals) > 1 {
				withdrawals = append(withdrawals, ',')
			}
			withdrawals = append(withdrawals, b.String("state", state).Bytes()...)
			continue
		}
		b.String("mode", a.rule.Terms.Mode)
		if a.item.Sensitivity == itemspec.Critical {
			b.Bool("usable", true) // a connection rule makes it usable only (§10.13)
		}
		if len(shares) > 1 {
			shares = append(shares, ',')
		}
		shares = append(shares, b.Bytes()...)
	}
	b := strictjson.NewBuilder()
	if before != nil {
		b.Uint("version", before.Version)
	}
	return b.Raw("shares", append(shares, ']')).Raw("withdrawals", append(withdrawals, ']')).Bytes(), nil
}

// ReadOnly implements vault.ReadOnlyForms: a dry run of item.put or
// item.tag changes nothing, so a desktop needs no step-up for it (§10.7,
// 0.21.0). Critical forms are still refused by AppOnly first.
func (f *Feature) ReadOnly(typ string, body json.RawMessage) bool {
	if typ != "item.put" && typ != "item.tag" {
		return false
	}
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return false
	}
	d, err := dryRun(o)
	return err == nil && d
}

// --- share.pending.list (§10.12, 0.21.0) ---

// pendingCursor is share.pending.list's opaque cursor: the rule id and
// the item id of the last entry returned.
func pendingCursor(rule, item string) string { return rule + "." + item }

func parsePendingCursor(c string) (string, string, bool) {
	if len(c) != 2*26+1 || c[26] != '.' || !envelope.ValidULID(c[:26]) || !envelope.ValidULID(c[27:]) {
		return "", "", false
	}
	return c[:26], c[27:], true
}

func (f *Feature) pendingList(s *vault.Session, body []byte) (json.RawMessage, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	n := 0
	for _, k := range []string{"rule_id", "connection_id", "agent_id"} {
		if o.Has(k) {
			n++
		}
	}
	if n > 1 {
		return nil, errBad
	}
	rid, hasRule, err := o.OptString("rule_id")
	if err != nil || hasRule && !envelope.ValidULID(rid) {
		return nil, errBad
	}
	conn, hasConn, err := o.OptString("connection_id")
	if err != nil || hasConn && (conn == "" || len(conn) > 128) {
		return nil, errBad
	}
	agent, hasAgent, err := o.OptString("agent_id")
	if err != nil || hasAgent && (agent == "" || len(agent) > 128) {
		return nil, errBad
	}
	afterRule, afterItem := "", ""
	if c, present, err := o.OptString("after"); err != nil {
		return nil, errBad
	} else if present {
		var ok bool
		if afterRule, afterItem, ok = parsePendingCursor(c); !ok {
			return nil, errBad
		}
	}
	limit := uint64(DefaultListLimit)
	if v, present, err := o.OptUint("limit", 1, MaxListLimit); err != nil {
		return nil, errBad
	} else if present {
		limit = v
	}
	rs := f.rules(s)
	sort.Slice(rs, func(i, j int) bool { return rs[i].ID < rs[j].ID })
	arr := []byte{'['}
	count, more := uint64(0), false
	lastRule, lastItem := "", ""
outer:
	for i := range rs {
		r := &rs[i]
		if hasRule && r.ID != rid || hasConn && r.Conn != conn || hasAgent && r.Agent != agent || r.ID < afterRule {
			continue
		}
		m := f.st.Incl[r.ID]
		for _, id := range sortedKeys(m) {
			inc := m[id]
			it := f.st.Items[id]
			if inc.State != StatePending || it == nil || r.ID == afterRule && id <= afterItem {
				continue
			}
			enc := strictjson.NewBuilder().String("rule_id", r.ID).Raw("subject", subjectJSON(r)).String("item_id", id).
				String("name", it.Name).String("category", it.Category).String("sensitivity", it.Sensitivity).
				String("at", envelope.FormatTS(inc.At)).Bytes()
			if count >= limit || count > 0 && len(arr)+len(enc)+64 > MaxListBytes {
				more = true
				break outer
			}
			if count > 0 {
				arr = append(arr, ',')
			}
			arr = append(arr, enc...)
			count++
			lastRule, lastItem = r.ID, id
		}
	}
	b := strictjson.NewBuilder().Raw("pending", append(arr, ']'))
	if more {
		b.String("next", pendingCursor(lastRule, lastItem))
	}
	return b.Bytes(), nil
}
