package items

import (
	"encoding/json"
	"sort"
	"time"

	"github.com/vettid/vettid-vault/features/itemspec"
	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/leashwire"
)

// Agent rule limits (§10.11): the LEASH grant limits.
const (
	MaxPerHour     = 3600
	MaxPerDay      = 86400
	DefaultPerHour = 60
	DefaultPerDay  = 1000
)

// ruleView is a share rule of either subject, as matching sees it.
type ruleView struct {
	ID      string
	Version uint64
	Conn    string // the connection subject, or
	Agent   string // the agent subject
	Terms   itemspec.Terms
	Created time.Time
	Updated time.Time
	// Limits are a connection rule's rate limits (0.23.0, §10.12).
	Limits itemspec.RateLimits
	agent  *itemspec.AgentRule
}

func connView(r *Rule) ruleView {
	return ruleView{ID: r.ID, Version: r.Version, Conn: r.Conn, Terms: r.Terms, Created: r.Created, Updated: r.Updated, Limits: r.Limits}
}

// sameSubject reports whether two rules have the same subject.
func (r *ruleView) sameSubject(q *ruleView) bool { return r.Conn == q.Conn && r.Agent == q.Agent }

func agentView(r *itemspec.AgentRule) ruleView {
	return ruleView{ID: r.ID, Version: r.Version, Agent: r.AgentID, Terms: r.Terms, Created: r.Created, Updated: r.Updated, agent: r}
}

// rules lists every rule in force, connection rules first, each sorted by
// id.
func (f *Feature) rules(s *vault.Session) []ruleView {
	var out []ruleView
	for _, id := range sortedKeys(f.st.Rules) {
		out = append(out, connView(f.st.Rules[id]))
	}
	if f.agents != nil {
		ars := f.agents.AgentRules(s.Now())
		sort.Slice(ars, func(i, j int) bool { return ars[i].ID < ars[j].ID })
		for i := range ars {
			out = append(out, agentView(&ars[i]))
		}
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// matches reports whether an item matches a rule now (§10.12): the rule
// in force, the tags, and never a critical item for an agent.
func (r *ruleView) matches(it *itemspec.Item, now time.Time) bool {
	if it == nil || !r.Terms.InForce(now) || !r.Terms.TagsMatch(it.Tags) {
		return false
	}
	return r.Agent == "" || it.Sensitivity != itemspec.Critical
}

func (f *Feature) incl(rule, item string) *Inclusion {
	if m := f.st.Incl[rule]; m != nil {
		return m[item]
	}
	return nil
}

// --- plans ---

const (
	opNone     = -1 // resolve: an action dropped (the item stays as it is)
	opWithdraw = iota - 1
	opPend
	opInclude
)

// action is one planned change of an item's inclusion in a rule.
type action struct {
	op   int
	rule ruleView
	item *itemspec.Item
	// askRule names the ask rule that holds an item pending in an auto
	// rule (0.23.0, §10.12 Overlapping rules).
	askRule string
	// promote: an inclusion of a pending item by a rule replaced from ask
	// to auto, which includes it in every rule of the subject where it is
	// pending.
	promote bool
}

func live(inc *Inclusion) bool {
	return inc != nil && (inc.State == StatePending || inc.State == StateIncluded)
}

// planPair plans one (rule, item) pair across a change: the rule from
// oldR to newR and the item from oldI to newI (either may be nil).
// tagGain: gaining one of the rule's tags is a gain; newGain: newly
// matching is a gain (false for a rule created or replaced without
// include_existing).
func (f *Feature) planPair(s *vault.Session, oldR, newR *ruleView, oldI, newI *itemspec.Item, tagGain, newGain bool) []action {
	now := s.Now()
	r := newR
	if r == nil {
		r = oldR
	}
	id := ""
	if newI != nil {
		id = newI.ID
	} else if oldI != nil {
		id = oldI.ID
	}
	inc := f.incl(r.ID, id)
	mb := oldR != nil && oldR.matches(oldI, now)
	ma := newR != nil && newR.matches(newI, now)
	if !ma {
		if live(inc) {
			return []action{{op: opWithdraw, rule: *r, item: oldI}}
		}
		return nil
	}
	if inc != nil && inc.State == StatePending && newR.Terms.Mode == itemspec.ModeAuto &&
		oldR != nil && oldR.ID == newR.ID && oldR.Terms.Mode == itemspec.ModeAsk {
		// ask → auto includes the pending (unless another ask rule holds
		// the item, resolve).
		return []action{{op: opInclude, rule: *newR, item: newI, promote: true}}
	}
	gain := !mb && newGain || mb && tagGain && oldI != nil && newR.Terms.GainedTag(oldI.Tags, newI.Tags)
	if !gain || live(inc) {
		return nil
	}
	op := opPend
	if newR.Terms.Mode == itemspec.ModeAuto {
		op = opInclude
	}
	return []action{{op: op, rule: *newR, item: newI}}
}

// planFresh plans an item gaining a rule after it was withdrawn from it
// (a move across critical, §10.12): every match is a gain.
func (f *Feature) planFresh(s *vault.Session, r *ruleView, it *itemspec.Item) []action {
	if it == nil || !r.matches(it, s.Now()) {
		return nil
	}
	op := opPend
	if r.Terms.Mode == itemspec.ModeAuto {
		op = opInclude
	}
	return []action{{op: op, rule: *r, item: it}}
}

// --- overlapping rules: ask wins (0.23.0, §10.12) ---

// planState is an item's state in a rule after a plan: the plan's last
// action for the pair, else its current inclusion ("" for none).
type planState map[[2]string]string

func (f *Feature) planStates(plan []action) planState {
	st := planState{}
	for _, a := range plan {
		k := [2]string{a.rule.ID, a.item.ID}
		switch a.op {
		case opWithdraw:
			st[k] = ""
		case opPend:
			st[k] = StatePending
		case opInclude:
			st[k] = StateIncluded
		}
	}
	return st
}

func (f *Feature) stateIn(st planState, rule, item string) string {
	if v, ok := st[[2]string{rule, item}]; ok {
		return v
	}
	if inc := f.incl(rule, item); inc != nil {
		return inc.State
	}
	return ""
}

// holder returns the ask rule that holds it for r's subject: among the
// other rules of the subject (rules, as they are after the change), the
// lowest id of an ask rule that covers it (matches it) and does not
// include it; "" if none.
func (f *Feature) holder(s *vault.Session, rules []ruleView, r *ruleView, it *itemspec.Item, st planState) string {
	h := ""
	for i := range rules {
		q := &rules[i]
		if q.ID == r.ID || !q.sameSubject(r) || q.Terms.Mode != itemspec.ModeAsk || !q.matches(it, s.Now()) {
			continue
		}
		if it.ID != "" && f.stateIn(st, q.ID, it.ID) == StateIncluded {
			continue // the member approved this item for this subject
		}
		if h == "" || q.ID < h {
			h = q.ID
		}
	}
	return h
}

// resolve applies "ask wins" to a plan made over rules (the rules as they
// are after the change, in the same flush): an item gaining an auto rule
// is included at once only if no ask rule of the same subject holds it;
// otherwise it becomes pending there with that ask rule's id. A rule
// replaced from ask to auto includes a pending item, in every rule of the
// subject where it is pending, only if no other ask rule holds it.
func (f *Feature) resolve(s *vault.Session, plan []action, rules []ruleView) []action {
	st := f.planStates(plan)
	for i := range plan {
		a := &plan[i]
		if a.op != opInclude || a.rule.Terms.Mode != itemspec.ModeAuto {
			continue
		}
		if h := f.holder(s, rules, &a.rule, a.item, st); h != "" {
			if a.promote {
				a.op = opNone // stays pending: no change
				continue
			}
			a.op, a.askRule = opPend, h
		}
	}
	out := plan[:0]
	for _, a := range plan {
		if a.op != opNone {
			out = append(out, a)
		}
	}
	plan = out
	st = f.planStates(plan)
	var extra []action
	for _, a := range plan {
		if a.op != opInclude || !a.promote || a.item.ID == "" {
			continue
		}
		for i := range rules {
			q := &rules[i]
			k := [2]string{q.ID, a.item.ID}
			if q.ID == a.rule.ID || !q.sameSubject(&a.rule) || f.stateIn(st, q.ID, a.item.ID) != StatePending {
				continue
			}
			if _, planned := st[k]; planned {
				continue
			}
			st[k] = StateIncluded
			extra = append(extra, action{op: opInclude, rule: *q, item: a.item})
		}
	}
	return append(plan, extra...)
}

// overlap describes a pending entry for the member (share.pending,
// share.pending.list): the ask rule that holds an item pending in an auto
// rule (ask_rule_id), and whether another rule of the subject already
// includes the item (shared). rules are the rules in force.
func (f *Feature) overlap(s *vault.Session, rules []ruleView, r *ruleView, it *itemspec.Item) (askRule string, shared bool) {
	if r.Terms.Mode == itemspec.ModeAuto {
		askRule = f.holder(s, rules, r, it, nil)
	}
	for i := range rules {
		q := &rules[i]
		if q.ID != r.ID && q.sameSubject(r) && f.stateIn(nil, q.ID, it.ID) == StateIncluded {
			shared = true
		}
	}
	return askRule, shared
}

// overlapMembers adds a pending entry's 0.23.0 members (share.pending's
// items, share.pending.list's entries): ask_rule_id? and shared?.
func overlapMembers(b *strictjson.Builder, askRule string, shared bool) *strictjson.Builder {
	if askRule != "" {
		b.String("ask_rule_id", askRule)
	}
	if shared {
		b.Bool("shared", true)
	}
	return b
}

// readable reports whether an inclusion of it makes a grant (§10.12).
func readable(r *ruleView, it *itemspec.Item) bool {
	return r.Conn != "" && it != nil && it.Sensitivity != itemspec.Critical
}

// checkPlan checks the limits a plan would reach (§10.12).
func (f *Feature) checkPlan(plan []action) error {
	pending := f.pendingCount()
	grants := 0
	for _, a := range plan {
		inc := f.incl(a.rule.ID, a.item.ID)
		switch a.op {
		case opWithdraw:
			if inc != nil && inc.State == StatePending {
				pending--
			}
		case opPend:
			pending++
		case opInclude:
			if inc != nil && inc.State == StatePending {
				pending--
			}
			if readable(&a.rule, a.item) {
				grants++
			}
		}
	}
	if pending > MaxPending {
		return vault.LimitError("share_pending", MaxPending)
	}
	if grants > 0 && (f.grants == nil || grants > f.grants.GivenRoom()) {
		return vault.LimitError("grants_given", MaxGivenGrants)
	}
	return nil
}

func (f *Feature) pendingCount() int {
	n := 0
	for _, m := range f.st.Incl {
		for _, inc := range m {
			if inc.State == StatePending {
				n++
			}
		}
	}
	return n
}

func subjectJSON(r *ruleView) []byte {
	if r.Agent != "" {
		return strictjson.NewBuilder().String("agent_id", r.Agent).Bytes()
	}
	return strictjson.NewBuilder().String("connection_id", r.Conn).Bytes()
}

func (r *ruleView) activity(kind, item string) vault.Activity {
	return vault.Activity{Kind: kind, ConnectionID: r.Conn, DeviceID: r.Agent, Ref: item, Audit: true}
}

// apply carries out a plan: withdrawals (grants revoked), pending items
// (share.pending per rule), inclusions (grants issued per connection and
// rule, data.shared).
func (f *Feature) apply(s *vault.Session, plan []action, reason string) {
	t := now(s)
	type batch struct {
		rule  ruleView
		items []*itemspec.Item
	}
	var pendOrder, inclOrder []string
	pend, incl := map[string]*batch{}, map[string]*batch{}
	for _, a := range plan {
		m := f.st.Incl[a.rule.ID]
		if m == nil {
			m = map[string]*Inclusion{}
			f.st.Incl[a.rule.ID] = m
		}
		id := a.item.ID
		inc := m[id]
		switch a.op {
		case opWithdraw:
			if !live(inc) {
				continue
			}
			if inc.State == StateIncluded {
				if inc.GrantID != "" && f.grants != nil {
					f.grants.RevokeRuleGrant(s, inc.GrantID)
				}
				s.Record(a.rule.activity("share.withdrawn", id))
			}
			delete(m, id)
		case opPend:
			m[id] = &Inclusion{State: StatePending, Conn: a.rule.Conn, Agent: a.rule.Agent, At: t}
			b := pend[a.rule.ID]
			if b == nil {
				b = &batch{rule: a.rule}
				pend[a.rule.ID] = b
				pendOrder = append(pendOrder, a.rule.ID)
			}
			b.items = append(b.items, a.item)
		case opInclude:
			m[id] = &Inclusion{State: StateIncluded, Conn: a.rule.Conn, Agent: a.rule.Agent, At: t}
			s.Record(a.rule.activity("share.included", id))
			if readable(&a.rule, a.item) {
				b := incl[a.rule.ID]
				if b == nil {
					b = &batch{rule: a.rule}
					incl[a.rule.ID] = b
					inclOrder = append(inclOrder, a.rule.ID)
				}
				b.items = append(b.items, a.item)
			}
		}
		if len(m) == 0 {
			delete(f.st.Incl, a.rule.ID)
		}
	}
	for _, rid := range inclOrder {
		b := incl[rid]
		f.issue(s, &b.rule, b.items)
	}
	var cur []ruleView
	if len(pendOrder) > 0 {
		cur = f.rules(s)
	}
	for _, rid := range pendOrder {
		b := pend[rid]
		var encs [][]byte
		for _, it := range b.items {
			ask, shared := f.overlap(s, cur, &b.rule, it)
			encs = append(encs, overlapMembers(strictjson.NewBuilder().String("item_id", it.ID).String("name", it.Name).
				String("category", it.Category).String("sensitivity", it.Sensitivity), ask, shared).Bytes())
		}
		// One share.pending per batch, split to stay within a message.
		for _, arr := range chunkArrays(encs, MaxMessageBytes) {
			s.NotifyAllDevices("share.pending", strictjson.NewBuilder().String("rule_id", rid).Raw("subject", subjectJSON(&b.rule)).
				Raw("items", arr).String("reason", reason).Bytes())
		}
		s.Record(vault.Activity{Kind: "share.pending", ConnectionID: b.rule.Conn, DeviceID: b.rule.Agent, Ref: rid, Feed: true})
	}
}

// chunkArrays packs encoded elements into JSON arrays of at most max
// bytes each (an element alone is never split).
func chunkArrays(encs [][]byte, max int) [][]byte {
	var out [][]byte
	arr := []byte{'['}
	for _, e := range encs {
		if len(arr) > 1 && len(arr)+len(e)+2 > max {
			out = append(out, append(arr, ']'))
			arr = []byte{'['}
		}
		if len(arr) > 1 {
			arr = append(arr, ',')
		}
		arr = append(arr, e...)
	}
	if len(arr) > 1 {
		out = append(out, append(arr, ']'))
	}
	return out
}

// issue gives the grants of included readable items, at most 64 per
// data.shared (§10.12).
func (f *Feature) issue(s *vault.Session, r *ruleView, its []*itemspec.Item) {
	if f.grants == nil {
		return
	}
	for len(its) > 0 {
		n := min(len(its), 64)
		chunk := its[:n]
		its = its[n:]
		metas := make([]itemspec.Meta, len(chunk))
		for i, it := range chunk {
			metas[i] = itemspec.MetaOf(it, nil)
		}
		ids, err := f.grants.IssueRuleGrants(s, r.Conn, r.ID, metas, r.Terms.Uses, r.Limits, r.Terms.Expires)
		if err != nil {
			continue // checked beforehand (checkPlan); the item stays included without a grant
		}
		for i, id := range ids {
			if inc := f.incl(r.ID, chunk[i].ID); inc != nil {
				inc.GrantID = id
			}
		}
	}
}

// expire drops connection rules past their expiry (their grants expire
// with them) and the inclusions of rules that no longer exist (an agent
// rule leash revoked, expired or dropped at unlink).
func (f *Feature) expire(s *vault.Session) {
	now := s.Now()
	for _, id := range sortedKeys(f.st.Rules) {
		r := f.st.Rules[id]
		if !r.Terms.InForce(now) {
			v := connView(r)
			f.withdrawRule(s, &v)
			delete(f.st.Rules, id)
			s.SyncEvent("share.rule.deleted", strictjson.NewBuilder().String("rule_id", id).Bytes())
		}
	}
	if len(f.st.Incl) == 0 {
		return
	}
	known := map[string]bool{}
	for id := range f.st.Rules {
		known[id] = true
	}
	if f.agents != nil {
		for _, r := range f.agents.AgentRules(now) {
			known[r.ID] = true
		}
	}
	for id := range f.st.Incl {
		if !known[id] {
			delete(f.st.Incl, id)
		}
	}
}

// withdrawRule withdraws every item of a rule and forgets its declines.
func (f *Feature) withdrawRule(s *vault.Session, r *ruleView) {
	m := f.st.Incl[r.ID]
	for _, id := range sortedKeys(m) {
		inc := m[id]
		if inc.State == StateIncluded {
			if inc.GrantID != "" && f.grants != nil {
				f.grants.RevokeRuleGrant(s, inc.GrantID)
			}
			s.Record(r.activity("share.withdrawn", id))
		}
	}
	delete(f.st.Incl, r.ID)
}

// --- share.rule.* (§10.12) ---

// ruleSpec is a parsed share.rule.set body.
type ruleSpec struct {
	ID        string
	Version   uint64
	Conn      string
	Agent     string
	Terms     itemspec.Terms
	PerHour   uint64
	PerDay    uint64
	StatusTTL time.Duration
	DryRun    bool
	// Limits are a connection rule's per_hour and per_day (0.23.0).
	Limits itemspec.RateLimits
}

// ParseRuleSet parses a share.rule.set body strictly.
func ParseRuleSet(body []byte, now time.Time) (*ruleSpec, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	sp := &ruleSpec{}
	id, hasID, err := o.OptString("rule_id")
	if err != nil || hasID && !envelope.ValidULID(id) {
		return nil, errBad
	}
	ver, hasVer, err := o.OptUint("version", 1, strictjson.MaxSafeInteger)
	if err != nil || hasID != hasVer {
		return nil, errBad
	}
	sp.ID, sp.Version = id, ver
	so, err := o.Object("subject")
	if err != nil || len(so) != 1 {
		return nil, errBad
	}
	if c, ok, err := so.OptString("connection_id"); err != nil {
		return nil, errBad
	} else if ok {
		sp.Conn = c
	}
	if a, ok, err := so.OptString("agent_id"); err != nil {
		return nil, errBad
	} else if ok {
		sp.Agent = a
	}
	if sp.Conn == "" && sp.Agent == "" || len(sp.Conn) > 128 || len(sp.Agent) > 128 {
		return nil, errBad
	}
	t, err := itemspec.ParseTerms(o, now)
	if err != nil {
		return nil, errBad
	}
	sp.Terms = *t
	ph, phSet, err := o.OptUint("per_hour", 1, MaxPerHour)
	if err != nil {
		return nil, errBad
	}
	pd, pdSet, err := o.OptUint("per_day", 1, MaxPerDay)
	if err != nil {
		return nil, errBad
	}
	ttl, ttlSet, err := o.OptUint("status_ttl", uint64(leashwire.MinStatusTTL/time.Second), uint64(leashwire.MaxStatusTTL/time.Second))
	if err != nil {
		return nil, errBad
	}
	if sp.Conn != "" && ttlSet {
		return nil, errBad // agent rules only (§10.11)
	}
	if sp.Conn != "" {
		// 0.23.0 (§10.12 Rate limits for connections): optional, no
		// default.
		if phSet {
			sp.Limits.PerHour = ph
		}
		if pdSet {
			sp.Limits.PerDay = pd
		}
	}
	if sp.Agent != "" {
		sp.PerHour, sp.PerDay, sp.StatusTTL = DefaultPerHour, DefaultPerDay, leashwire.DefaultStatusTTL
		if phSet {
			sp.PerHour = ph
		}
		if pdSet {
			sp.PerDay = pd
		}
		if ttlSet {
			sp.StatusTTL = time.Duration(ttl) * time.Second
		}
	}
	if o.Has("dry_run") {
		if sp.DryRun, err = o.Bool("dry_run"); err != nil {
			return nil, errBad
		}
	}
	return sp, nil
}

func (f *Feature) countRules(s *vault.Session, conn, agent string) (subj, all int) {
	for _, r := range f.rules(s) {
		all++
		if conn != "" && r.Conn == conn || agent != "" && r.Agent == agent {
			subj++
		}
	}
	return
}

func (f *Feature) findRule(s *vault.Session, id string) (*ruleView, bool) {
	for _, r := range f.rules(s) {
		if r.ID == id {
			r := r
			return &r, true
		}
	}
	return nil, false
}

func (f *Feature) sortedItems() []*itemspec.Item {
	out := make([]*itemspec.Item, 0, len(f.st.Items))
	for _, id := range sortedKeys(f.st.Items) {
		out = append(out, f.st.Items[id])
	}
	return out
}

// planRule plans a rule's creation or replacement over every item, with
// ask wins over the rules as they will be (§10.12).
func (f *Feature) planRule(s *vault.Session, oldR, newR *ruleView) []action {
	var plan []action
	for _, it := range f.sortedItems() {
		plan = append(plan, f.planPair(s, oldR, newR, it, it, false, newR.Terms.IncludeExisting)...)
	}
	after := f.rules(s)
	found := false
	for i := range after {
		if after[i].ID == newR.ID {
			after[i], found = *newR, true
		}
	}
	if !found {
		after = append(after, *newR)
	}
	return f.resolve(s, plan, after)
}

func (f *Feature) ruleSet(s *vault.Session, body []byte) (json.RawMessage, error) {
	t := now(s)
	sp, err := ParseRuleSet(body, t)
	if err != nil {
		return nil, err
	}
	var old *ruleView
	if sp.ID != "" {
		r, ok := f.findRule(s, sp.ID)
		if !ok {
			return nil, errNotFound
		}
		if r.Conn != sp.Conn || r.Agent != sp.Agent {
			return nil, errBad // the subject cannot change
		}
		if r.Version != sp.Version {
			return nil, errConflict
		}
		old = r
	} else {
		subj, all := f.countRules(s, sp.Conn, sp.Agent)
		if subj >= MaxRulesPerSubj {
			return nil, vault.LimitError("share_rules_subject", MaxRulesPerSubj)
		}
		if all >= MaxRules {
			return nil, vault.LimitError("share_rules", MaxRules)
		}
	}
	if sp.Conn != "" {
		if p, ok := s.Connection(sp.Conn); !ok || p.State != vault.PeerActive {
			return nil, errNotFound
		}
	} else {
		if f.agents == nil {
			return nil, errNotFound
		}
		if p, ok := s.PairedDevice(sp.Agent); !ok || p.Kind != vault.KindAgent {
			return nil, errNotFound
		}
		if s.From().Kind != vault.KindApp {
			return nil, errForbidden // an agent rule is signed with the credential key (§10.11)
		}
	}
	id := sp.ID
	if id == "" {
		id = s.NewID()
	}
	next := ruleView{ID: id, Version: sp.Version + 1, Conn: sp.Conn, Agent: sp.Agent, Terms: sp.Terms, Created: t, Updated: t, Limits: sp.Limits}
	if old != nil {
		next.Created = old.Created
	}
	plan := f.planRule(s, old, &next)
	if sp.DryRun {
		return f.dryRunMatches(s, &next, plan), nil
	}
	if err := f.checkPlan(plan); err != nil {
		return nil, err
	}
	if sp.Agent != "" {
		ar, err := f.agents.SetAgentRule(s, &itemspec.AgentRule{ID: id, Version: sp.Version, AgentID: sp.Agent, Terms: sp.Terms,
			PerHour: sp.PerHour, PerDay: sp.PerDay, StatusTTL: sp.StatusTTL, Created: next.Created, Updated: t})
		if err != nil {
			return nil, err
		}
		next = agentView(ar)
	} else {
		nr := &Rule{ID: id, Version: next.Version, Conn: sp.Conn, Terms: sp.Terms, Created: next.Created, Updated: t, Limits: sp.Limits}
		if prev := f.st.Rules[id]; prev != nil {
			// The windows are kept when the rule is replaced: a lowered
			// limit applies at once to the open window (0.23.0).
			nr.Windows = prev.Windows
			if prev.Limits != sp.Limits && f.grants != nil {
				f.grants.SetRuleLimits(s, id, sp.Limits) // a given grant carries the rule's current limits
			}
		}
		f.st.Rules[id] = nr
	}
	f.apply(s, plan, "rule")
	kind := "share.rule.created"
	if old != nil {
		kind = "share.rule.updated"
	}
	s.Record(vault.Activity{Kind: kind, ConnectionID: next.Conn, DeviceID: next.Agent, Ref: id, Audit: true})
	s.SyncEvent("share.rule.changed", strictjson.NewBuilder().String("rule_id", id).Uint("version", next.Version).Bytes())
	return f.ruleJSON(&next), nil
}

// dryRunMatches lists the items a rule would match, with their current
// state for that rule (§10.12): at most MaxMessageBytes of them, and the
// total. Since 0.23.0 an entry whose state the request would change
// carries outcome (include or ask) and, when an ask rule of the subject
// holds it, ask_rule_id (plan: the resolved plan of the request).
func (f *Feature) dryRunMatches(s *vault.Session, r *ruleView, plan []action) []byte {
	outcome := map[string]*action{}
	for i := range plan {
		if a := &plan[i]; a.rule.ID == r.ID && a.op != opWithdraw {
			outcome[a.item.ID] = a
		}
	}
	arr := []byte{'['}
	n := 0
	for _, it := range f.sortedItems() {
		if !r.matches(it, s.Now()) {
			continue
		}
		n++
		b := strictjson.NewBuilder().String("item_id", it.ID).String("name", it.Name).String("category", it.Category).
			String("sensitivity", it.Sensitivity)
		if inc := f.incl(r.ID, it.ID); inc != nil {
			b.String("state", inc.State)
		}
		if a := outcome[it.ID]; a != nil {
			if a.op == opInclude {
				b.String("outcome", "include")
			} else {
				b.String("outcome", "ask")
				if a.askRule != "" {
					b.String("ask_rule_id", a.askRule)
				}
			}
		}
		e := b.Bytes()
		if len(arr)+len(e)+2 > MaxMessageBytes {
			continue // counted, not listed
		}
		if len(arr) > 1 {
			arr = append(arr, ',')
		}
		arr = append(arr, e...)
	}
	return strictjson.NewBuilder().Raw("matches", append(arr, ']')).Uint("total", uint64(n)).Bytes()
}

func (f *Feature) ruleJSON(r *ruleView) []byte {
	b := strictjson.NewBuilder().String("rule_id", r.ID).Uint("version", r.Version).Raw("subject", subjectJSON(r))
	r.Terms.JSONMembers(b)
	if r.Agent == "" {
		// A connection rule's rate limits (0.23.0), when set.
		if r.Limits.PerHour > 0 {
			b.Uint("per_hour", r.Limits.PerHour)
		}
		if r.Limits.PerDay > 0 {
			b.Uint("per_day", r.Limits.PerDay)
		}
	}
	if a := r.agent; a != nil {
		b.Uint("per_hour", a.PerHour).Uint("per_day", a.PerDay).Uint("status_ttl", uint64(a.StatusTTL/time.Second))
		if a.Delegation != nil {
			b.Base64("delegation", a.Delegation).Base64("sig", a.DelegationSig)
		}
	}
	b.String("created_at", envelope.FormatTS(r.Created)).String("updated_at", envelope.FormatTS(r.Updated))
	var inc, pend, dec []string
	m := f.st.Incl[r.ID]
	for _, id := range sortedKeys(m) {
		switch m[id].State {
		case StateIncluded:
			inc = append(inc, id)
		case StatePending:
			pend = append(pend, id)
		case StateDeclined:
			dec = append(dec, id)
		}
	}
	return b.Raw("included", itemspec.StrList(nonNil(inc))).Raw("pending", itemspec.StrList(nonNil(pend))).
		Raw("declined", itemspec.StrList(nonNil(dec))).Bytes()
}

func nonNil(l []string) []string {
	if l == nil {
		return []string{}
	}
	return l
}

func (f *Feature) ruleList(s *vault.Session, body []byte) (json.RawMessage, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	conn, hasConn, err := o.OptString("connection_id")
	if err != nil {
		return nil, errBad
	}
	agent, hasAgent, err := o.OptString("agent_id")
	if err != nil || hasConn && hasAgent {
		return nil, errBad
	}
	after, _, err := o.OptString("after")
	if err != nil || after != "" && !envelope.ValidULID(after) {
		return nil, errBad
	}
	limit := uint64(DefaultRuleLimit)
	if v, present, err := o.OptUint("limit", 1, MaxRuleLimit); err != nil {
		return nil, errBad
	} else if present {
		limit = v
	}
	rs := f.rules(s)
	sort.Slice(rs, func(i, j int) bool { return rs[i].ID < rs[j].ID })
	arr := []byte{'['}
	n, last, more := uint64(0), "", false
	for _, r := range rs {
		if r.ID <= after || hasConn && r.Conn != conn || hasAgent && r.Agent != agent {
			continue
		}
		enc := f.ruleJSON(&r)
		if n >= limit || n > 0 && len(arr)+len(enc)+64 > MaxMessageBytes {
			more = true
			break
		}
		if n > 0 {
			arr = append(arr, ',')
		}
		arr = append(arr, enc...)
		n++
		last = r.ID
	}
	b := strictjson.NewBuilder().Raw("rules", append(arr, ']'))
	if more {
		b.String("next", last)
	}
	return b.Bytes(), nil
}

func (f *Feature) ruleDelete(s *vault.Session, body []byte) (json.RawMessage, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	id, err := parseItemID(o, "rule_id")
	if err != nil {
		return nil, err
	}
	r, ok := f.findRule(s, id)
	if !ok {
		return nil, errNotFound
	}
	if r.Agent != "" {
		if !f.agents.DeleteAgentRule(s, id) {
			return nil, errNotFound
		}
	} else {
		delete(f.st.Rules, id)
	}
	f.withdrawRule(s, r)
	s.Record(vault.Activity{Kind: "share.rule.deleted", ConnectionID: r.Conn, DeviceID: r.Agent, Ref: id, Audit: true})
	s.SyncEvent("share.rule.deleted", strictjson.NewBuilder().String("rule_id", id).Bytes())
	return nil, nil
}

// decideLists parses share.decide's item lists: {items, approve}, or
// (0.21.0) {include?, decline?}, together 1–500 distinct ids; mixing the
// forms is bad_request.
func decideLists(o strictjson.Object) (include, decline []string, err error) {
	oldForm := o.Has("items") || o.Has("approve")
	if !o.Has("include") && !o.Has("decline") {
		if !oldForm {
			return nil, nil, errBad
		}
		ids, present, err := idList(o, "items", MaxDecide, envelope.ValidULID)
		if err != nil || !present {
			return nil, nil, errBad
		}
		approve, err := o.Bool("approve")
		if err != nil {
			return nil, nil, errBad
		}
		if approve {
			return ids, nil, nil
		}
		return nil, ids, nil
	}
	if oldForm {
		return nil, nil, errBad
	}
	seen := map[string]bool{}
	list := func(name string) ([]string, error) {
		arr, _, err := o.OptArray(name)
		if err != nil {
			return nil, errBad
		}
		var out []string
		for _, r := range arr {
			v, err := strictjson.AsString(r)
			if err != nil || !envelope.ValidULID(v) || seen[v] {
				return nil, errBad // in both lists, or twice in one
			}
			seen[v] = true
			out = append(out, v)
		}
		return out, nil
	}
	if include, err = list("include"); err != nil {
		return nil, nil, err
	}
	if decline, err = list("decline"); err != nil {
		return nil, nil, err
	}
	if n := len(include) + len(decline); n == 0 || n > MaxDecide {
		return nil, nil, errBad
	}
	return include, decline, nil
}

// decide includes and declines pending items of a rule in one change
// (§10.12; both lists at once since 0.21.0): one response, and on an
// error (a limit) no change at all. Since 0.23.0 an answer is per item and
// subject (Overlapping rules): an inclusion includes the item in every
// rule of the subject where it is pending; a decline declines it in every
// rule of the subject where it is pending or included, withdrawing it
// where it was included. One share.decided per rule changed.
func (f *Feature) decide(s *vault.Session, body []byte) (json.RawMessage, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	rid, err := parseItemID(o, "rule_id")
	if err != nil {
		return nil, err
	}
	include, decline, err := decideLists(o)
	if err != nil {
		return nil, err
	}
	r, ok := f.findRule(s, rid)
	if !ok {
		return nil, errNotFound
	}
	pending := func(id string) *itemspec.Item {
		inc := f.incl(rid, id)
		it := f.st.Items[id]
		if inc == nil || inc.State != StatePending || it == nil {
			return nil // not pending: ignored
		}
		return it
	}
	rules := f.rules(s)
	var subj []*ruleView // the rules of the subject, sorted by id
	for i := range rules {
		if rules[i].sameSubject(r) {
			subj = append(subj, &rules[i])
		}
	}
	type change struct {
		rule *ruleView
		item string
	}
	var plan []action
	var includedIDs, declinedIDs []string
	for _, id := range include {
		it := pending(id)
		if it == nil {
			continue
		}
		includedIDs = append(includedIDs, id)
		for _, q := range subj {
			if inc := f.incl(q.ID, id); inc != nil && inc.State == StatePending {
				plan = append(plan, action{op: opInclude, rule: *q, item: it})
			}
		}
	}
	var declines []change
	for _, id := range decline {
		if pending(id) == nil {
			continue
		}
		declinedIDs = append(declinedIDs, id)
		for _, q := range subj {
			if inc := f.incl(q.ID, id); live(inc) {
				declines = append(declines, change{rule: q, item: id})
			}
		}
	}
	if len(plan) == 0 && len(declines) == 0 {
		return nil, errBad
	}
	if err := f.checkPlan(plan); err != nil {
		return nil, err
	}
	f.apply(s, plan, "")
	t := now(s)
	perRule := map[string]*[2][]string{}
	var order []string
	note := func(rule, item string, k int) {
		e := perRule[rule]
		if e == nil {
			e = &[2][]string{}
			perRule[rule] = e
			order = append(order, rule)
		}
		e[k] = append(e[k], item)
	}
	for _, a := range plan {
		note(a.rule.ID, a.item.ID, 0)
	}
	for _, d := range declines {
		inc := f.incl(d.rule.ID, d.item)
		if inc.State == StateIncluded {
			// A decline stops sharing the item with the subject: an
			// explicit act of the member, not a silent withdrawal.
			if inc.GrantID != "" && f.grants != nil {
				f.grants.RevokeRuleGrant(s, inc.GrantID)
			}
			s.Record(d.rule.activity("share.withdrawn", d.item))
		}
		f.st.Incl[d.rule.ID][d.item] = &Inclusion{State: StateDeclined, Conn: d.rule.Conn, Agent: d.rule.Agent, At: t}
		s.Record(d.rule.activity("share.declined", d.item))
		note(d.rule.ID, d.item, 1)
	}
	sort.Strings(order)
	for _, id := range order {
		e := perRule[id]
		s.SyncEvent("share.decided", strictjson.NewBuilder().String("rule_id", id).Raw("included", itemspec.StrList(nonNil(e[0]))).
			Raw("declined", itemspec.StrList(nonNil(e[1]))).Bytes())
	}
	inc, dec := itemspec.StrList(nonNil(includedIDs)), itemspec.StrList(nonNil(declinedIDs))
	return strictjson.NewBuilder().Raw("included", inc).Raw("declined", dec).Bytes(), nil
}

// --- observers ---

// ConnectionRemoved implements vault.ConnectionRemovedObserver: the
// connection's rules and inclusions go (its grants are dropped by the
// grants feature, §7.4), and so does its profile record.
func (f *Feature) ConnectionRemoved(_ *vault.Session, conn string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for id, r := range f.st.Rules {
		if r.Conn == conn {
			delete(f.st.Rules, id)
			delete(f.st.Incl, id)
		}
	}
	delete(f.st.Profile.Peers, conn)
}

// DeviceRemoved implements vault.DeviceRemovedObserver: an unlinked
// agent's inclusions go (leash revokes its rules, §7.4).
func (f *Feature) DeviceRemoved(_ *vault.Session, device string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for rid, m := range f.st.Incl {
		for id, inc := range m {
			if inc.Agent == device {
				delete(m, id)
			}
		}
		if len(m) == 0 {
			delete(f.st.Incl, rid)
		}
	}
}

// CredentialDeleted implements credential.DeleteObserver: the critical
// items go with the credential (§10.6); their inclusions (usable, never
// granted) are dropped.
func (f *Feature) CredentialDeleted(s *vault.Session) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, id := range sortedKeys(f.st.Items) {
		if f.st.Items[id].Sensitivity != itemspec.Critical {
			continue
		}
		delete(f.st.Items, id)
		for rid, m := range f.st.Incl {
			delete(m, id)
			if len(m) == 0 {
				delete(f.st.Incl, rid)
			}
		}
		s.SyncEvent("item.deleted", strictjson.NewBuilder().String("item_id", id).Bytes())
		s.Record(vault.Activity{Kind: "item.deleted", Ref: id, Audit: true})
	}
}
