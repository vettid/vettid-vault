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
	agent   *itemspec.AgentRule
}

func connView(r *Rule) ruleView {
	return ruleView{ID: r.ID, Version: r.Version, Conn: r.Conn, Terms: r.Terms, Created: r.Created, Updated: r.Updated}
}

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
	opWithdraw = iota
	opPend
	opInclude
)

// action is one planned change of an item's inclusion in a rule.
type action struct {
	op   int
	rule ruleView
	item *itemspec.Item
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
	if inc != nil && inc.State == StatePending && newR.Terms.Mode == itemspec.ModeAuto {
		return []action{{op: opInclude, rule: *newR, item: newI}} // ask → auto includes the pending
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
		return errLimit
	}
	if grants > 0 && (f.grants == nil || grants > f.grants.GivenRoom()) {
		return errLimit
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
	for _, rid := range pendOrder {
		b := pend[rid]
		var encs [][]byte
		for _, it := range b.items {
			encs = append(encs, strictjson.NewBuilder().String("item_id", it.ID).String("name", it.Name).
				String("category", it.Category).String("sensitivity", it.Sensitivity).Bytes())
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
		ids, err := f.grants.IssueRuleGrants(s, r.Conn, r.ID, metas, r.Terms.Uses, r.Terms.Expires)
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
	if sp.Conn != "" && (phSet || pdSet || ttlSet) {
		return nil, errBad // agent rules only (§10.11)
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

// planRule plans a rule's creation or replacement over every item.
func (f *Feature) planRule(s *vault.Session, oldR, newR *ruleView) []action {
	var plan []action
	for _, it := range f.sortedItems() {
		plan = append(plan, f.planPair(s, oldR, newR, it, it, false, newR.Terms.IncludeExisting)...)
	}
	return plan
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
		if subj >= MaxRulesPerSubj || all >= MaxRules {
			return nil, errLimit
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
	next := ruleView{ID: id, Version: sp.Version + 1, Conn: sp.Conn, Agent: sp.Agent, Terms: sp.Terms, Created: t, Updated: t}
	if old != nil {
		next.Created = old.Created
	}
	plan := f.planRule(s, old, &next)
	if sp.DryRun {
		return f.dryRunMatches(s, &next), nil
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
		f.st.Rules[id] = &Rule{ID: id, Version: next.Version, Conn: sp.Conn, Terms: sp.Terms, Created: next.Created, Updated: t}
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
// total.
func (f *Feature) dryRunMatches(s *vault.Session, r *ruleView) []byte {
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
	if a := r.agent; a != nil {
		b.Uint("per_hour", a.PerHour).Uint("per_day", a.PerDay).Uint("status_ttl", uint64(a.StatusTTL/time.Second))
		if a.Delegation != nil {
			b.Base64("delegation", a.Delegation).Base64("delegation_sig", a.DelegationSig).Base64("key", a.Key)
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

func (f *Feature) decide(s *vault.Session, body []byte) (json.RawMessage, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	rid, err := parseItemID(o, "rule_id")
	if err != nil {
		return nil, err
	}
	ids, present, err := idList(o, "items", MaxDecide, envelope.ValidULID)
	if err != nil || !present {
		return nil, errBad
	}
	approve, err := o.Bool("approve")
	if err != nil {
		return nil, errBad
	}
	r, ok := f.findRule(s, rid)
	if !ok {
		return nil, errNotFound
	}
	var plan []action
	var declined []string
	for _, id := range ids {
		inc := f.incl(rid, id)
		it := f.st.Items[id]
		if inc == nil || inc.State != StatePending || it == nil {
			continue
		}
		if approve {
			plan = append(plan, action{op: opInclude, rule: *r, item: it})
		} else {
			declined = append(declined, id)
		}
	}
	if len(plan) == 0 && len(declined) == 0 {
		return nil, errBad
	}
	if err := f.checkPlan(plan); err != nil {
		return nil, err
	}
	f.apply(s, plan, "")
	t := now(s)
	for _, id := range declined {
		f.st.Incl[rid][id] = &Inclusion{State: StateDeclined, Conn: r.Conn, Agent: r.Agent, At: t}
		s.Record(r.activity("share.declined", id))
	}
	var included []string
	for _, a := range plan {
		included = append(included, a.item.ID)
	}
	inc, dec := itemspec.StrList(nonNil(included)), itemspec.StrList(nonNil(declined))
	s.SyncEvent("share.decided", strictjson.NewBuilder().String("rule_id", rid).Raw("included", inc).Raw("declined", dec).Bytes())
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
