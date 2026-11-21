package leash

import (
	"encoding/json"

	"github.com/vettid/vettid-vault/features/itemspec"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/strictjson"
)

var errSessionRequired = vault.NewError("session_required", "")

// proxyRefusal is the answer to an item.proxy the item's settings refuse
// (§10.11): way_not_allowed {ways}, or bad_request for a host the item
// does not bind.
func proxyRefusal(j itemspec.ProxyJudgement, w *itemspec.ItemWays) error {
	if j.Refusal == "way_not_allowed" {
		return wayNotAllowed(w)
	}
	return errBad
}

// proxyNote is what a referred item.proxy was decided under, kept with
// the held request (vault.Session.NoteApproval) and read back when an
// app approves it: the bound host, the header and the prefix the value
// would be sent with. The app shows the header's name and the prefix
// (§10.11); they are not in the held request's body.
type proxyNote struct {
	Host   string `json:"host"`
	Header string `json:"header"`
	Prefix string `json:"prefix"`
}

func proxyNoteOf(j itemspec.ProxyJudgement) proxyNote {
	return proxyNote{Host: j.Host, Header: j.Header, Prefix: j.Prefix}
}

func (n proxyNote) raw() json.RawMessage {
	raw, _ := json.Marshal(n)
	return raw
}

// shown is what the approval shows of n (approval.pending{proxy}, 0.92.0):
// the same three values, as the vault will send them.
func (n proxyNote) shown() *vault.ApprovalProxy {
	return &vault.ApprovalProxy{Host: n.Host, Header: n.Header, Prefix: n.Prefix}
}

// itemProxy answers an item.proxy (§10.11) once an app approved it: an
// item.proxy is always referred, so one not approved is forbidden (fail
// secure). The settings are judged again: a proxy they now refuse gets
// that refusal, never the value. One whose host, header or prefix changed
// while it waited is referred again as a new approval (a new referral,
// forbidden past the cap), so the value is never sent with a header the
// approval did not show.
//
// The proxy lasts seconds (default 900), cut to the end of the agent's
// access session; with no session left it is session_required. A value
// that is not visible ASCII and spaces cannot go in a header
// (bad_request); an address field is not_found. The answer is
// {item_id, field_id, value, header, prefix, host, expires_at}, noted as
// leash.item.proxy (summarised).
func (f *Feature) itemProxy(s *vault.Session, agent string, rules []itemspec.AgentRule, r *Request) (json.RawMessage, error) {
	w, ok := f.items.AgentWays(agent, rules, r.ItemID)
	if !ok {
		return nil, errNotFound
	}
	j := itemspec.JudgeProxy(w, r.Proxy)
	if j.Refusal != "" {
		return nil, proxyRefusal(j, w)
	}
	if !s.Approved() {
		return nil, errForbidden
	}
	var n proxyNote
	if err := json.Unmarshal(s.HeldNote(), &n); err != nil || n.Host == "" {
		return nil, errForbidden // a held proxy without its note: never sent unseen
	}
	// Compared exactly, header case included, though a change of the
	// header's case alone is not a widening (itemspec.Widens): the member
	// approves what the approval showed, and asking again costs little.
	if n != proxyNoteOf(j) {
		n := proxyNoteOf(j)
		return nil, f.referAgain(s, agent, vault.Approval{Note: n.raw(), Proxy: n.shown()})
	}
	expires, ok := itemspec.ProxyExpiry(s.Now(), r.Proxy.Seconds, s.From().SessionExpires)
	if !ok {
		return nil, errSessionRequired
	}
	value, ok := f.items.AgentFieldValue(agent, rules, r.ItemID, r.FieldID)
	if !ok {
		return nil, errNotFound
	}
	if !itemspec.HeaderSafe(value) {
		return nil, errBad
	}
	f.note(s, agent, f.agent(s, agent), vault.Activity{Kind: KindProxy, Ref: r.ItemID, Feed: true})
	answer := func(withValue bool) json.RawMessage {
		b := strictjson.NewBuilder().String("item_id", r.ItemID).String("field_id", r.FieldID)
		if withValue {
			b = b.String("value", value)
		}
		b = b.String("header", j.Header).String("prefix", j.Prefix).String("host", j.Host).
			String("expires_at", envelope.FormatTS(expires))
		if !withValue {
			b = b.Bool("withheld", true) // the cached copy (#15273)
		}
		return b.Bytes()
	}
	s.CacheResponseAs(answer(false)) // no value in the response cache (#14595)
	return answer(true), nil
}
