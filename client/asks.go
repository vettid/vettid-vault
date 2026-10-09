package client

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// VAULT-MESSAGING 0.23.0 from a device's side: a connection's asks
// (§10.4.1: mute, resume, the state on <connection>), connection rule
// rate limits and the overlap of rules (§10.12: the dry run's outcome and
// ask_rule_id, the pending entries' ask_rule_id and shared, rules named by
// their tags).

// AskState is <connection>.asks (§10.4.1).
type AskState struct {
	Muted     bool
	Paused    bool
	PausedAt  time.Time // zero unless paused
	Cooldowns uint64
}

// ParseAskState parses a <connection>'s asks member.
func ParseAskState(raw json.RawMessage) (*AskState, error) {
	o, err := strictjson.AsObject(raw)
	if err != nil {
		return nil, ErrProtocol
	}
	a := &AskState{}
	if a.Muted, err = o.Bool("muted"); err != nil {
		return nil, ErrProtocol
	}
	if a.Paused, err = o.Bool("paused"); err != nil {
		return nil, ErrProtocol
	}
	if ts, ok, err := o.OptString("paused_at"); err != nil || ok != a.Paused {
		return nil, ErrProtocol
	} else if ok {
		if a.PausedAt, err = envelope.ParseTS(ts); err != nil {
			return nil, ErrProtocol
		}
	}
	if a.Cooldowns, err = o.Uint("cooldowns", 0, 64); err != nil {
		return nil, ErrProtocol
	}
	return a, nil
}

// ConnectionAsks reads a connection's ask state (connection.get's asks).
func (d *Device) ConnectionAsks(ctx context.Context, connectionID string) (*AskState, error) {
	o, err := d.Op(ctx, "connection.get", map[string]any{"connection_id": connectionID})
	if err != nil {
		return nil, err
	}
	raw, ok := o["asks"]
	if !ok {
		return nil, ErrProtocol
	}
	return ParseAskState(raw)
}

// ConnectionAsksMute mutes (or unmutes) a connection's asks.
func (d *Device) ConnectionAsksMute(ctx context.Context, connectionID string, muted bool) error {
	_, err := d.Op(ctx, "connection.asks.mute", map[string]any{"connection_id": connectionID, "muted": muted})
	return err
}

// ConnectionAsksResume always clears a connection's decline times and
// cooldowns and ends a pause of its asks, if any (0.23.1).
func (d *Device) ConnectionAsksResume(ctx context.Context, connectionID string) error {
	_, err := d.Op(ctx, "connection.asks.resume", map[string]any{"connection_id": connectionID})
	return err
}

// RuleMatch is one entry of share.rule.set's dry run (§10.12): Outcome
// "include" or "ask" when the request would change the item's state in
// the rule ("" otherwise), AskRuleID when an ask rule of the subject holds
// the item (0.23.0).
type RuleMatch struct {
	ItemID, Name, Category, Sensitivity string
	State                               string
	Outcome                             string
	AskRuleID                           string
}

// RuleDryRun is share.rule.set{dry_run}'s answer.
type RuleDryRun struct {
	Matches []RuleMatch
	Total   uint64
}

// ShareRuleDryRun previews a share.rule.set (body as ShareRuleSet's,
// dry_run added).
func (d *Device) ShareRuleDryRun(ctx context.Context, body map[string]any) (*RuleDryRun, error) {
	b := map[string]any{}
	for k, v := range body {
		b[k] = v
	}
	b["dry_run"] = true
	o, err := d.Op(ctx, "share.rule.set", b)
	if err != nil {
		return nil, err
	}
	arr, err := o.Array("matches")
	if err != nil {
		return nil, ErrProtocol
	}
	out := &RuleDryRun{}
	if out.Total, err = o.Uint("total", 0, strictjson.MaxSafeInteger); err != nil {
		return nil, ErrProtocol
	}
	for _, raw := range arr {
		m, err := strictjson.AsObject(raw)
		if err != nil {
			return nil, ErrProtocol
		}
		var e RuleMatch
		for k, p := range map[string]*string{"item_id": &e.ItemID, "name": &e.Name, "category": &e.Category, "sensitivity": &e.Sensitivity} {
			if *p, err = m.String(k); err != nil {
				return nil, ErrProtocol
			}
		}
		for k, p := range map[string]*string{"state": &e.State, "outcome": &e.Outcome, "ask_rule_id": &e.AskRuleID} {
			if *p, _, err = m.OptString(k); err != nil {
				return nil, ErrProtocol
			}
		}
		if e.Outcome != "" && e.Outcome != "include" && e.Outcome != "ask" || e.AskRuleID != "" && e.Outcome != "ask" {
			return nil, ErrProtocol
		}
		out.Matches = append(out.Matches, e)
	}
	return out, nil
}

// RuleName names a rule to the member by its tags (§10.12 Naming a rule
// to the member, 0.23.0): one tag alone; with match "all" the tags joined
// by " + ", with "any" by " or ", in the rule's order. names maps a tag to
// the member's name for it (nil: the tag itself).
func RuleName(tags []string, match string, names map[string]string) string {
	ns := make([]string, len(tags))
	for i, t := range tags {
		ns[i] = t
		if n, ok := names[t]; ok && n != "" {
			ns[i] = n
		}
	}
	sep := " or "
	if match == "all" {
		sep = " + "
	}
	return strings.Join(ns, sep)
}
