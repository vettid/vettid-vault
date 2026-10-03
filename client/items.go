package client

import (
	"context"
	"encoding/json"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/credwire"
)

// Items, tags and share rules from a device's side (VAULT-MESSAGING
// §10.7, §10.8, §10.12). Items of sensitivity data or secret are ordinary
// requests; critical items are credential operations of an app: the
// content travels sealed to a UTK, the values come back sealed to a
// one-time reply key, and the new blob is kept (§3.5.3, §3.5.4).

// ItemField is one field of an item to put. ID is empty for a new field;
// Value is a string, or an address object (map[string]string).
type ItemField struct {
	ID    string `json:"field_id,omitempty"`
	Label string `json:"label"`
	Kind  string `json:"kind"`
	Value any    `json:"value"`
}

// ItemContent is an item's content: what item.put sets.
type ItemContent struct {
	Name     string      `json:"name"`
	Category string      `json:"category,omitempty"`
	Template string      `json:"template,omitempty"`
	Fields   []ItemField `json:"fields,omitempty"`
	Notes    string      `json:"notes,omitempty"`
}

func (c ItemContent) body() map[string]any {
	b := map[string]any{"name": c.Name}
	if c.Category != "" {
		b["category"] = c.Category
	}
	if c.Template != "" {
		b["template"] = c.Template
	}
	if c.Fields != nil {
		b["fields"] = c.Fields
	}
	if c.Notes != "" {
		b["notes"] = c.Notes
	}
	return b
}

func idVersion(o strictjson.Object) (string, uint64, error) {
	id, err := o.String("item_id")
	if err != nil {
		return "", 0, ErrProtocol
	}
	v, err := o.Uint("version", 1, strictjson.MaxSafeInteger)
	if err != nil {
		return "", 0, ErrProtocol
	}
	return id, v, nil
}

// ItemPut creates (id "") or replaces a data or secret item and returns
// its id and version. sensitivity "" means data for a new item (and the
// current one for a replacement); tags nil leaves them as they are.
func (d *Device) ItemPut(ctx context.Context, id string, version uint64, sensitivity string, tags []string, c ItemContent) (string, uint64, error) {
	body := c.body()
	if id != "" {
		body["item_id"], body["version"] = id, version
	}
	if sensitivity != "" {
		body["sensitivity"] = sensitivity
	}
	if tags != nil {
		body["tags"] = tags
	}
	o, err := d.Op(ctx, "item.put", body)
	if err != nil {
		return "", 0, err
	}
	return idVersion(o)
}

// ItemPutCritical creates (id "") or replaces a critical item with the
// credential password; the content and the item id travel sealed (§10.7).
func (d *Device) ItemPutCritical(ctx context.Context, password, id string, version uint64, tags []string, c ItemContent) (string, uint64, error) {
	extra := map[string]any{"sensitivity": "critical"}
	if id != "" {
		extra["version"] = version
	}
	if tags != nil {
		extra["tags"] = tags
	}
	o, _, _, err := d.credOpWith(ctx, "item.put", extra, func() map[string]any {
		p := map[string]any{"password": password, "item": c.body()}
		if id != "" {
			p["item_id"] = id
		}
		return p
	}, false)
	if err != nil {
		return "", 0, err
	}
	return idVersion(o)
}

// ItemGet returns an item: a data item with its values, a secret or
// critical item without them.
func (d *Device) ItemGet(ctx context.Context, id string) (strictjson.Object, error) {
	return d.Op(ctx, "item.get", map[string]any{"item_id": id})
}

// ItemReveal returns a secret (or data) item with its values; fields (nil:
// all) narrows it.
func (d *Device) ItemReveal(ctx context.Context, id string, fields []string) (strictjson.Object, error) {
	body := map[string]any{"item_id": id}
	if fields != nil {
		body["fields"] = fields
	}
	return d.Op(ctx, "item.reveal", body)
}

// ItemRevealCritical opens the credential and returns a critical item's
// values, {"fields":[{field_id,value}],"notes"?}, which the vault sealed
// to a one-time reply key (§3.5.4).
func (d *Device) ItemRevealCritical(ctx context.Context, password, id string) (json.RawMessage, error) {
	o, rk, rid, err := d.credOpWith(ctx, "item.reveal", map[string]any{"item_id": id}, func() map[string]any {
		return map[string]any{"password": password, "item_id": id}
	}, true)
	if err != nil {
		return nil, err
	}
	defer rk.Destroy()
	sv, err := o.Base64("values_sealed", -1)
	if err != nil {
		return nil, ErrProtocol
	}
	return credwire.OpenValue(rk, d.VaultID(), rid, sv)
}

// ItemList lists items (metadata only) with an item.list filter (tags,
// match, category, sensitivity, after, limit).
func (d *Device) ItemList(ctx context.Context, filter map[string]any) (strictjson.Object, error) {
	return d.Op(ctx, "item.list", filter)
}

// ItemTag replaces an item's tags and returns its new version.
func (d *Device) ItemTag(ctx context.Context, id string, version uint64, tags []string) (uint64, error) {
	if tags == nil {
		tags = []string{}
	}
	o, err := d.Op(ctx, "item.tag", map[string]any{"item_id": id, "version": version, "tags": tags})
	if err != nil {
		return 0, err
	}
	return o.Uint("version", 1, strictjson.MaxSafeInteger)
}

// ItemSensitivity changes an item's sensitivity and returns its new
// version. A move to or from critical needs the password (a credential
// operation); apps warn the member before an item leaves critical.
func (d *Device) ItemSensitivity(ctx context.Context, id string, version uint64, sensitivity, password string) (uint64, error) {
	body := map[string]any{"item_id": id, "version": version, "sensitivity": sensitivity}
	var o strictjson.Object
	var err error
	if password == "" {
		o, err = d.Op(ctx, "item.sensitivity", body)
	} else {
		o, _, _, err = d.credOpWith(ctx, "item.sensitivity", body, func() map[string]any {
			return map[string]any{"password": password, "item_id": id}
		}, false)
	}
	if err != nil {
		return 0, err
	}
	return o.Uint("version", 1, strictjson.MaxSafeInteger)
}

// ItemDelete deletes an item; a critical item needs the password.
func (d *Device) ItemDelete(ctx context.Context, id, password string) error {
	if password == "" {
		_, err := d.Op(ctx, "item.delete", map[string]any{"item_id": id})
		return err
	}
	_, _, _, err := d.credOpWith(ctx, "item.delete", map[string]any{"item_id": id}, func() map[string]any {
		return map[string]any{"password": password, "item_id": id}
	}, false)
	return err
}

// TagList returns the tag registry and the tags in use.
func (d *Device) TagList(ctx context.Context) (strictjson.Object, error) {
	return d.Op(ctx, "tag.list", nil)
}

// TagOp sends tag.set, tag.delete or tag.merge with body (which names the
// registry version) and returns the response.
func (d *Device) TagOp(ctx context.Context, typ string, body map[string]any) (strictjson.Object, error) {
	return d.Op(ctx, typ, body)
}

// ShareRuleSet creates or replaces a share rule (body as §10.12) and
// returns the rule, or with dry_run the items it would match.
func (d *Device) ShareRuleSet(ctx context.Context, body map[string]any) (strictjson.Object, error) {
	return d.Op(ctx, "share.rule.set", body)
}

// ShareRuleList lists the share rules (filter: connection_id or agent_id).
func (d *Device) ShareRuleList(ctx context.Context, filter map[string]any) (strictjson.Object, error) {
	return d.Op(ctx, "share.rule.list", filter)
}

// ShareRuleDelete deletes a share rule.
func (d *Device) ShareRuleDelete(ctx context.Context, ruleID string) error {
	_, err := d.Op(ctx, "share.rule.delete", map[string]any{"rule_id": ruleID})
	return err
}

// ShareDecide approves or declines pending items of a rule.
func (d *Device) ShareDecide(ctx context.Context, ruleID string, items []string, approve bool) (strictjson.Object, error) {
	return d.Op(ctx, "share.decide", map[string]any{"rule_id": ruleID, "items": items, "approve": approve})
}
