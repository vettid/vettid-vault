package items

import (
	"encoding/json"

	"github.com/vettid/vettid-vault/features/credential"
	"github.com/vettid/vettid-vault/features/itemspec"
	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/credwire"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Critical items (§10.7): their values live inside the Protean
// Credential; every read or change of them is a credential operation
// (§3.5.3) from an app, with the content in the UTK-sealed payload and
// values returned sealed to a one-time reply key. Their metadata is here.

func appOnly(s *vault.Session) error {
	if s.From().Kind != vault.KindApp || s.From().Recovering {
		return errForbidden
	}
	return nil
}

func (f *Feature) operate(s *vault.Session, in *envelope.Inner, need int, check func(*credential.Payload) error,
	op func(*credential.Inner, *credential.Payload) error) (*credential.OpResult, error) {
	if f.cred == nil {
		return nil, vault.NewError("credential_required", "")
	}
	return f.cred.Operate(s, in, need, check, op)
}

// critValues builds the credential's copy of an item's values.
func critValues(it *itemspec.Item, notes string) credential.Item {
	ci := credential.Item{ID: it.ID}
	for _, fl := range it.Fields {
		ci.Values = append(ci.Values, credential.Value{FieldID: fl.ID, Raw: append([]byte(nil), fl.Value...)})
	}
	if notes != "" {
		ci.Notes = strictjson.MarshalString(notes)
	}
	return ci
}

// stripValues makes an item's DEK copy of a critical item: no values, no
// notes (HasNotes instead).
func stripValues(it *itemspec.Item) {
	for i := range it.Fields {
		suite.Wipe(it.Fields[i].Value)
		it.Fields[i].Value = nil
	}
	it.HasNotes = it.Notes != ""
	it.Notes = ""
}

func checkCritSize(it *itemspec.Item) error {
	if len(it.Fields) > itemspec.MaxCritFields || it.Size() > itemspec.MaxCritBytes {
		return errLimit
	}
	return nil
}

// putCritical creates or replaces a critical item: the content is in the
// sealed payload, item_id too when replacing (§10.7).
func (f *Feature) putCritical(s *vault.Session, in *envelope.Inner, o strictjson.Object) (json.RawMessage, error) {
	if err := appOnly(s); err != nil {
		return nil, err
	}
	if o.Has("item_id") || o.Has("name") || o.Has("fields") || o.Has("notes") {
		return nil, errBad // the content and the item travel sealed
	}
	ver, hasVer, err := o.OptUint("version", 1, strictjson.MaxSafeInteger)
	if err != nil {
		return nil, errBad
	}
	tags, hasTags, err := optTags(o)
	if err != nil {
		return nil, err
	}
	t := now(s)
	var cur, it *itemspec.Item
	var ch *change
	check := func(p *credential.Payload) error {
		if (p.ItemID != "") != hasVer {
			return errBad
		}
		return nil
	}
	op := func(inner *credential.Inner, p *credential.Payload) error {
		po, err := strictjson.ParseObject(p.Item)
		if err != nil {
			return errBad
		}
		c, err := itemspec.ParseContent(po)
		if err != nil {
			return errBad
		}
		if p.ItemID == "" {
			if len(f.st.Items) >= itemspec.MaxItems || len(inner.Items) >= credential.MaxItems {
				return errLimit
			}
			it = &itemspec.Item{ID: s.NewID(), Sensitivity: itemspec.Critical, Created: t, NextField: 1}
		} else {
			cur = f.st.Items[p.ItemID]
			if cur == nil || cur.Sensitivity != itemspec.Critical {
				return errNotFound
			}
			if cur.Version != ver {
				return errConflict
			}
			it = cur.Clone()
		}
		if !c.Apply(it, cur) {
			return errBad
		}
		if hasTags {
			it.Tags = tags
		}
		it.Version++
		it.Updated = t
		if err := checkProfileTag(it); err != nil {
			return err
		}
		if err := checkCritSize(it); err != nil {
			return err
		}
		ci := critValues(it, it.Notes)
		if i := inner.FindItem(it.ID); i >= 0 {
			inner.Items[i].Wipe()
			inner.Items[i] = ci
		} else {
			inner.Items = append(inner.Items, ci)
		}
		stripValues(it)
		var err2 error
		if ch, err2 = f.prepare(s, cur, it, nil); err2 != nil {
			return err2
		}
		return nil
	}
	res, err := f.operate(s, in, credential.NeedOptItemID|credential.NeedItem, check, op)
	if err != nil {
		if ch != nil {
			ch.undo() // the credential did not change (e.g. limit when sealing)
		}
		return nil, err
	}
	kind := "item.updated"
	if cur == nil {
		kind = "item.added"
	}
	f.finish(s, ch, kind)
	b := strictjson.NewBuilder().String("item_id", it.ID).Uint("version", it.Version).String("updated_at", envelope.FormatTS(t))
	res.Members(b)
	return b.Bytes(), nil
}

// revealCritical opens the credential and returns the item's values
// sealed to the request's reply key (§3.5.4, §10.7).
func (f *Feature) revealCritical(s *vault.Session, in *envelope.Inner, o strictjson.Object, it *itemspec.Item) (json.RawMessage, error) {
	if err := appOnly(s); err != nil {
		return nil, err
	}
	if o.Has("fields") {
		return nil, errBad
	}
	var sealed []byte
	check := func(p *credential.Payload) error {
		if p.ItemID != it.ID {
			return errBad // consent bound to this item
		}
		return nil
	}
	op := func(inner *credential.Inner, p *credential.Payload) error {
		i := inner.FindItem(it.ID)
		if i < 0 {
			return errNotFound
		}
		pt := inner.Items[i].ValuesJSON()
		defer suite.Wipe(pt)
		var err error
		if sealed, err = credwire.SealValue(p.Reply, s.VaultID(), in.ID, pt); err != nil {
			return errInternal
		}
		return nil
	}
	res, err := f.operate(s, in, credential.NeedItemID|credential.NeedReply, check, op)
	if err != nil {
		return nil, err
	}
	s.Record(vault.Activity{Kind: "item.revealed", Ref: it.ID, Audit: true, Feed: true})
	b := strictjson.NewBuilder().String("item_id", it.ID).Uint("version", it.Version).Base64("values_sealed", sealed)
	res.Members(b)
	return b.Bytes(), nil
}

func (f *Feature) deleteCritical(s *vault.Session, in *envelope.Inner, cur *itemspec.Item) (json.RawMessage, error) {
	if err := appOnly(s); err != nil {
		return nil, err
	}
	var ch *change
	check := func(p *credential.Payload) error {
		if p.ItemID != cur.ID {
			return errBad
		}
		return nil
	}
	op := func(inner *credential.Inner, _ *credential.Payload) error {
		if i := inner.FindItem(cur.ID); i >= 0 {
			inner.Items[i].Wipe()
			inner.Items = append(inner.Items[:i:i], inner.Items[i+1:]...)
		}
		var err error
		ch, err = f.prepare(s, cur, nil, nil)
		return err
	}
	res, err := f.operate(s, in, credential.NeedItemID, check, op)
	if err != nil {
		if ch != nil {
			ch.undo()
		}
		return nil, err
	}
	f.finish(s, ch, "item.deleted")
	b := strictjson.NewBuilder()
	res.Members(b)
	return b.Bytes(), nil
}

// sensitivityCritical moves an item into or out of the credential: the
// vault moves the values itself, so they never cross the session (§10.7).
func (f *Feature) sensitivityCritical(s *vault.Session, in *envelope.Inner, cur *itemspec.Item, sens string) (json.RawMessage, error) {
	if err := appOnly(s); err != nil {
		return nil, err
	}
	it := cur.Clone()
	it.Sensitivity, it.Version, it.Updated = sens, it.Version+1, now(s)
	if sens == itemspec.Critical {
		if err := checkCritSize(cur); err != nil {
			return nil, err
		}
	}
	var ch *change
	check := func(p *credential.Payload) error {
		if p.ItemID != cur.ID {
			return errBad
		}
		return nil
	}
	op := func(inner *credential.Inner, _ *credential.Payload) error {
		i := inner.FindItem(cur.ID)
		if sens == itemspec.Critical {
			if i >= 0 || len(inner.Items) >= credential.MaxItems {
				return errLimit
			}
			inner.Items = append(inner.Items, critValues(cur, cur.Notes))
			stripValues(it)
		} else {
			if i < 0 {
				return errNotFound
			}
			ci := &inner.Items[i]
			for k := range it.Fields {
				for _, v := range ci.Values {
					if v.FieldID == it.Fields[k].ID {
						it.Fields[k].Value = append(json.RawMessage(nil), v.Raw...)
					}
				}
				if it.Fields[k].Value == nil {
					it.Fields[k].Value = json.RawMessage(`""`)
					if it.Fields[k].Kind == itemspec.KindAddress {
						it.Fields[k].Value = json.RawMessage(`{}`)
					}
				}
			}
			if ci.Notes != nil {
				n, err := strictjson.AsString(ci.Notes)
				if err != nil {
					return errInternal
				}
				it.Notes = n
			}
			it.HasNotes = false
			ci.Wipe()
			inner.Items = append(inner.Items[:i:i], inner.Items[i+1:]...)
		}
		var err error
		ch, err = f.prepare(s, cur, it, nil)
		return err
	}
	res, err := f.operate(s, in, credential.NeedItemID, check, op)
	if err != nil {
		if ch != nil {
			ch.undo()
		}
		return nil, err
	}
	f.finish(s, ch, "item.sensitivity_changed")
	b := strictjson.NewBuilder().Uint("version", it.Version)
	res.Members(b)
	return b.Bytes(), nil
}

// AppOnly implements vault.AppOnlyForms: the forms of the step-up types
// that only an app may send (§10.7, §10.12) are refused for a desktop at
// once rather than held for an app's approval they could not pass.
func (f *Feature) AppOnly(typ string, body json.RawMessage) bool {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return false
	}
	if o.Has("credential") || o.Has("sealed") || o.Has("utk_id") {
		return true
	}
	switch typ {
	case "item.put", "item.sensitivity":
		if s, _, _ := o.OptString("sensitivity"); s == itemspec.Critical {
			return true
		}
	case "share.rule.set":
		if so, err := o.Object("subject"); err == nil && so.Has("agent_id") {
			return true
		}
	}
	switch typ {
	case "item.reveal", "item.delete", "item.sensitivity":
		id, _, _ := o.OptString("item_id")
		f.mu.Lock()
		defer f.mu.Unlock()
		if it := f.st.Items[id]; it != nil && it.Sensitivity == itemspec.Critical {
			return true
		}
	}
	return false
}
