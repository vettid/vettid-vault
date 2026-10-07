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

// stripValues makes an item's DEK copy of a critical item: no values, no
// notes (HasNotes instead); its ciphertext replaces them.
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

// encrypt seals an item that holds its values under a fresh key of
// generation gen, puts the key into the plaintext (replacing the item's
// entry, or appending one) and turns the item into its DEK copy.
func encrypt(s *vault.Session, it *itemspec.Item, inner *credential.Inner, gen uint64) error {
	pt := valuesJSON(it)
	defer suite.Wipe(pt)
	e, sealed, err := seal(s.VaultID(), it, gen, pt)
	if err != nil {
		return errInternal
	}
	if i := inner.FindItem(it.ID); i >= 0 {
		inner.Items[i].Wipe()
		inner.Items[i] = e
	} else {
		if len(inner.Items) >= credential.MaxItems {
			e.Wipe()
			return errLimit
		}
		inner.Items = append(inner.Items, e)
	}
	stripValues(it)
	it.Sealed, it.Gen = sealed, gen
	return nil
}

// putCritical creates or replaces a critical item: the content is in the
// sealed payload, item_id too when replacing (§10.7). The values are
// encrypted under a fresh item key, which goes into the credential.
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
		if f.guarded(p.ItemID) {
			return errInUse // a wallet's content changes only through the wallet (§10.18)
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
		gen := uint64(1)
		if p.ItemID == "" {
			if len(f.st.Items) >= itemspec.MaxItems || f.criticalCount() >= itemspec.MaxCritItems {
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
			i := inner.FindItem(cur.ID)
			if i < 0 {
				return errNotFound
			}
			gen = inner.Items[i].Gen + 1
			it = cur.Clone()
			it.Sealed = nil
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
		if err := encrypt(s, it, inner, gen); err != nil {
			return err
		}
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

func (f *Feature) criticalCount() int {
	n := 0
	for _, it := range f.st.Items {
		if it.Sensitivity == itemspec.Critical {
			n++
		}
	}
	return n
}

// revealCritical opens the credential, decrypts the item's values with its
// key and returns them sealed to the request's reply key (§3.5.4, §10.7);
// the item is then re-encrypted under a fresh key.
func (f *Feature) revealCritical(s *vault.Session, in *envelope.Inner, o strictjson.Object, it *itemspec.Item) (json.RawMessage, error) {
	if err := appOnly(s); err != nil {
		return nil, err
	}
	if o.Has("fields") {
		return nil, errBad
	}
	var replySealed, newSealed []byte
	var gen uint64
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
		pt, err := open(s.VaultID(), it, &inner.Items[i])
		if err != nil {
			return errInternal
		}
		defer suite.Wipe(pt)
		if replySealed, err = credwire.SealValue(p.Reply, s.VaultID(), in.ID, pt); err != nil {
			return errInternal
		}
		if newSealed, gen, err = rekey(s.VaultID(), it, inner, i); err != nil {
			return errInternal
		}
		return nil
	}
	res, err := f.operate(s, in, credential.NeedItemID|credential.NeedReply, check, op)
	if err != nil {
		return nil, err
	}
	it.Sealed, it.Gen = newSealed, gen // the item key rotated with the use
	s.Record(vault.Activity{Kind: "item.revealed", Ref: it.ID, Audit: true, Feed: true})
	b := strictjson.NewBuilder().String("item_id", it.ID).Uint("version", it.Version).Base64("values_sealed", replySealed)
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

// sensitivityCritical moves an item into or out of the credential's
// protection: the vault encrypts or decrypts the values itself, so they
// never cross the session (§10.7).
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
		if f.criticalCount() >= itemspec.MaxCritItems {
			return nil, errLimit
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
			if i >= 0 {
				return errLimit
			}
			if err := encrypt(s, it, inner, 1); err != nil {
				return err
			}
		} else {
			if i < 0 {
				return errNotFound
			}
			pt, err := open(s.VaultID(), cur, &inner.Items[i])
			if err != nil {
				return errInternal
			}
			v, err := ParseValues(pt)
			suite.Wipe(pt)
			if err != nil {
				return errInternal
			}
			for k := range it.Fields {
				it.Fields[k].Value = v.Fields[it.Fields[k].ID]
				if it.Fields[k].Value == nil {
					it.Fields[k].Value = json.RawMessage(`""`)
					if it.Fields[k].Kind == itemspec.KindAddress {
						it.Fields[k].Value = json.RawMessage(`{}`)
					}
				}
			}
			it.Notes, it.HasNotes, it.Sealed, it.Gen = v.Notes, false, nil, 0
			inner.Items[i].Wipe()
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

// RekeyCriticalItems implements credential.ItemRekeyer: at
// credential.rotate and credential.recover every critical item is
// re-encrypted under a fresh key (§10.7). The new ciphertexts are
// installed by commit, after the credential is sealed.
func (f *Feature) RekeyCriticalItems(s *vault.Session, inner *credential.Inner) (func(), error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	type next struct {
		sealed []byte
		gen    uint64
	}
	staged := map[string]next{}
	for i := range inner.Items {
		it := f.st.Items[inner.Items[i].ID]
		if it == nil || it.Sensitivity != itemspec.Critical {
			continue
		}
		sealed, gen, err := rekey(s.VaultID(), it, inner, i)
		if err != nil {
			return nil, errInternal
		}
		staged[it.ID] = next{sealed, gen}
	}
	return func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		for id, n := range staged {
			if it := f.st.Items[id]; it != nil {
				it.Sealed, it.Gen = n.sealed, n.gen
			}
		}
	}, nil
}

// UseCriticalField returns a critical item's field value (its canonical
// JSON) for one use within a credential operation (§10.13) and re-keys
// the item; commit installs the new ciphertext once the credential is
// sealed. The caller wipes the value.
func (f *Feature) UseCriticalField(s *vault.Session, inner *credential.Inner, itemID, fieldID string) ([]byte, func(), error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	it := f.st.Items[itemID]
	i := inner.FindItem(itemID)
	if it == nil || it.Sensitivity != itemspec.Critical || i < 0 {
		return nil, nil, errNotFound
	}
	pt, err := open(s.VaultID(), it, &inner.Items[i])
	if err != nil {
		return nil, nil, errInternal
	}
	v, err := ParseValues(pt)
	suite.Wipe(pt)
	if err != nil {
		return nil, nil, errInternal
	}
	raw := v.Fields[fieldID]
	for id, other := range v.Fields {
		if id != fieldID {
			suite.Wipe(other)
		}
	}
	if raw == nil {
		return nil, nil, errNotFound
	}
	sealed, gen, err := rekey(s.VaultID(), it, inner, i)
	if err != nil {
		suite.Wipe(raw)
		return nil, nil, errInternal
	}
	return raw, func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		if cur := f.st.Items[itemID]; cur != nil {
			cur.Sealed, cur.Gen = sealed, gen
		}
	}, nil
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

// ItemGuard is a feature that owns some critical items (the wallet,
// §10.18): their content and sensitivity change only through it, so
// item.put and item.sensitivity of such an item are refused with in_use.
// Tags, reveal and delete stay with the member. ItemInUse is called with
// this feature's lock held and must not call back into it.
type ItemGuard interface {
	ItemInUse(itemID string) bool
}

// SetGuard connects the wallet feature (at construction).
func (f *Feature) SetGuard(g ItemGuard) { f.guard = g }

func (f *Feature) guarded(id string) bool { return id != "" && f.guard != nil && f.guard.ItemInUse(id) }

// NewField is a field of an item another feature creates.
type NewField struct {
	Label, Kind string
	Value       string
}

// NewCriticalItem creates a critical item inside another feature's
// credential operation (op of credential.Operate): its values are
// encrypted under a fresh item key that goes into the plaintext. It
// returns the item id and its field ids; commit applies the change (share
// rules, notices, audit) once the credential is sealed, abort undoes it.
func (f *Feature) NewCriticalItem(s *vault.Session, inner *credential.Inner, name, category, template string, tags []string,
	fields []NewField) (id string, fieldIDs []string, commit, abort func(), err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.st.Items) >= itemspec.MaxItems || f.criticalCount() >= itemspec.MaxCritItems {
		return "", nil, nil, nil, errLimit
	}
	arr := []byte{'['}
	for i, fl := range fields {
		if i > 0 {
			arr = append(arr, ',')
		}
		arr = append(arr, strictjson.NewBuilder().String("label", fl.Label).String("kind", fl.Kind).String("value", fl.Value).Bytes()...)
	}
	body := strictjson.NewBuilder().String("name", name).String("category", category).String("template", template).
		Raw("fields", append(arr, ']')).Bytes()
	defer suite.Wipe(body)
	defer suite.Wipe(arr)
	o, perr := strictjson.ParseObject(body)
	if perr != nil {
		return "", nil, nil, nil, errBad
	}
	c, perr := itemspec.ParseContent(o)
	if perr != nil {
		return "", nil, nil, nil, errBad
	}
	t := now(s)
	it := &itemspec.Item{ID: s.NewID(), Sensitivity: itemspec.Critical, Created: t, NextField: 1}
	if !c.Apply(it, nil) {
		return "", nil, nil, nil, errBad
	}
	it.Tags, it.Version, it.Updated = tags, 1, t
	if err := checkProfileTag(it); err != nil {
		return "", nil, nil, nil, err
	}
	if err := checkCritSize(it); err != nil {
		return "", nil, nil, nil, err
	}
	if err := encrypt(s, it, inner, 1); err != nil {
		return "", nil, nil, nil, err
	}
	ch, err := f.prepare(s, nil, it, nil)
	if err != nil {
		if i := inner.FindItem(it.ID); i >= 0 {
			inner.Items[i].Wipe()
			inner.Items = append(inner.Items[:i:i], inner.Items[i+1:]...)
		}
		return "", nil, nil, nil, err
	}
	for _, fl := range it.Fields {
		fieldIDs = append(fieldIDs, fl.ID)
	}
	commit = func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.finish(s, ch, "item.added")
	}
	abort = func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		ch.undo()
	}
	return it.ID, fieldIDs, commit, abort, nil
}

// UseCriticalValues returns every field value of a critical item (field
// id → canonical JSON) for one use within a credential operation and
// re-keys the item, as UseCriticalField does. The caller wipes the values.
func (f *Feature) UseCriticalValues(s *vault.Session, inner *credential.Inner, itemID string) (map[string]json.RawMessage, func(), error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	it := f.st.Items[itemID]
	i := inner.FindItem(itemID)
	if it == nil || it.Sensitivity != itemspec.Critical || i < 0 {
		return nil, nil, errNotFound
	}
	pt, err := open(s.VaultID(), it, &inner.Items[i])
	if err != nil {
		return nil, nil, errInternal
	}
	v, err := ParseValues(pt)
	suite.Wipe(pt)
	if err != nil {
		return nil, nil, errInternal
	}
	sealed, gen, err := rekey(s.VaultID(), it, inner, i)
	if err != nil {
		for _, x := range v.Fields {
			suite.Wipe(x)
		}
		return nil, nil, errInternal
	}
	return v.Fields, func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		if cur := f.st.Items[itemID]; cur != nil {
			cur.Sealed, cur.Gen = sealed, gen
		}
	}, nil
}

// CriticalExists reports whether a critical item exists (the wallet
// notices item.delete and credential.reset of its items, §10.18).
func (f *Feature) CriticalExists(itemID string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	it := f.st.Items[itemID]
	return it != nil && it.Sensitivity == itemspec.Critical
}

// ItemName returns an item's current name (§10.7), whatever its
// sensitivity (a critical item's name is DEK-state metadata here), for the
// audit search (§10.9, 0.20.0); ok is false for an item that does not
// exist (deleted). It calls nothing outside this feature.
func (f *Feature) ItemName(itemID string) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	it := f.st.Items[itemID]
	if it == nil {
		return "", false
	}
	return it.Name, true
}
