package items

import (
	"encoding/binary"
	"encoding/json"
	"errors"

	"github.com/vettid/vettid-vault/features/credential"
	"github.com/vettid/vettid-vault/features/itemspec"
	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Envelope encryption of critical items (§3.5.2, §10.7): an item's values
// and notes are encrypted under a random 32-byte item key with
// XChaCha20-Poly1305; the ciphertext is kept with the item's metadata in
// DEK state, the key (and its generation) only inside the Protean
// Credential. Without the credential and the password the vault cannot
// decrypt them.
//
//	sealed = nonce (24) || XChaCha20-Poly1305(item key, nonce, aad, values)
//	aad    = "vettid/vms/2/critical-item" || 0x00 || vault_id || 0x00 || item_id
//	         || 0x00 || uint64be(gen) || (0x00 || field_id)*
//	values = {"fields":[{"field_id","value"}],"notes"?}
//
// The AAD binds the ciphertext to the vault, the item, the key's
// generation and the item's field ids in order. Every use of an item
// re-encrypts it under a fresh key (gen + 1).

const labelItem = "vettid/vms/2/critical-item"

var errSealed = errors.New("items: critical values do not open")

func itemAAD(vaultID string, it *itemspec.Item, gen uint64) []byte {
	b := append([]byte(labelItem), 0)
	b = append(append(b, vaultID...), 0)
	b = append(b, it.ID...)
	b = append(b, 0)
	b = binary.BigEndian.AppendUint64(b, gen)
	for _, f := range it.Fields {
		b = append(append(b, 0), f.ID...)
	}
	return b
}

// valuesJSON is the values plaintext of an item that holds its values.
// The caller wipes it.
func valuesJSON(it *itemspec.Item) []byte {
	arr := []byte{'['}
	for i, f := range it.Fields {
		if i > 0 {
			arr = append(arr, ',')
		}
		v := f.Value
		if v == nil {
			v = json.RawMessage(`""`)
		}
		arr = append(arr, strictjson.NewBuilder().String("field_id", f.ID).Raw("value", v).Bytes()...)
	}
	b := strictjson.NewBuilder().Raw("fields", append(arr, ']'))
	if it.Notes != "" {
		b.String("notes", it.Notes)
	}
	return b.Bytes()
}

// Values is a parsed values plaintext.
type Values struct {
	Fields map[string]json.RawMessage
	Notes  string
}

// ParseValues parses a values plaintext strictly.
func ParseValues(pt []byte) (*Values, error) {
	o, err := strictjson.ParseObject(pt)
	if err != nil {
		return nil, errSealed
	}
	arr, err := o.Array("fields")
	if err != nil || len(arr) > itemspec.MaxFields {
		return nil, errSealed
	}
	v := &Values{Fields: map[string]json.RawMessage{}}
	for _, raw := range arr {
		fo, err := strictjson.AsObject(raw)
		if err != nil {
			return nil, errSealed
		}
		id, err := fo.String("field_id")
		if err != nil || !itemspec.ValidFieldID(id) || v.Fields[id] != nil {
			return nil, errSealed
		}
		val, ok := fo["value"]
		if !ok || len(val) == 0 || val[0] != '"' && val[0] != '{' {
			return nil, errSealed
		}
		v.Fields[id] = append(json.RawMessage(nil), val...)
	}
	if n, present, err := o.OptString("notes"); err != nil || !itemspec.ValidNotes(n) {
		return nil, errSealed
	} else if present {
		v.Notes = n
	}
	return v, nil
}

// seal encrypts pt under a fresh key as generation gen of it and returns
// the credential entry and the ciphertext.
func seal(vaultID string, it *itemspec.Item, gen uint64, pt []byte) (credential.Item, []byte, error) {
	key, err := suite.RandomBytes(credential.ItemKeySize)
	if err != nil {
		return credential.Item{}, nil, err
	}
	nonce, err := suite.NewNonce()
	if err != nil {
		suite.Wipe(key)
		return credential.Item{}, nil, err
	}
	ct, err := suite.SealX(key, nonce, itemAAD(vaultID, it, gen), pt)
	if err != nil {
		suite.Wipe(key)
		return credential.Item{}, nil, err
	}
	return credential.Item{ID: it.ID, Gen: gen, Key: key}, append(nonce, ct...), nil
}

// open decrypts a critical item's ciphertext with its credential entry.
// The caller wipes the result.
func open(vaultID string, it *itemspec.Item, e *credential.Item) ([]byte, error) {
	if e.Gen != it.Gen || len(it.Sealed) < suite.XNonceSize+16 {
		return nil, errSealed
	}
	pt, err := suite.OpenX(e.Key, it.Sealed[:suite.XNonceSize], itemAAD(vaultID, it, e.Gen), it.Sealed[suite.XNonceSize:])
	if err != nil {
		return nil, errSealed
	}
	return pt, nil
}

// rekey re-encrypts an item's values under a fresh key (gen + 1),
// replacing its entry in the plaintext; it returns the new ciphertext and
// generation for the caller to install once the credential is sealed, and
// the item's size without its tags (0.21.0, §10.7: recorded whenever its
// values open; 0 if the plaintext does not parse).
func rekey(vaultID string, it *itemspec.Item, inner *credential.Inner, i int) ([]byte, uint64, int, error) {
	pt, err := open(vaultID, it, &inner.Items[i])
	if err != nil {
		return nil, 0, 0, err
	}
	defer suite.Wipe(pt)
	e, sealed, err := seal(vaultID, it, inner.Items[i].Gen+1, pt)
	if err != nil {
		return nil, 0, 0, err
	}
	inner.Items[i].Wipe()
	inner.Items[i] = e
	return sealed, e.Gen, sizeNoTags(it, pt), nil
}

// sizeNoTags is the size without its tags of a critical item whose
// values plaintext is pt (0 if it does not parse).
func sizeNoTags(it *itemspec.Item, pt []byte) int {
	v, err := ParseValues(pt)
	if err != nil {
		return 0
	}
	defer wipeValues(v)
	full := withValues(it, v)
	full.RecordSize()
	return full.SizeNoTags
}
