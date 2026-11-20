package leash

import (
	"encoding/json"

	"github.com/vettid/vettid-vault/vms/strictjson"
)

// The cached copies of answers that carry a secret value (§8.2 Exception:
// responses that carry secret values in the clear; owner decision a,
// #14595). A retransmission of the same request is answered from the
// response cache, before any session, suspension, grant or settings check,
// for 24 hours; so the copy kept there holds no value. It still tells the
// agent the request was handled; to get the value it asks again, as a new
// request (counted, decided and referred as usual).

// getCached is an item.get answer's cached copy: the item's id, name and
// category, and its fields without their values. Notes are left out: the
// item model keeps them with the values.
func getCached(answer []byte) json.RawMessage {
	o, err := strictjson.ParseObject(answer)
	if err != nil {
		return emptyObject // never the answer itself
	}
	b := strictjson.NewBuilder()
	for _, k := range []string{"item_id", "name", "category"} {
		if v, ok := o[k]; ok {
			b.Raw(k, v)
		}
	}
	if raw, ok := o["fields"]; ok {
		fields, err := strictjson.AsArray(raw)
		if err != nil {
			return emptyObject
		}
		// Each field's members as sent, in the answer's order, without
		// value: raw members, so nothing is re-encoded.
		arr := []byte{'['}
		for i, fr := range fields {
			f, err := strictjson.AsObject(fr)
			if err != nil {
				return emptyObject
			}
			if i > 0 {
				arr = append(arr, ',')
			}
			fb := strictjson.NewBuilder()
			for _, k := range []string{"field_id", "label", "kind"} {
				if v, ok := f[k]; ok {
					fb.Raw(k, v)
				}
			}
			arr = append(arr, fb.Bytes()...)
		}
		b.Raw("fields", append(arr, ']'))
	}
	return b.Bytes()
}

// runCached is an item.run answer's cached copy: {item_id, field_id}.
func runCached(item, field string) json.RawMessage {
	return strictjson.NewBuilder().String("item_id", item).String("field_id", field).Bytes()
}

var emptyObject = json.RawMessage(`{}`)
