package items_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/vettid/vettid-vault/features/itemspec"
)

// VAULT-MESSAGING 0.21.1 (§15 item 29.7): errata to 0.21.0 from this
// implementation.

// §10.7 (0.21.1, points 1 and 2): a dry run follows the access rule of
// the call it previews but never needs step-up. A desktop may dry-run
// item.tag of a critical item (the real item.tag is allowed with
// step-up: not an app-only form); a dry run of item.put for a critical
// item is forbidden. item.put's dry run requires version with item_id.
func TestDryRunErrata(t *testing.T) {
	e := newEnv(t)
	e.createCredential()
	e.rule(map[string]any{"subject": conn("cA"), "tags": []string{"work"}})
	id := e.put("data", "Doc", nil)
	cid := e.putCritical("Key", nil, field{Label: "S", Kind: "password", Value: "x"})

	// item.tag of a critical item is not an app-only form, with or
	// without dry_run; its dry run is read-only (no step-up).
	tag := json.RawMessage(`{"item_id":"` + cid + `","version":1,"tags":["work"],"dry_run":true}`)
	if e.set.Items.AppOnly("item.tag", tag) || !e.set.Items.ReadOnly("item.tag", tag) {
		t.Fatal("a desktop's dry run of item.tag on a critical item is not answered at once")
	}
	realTag := json.RawMessage(`{"item_id":"` + cid + `","version":1,"tags":["work"]}`)
	if e.set.Items.AppOnly("item.tag", realTag) || e.set.Items.ReadOnly("item.tag", realTag) {
		t.Fatal("a desktop's item.tag on a critical item is not a step-up request")
	}
	d := e.dry("desktop", "item.tag", map[string]any{"item_id": cid, "version": 1, "tags": []string{"work"}})
	if len(d.Shares) != 1 || d.Shares[0].Usable == nil || !*d.Shares[0].Usable {
		t.Fatalf("desktop critical tag dry run: %+v", d)
	}
	// item.put's dry run of a critical item stays app-only.
	e.code(e.call("desktop", "item.put", js(map[string]any{"dry_run": true, "item_id": cid, "version": 1})), "forbidden")
	if !e.set.Items.AppOnly("item.put", json.RawMessage(`{"dry_run":true,"sensitivity":"critical"}`)) {
		t.Fatal("a critical put dry run from a desktop is not refused at once")
	}
	// version and item_id together, as in the real item.put.
	for _, body := range []string{
		`{"dry_run":true,"item_id":"` + id + `"}`,
		`{"dry_run":true,"version":1}`,
		`{"dry_run":true,"version":1,"tags":["work"]}`,
	} {
		e.code(e.call("app", "item.put", body), "bad_request")
	}
	e.dry("app", "item.put", map[string]any{"item_id": id, "version": 1})
}

// §10.7, §10.1 (0.21.1, point 3): more than 64 fields is bad_request for
// every sensitivity, never a limit.
func TestFieldCountEveryCritical(t *testing.T) {
	e := newEnv(t)
	e.createCredential()
	many := make([]field, itemspec.MaxFields+1)
	for i := range many {
		many[i] = field{Label: "L", Kind: "text", Value: ""}
	}
	for _, sens := range []string{"data", "secret"} {
		e.code(e.call("app", "item.put", js(map[string]any{"name": "x", "sensitivity": sens, "fields": many})), "bad_request")
	}
	e.code(e.sealed("app", "item.put", map[string]any{"sensitivity": "critical"},
		map[string]any{"password": pw, "item": map[string]any{"name": "x", "fields": many}}, true, false), "bad_request")
	e.putCritical("Max", nil, many[:itemspec.MaxFields]...)
}

// §10.7 (0.21.1, point 4): a move to critical checks the size of the
// item as it will be stored, with "sensitivity":"critical".
func TestMoveToCriticalSize(t *testing.T) {
	e := newEnv(t)
	e.createCredential()
	probe := e.put("data", "x", nil, field{Label: "L", Kind: "multiline", Value: ""})
	base := e.stored(probe).Size() // the data item with an empty value
	grow := len(`"critical"`) - len(`"data"`)
	for _, c := range []struct {
		dataSize int
		ok       bool
	}{
		{itemspec.MaxCritBytes - grow, true},      // exactly 12,288 as critical
		{itemspec.MaxCritBytes - grow + 1, false}, // within 12,288 as data, over as critical
	} {
		id := e.put("data", "x", nil, field{Label: "L", Kind: "multiline", Value: strings.Repeat("v", c.dataSize-base)})
		st := e.stored(id)
		if st.Size() != c.dataSize {
			t.Fatalf("data size %d, want %d", st.Size(), c.dataSize)
		}
		r := e.sealed("app", "item.sensitivity", map[string]any{"item_id": id, "version": 1, "sensitivity": "critical"},
			map[string]any{"password": pw, "item_id": id}, true, false)
		if c.ok {
			e.ok(r)
			continue
		}
		o := e.limit(r, "item_size")
		if size, _ := o.Uint("size", 0, 1<<53); int(size) != c.dataSize+grow {
			t.Fatalf("size %d, want %d (counted as critical)", size, c.dataSize+grow)
		}
		if e.stored(id).Sensitivity != itemspec.Data {
			t.Fatal("moved despite the limit")
		}
	}
}
