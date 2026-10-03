package secrets

import (
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/featuretest"
)

func call(f *Feature, h *featuretest.Host, kind, typ, body string) featuretest.Result {
	return featuretest.Call(f, h, time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC), kind, typ, body)
}

func TestAuthorization(t *testing.T) {
	f, h := New(), featuretest.NewHost()
	for _, typ := range []string{"secret.put", "secret.get", "secret.list", "secret.delete"} {
		for _, k := range []string{"agent", "connection:c1"} {
			if r := call(f, h, k, typ, `{}`); r.Code != "forbidden" {
				t.Fatalf("%s may send %s", k, typ)
			}
		}
	}
	if r := call(f, h, "desktop", "secret.list", `{}`); !r.OK() {
		t.Fatal("desktop may list")
	}
}

func TestPutGetListDelete(t *testing.T) {
	f, h := New(), featuretest.NewHost()
	r := call(f, h, "app", "secret.put", `{"name":"wifi","value":"hunter22","category":"network","description":"home"}`)
	if !r.OK() {
		t.Fatal(r.Code)
	}
	id, _ := r.Obj(t).String("secret_id")
	if v, _ := r.Obj(t).Uint("version", 1, 1); v != 1 {
		t.Fatal("version")
	}
	if ev := h.SentOfType("sync.event"); len(ev) != 1 || ev[0].To != "devices-except:dev-app" || !strings.Contains(string(ev[0].Body), id) ||
		strings.Contains(string(ev[0].Body), "hunter22") {
		t.Fatalf("sync.event: %+v", ev)
	}
	// Updates name the version (§8.4).
	if r := call(f, h, "desktop", "secret.put", `{"secret_id":"`+id+`","version":2,"name":"wifi","value":"x"}`); r.Code != "conflict" {
		t.Fatalf("stale version: %q", r.Code)
	}
	if r := call(f, h, "desktop", "secret.put", `{"secret_id":"`+id+`","name":"wifi","value":"x"}`); r.Code != "bad_request" {
		t.Fatalf("update without version: %q", r.Code)
	}
	if r := call(f, h, "desktop", "secret.put", `{"secret_id":"`+testID+`","version":1,"name":"wifi","value":"x"}`); r.Code != "not_found" {
		t.Fatalf("unknown id: %q", r.Code)
	}
	if r := call(f, h, "desktop", "secret.put", `{"secret_id":"`+id+`","version":1,"name":"wifi","value":"new value"}`); !r.OK() {
		t.Fatal(r.Code)
	}
	g := call(f, h, "app", "secret.get", `{"secret_id":"`+id+`"}`).Obj(t)
	if v, _ := g.String("value"); v != "new value" {
		t.Fatal("value")
	}
	if c, _ := g.String("category"); c != "other" {
		t.Fatalf("category not replaced with the default: %q", c)
	}
	l := call(f, h, "app", "secret.list", `{}`)
	if strings.Contains(string(l.Body), "new value") || !strings.Contains(string(l.Body), `"wifi"`) {
		t.Fatalf("list: %s", l.Body)
	}
	g2 := New()
	featuretest.RoundTrip(t, f, g2)
	if r := call(g2, h, "app", "secret.delete", `{"secret_id":"`+id+`"}`); !r.OK() {
		t.Fatal(r.Code)
	}
	if r := call(g2, h, "app", "secret.get", `{"secret_id":"`+id+`"}`); r.Code != "not_found" {
		t.Fatal("deleted secret readable")
	}
	if !h.HasActivity("secret.added") || !h.HasActivity("secret.deleted") {
		t.Fatal("not audited")
	}
}

func TestBadBodies(t *testing.T) {
	f, h := New(), featuretest.NewHost()
	for _, b := range []string{
		`{"value":"x"}`,
		`{"name":"","value":"x"}`,
		`{"name":"n","value":""}`,
		`{"name":"n","value":"` + strings.Repeat("v", MaxValue+1) + `"}`,
		`{"name":"n","value":"x","category":"Not Valid"}`,
		`{"name":"n","value":"x","discoverability":"public"}`,
		`{"name":"n","value":"x","version":1}`,
		`{"name":"n","name":"m","value":"x"}`,
		`[]`,
	} {
		if r := call(f, h, "app", "secret.put", b); r.Code != "bad_request" {
			t.Errorf("%s: %q", b, r.Code)
		}
	}
	if r := call(f, h, "app", "secret.get", `{"secret_id":"x"}`); r.Code != "bad_request" {
		t.Error("bad id")
	}
}

func TestLimit(t *testing.T) {
	f, h := New(), featuretest.NewHost()
	for i := 0; i < MaxSecrets; i++ {
		if r := call(f, h, "app", "secret.put", `{"name":"n","value":"v"}`); !r.OK() {
			t.Fatal(r.Code)
		}
	}
	if r := call(f, h, "app", "secret.put", `{"name":"n","value":"v"}`); r.Code != "limit" {
		t.Fatalf("over the limit: %q", r.Code)
	}
}

func FuzzParsePut(f *testing.F) {
	f.Add([]byte(`{"name":"n","value":"v","category":"other","discoverability":"cataloged"}`))
	f.Add([]byte(`{"secret_id":"` + testID + `","version":3,"name":"n","value":"v"}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := ParsePut(b)
		if err != nil {
			return
		}
		if p.Name == "" || len(p.Name) > MaxName || p.Value == "" || len(p.Value) > MaxValue || (p.SecretID == "") != (p.Version == 0) {
			t.Fatal("invalid put accepted")
		}
	})
}

// testID is a fixed ULID for tests.
const testID = "01JB2Z6V9K3M4N5P6Q7R8S9T0V"
