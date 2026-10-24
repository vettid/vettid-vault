package parent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/credentials"
)

// fakeDDB records the DynamoDB requests and answers each from script.
type fakeDDB struct {
	mu   sync.Mutex
	reqs []map[string]any
	// script answers request n (from 1): "" ok, "cond" a failed condition,
	// "fail" another failure.
	script func(n int, target string) string
	item   string // the GetItem answer, DynamoDB JSON
}

func (f *fakeDDB) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	var body map[string]any
	_ = json.Unmarshal(b, &body)
	target := strings.TrimPrefix(r.Header.Get("X-Amz-Target"), "DynamoDB_20120810.")
	body["_target"] = target
	f.mu.Lock()
	f.reqs = append(f.reqs, body)
	n := len(f.reqs)
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/x-amz-json-1.0")
	ans := ""
	if f.script != nil {
		ans = f.script(n, target)
	}
	switch {
	case ans == "cond":
		w.WriteHeader(400)
		_, _ = w.Write([]byte(`{"__type":"com.amazonaws.dynamodb.v20120810#ConditionalCheckFailedException","message":"x"}`))
	case ans == "fail":
		w.WriteHeader(400)
		_, _ = w.Write([]byte(`{"__type":"com.amazon.coral.validate#ValidationException","message":"x"}`))
	case target == "GetItem":
		_, _ = w.Write([]byte(f.item))
	default:
		_, _ = w.Write([]byte(`{}`))
	}
}

func (f *fakeDDB) updates() []map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []map[string]any
	for _, r := range f.reqs {
		if r["_target"] == "UpdateItem" {
			out = append(out, r)
		}
	}
	return out
}

func newFakeAWS(t *testing.T, f *fakeDDB) *AWS {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	a, err := NewAWS(AWSConfig{Region: "us-east-1", Credentials: credentials.NewStaticCredentialsProvider("a", "b", ""), Endpoint: srv.URL,
		Bucket: "b", VaultsTable: "vaults", InstancesTable: "i", RequestsTable: "r"})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func expr(r map[string]any) string { s, _ := r["UpdateExpression"].(string); return s }

// (b) app_key and the removal of app_key_next are ONE UpdateItem: no
// failure between two writes can leave the row without the key.
func TestAppKeySingleUpdate(t *testing.T) {
	f := &fakeDDB{}
	a := newFakeAWS(t, f)
	ev := Lifecycle{Event: EventAppKey, VaultID: "v1", AppKey: []byte("k2"), AppKeySeq: 2}
	if err := a.AppKeys(context.Background(), ev, time.Now()); err != nil {
		t.Fatal(err)
	}
	u := f.updates()
	if len(u) != 1 {
		t.Fatalf("%d updates", len(u))
	}
	e := expr(u[0])
	if !strings.Contains(e, "SET #ak = :ak") || !strings.Contains(e, "REMOVE #akn") {
		t.Fatalf("expression %q", e)
	}
	// The condition keeps seq's rule and a next key above seq.
	c, _ := u[0]["ConditionExpression"].(string)
	if !strings.Contains(c, "#ak.#seq < :seq") || !strings.Contains(c, "#akn.#seq <= :seq") {
		t.Fatalf("condition %q", c)
	}
}

// A next key above this seq stays: the key alone, in its own single update.
func TestAppKeyFallbackKeepsHigherNext(t *testing.T) {
	f := &fakeDDB{script: func(n int, _ string) string {
		if n == 1 {
			return "cond"
		}
		return ""
	}}
	a := newFakeAWS(t, f)
	ev := Lifecycle{Event: EventAppKey, VaultID: "v1", AppKey: []byte("k2"), AppKeySeq: 2}
	if err := a.AppKeys(context.Background(), ev, time.Now()); err != nil {
		t.Fatal(err)
	}
	u := f.updates()
	if len(u) != 2 || strings.Contains(expr(u[1]), "REMOVE") || !strings.Contains(expr(u[1]), "SET #ak = :ak") {
		t.Fatalf("updates %v", u)
	}
}

// A failure of the app_key write leaves the row as it was (a single
// update), is reported as an AppKeyWriteError, and does not hold back the
// rest of the event.
func TestAppKeyFailureDoesNotHoldBackEvent(t *testing.T) {
	down := true
	f := &fakeDDB{script: func(n int, _ string) string {
		if n == 1 && down {
			return "fail"
		}
		return ""
	}}
	a := newFakeAWS(t, f)
	ev := Lifecycle{Event: "unlocked", VaultID: "v1", VaultVersion: "x", AppKey: []byte("k2"), AppKeySeq: 2}
	err := a.Lifecycle(context.Background(), ev, "me", time.Now())
	var ke *AppKeyWriteError
	if !errors.As(err, &ke) || ke.Rest != nil {
		t.Fatalf("err %v", err)
	}
	u := f.updates()
	if len(u) < 2 || !strings.Contains(expr(u[1]), "#st = :st") {
		t.Fatalf("the rest of the event was not written: %v", u)
	}
	// The retry writes the keys alone.
	f.mu.Lock()
	f.reqs, down = nil, false
	f.mu.Unlock()
	if err := a.AppKeys(context.Background(), ev, time.Now()); err != nil {
		t.Fatal(err)
	}
	if u := f.updates(); len(u) != 1 || strings.Contains(expr(u[0]), "#st") {
		t.Fatalf("retry wrote %v", u)
	}
}

// ConfirmAppKey: the row's app_key_next is written; the answer is ok only
// when the row names the key afterwards, and a refusal is ErrConflict.
func TestAWSConfirmAppKey(t *testing.T) {
	key := []byte("k2")
	kid := AppKeyID(key)
	named := func(attr string, seq string) string {
		return `{"Item":{"` + attr + `":{"M":{"kid":{"S":"` + kid + `"},"seq":{"N":"` + seq + `"}}}}}`
	}
	cases := []struct {
		name   string
		script func(int, string) string
		item   string
		want   error
	}{
		{"written", nil, named("app_key_next", "2"), nil},
		{"app_key already", func(n int, _ string) string { return map[bool]string{true: "cond"}[n == 1] }, named("app_key", "2"), nil},
		{"another key", func(n int, _ string) string { return map[bool]string{true: "cond"}[n == 1] }, `{"Item":{"app_key":{"M":{"kid":{"S":"other"},"seq":{"N":"2"}}}}}`, ErrConflict},
		{"no row", func(n int, _ string) string { return map[bool]string{true: "cond"}[n == 1] }, `{}`, ErrConflict},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := &fakeDDB{script: c.script, item: c.item}
			a := newFakeAWS(t, f)
			err := a.ConfirmAppKey(context.Background(), "v1", "next", key, 2, 5, time.Now())
			if !errors.Is(err, c.want) || (c.want == nil) != (err == nil) {
				t.Fatalf("err %v, want %v", err, c.want)
			}
		})
	}
	// A failing write is an error, not a conflict.
	f := &fakeDDB{script: func(int, string) string { return "fail" }}
	if err := newFakeAWS(t, f).ConfirmAppKey(context.Background(), "v1", "next", key, 2, 5, time.Now()); err == nil || errors.Is(err, ErrConflict) {
		t.Fatalf("err %v", err)
	}
}
