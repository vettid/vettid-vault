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
	// condItem is the Item of a failed condition (ReturnValuesOnConditionCheckFailure).
	condItem string
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
	if target == "UpdateItem" && unusedPlaceholder(body) {
		ans = "fail" // DynamoDB: ValidationException for an unused name or value
	}
	if f.script != nil {
		ans = f.script(n, target)
	}
	switch {
	case ans == "cond":
		w.WriteHeader(400)
		item := ""
		if f.condItem != "" {
			item = `,"Item":` + f.condItem
		}
		_, _ = w.Write([]byte(`{"__type":"com.amazonaws.dynamodb.v20120810#ConditionalCheckFailedException","message":"x"` + item + `}`))
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
	}, condItem: `{"app_key":{"M":{"seq":{"N":"1"}}},"app_key_next":{"M":{"seq":{"N":"3"}}}}`}
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
			err := a.ConfirmAppKey(context.Background(), "v1", "next", key, 2, 5, att(), time.Now())
			if !errors.Is(err, c.want) || (c.want == nil) != (err == nil) {
				t.Fatalf("err %v, want %v", err, c.want)
			}
		})
	}
	// A failing write is an error, not a conflict.
	f := &fakeDDB{script: func(int, string) string { return "fail" }}
	if err := newFakeAWS(t, f).ConfirmAppKey(context.Background(), "v1", "next", key, 2, 5, att(), time.Now()); err == nil || errors.Is(err, ErrConflict) {
		t.Fatalf("err %v", err)
	}
}

// A stale report (the row's app_key is at that seq or higher) or a missing
// row costs one write, not two.
func TestAppKeyStaleReportOneWrite(t *testing.T) {
	for name, item := range map[string]string{
		"stale":   `{"app_key":{"M":{"seq":{"N":"2"}}},"app_key_next":{"M":{"seq":{"N":"3"}}}}`,
		"no row":  "",
		"no next": `{"app_key":{"M":{"seq":{"N":"1"}}}}`,
	} {
		f := &fakeDDB{script: func(int, string) string { return "cond" }, condItem: item}
		a := newFakeAWS(t, f)
		ev := Lifecycle{Event: EventAppKeyAssert, VaultID: "v1", AppKey: []byte("k2"), AppKeySeq: 2}
		if err := a.AppKeys(context.Background(), ev, time.Now()); err != nil || len(f.updates()) != 1 {
			t.Fatalf("%s: %v, %d updates", name, err, len(f.updates()))
		}
	}
}

// Every app_key_next write is ordered by header_seq, a clear is bounded by
// it, and the enrolled event is conditional.
func TestAppKeyConditionsOrdered(t *testing.T) {
	f := &fakeDDB{}
	a := newFakeAWS(t, f)
	ctx, now := context.Background(), time.Now()
	_ = a.AppKeys(ctx, Lifecycle{Event: EventAppKeyNext, VaultID: "v1", AppKey: []byte("k2"), AppKeySeq: 2, HeaderSeq: 5}, now)
	_ = a.AppKeys(ctx, Lifecycle{Event: EventAppKey, VaultID: "v1", AppKey: []byte("k1"), AppKeySeq: 1, NextCleared: true, HeaderSeq: 5}, now)
	_ = a.AppKeys(ctx, Lifecycle{Event: "enrolled", VaultID: "v1", AppKey: []byte("k1"), AppKeySeq: 1}, now)
	u := f.updates()
	cond := func(i int) string { c, _ := u[i]["ConditionExpression"].(string); return c }
	// A report never replaces an app_key_next of an equal header_seq (it
	// would drop the live entry's attempt stamp).
	if len(u) != 3 || !strings.Contains(cond(0), "#akn.#hs < :hs)") || strings.Contains(cond(0), "<= :hs") || strings.Contains(cond(0), "#kid") {
		t.Fatalf("next: %v", u)
	}
	if !strings.Contains(cond(1), "#akn.#hs <= :hs") {
		t.Fatalf("clear: %q", cond(1))
	}
	if !strings.Contains(cond(2), "#ak.#seq < :seq") || !strings.Contains(cond(2), "#ak.#kid = :kid") {
		t.Fatalf("enrolled: %q", cond(2))
	}
}

// Permanent failures are told from transient ones.
func TestPermanentErrors(t *testing.T) {
	f := &fakeDDB{script: func(int, string) string { return "fail" }} // ValidationException
	err := newFakeAWS(t, f).AppKeys(context.Background(), Lifecycle{Event: EventAppKey, VaultID: "v1", AppKey: []byte("k"), AppKeySeq: 1}, time.Now())
	if err == nil || !Permanent(err) || Permanent(errors.New("ddb update vault: request failed")) || Permanent(nil) {
		t.Fatalf("%v", err)
	}
	if err.Error() != "ddb update vault: ValidationException" {
		t.Fatalf("text changed: %q", err)
	}
}

// The live confirm may replace an equal header_seq of another key and a
// equal header_seq of another key (R2); a report may not. Neither replaces a higher seq.
func TestLiveConfirmCondition(t *testing.T) {
	f := &fakeDDB{item: `{"Item":{"app_key_next":{"M":{"kid":{"S":"` + AppKeyID([]byte("k2")) + `"},"seq":{"N":"2"}}}}}`}
	a := newFakeAWS(t, f)
	if err := a.ConfirmAppKey(context.Background(), "v1", "next", []byte("k2"), 2, 5, att(), time.Now()); err != nil {
		t.Fatal(err)
	}
	_ = a.AppKeys(context.Background(), Lifecycle{Event: EventAppKeyNext, VaultID: "v1", AppKey: []byte("k2"), AppKeySeq: 2, HeaderSeq: 5}, time.Now())
	u := f.updates()
	live, _ := u[0]["ConditionExpression"].(string)
	report, _ := u[1]["ConditionExpression"].(string)
	if !strings.Contains(live, "#akn.#hs = :hs AND (attribute_not_exists(#akn.#att) OR #akn.#att < :att)") || strings.Contains(live, "#akn.#seq > :seq") || strings.Contains(report, "#akn.#att") || strings.Contains(report, "#akn.#seq > :seq") || strings.Contains(report, "OR #akn.#hs <= :hs OR") {
		t.Fatalf("live %q\nreport %q", live, report)
	}
}

// unusedPlaceholder reports an expression attribute name or value that no
// expression uses: DynamoDB refuses such a request (ValidationException).
func unusedPlaceholder(body map[string]any) bool {
	var text string
	for _, k := range []string{"UpdateExpression", "ConditionExpression"} {
		if e, ok := body[k].(string); ok {
			text += " " + e
		}
	}
	for _, k := range []string{"ExpressionAttributeNames", "ExpressionAttributeValues"} {
		m, _ := body[k].(map[string]any)
		for name := range m {
			if !strings.Contains(text, name) {
				return true
			}
		}
	}
	return false
}

func att() int64 { return time.Now().UnixNano() }

// The orphan clear's condition names the key and the header_seq exactly;
// it is one write, and a failed condition is no error.
func TestOrphanClearCondition(t *testing.T) {
	f := &fakeDDB{script: func(int, string) string { return "cond" }}
	a := newFakeAWS(t, f)
	if err := a.AppKeys(context.Background(), Lifecycle{Event: EventAppKeyNextClear, VaultID: "v1", AppKey: []byte("k8"), AppKeySeq: 6, HeaderSeq: 9}, time.Now()); err != nil {
		t.Fatal(err)
	}
	u := f.updates()
	c, _ := u[0]["ConditionExpression"].(string)
	if len(u) != 1 || !strings.Contains(c, "#akn.#kid = :kid") || !strings.Contains(c, "#akn.#hs = :hs") || strings.Contains(c, "<=") {
		t.Fatalf("%v", u)
	}
}
