package messaging

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
)

func TestParseDeliver(t *testing.T) {
	ok := `{"message_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V","text":"hi","sent_at":"2026-10-01T12:00:00.000Z"}`
	if _, err := ParseDeliver([]byte(ok)); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{
		`{"message_id":"x","text":"hi","sent_at":"2026-10-01T12:00:00.000Z"}`,
		`{"message_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V","text":"","sent_at":"2026-10-01T12:00:00.000Z"}`,
		`{"message_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V","text":"hi","sent_at":"2026-10-01T12:00:00Z"}`,
		`{"message_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V","text":"hi"}`,
		`{"message_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V","message_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0W","text":"hi","sent_at":"2026-10-01T12:00:00.000Z"}`,
	} {
		if _, err := ParseDeliver([]byte(s)); err == nil {
			t.Errorf("accepted %s", s)
		}
	}
	long, _ := json.Marshal(map[string]string{"message_id": "01JB2Z6V9K3M4N5P6Q7R8S9T0V", "text": string(make([]byte, MaxText+1)), "sent_at": "2026-10-01T12:00:00.000Z"})
	if _, err := ParseDeliver(long); err == nil {
		t.Error("oversized text accepted")
	}
}

func TestParseReceipt(t *testing.T) {
	if _, err := ParseReceipt([]byte(`{"message_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V","receipt":"read","at":"2026-10-01T12:00:00.000Z"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseReceipt([]byte(`{"message_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V","receipt":"seen","at":"2026-10-01T12:00:00.000Z"}`)); err == nil {
		t.Fatal("bad receipt kind accepted")
	}
}

func FuzzParseDeliver(f *testing.F) {
	f.Add([]byte(`{"message_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V","text":"hi","sent_at":"2026-10-01T12:00:00.000Z"}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		d, err := ParseDeliver(b)
		if err == nil && (d.Text == "" || len(d.Text) > MaxText) {
			t.Fatal("invalid deliver accepted")
		}
	})
}

func FuzzParseReceipt(f *testing.F) {
	f.Add([]byte(`{"message_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V","receipt":"delivered","at":"2026-10-01T12:00:00.000Z"}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := ParseReceipt(b)
		if err == nil && r.Kind != "delivered" && r.Kind != "read" {
			t.Fatal("invalid receipt accepted")
		}
	})
}

// conv fills a feature with n messages of text length size (ids m0000..).
func conv(n, size int) (*Feature, []string) {
	f := New()
	ids := make([]string, n)
	for i := range n {
		ids[i] = fmt.Sprintf("01JB2Z6V9K3M4N5P6Q7R8S%04d", i)
		f.convs["c1"] = append(f.convs["c1"], &Message{ID: ids[i], Dir: DirIn, Text: strings.Repeat("x", size),
			SentAt: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)})
	}
	return f, ids
}

type page struct {
	Messages []struct {
		ID string `json:"message_id"`
	} `json:"messages"`
	NextBefore *string `json:"next_before"`
}

func listPage(t *testing.T, f *Feature, body string) (page, int, error) {
	t.Helper()
	o, err := strictjson.ParseObject([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := f.list(o)
	if err != nil {
		return page{}, 0, err
	}
	var p page
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatalf("%v: %s", err, raw)
	}
	return p, len(raw), nil
}

// §10.5.2 (0.32.0): pages are at most PageBytes, newest first from the
// cursor, returned oldest first, and continue with next_before until the
// oldest message; the pages together are the conversation in arrival order.
func TestListPagesByBytes(t *testing.T) {
	f, ids := conv(300, MaxText) // ~4.9 MB of text: far beyond one response
	var got []string
	body := `{"connection_id":"c1","limit":500}`
	pages := 0
	for {
		p, n, err := listPage(t, f, body)
		if err != nil {
			t.Fatal(err)
		}
		pages++
		if n > PageBytes {
			t.Fatalf("page of %d bytes", n)
		}
		if len(p.Messages) == 0 {
			t.Fatal("empty page")
		}
		var ps []string
		for _, m := range p.Messages {
			ps = append(ps, m.ID)
		}
		got = append(ps, got...)
		if p.NextBefore == nil {
			break
		}
		if *p.NextBefore != ps[0] {
			t.Fatalf("next_before %s, oldest %s", *p.NextBefore, ps[0])
		}
		// The next message would not have fitted.
		if n+len(msgJSON("c1", f.convs["c1"][0]))+1 <= PageBytes {
			t.Fatalf("page of %d bytes stopped early", n)
		}
		body = `{"connection_id":"c1","limit":500,"before":"` + *p.NextBefore + `"}`
	}
	if strings.Join(got, ",") != strings.Join(ids, ",") || pages < 30 {
		t.Fatalf("%d pages, %d messages", pages, len(got))
	}
	// The limit still applies, and small messages fill it.
	f, ids = conv(150, 10)
	p, _, _ := listPage(t, f, `{"connection_id":"c1"}`)
	if len(p.Messages) != DefaultLimit || p.Messages[0].ID != ids[50] || *p.NextBefore != ids[50] {
		t.Fatalf("default limit: %d", len(p.Messages))
	}
	p, _, _ = listPage(t, f, `{"connection_id":"c1","limit":3,"before":"`+ids[50]+`"}`)
	if len(p.Messages) != 3 || p.Messages[0].ID != ids[47] || p.Messages[2].ID != ids[49] || *p.NextBefore != ids[47] {
		t.Fatalf("before: %+v", p)
	}
	// The last page has no next_before; one before the oldest is empty.
	p, _, _ = listPage(t, f, `{"connection_id":"c1","before":"`+ids[3]+`"}`)
	if len(p.Messages) != 3 || p.NextBefore != nil {
		t.Fatalf("last page: %+v", p)
	}
	p, _, _ = listPage(t, f, `{"connection_id":"c1","before":"`+ids[0]+`"}`)
	if len(p.Messages) != 0 || p.NextBefore != nil {
		t.Fatalf("before the oldest: %+v", p)
	}
	if p, _, _ := listPage(t, f, `{"connection_id":"none"}`); len(p.Messages) != 0 || p.NextBefore != nil {
		t.Fatal("unknown conversation")
	}
}

// §10.5.2: a message is never too large for a page: the page holds at
// least one message when one is older than the cursor, even past the
// budget (which a real message cannot reach: the budget is lowered here).
func TestListAtLeastOne(t *testing.T) {
	defer func(b int) { pageBytes = b }(pageBytes)
	pageBytes = 1000
	f, ids := conv(3, 2000)
	p, n, err := listPage(t, f, `{"connection_id":"c1"}`)
	if err != nil || len(p.Messages) != 1 || p.Messages[0].ID != ids[2] || *p.NextBefore != ids[2] || n <= pageBytes {
		t.Fatalf("%+v %d %v", p, n, err)
	}
	p, _, _ = listPage(t, f, `{"connection_id":"c1","before":"`+ids[1]+`"}`)
	if len(p.Messages) != 1 || p.Messages[0].ID != ids[0] || p.NextBefore != nil {
		t.Fatalf("%+v", p)
	}
	// The largest possible message (every character escaped) fits the
	// real budget with room to spare.
	m := &Message{ID: ids[0], Dir: DirOut, Text: strings.Repeat("\x01", MaxText), SentAt: time.Now(), Delivered: true, Read: true}
	if n := len(msgJSON("c1", m)) + len(`{"messages":[]}`) + nextBeforeLen(ids[0]); n > PageBytes {
		t.Fatalf("largest message: %d bytes", n)
	}
}

// §10.5.2: a cursor the vault does not hold (unknown, or deleted since) is
// not_found; a bad one is bad_request.
func TestListCursor(t *testing.T) {
	f, ids := conv(5, 10)
	o, _ := strictjson.ParseObject([]byte(`{"connection_id":"c1","message_id":"` + ids[2] + `"}`))
	if _, err := f.del(o); err != nil {
		t.Fatal(err)
	}
	for _, c := range []string{ids[2], "01JB2Z6V9K3M4N5P6Q7R8S9999", ""} {
		if _, _, err := listPage(t, f, `{"connection_id":"c1","before":"`+c+`"}`); vaultCode(err) != "not_found" {
			t.Fatalf("cursor %q: %v", c, err)
		}
	}
	if _, _, err := listPage(t, f, `{"connection_id":"c1","before":5}`); vaultCode(err) != "bad_request" {
		t.Fatalf("numeric cursor: %v", err)
	}
	// A cursor of another conversation is unknown in this one.
	f.convs["c2"] = []*Message{{ID: "01JB2Z6V9K3M4N5P6Q7R8SAAAA", Dir: DirIn, Text: "y"}}
	if _, _, err := listPage(t, f, `{"connection_id":"c1","before":"01JB2Z6V9K3M4N5P6Q7R8SAAAA"}`); vaultCode(err) != "not_found" {
		t.Fatalf("other conversation's cursor: %v", err)
	}
	// After a deletion the pages skip the deleted message.
	p, _, _ := listPage(t, f, `{"connection_id":"c1","before":"`+ids[3]+`"}`)
	if len(p.Messages) != 2 || p.Messages[0].ID != ids[0] || p.Messages[1].ID != ids[1] {
		t.Fatalf("%+v", p)
	}
}

// §8.2 (0.32.0): message.list and message.get are volatile, the other
// messaging types are not.
func TestListGetVolatile(t *testing.T) {
	for _, ts := range New().Types() {
		want := ts.Type == "message.list" || ts.Type == "message.get"
		if ts.Volatile != want {
			t.Errorf("%s volatile %v", ts.Type, ts.Volatile)
		}
	}
}

func vaultCode(err error) string {
	var he *vault.HandlerError
	if errors.As(err, &he) {
		return he.Code
	}
	return ""
}
