package messaging

import (
	"encoding/json"
	"testing"
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
