package parent

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/hostproto"
)

// The alarm id is a ULID the member API's mailer accepts
// (^[0-9A-HJKMNP-TV-Z]{26}$), time-ordered (§11.5).
func TestAlarmULID(t *testing.T) {
	re := regexp.MustCompile(`^[0-9A-HJKMNP-TV-Z]{26}$`)
	a, err := newULID(time.UnixMilli(1790000000000))
	if err != nil || !re.MatchString(a) {
		t.Fatalf("%q %v", a, err)
	}
	b, _ := newULID(time.UnixMilli(1790000000001))
	if a[:10] >= b[:10] || a[0] > '7' {
		t.Fatalf("not time-ordered: %s %s", a, b)
	}
}

// parseLifecycle accepts the one alarm kind and nothing else.
func TestParseAlarmEvent(t *testing.T) {
	pcr := ""
	for i := 0; i < 96; i++ {
		pcr += "a"
	}
	f := func(ev string) bool {
		_, ok := parseLifecycle(&hostproto.Frame{Fields: [][]byte{[]byte(ev), []byte("v1"), []byte(pcr), []byte(pcr), []byte("1")}})
		return ok
	}
	if !f(EventAlarmCredentialClone) || f("alarm.other") || f("alarm") {
		t.Fatal("alarm parsing")
	}
}

// §11.5 (0.15.0): lifecycle frames carry the app key and its sequence
// (seven fields; five from an enclave before 0.15.0); the event app_key
// needs a key; a malformed sequence is refused.
func TestParseLifecycleAppKey(t *testing.T) {
	pcr := strings.Repeat("a", 96)
	frame := func(fs ...string) *hostproto.Frame {
		f := &hostproto.Frame{}
		for _, s := range fs {
			f.Fields = append(f.Fields, []byte(s))
		}
		return f
	}
	ev, ok := parseLifecycle(frame("unlocked", "v1", pcr, pcr, "1", "\x30\x59key", "3"))
	if !ok || string(ev.AppKey) != "\x30\x59key" || ev.AppKeySeq != 3 {
		t.Fatalf("%+v %v", ev, ok)
	}
	if ev, ok := parseLifecycle(frame("locked", "v1", pcr, pcr, "1", "", "0")); !ok || ev.AppKey != nil {
		t.Fatal("no key")
	}
	if _, ok := parseLifecycle(frame("locked", "v1", pcr, pcr, "1")); !ok {
		t.Fatal("five fields")
	}
	if _, ok := parseLifecycle(frame(EventAppKey, "v1", pcr, pcr, "1", "k", "2")); !ok {
		t.Fatal("app_key event")
	}
	for _, f := range []*hostproto.Frame{
		frame(EventAppKey, "v1", pcr, pcr, "1", "", "0"),
		frame("unlocked", "v1", pcr, pcr, "1", "k", "0"),
		frame("unlocked", "v1", pcr, pcr, "1", "k", "02"),
		frame("unlocked", "v1", pcr, pcr, "1", "k"),
		frame("unlocked", "v1", pcr, pcr, "1", strings.Repeat("k", 257), "1"),
	} {
		if _, ok := parseLifecycle(f); ok {
			t.Fatalf("accepted %q", f.Fields)
		}
	}
}

// §11.5 (0.16.0): the backup bit as the eighth field; the event
// credential_backup needs it.
func TestParseLifecycleBackup(t *testing.T) {
	pcr := strings.Repeat("a", 96)
	frame := func(fs ...string) *hostproto.Frame {
		f := &hostproto.Frame{}
		for _, s := range fs {
			f.Fields = append(f.Fields, []byte(s))
		}
		return f
	}
	ev, ok := parseLifecycle(frame("locked", "v1", pcr, pcr, "1", "", "0", "0"))
	if !ok || ev.CredentialBackup == nil || *ev.CredentialBackup {
		t.Fatalf("%+v %v", ev, ok)
	}
	if ev, ok := parseLifecycle(frame("unlocked", "v1", pcr, pcr, "1", "k", "2", "1")); !ok || string(ev.AppKey) != "k" || ev.AppKeySeq != 2 || !*ev.CredentialBackup {
		t.Fatalf("app key with the bit: %+v", ev)
	}
	if ev, ok := parseLifecycle(frame(EventCredentialBackup, "v1", pcr, pcr, "1", "", "0", "1")); !ok || !*ev.CredentialBackup {
		t.Fatal("credential_backup event")
	}
	if ev, ok := parseLifecycle(frame("unlocked", "v1", pcr, pcr, "1", "", "0", "")); !ok || ev.CredentialBackup != nil {
		t.Fatal("unreported bit")
	}
	for _, f := range []*hostproto.Frame{frame(EventCredentialBackup, "v1", pcr, pcr, "1", "", "0", ""), frame("locked", "v1", pcr, pcr, "1", "", "0", "yes")} {
		if _, ok := parseLifecycle(f); ok {
			t.Fatalf("accepted %q", f.Fields)
		}
	}
}
