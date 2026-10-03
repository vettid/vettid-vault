package parent

import (
	"regexp"
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
