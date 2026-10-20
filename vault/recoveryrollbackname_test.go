package vault

import (
	"bytes"
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// VAULT-MESSAGING 0.50.0 §11.14.11: recovery.generation_closed's reason
// `rollback` (a next generation that already shows used attempts, with an
// urgent feed item) against `stale` (audit only), and the attempting
// phone's self-reported name as the third part of a noted open's ref.

// closedEntries is the sink's recovery.generation_closed activities.
func closedEntries(s *recSink) []Activity {
	var out []Activity
	for _, a := range s.got {
		if a.Kind == "recovery.generation_closed" {
			out = append(out, a)
		}
	}
	return out
}

// changeWithKnownNext arms generation 1, lets prepare make generation 2
// known to the counter, and sends a password change: refused with retry,
// both generations closed.
func changeWithKnownNext(t *testing.T, prepare func(f *rFixture)) []Activity {
	f := newRFixture(t)
	if st := f.arm(); st != RecoveryArmed {
		t.Fatal(st)
	}
	f.flush()
	sink := &recSink{}
	f.m.mu.Lock()
	f.m.features = append(f.m.features, sink)
	f.m.mu.Unlock()
	prepare(f)
	err := f.change(SecretChange{Reason: ReplacePassword, PIN: testPIN, Password: []byte(rPW), NewPassword: []byte(rNewPW)})
	if he, ok := err.(*HandlerError); !ok || he.Code != errRetry.Code {
		t.Fatalf("change: %v", err)
	}
	if f.m.hdr.Rec.Generation != 3 || f.m.hdr.Rec.Wrap != nil || !f.m.hdr.Rec.ClosedUnchanged {
		t.Fatalf("after: %+v", f.m.hdr.Rec)
	}
	for _, g := range []uint64{1, 2} {
		if v, err := f.m.counter().Status(context.Background(), g); err != nil || !v.Closed {
			t.Fatalf("generation %d not closed: %v %+v", g, err, v)
		}
	}
	return closedEntries(sink)
}

func TestChangeRollbackForANextGenerationWithAttempts(t *testing.T) {
	got := changeWithKnownNext(t, func(f *rFixture) {
		if sp := f.m.counter().Spend(context.Background(), 2, 1); sp.Used != 1 {
			t.Fatalf("spend: %+v", sp)
		}
	})
	if len(got) != 2 {
		t.Fatalf("entries: %+v", got)
	}
	if a := got[0]; a.Ref != "1/stale" || !a.Audit || a.Feed || a.Priority != "" {
		t.Fatalf("current generation: %+v", a)
	}
	if a := got[1]; a.Ref != "2/rollback" || !a.Audit || !a.Feed || a.Priority != "urgent" {
		t.Fatalf("next generation: %+v", a)
	}
}

func TestChangeRollbackForAClosedNextGenerationWithAttempts(t *testing.T) {
	got := changeWithKnownNext(t, func(f *rFixture) {
		f.m.counter().Spend(context.Background(), 2, 1)
		if err := f.m.counter().Close(context.Background(), 2); err != nil {
			t.Fatal(err)
		}
	})
	if len(got) != 2 || got[0].Ref != "1/stale" || got[1].Ref != "2/rollback" || !got[1].Feed || got[1].Priority != "urgent" {
		t.Fatalf("entries: %+v", got)
	}
}

func TestChangeStaleForANextGenerationOnlyClosed(t *testing.T) {
	got := changeWithKnownNext(t, func(f *rFixture) {
		if err := f.m.counter().Close(context.Background(), 2); err != nil {
			t.Fatal(err)
		}
	})
	if len(got) != 2 {
		t.Fatalf("entries: %+v", got)
	}
	for i, want := range []string{"1/stale", "2/stale"} {
		if a := got[i]; a.Ref != want || !a.Audit || a.Feed || a.Priority != "" {
			t.Fatalf("entry %d: %+v", i, a)
		}
	}
}

func TestCleanOpenName(t *testing.T) {
	long := strings.Repeat("é", 40) // 80 bytes, 2 per character
	cases := []struct{ in, want string }{
		{"", ""},
		{"Pixel 10 Pro", "Pixel 10 Pro"},
		{"a\x00b\tc\nd\x1fe\x7ff\u0080g\u009fh", "abcdefgh"},
		{"\x00\r\n\u0085", ""},
		{"bad\xffutf8", "badutf8"},
		{"Al's \u202eenohp\u202c / mine", "Al's \u202eenohp\u202c / mine"}, // bidi controls are not C0, DEL or C1 and stay
		{long, strings.Repeat("é", 32)},
		{strings.Repeat("a", 63) + "€", strings.Repeat("a", 63)}, // € is 3 bytes: not split
		{strings.Repeat("a", 61) + "€x", strings.Repeat("a", 61) + "€"},
		{strings.Repeat("a", 70), strings.Repeat("a", 64)},
		{"\x01" + strings.Repeat("b", 64), strings.Repeat("b", 64)}, // removed before the cut
	}
	for _, c := range cases {
		got := cleanOpenName(c.in)
		if got != c.want || len(got) > maxOpenName || !utf8.ValidString(got) {
			t.Errorf("cleanOpenName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestOpenRef(t *testing.T) {
	enc := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	cases := []struct {
		app  *RecoveryApp
		want string
	}{
		{nil, "r1/wrong"},
		{&RecoveryApp{}, "r1/wrong"},
		{&RecoveryApp{Name: "\x00\x1b\u0085"}, "r1/wrong"},
		{&RecoveryApp{Name: "Pixel/7?>"}, "r1/wrong/" + enc("Pixel/7?>")},
		{&RecoveryApp{Name: "x\u202ey\x1b[31m"}, "r1/wrong/" + enc("x\u202ey[31m")},
		{&RecoveryApp{Name: strings.Repeat("日", 30)}, "r1/wrong/" + enc(strings.Repeat("日", 21))},
	}
	for _, c := range cases {
		got := openRef(&RecoveryRecord{ID: "r1", App: c.app}, OpenWrong)
		if got != c.want {
			t.Errorf("openRef(%+v) = %q, want %q", c.app, got, c.want)
		}
		if p := strings.Split(got, "/"); len(p) > 3 || strings.ContainsAny(got, "=+") {
			t.Errorf("ref %q has %d parts", got, len(p))
		}
	}
}

// setRecoveryName sets the registered phone's name in the stored header,
// as vault.recovery.register would have stored it.
func (f *openFixture) setRecoveryName(name string, extra ...RecoveryEvent) {
	f.t.Helper()
	p := HeaderParams{Options: f.opts, VaultID: f.vid, UserGUID: "u1"}
	if err := headerTx(context.Background(), p, func(h *Header, _ time.Time) (bool, error) {
		h.Recovery.App.Name = name
		h.RecoveryLog = append(h.RecoveryLog, extra...)
		return true, nil
	}); err != nil {
		f.t.Fatal(err)
	}
}

func openRefsIn(log []RecoveryEvent) []string {
	var out []string
	for _, e := range log {
		if e.Kind == "recovery.open" {
			out = append(out, e.Ref)
		}
	}
	return out
}

// A named phone's noted opens carry its cleaned, encoded name, also once
// moved into the audit log at the next resume; an entry noted before (two parts) moves as it
// is; and the name changes no outcome or priority.
func TestRecoveryOpenNotesThePhoneName(t *testing.T) {
	f := newOpenFixture(t)
	sink := &recSink{}
	f.opts.Features = append(f.opts.Features, sink)
	old := RecoveryEvent{At: f.clock, Kind: "recovery.open", Ref: "old-recovery/wrong"}
	name := "URGENT\x1b[0m \u202eVettID\u202c " + strings.Repeat("ü", 40)
	f.setRecoveryName(name, old)
	wantName := base64.RawURLEncoding.EncodeToString([]byte(cleanOpenName(name)))
	if m, out := f.open(testPIN, "wrong password one"); m != nil || out.Code != OpenWrong || !out.Counted {
		t.Fatalf("wrong: %+v", out)
	}
	if m, out := f.open(testPIN, "wrong password one"); m != nil || out.Code != OpenWrongAgain {
		t.Fatalf("wrong again: %+v", out)
	}
	want := []string{old.Ref, recID + "/" + OpenWrong + "/" + wantName, recID + "/" + OpenWrongAgain + "/" + wantName}
	if got := openRefsIn(f.storedHeader().RecoveryLog); !sameRefs(got, want) {
		t.Fatalf("header log: %v, want %v", got, want)
	}
	m, out := f.open(testPIN, rPW)
	if m == nil || !out.OK {
		t.Fatalf("right pair: %+v", out)
	}
	// Moved into the audit log at the next resume.
	if err := m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.clock = f.clock.Add(time.Hour)
	m2 := f.mustUnlock(testPIN, f.phoneUS)
	defer m2.Crash()
	var got []string
	for _, a := range sink.got {
		if a.Kind == "recovery.open" {
			got = append(got, a.Ref)
			if !a.Audit || a.Feed || a.Priority != "" {
				t.Fatalf("open entry: %+v", a)
			}
		}
	}
	if !sameRefs(got, want) {
		t.Fatalf("audit: %v, want %v", got, want)
	}
	b, _ := base64.RawURLEncoding.DecodeString(wantName)
	if bytes.ContainsAny(b, "\x1b") || len(b) > maxOpenName {
		t.Fatalf("name not cleaned: %q", b)
	}
}

// A phone without a name writes the two-part form.
func TestRecoveryOpenWithoutAName(t *testing.T) {
	f := newOpenFixture(t)
	f.setRecoveryName("\x00\x7f")
	if m, out := f.open(testPIN, "wrong password one"); m != nil || out.Code != OpenWrong {
		t.Fatalf("wrong: %+v", out)
	}
	if got := openRefsIn(f.storedHeader().RecoveryLog); !sameRefs(got, []string{recID + "/" + OpenWrong}) {
		t.Fatalf("header log: %v", got)
	}
}
