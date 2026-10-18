package altchan

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
)

// Owner decision of 2026-10-16: recovery_offered is listed exactly when
// the release offers recovery; recovery_r is listed either way.
func TestReleaseCapabilities(t *testing.T) {
	c := ReleaseCapabilities(true)
	if !ValidCapabilities(c) || !HasCapability(c, CapRecoveryR) || !HasCapability(c, CapAttachments) || !HasCapability(c, CapRecoveryOffered) || len(c) != 3 {
		t.Fatalf("%q", c)
	}
	c = ReleaseCapabilities(false)
	if !ValidCapabilities(c) || !HasCapability(c, CapRecoveryR) || HasCapability(c, CapRecoveryOffered) || len(c) != 2 {
		t.Fatalf("not offered: %q", c)
	}
	c[0] = "changed"
	if ReleaseCapabilities(false)[0] != CapAttachments {
		t.Fatal("ReleaseCapabilities returned a shared slice")
	}
	if HasCapability(nil, CapRecoveryR) {
		t.Fatal("nil list has recovery_r")
	}
}

func TestValidCapabilities(t *testing.T) {
	long := make([]string, MaxCapabilities+1)
	for i := range long {
		long[i] = "c" + string(rune('a'+i/26)) + string(rune('a'+i%26))
	}
	for _, ok := range [][]string{nil, {}, {"a"}, {"attachments", "recovery_r"}, {strings.Repeat("z", MaxCapabilityName)}, long[:MaxCapabilities]} {
		if !ValidCapabilities(ok) {
			t.Fatalf("refused %q", ok)
		}
	}
	for _, bad := range [][]string{{""}, {"Recovery"}, {"recovery-r"}, {"a b"}, {"recovery_r", "attachments"}, {"a", "a"},
		{strings.Repeat("z", MaxCapabilityName+1)}, long} {
		if ValidCapabilities(bad) {
			t.Fatalf("accepted %q", bad)
		}
	}
}

// 0.34.0 (§11.2, §11.10.9): the descriptor's capabilities: written after
// not_after, read back; absent is nil (a release before R); present but
// malformed refuses the descriptor.
func TestDescriptorCapabilities(t *testing.T) {
	k := testKEM(t)
	na := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	rel := strings.Repeat("ab", 48)
	d := MarshalDescriptor("i-1", k.Public(), rel, na, ReleaseCapabilities(false), 0)
	if !strings.HasSuffix(string(d), `"not_after":"2026-10-16T12:00:00Z","capabilities":["attachments","recovery_r"]}`) {
		t.Fatalf("member order: %s", d)
	}
	p, err := ParseDescriptor(d)
	if err != nil || len(p.Capabilities) != 2 || !HasCapability(p.Capabilities, CapRecoveryR) {
		t.Fatalf("%v %q", err, p.Capabilities)
	}
	old := MarshalDescriptor("i-1", k.Public(), rel, na, nil, 0)
	if strings.Contains(string(old), "capabilities") {
		t.Fatal("nil list written")
	}
	if p, err := ParseDescriptor(old); err != nil || p.Capabilities != nil {
		t.Fatalf("a descriptor before R: %v %q", err, p.Capabilities)
	}
	if p, err := ParseDescriptor(MarshalDescriptor("i-1", k.Public(), rel, na, []string{}, 0)); err != nil || p.Capabilities == nil || len(p.Capabilities) != 0 {
		t.Fatalf("empty list: %v", err)
	}
	// Unknown names are kept (apps ignore them).
	if p, err := ParseDescriptor(MarshalDescriptor("i-1", k.Public(), rel, na, []string{"future_thing", "recovery_r"}, 0)); err != nil || len(p.Capabilities) != 2 {
		t.Fatalf("unknown name: %v", err)
	}
	cut := strings.TrimSuffix(string(old), "}")
	for _, bad := range []string{
		cut + `,"capabilities":"recovery_r"}`,
		cut + `,"capabilities":[1]}`,
		cut + `,"capabilities":["recovery_r","attachments"]}`,
		cut + `,"capabilities":["recovery_r","recovery_r"]}`,
		cut + `,"capabilities":["Recovery_R"]}`,
		cut + `,"capabilities":[""]}`,
		cut + `,"capabilities":null}`,
	} {
		if _, err := ParseDescriptor([]byte(bad)); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
}

// 0.34.0 (§11.14.6): attempt_used is in every result, ok or not, and a
// result without it is malformed.
func TestRecoveryOpenResultAttemptUsed(t *testing.T) {
	for _, r := range []*RecoveryOpenResult{
		{OK: false, Code: "wrong", AttemptUsed: true, Counted: true, Used: 1},
		{OK: false, Code: "wrong_again"},
		{OK: false, Code: "wait", Counted: true, Used: 2, RetryAt: time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)},
		{OK: true, StateSeq: 3, HeaderSeq: 4, Token: "t", VaultBundle: []byte("b"), Release: "r", ReleaseNumber: 15, UnlockID: "u",
			AttemptUsed: true, Counted: true, Used: 3},
		{OK: true, StateSeq: 3, HeaderSeq: 4, Token: "t", VaultBundle: []byte("b")},
	} {
		b := r.Marshal()
		o, err := strictjson.ParseObject(b)
		if err != nil {
			t.Fatal(err)
		}
		got, err := ParseRecoveryOpenResult(o)
		if err != nil || got.AttemptUsed != r.AttemptUsed || got.Code != r.Code || got.OK != r.OK || got.Used != r.Used || got.Counted != r.Counted {
			t.Fatalf("%s: %v %+v", b, err, got)
		}
		delete(o, "attempt_used")
		if _, err := ParseRecoveryOpenResult(o); err == nil {
			t.Fatalf("accepted without attempt_used: %s", b)
		}
		o["attempt_used"] = []byte(`"yes"`)
		if _, err := ParseRecoveryOpenResult(o); err == nil {
			t.Fatalf("accepted a non-boolean attempt_used: %s", b)
		}
	}
}

// MarshalDescriptor never writes a list that apps would refuse.
func TestMarshalDescriptorValidatesCapabilities(t *testing.T) {
	k := testKEM(t)
	na := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	for _, bad := range [][]string{{"recovery_r", "attachments"}, {"Recovery"}, {""}, {"a", "a"}} {
		func() {
			defer func() {
				if recover() == nil {
					t.Fatalf("%q written", bad)
				}
			}()
			MarshalDescriptor("i-1", k.Public(), strings.Repeat("ab", 48), na, bad, 0)
		}()
	}
}

// 0.43.0 (§11.10.9, STAGING-TIME-SCALE §5.2): the descriptor's time_scale,
// written after capabilities, read back; absent is 0 (a release before
// the scale, meaning 1); present but not an integer 1..MaxTimeScale
// refuses the descriptor.
func TestDescriptorTimeScale(t *testing.T) {
	k := testKEM(t)
	na := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	rel := strings.Repeat("ab", 48)
	for _, n := range []uint64{1, 24, 3600} {
		d := MarshalDescriptor("i-1", k.Public(), rel, na, ReleaseCapabilities(true), n)
		if !strings.HasSuffix(string(d), `"capabilities":["attachments","recovery_offered","recovery_r"],"time_scale":`+strconv.FormatUint(n, 10)+`}`) {
			t.Fatalf("member order: %s", d)
		}
		if p, err := ParseDescriptor(d); err != nil || p.TimeScale != n {
			t.Fatalf("%d: %v", n, err)
		}
	}
	old := MarshalDescriptor("i-1", k.Public(), rel, na, ReleaseCapabilities(true), 0)
	if strings.Contains(string(old), "time_scale") {
		t.Fatal("0 written")
	}
	if p, err := ParseDescriptor(old); err != nil || p.TimeScale != 0 {
		t.Fatalf("a descriptor before the scale: %v", err)
	}
	cut := strings.TrimSuffix(string(old), "}")
	for _, bad := range []string{`0`, `-1`, `86401`, `1.5`, `"24"`, `null`, `true`} {
		if _, err := ParseDescriptor([]byte(cut + `,"time_scale":` + bad + `}`)); err == nil {
			t.Errorf("time_scale %s accepted", bad)
		}
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("a scale above the bound written")
			}
		}()
		MarshalDescriptor("i-1", k.Public(), rel, na, nil, MaxTimeScale+1)
	}()
}
