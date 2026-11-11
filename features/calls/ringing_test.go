package calls

import (
	"testing"
	"time"
)

// (C2, VAULT-MESSAGING §14.2 trigger 5) CallRinging says whether a call's
// wake may still go: an incoming call ringing before its offer's exp; not
// an outgoing one, one answered or ended, one past its exp, or one unknown.
func TestCallRinging(t *testing.T) {
	now := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	f := New(Options{})
	f.calls["in"] = &Call{ID: "in", Dir: DirIn, State: StateRinging, Exp: now.Add(30 * time.Second)}
	f.calls["out"] = &Call{ID: "out", Dir: DirOut, State: StateRinging, Exp: now.Add(30 * time.Second)}
	f.calls["active"] = &Call{ID: "active", Dir: DirIn, State: StateActive, Exp: now.Add(30 * time.Second)}
	f.calls["ended"] = &Call{ID: "ended", Dir: DirIn, State: StateEnded, Exp: now.Add(30 * time.Second)}
	f.calls["late"] = &Call{ID: "late", Dir: DirIn, State: StateRinging, Exp: now}
	for _, c := range f.calls {
		f.syncRinging(c)
	}
	// A call that rang and then ended no longer rings.
	f.calls["was"] = &Call{ID: "was", Dir: DirIn, State: StateRinging, Exp: now.Add(30 * time.Second)}
	f.syncRinging(f.calls["was"])
	f.notRinging("was")
	for id, want := range map[string]bool{"was": false, "in": true, "out": false, "active": false, "ended": false, "late": false, "nobody": false} {
		if got := f.CallRinging(id, now); got != want {
			t.Errorf("%s: %v", id, got)
		}
	}
}
