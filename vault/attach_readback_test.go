package vault

import (
	"encoding/json"
	"testing"
)

// The attachments' state read back after a lock (§10.5.1, §12.3): its maps
// are omitempty, so empty ones come back nil; the state's init makes them
// again before the runner, which writes turns directly, runs (staging,
// release 33: a nil map in the vault ended it after an unlock).
func TestAttachStateReadBackHasItsMaps(t *testing.T) {
	st := &State{Attach: &AttachState{Entries: map[string]*AttEntry{"a1": {ID: "a1", Dir: DirIn, State: AttFetching}}}}
	b, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	var back State
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.Attach == nil || back.Attach.Turns != nil {
		t.Fatalf("not the stored shape this is about: %s", b)
	}
	back.init()
	a := back.Attach
	if a.Turns == nil || a.Accepted == nil || a.Reuploads == nil || a.Refreshed == nil || a.FullFed == nil || a.Renewed == nil {
		t.Fatalf("maps left nil: %+v", a)
	}
	a.Turns["conn"] = &AttTurn{Att: "a1"}
	// A state without attachments gets none.
	var none State
	none.init()
	if none.Attach != nil {
		t.Fatal("an attachments state made from nothing")
	}
}
