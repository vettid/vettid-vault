package client

import "testing"

// §10.11 "Grant-set sequence": the agent keeps the set with the highest
// grant_seq; a lower one (reordered or replayed) is ignored; an equal one
// (a hold's end re-sending fresh statements) replaces it; an unnumbered one
// is taken only before the first numbered one.
func TestNewerGrantSet(t *testing.T) {
	d := &Device{}
	for _, c := range []struct {
		body string
		want bool
	}{
		{`{"grants":[]}`, true},
		{`{"grants":[],"grant_seq":3}`, true},
		{`{"grants":[]}`, false},
		{`{"grants":[],"grant_seq":2}`, false},
		{`{"grants":[],"grant_seq":3}`, true},
		{`{"grants":[],"grant_seq":0}`, false},
		{`{"grants":[],"grant_seq":5}`, true},
		{`not json`, false},
	} {
		if got := d.newerGrantSet([]byte(c.body)); got != c.want {
			t.Fatalf("%s: %v, want %v (kept %d)", c.body, got, c.want, d.leashSeq)
		}
	}
	if d.leashSeq != 5 {
		t.Fatalf("kept %d, want 5", d.leashSeq)
	}
}
