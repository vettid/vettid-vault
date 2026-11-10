package vault

import (
	"context"
	"encoding/json"
	"strconv"
	"testing"

	"github.com/vettid/vettid-vault/vms/envelope"
)

// counterFeature changes its own state in a queued request, as LEASH does
// when an agent's leash.grant.list takes a grant_seq (§10.11): each
// test.count takes the next number and answers it.
type counterFeature struct {
	n        uint64
	volatile bool
}

func (c *counterFeature) Name() string { return "counter" }
func (c *counterFeature) Types() []TypeSpec {
	return []TypeSpec{{Type: "test.count", Request: true, From: []string{KindApp}, Volatile: c.volatile}}
}
func (c *counterFeature) Handle(context.Context, *Session, *envelope.Inner) (json.RawMessage, error) {
	c.n++
	return json.RawMessage(`{"n":` + strconv.FormatUint(c.n, 10) + `}`), nil
}
func (c *counterFeature) Load(raw json.RawMessage) error {
	if len(raw) == 0 {
		return nil
	}
	return json.Unmarshal(raw, &c.n)
}
func (c *counterFeature) Save() (json.RawMessage, error) { return json.Marshal(c.n) }

// A feature's state changed by a queued request is stored before the
// answer naming it goes out (§8.2, §8.3): a failed write sends nothing; the
// next write that succeeds stores the feature's state and only then sends
// the answer; and a vault reopened after a crash (no write of its own) has
// the number the answer carried, so it is never given out again.
func TestFeatureStateStoredBeforeAnswer(t *testing.T) {
	d := newDevFixture(t)
	c := &counterFeature{}
	d.m.addFeature(c)
	_ = d.responses(t)
	failWrites(d, 1)
	if err := d.send("test.count", []byte(`{}`)); err == nil {
		t.Fatal("the batch's write did not fail")
	}
	d.m.mu.Lock()
	d.m.drainOutbox(context.Background()) // any drain in between (the attachment runner's)
	d.m.mu.Unlock()
	if got := d.responses(t); len(got) != 0 {
		t.Fatalf("sent before a write stored it: %v", typesOf(got))
	}
	if err := d.send("device.list", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	var answered string
	for _, in := range d.responses(t) {
		if in.Type == "test.count" {
			answered = string(in.Body)
		}
	}
	if answered != `{"n":1}` {
		t.Fatalf("after the later write, test.count answered %q", answered)
	}

	// Reopen from the store without a write of the vault's own.
	d.m.Crash()
	d.opts.Store = d.store
	c2 := &counterFeature{}
	opts := d.opts
	opts.Features = append(append([]Feature(nil), d.opts.Features...), c2)
	m, _, err := Unlock(context.Background(), UnlockParams{Options: opts, VaultID: d.vid, PIN: testPIN, UnlockSecret: testSecret})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Crash()
	if c2.n != 1 {
		t.Fatalf("the stored state has %d, the answer said 1", c2.n)
	}
}
