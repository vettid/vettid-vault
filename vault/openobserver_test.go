package vault

import (
	"context"
	"encoding/json"
	"sync"
	"testing"

	"github.com/vettid/vettid-vault/vms/envelope"
)

type openStub struct {
	mu     sync.Mutex
	opened int
}

func (o *openStub) Name() string                   { return "openstub" }
func (o *openStub) Types() []TypeSpec              { return nil }
func (o *openStub) Load(json.RawMessage) error     { return nil }
func (o *openStub) Save() (json.RawMessage, error) { return nil, nil }
func (o *openStub) Opened(*Session)                { o.mu.Lock(); o.opened++; o.mu.Unlock() }
func (o *openStub) Handle(context.Context, *Session, *envelope.Inner) (json.RawMessage, error) {
	return json.RawMessage(`{}`), nil
}

// OpenObserver features are told once per opening, before the first collect (which may wait for the relay's long
// poll): the calls pool asks for its credentials within 5 s of the unlock (VAULT-MESSAGING §10.10).
func TestOpenObserverBeforeTheFirstCollect(t *testing.T) {
	d := newDevFixture(t)
	o := &openStub{}
	d.m.addFeature(o)
	if err := d.m.beforeCollect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if o.opened != 1 {
		t.Fatalf("told %d times before the first collect", o.opened)
	}
	_ = d.m.beforeCollect(context.Background())
	_ = d.m.ProcessBatch(context.Background(), &fakeCollector{}, nil)
	if o.opened != 1 {
		t.Fatalf("told %d times in one opening", o.opened)
	}
}
