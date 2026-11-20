package client

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/envelope"
)

// Config.PersistBatch (AGENT-PLAN §7.1 AV1): Persist's contract, and the
// responses and events not yet saved handed to the save, before any of
// them is acknowledged.

// batchTypes is the inner types of a batch.
func batchTypes(batch []*envelope.Inner) []string {
	var ts []string
	for _, in := range batch {
		ts = append(ts, in.Type)
	}
	return ts
}

// eventTypes drains Events and returns their types.
func eventTypes(d *Device) []string { return batchTypes(d.Events()) }

// A batch's events reach PersistBatch, with the state, while none of
// them is acknowledged; then the batch is acknowledged and the events
// reach Events as with Persist. Persist is not called when PersistBatch
// is set.
func TestPersistBatchBeforeAck(t *testing.T) {
	r, v, d := pair(t)
	_ = eventTypes(d)
	var saved []byte
	var calls [][]string
	var waiting [][]string
	d.cfg.Persist = func([]byte) error {
		t.Error("Persist called with PersistBatch set")
		return nil
	}
	d.cfg.PersistBatch = func(st []byte, batch []*envelope.Inner) error {
		saved = append([]byte(nil), st...)
		calls = append(calls, batchTypes(batch))
		waiting = append(waiting, r.pending(v.dev.Mailbox))
		r.note("persist")
		return nil
	}
	id1 := v.send("test.one", []byte(`{}`))
	id2 := v.send("test.two", []byte(`{"n":2}`))
	mark := len(r.entries())
	if err := d.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 1 || !slices.Equal(calls[0], []string{"test.one", "test.two"}) {
		t.Fatalf("PersistBatch batches %v", calls)
	}
	if !slices.Equal(waiting[0], []string{id1, id2}) {
		t.Fatalf("waiting at the relay during PersistBatch: %v", waiting[0])
	}
	if got, want := r.entries()[mark:], []string{"persist", "ack " + id1, "ack " + id2}; !slices.Equal(got, want) {
		t.Fatalf("relay calls %v, want %v", got, want)
	}
	if st := loadState(t, saved); st.Seen[id1].IsZero() || st.Seen[id2].IsZero() {
		t.Fatal("the saved state lacks the batch's msg_ids")
	}
	if got := eventTypes(d); !slices.Equal(got, []string{"test.one", "test.two"}) {
		t.Fatalf("events %v", got)
	}
	// The next save is given only what came since: nothing is held after
	// a successful one.
	id3 := v.send("test.three", []byte(`{}`))
	if err := d.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 || !slices.Equal(calls[1], []string{"test.three"}) || !slices.Equal(waiting[1], []string{id3}) {
		t.Fatalf("second save: batches %v, waiting %v", calls, waiting)
	}
	if got := eventTypes(d); !slices.Equal(got, []string{"test.three"}) {
		t.Fatalf("events after the second save %v", got)
	}
}

// batch is the callback's own slice: emptying it, overwriting an entry or
// appending to it changes nothing of what the waiting calls and Events
// get.
func TestPersistBatchSliceIsACopy(t *testing.T) {
	r, v, d := pair(t)
	_ = eventTypes(d)
	_ = r
	d.cfg.PersistBatch = func(_ []byte, batch []*envelope.Inner) error {
		if len(batch) > 0 {
			batch[0] = &envelope.Inner{Type: "test.forged"}
		}
		batch = append(batch, &envelope.Inner{Type: "test.appended"})
		_ = batch
		return nil
	}
	v.send("test.one", []byte(`{}`))
	v.send("test.two", []byte(`{}`))
	if err := d.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	in, err := d.WaitEvent(ctx, "test.one", nil)
	if err != nil || in == nil || in.Type != "test.one" {
		t.Fatalf("WaitEvent: %v, %v", in, err)
	}
	if got := eventTypes(d); !slices.Equal(got, []string{"test.two"}) {
		t.Fatalf("events %v", got)
	}
}

// Across failures: a failed Deliver of A, then a failed Deliver of B, then
// a Poll that saves: the save is given [A, B] in order, and a later save
// is not given them again.
func TestPersistBatchAcrossFailures(t *testing.T) {
	r, v, d := pair(t)
	_ = eventTypes(d)
	fail := true
	var calls [][]string
	d.cfg.PersistBatch = func(_ []byte, batch []*envelope.Inner) error {
		calls = append(calls, batchTypes(batch))
		if fail {
			return errors.New("disk full")
		}
		return nil
	}
	v.send("test.a", []byte(`{}`))
	d.Deliver(context.Background(), r.take(v.dev.Mailbox)[0])
	v.send("test.b", []byte(`{}`))
	d.Deliver(context.Background(), r.take(v.dev.Mailbox)[0])
	if got := eventTypes(d); len(got) != 0 {
		t.Fatalf("events before a save: %v", got)
	}
	fail = false
	if err := d.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	v.send("test.c", []byte(`{}`))
	if err := d.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := [][]string{{"test.a"}, {"test.a", "test.b"}, {"test.a", "test.b"}, {"test.c"}}
	if !slices.EqualFunc(calls, want, slices.Equal[[]string]) {
		t.Fatalf("PersistBatch batches %v, want %v", calls, want)
	}
	if got := eventTypes(d); !slices.Equal(got, []string{"test.a", "test.b", "test.c"}) {
		t.Fatalf("events %v", got)
	}
}

// A PersistBatch error: Poll returns it, nothing is acknowledged and no
// event reaches the caller; the next Poll calls PersistBatch again with
// the same messages before collecting, and the redelivered batch adds no
// second copy; each event then reaches Events once.
func TestPersistBatchErrorAcksNothing(t *testing.T) {
	r, v, d := pair(t)
	_ = eventTypes(d)
	errDisk := errors.New("disk full")
	fail := true
	var calls [][]string
	d.cfg.PersistBatch = func(_ []byte, batch []*envelope.Inner) error {
		calls = append(calls, batchTypes(batch))
		if fail {
			return errDisk
		}
		r.note("persist")
		return nil
	}
	id := v.send("test.one", []byte(`{}`))
	mark := len(r.entries())
	if err := d.Poll(context.Background()); !errors.Is(err, errDisk) {
		t.Fatalf("Poll: %v, want the PersistBatch error", err)
	}
	if got := r.entries()[mark:]; len(got) != 0 {
		t.Fatalf("relay calls after a PersistBatch error: %v", got)
	}
	if got := eventTypes(d); len(got) != 0 {
		t.Fatalf("events before the save: %v", got)
	}
	if got := r.pending(v.dev.Mailbox); !slices.Equal(got, []string{id}) {
		t.Fatalf("waiting at the relay %v", got)
	}
	fail = false
	if err := d.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 || !slices.Equal(calls[0], []string{"test.one"}) || !slices.Equal(calls[1], []string{"test.one"}) {
		t.Fatalf("PersistBatch batches %v", calls)
	}
	if got := strings.Join(r.entries()[mark:], ","); got != "persist,ack "+id {
		t.Fatalf("relay calls %s", got)
	}
	if got := eventTypes(d); !slices.Equal(got, []string{"test.one"}) {
		t.Fatalf("events %v", got)
	}
	// The redelivered message was collected again and acknowledged
	// without a third save.
	if got := r.pending(v.dev.Mailbox); len(got) != 0 {
		t.Fatalf("still waiting at the relay: %v", got)
	}
}

// Deliver with PersistBatch saves the message as a batch of one, handed
// to PersistBatch.
func TestPersistBatchDeliver(t *testing.T) {
	r, v, d := pair(t)
	_ = eventTypes(d)
	var calls [][]string
	d.cfg.PersistBatch = func(_ []byte, batch []*envelope.Inner) error {
		calls = append(calls, batchTypes(batch))
		return nil
	}
	v.send("test.one", []byte(`{}`))
	msgs := r.take(v.dev.Mailbox)
	if len(msgs) != 1 {
		t.Fatalf("%d messages", len(msgs))
	}
	d.Deliver(context.Background(), msgs[0])
	if len(calls) != 1 || !slices.Equal(calls[0], []string{"test.one"}) {
		t.Fatalf("PersistBatch batches %v", calls)
	}
	if got := eventTypes(d); !slices.Equal(got, []string{"test.one"}) {
		t.Fatalf("events %v", got)
	}
}

// With only PersistBatch set, the deposits a batch's handling makes (a
// rekey's hs.resp and the token's, here) wait in the outbox until
// PersistBatch has saved them, and go before the acks.
func TestPersistBatchDepositsAfterSave(t *testing.T) {
	r, v, d := pair(t)
	var saved []byte
	d.cfg.PersistBatch = func(st []byte, _ []*envelope.Inner) error { return keep(&saved, r)(st) }
	ids, _, _ := sendBatch(v)
	mark := len(r.entries())
	if err := d.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := []string{"persist", "deposit " + v.mailbox(), "deposit " + v.mailbox(), "ack " + ids[0], "ack " + ids[1], "ack " + ids[2]}
	if got := r.entries()[mark:]; !slices.Equal(got, want) {
		t.Fatalf("relay calls %v, want %v", got, want)
	}
	if st := loadState(t, saved); len(st.Outbox) != 2 {
		t.Fatalf("saved outbox %d, want the 2 deposits", len(st.Outbox))
	}
	checkRekeyed(t, r, v, d)
}

// Deliver whose PersistBatch fails: no event reaches the caller; the next
// Poll saves again before collecting, with the same message, and only
// then is it an event.
func TestPersistBatchDeliverFails(t *testing.T) {
	r, v, d := pair(t)
	_ = eventTypes(d)
	fail := true
	var calls [][]string
	d.cfg.PersistBatch = func(_ []byte, batch []*envelope.Inner) error {
		calls = append(calls, batchTypes(batch))
		if fail {
			return errors.New("disk full")
		}
		return nil
	}
	v.send("test.one", []byte(`{}`))
	msgs := r.take(v.dev.Mailbox)
	d.Deliver(context.Background(), msgs[0])
	if d.PersistError() == nil {
		t.Fatal("no PersistError")
	}
	if got := eventTypes(d); len(got) != 0 {
		t.Fatalf("events before the save: %v", got)
	}
	fail = false
	if err := d.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 || !slices.Equal(calls[0], []string{"test.one"}) || !slices.Equal(calls[1], []string{"test.one"}) {
		t.Fatalf("PersistBatch batches %v", calls)
	}
	if got := eventTypes(d); !slices.Equal(got, []string{"test.one"}) {
		t.Fatalf("events %v", got)
	}
}
