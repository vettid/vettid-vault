package parent_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/aws/smithy-go"

	"github.com/vettid/vettid-vault/internal/parenttest"
	"github.com/vettid/vettid-vault/parent"
)

func answerDone(msg []byte) []byte {
	var m struct {
		RequestID string `json:"request_id"`
	}
	_ = json.Unmarshal(msg, &m)
	return response(m.RequestID, "done", nil)
}

// request sends one queue message to the instance and waits for its slot.
func (h *harness) request(rid string) {
	h.t.Helper()
	h.tables.PutSlot(rid, "i-test")
	if !h.queues.Send(h.queue, queueMsg("lock", rid)) {
		h.t.Fatal("no queue to send to")
	}
	waitFor(h.t, "slot "+rid, func() bool { s, _ := h.tables.Slot(rid); return s.Status == "done" })
}

// A parent whose queue was deleted while it runs creates it again, under
// the same name, and serves requests; the registry row names a queue that
// exists.
func TestQueueDeletedWhileRunningIsRecreated(t *testing.T) {
	h := newHarness(t, nil)
	e := h.connect("boot-1", answerDone)
	e.descriptor()
	waitFor(t, "ready", func() bool { return h.p.Health().OK })
	h.request("01JAAAAAAAAAAAAAAAAAAAAAAA")

	if err := h.queues.Destroy(context.Background(), h.queue); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "queue created again", func() bool { return h.queues.Exists(h.queue) })
	h.request("01JBBBBBBBBBBBBBBBBBBBBBBB")
	if row, ok := h.tables.Instance("i-test"); !ok || row.QueueURL != h.queue {
		t.Fatalf("registry row %+v", row)
	}
	h.logMu.Lock()
	logs := h.logs.String()
	h.logMu.Unlock()
	for _, want := range []string{
		`"level":"WARN","msg":"queue receive failed","error":"parent: queue not found: sqs receive: AWS.SimpleQueueService.NonExistentQueue"`,
		`"level":"WARN","msg":"instance queue is missing; creating it again","queue":"test-vault-control-i-test"`,
		`"level":"INFO","msg":"instance queue created again","queue":"test-vault-control-i-test"`,
	} {
		if !strings.Contains(logs, want) {
			t.Errorf("no log line %s in:\n%s", want, logs)
		}
	}
}

// checkedTables counts the registry rows written while the queue they
// name does not exist.
type checkedTables struct {
	*parenttest.Tables
	queues  *parenttest.Queues
	orphans atomic.Int32
}

func (c *checkedTables) PutInstance(ctx context.Context, r parent.InstanceRow) error {
	if !c.queues.Exists(r.QueueURL) {
		c.orphans.Add(1)
	}
	return c.Tables.PutInstance(ctx, r)
}

func (h *harness) logged() string {
	h.logMu.Lock()
	defer h.logMu.Unlock()
	return h.logs.String()
}

// refusingQueues is a queue service that refuses to create a queue, as
// SQS does for a name deleted less than 60 s ago, for as long as the test
// says (not for a length of time: the test does not depend on the clock).
type refusingQueues struct {
	*parenttest.Queues
	refuse atomic.Bool
}

func (r *refusingQueues) Create(ctx context.Context, name string) (string, error) {
	if r.refuse.Load() {
		return "", fmt.Errorf("%w: sqs create: AWS.SimpleQueueService.QueueDeletedRecently", parent.ErrQueueDeletedRecently)
	}
	return r.Queues.Create(ctx, name)
}

// The case with two instances: while one instance's enclave is
// disconnected its registry row is gone, so another instance's sweeper
// takes its queue for a gone instance's and deletes it. When the enclave
// is back the instance makes its queue again and answers requests; and it
// writes no registry row before the queue exists, also while SQS still
// refuses the deleted queue's name.
func TestQueueSweptWhileEnclaveDisconnectedIsRecreated(t *testing.T) {
	defer parent.SetQueueRetryForTest(20*time.Millisecond, 50*time.Millisecond, 10*time.Second)()
	var (
		ct *checkedTables
		rq *refusingQueues
	)
	h := newHarness(t, func(c *parent.Config) {
		ct = &checkedTables{Tables: c.Tables.(*parenttest.Tables), queues: c.Queues.(*parenttest.Queues)}
		rq = &refusingQueues{Queues: c.Queues.(*parenttest.Queues)}
		c.Tables, c.Queues = ct, rq
	})
	e := h.connect("boot-1", answerDone)
	e.descriptor()
	waitFor(t, "ready", func() bool { return h.p.Health().OK })
	h.request("01JAAAAAAAAAAAAAAAAAAAAAAA")

	// The enclave goes away (its own restart; the parent keeps running).
	e.conn.Close()
	waitFor(t, "row deleted", func() bool { _, ok := h.tables.Instance("i-test"); return !ok })

	// Another instance sweeps, 20 minutes on (the queue is then older than
	// the sweeper's 15 minutes).
	other, err := parent.New(parent.Config{InstanceID: "i-other", QueuePrefix: "test-vault-control-", ControlListener: listen(t), EgressListener: listen(t),
		Objects: h.objs, Queues: h.queues, Tables: h.tables, Creds: parenttest.StaticCreds{AccessKeyID: "AK", SecretAccessKey: "SK"},
		SweepInterval: 20 * time.Millisecond, Now: func() time.Time { return time.Now().Add(20 * time.Minute) },
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	octx, ostop := context.WithCancel(context.Background())
	odone := make(chan struct{})
	go func() { defer close(odone); _ = other.Run(octx) }()
	waitFor(t, "the other instance's sweep", func() bool { return !h.queues.Exists(h.queue) })
	ostop()
	<-odone

	// The enclave is back while SQS still refuses the deleted queue's
	// name: the row is withheld, for as long as that lasts.
	rq.refuse.Store(true)
	e = h.connect("boot-2", answerDone)
	e.descriptor()
	waitFor(t, "the row to be withheld", func() bool {
		return strings.Count(h.logged(), `"msg":"registry row withheld: the instance queue cannot be created yet","queue":"test-vault-control-i-test"`) >= 2
	})
	if _, ok := h.tables.Instance("i-test"); ok || h.queues.Exists(h.queue) {
		t.Fatal("a registry row or a queue while SQS refuses the name")
	}
	// SQS allows the name again.
	rq.refuse.Store(false)
	waitFor(t, "queue created again", func() bool { return h.queues.Exists(h.queue) })
	h.request("01JBBBBBBBBBBBBBBBBBBBBBBB")
	waitFor(t, "registry row", func() bool { row, ok := h.tables.Instance("i-test"); return ok && row.QueueURL == h.queue })
	if n := ct.orphans.Load(); n != 0 {
		t.Fatalf("%d registry rows written while their queue did not exist", n)
	}
}

// movedQueues is a queue service whose Create, from some moment on,
// answers with another URL than before.
type movedQueues struct {
	*parenttest.Queues
	moved atomic.Bool
}

func (m *movedQueues) Create(ctx context.Context, name string) (string, error) {
	if m.moved.Load() {
		name = "moved-" + name
	}
	return m.Queues.Create(ctx, name)
}

// The check of the queue after a disconnection takes the URL that the
// create returns: the registry row carries it, and requests sent to it
// are received.
func TestQueueCheckTakesTheReturnedURL(t *testing.T) {
	var q *movedQueues
	h := newHarness(t, func(c *parent.Config) { q = &movedQueues{Queues: c.Queues.(*parenttest.Queues)}; c.Queues = q })
	e := h.connect("boot-1", answerDone)
	e.descriptor()
	waitFor(t, "ready", func() bool { return h.p.Health().OK })
	if row, _ := h.tables.Instance("i-test"); row.QueueURL != h.queue {
		t.Fatalf("registry row %+v", row)
	}
	e.conn.Close()
	waitFor(t, "row deleted", func() bool { _, ok := h.tables.Instance("i-test"); return !ok })
	q.moved.Store(true)
	e = h.connect("boot-2", answerDone)
	e.descriptor()
	waitFor(t, "registry row", func() bool { _, ok := h.tables.Instance("i-test"); return ok })
	moved := "http://sqs.test/000000000000/moved-test-vault-control-i-test"
	if row, _ := h.tables.Instance("i-test"); row.QueueURL != moved {
		t.Fatalf("the row names %q; the create returned %q", row.QueueURL, moved)
	}
	h.queue = moved
	h.request("01JAAAAAAAAAAAAAAAAAAAAAAA")
}

// createFails is a queue service whose Create fails on demand.
type createFails struct {
	*parenttest.Queues
	fail atomic.Bool
}

func (c *createFails) Create(ctx context.Context, name string) (string, error) {
	if c.fail.Load() {
		return "", errors.New("sqs create: AccessDenied")
	}
	return c.Queues.Create(ctx, name)
}

// The check of the queue before the registry row never keeps an instance
// out of the registry: if the queue cannot be checked (anything but SQS's
// refusal of a deleted queue's name), the row is written as before.
func TestQueueCheckFailureDoesNotWithholdTheRow(t *testing.T) {
	var q *createFails
	h := newHarness(t, func(c *parent.Config) { q = &createFails{Queues: c.Queues.(*parenttest.Queues)}; c.Queues = q })
	e := h.connect("boot-1", answerDone)
	e.descriptor()
	waitFor(t, "ready", func() bool { return h.p.Health().OK })
	e.conn.Close()
	waitFor(t, "row deleted", func() bool { _, ok := h.tables.Instance("i-test"); return !ok })
	q.fail.Store(true)
	e = h.connect("boot-2", answerDone)
	e.descriptor()
	waitFor(t, "registry row", func() bool { _, ok := h.tables.Instance("i-test"); return ok })
	h.request("01JAAAAAAAAAAAAAAAAAAAAAAA")
	if n := strings.Count(h.logged(), `"msg":"instance queue not checked before the registry row"`); n != 1 {
		t.Fatalf("failed check logged %d times:\n%s", n, h.logged())
	}
}

// goneQueues is a queue service that goes on answering "no such queue"
// after the queue was created again, as SQS may for a while.
type goneQueues struct {
	*parenttest.Queues
	gone    atomic.Bool
	mu      sync.Mutex
	creates []time.Time
}

func (g *goneQueues) Receive(ctx context.Context, url string) ([]parent.QueueMessage, error) {
	if g.gone.Load() {
		return nil, fmt.Errorf("%w: sqs receive: AWS.SimpleQueueService.NonExistentQueue", parent.ErrQueueNotFound)
	}
	return g.Queues.Receive(ctx, url)
}

func (g *goneQueues) Create(ctx context.Context, name string) (string, error) {
	g.mu.Lock()
	g.creates = append(g.creates, time.Now())
	g.mu.Unlock()
	return g.Queues.Create(ctx, name)
}

// A receive that still finds no queue right after the queue was created
// again does not turn into a loop at the speed of the calls: the parent
// waits before the next receive, longer each time, and serves requests
// when the queue is there.
func TestQueueStillMissingAfterRecreateBacksOff(t *testing.T) {
	defer parent.SetQueueLostWaitForTest(40*time.Millisecond, 320*time.Millisecond)()
	var q *goneQueues
	h := newHarness(t, func(c *parent.Config) { q = &goneQueues{Queues: c.Queues.(*parenttest.Queues)}; c.Queues = q })
	e := h.connect("boot-1", answerDone)
	e.descriptor()
	waitFor(t, "ready", func() bool { return h.p.Health().OK })
	q.mu.Lock()
	q.creates = nil
	q.mu.Unlock()
	q.gone.Store(true)
	var creates []time.Time
	waitFor(t, "five recreations", func() bool {
		q.mu.Lock()
		defer q.mu.Unlock()
		creates = append(creates[:0], q.creates...)
		return len(creates) >= 5
	})
	q.gone.Store(false)
	// Between two recreations lies at least the configured wait: 40, 80,
	// 160 and 320 ms (the last is the maximum). A wait is never shorter
	// than asked for, so a slow machine only lengthens the gaps; a loop
	// without a wait, or with one that does not grow, has shorter ones.
	for i, least := range []time.Duration{40 * time.Millisecond, 80 * time.Millisecond, 160 * time.Millisecond, 320 * time.Millisecond} {
		if gap := creates[i+1].Sub(creates[i]); gap < least {
			t.Fatalf("recreation %d came %v after the one before; the wait there is %v", i+2, gap, least)
		}
	}
	h.request("01JAAAAAAAAAAAAAAAAAAAAAAA")
}

// SQS refuses a queue's name for 60 s after its deletion: the parent
// waits that out, as at start, and keeps its heartbeat meanwhile.
func TestQueueRecreatedAfterSQSRefusal(t *testing.T) {
	defer parent.SetQueueRetryForTest(20*time.Millisecond, 50*time.Millisecond, 10*time.Second)()
	h := newHarness(t, nil)
	h.queues.DeletedRecently = 600 * time.Millisecond
	e := h.connect("boot-1", answerDone)
	e.descriptor()
	waitFor(t, "ready", func() bool { return h.p.Health().OK })
	if err := h.queues.Destroy(context.Background(), h.queue); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "queue created again", func() bool { return h.queues.Exists(h.queue) })
	if h.queues.CreateRefusals == 0 {
		t.Fatal("the create was not refused first")
	}
	// One recreation that waited (createQueue), not one failed attempt
	// after another.
	logs := h.logged()
	if n := strings.Count(logs, `"msg":"waiting for SQS to allow recreating the queue"`); n != 1 {
		t.Fatalf("wait logged %d times:\n%s", n, logs)
	}
	if strings.Contains(logs, `"msg":"instance queue not created again"`) || strings.Count(logs, `"msg":"instance queue is missing; creating it again"`) != 1 {
		t.Fatalf("the recreation did not wait for SQS:\n%s", logs)
	}
	if !h.p.Health().OK {
		t.Fatalf("heartbeat stopped while waiting for the queue: %+v", h.p.Health())
	}
	h.request("01JAAAAAAAAAAAAAAAAAAAAAAA")
}

// The AWS backend recognizes a queue that does not exist in both
// protocols' spellings, and nothing else as that.
func TestQueueNotFoundClassified(t *testing.T) {
	for _, c := range []struct {
		err  error
		want bool
	}{
		{&sqstypes.QueueDoesNotExist{}, true},
		{&smithy.GenericAPIError{Code: "AWS.SimpleQueueService.NonExistentQueue"}, true},
		{&smithy.GenericAPIError{Code: "QueueDoesNotExist"}, true},
		{&smithy.GenericAPIError{Code: "AWS.SimpleQueueService.QueueDeletedRecently"}, false},
		{&smithy.GenericAPIError{Code: "AccessDenied"}, false},
		{errors.New("QueueDoesNotExist"), false},
	} {
		if got := parent.QueueNotFoundForTest(c.err); got != c.want {
			t.Errorf("%v: %v", c.err, got)
		}
	}
}
