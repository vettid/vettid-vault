package parent_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/aws/smithy-go"

	"github.com/vettid/vettid-vault/internal/parenttest"
	"github.com/vettid/vettid-vault/parent"
)

const testQueue = "http://sqs.test/000000000000/test-vault-control-i-test"

// A restart within SQS's 60 s after a clean stop waits for the queue name
// instead of exiting (systemd would restart-loop), and says so once.
func TestQueueDeletedRecentlyWaits(t *testing.T) {
	defer parent.SetQueueRetryForTest(50*time.Millisecond, 100*time.Millisecond, 10*time.Second)()
	q := parenttest.NewQueues()
	q.DeletedRecently = 400 * time.Millisecond
	ctx := context.Background()
	u, err := q.Create(ctx, "test-vault-control-i-test")
	if err != nil {
		t.Fatal(err)
	}
	if err := q.Destroy(ctx, u); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Create(ctx, "test-vault-control-i-test"); !errors.Is(err, parent.ErrQueueDeletedRecently) {
		t.Fatalf("fake SQS: %v", err)
	}
	h := newHarness(t, func(c *parent.Config) { c.Queues = q })
	waitFor(t, "queue recreated", func() bool { return q.Send(testQueue, "{}") })
	if q.CreateRefusals < 3 {
		t.Fatalf("refusals: %d", q.CreateRefusals)
	}
	h.logMu.Lock()
	logs := h.logs.String()
	h.logMu.Unlock()
	if n := strings.Count(logs, `"level":"INFO","msg":"waiting for SQS to allow recreating the queue"`); n != 1 {
		t.Fatalf("wait logged %d times:\n%s", n, logs)
	}
	if !strings.Contains(logs, `"msg":"queue ready"`) {
		t.Fatalf("no queue ready:\n%s", logs)
	}
}

func runParent(t *testing.T, qs parent.Queues) (string, error) {
	t.Helper()
	var mu sync.Mutex
	logs := &bytes.Buffer{}
	p, err := parent.New(parent.Config{InstanceID: "i-test", QueuePrefix: "test-vault-control-", ControlListener: listen(t), EgressListener: listen(t),
		Objects: parenttest.NewObjects(), Queues: qs, Tables: parenttest.NewTables(), Creds: parenttest.StaticCreds{AccessKeyID: "AK", SecretAccessKey: "SK"},
		SweepInterval: -1, Logger: slog.New(slog.NewJSONHandler(lockedWriter{&mu, logs}, nil))})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = p.Run(ctx)
	mu.Lock()
	defer mu.Unlock()
	return logs.String(), err
}

// The wait is bounded: a queue name SQS keeps refusing ends the run.
func TestQueueDeletedRecentlyGivesUp(t *testing.T) {
	defer parent.SetQueueRetryForTest(20*time.Millisecond, 50*time.Millisecond, 300*time.Millisecond)()
	q := parenttest.NewQueues()
	q.DeletedRecently = time.Hour
	u, _ := q.Create(context.Background(), "test-vault-control-i-test")
	_ = q.Destroy(context.Background(), u)
	start := time.Now()
	_, err := runParent(t, q)
	if !errors.Is(err, parent.ErrQueueDeletedRecently) {
		t.Fatalf("run: %v", err)
	}
	if d := time.Since(start); d < 300*time.Millisecond || d > 3*time.Second {
		t.Fatalf("gave up after %v", d)
	}
}

type failingQueues struct {
	*parenttest.Queues
	calls int
}

func (f *failingQueues) Create(context.Context, string) (string, error) {
	f.calls++
	return "", errors.New("sqs create: AccessDenied")
}

// Other create errors fail at once, as before.
func TestQueueCreateOtherErrorFails(t *testing.T) {
	f := &failingQueues{Queues: parenttest.NewQueues()}
	logs, err := runParent(t, f)
	if err == nil || errors.Is(err, parent.ErrQueueDeletedRecently) || f.calls != 1 {
		t.Fatalf("run: %v after %d creates", err, f.calls)
	}
	if strings.Contains(logs, "waiting for SQS") {
		t.Fatal("waited on another error")
	}
}

// The AWS backend recognizes SQS's refusal in both protocols' spellings.
func TestQueueDeletedRecentlyClassified(t *testing.T) {
	for _, c := range []struct {
		err  error
		want bool
	}{
		{&sqstypes.QueueDeletedRecently{}, true},
		{&smithy.GenericAPIError{Code: "AWS.SimpleQueueService.QueueDeletedRecently"}, true},
		{&smithy.GenericAPIError{Code: "QueueDeletedRecently"}, true},
		{&smithy.GenericAPIError{Code: "AWS.SimpleQueueService.NonExistentQueue"}, false},
		{errors.New("QueueDeletedRecently"), false},
	} {
		if got := parent.QueueDeletedRecentlyForTest(c.err); got != c.want {
			t.Errorf("%v: %v", c.err, got)
		}
	}
}
