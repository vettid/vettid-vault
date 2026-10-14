package parent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

func jsonResponse(r *http.Request, status int, header http.Header, body string) *http.Response {
	if header == nil {
		header = http.Header{}
	}
	header.Set("Content-Type", "application/x-amz-json-1.0")
	return &http.Response{StatusCode: status, Status: http.StatusText(status), Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1, Request: r,
		Header: header, ContentLength: int64(len(body)), Body: io.NopCloser(strings.NewReader(body))}
}

const testPolicy = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:root"},"Action":"sqs:SendMessage","Resource":"*"}]}`

// Every queue the parent creates, the first and one created again, is
// asked for with the access policy, the redrive to the dead-letter queue
// and the other attributes: a queue without the policy would refuse the
// member API, and one without the redrive would keep a poisonous message.
func TestCreateQueueAttributes(t *testing.T) {
	var got struct {
		QueueName  string
		Attributes map[string]string
	}
	calls := 0
	a := testAWS(t, AWSConfig{QueuePolicy: testPolicy, DLQARN: "arn:aws:sqs:us-east-1:000000000000:dead"}, func(r *http.Request) (*http.Response, error) {
		if tg := r.Header.Get("X-Amz-Target"); tg != "AmazonSQS.CreateQueue" {
			t.Errorf("call %q", tg)
		}
		calls++
		b, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(b, &got); err != nil {
			t.Error(err)
		}
		return jsonResponse(r, 200, nil, `{"QueueUrl":"http://aws.test/000000000000/q-i1"}`), nil
	})
	want := map[string]string{
		"Policy":                        testPolicy,
		"RedrivePolicy":                 `{"deadLetterTargetArn":"arn:aws:sqs:us-east-1:000000000000:dead","maxReceiveCount":"3"}`,
		"MessageRetentionPeriod":        "300",
		"VisibilityTimeout":             "120",
		"ReceiveMessageWaitTimeSeconds": "20",
		"SqsManagedSseEnabled":          "true",
	}
	for i := 0; i < 2; i++ { // the second create is the one after a deletion
		got.QueueName, got.Attributes = "", nil
		u, err := a.Create(context.Background(), "q-i1")
		if err != nil || u != "http://aws.test/000000000000/q-i1" || got.QueueName != "q-i1" {
			t.Fatalf("create: %q %v, name %q", u, err, got.QueueName)
		}
		if len(got.Attributes) != len(want) {
			t.Fatalf("attributes %v", got.Attributes)
		}
		for k, v := range want {
			if got.Attributes[k] != v {
				t.Errorf("attribute %s: %q", k, got.Attributes[k])
			}
		}
	}
	// Without a dead-letter queue there is no redrive; without a policy
	// there is no call.
	a.cfg.DLQARN = ""
	got.Attributes = nil
	if _, err := a.Create(context.Background(), "q-i1"); err != nil || got.Attributes["RedrivePolicy"] != "" || got.Attributes["Policy"] != testPolicy {
		t.Fatalf("create without a dead-letter queue: %v %v", err, got.Attributes)
	}
	a.cfg.QueuePolicy = ""
	n := calls
	if _, err := a.Create(context.Background(), "q-i1"); !errors.Is(err, ErrConfig) || calls != n {
		t.Fatalf("create without a policy: %v after %d calls", err, calls-n)
	}
}

// A receive from a queue that does not exist is ErrQueueNotFound, in
// either protocol's spelling of the code, with the text every failed
// receive has in the log; another failure is not.
func TestReceiveQueueNotFound(t *testing.T) {
	for _, c := range []struct {
		name   string
		header http.Header
		body   string
		gone   bool
	}{
		{"JSON protocol", nil, `{"__type":"com.amazonaws.sqs#QueueDoesNotExist","message":"The specified queue does not exist."}`, true},
		{"query-compatible code", http.Header{"X-Amzn-Query-Error": {"AWS.SimpleQueueService.NonExistentQueue;Sender"}},
			`{"__type":"com.amazonaws.sqs#QueueDoesNotExist","message":"The specified queue does not exist."}`, true},
		{"access denied", nil, `{"__type":"com.amazonaws.sqs#AccessDeniedException","message":"no"}`, false},
		{"deleted recently", nil, `{"__type":"com.amazonaws.sqs#QueueDeletedRecently","message":"wait"}`, false},
	} {
		a := testAWS(t, AWSConfig{}, func(r *http.Request) (*http.Response, error) {
			return jsonResponse(r, 400, c.header.Clone(), c.body), nil
		})
		_, err := a.Receive(context.Background(), "http://aws.test/000000000000/q-i1")
		if err == nil || errors.Is(err, ErrQueueNotFound) != c.gone {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if !strings.HasPrefix(err.Error(), "sqs receive: ") || strings.Contains(err.Error(), "parent:") {
			t.Errorf("%s: the error's text changed: %q", c.name, err)
		}
	}
}
