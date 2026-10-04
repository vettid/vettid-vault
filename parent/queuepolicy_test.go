package parent

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

const okPolicy = `{"Version":"2012-10-17","Statement":[{"Sid":"MemberApiSend","Effect":"Allow",
"Principal":{"AWS":["arn:aws:iam::111122223333:role/member-api"]},"Action":"sqs:SendMessage",
"Resource":"arn:aws:sqs:us-east-1:444455556666:vettid-org-vault-control-*"}]}`

func TestValidateQueuePolicy(t *testing.T) {
	if err := ValidateQueuePolicy(okPolicy); err != nil {
		t.Fatal(err)
	}
	if err := ValidateQueuePolicy(`{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":{"AWS":"arn:aws:iam::111122223333:root"},"Action":"sqs:*"}]}`); err != nil {
		t.Fatal(err)
	}
	stmt := func(principal string) string {
		return `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":` + principal + `,"Action":"sqs:SendMessage"}]}`
	}
	for name, p := range map[string]string{
		"empty":            "",
		"not json":         "{",
		"array":            `[]`,
		"no version":       `{"Statement":[{"Effect":"Allow"}]}`,
		"null version":     `{"Version":null,"Statement":[{"Effect":"Allow"}]}`,
		"no statement":     `{"Version":"2012-10-17"}`,
		"empty statement":  `{"Version":"2012-10-17","Statement":[]}`,
		"statement object": `{"Version":"2012-10-17","Statement":{"Effect":"Allow"}}`,
		"statement null":   `{"Version":"2012-10-17","Statement":[null]}`,
		"statement string": `{"Version":"2012-10-17","Statement":["x"]}`,
		"principal *":      stmt(`"*"`),
		"AWS *":            stmt(`{"AWS":"*"}`),
		"AWS [*]":          stmt(`{"AWS":["arn:aws:iam::111122223333:root","*"]}`),
		"principal number": stmt(`1`),
		"too long":         `{"Version":"2012-10-17","Statement":[{"Sid":"` + strings.Repeat("a", MaxQueuePolicy) + `"}]}`,
	} {
		if err := ValidateQueuePolicy(p); !errors.Is(err, ErrQueuePolicy) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

type fakeSSM struct {
	val *string
	err error
}

func (f fakeSSM) GetParameter(_ context.Context, in *ssm.GetParameterInput, _ ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &ssm.GetParameterOutput{Parameter: &ssmtypes.Parameter{Name: in.Name, Value: f.val}}, nil
}

func TestLoadQueuePolicy(t *testing.T) {
	ctx := context.Background()
	const name = "/vettid-org/prod/vault/control-queue-policy"
	p, err := LoadQueuePolicy(ctx, fakeSSM{val: aws.String(okPolicy)}, name)
	if err != nil || p != okPolicy {
		t.Fatalf("ok: %q %v", p, err)
	}
	for what, g := range map[string]fakeSSM{
		"missing":  {err: &ssmtypes.ParameterNotFound{Message: aws.String("nope")}},
		"empty":    {val: aws.String("")},
		"nil":      {},
		"invalid":  {val: aws.String("{not json")},
		"wildcard": {val: aws.String(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"sqs:SendMessage"}]}`)},
	} {
		if p, err := LoadQueuePolicy(ctx, g, name); !errors.Is(err, ErrQueuePolicy) || p != "" {
			t.Errorf("%s: %q %v", what, p, err)
		}
	}
	if _, err := LoadQueuePolicy(ctx, fakeSSM{err: errors.New("network")}, name); err == nil {
		t.Error("service error accepted")
	}
	if _, err := LoadQueuePolicy(ctx, fakeSSM{val: aws.String(okPolicy)}, ""); !errors.Is(err, ErrQueuePolicy) {
		t.Errorf("no name: %v", err)
	}
}

// sameJSON compares two JSON documents semantically (LocalStack and SQS
// may reformat a policy).
func sameJSON(a, b string) bool {
	var x, y any
	if json.Unmarshal([]byte(a), &x) != nil || json.Unmarshal([]byte(b), &y) != nil {
		return false
	}
	return reflect.DeepEqual(x, y)
}

func TestSameJSON(t *testing.T) {
	if !sameJSON(okPolicy, strings.ReplaceAll(okPolicy, "\n", " ")) || sameJSON(okPolicy, `{}`) {
		t.Fatal("sameJSON")
	}
}

type countingRT struct{ n atomic.Int32 }

func (c *countingRT) RoundTrip(*http.Request) (*http.Response, error) {
	c.n.Add(1)
	return nil, errors.New("no network in this test")
}

// Without a policy the backend creates no queue and makes no call.
func TestCreateWithoutPolicy(t *testing.T) {
	rt := &countingRT{}
	a, err := NewAWS(AWSConfig{Region: "us-east-1", Credentials: credentials.NewStaticCredentialsProvider("a", "b", ""),
		Endpoint: "http://127.0.0.1:1", Bucket: "b", VaultsTable: "v", InstancesTable: "i", RequestsTable: "r",
		HTTPClient: &http.Client{Transport: rt}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Create(context.Background(), "q"); !errors.Is(err, ErrConfig) {
		t.Fatalf("create without a policy: %v", err)
	}
	if rt.n.Load() != 0 {
		t.Fatal("an API call was made")
	}
}
