package parent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
)

// MaxQueuePolicy is SQS's limit on the Policy attribute.
const MaxQueuePolicy = 20480

// ErrQueuePolicy is a missing or unacceptable control-queue policy.
var ErrQueuePolicy = errors.New("parent: invalid control-queue policy")

// ValidateQueuePolicy checks the control-queue policy vettid.org
// publishes (SSM /vettid-org/<stage>/vault/control-queue-policy): a JSON
// object of at most 20480 bytes with a Version and a non-empty Statement
// array of objects, none of which names an anonymous principal ("*" or
// {"AWS": "*"}). It does not judge the statements otherwise; the policy
// is vettid.org's.
func ValidateQueuePolicy(p string) error {
	if p == "" || len(p) > MaxQueuePolicy {
		return fmt.Errorf("%w: empty or over %d bytes", ErrQueuePolicy, MaxQueuePolicy)
	}
	var doc struct {
		Version   json.RawMessage
		Statement []map[string]json.RawMessage
	}
	if err := json.Unmarshal([]byte(p), &doc); err != nil {
		return fmt.Errorf("%w: not a JSON object with a Statement array of objects", ErrQueuePolicy)
	}
	if len(doc.Version) == 0 || string(doc.Version) == "null" || len(doc.Statement) == 0 {
		return fmt.Errorf("%w: no Version or no Statement", ErrQueuePolicy)
	}
	for i, st := range doc.Statement {
		if st == nil {
			return fmt.Errorf("%w: statement %d is not an object", ErrQueuePolicy, i)
		}
		if anonymous(st["Principal"]) {
			return fmt.Errorf("%w: statement %d has a wildcard principal", ErrQueuePolicy, i)
		}
	}
	return nil
}

// anonymous reports a "*" principal, an {"AWS": "*"} one, or "*" in an
// AWS principal array.
func anonymous(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s == "*"
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return true // neither a string nor an object: refuse
	}
	for _, v := range m {
		if json.Unmarshal(v, &s) == nil {
			if s == "*" {
				return true
			}
			continue
		}
		var a []string
		if json.Unmarshal(v, &a) != nil {
			return true
		}
		for _, x := range a {
			if x == "*" {
				return true
			}
		}
	}
	return false
}

// ParameterGetter is the SSM call LoadQueuePolicy needs (*ssm.Client).
type ParameterGetter interface {
	GetParameter(ctx context.Context, in *ssm.GetParameterInput, opts ...func(*ssm.Options)) (*ssm.GetParameterOutput, error)
}

// NewSSM builds the SSM client the parent reads its queue policy with
// (endpoint: LocalStack in tests).
func NewSSM(region, endpoint string, creds aws.CredentialsProvider, hc *http.Client) *ssm.Client {
	ac := aws.Config{Region: region, Credentials: creds}
	if hc != nil {
		ac.HTTPClient = hc
	}
	return ssm.NewFromConfig(ac, func(o *ssm.Options) {
		if endpoint != "" {
			o.BaseEndpoint = aws.String(endpoint)
		}
	})
}

// LoadQueuePolicy reads the control-queue policy parameter and validates
// it. A missing parameter, an empty value or an invalid policy is an
// error: the parent then creates no queue (fail closed).
func LoadQueuePolicy(ctx context.Context, g ParameterGetter, name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("%w: no parameter name", ErrQueuePolicy)
	}
	out, err := g.GetParameter(ctx, &ssm.GetParameterInput{Name: aws.String(name)})
	if err != nil {
		if apiCode(err) == "ParameterNotFound" {
			return "", fmt.Errorf("%w: parameter %s not found", ErrQueuePolicy, name)
		}
		return "", errClass("ssm get parameter", err)
	}
	if out == nil || out.Parameter == nil || aws.ToString(out.Parameter.Value) == "" {
		return "", fmt.Errorf("%w: parameter %s is empty", ErrQueuePolicy, name)
	}
	p := aws.ToString(out.Parameter.Value)
	if err := ValidateQueuePolicy(p); err != nil {
		return "", err
	}
	return p, nil
}
