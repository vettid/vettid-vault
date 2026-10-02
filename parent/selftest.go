package parent

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/vettid/vettid-vault/internal/hostproto"
	"github.com/vettid/vettid-vault/internal/selftest"
)

// SelftestConfig configures the hardware smoke test (docs/SMOKE.md): a
// parent with only a control server, the forwarder, S3 under
// smoke/<run_id>/ and the role's credentials. No queue, tables or leases.
type SelftestConfig struct {
	ControlListener net.Listener
	EgressListener  net.Listener
	Allow           []string
	Resolve         map[string]string
	Objects         Objects
	Creds           CredentialSource
	Request         selftest.Request
	Timeout         time.Duration
	Logger          *slog.Logger
}

// RunSelftest waits for the enclave, asks it to run its self-test and
// returns the report.
func RunSelftest(ctx context.Context, c SelftestConfig) (*selftest.Report, error) {
	if c.Timeout == 0 {
		c.Timeout = 10 * time.Minute
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	reqJSON, err := json.Marshal(c.Request)
	if err != nil {
		return nil, err
	}
	if _, err := selftest.ParseRequest(reqJSON); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	fwd := newForwarder(&Config{EgressListener: c.EgressListener, Allow: c.Allow, Resolve: c.Resolve, Logger: c.Logger})
	go fwd.serve(ctx)
	go func() { <-ctx.Done(); c.ControlListener.Close(); c.EgressListener.Close() }()

	prefix := "smoke/" + c.Request.RunID + "/"
	hello := make(chan *hostproto.Conn, 1)
	for {
		nc, err := c.ControlListener.Accept()
		if err != nil {
			return nil, errors.New("parent: no enclave connected: " + err.Error())
		}
		var conn *hostproto.Conn
		ready := make(chan struct{})
		conn = hostproto.NewConn(nc, func(ctx context.Context, f *hostproto.Frame) [][]byte {
			<-ready
			return selftestHandle(ctx, c, prefix, conn, hello, f)
		}, func(f *hostproto.Frame) {
			if f.Kind == hostproto.KindLog && len(f.Fields) >= 2 {
				c.Logger.Info(truncate(string(f.Fields[1]), 200), "source", "enclave")
			}
		})
		close(ready)
		select {
		case hc := <-hello:
			c.Logger.Info("enclave connected; running the self-test")
			r, err := hc.Call(ctx, hostproto.KindSelftest, reqJSON)
			hc.Close()
			if err != nil || len(r) != 2 || string(r[0]) != hostproto.StatusOK {
				return nil, errors.New("parent: the enclave did not run the self-test")
			}
			var rep selftest.Report
			if err := json.Unmarshal(r[1], &rep); err != nil {
				return nil, errors.New("parent: malformed self-test report")
			}
			return &rep, nil
		case <-conn.Done():
			continue
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func selftestHandle(ctx context.Context, c SelftestConfig, prefix string, conn *hostproto.Conn, hello chan *hostproto.Conn, f *hostproto.Frame) [][]byte {
	key := func(i int) (string, bool) {
		if i >= len(f.Fields) {
			return "", false
		}
		k := string(f.Fields[i])
		return k, strings.HasPrefix(k, prefix) && !strings.Contains(k, "..")
	}
	switch f.Kind {
	case hostproto.KindHello:
		if len(f.Fields) != 2 || !isHex(string(f.Fields[0]), 96) {
			return reply(hostproto.StatusInvalid)
		}
		select {
		case hello <- conn:
		default:
		}
		return reply(hostproto.StatusOK, "selftest", "selftest")
	case hostproto.KindCredentials:
		cr, err := c.Creds.Retrieve(ctx)
		if err != nil {
			return reply(hostproto.StatusError)
		}
		exp := ""
		if !cr.Expires.IsZero() {
			exp = cr.Expires.UTC().Format(time.RFC3339)
		}
		return reply(hostproto.StatusOK, cr.AccessKeyID, cr.SecretAccessKey, cr.SessionToken, exp)
	case hostproto.KindStoreGet:
		k, ok := key(0)
		if !ok || len(f.Fields) != 1 {
			return reply(hostproto.StatusInvalid)
		}
		b, v, err := c.Objects.Get(ctx, k)
		if err != nil {
			return storeErr(err)
		}
		return [][]byte{[]byte(hostproto.StatusOK), b, []byte(v)}
	case hostproto.KindStorePut:
		k, ok := key(0)
		if !ok || len(f.Fields) != 3 {
			return reply(hostproto.StatusInvalid)
		}
		v, err := c.Objects.Put(ctx, k, f.Fields[1], string(f.Fields[2]))
		if err != nil {
			return storeErr(err)
		}
		return reply(hostproto.StatusOK, v)
	case hostproto.KindStoreDelete:
		k, ok := key(0)
		if !ok || len(f.Fields) != 2 {
			return reply(hostproto.StatusInvalid)
		}
		if err := c.Objects.Delete(ctx, k, string(f.Fields[1])); err != nil {
			return storeErr(err)
		}
		return reply(hostproto.StatusOK)
	}
	return reply(hostproto.StatusInvalid)
}

// SelftestVerdict lists the unexpected results of a report: required
// checks that failed, and a key-policy refusal by another check than
// expected (0: any).
func SelftestVerdict(r *selftest.Report, expectKeyCheck int) []string {
	var bad []string
	for _, c := range r.Checks {
		if c.Required && !c.OK {
			bad = append(bad, c.Name+": "+c.Detail)
		}
	}
	if expectKeyCheck != 0 && r.KeyPolicyCheck != expectKeyCheck {
		bad = append(bad, "kms.policy_check: refused by check "+itoa(r.KeyPolicyCheck)+", expected check "+itoa(expectKeyCheck))
	}
	if len(r.Checks) == 0 {
		bad = append(bad, "empty report")
	}
	return bad
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}
