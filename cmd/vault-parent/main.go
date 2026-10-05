// Command vault-parent runs on the enclave's EC2 host (VAULT-PLAN V3):
// the vsock control server and egress forwarder for the enclave, the
// instance's SQS queue and consumer, the instance registry, vault leases,
// response slots and the vault data bucket (package parent). It is
// outside the trusted code base and links the AWS SDK; the enclave never
// does.
//
//	vault-parent -region us-east-1 -bucket B -table-vaults T1 -table-instances T2 \
//	    -table-requests T3 -queue-prefix vettid-org-vault-control- \
//	    -queue-policy-param /vettid-org/prod/vault/control-queue-policy
//
// The instance queue gets the access policy vettid.org publishes in that
// SSM parameter; without a valid one the parent exits before creating
// anything (fail closed). deploy/host runs it under systemd.
//
// Development and integration tests use -control-tcp/-egress-tcp instead
// of vsock, -aws-endpoint for LocalStack, -static-credentials and
// -resolve to map allowlisted hosts to local test servers.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/ec2rolecreds"

	"github.com/vettid/vettid-vault/internal/selftest"
	"github.com/vettid/vettid-vault/internal/vsock"
	"github.com/vettid/vettid-vault/parent"
)

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func main() {
	var (
		instanceID   = flag.String("instance-id", "", "instance id ([A-Za-z0-9_-]{1,48}; default: random vi-<hex>)")
		region       = flag.String("region", "", "AWS region (sealing keys and KMS endpoint)")
		bucket       = flag.String("bucket", "", "vault data bucket")
		tVaults      = flag.String("table-vaults", "", "vaults table")
		tInstances   = flag.String("table-instances", "", "vault-instances table")
		tRequests    = flag.String("table-requests", "", "vault-requests table")
		queuePrefix  = flag.String("queue-prefix", "vettid-org-vault-control-", "queue name prefix")
		dlq          = flag.String("dlq-arn", "", "dead-letter queue ARN (optional)")
		policyParam  = flag.String("queue-policy-param", "", "SSM parameter holding the control queue's access policy (vettid.org /vettid-org/<stage>/vault/control-queue-policy); required except in -selftest")
		relayHost    = flag.String("relay-host", "relay.vettid.org", "relay host on the egress allowlist")
		controlPort  = flag.Uint("control-port", 5000, "vsock control port")
		egressPort   = flag.Uint("egress-port", 5001, "vsock egress port")
		controlTCP   = flag.String("control-tcp", "", "development: control listen address (TCP instead of vsock)")
		egressTCP    = flag.String("egress-tcp", "", "development: egress listen address (TCP instead of vsock)")
		endpoint     = flag.String("aws-endpoint", "", "development: endpoint for every AWS service (LocalStack)")
		staticCreds  = flag.Bool("static-credentials", false, "development: credentials from AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY/AWS_SESSION_TOKEN instead of the instance role")
		health       = flag.String("health", "127.0.0.1:8081", "health endpoint address (empty: none)")
		leaseRenew   = flag.Duration("lease-renew", 60*time.Second, "lease renewal interval (§11.1)")
		leaseLength  = flag.Duration("lease-length", 180*time.Second, "lease length (§11.1)")
		heartbeat    = flag.Duration("heartbeat", 20*time.Second, "registry heartbeat interval (≤ 30 s, §11.1)")
		sweepEvery   = flag.Duration("sweep", 10*time.Minute, "stale queue sweep interval (negative: never)")
		debug        = flag.Bool("debug", false, "debug logging")
		selftestMode = flag.Bool("selftest", false, "hardware smoke test (docs/SMOKE.md): run the enclave's self-test, print the report as JSON, exit non-zero on any unexpected result")
		smokeKey     = flag.String("smoke-key-arn", "", "selftest: the deletable test KMS key")
		smokeAccount = flag.String("smoke-account", "", "selftest: the test key's account")
		runID        = flag.String("run-id", "", "selftest: S3 prefix smoke/<run-id>/ ([a-z0-9-]; default: random)")
		expectCheck  = flag.Int("expect-key-check", 6, "selftest: the §11.10.7 check expected to refuse the test key (0: any)")
		smokeTimeout = flag.Duration("selftest-timeout", 10*time.Minute, "selftest: overall timeout (with -capacity: the budget plus 20m)")
		capVaults    = flag.Int("capacity", 0, "selftest: also measure capacity with up to N synthetic vault processes (docs/SMOKE.md; 0: off)")
		capStateKiB  = flag.Int("capacity-state-kib", 1024, "selftest -capacity: decrypted state per synthetic vault (KiB)")
		capFloorMiB  = flag.Int("capacity-floor-mib", 0, "selftest -capacity: raise the memory floor (MiB; never below 15% of the enclave's memory)")
		capUnlocks   = flag.String("capacity-unlocks", "1,2,4", "selftest -capacity: concurrent-unlock levels to time")
		capSamples   = flag.Int("capacity-unlock-samples", 8, "selftest -capacity: unlocks timed per level")
		capSettle    = flag.Duration("capacity-settle", 180*time.Second, "selftest -capacity: wait for memory to come back at the floor, and before the steady-state measurement")
		capIdle      = flag.Duration("capacity-idle", 60*time.Second, "selftest -capacity: idle CPU measurement window")
		capBudget    = flag.Duration("capacity-budget", 90*time.Minute, "selftest -capacity: time for the whole measurement (the fill stops early enough)")
		resolve      multi
		extraAllowed multi
	)
	flag.Var(&resolve, "resolve", "development: host=addr, dial addr for an allowlisted host (repeatable)")
	flag.Var(&extraAllowed, "allow", "development: additional allowlisted host (repeatable)")
	flag.Parse()

	lvl := slog.LevelInfo
	if *debug {
		lvl = slog.LevelDebug
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: lvl})).With("component", "vault-parent")
	fail := func(msg string, err error) {
		log.Error(msg, "error", err.Error())
		os.Exit(1)
	}
	if *instanceID == "" {
		b := make([]byte, 8)
		_, _ = rand.Read(b)
		*instanceID = "vi-" + hex.EncodeToString(b)
	}
	if *region == "" {
		fail("configuration", errors.New("-region is required"))
	}

	var cp aws.CredentialsProvider
	if *staticCreds {
		id, secret := os.Getenv("AWS_ACCESS_KEY_ID"), os.Getenv("AWS_SECRET_ACCESS_KEY")
		if id == "" || secret == "" {
			fail("configuration", errors.New("-static-credentials needs AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY"))
		}
		cp = credentials.NewStaticCredentialsProvider(id, secret, os.Getenv("AWS_SESSION_TOKEN"))
	} else {
		cp = aws.NewCredentialsCache(ec2rolecreds.New())
	}
	var (
		queuePolicy string
		err         error
	)
	if *selftestMode {
		// The smoke test touches no table and creates no queue; NewAWS
		// wants names.
		for _, t := range []*string{tVaults, tInstances, tRequests} {
			if *t == "" {
				*t = "unused-in-selftest"
			}
		}
	} else {
		// Fail closed: no queue without vettid.org's policy.
		if *policyParam == "" {
			fail("configuration", errors.New("-queue-policy-param is required"))
		}
		pctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		queuePolicy, err = parent.LoadQueuePolicy(pctx, parent.NewSSM(*region, *endpoint, cp, nil), *policyParam)
		cancel()
		if err != nil {
			fail("control-queue policy", err)
		}
		log.Info("control-queue policy loaded", "parameter", *policyParam, "bytes", len(queuePolicy))
	}
	backend, err := parent.NewAWS(parent.AWSConfig{Region: *region, Credentials: cp, Endpoint: *endpoint, Bucket: *bucket,
		VaultsTable: *tVaults, InstancesTable: *tInstances, RequestsTable: *tRequests, DLQARN: *dlq, QueuePolicy: queuePolicy,
		// LocalStack does not implement If-Match on DeleteObject.
		EmulateConditionalDelete: *endpoint != ""})
	if err != nil {
		fail("configuration", err)
	}

	listen := func(tcp string, port uint) (net.Listener, error) {
		if tcp != "" {
			return net.Listen("tcp", tcp)
		}
		return vsock.Listen(uint32(port))
	}
	cl, err := listen(*controlTCP, *controlPort)
	if err != nil {
		fail("control listener", err)
	}
	el, err := listen(*egressTCP, *egressPort)
	if err != nil {
		fail("egress listener", err)
	}
	res := map[string]string{}
	for _, r := range resolve {
		h, a, ok := strings.Cut(r, "=")
		if !ok {
			fail("configuration", fmt.Errorf("bad -resolve %q", r))
		}
		res[h] = a
	}
	var capReq *selftest.CapacityRequest
	if *capVaults != 0 {
		if !*selftestMode {
			fail("configuration", errors.New("-capacity runs only with -selftest"))
		}
		capReq, err = capacityRequest(*capVaults, *capStateKiB, *capFloorMiB, *capUnlocks, *capSamples, *capSettle, *capIdle, *capBudget)
		if err != nil {
			fail("configuration", err)
		}
		timeoutSet := false
		flag.Visit(func(f *flag.Flag) { timeoutSet = timeoutSet || f.Name == "selftest-timeout" })
		if !timeoutSet {
			*smokeTimeout = *capBudget + 20*time.Minute
		}
	}
	if *selftestMode {
		os.Exit(runSelftest(log, cl, el, append(parent.DefaultAllow(*relayHost, *region), extraAllowed...), res, backend, parent.ProviderCredentials{P: cp},
			selftest.Request{RunID: *runID, KeyARN: *smokeKey, Account: *smokeAccount, Region: *region, Capacity: capReq}, *expectCheck, *smokeTimeout))
	}
	p, err := parent.New(parent.Config{
		InstanceID: *instanceID, QueuePrefix: *queuePrefix, DLQARN: *dlq,
		ControlListener: cl, EgressListener: el,
		Allow:   append(parent.DefaultAllow(*relayHost, *region), extraAllowed...),
		Resolve: res,
		Objects: backend, Queues: backend, Tables: backend, Creds: parent.ProviderCredentials{P: cp},
		HealthAddr: *health, Heartbeat: *heartbeat, LeaseLength: *leaseLength, LeaseRenew: *leaseRenew, SweepInterval: *sweepEvery,
		Logger: log,
	})
	if err != nil {
		fail("configuration", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	log.Info("parent starting", "instance_id", *instanceID, "control", cl.Addr().String(), "egress", el.Addr().String())
	if err := p.Run(ctx); err != nil {
		fail("parent stopped", err)
	}
}

// runSelftest runs the hardware smoke test and prints the report.
func runSelftest(log *slog.Logger, cl, el net.Listener, allow []string, res map[string]string, obj parent.Objects, creds parent.CredentialSource,
	req selftest.Request, expectCheck int, timeout time.Duration) int {
	if req.RunID == "" {
		b := make([]byte, 6)
		_, _ = rand.Read(b)
		req.RunID = "run-" + hex.EncodeToString(b)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	log.Info("selftest: waiting for the enclave", "run_id", req.RunID)
	rep, err := parent.RunSelftest(ctx, parent.SelftestConfig{ControlListener: cl, EgressListener: el, Allow: allow, Resolve: res,
		Objects: obj, Creds: creds, Request: req, Timeout: timeout, Logger: log})
	if err != nil {
		log.Error("selftest failed", "error", err.Error())
		fmt.Println(`{"result":"FAIL","error":` + strconv.Quote(err.Error()) + `}`)
		return 1
	}
	bad := parent.SelftestVerdict(rep, expectCheck)
	out := map[string]any{"result": "PASS", "run_id": req.RunID, "report": rep}
	if len(bad) > 0 {
		out["result"], out["unexpected"] = "FAIL", bad
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(b))
	for _, c := range rep.Checks {
		status := "PASS"
		if !c.OK {
			status = "FAIL"
			if !c.Required {
				status = "INFO"
			}
		}
		fmt.Fprintf(os.Stderr, "%-4s %s %s\n", status, c.Name, c.Detail)
	}
	for _, l := range rep.Capacity.Lines() {
		fmt.Fprintln(os.Stderr, l)
	}
	if len(bad) > 0 {
		return 1
	}
	return 0
}

// capacityRequest builds the capacity measurement's parameters from the
// flags (validated again, with the same rules, by the enclave).
func capacityRequest(n, stateKiB, floorMiB int, unlocks string, samples int, settle, idle, budget time.Duration) (*selftest.CapacityRequest, error) {
	c := &selftest.CapacityRequest{MaxVaults: n, StateKiB: stateKiB, FloorMiB: floorMiB, UnlockSamples: samples,
		SettleSeconds: int(settle / time.Second), IdleSeconds: int(idle / time.Second), BudgetMinutes: int(budget / time.Minute)}
	if settle < time.Second || idle < time.Second || budget < time.Minute {
		return nil, errors.New("-capacity-settle and -capacity-idle must be at least 1s, -capacity-budget at least 1m")
	}
	for _, u := range strings.Split(unlocks, ",") {
		v, err := strconv.Atoi(strings.TrimSpace(u))
		if err != nil {
			return nil, fmt.Errorf("bad -capacity-unlocks %q", unlocks)
		}
		c.UnlockConcurrency = append(c.UnlockConcurrency, v)
	}
	b, _ := json.Marshal(selftest.Request{RunID: "check", KeyARN: "x", Account: "000000000000", Region: "us-east-1", Capacity: c})
	if _, err := selftest.ParseRequest(b); err != nil {
		return nil, errors.New("bad -capacity parameters (docs/SMOKE.md has the limits)")
	}
	return c, nil
}
