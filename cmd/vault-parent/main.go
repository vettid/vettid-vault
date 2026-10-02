// Command vault-parent runs on the enclave's EC2 host (VAULT-PLAN V3):
// the vsock control server and egress forwarder for the enclave, the
// instance's SQS queue and consumer, the instance registry, vault leases,
// response slots and the vault data bucket (package parent). It is
// outside the trusted code base and links the AWS SDK; the enclave never
// does.
//
//	vault-parent -region us-east-1 -bucket B -table-vaults T1 -table-instances T2 \
//	    -table-requests T3 -queue-prefix vettid-org-vault-control-
//
// Development and integration tests use -control-tcp/-egress-tcp instead
// of vsock, -aws-endpoint for LocalStack, -static-credentials and
// -resolve to map allowlisted hosts to local test servers.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/ec2rolecreds"

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
	backend, err := parent.NewAWS(parent.AWSConfig{Region: *region, Credentials: cp, Endpoint: *endpoint, Bucket: *bucket,
		VaultsTable: *tVaults, InstancesTable: *tInstances, RequestsTable: *tRequests, DLQARN: *dlq,
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
