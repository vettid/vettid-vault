//go:build devenclave

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"

	"github.com/vettid/vettid-vault/enclave/awskms"
	"github.com/vettid/vettid-vault/internal/enclavetest"
	"github.com/vettid/vettid-vault/internal/memberapitest"
	"github.com/vettid/vettid-vault/internal/relaytest"
	"github.com/vettid/vettid-vault/parent"
	"github.com/vettid/vettid-vault/vms/manifest"
)

const (
	relayHost      = "relay.vettid.test"
	relayURL       = "https://" + relayHost
	region         = enclavetest.KMSRegion
	kmsHost        = "kms." + region + ".amazonaws.com"
	gHost          = "android.googleapis.com"
	peerGUID       = "peer-vaultctl"
	peerPIN        = "24680135"
	release        = 3
	localstackURL  = "http://127.0.0.1:4566"
	composeProject = "vettid-devstack"
	childProcs     = "GOMAXPROCS=2"
)

type stack struct {
	opts   *options
	src    string
	policy *enclavetest.DevDevicePolicy
	binDir string
	runDir string
	logDir string

	cleanups []func()
	stopping atomic.Bool
	died     chan error
	started  time.Time

	ep     string
	bucket string
	tables memberapitest.Tables
	s3     *s3.Client
	w      *enclavetest.World

	relayL, apiL, ctlL net.Listener
	relayTLS           string // the TLS front (relay.vettid.test) for the enclave and vaultctl
	kmsAddr, gAddr     string
	parentBin, enclBin string
	ctlBin             string
	parentArgs         []string

	// The recovery clock (-recovery-skew): its offset from real time, in
	// the member API stand-in and, through recClock, the dev enclave.
	recOff   atomic.Int64
	recClock string
	recMu    sync.Mutex

	peerState  string
	vaultctlFn func(args ...string) (string, error)
	peerMu     sync.Mutex
	peerEvents []map[string]any
}

func (s *stack) logf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "%s devstack: %s\n", time.Now().UTC().Format("15:04:05.000"), fmt.Sprintf(format, a...))
}

func (s *stack) cleanup(f func()) { s.cleanups = append(s.cleanups, f) }

// close stops everything, last started first.
func (s *stack) close() {
	s.stopping.Store(true)
	for i := len(s.cleanups) - 1; i >= 0; i-- {
		s.cleanups[i]()
	}
	s.cleanups = nil
}

func (s *stack) fail(err error) {
	if s.stopping.Load() {
		return
	}
	select {
	case s.died <- err:
	default:
	}
}

func (s *stack) start(ctx context.Context) error {
	s.died = make(chan error, 4)
	s.started = time.Now()
	if err := os.RemoveAll(s.runDir); err != nil {
		return err
	}
	s.logDir = filepath.Join(s.runDir, "logs")
	if err := os.MkdirAll(s.logDir, 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(s.binDir, 0o700); err != nil {
		return err
	}
	// The fixed ports first: fail before building or starting anything.
	var err error
	for _, l := range []struct {
		dst  *net.Listener
		port int
	}{{&s.relayL, s.opts.relayPort}, {&s.apiL, s.opts.apiPort}, {&s.ctlL, s.opts.ctlPort}} {
		if *l.dst, err = net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(l.port)); err != nil {
			return fmt.Errorf("listen on 127.0.0.1:%d: %w", l.port, err)
		}
		ln := *l.dst
		s.cleanup(func() { ln.Close() })
	}

	s.logf("building from %s", s.src)
	relayBin, err := relaytest.BuildBinary(s.src)
	if err != nil {
		return err
	}
	s.parentBin, s.enclBin, s.ctlBin = filepath.Join(s.binDir, "vault-parent"), filepath.Join(s.binDir, "vault-enclave"), filepath.Join(s.binDir, "vaultctl")
	for _, b := range []struct{ out, tags, pkg string }{
		{s.parentBin, "", "./cmd/vault-parent"},
		{s.enclBin, "devenclave", "./cmd/vault-enclave"},
		{s.ctlBin, "devenclave", "./cmd/vaultctl"},
	} {
		if err := s.build(ctx, b.out, b.tags, b.pkg); err != nil {
			return err
		}
	}

	if err := s.startLocalStack(ctx); err != nil {
		return err
	}
	if err := s.setupAWS(ctx); err != nil {
		return err
	}

	// The relay (real binary); its TLS front for the enclave and vaultctl;
	// a plain-HTTP front on the relay port for the phone.
	rlog, err := s.logFile("relay.log")
	if err != nil {
		return err
	}
	r, err := relaytest.Run(relayBin, filepath.Join(s.runDir, "relay.db"), rlog, relaytest.Options{"RELAY_BASE_URL": relayURL})
	if err != nil {
		return err
	}
	s.cleanup(r.Stop)
	target, _ := url.Parse(r.URL)
	proxy := &httputil.ReverseProxy{Rewrite: func(p *httputil.ProxyRequest) { p.SetURL(target); p.Out.Host = p.In.Host },
		FlushInterval: -1, ErrorLog: log.New(io.Discard, "", 0)}
	s.relayTLS = s.tlsFront(proxy, true, relayHost)
	s.serve(s.relayL, proxy)
	kms := enclavetest.NewKMSServer(s.w.KMS, region, awskms.Credentials{AccessKeyID: "test", SecretAccessKey: "test"})
	s.kmsAddr = s.tlsFront(kms, false, kmsHost)
	// Google's attestation status list (empty).
	s.gAddr = s.tlsFront(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/attestation/status" {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, `{"entries":{}}`)
	}), true, gHost)

	if err := s.startInstance(ctx); err != nil {
		return err
	}

	// The vaultctl peer: a second member's vault, enrolled through the API.
	s.peerState = filepath.Join(s.runDir, "peer.json")
	s.vaultctlFn = s.runVaultctl
	if out, err := s.vaultctlFn("init", "-role", "app", "-name", "vaultctl-peer", "-relay", relayURL); err != nil {
		return fmt.Errorf("vaultctl init: %v\n%s", err, out)
	}
	out, err := s.vaultctlFn("api-enroll", "-api", s.apiURL(), "-guid", peerGUID, "-pin", peerPIN)
	if err != nil {
		return fmt.Errorf("vaultctl api-enroll: %v\n%s", err, out)
	}
	s.logf("peer vault enrolled: %s", strings.TrimSpace(out))

	s.serve(s.ctlL, logged("ctl", s.control()))
	return nil
}

// recoveryNow is the member API's recovery clock.
func (s *stack) recoveryNow() time.Time { return time.Now().Add(time.Duration(s.recOff.Load())) }

// setRecoveryOffset sets the recovery clock's offset, for the enclave
// (the clock file) and the member API.
func (s *stack) setRecoveryOffset(d time.Duration) error {
	tmp := s.recClock + ".tmp"
	if err := os.WriteFile(tmp, []byte(d.String()+"\n"), 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.recClock); err != nil {
		return err
	}
	s.recOff.Store(int64(d))
	return nil
}

func (s *stack) apiURL() string { return "http://" + s.apiL.Addr().String() }
func (s *stack) ctlURL() string { return "http://" + s.ctlL.Addr().String() }

// info is ready.json and GET /dev/info.
func (s *stack) info() map[string]any {
	m := map[string]any{
		"relay_url":       relayURL,
		"relay_transport": "http://" + s.relayL.Addr().String(),
		"relay_tls":       s.relayTLS, // relay.vettid.test's TLS front (vaultctl: VAULTCTL_DEV_RESOLVE)
		"api":             s.apiURL(),
		"ctl":             s.ctlURL(),
		"peer_guid":       peerGUID,
		"release":         release,
		"started_at":      s.started.UTC().Format(time.RFC3339),
		"source":          s.src,
		"logs":            s.logDir,
		"pid":             os.Getpid(),
		"localstack":      s.ep,
		"device_policy":   nil,
		"recovery_skew":   s.opts.recoverySkew.String(),
	}
	if s.policy != nil {
		m["device_policy"] = s.policy.Summary()
	}
	return m
}

func (s *stack) logFile(name string) (*os.File, error) {
	f, err := os.OpenFile(filepath.Join(s.logDir, name), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	s.cleanup(func() { f.Close() })
	return f, nil
}

// build compiles pkg of the source tree (two packages at a time: the
// machine is shared).
func (s *stack) build(ctx context.Context, out, tags, pkg string) error {
	args := []string{"build", "-p", "2", "-o", out}
	if tags != "" {
		args = append(args, "-tags", tags)
	}
	cmd := exec.CommandContext(ctx, "go", append(args, pkg)...)
	cmd.Dir = s.src
	cmd.Env = append(os.Environ(), "GOWORK=off", "GOFLAGS=-mod=readonly")
	if b, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("build %s: %v\n%s", pkg, err, b)
	}
	return nil
}

func (s *stack) composeCmd() []string {
	if s.opts.compose != "" {
		return strings.Fields(s.opts.compose)
	}
	if _, err := exec.LookPath("podman"); err == nil {
		return []string{"podman", "compose"}
	}
	return []string{"docker", "compose"}
}

// startLocalStack starts integration/docker-compose.yml (one LocalStack
// container, 1.5 GB cap) unless -localstack names an external one, and
// waits until it is healthy.
func (s *stack) startLocalStack(ctx context.Context) error {
	s.ep = s.opts.localstack
	if s.ep == "" {
		if healthy(localstackURL + "/_localstack/health") {
			return errors.New("a LocalStack is already running on 127.0.0.1:4566; use it with -localstack " + localstackURL + " or stop it")
		}
		c := s.composeCmd()
		file := filepath.Join(s.src, "integration", "docker-compose.yml")
		clog, err := s.logFile("compose.log")
		if err != nil {
			return err
		}
		run := func(ctx context.Context, args ...string) error {
			cmd := exec.CommandContext(ctx, c[0], append(append(c[1:], "-p", composeProject, "-f", file), args...)...)
			cmd.Stdout, cmd.Stderr = clog, clog
			return cmd.Run()
		}
		s.logf("starting LocalStack (%s, %s)", strings.Join(c, " "), file)
		s.cleanup(func() {
			s.logf("stopping LocalStack")
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			if err := run(ctx, "down"); err != nil {
				s.logf("compose down: %v (see %s)", err, filepath.Join(s.logDir, "compose.log"))
			}
		})
		if err := run(ctx, "up", "-d"); err != nil {
			return fmt.Errorf("compose up: %v (see %s)", err, filepath.Join(s.logDir, "compose.log"))
		}
		s.ep = localstackURL
	}
	deadline := time.Now().Add(3 * time.Minute)
	for !healthy(strings.TrimSuffix(s.ep, "/") + "/_localstack/health") {
		if time.Now().After(deadline) {
			return fmt.Errorf("LocalStack at %s is not healthy", s.ep)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return nil
}

// setupAWS creates this run's bucket, tables, control-queue policy
// parameter and the test release; the names have a fresh prefix.
func (s *stack) setupAWS(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	rb := make([]byte, 4)
	_, _ = rand.Read(rb)
	pfx := "ds" + hex.EncodeToString(rb)
	s.bucket = pfx + "-vault-data"
	qprefix := pfx + "-vault-control-"
	s.tables = memberapitest.Tables{Vaults: pfx + "-vaults", Instances: pfx + "-vault-instances", Requests: pfx + "-vault-requests", Releases: pfx + "-vault-releases"}
	ac := aws.Config{Region: region, Credentials: credentials.NewStaticCredentialsProvider("test", "test", "")}
	ep := s.ep
	s.s3 = s3.NewFromConfig(ac, func(o *s3.Options) { o.BaseEndpoint = aws.String(ep); o.UsePathStyle = true })
	if _, err := s.s3.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(s.bucket)}); err != nil {
		return fmt.Errorf("bucket: %w", err)
	}
	db := dynamodb.NewFromConfig(ac, func(o *dynamodb.Options) { o.BaseEndpoint = aws.String(ep) })
	sq := sqs.NewFromConfig(ac, func(o *sqs.Options) { o.BaseEndpoint = aws.String(ep) })
	if err := memberapitest.CreateTables(ctx, db, s.tables); err != nil {
		return fmt.Errorf("tables: %w", err)
	}
	probe, err := sq.CreateQueue(ctx, &sqs.CreateQueueInput{QueueName: aws.String(qprefix + "probe")})
	if err != nil {
		return fmt.Errorf("probe queue: %w", err)
	}
	urlPrefix := strings.TrimSuffix(*probe.QueueUrl, "probe")
	_, _ = sq.DeleteQueue(ctx, &sqs.DeleteQueueInput{QueueUrl: probe.QueueUrl})
	// vettid.org's control-queue policy (SSM vault/control-queue-policy).
	policyParam := "/" + pfx + "/vault/control-queue-policy"
	queuePolicy := `{"Version":"2012-10-17","Statement":[{"Sid":"MemberApiSend","Effect":"Allow",` +
		`"Principal":{"AWS":"arn:aws:iam::000000000000:root"},"Action":"sqs:SendMessage",` +
		`"Resource":"arn:aws:sqs:` + region + `:000000000000:` + qprefix + `*"}]}`
	ssmc := ssm.NewFromConfig(ac, func(o *ssm.Options) { o.BaseEndpoint = aws.String(ep) })
	if _, err := ssmc.PutParameter(ctx, &ssm.PutParameterInput{Name: aws.String(policyParam), Value: aws.String(queuePolicy),
		Type: ssmtypes.ParameterTypeString}); err != nil {
		return fmt.Errorf("policy parameter: %w", err)
	}
	s.w = enclavetest.NewWorld(time.Now, relayURL)
	s.w.SetSerial(uint64(time.Now().Unix()))
	s.w.AddRelease(enclavetest.Spec(release, "active"))
	if err := memberapitest.PutRelease(ctx, db, s.tables.Releases, enclavetest.Spec(release, "").PCR0Hex(), release, "active"); err != nil {
		return err
	}
	api := memberapitest.New(memberapitest.Config{DDB: db, SQS: sq, Tables: s.tables, QueueURLPrefix: urlPrefix, Manifest: s.publishedManifest,
		RecoveryNow: s.recoveryNow})
	s.serve(s.apiL, logged("api", api))
	s.parentArgs = []string{"-instance-id", pfx + "-a", "-region", region, "-bucket", s.bucket,
		"-table-vaults", s.tables.Vaults, "-table-instances", s.tables.Instances, "-table-requests", s.tables.Requests,
		"-queue-prefix", qprefix, "-queue-policy-param", policyParam, "-relay-host", relayHost,
		"-aws-endpoint", s.ep, "-static-credentials", "-heartbeat", "10s", "-sweep", "-1s"}
	return nil
}

// publishedManifest serves the world's manifest the way the publish step
// does: to the data bucket first, then the site.
func (s *stack) publishedManifest() []byte {
	doc := s.w.Served()
	sv, err := manifest.ParseServed(doc)
	if err != nil {
		panic(err)
	}
	if _, err := s.s3.PutObject(context.Background(), &s3.PutObjectInput{Bucket: aws.String(s.bucket),
		Key: aws.String(manifest.ObjectKey(manifest.SHA256Hex(sv.Manifest))), Body: bytes.NewReader(doc)}); err != nil {
		panic(err)
	}
	return doc
}

func (s *stack) tlsFront(h http.Handler, h2 bool, names ...string) string {
	srv := httptest.NewUnstartedServer(h)
	srv.EnableHTTP2 = h2
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{enclavetest.ServerCert(names...)}}
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	s.cleanup(srv.Close)
	return srv.Listener.Addr().String()
}

func (s *stack) serve(l net.Listener, h http.Handler) {
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 30 * time.Second, ErrorLog: log.New(io.Discard, "", 0)}
	go func() { _ = srv.Serve(l) }()
	s.cleanup(func() { _ = srv.Close() })
}

func freeAddr() (string, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	defer l.Close()
	return l.Addr().String(), nil
}

// proc starts a child process, stops it (SIGTERM, then SIGKILL after
// grace) at close, and reports an unexpected exit.
func (s *stack) proc(name string, cmd *exec.Cmd, grace time.Duration) error {
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	done := make(chan struct{})
	go func() {
		err := cmd.Wait()
		close(done)
		s.fail(fmt.Errorf("%s exited: %v (logs in %s)", name, err, s.logDir))
	}()
	s.cleanup(func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(grace):
			_ = cmd.Process.Kill()
			<-done
		}
	})
	return nil
}

// startInstance runs one instance of the test release: vault-parent (TCP)
// and the dev vault-enclave.
func (s *stack) startInstance(ctx context.Context) error {
	var ctl, egr, health string
	for _, p := range []*string{&ctl, &egr, &health} {
		a, err := freeAddr()
		if err != nil {
			return err
		}
		*p = a
	}
	args := append(append([]string(nil), s.parentArgs...), "-control-tcp", ctl, "-egress-tcp", egr, "-health", health,
		"-resolve", relayHost+"="+s.relayTLS, "-resolve", kmsHost+"="+s.kmsAddr, "-resolve", gHost+"="+s.gAddr)
	plog, err := s.logFile("parent.log")
	if err != nil {
		return err
	}
	elog, err := s.logFile("enclave.log")
	if err != nil {
		return err
	}
	// The enclave stops after the parent (cleanups run last first).
	eargs := []string{"-release", strconv.Itoa(release), "-control", ctl, "-egress", egr, "-relay-url", relayURL}
	if s.opts.devicePolicy != "" {
		eargs = append(eargs, "-dev-device-policy", s.opts.devicePolicy)
	}
	if s.opts.recoverySkew > 0 {
		abs, err := filepath.Abs(filepath.Join(s.runDir, "recovery-clock"))
		if err != nil {
			return err
		}
		s.recClock = abs
		if err := s.setRecoveryOffset(0); err != nil {
			return err
		}
		eargs = append(eargs, "-dev-recovery-clock", s.recClock)
	}
	e := exec.Command(s.enclBin, eargs...)
	e.Env = []string{"PATH=" + os.Getenv("PATH"), childProcs}
	e.Stdout, e.Stderr = elog, elog
	if err := s.proc("vault-enclave", e, 30*time.Second); err != nil {
		return err
	}
	p := exec.Command(s.parentBin, args...)
	p.Env = []string{"AWS_ACCESS_KEY_ID=test", "AWS_SECRET_ACCESS_KEY=test", "PATH=" + os.Getenv("PATH"), childProcs}
	p.Stdout, p.Stderr = plog, plog
	if err := s.proc("vault-parent", p, 60*time.Second); err != nil {
		return err
	}
	deadline := time.Now().Add(90 * time.Second)
	for {
		if resp, err := http.Get("http://" + health + "/healthz"); err == nil {
			var h parent.Health
			_ = json.NewDecoder(resp.Body).Decode(&h)
			resp.Body.Close()
			if h.OK {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the instance is not healthy (logs in %s)", s.logDir)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-s.died:
			return err
		case <-time.After(300 * time.Millisecond):
		}
	}
}

// runVaultctl runs the dev vaultctl on the peer's state file.
func (s *stack) runVaultctl(args ...string) (string, error) {
	cmd := exec.Command(s.ctlBin, append([]string{"-state", s.peerState, "-timeout", "150s"}, args...)...)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "VAULTCTL_DEV_RESOLVE=" + relayHost + "=" + s.relayTLS, childProcs}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.String(), err
}

// logged writes one line per request (method, path, status) to stderr:
// never bodies (envelopes) or headers (bearer guids).
func logged(name string, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rw := &statusWriter{ResponseWriter: w, status: 200}
		start := time.Now()
		h.ServeHTTP(rw, r)
		fmt.Fprintf(os.Stderr, "%s %s %s %s -> %d (%s)\n", time.Now().UTC().Format("15:04:05.000"), name, r.Method, r.URL.Path, rw.status,
			time.Since(start).Round(time.Millisecond))
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (s *statusWriter) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// Flush passes streaming through (the relay's long polls).
func (s *statusWriter) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (s *statusWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }
