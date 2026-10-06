//go:build devenclave && integration

// Package integration runs the V3 exit test (VAULT-PLAN §4 V3) against
// LocalStack: the real vettid-relay binary behind a TLS front, LocalStack
// (S3, SQS, DynamoDB), vault-parent in TCP mode, vault-enclave dev builds
// (fake NSM, test roots) whose KMS client talks SigV4 over TLS to a fake
// KMS endpoint, a stand-in for the member API's vault routes over the same
// tables (internal/memberapitest), and vaultctl.
//
//	make integration      # starts LocalStack with docker compose
//
// or, with LocalStack already on :4566,
//
//	VAULT_IT_LOCALSTACK=http://127.0.0.1:4566 go test -count=1 -tags 'devenclave integration' ./integration/
package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
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
	relayHost = "relay.vettid.test"
	relayURL  = "https://" + relayHost
	region    = enclavetest.KMSRegion
	kmsHost   = "kms." + region + ".amazonaws.com"
	gHost     = "android.googleapis.com"
)

// syncBuffer collects a process's output.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type stack struct {
	t         *testing.T
	dir       string
	ep        string
	pfx       string
	bucket    string
	qprefix   string
	tables    memberapitest.Tables
	db        *dynamodb.Client
	sqs       *sqs.Client
	w         *enclavetest.World
	kms       *enclavetest.KMSServer
	relay     *relaytest.Relay
	relayAddr string
	kmsAddr   string
	gAddr     string
	api       *httptest.Server
	mapi      *memberapitest.API
	appHTTP   *http.Client
	s3        *s3.Client

	sentMu    sync.Mutex
	sent      map[string][2]string // request_id -> queue URL, body
	parentBin string
	enclBin   string
	ctlBin    string
	// prevDir and prevRelease: instances of prevRelease run the parent
	// and dev enclave binaries in prevDir, built from a previous release's
	// tag (the compatibility matrix, VAULT-RELEASES §11.3).
	prevDir     string
	prevRelease uint64
	// policyParam holds queuePolicy in LocalStack SSM (vettid.org's
	// vault/control-queue-policy).
	policyParam, queuePolicy string
	instances                []*instance
}

type instance struct {
	s          *stack
	name, id   string
	release    uint64
	health     string
	parent     *exec.Cmd
	enclave    *exec.Cmd
	plog, elog *syncBuffer
	stopped    bool
}

func freeAddr(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

func ctxT(t *testing.T, d time.Duration) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}

func build(t *testing.T, out string, tags string, pkg string) {
	t.Helper()
	args := []string{"build", "-o", out}
	if tags != "" {
		args = append(args, "-tags", tags)
	}
	cmd := exec.Command("go", append(args, pkg)...)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", pkg, err, b)
	}
}

// tlsServer serves h on a TLS front for names (HTTP/2 when h2).
func tlsServer(t *testing.T, h http.Handler, h2 bool, names ...string) *httptest.Server {
	s := httptest.NewUnstartedServer(h)
	s.EnableHTTP2 = h2
	s.TLS = &tls.Config{Certificates: []tls.Certificate{enclavetest.ServerCert(names...)}}
	s.StartTLS()
	t.Cleanup(s.Close)
	return s
}

func newStack(t *testing.T) *stack {
	ep := os.Getenv("VAULT_IT_LOCALSTACK")
	if ep == "" {
		t.Skip("VAULT_IT_LOCALSTACK not set (make integration)")
	}
	s := &stack{t: t, dir: t.TempDir(), ep: ep}
	rb := make([]byte, 4)
	_, _ = rand.Read(rb)
	s.pfx = "it" + hex.EncodeToString(rb)
	s.bucket = s.pfx + "-vault-data"
	s.qprefix = s.pfx + "-vault-control-"
	s.tables = memberapitest.Tables{Vaults: s.pfx + "-vaults", Instances: s.pfx + "-vault-instances", Requests: s.pfx + "-vault-requests", Releases: s.pfx + "-vault-releases"}

	// Binaries: the parent as released, the enclave and vaultctl as dev
	// builds.
	s.parentBin = filepath.Join(s.dir, "vault-parent")
	s.enclBin = filepath.Join(s.dir, "vault-enclave")
	s.ctlBin = filepath.Join(s.dir, "vaultctl")
	build(t, s.parentBin, "", "../cmd/vault-parent")
	build(t, s.enclBin, "devenclave", "../cmd/vault-enclave")
	build(t, s.ctlBin, "devenclave", "../cmd/vaultctl")

	// LocalStack: bucket, tables, the first release.
	ctx := ctxT(t, 2*time.Minute)
	ac := aws.Config{Region: region, Credentials: credentials.NewStaticCredentialsProvider("test", "test", "")}
	s3c := s3.NewFromConfig(ac, func(o *s3.Options) { o.BaseEndpoint = aws.String(ep); o.UsePathStyle = true })
	if _, err := s3c.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(s.bucket)}); err != nil {
		t.Fatalf("bucket: %v", err)
	}
	s.s3 = s3c
	s.sent = map[string][2]string{}
	s.db = dynamodb.NewFromConfig(ac, func(o *dynamodb.Options) { o.BaseEndpoint = aws.String(ep) })
	s.sqs = sqs.NewFromConfig(ac, func(o *sqs.Options) { o.BaseEndpoint = aws.String(ep) })
	if err := memberapitest.CreateTables(ctx, s.db, s.tables); err != nil {
		t.Fatalf("tables: %v", err)
	}
	probe, err := s.sqs.CreateQueue(ctx, &sqs.CreateQueueInput{QueueName: aws.String(s.qprefix + "probe")})
	if err != nil {
		t.Fatalf("probe queue: %v", err)
	}
	urlPrefix := strings.TrimSuffix(*probe.QueueUrl, "probe")
	_, _ = s.sqs.DeleteQueue(ctx, &sqs.DeleteQueueInput{QueueUrl: probe.QueueUrl})
	// vettid.org's control-queue policy (SSM vault/control-queue-policy):
	// SendMessage for the member API's account.
	s.policyParam = "/" + s.pfx + "/vault/control-queue-policy"
	s.queuePolicy = `{"Version":"2012-10-17","Statement":[{"Sid":"MemberApiSend","Effect":"Allow",` +
		`"Principal":{"AWS":"arn:aws:iam::000000000000:root"},"Action":"sqs:SendMessage",` +
		`"Resource":"arn:aws:sqs:` + region + `:000000000000:` + s.qprefix + `*"}]}`
	ssmc := ssm.NewFromConfig(ac, func(o *ssm.Options) { o.BaseEndpoint = aws.String(ep) })
	if _, err := ssmc.PutParameter(ctx, &ssm.PutParameterInput{Name: aws.String(s.policyParam), Value: aws.String(s.queuePolicy),
		Type: ssmtypes.ParameterTypeString}); err != nil {
		t.Fatalf("policy parameter: %v", err)
	}

	// Releases, manifest and KMS keys (test world).
	s.w = enclavetest.NewWorld(time.Now, relayURL)
	s.w.SetSerial(uint64(time.Now().Unix()))
	s.addRelease(3)

	// The relay behind a TLS front with the test root, as relay.vettid.test.
	s.relay = relaytest.Start(t, relaytest.Options{"RELAY_BASE_URL": relayURL})
	target, _ := url.Parse(s.relay.URL)
	front := &httputil.ReverseProxy{Rewrite: func(r *httputil.ProxyRequest) { r.SetURL(target); r.Out.Host = r.In.Host }, FlushInterval: -1}
	s.relayAddr = tlsServer(t, front, true, relayHost).Listener.Addr().String()
	// The KMS endpoint (HTTP/1.1 only, like AWS) with SigV4 verification.
	s.kms = enclavetest.NewKMSServer(s.w.KMS, region, awskms.Credentials{AccessKeyID: "test", SecretAccessKey: "test"})
	s.kmsAddr = tlsServer(t, s.kms, false, kmsHost).Listener.Addr().String()
	// Google's attestation status list (empty).
	s.gAddr = tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/attestation/status" {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, `{"entries":{}}`)
	}), true, gHost).Listener.Addr().String()

	// The member API stand-in.
	s.mapi = memberapitest.New(memberapitest.Config{DDB: s.db, SQS: s.sqs, Tables: s.tables,
		QueueURLPrefix: urlPrefix, Manifest: s.publishedManifest, Sent: func(rid, q, body string) {
			s.sentMu.Lock()
			s.sent[rid] = [2]string{q, body}
			s.sentMu.Unlock()
		}})
	s.api = httptest.NewServer(s.mapi)
	t.Cleanup(s.api.Close)

	roots := x509.NewCertPool()
	roots.AddCert(enclavetest.TestTLSCA().Cert)
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}, ForceAttemptHTTP2: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if h, _, _ := net.SplitHostPort(addr); h == relayHost {
				addr = s.relayAddr
			}
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		}}
	s.appHTTP = &http.Client{Transport: tr, Timeout: 90 * time.Second}

	t.Cleanup(func() {
		for _, in := range s.instances {
			in.stop()
		}
		if t.Failed() || os.Getenv("VAULT_IT_LOGS") != "" {
			for _, in := range s.instances {
				t.Logf("== parent %s\n%s", in.name, in.plog.String())
				t.Logf("== enclave %s\n%s", in.name, in.elog.String())
			}
		}
	})
	return s
}

func (s *stack) addRelease(n uint64) {
	s.t.Helper()
	s.w.AddRelease(enclavetest.Spec(n, "active"))
	ctx := ctxT(s.t, 30*time.Second)
	if err := memberapitest.PutRelease(ctx, s.db, s.tables.Releases, enclavetest.Spec(n, "").PCR0Hex(), n, "active"); err != nil {
		s.t.Fatal(err)
	}
}

// parentHasFlag reports whether a vault-parent binary lists -name in its
// -h output (flag usage: "  -name ...").
func parentHasFlag(t *testing.T, bin, name string) bool {
	t.Helper()
	out, _ := exec.Command(bin, "-h").CombinedOutput() // -h exits 0 or 2 depending on the flag set
	for _, l := range strings.Split(string(out), "\n") {
		if f := strings.Fields(l); len(f) > 0 && f[0] == "-"+name {
			return true
		}
	}
	if !strings.Contains(string(out), "-instance-id") {
		t.Fatalf("%s -h: no flag usage: %s", bin, out)
	}
	return false
}

// start runs a parent and an enclave of release n.
func (s *stack) start(name string, n uint64, parentFlags ...string) *instance {
	t := s.t
	t.Helper()
	in := &instance{s: s, name: name, id: s.pfx + "-" + name, release: n, plog: &syncBuffer{}, elog: &syncBuffer{}}
	ctl, egr := freeAddr(t), freeAddr(t)
	in.health = freeAddr(t)
	args := []string{"-instance-id", in.id, "-region", region, "-bucket", s.bucket,
		"-table-vaults", s.tables.Vaults, "-table-instances", s.tables.Instances, "-table-requests", s.tables.Requests,
		"-queue-prefix", s.qprefix, "-relay-host", relayHost, "-control-tcp", ctl, "-egress-tcp", egr,
		"-aws-endpoint", s.ep, "-static-credentials", "-health", in.health, "-heartbeat", "2s", "-sweep", "-1s",
		"-resolve", relayHost + "=" + s.relayAddr, "-resolve", kmsHost + "=" + s.kmsAddr, "-resolve", gHost + "=" + s.gAddr}
	parentBin, enclBin := s.parentBin, s.enclBin
	if s.prevDir != "" && n == s.prevRelease {
		parentBin, enclBin = filepath.Join(s.prevDir, "vault-parent"), filepath.Join(s.prevDir, "vault-enclave")
	}
	// Parents since #16 refuse to start without the control-queue policy;
	// older tags' parents (the compatibility matrix) do not know the flag.
	if parentBin == s.parentBin || parentHasFlag(t, parentBin, "queue-policy-param") {
		args = append(args, "-queue-policy-param", s.policyParam)
	}
	in.parent = exec.Command(parentBin, append(args, parentFlags...)...)
	in.parent.Env = []string{"AWS_ACCESS_KEY_ID=test", "AWS_SECRET_ACCESS_KEY=test", "PATH=" + os.Getenv("PATH"), "GOMAXPROCS=2"}
	in.parent.Stdout, in.parent.Stderr = in.plog, in.plog
	if err := in.parent.Start(); err != nil {
		t.Fatal(err)
	}
	in.enclave = exec.Command(enclBin, "-release", fmt.Sprint(n), "-control", ctl, "-egress", egr, "-relay-url", relayURL)
	in.enclave.Env = []string{"PATH=" + os.Getenv("PATH"), "GOMAXPROCS=2"}
	in.enclave.Stdout, in.enclave.Stderr = in.elog, in.elog
	if err := in.enclave.Start(); err != nil {
		t.Fatal(err)
	}
	s.instances = append(s.instances, in)
	in.waitHealth(func(h parent.Health) bool { return h.OK }, "healthy")
	return in
}

func (in *instance) healthNow() (parent.Health, error) {
	var h parent.Health
	r, err := http.Get("http://" + in.health + "/healthz")
	if err != nil {
		return h, err
	}
	defer r.Body.Close()
	err = json.NewDecoder(r.Body).Decode(&h)
	return h, err
}

func (in *instance) waitHealth(ok func(parent.Health) bool, what string) parent.Health {
	t := in.s.t
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for {
		h, err := in.healthNow()
		if err == nil && ok(h) {
			return h
		}
		if time.Now().After(deadline) {
			t.Fatalf("instance %s not %s: %+v %v", in.name, what, h, err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func (in *instance) stop() {
	if in.stopped {
		return
	}
	in.stopped = true
	_ = in.parent.Process.Signal(syscall.SIGTERM)
	done := make(chan struct{})
	go func() { _ = in.parent.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		_ = in.parent.Process.Kill()
	}
	_ = in.enclave.Process.Signal(syscall.SIGTERM)
	done = make(chan struct{})
	go func() { _ = in.enclave.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		_ = in.enclave.Process.Kill()
	}
}

// vaultctl runs vaultctl with a state file.
func (s *stack) vaultctl(state string, args ...string) (string, error) {
	cmd := exec.Command(s.ctlBin, append([]string{"-state", state, "-timeout", "150s"}, args...)...)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "VAULTCTL_DEV_RESOLVE=" + relayHost + "=" + s.relayAddr, "GOMAXPROCS=2"}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.String(), err
}

func (s *stack) mustVaultctl(state string, args ...string) string {
	s.t.Helper()
	out, err := s.vaultctl(state, args...)
	if err != nil {
		s.t.Fatalf("vaultctl %v: %v\n%s", args, err, out)
	}
	return out
}

// jsonValues decodes the JSON values printed by vaultctl.
func jsonValues(out string) []map[string]any {
	var vs []map[string]any
	i := strings.IndexByte(out, '{')
	if i < 0 {
		return nil
	}
	dec := json.NewDecoder(strings.NewReader(out[i:]))
	for {
		var v map[string]any
		if dec.Decode(&v) != nil {
			return vs
		}
		vs = append(vs, v)
	}
}

// vaultRow is what the parent wrote to a vault's row.
type vaultRow struct {
	State, SealedRelease, VaultVersion, LeaseInstance string
	// AppKeyID, AppKeySeq: the app_key the parent wrote (0.15.0).
	AppKeyID, AppKeySeq string
	// CredentialBackup: the backup bit the parent wrote (0.16.0): "true",
	// "false" or "".
	CredentialBackup string
}

func (s *stack) vaultRow(id string) vaultRow {
	s.t.Helper()
	it, err := memberapitest.VaultItem(ctxT(s.t, 10*time.Second), s.db, s.tables.Vaults, id)
	if err != nil {
		s.t.Fatal(err)
	}
	str := func(m map[string]ddbtypes.AttributeValue, k string) string {
		if v, ok := m[k].(*ddbtypes.AttributeValueMemberS); ok {
			return v.Value
		}
		return ""
	}
	r := vaultRow{State: str(it, "state"), SealedRelease: str(it, "sealed_release"), VaultVersion: str(it, "vault_version")}
	if l, ok := it["lease"].(*ddbtypes.AttributeValueMemberM); ok {
		r.LeaseInstance = str(l.Value, "instance_id")
	}
	if b, ok := it["credential_backup"].(*ddbtypes.AttributeValueMemberBOOL); ok {
		r.CredentialBackup = fmt.Sprint(b.Value)
	}
	if k, ok := it["app_key"].(*ddbtypes.AttributeValueMemberM); ok {
		r.AppKeyID = str(k.Value, "kid")
		if n, ok := k.Value["seq"].(*ddbtypes.AttributeValueMemberN); ok {
			r.AppKeySeq = n.Value
		}
	}
	return r
}

func expireLease(s *stack, vaultID string) error {
	return memberapitest.ExpireLease(ctxT(s.t, 10*time.Second), s.db, s.tables.Vaults, vaultID)
}

func queueCount(s *stack) int {
	r, err := s.sqs.ListQueues(ctxT(s.t, 10*time.Second), &sqs.ListQueuesInput{QueueNamePrefix: aws.String(s.qprefix)})
	if err != nil {
		s.t.Fatal(err)
	}
	return len(r.QueueUrls)
}

// queuePolicyOf returns the Policy attribute of an instance's queue.
func (s *stack) queuePolicyOf(in *instance) string {
	s.t.Helper()
	ctx := ctxT(s.t, 10*time.Second)
	u, err := s.sqs.GetQueueUrl(ctx, &sqs.GetQueueUrlInput{QueueName: aws.String(s.qprefix + in.id)})
	if err != nil {
		s.t.Fatal(err)
	}
	at, err := s.sqs.GetQueueAttributes(ctx, &sqs.GetQueueAttributesInput{QueueUrl: u.QueueUrl,
		AttributeNames: []sqstypes.QueueAttributeName{sqstypes.QueueAttributeNamePolicy}})
	if err != nil {
		s.t.Fatal(err)
	}
	return at.Attributes[string(sqstypes.QueueAttributeNamePolicy)]
}

// sameJSON compares two JSON documents semantically (SQS may reformat a
// policy).
func sameJSON(a, b string) bool {
	var x, y any
	if json.Unmarshal([]byte(a), &x) != nil || json.Unmarshal([]byte(b), &y) != nil {
		return false
	}
	return reflect.DeepEqual(x, y)
}

// lastSent returns the last queue message the API sent for op.
func (s *stack) lastSent(op string) (rid, queue, body string) {
	s.sentMu.Lock()
	defer s.sentMu.Unlock()
	for id, m := range s.sent {
		if strings.Contains(m[1], `"op":"`+op+`"`) && id > rid {
			rid, queue, body = id, m[0], m[1]
		}
	}
	return rid, queue, body
}

func (s *stack) getObject(key string) []byte {
	s.t.Helper()
	out, err := s.s3.GetObject(ctxT(s.t, 10*time.Second), &s3.GetObjectInput{Bucket: aws.String(s.bucket), Key: aws.String(key)})
	if err != nil {
		s.t.Fatal(err)
	}
	defer out.Body.Close()
	b, err := io.ReadAll(out.Body)
	if err != nil {
		s.t.Fatal(err)
	}
	return b
}

// publishedManifest serves the world's current manifest the way the
// publish step does (VAULT-MESSAGING 0.10.0): the document goes to the
// vault data bucket as manifests/<sha256>.json before the site serves it,
// and the parent reads it from there.
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

// putObject overwrites an object unconditionally, as a dishonest host
// could.
func (s *stack) putObject(key string, b []byte) {
	s.t.Helper()
	if _, err := s.s3.PutObject(ctxT(s.t, 10*time.Second), &s3.PutObjectInput{Bucket: aws.String(s.bucket), Key: aws.String(key), Body: bytes.NewReader(b)}); err != nil {
		s.t.Fatal(err)
	}
}

// requeue makes a response slot queued again and re-sends a queue
// message, as a dishonest host replaying a request would.
func (s *stack) requeue(rid, queue, body, guid, appKID string) {
	s.t.Helper()
	ctx := ctxT(s.t, 10*time.Second)
	_, err := s.db.PutItem(ctx, &dynamodb.PutItemInput{TableName: aws.String(s.tables.Requests), Item: map[string]ddbtypes.AttributeValue{
		"request_id": &ddbtypes.AttributeValueMemberS{Value: rid}, "user_guid": &ddbtypes.AttributeValueMemberS{Value: guid},
		"app_kid": &ddbtypes.AttributeValueMemberS{Value: appKID},
		"status":  &ddbtypes.AttributeValueMemberS{Value: "queued"}, "created_at": &ddbtypes.AttributeValueMemberS{Value: time.Now().UTC().Format(time.RFC3339)},
		"expires_at": &ddbtypes.AttributeValueMemberN{Value: fmt.Sprint(time.Now().Unix() + 900)}}})
	if err != nil {
		s.t.Fatal(err)
	}
	if _, err := s.sqs.SendMessage(ctx, &sqs.SendMessageInput{QueueUrl: aws.String(queue), MessageBody: aws.String(body)}); err != nil {
		s.t.Fatal(err)
	}
}
