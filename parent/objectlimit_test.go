package parent

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/credentials"

	"github.com/vettid/vettid-vault/internal/hostproto"
	"github.com/vettid/vettid-vault/internal/selftest"
)

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type zeros struct{}

func (zeros) Read(b []byte) (int, error) { clear(b); return len(b), nil }

func testAWS(t *testing.T, c AWSConfig, rt roundTrip) *AWS {
	t.Helper()
	c.Region, c.Credentials = "us-east-1", credentials.NewStaticCredentialsProvider("AK", "SK", "")
	c.Endpoint, c.Bucket, c.VaultsTable, c.InstancesTable, c.RequestsTable = "http://aws.test", "b", "v", "i", "r"
	c.HTTPClient = &http.Client{Transport: rt}
	a, err := NewAWS(c)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// s3Object is an S3 that holds one object of n bytes.
func s3Object(t *testing.T, n int64) *AWS {
	return testAWS(t, AWSConfig{}, func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Status: "200 OK", Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1, Request: r,
			Header:        http.Header{"Etag": {`"v1"`}, "Content-Length": {strconv.FormatInt(n, 10)}, "Content-Type": {"application/octet-stream"}},
			ContentLength: n, Body: io.NopCloser(io.LimitReader(zeros{}, n))}, nil
	})
}

var longestVersion = strings.Repeat("v", MaxVersion)

func getReplyFrame(n int, version string) *hostproto.Frame {
	return &hostproto.Frame{Kind: hostproto.KindReply, ID: 1, Fields: [][]byte{[]byte(hostproto.StatusOK), make([]byte, n), []byte(version)}}
}

// MaxObject is exactly the largest object a StoreGet reply can carry with
// the longest version the enclave accepts: one byte more does not fit a
// frame, and the limit leaves no room unused.
func TestMaxObjectIsWhatAReplyCarries(t *testing.T) {
	if _, err := getReplyFrame(MaxObject, longestVersion).Marshal(); err != nil {
		t.Fatalf("a reply with an object of MaxObject (%d) bytes does not fit a frame: %v", MaxObject, err)
	}
	if _, err := getReplyFrame(MaxObject+1, longestVersion).Marshal(); !errors.Is(err, hostproto.ErrTooBig) {
		t.Fatalf("a reply with an object of MaxObject+1 bytes fits a frame (%v): the limit is too low", err)
	}
	if MaxObject != 67108583 {
		t.Fatalf("MaxObject is %d; the specification's table of limits says 67,108,583", MaxObject)
	}
}

// The parent reads back what it can have written: an object over the
// former 48 MiB read limit, and one of exactly MaxObject bytes. One byte
// more is not read into memory.
func TestObjectReadLimit(t *testing.T) {
	ctx := context.Background()
	for _, n := range []int{48<<20 + 1, MaxObject} {
		b, v, err := s3Object(t, int64(n)).Get(ctx, "vaults/v1/state")
		if err != nil || len(b) != n || v != `"v1"` {
			t.Fatalf("object of %d bytes: %d bytes read, version %q, %v", n, len(b), v, err)
		}
	}
	if b, _, err := s3Object(t, int64(MaxObject)+1).Get(ctx, "vaults/v1/state"); err == nil {
		t.Fatalf("object over the limit read: %d bytes", len(b))
	}
}

// sizedObjects is a store whose Get returns an object and a version of
// the sizes asked for, and whose Put records what it was given.
type sizedObjects struct {
	n       int
	version string
	put     int
}

func (s *sizedObjects) Get(context.Context, string) ([]byte, string, error) {
	return make([]byte, s.n), s.version, nil
}
func (s *sizedObjects) Put(_ context.Context, _ string, b []byte, _ string) (string, error) {
	s.put = len(b)
	return "v2", nil
}
func (*sizedObjects) Delete(context.Context, string, string) error { return nil }

// Every StoreGet answer fits a frame. An object or a version that no
// reply can carry is answered "error" at once (the frame could not be
// written, and the enclave would wait 60 s for nothing); and the parent
// does not write an object that it could not hand back. Both hold for the
// ordinary parent and for the self-test's.
func TestStoreAnswersFitAFrame(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	objs := &sizedObjects{}
	p := &Parent{cfg: Config{Objects: objs}, log: log}
	sc := SelftestConfig{Objects: objs, Logger: log, Request: selftest.Request{RunID: "run-1"}}
	handlers := map[string]struct {
		key    string
		handle func(*hostproto.Frame) [][]byte
	}{
		"parent": {"vaults/v1/state", func(f *hostproto.Frame) [][]byte { return p.handle(context.Background(), nil, f) }},
		"selftest": {"smoke/run-1/state", func(f *hostproto.Frame) [][]byte {
			return selftestHandle(context.Background(), sc, "smoke/run-1/", nil, make(chan *hostproto.Conn, 1), f)
		}},
	}
	for name, h := range handlers {
		for _, c := range []struct {
			n       int
			version string
			want    string
		}{
			{MaxObject, longestVersion, hostproto.StatusOK},
			{MaxObject + 1, `"etag"`, hostproto.StatusError},
			{MaxObject + 1, longestVersion, hostproto.StatusError},
			{16, longestVersion + "v", hostproto.StatusError},
			{hostproto.MaxFrame, `"etag"`, hostproto.StatusError},
		} {
			objs.n, objs.version = c.n, c.version
			r := h.handle(&hostproto.Frame{Kind: hostproto.KindStoreGet, ID: 1, Fields: hostproto.Strings(h.key)})
			if len(r) == 0 || string(r[0]) != c.want {
				t.Errorf("%s: get of %d bytes, version of %d: %q", name, c.n, len(c.version), r[0])
			}
			if _, err := (&hostproto.Frame{Kind: hostproto.KindReply, ID: 1, Fields: r}).Marshal(); err != nil {
				t.Errorf("%s: the reply to a get of %d bytes does not fit a frame: %v", name, c.n, err)
			}
			if c.want == hostproto.StatusOK && len(r[1]) != c.n {
				t.Errorf("%s: %d of %d bytes answered", name, len(r[1]), c.n)
			}
		}
		for _, c := range []struct {
			n    int
			want string
		}{{MaxObject, hostproto.StatusOK}, {MaxObject + 1, hostproto.StatusError}} {
			objs.put = -1
			r := h.handle(&hostproto.Frame{Kind: hostproto.KindStorePut, ID: 1, Fields: [][]byte{[]byte(h.key), make([]byte, c.n), nil}})
			if len(r) == 0 || string(r[0]) != c.want || (objs.put == c.n) != (c.want == hostproto.StatusOK) {
				t.Errorf("%s: put of %d bytes: %q, %d bytes written", name, c.n, r[0], objs.put)
			}
		}
	}
}
