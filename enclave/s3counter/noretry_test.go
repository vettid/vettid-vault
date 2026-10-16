package s3counter_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/enclave/s3counter"
	"github.com/vettid/vettid-vault/vms/recovery"
)

// A token's create-only put is sent once, never again by the client or by
// net/http underneath it, even when the connection breaks before an
// answer on a reused connection (where the transport replays only
// GET, HEAD, OPTIONS and TRACE): a repeated Spend could take a second
// attempt, and the open's attempt_used (VAULT-MESSAGING 0.34.0 §11.14.6)
// would no longer be one request's own.
func TestPutCreateIsNeverRetried(t *testing.T) {
	var puts, lists atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			puts.Add(1)
			hj, ok := w.(http.Hijacker)
			if !ok {
				t.Error("no hijacker")
				return
			}
			conn, _, err := hj.Hijack()
			if err == nil {
				_ = conn.Close() // no answer at all
			}
			return
		}
		lists.Add(1)
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><ListVersionsResult><IsTruncated>false</IsTruncated></ListVersionsResult>`))
	}))
	defer srv.Close()
	cl := &s3counter.Client{HTTP: &http.Client{CheckRedirect: s3counter.NoRedirect}, Bucket: "b", Account: "111122223333", Region: "us-east-1",
		Creds: creds{}, Endpoint: srv.URL, Now: func() time.Time { return time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC) }}
	ctx := context.Background()
	key := recovery.CounterPrefixRoot + "x/token"
	// A first call leaves a kept-alive connection for the put to reuse.
	_, _ = cl.List(ctx, recovery.CounterPrefixRoot+"x/")
	if lists.Load() == 0 {
		t.Fatal("no list reached the server")
	}
	if _, _, err := cl.PutCreate(ctx, key, []byte("body"), time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)); err == nil {
		t.Fatal("a put without an answer succeeded")
	}
	if n := puts.Load(); n != 1 {
		t.Fatalf("the put was sent %d times", n)
	}
}
