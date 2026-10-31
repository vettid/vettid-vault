package vault

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/envelope"
)

// blobStub is an app request that travels as a blob: its handler defers the
// call, which answers with the plaintext's length.
type blobStub struct {
	mu   sync.Mutex
	runs int
}

func (g *blobStub) Name() string                   { return "blobstub" }
func (g *blobStub) Load(json.RawMessage) error     { return nil }
func (g *blobStub) Save() (json.RawMessage, error) { return nil, nil }
func (g *blobStub) Types() []TypeSpec {
	return []TypeSpec{{Type: "test.blobcall", Request: true, From: []string{KindApp}}}
}
func (g *blobStub) Handle(_ context.Context, s *Session, in *envelope.Inner) (json.RawMessage, error) {
	var b struct {
		ID     string `json:"id"`
		Key    []byte `json:"key"`
		SHA256 []byte `json:"sha256"`
		Size   int    `json:"size"`
	}
	if err := json.Unmarshal(in.Body, &b); err != nil {
		return nil, errBadRequest
	}
	if err := s.DeferBlob(b.ID, b.Key, b.SHA256, b.Size, func(s *Session, plain []byte) (json.RawMessage, error) {
		g.mu.Lock()
		g.runs++
		g.mu.Unlock()
		if string(plain) == "fail" {
			return nil, NewError("limit", "")
		}
		return json.RawMessage(`{"len":` + strconv.Itoa(len(plain)) + `}`), nil
	}); err != nil {
		return nil, err
	}
	return nil, ErrDeferred
}

// A request that is a §5.5 blob: fetched in the background, checked
// (sha256, size, decryption), the blob deleted, the handler run on the
// plaintext, and the answer sent then.
func TestBlobCallAnswersLater(t *testing.T) {
	d := newDevFixture(t)
	st := &blobStub{}
	d.m.addFeature(st)
	max := int64(1 << 24)
	ttl := int64(3600)
	d.m.limits.MaxBlobBytes, d.m.limits.BlobTTLSeconds = &max, &ttl
	put := func(plain string) (id string, key, sum []byte, size int) {
		data, k, s, err := envelope.SealBlob([]byte(plain))
		if err != nil {
			t.Fatal(err)
		}
		d.relay.blobs = &stubBlobs{byID: map[string]stubBlob{}}
		id = "01JB2Z6V9K3M4N5P6Q7R8S0009"
		d.relay.blobs.byID[id] = stubBlob{mailbox: mailboxOf(d.relay.key), data: data}
		return id, k, s[:], len(plain)
	}
	body := func(id string, key, sum []byte, size int) string {
		return `{"id":"` + id + `","key":"` + base64.StdEncoding.EncodeToString(key) + `","sha256":"` + base64.StdEncoding.EncodeToString(sum) + `","size":` + strconv.Itoa(size) + `}`
	}
	answer := func(reqID string) *envelope.Inner {
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			for _, x := range d.appInbox() {
				if x.Re == reqID {
					return x
				}
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatal("no answer")
		return nil
	}
	id, k, s, n := put("hello blob")
	req := d.sendAs(d.self(), "test.blobcall", body(id, k, s, n))
	r := answer(req)
	if r.Status != envelope.StatusOK || !strings.Contains(string(r.Body), `"len":10`) {
		t.Fatalf("%+v %s", r, r.Body)
	}
	d.relay.blobs.mu.Lock()
	left := len(d.relay.blobs.byID)
	d.relay.blobs.mu.Unlock()
	if left != 0 {
		t.Error("the blob was not deleted")
	}
	// A handler error is the response.
	id, k, s, n = put("fail")
	if r := answer(d.sendAs(d.self(), "test.blobcall", body(id, k, s, n))); errCode(r) != "limit" {
		t.Errorf("%+v", r)
	}
	// Wrong sha256, wrong size, wrong key, unknown blob: bad_request, and the
	// blob is deleted.
	for name, b := range map[string]func() string{
		"sha":  func() string { id, k, _, n := put("abc"); return body(id, k, make([]byte, 32), n) },
		"size": func() string { id, k, s, n := put("abc"); return body(id, k, s, n+1) },
		"key":  func() string { id, _, s, n := put("abc"); return body(id, make([]byte, 32), s, n) },
		"none": func() string { id, k, s, n := put("abc"); delete(d.relay.blobs.byID, id); return body(id, k, s, n) },
	} {
		r := answer(d.sendAs(d.self(), "test.blobcall", b()))
		if errCode(r) != "bad_request" {
			t.Errorf("%s: %+v", name, r)
		}
		d.relay.blobs.mu.Lock()
		l := len(d.relay.blobs.byID)
		d.relay.blobs.mu.Unlock()
		if l != 0 {
			t.Errorf("%s: a blob is left", name)
		}
	}
	// A relay without blobs, or a blob over its limit: payload_too_large.
	id, k, s, n = put("abc")
	small := int64(10)
	d.m.limits.MaxBlobBytes = &small
	if r := answer(d.sendAs(d.self(), "test.blobcall", body(id, k, s, n))); errCode(r) != "payload_too_large" {
		t.Errorf("over the limit: %+v", r)
	}
	d.m.limits.MaxBlobBytes = nil
	if r := answer(d.sendAs(d.self(), "test.blobcall", body(id, k, s, n))); errCode(r) != "payload_too_large" {
		t.Errorf("no blobs: %+v", r)
	}
}

// Many blob requests at once: one call in flight per device, the others
// answered busy (or the retransmission of the running one reused), and the
// relay is asked for one blob at a time.
func TestBlobCallOnePerDevice(t *testing.T) {
	d := newDevFixture(t)
	d.m.addFeature(&blobStub{})
	max := int64(1 << 24)
	ttl := int64(3600)
	d.m.limits.MaxBlobBytes, d.m.limits.BlobTTLSeconds = &max, &ttl
	d.relay.blobs = &stubBlobs{byID: map[string]stubBlob{}}
	var mu sync.Mutex
	inflight, peak, gets := 0, 0, 0
	gate := make(chan struct{})
	d.relay.getHook = func() {
		mu.Lock()
		inflight++
		gets++
		peak = max2(peak, inflight)
		mu.Unlock()
		<-gate
		mu.Lock()
		inflight--
		mu.Unlock()
	}
	data, k, s, err := envelope.SealBlob([]byte("hello blob"))
	if err != nil {
		t.Fatal(err)
	}
	id := "01JB2Z6V9K3M4N5P6Q7R8S0010"
	d.relay.blobs.byID[id] = stubBlob{mailbox: mailboxOf(d.relay.key), data: data}
	body := `{"id":"` + id + `","key":"` + base64.StdEncoding.EncodeToString(k) + `","sha256":"` + base64.StdEncoding.EncodeToString(s[:]) + `","size":10}`
	var reqs []string
	for i := 0; i < 12; i++ {
		reqs = append(reqs, d.sendAs(d.self(), "test.blobcall", body))
	}
	time.Sleep(300 * time.Millisecond)
	close(gate)
	ok, busy := 0, 0
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && ok+busy < len(reqs) {
		for _, x := range d.appInbox() {
			for _, r := range reqs {
				if x.Re == r {
					if x.Status == envelope.StatusOK {
						ok++
					} else if errCode(x) == "busy" {
						busy++
					}
				}
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if peak != 1 || gets != 1 || ok != 1 || busy != len(reqs)-1 {
		t.Fatalf("peak %d gets %d ok %d busy %d", peak, gets, ok, busy)
	}
}

func max2(a, b int) int {
	if a > b {
		return a
	}
	return b
}
