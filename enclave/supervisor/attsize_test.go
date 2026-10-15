package supervisor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/hostproto"
	"github.com/vettid/vettid-vault/internal/vaultipc"
	"github.com/vettid/vettid-vault/vault/store"
	"github.com/vettid/vettid-vault/vms/attwire"
	"github.com/vettid/vettid-vault/vms/envelope"
)

type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// VAULT-MESSAGING 0.32.0 §10.5.1, VAULT-HOST-PROTOCOL 0.1.9 §9: the
// relay proxy carries a blob of the relay's max_blob_bytes (8 MiB) both
// ways, and the store channel an attachment object of the largest size
// and its thumbnail, under the vault's own att/ prefix only.
func TestAttachmentSizesThroughChannel(t *testing.T) {
	ctx := context.Background()
	blob := bytes.Repeat([]byte{0xA5}, attwire.ReferenceMaxBlob)
	var gotLen int64
	var gotSum [32]byte
	rt := rtFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodPut {
			b, _ := io.ReadAll(r.Body)
			gotLen, gotSum = r.ContentLength, sha256.Sum256(b)
			return &http.Response{StatusCode: 201, Header: http.Header{}, Body: io.NopCloser(bytes.NewReader([]byte(`{}`))), Request: r}, nil
		}
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(bytes.NewReader(blob)), Request: r}, nil
	})
	m := store.NewMemory()
	s := &Supervisor{st: &hostStore{l: memParent(t, m)}, relays: map[string]bool{"relay.example": true},
		relayHTTP: &http.Client{Transport: rt}, activity: map[string]time.Time{}}
	p := &vproc{h: &procHost{s: s}, vaultID: "aaaa", userGUID: "u1"}

	r := p.handle(ctx, &hostproto.Frame{Kind: vaultipc.KindHTTP, ID: 1, Fields: [][]byte{[]byte(http.MethodPut),
		[]byte("https://relay.example/v1/blob/mbx"), vaultipc.EncodeHeaders(http.Header{}), blob}})
	if string(r[0]) != hostproto.StatusOK || string(r[1]) != "201" || gotLen != int64(len(blob)) || gotSum != sha256.Sum256(blob) {
		t.Fatalf("upload: %s %s, %d bytes", r[0], r[1], gotLen)
	}
	r = p.handle(ctx, &hostproto.Frame{Kind: vaultipc.KindHTTP, ID: 2, Fields: [][]byte{[]byte(http.MethodGet),
		[]byte("https://relay.example/v1/blob/01JB2Z6V9K3M4N5P6Q7R8S9T60"), vaultipc.EncodeHeaders(http.Header{}), nil}})
	if string(r[0]) != hostproto.StatusOK || !bytes.Equal(r[3], blob) {
		t.Fatalf("download: %s, %d bytes", r[0], len(r[3]))
	}

	cs := channelStore{p}
	id := "01JB2Z6V9K3M4N5P6Q7R8S9T60"
	obj := bytes.Repeat([]byte{1}, envelope.BlobLen(attwire.ReferenceMaxContent))
	if len(obj) != 8257577 {
		t.Fatalf("largest object %d bytes", len(obj))
	}
	v, err := cs.Put(ctx, attwire.ContentKey("aaaa", id), obj, "")
	if err != nil {
		t.Fatal(err)
	}
	if b, _, err := cs.Get(ctx, attwire.ContentKey("aaaa", id)); err != nil || !bytes.Equal(b, obj) {
		t.Fatal("object read back")
	}
	if _, err := cs.Put(ctx, attwire.ThumbKey("aaaa", id), make([]byte, attwire.MaxThumbObject), ""); err != nil {
		t.Fatal(err)
	}
	if err := cs.Delete(ctx, attwire.ContentKey("aaaa", id), v); err != nil {
		t.Fatal(err)
	}
	if _, err := cs.Put(ctx, attwire.ContentKey("bbbb", id), []byte{1}, ""); err == nil {
		t.Fatal("another vault's attachment written")
	}
}
