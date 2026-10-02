package supervisor

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/hostproto"
	"github.com/vettid/vettid-vault/vault/store"
)

// fakeParent answers store requests with canned replies.
func fakeParent(t *testing.T, answer func(f *hostproto.Frame) [][]byte) *link {
	a, b := net.Pipe()
	p := hostproto.NewConn(b, func(_ context.Context, f *hostproto.Frame) [][]byte { return answer(f) }, nil)
	c := hostproto.NewConn(a, nil, nil)
	t.Cleanup(func() { c.Close(); p.Close() })
	l := &link{}
	l.set(c, time.Now())
	return l
}

func TestHostStoreMapping(t *testing.T) {
	ctx := context.Background()
	var reply [][]byte
	var wrote []string
	l := fakeParent(t, func(*hostproto.Frame) [][]byte { return reply })
	h := &hostStore{l: l, onWrite: func(k string) { wrote = append(wrote, k) }}
	for _, c := range []struct {
		reply []string
		want  error
	}{
		{[]string{"not_found"}, store.ErrNotFound},
		{[]string{"error"}, errHost},
		{[]string{"ok", "data"}, errHost}, // missing version
		{[]string{"ok", "data", ""}, errHost},
	} {
		reply = hostproto.Strings(c.reply...)
		if _, _, err := h.Get(ctx, "vaults/v/state"); !errors.Is(err, c.want) {
			t.Errorf("get %v: %v", c.reply, err)
		}
	}
	reply = hostproto.Strings("ok", "data", `"etag"`)
	if b, v, err := h.Get(ctx, "vaults/v/state"); err != nil || string(b) != "data" || v != `"etag"` {
		t.Fatalf("get: %q %q %v", b, v, err)
	}
	reply = hostproto.Strings("conflict")
	if _, err := h.Put(ctx, "vaults/v/state", []byte("x"), "v"); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("put conflict: %v", err)
	}
	reply = hostproto.Strings("ok", `"v2"`)
	if v, err := h.Put(ctx, "vaults/v/state", []byte("x"), "v"); err != nil || v != `"v2"` {
		t.Fatalf("put: %v", err)
	}
	if len(wrote) != 1 || wrote[0] != "vaults/v/state" {
		t.Fatalf("activity %v", wrote)
	}
	if _, err := h.Put(ctx, "../x", nil, ""); !errors.Is(err, store.ErrKey) {
		t.Fatal("invalid key sent")
	}
	reply = hostproto.Strings("not_found")
	if err := h.Delete(ctx, "vaults/v/state", "v"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("delete: %v", err)
	}
	// A cancelled context does not abandon a write half way.
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	reply = hostproto.Strings("ok", `"v3"`)
	if v, err := h.Put(cctx, "vaults/v/state", []byte("x"), "v"); err != nil || v != `"v3"` {
		t.Fatalf("put under a cancelled context: %v", err)
	}
	// A link that is down fails fast.
	l.set(nil, time.Now())
	if _, _, err := h.Get(ctx, "vaults/v/state"); !errors.Is(err, errHost) {
		t.Fatalf("down: %v", err)
	}
}

func TestCredentials(t *testing.T) {
	l := fakeParent(t, func(*hostproto.Frame) [][]byte {
		return hostproto.Strings("ok", "AK", "SK", "ST", "2026-10-02T12:00:00Z")
	})
	c, err := l.credentials(context.Background())
	if err != nil || c.AccessKeyID != "AK" || c.SessionToken != "ST" || c.Expires.IsZero() {
		t.Fatalf("credentials %+v %v", c, err)
	}
	l = fakeParent(t, func(*hostproto.Frame) [][]byte { return hostproto.Strings("ok", "AK", "SK", "ST", "tomorrow") })
	if _, err := l.credentials(context.Background()); err == nil {
		t.Fatal("bad expiry accepted")
	}
}

func TestVaultOfStateKey(t *testing.T) {
	for k, want := range map[string]string{"vaults/abc/state": "abc", "vaults/abc/header/x": "", "users/x/vault": "", "vaults/a/b/state": ""} {
		if got, _ := vaultOfStateKey(k); got != want {
			t.Errorf("%s: %q", k, got)
		}
	}
}

func TestErrText(t *testing.T) {
	if errText(context.Canceled) != "canceled" || errText(&net.OpError{Op: "dial", Err: errors.New("secret detail")}) != "network error" {
		t.Fatal("errText")
	}
}
