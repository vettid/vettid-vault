package parent

import (
	"context"
	"testing"

	"github.com/vettid/vettid-vault/internal/hostproto"
	"github.com/vettid/vettid-vault/internal/selftest"
)

type memObjects map[string][]byte

func (m memObjects) Get(_ context.Context, k string) ([]byte, string, error) {
	b, ok := m[k]
	if !ok {
		return nil, "", ErrNotFound
	}
	return b, "v", nil
}
func (m memObjects) Put(_ context.Context, k string, b []byte, _ string) (string, error) {
	m[k] = b
	return "v", nil
}
func (m memObjects) Delete(_ context.Context, k, _ string) error { delete(m, k); return nil }

// The self-test parent stores only under smoke/<run_id>/.
func TestSelftestScope(t *testing.T) {
	c := SelftestConfig{Objects: memObjects{}}
	h := func(k hostproto.Kind, f ...string) string {
		r := selftestHandle(context.Background(), c, "smoke/run-1/", nil, make(chan *hostproto.Conn, 1), &hostproto.Frame{Kind: k, Fields: hostproto.Strings(f...)})
		return string(r[0])
	}
	if got := h(hostproto.KindStorePut, "smoke/run-1/object", "x", ""); got != "ok" {
		t.Fatalf("own prefix: %s", got)
	}
	for _, k := range []string{"vaults/a/state", "smoke/run-2/object", "smoke/run-1/../x", "users/u/vault"} {
		if got := h(hostproto.KindStorePut, k, "x", ""); got != hostproto.StatusInvalid {
			t.Errorf("%s: %s", k, got)
		}
	}
	if got := h(hostproto.KindQueue, "x"); got != hostproto.StatusInvalid {
		t.Fatalf("queue in selftest: %s", got)
	}
}

func TestSelftestVerdict(t *testing.T) {
	r := &selftest.Report{KeyPolicyCheck: 6}
	r.Add("a", true, true, "")
	r.Add("b", false, false, "info")
	if bad := SelftestVerdict(r, 6); len(bad) != 0 {
		t.Fatalf("%v", bad)
	}
	if bad := SelftestVerdict(r, 8); len(bad) != 1 {
		t.Fatalf("wrong check accepted: %v", bad)
	}
	r.Add("c", false, true, "")
	if bad := SelftestVerdict(r, 0); len(bad) != 1 {
		t.Fatalf("required failure: %v", bad)
	}
	if _, err := selftest.ParseRequest([]byte(`{"run_id":"Bad/ID","key_arn":"x","account":"111122223333","region":"us-east-1"}`)); err == nil {
		t.Fatal("bad run id accepted")
	}
}
