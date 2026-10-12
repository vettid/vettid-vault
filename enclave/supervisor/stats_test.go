package supervisor

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/enclave/egress"
	"github.com/vettid/vettid-vault/internal/hostproto"
	"github.com/vettid/vettid-vault/internal/vaultipc"
)

// VAULT-RELAY-SCALING §6: the supervisor counts the relay requests that
// got no answer and reports them, with the state of the shared relay
// connections, to the parent.
func TestRelayStats(t *testing.T) {
	tr, err := egress.New(egress.Config{Hosts: []egress.Host{{Name: "relay.example", Roots: x509.NewCertPool(), HTTP2: true}},
		Dialer: egress.DialerFunc(func(context.Context, string, uint16) (net.Conn, error) { return nil, errors.New("down") })})
	if err != nil {
		t.Fatal(err)
	}
	s := &Supervisor{cfg: Config{Egress: tr}, relays: map[string]bool{"relay.example": true}, relayHTTP: tr.Client(5 * time.Second),
		activity: map[string]time.Time{}}
	p := &vproc{h: &procHost{s: s}, vaultID: "aaaa"}
	get := func(ctx context.Context) string {
		r := p.handle(ctx, &hostproto.Frame{Kind: vaultipc.KindHTTP, ID: 1,
			Fields: [][]byte{[]byte(http.MethodGet), []byte("https://relay.example/v1/mailbox"), vaultipc.EncodeHeaders(http.Header{}), nil}})
		return string(r[0])
	}
	if got := get(context.Background()); got != hostproto.StatusError {
		t.Fatalf("request without a connection: %s", got)
	}
	// A request its vault process gave up is not the relay's failure.
	gone, cancel := context.WithCancel(context.Background())
	cancel()
	if got := get(gone); got != hostproto.StatusError {
		t.Fatalf("abandoned request: %s", got)
	}
	r := s.stats()
	if string(r[0]) != hostproto.StatusOK || len(r)%2 != 1 {
		t.Fatalf("stats reply %q", r)
	}
	got := map[string]string{}
	for i := 1; i < len(r); i += 2 {
		got[string(r[i])] = string(r[i+1])
	}
	want := map[string]string{hostproto.StatRelayConns: "0", hostproto.StatRelayDialed: "0", hostproto.StatRelayStreams: "0",
		hostproto.StatRelayInFlight: "0", hostproto.StatRelayWaiting: "0", hostproto.StatRelayErrors: "1",
		hostproto.StatRelayRefusedMax: "0", hostproto.StatRelayRefusedMin: "0"}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %s", k, got[k], v)
		}
	}
	if _, ok := got[hostproto.StatRelayWaitMaxMS]; !ok || len(got) != len(want)+1 {
		t.Errorf("stats %v", got)
	}
}
