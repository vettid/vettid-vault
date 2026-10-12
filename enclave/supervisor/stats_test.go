package supervisor

import (
	"context"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"reflect"
	"sync"
	"sync/atomic"
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
	// The parent sees a snapshot, however often it asks: one more
	// failure does not show at once.
	if got := get(context.Background()); got != hostproto.StatusError {
		t.Fatalf("request without a connection: %s", got)
	}
	if again := s.stats(); !reflect.DeepEqual(again, r) {
		t.Errorf("stats asked again at once: %q", again)
	}
	s.statsAt = s.statsAt.Add(-statsEvery)
	if again := s.stats(); string(again[len(again)-5]) != "2" {
		t.Errorf("stats a second later: %q", again)
	}
}

// One vault process cannot take the shared streams from the others: its
// requests beyond maxVaultEgress in flight wait for one of its own to
// end, and are answered an error if their time ends first.
func TestVaultEgressLimit(t *testing.T) {
	var held atomic.Int32
	release := make(chan struct{})
	rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		held.Add(1)
		defer held.Add(-1)
		select {
		case <-release:
			return &http.Response{StatusCode: 200, Header: http.Header{}, Body: http.NoBody, Request: r}, nil
		case <-r.Context().Done():
			return nil, r.Context().Err()
		}
	})
	s := &Supervisor{relays: map[string]bool{"relay.example": true}, relayHTTP: &http.Client{Transport: rt}, activity: map[string]time.Time{},
		log: slog.New(slog.DiscardHandler)}
	h := &procHost{s: s}
	mine, other := &vproc{h: h, vaultID: "aaaa"}, &vproc{h: h, vaultID: "bbbb"}
	get := func(ctx context.Context, p *vproc) string {
		r := p.handle(ctx, &hostproto.Frame{Kind: vaultipc.KindHTTP, ID: 1,
			Fields: [][]byte{[]byte(http.MethodGet), []byte("https://relay.example/v1/mailbox"), vaultipc.EncodeHeaders(http.Header{}), nil}})
		return string(r[0])
	}
	var wg sync.WaitGroup
	var ok atomic.Int32
	for i := 0; i < maxVaultEgress+12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if get(context.Background(), mine) == hostproto.StatusOK {
				ok.Add(1)
			}
		}()
	}
	deadline := time.Now().Add(10 * time.Second)
	for held.Load() != maxVaultEgress && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	if n := held.Load(); n != maxVaultEgress {
		t.Fatalf("%d requests of one vault in flight; want %d", n, maxVaultEgress)
	}
	// A request over the limit whose time ends is refused; it never
	// reached the relay, and it is not counted as the relay's failure.
	short, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if got := get(short, mine); got != hostproto.StatusError || held.Load() != maxVaultEgress || s.relayErrs.Load() != 0 {
		t.Errorf("request over the limit: %s, %d in flight, %d counted", got, held.Load(), s.relayErrs.Load())
	}
	// Another vault is not held up.
	wg.Add(1)
	go func() { defer wg.Done(); get(context.Background(), other) }()
	for held.Load() != maxVaultEgress+1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if n := held.Load(); n != maxVaultEgress+1 {
		t.Errorf("another vault's request did not go out: %d in flight", n)
	}
	close(release)
	wg.Wait()
	if ok.Load() != maxVaultEgress+12 {
		t.Errorf("%d of %d requests answered once the first ended", ok.Load(), maxVaultEgress+12)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
