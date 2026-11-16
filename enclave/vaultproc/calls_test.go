package vaultproc

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/hostproto"
	"github.com/vettid/vettid-vault/internal/vaultipc"
	"github.com/vettid/vettid-vault/vms/callswire"
)

// A vault process's request for credentials reaches the supervisor as KindCalls (the push handler would refuse it),
// for the credentials path only, signed and without an attestation of its own.
func TestCallsIssuerGoesAsKindCalls(t *testing.T) {
	if callsIssuer("", channel{}) != nil {
		t.Fatal("an issuer without a calls_url")
	}
	a, b := net.Pipe()
	got := make(chan *hostproto.Frame, 1)
	sup := hostproto.NewConn(a, func(_ context.Context, f *hostproto.Frame) [][]byte {
		got <- f
		return [][]byte{[]byte(hostproto.StatusOK), []byte("200"), vaultipc.EncodeHeaders(nil), []byte(`{"stun":[],"turn":[],"credentials":[]}`)}
	}, nil)
	defer sup.Close()
	proc := hostproto.NewConn(b, nil, nil)
	defer proc.Close()
	ci := callsIssuer("https://calls.staging.vettid.org", channel{c: proc})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := ci.Credentials(ctx, 4); err != nil {
		t.Fatal(err)
	}
	f := <-got
	if f.Kind != vaultipc.KindCalls || len(f.Fields) != 3 || string(f.Fields[0]) != callswire.PathCredentials || string(f.Fields[2]) != `{"count":4}` {
		t.Fatalf("kind %#x, fields %q", f.Kind, f.Fields)
	}
	h, err := vaultipc.DecodeHeaders(f.Fields[1])
	if err != nil || h.Get("X-VettID-Key") == "" || h.Get(callswire.HeaderAttestation) != "" {
		t.Fatalf("headers %v", h)
	}
}
