package vaultproc

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/enclave"
	"github.com/vettid/vettid-vault/internal/hostproto"
	"github.com/vettid/vettid-vault/internal/vaultipc"
)

// A code pairing's permit (0.94.0 §6.7.2) is asked of the supervisor as
// acquire_code, the recovery wrap's as acquire, both on KindHeavyPermit; a
// "0" is no permit, and the release goes back as release.
func TestPermitsGoToTheSupervisor(t *testing.T) {
	a, b := net.Pipe()
	got := make(chan string, 8)
	give := "1"
	sup := hostproto.NewConn(a, func(_ context.Context, f *hostproto.Frame) [][]byte {
		if f.Kind != vaultipc.KindHeavyPermit || len(f.Fields) != 1 {
			return [][]byte{[]byte("error")}
		}
		got <- string(f.Fields[0])
		return [][]byte{[]byte(hostproto.StatusOK), []byte(give)}
	}, nil)
	defer sup.Close()
	proc := hostproto.NewConn(b, nil, nil)
	defer proc.Close()
	ch := channel{c: proc}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rel, ok := codePermit(ch)(ctx)
	if !ok || <-got != vaultipc.HeavyAcquireCode {
		t.Fatal("the code permit is not asked as acquire_code")
	}
	rel()
	if <-got != vaultipc.HeavyRelease {
		t.Fatal("not released")
	}
	if _, ok := heavyPermit(ch)(ctx); !ok || <-got != vaultipc.HeavyAcquire {
		t.Fatal("the heavy permit is not asked as acquire")
	}
	give = "0"
	if _, ok := codePermit(ch)(ctx); ok {
		t.Fatal("a refusal taken as a permit")
	}
}

// The opened vault's options carry both permits, each asking its own op;
// a "-" (no room) reads as no permit, not worth waiting for.
func TestVaultOptionsCarryThePermits(t *testing.T) {
	a, b := net.Pipe()
	got := make(chan string, 8)
	reply := "1"
	sup := hostproto.NewConn(a, func(_ context.Context, f *hostproto.Frame) [][]byte {
		got <- string(f.Fields[0])
		return [][]byte{[]byte(hostproto.StatusOK), []byte(reply)}
	}, nil)
	defer sup.Close()
	proc0 := hostproto.NewConn(b, nil, nil)
	defer proc0.Close()
	pr := &proc{p: Platform{}, ch: channel{c: proc0}}
	o := pr.vaultOptions(enclave.Config{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, ok := o.CodePermit(ctx); !ok || <-got != vaultipc.HeavyAcquireCode {
		t.Fatal("CodePermit does not ask acquire_code")
	}
	if _, ok := o.HeavyPermit(ctx); !ok || <-got != vaultipc.HeavyAcquire {
		t.Fatal("HeavyPermit does not ask acquire")
	}
	reply = vaultipc.HeavyNoRoom
	if rel, ok := o.CodePermit(ctx); ok || rel == nil {
		t.Fatal("no room not read as busy now")
	}
	<-got
	reply = "0"
	if rel, ok := o.CodePermit(ctx); ok || rel != nil {
		t.Fatal("held read as no room")
	}
}
