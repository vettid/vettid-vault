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

// The opened vault's options carry both permits.
func TestVaultOptionsCarryThePermits(t *testing.T) {
	pr := &proc{p: Platform{}}
	o := pr.vaultOptions(enclave.Config{})
	if o.HeavyPermit == nil || o.CodePermit == nil {
		t.Fatal("a permit not wired")
	}
}
