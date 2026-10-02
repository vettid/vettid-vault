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

func TestServeRefusesMalformedOpen(t *testing.T) {
	a, b := net.Pipe()
	done := make(chan int, 1)
	go func() {
		done <- Serve(b, Platform{Config: func(string) enclave.Config { return enclave.Config{} }})
	}()
	sup := hostproto.NewConn(a, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r, err := sup.Call(ctx, vaultipc.KindOpen, hostproto.Strings("0", "i-1")...)
	if err != nil || string(r[0]) != hostproto.StatusInvalid {
		t.Fatalf("bad version: %q %v", r, err)
	}
	// One open per process, even after a refusal.
	r, err = sup.Call(ctx, vaultipc.KindOpen, hostproto.Strings(vaultipc.Version, "i-1")...)
	if err != nil || string(r[0]) != hostproto.StatusInvalid {
		t.Fatalf("second open: %q %v", r, err)
	}
	if r, err := sup.Call(ctx, vaultipc.KindLock); err != nil || string(r[0]) != hostproto.StatusOK {
		t.Fatalf("lock without a vault: %q %v", r, err)
	}
	// Unknown kinds get "invalid".
	if r, _ := sup.Call(ctx, vaultipc.KindStoreGet, []byte("vaults/x/state")); string(r[0]) != hostproto.StatusInvalid {
		t.Fatalf("store request to a vault process: %q", r)
	}
	sup.Close()
	select {
	case code := <-done:
		if code != ExitLocked {
			t.Fatalf("exit %d", code)
		}
	case <-ctx.Done():
		t.Fatal("vault process did not end with its channel")
	}
}

func TestHardenNotDumpable(t *testing.T) {
	Harden()
	if d, err := Dumpable(); err == nil && d > 0 {
		t.Fatalf("dumpable %d", d)
	}
}
