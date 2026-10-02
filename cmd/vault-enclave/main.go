// Command vault-enclave is the process that runs inside the Nitro enclave
// (VAULT-PLAN V3, decision D4): the supervisor, which owns the NSM, the
// ETKs and the alternate channel, the egress transport, and one vault
// manager per unlocked vault.
//
// Release builds (no build tags) talk to the parent over vsock, use the
// real NSM, and reach only relay.vettid.org, kms.<region>.amazonaws.com
// and android.googleapis.com through TLS against pinned roots. Development
// builds (-tags devenclave, vault_dev.go) use TCP, the TEST-ONLY fake NSM
// and test roots instead; `make check-tcb` keeps that code out of release
// builds.
package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"

	"github.com/vettid/vettid-vault/enclave/supervisor"
)

func main() {
	cfg, err := platform()
	if err != nil {
		fmt.Fprintln(os.Stderr, "vault-enclave:", err)
		os.Exit(2)
	}
	if total := memTotal(); total > 0 {
		// Collect hard before the enclave runs out of memory, and lock
		// the least recently active vaults above 70% (§12.3).
		debug.SetMemoryLimit(int64(total) * 85 / 100)
		if cfg.MemoryHigh == 0 {
			cfg.MemoryHigh = total * 70 / 100
		}
	}
	s, err := supervisor.New(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "vault-enclave:", err)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	s.Logger().Info("enclave starting")
	if err := s.Run(ctx); err != nil {
		s.Logger().Error("enclave stopped", "error", err.Error())
		os.Exit(1)
	}
}

// memTotal reads MemTotal from /proc/meminfo (bytes; 0 if unknown).
func memTotal() uint64 {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if rest, ok := strings.CutPrefix(sc.Text(), "MemTotal:"); ok {
			kb, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimSpace(rest), " kB"), 10, 64)
			if err == nil {
				return kb * 1024
			}
		}
	}
	return 0
}
