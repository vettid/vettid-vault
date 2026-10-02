// Command vault-enclave is the process that runs inside the Nitro enclave
// (VAULT-PLAN V3, decision D4): the supervisor, which owns the NSM, the
// ETKs and the alternate channel, the egress transport, and one vault
// manager per unlocked vault.
//
// The same binary, started with vaultproc.Arg, is one vault's process
// (VAULT-MESSAGING §12.4): the supervisor re-executes itself for every
// unlocked vault, so there is one measured image.
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
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/vettid/vettid-vault/enclave/supervisor"
	"github.com/vettid/vettid-vault/enclave/vaultproc"
)

func main() {
	if len(os.Args) > 2 && os.Args[1] == vaultproc.Arg && slices.Contains(os.Args[2:], vaultproc.SelftestArg) {
		// The hardware smoke test's vault process (docs/SMOKE.md).
		vaultproc.SelftestMain()
		return
	}
	if len(os.Args) > 1 && os.Args[1] == vaultproc.Arg {
		// A vault's own process (D4), started by the supervisor.
		p, err := vaultPlatform(os.Args[2:])
		if err != nil {
			os.Exit(vaultproc.ExitError)
		}
		vaultproc.Main(p)
		return
	}
	cfg, err := platform()
	if err != nil {
		fmt.Fprintln(os.Stderr, "vault-enclave:", err)
		os.Exit(2)
	}
	if total := memTotal(); total > 0 {
		// Lock the least recently active vaults (ending their processes)
		// while less than 15% of the enclave's memory is available (§12.3).
		debug.SetMemoryLimit(int64(total) * 25 / 100) // the supervisor's own heap
		if cfg.MemoryReserve == 0 {
			cfg.MemoryReserve = total * 15 / 100
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
