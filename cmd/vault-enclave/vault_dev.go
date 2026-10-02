//go:build devenclave

package main

import (
	"flag"
	"log/slog"
	"time"

	"github.com/vettid/vettid-vault/enclave/supervisor"
	"github.com/vettid/vettid-vault/internal/enclavetest"
)

// platform (development): TCP to the parent, the TEST-ONLY fake NSM with
// the PCRs of test release N, and the TEST-ONLY TLS root for every egress
// host (enclavetest.DevSupervisor). The supervisor, egress transport, KMS
// client (SigV4, TLS, Recipient CMS) and host protocol are the release
// code.
func platform() (supervisor.Config, error) {
	release := flag.Uint64("release", 3, "test release number (PCRs from enclavetest.Spec)")
	control := flag.String("control", "127.0.0.1:5000", "parent control address (TCP)")
	egress := flag.String("egress", "127.0.0.1:5001", "parent egress address (TCP)")
	relayURL := flag.String("relay-url", "https://relay.vettid.test", "relay base URL (its host is allowlisted)")
	maxVaults := flag.Int("max-vaults", 0, "vault cap (0 = none)")
	downLock := flag.Duration("down-lock", 30*time.Second, "lock every vault after the parent is gone this long")
	debug := flag.Bool("debug", false, "debug logging")
	flag.Parse()
	lvl := slog.LevelInfo
	if *debug {
		lvl = slog.LevelDebug
	}
	return enclavetest.DevSupervisor(enclavetest.DevOptions{Release: *release, Control: *control, Egress: *egress,
		RelayURL: *relayURL, MaxVaults: *maxVaults, DownLock: *downLock, LogLevel: lvl})
}
