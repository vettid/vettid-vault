//go:build devenclave

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/vettid/vettid-vault/enclave/supervisor"
	"github.com/vettid/vettid-vault/enclave/vaultproc"
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
	uidBase := flag.Int("vault-uid-base", 0, "run vault processes under uid/gid base+i (needs root; 0: keep ids)")
	debug := flag.Bool("debug", false, "debug logging")
	devPolicy := flag.String("dev-device-policy", "", "JSON file extending the TEST device-attestation policy (DEVELOPMENT ONLY; enclavetest.DevDevicePolicy)")
	flag.Parse()
	if flag.NArg() != 0 {
		return supervisor.Config{}, fmt.Errorf("unexpected arguments %q", flag.Args())
	}
	var dp *enclavetest.DevDevicePolicy
	if *devPolicy != "" {
		b, err := readSmall(*devPolicy, enclavetest.MaxDevDevicePolicySize)
		if err != nil {
			return supervisor.Config{}, fmt.Errorf("-dev-device-policy: %w", err)
		}
		if dp, err = enclavetest.ParseDevDevicePolicy(b); err != nil {
			return supervisor.Config{}, fmt.Errorf("-dev-device-policy: %w", err)
		}
		fmt.Fprintf(os.Stderr, "vault-enclave: DEVELOPMENT device policy from %s extends the TEST policy: %v\n", *devPolicy, dp.Summary())
	}
	lvl := slog.LevelInfo
	if *debug {
		lvl = slog.LevelDebug
	}
	exe, err := os.Executable()
	if err != nil {
		return supervisor.Config{}, err
	}
	cfg, err := enclavetest.DevSupervisor(enclavetest.DevOptions{Release: *release, Control: *control, Egress: *egress,
		RelayURL: *relayURL, MaxVaults: *maxVaults, DownLock: *downLock, LogLevel: lvl, DevicePolicy: dp,
		VaultExec: append(append([]string{exe, vaultproc.Arg}, enclavetest.DevVaultArgs(*release, *relayURL)...),
			enclavetest.DevVaultPolicyArgs(dp)...)})
	cfg.Proc.UIDBase = *uidBase
	cfg.Harden = true
	return cfg, err
}

// vaultPlatform (development): the TEST-ONLY configuration of the test
// release, from the arguments the supervisor passed.
func vaultPlatform(args []string) (vaultproc.Platform, error) {
	return enclavetest.DevVaultPlatform(args)
}

// readSmall reads a regular file of at most max bytes.
func readSmall(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, errors.New("file too large")
	}
	return b, nil
}
