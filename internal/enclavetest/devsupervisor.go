package enclavetest

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"errors"
	"flag"
	"github.com/vettid/vettid-vault/internal/countertest"
	"github.com/vettid/vettid-vault/internal/reckeytest"
	"io"
	"log/slog"
	"net"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/vettid/vettid-vault/enclave"
	"github.com/vettid/vettid-vault/enclave/egress"
	"github.com/vettid/vettid-vault/enclave/supervisor"
	"github.com/vettid/vettid-vault/enclave/vaultproc"
	"github.com/vettid/vettid-vault/features/all"
	"github.com/vettid/vettid-vault/internal/hostproto"
	"github.com/vettid/vettid-vault/vault"
)

// DevOptions configure a TEST-ONLY development supervisor.
type DevOptions struct {
	// Release is the test release number (PCRs from Spec).
	Release uint64
	// Control and Egress are the parent's TCP addresses.
	Control, Egress string
	// RelayURL is https://<host>; the host is allowlisted.
	RelayURL  string
	MaxVaults int
	// VaultExec is the vault process's argv (a dev vault-enclave binary
	// with vaultproc.Arg and DevVaultArgs).
	VaultExec []string
	DownLock  time.Duration
	LogLevel  slog.Level
	OnReady   func(*enclave.Instance)
	// DevicePolicy extends the TEST device-attestation policy
	// (DEVELOPMENT ONLY, -dev-device-policy); nil: the TEST policy. The
	// vault processes need it too: append DevVaultPolicyArgs to VaultExec.
	DevicePolicy *DevDevicePolicy
	// RecoveryClock, if set, names a file holding the offset (a Go
	// duration) of the recovery clock from the real one (DEVELOPMENT ONLY,
	// -dev-recovery-clock; DevRecoveryClock). The vault processes need it
	// too: append DevVaultRecoveryClockArgs to VaultExec.
	RecoveryClock string
	// PushURL, if set, is the push gateway stand-in (https://host,
	// internal/pushtest; 0.24.0): its host is allowlisted with the test
	// TLS root. The vault processes need it too: append DevVaultPushArgs.
	PushURL string
	// TimeScale, if above 1, is the development time scale (0.43.0,
	// STAGING-TIME-SCALE §5.1; DEVELOPMENT ONLY, devstack -time-scale):
	// 1 to vault.MaxTimeScale. The vault processes need it too: append
	// DevVaultTimeScaleArgs.
	TimeScale uint64
}

// DevSupervisor returns a supervisor configuration for development and
// tests: TCP to the parent, the fake NSM with the PCRs of test release N,
// the test TLS root for every egress host, the test manifest key and
// sealing namespace, test device-attestation roots, and the minimum KDF.
// Everything else (supervisor, egress, KMS client, host protocol) is the
// release code.
func DevSupervisor(o DevOptions) (supervisor.Config, error) {
	if o.Release == 0 || o.Release > 15 {
		return supervisor.Config{}, errors.New("enclavetest: release must be 1-15")
	}
	if o.TimeScale > vault.MaxTimeScale {
		return supervisor.Config{}, errors.New("enclavetest: time scale must be 1-86400")
	}
	u, err := url.Parse(o.RelayURL)
	if err != nil || u.Scheme != "https" || u.Port() != "" || u.Path != "" || u.Hostname() == "" {
		return supervisor.Config{}, errors.New("enclavetest: relay URL must be https://host")
	}
	var pushHost string
	if o.PushURL != "" {
		pu, err := url.Parse(o.PushURL)
		if err != nil || pu.Scheme != "https" || pu.Port() != "" || pu.Path != "" || pu.Hostname() == "" {
			return supervisor.Config{}, errors.New("enclavetest: push URL must be https://host")
		}
		pushHost = pu.Hostname()
	}
	spec := Spec(o.Release, "")
	roots := TLSRoots()
	egressAddr := o.Egress
	dialer := egress.DialerFunc(func(ctx context.Context, host string, port uint16) (net.Conn, error) {
		var d net.Dialer
		c, err := d.DialContext(ctx, "tcp", egressAddr)
		if err != nil {
			return nil, err
		}
		if err := hostproto.OpenEgress(c, host, port); err != nil {
			c.Close()
			return nil, err
		}
		return c, nil
	})
	hosts := func(region string) []egress.Host {
		h := []egress.Host{
			{Name: u.Hostname(), Roots: roots, HTTP2: true},
			{Name: "android.googleapis.com", Roots: roots, HTTP2: true},
			{Name: "kms." + region + ".amazonaws.com", Roots: roots},
		}
		if pushHost != "" {
			h = append(h, egress.Host{Name: pushHost, Roots: roots, HTTP2: true})
		}
		return h
	}
	tr, err := egress.New(egress.Config{Conns: 2, Hosts: hosts(KMSRegion), Dialer: dialer})
	if err != nil {
		return supervisor.Config{}, err
	}
	control := o.Control
	return supervisor.Config{
		Enclave: func(id string) enclave.Config {
			c := devConfig(id, o.Release, o.RelayURL, o.DevicePolicy)
			c.PushURL = o.PushURL
			c.TimeScale = o.TimeScale
			if o.RecoveryClock != "" {
				c.RecoveryNow = DevRecoveryClock(o.RecoveryClock)
			}
			return c
		},
		NSM: NewFakeNSM(spec.PCR0, spec.PCR1, spec.PCR2, time.Now),
		Control: func(ctx context.Context) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", control)
		},
		Egress:     tr,
		Proc:       supervisor.ProcConfig{Exec: o.VaultExec},
		RelayHosts: []string{u.Hostname()},
		NitroRoots: TestNitroCA().Roots(),
		SelftestEgress: func(region string) (*egress.Transport, error) {
			return egress.New(egress.Config{Conns: 1, Hosts: hosts(region), Dialer: dialer})
		},
		MaxVaults: o.MaxVaults,
		DownLock:  o.DownLock,
		LogLevel:  o.LogLevel,
		OnReady:   o.OnReady,
		// Release R: an in-memory stand-in for the attempt counter's
		// bucket (development only; its clock runs with the real time).
		Counter: countertest.NewLive(),
	}, nil
}

// DevConfig is the TEST-ONLY instance configuration of test release n:
// the test manifest key, sealing namespace and device-attestation roots,
// and the minimum KDF.
func DevConfig(instanceID string, n uint64, relayURL string) enclave.Config {
	return devConfig(instanceID, n, relayURL, nil)
}

func devConfig(instanceID string, n uint64, relayURL string, dp *DevDevicePolicy) enclave.Config {
	mk := ManifestKey()
	return enclave.Config{InstanceID: instanceID, ReleaseNumber: n, ManifestKeys: []*ecdsa.PublicKey{&mk.PublicKey},
		SealAccount: KMSAccount, SealRegion: KMSRegion,
		RetirementPrincipal: RetirementRole, RetirementWindowDays: RetirementWindow, DeviceAttest: dp.Apply(Policy()), RelayURL: relayURL, KDF: vault.MinKDF,
		// Release R: the stand-in's recovery request key, recovery offered.
		// The development stack has no attempt counter, so the quiet
		// period is not simulated here (the code is valid after 24 h).
		Recovery: enclave.RecoveryConfig{RequestKeys: reckeytest.Pinned(), Offered: true, WaitUnit: 10 * time.Minute, Quiet: time.Nanosecond}}
}

// DevVaultArgs are the arguments after vaultproc.Arg for a dev vault
// process.
func DevVaultArgs(n uint64, relayURL string) []string {
	return []string{"-release", strconv.FormatUint(n, 10), "-relay-url", relayURL}
}

// DevVaultPolicyArgs are the arguments that pass a dev device policy on
// to a dev vault process (none for nil).
func DevVaultPolicyArgs(p *DevDevicePolicy) []string {
	if p == nil {
		return nil
	}
	return []string{"-device-policy", base64.StdEncoding.EncodeToString(p.raw)}
}

// DevVaultRecoveryClockArgs pass a recovery clock file on to a dev vault
// process (none for "").
func DevVaultRecoveryClockArgs(path string) []string {
	if path == "" {
		return nil
	}
	return []string{"-recovery-clock", path}
}

// DevVaultPushArgs pass the push gateway stand-in's URL on to a dev vault
// process (none for "").
func DevVaultPushArgs(pushURL string) []string {
	if pushURL == "" {
		return nil
	}
	return []string{"-push-url", pushURL}
}

// DevVaultTimeScaleArgs pass a development time scale on to a dev vault
// process (none for 0 or 1).
func DevVaultTimeScaleArgs(n uint64) []string {
	if n <= 1 {
		return nil
	}
	return []string{"-time-scale", strconv.FormatUint(n, 10)}
}

// ParseDevFeatures parses a development feature list (-dev-features,
// VAULT-MESSAGING 0.26.0 §11.10.8, "The development build"): "all" (the
// default: every optional feature), "none" (production release 1's
// list), or a comma-separated list of optional feature names. The result
// is never nil.
func ParseDevFeatures(s string) ([]string, error) {
	switch s {
	case "all":
		return all.Optional(), nil
	case "none":
		return []string{}, nil
	}
	names := strings.Split(s, ",")
	if err := all.CheckOptional(names); err != nil {
		return nil, err
	}
	sort.Strings(names)
	return names, nil
}

// DevVaultFeatureArgs pass a development feature list on to a dev vault
// process (none for nil: every optional feature). The supervisor runs no
// feature code, so only the vault processes need it.
func DevVaultFeatureArgs(features []string) []string {
	if features == nil {
		return nil
	}
	if len(features) == 0 {
		return []string{"-features", "none"}
	}
	return []string{"-features", strings.Join(features, ",")}
}

// MaxRecoveryClockFile bounds the recovery clock file.
const MaxRecoveryClockFile = 64

// DevRecoveryClock is a DEVELOPMENT-ONLY recovery clock
// (enclave.Config.RecoveryNow): the real time plus the duration written in
// the file at path (e.g. "24h"), read at every call, so that a dev stack
// can move it past a recovery's 24 h delay while the enclave runs. A
// missing or malformed file is an offset of zero.
func DevRecoveryClock(path string) func() time.Time {
	return func() time.Time {
		return time.Now().Add(readRecoveryOffset(path))
	}
}

func readRecoveryOffset(path string) time.Duration {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, MaxRecoveryClockFile+1))
	if err != nil || len(b) > MaxRecoveryClockFile {
		return 0
	}
	d, err := time.ParseDuration(strings.TrimSpace(string(b)))
	if err != nil || d < 0 {
		return 0
	}
	return d
}

// DevVaultPlatform parses DevVaultArgs (and DevVaultPolicyArgs) into a dev vault process's
// platform (TEST-ONLY configuration, the messaging feature).
func DevVaultPlatform(args []string) (vaultproc.Platform, error) {
	fs := flag.NewFlagSet("vault-process", flag.ContinueOnError)
	n := fs.Uint64("release", 3, "test release")
	relay := fs.String("relay-url", "", "relay URL")
	policy := fs.String("device-policy", "", "dev device policy (base64)")
	clock := fs.String("recovery-clock", "", "recovery clock file (DevRecoveryClock)")
	push := fs.String("push-url", "", "push gateway stand-in URL (DevVaultPushArgs)")
	feats := fs.String("features", "all", "optional features (DevVaultFeatureArgs)")
	scale := fs.Uint64("time-scale", 1, "development time scale (DevVaultTimeScaleArgs)")
	if err := fs.Parse(args); err != nil || *n == 0 || *n > 15 || *relay == "" || fs.NArg() != 0 || *scale == 0 || *scale > vault.MaxTimeScale {
		return vaultproc.Platform{}, errors.New("enclavetest: bad vault process arguments")
	}
	optional, err := ParseDevFeatures(*feats)
	if err != nil {
		return vaultproc.Platform{}, errors.New("enclavetest: bad vault process arguments")
	}
	var dp *DevDevicePolicy
	if *policy != "" {
		b, err := base64.StdEncoding.Strict().DecodeString(*policy)
		if err != nil {
			return vaultproc.Platform{}, errors.New("enclavetest: bad vault process arguments")
		}
		if dp, err = ParseDevDevicePolicy(b); err != nil {
			return vaultproc.Platform{}, err
		}
	}
	return vaultproc.Platform{
		Config: func(id string) enclave.Config {
			c := devConfig(id, *n, *relay, dp)
			c.PushURL = *push
			c.TimeScale = *scale
			if *clock != "" {
				c.RecoveryNow = DevRecoveryClock(*clock)
			}
			return c
		},
		Features:       func() []vault.Feature { return all.New(all.DevOptionsWith(optional)) },
		RequireSeccomp: true,
	}, nil
}
