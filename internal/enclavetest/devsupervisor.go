package enclavetest

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"errors"
	"flag"
	"log/slog"
	"net"
	"net/url"
	"strconv"
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
	u, err := url.Parse(o.RelayURL)
	if err != nil || u.Scheme != "https" || u.Port() != "" || u.Path != "" || u.Hostname() == "" {
		return supervisor.Config{}, errors.New("enclavetest: relay URL must be https://host")
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
		return []egress.Host{
			{Name: u.Hostname(), Roots: roots, HTTP2: true},
			{Name: "android.googleapis.com", Roots: roots, HTTP2: true},
			{Name: "kms." + region + ".amazonaws.com", Roots: roots},
		}
	}
	tr, err := egress.New(egress.Config{Conns: 2, Hosts: hosts(KMSRegion), Dialer: dialer})
	if err != nil {
		return supervisor.Config{}, err
	}
	control := o.Control
	return supervisor.Config{
		Enclave: func(id string) enclave.Config { return devConfig(id, o.Release, o.RelayURL, o.DevicePolicy) },
		NSM:     NewFakeNSM(spec.PCR0, spec.PCR1, spec.PCR2, time.Now),
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
		RetirementPrincipal: RetirementRole, RetirementWindowDays: RetirementWindow, DeviceAttest: dp.Apply(Policy()), RelayURL: relayURL, KDF: vault.MinKDF}
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

// DevVaultPlatform parses DevVaultArgs (and DevVaultPolicyArgs) into a dev vault process's
// platform (TEST-ONLY configuration, the messaging feature).
func DevVaultPlatform(args []string) (vaultproc.Platform, error) {
	fs := flag.NewFlagSet("vault-process", flag.ContinueOnError)
	n := fs.Uint64("release", 3, "test release")
	relay := fs.String("relay-url", "", "relay URL")
	policy := fs.String("device-policy", "", "dev device policy (base64)")
	if err := fs.Parse(args); err != nil || *n == 0 || *n > 15 || *relay == "" || fs.NArg() != 0 {
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
		Config:         func(id string) enclave.Config { return devConfig(id, *n, *relay, dp) },
		Features:       func() []vault.Feature { return all.Dev() },
		RequireSeccomp: true,
	}, nil
}
