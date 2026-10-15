//go:build !devenclave

package main

import (
	"context"
	"errors"
	"net"
	"net/url"
	"os"

	"github.com/vettid/vettid-vault/enclave"
	"github.com/vettid/vettid-vault/enclave/egress"
	"github.com/vettid/vettid-vault/enclave/nsm"
	"github.com/vettid/vettid-vault/enclave/supervisor"
	"github.com/vettid/vettid-vault/enclave/vaultproc"
	"github.com/vettid/vettid-vault/features/all"
	"github.com/vettid/vettid-vault/internal/hostproto"
	"github.com/vettid/vettid-vault/internal/vsock"
	toolchain "github.com/vettid/vettid-vault/release"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/pins"
	"github.com/vettid/vettid-vault/vms/recovery"
)

// errTestCost: a release binary built with the test-only tag
// vettid_testcost (VAULT-MESSAGING 0.33.0 §11.14.14) refuses to start.
var errTestCost = errors.New("vault-enclave: built with vettid_testcost")

// vsock ports on the parent (CID 3).
const (
	controlPort = 5000
	egressPort  = 5001
)

func platform() (supervisor.Config, error) {
	if recovery.TestCost {
		return supervisor.Config{}, errTestCost
	}
	kernelRelease, kernelHardened := toolchain.Kernel()
	dev, err := nsm.Open()
	if err != nil {
		return supervisor.Config{}, err
	}
	tr, err := egress.New(egress.Config{Hosts: releaseHosts(enclave.ReleaseRegion()), Conns: 4, Dialer: egress.DialerFunc(dialEgress)})
	if err != nil {
		return supervisor.Config{}, err
	}
	exe, err := os.Executable()
	if err != nil {
		return supervisor.Config{}, err
	}
	return supervisor.Config{
		Enclave: func(id string) enclave.Config { return enclave.ReleaseConfig(id, enclave.ReleaseRelayURL()) },
		NSM:     dev,
		Control: func(ctx context.Context) (net.Conn, error) { return vsock.Dial(ctx, vsock.CIDHost, controlPort) },
		Egress:  tr,
		// One process per vault, each under its own uid (D4).
		Proc:       supervisor.ProcConfig{Exec: []string{exe, vaultproc.Arg}, UIDBase: vaultUIDBase},
		RelayHosts: []string{relayHost()},
		Harden:     true,
		OwnKernel:  true,
		// The enclave kernel release/eif-toolchain.lock pins (embedded).
		KernelRelease:  kernelRelease,
		KernelHardened: kernelHardened,
		NitroRoots:     enclave.NitroRoots(),
		// The hardware smoke test (docs/SMOKE.md) reaches the KMS endpoint
		// of the test key's region; same roots, same forwarder.
		SelftestEgress: func(region string) (*egress.Transport, error) {
			return egress.New(egress.Config{Hosts: releaseHosts(region), Conns: 1, Dialer: egress.DialerFunc(dialEgress)})
		},
	}, nil
}

// releaseHosts is the release egress allowlist: the relay and Google with
// HTTP/2, the regional KMS endpoint (HTTP/1.1 only, docs/V3-NOTES.md)
// when a region is pinned, and the channel's push gateway (0.24.0, behind
// the relay's load balancer: Amazon's roots, HTTP/2).
func releaseHosts(region string) []egress.Host {
	amazon := pins.Pool(pins.AmazonTLSRoots())
	hosts := []egress.Host{
		{Name: relayHost(), Roots: amazon, HTTP2: true},
		{Name: "android.googleapis.com", Roots: pins.Pool(pins.GoogleTLSRoots()), HTTP2: true},
	}
	if region != "" {
		hosts = append(hosts, egress.Host{Name: "kms." + region + ".amazonaws.com", Roots: amazon})
	}
	if h := hostOf(enclave.ReleasePushURL()); h != "" {
		hosts = append(hosts, egress.Host{Name: h, Roots: amazon, HTTP2: true})
	}
	return hosts
}

// relayHost is the host of the channel's relay URL.
func relayHost() string { return hostOf(enclave.ReleaseRelayURL()) }

func hostOf(s string) string {
	if s == "" {
		return ""
	}
	u, err := url.Parse(s)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// vaultUIDBase is the first uid (and gid) of the vault processes.
const vaultUIDBase = 200000

// vaultPlatform is a vault process's pinned configuration.
func vaultPlatform([]string) (vaultproc.Platform, error) {
	if recovery.TestCost {
		return vaultproc.Platform{}, errTestCost
	}
	return vaultproc.Platform{
		Config: func(id string) enclave.Config { return enclave.ReleaseConfig(id, enclave.ReleaseRelayURL()) },
		// The optional features are the embedded channel file's list
		// (0.26.0, §11.10.8): measured, and nothing at run time adds one.
		Features:       func() []vault.Feature { return all.New(all.Options{Optional: enclave.ReleaseFeatures()}) },
		RequireSeccomp: true,
	}, nil
}

func dialEgress(ctx context.Context, host string, port uint16) (net.Conn, error) {
	c, err := vsock.Dial(ctx, vsock.CIDHost, egressPort)
	if err != nil {
		return nil, err
	}
	if err := hostproto.OpenEgress(c, host, port); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}
