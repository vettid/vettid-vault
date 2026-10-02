//go:build !devenclave

package main

import (
	"context"
	"net"

	"github.com/vettid/vettid-vault/enclave"
	"github.com/vettid/vettid-vault/enclave/egress"
	"github.com/vettid/vettid-vault/enclave/nsm"
	"github.com/vettid/vettid-vault/enclave/supervisor"
	"github.com/vettid/vettid-vault/features/messaging"
	"github.com/vettid/vettid-vault/internal/hostproto"
	"github.com/vettid/vettid-vault/internal/vsock"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/pins"
)

// vsock ports on the parent (CID 3).
const (
	controlPort = 5000
	egressPort  = 5001
)

func platform() (supervisor.Config, error) {
	dev, err := nsm.Open()
	if err != nil {
		return supervisor.Config{}, err
	}
	amazon := pins.Pool(pins.AmazonTLSRoots())
	hosts := []egress.Host{
		{Name: "relay.vettid.org", Roots: amazon, HTTP2: true},
		{Name: "android.googleapis.com", Roots: pins.Pool(pins.GoogleTLSRoots()), HTTP2: true},
	}
	if r := enclave.ReleaseRegion(); r != "" {
		// KMS endpoints offer HTTP/1.1 only (docs/V3-NOTES.md).
		hosts = append(hosts, egress.Host{Name: "kms." + r + ".amazonaws.com", Roots: amazon})
	}
	tr, err := egress.New(egress.Config{Hosts: hosts, Conns: 4, Dialer: egress.DialerFunc(dialEgress)})
	if err != nil {
		return supervisor.Config{}, err
	}
	return supervisor.Config{
		Enclave: func(id string) enclave.Config { return enclave.ReleaseConfig(id, enclave.ReleaseRelayURL) },
		NSM:     dev,
		Control: func(ctx context.Context) (net.Conn, error) { return vsock.Dial(ctx, vsock.CIDHost, controlPort) },
		Egress:  tr,
		Features: func() []vault.Feature {
			return []vault.Feature{messaging.New()}
		},
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
