package enclavetest

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"log/slog"
	"net"
	"net/url"
	"time"

	"github.com/vettid/vettid-vault/enclave"
	"github.com/vettid/vettid-vault/enclave/egress"
	"github.com/vettid/vettid-vault/enclave/supervisor"
	"github.com/vettid/vettid-vault/features/messaging"
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
	DownLock  time.Duration
	LogLevel  slog.Level
	OnReady   func(*enclave.Instance)
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
	tr, err := egress.New(egress.Config{Conns: 2, Hosts: []egress.Host{
		{Name: u.Hostname(), Roots: roots, HTTP2: true},
		{Name: "android.googleapis.com", Roots: roots, HTTP2: true},
		{Name: "kms." + KMSRegion + ".amazonaws.com", Roots: roots},
	}, Dialer: egress.DialerFunc(func(ctx context.Context, host string, port uint16) (net.Conn, error) {
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
	})})
	if err != nil {
		return supervisor.Config{}, err
	}
	mk := ManifestKey()
	control := o.Control
	return supervisor.Config{
		Enclave: func(id string) enclave.Config {
			return enclave.Config{InstanceID: id, ReleaseNumber: o.Release, ManifestKeys: []*ecdsa.PublicKey{&mk.PublicKey},
				SealAccount: KMSAccount, SealRegion: KMSRegion, DeviceAttest: Policy(), RelayURL: o.RelayURL, KDF: vault.MinKDF}
		},
		NSM: NewFakeNSM(spec.PCR0, spec.PCR1, spec.PCR2, time.Now),
		Control: func(ctx context.Context) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", control)
		},
		Egress:    tr,
		Features:  func() []vault.Feature { return []vault.Feature{messaging.New()} },
		MaxVaults: o.MaxVaults,
		DownLock:  o.DownLock,
		LogLevel:  o.LogLevel,
		OnReady:   o.OnReady,
	}, nil
}
