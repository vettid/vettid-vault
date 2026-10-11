package devattest_test

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/vettid/vettid-vault/vms/devattest"
	"github.com/vettid/vettid-vault/vms/pins"
)

// oidProvisioningInfo is the extension a remotely provisioned (RKP)
// attestation certificate carries: on the certificate above the leaf.
var oidProvisioningInfo = []int{1, 3, 6, 1, 4, 1, 11129, 2, 1, 30}

// readRealChain reads one testdata/real file: only PEM CERTIFICATE
// blocks, leaf first, the root last (testdata/real/README.md).
func readRealChain(t *testing.T, path string) [][]byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var chain [][]byte
	for {
		var blk *pem.Block
		if blk, b = pem.Decode(b); blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" || len(blk.Headers) != 0 {
			t.Fatalf("a PEM block that is not a plain CERTIFICATE")
		}
		chain = append(chain, blk.Bytes)
	}
	if len(bytes.TrimSpace(b)) != 0 {
		t.Fatalf("text after the last certificate")
	}
	if len(chain) < 2 || len(chain) > 10 {
		t.Fatalf("%d certificates (2 to 10: leaf first, root last)", len(chain))
	}
	return chain
}

// The chain rules against key attestation chains of real devices
// (testdata/real/*.pem, see the README there): each must end at a pinned
// Google root and pass every chain rule (signatures, CA certificates above
// the leaf, path length, the attestation extension on the leaf only, the
// standard library's path validation), and its key description must
// parse. Run it with the chains of the test phones before a release: the
// test PKI of the other tests is made to satisfy the rules, these are
// what shows that real hardware does. The package, signer, boot state and
// challenge are not checked here (they depend on the app and the device).
func TestRealAndroidChains(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("testdata", "real", "*.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Skip("no real attestation chains in vms/devattest/testdata/real (*.pem, leaf first; see the README there): the chain rules are not checked against real hardware in this run")
	}
	p := &devattest.Policy{AndroidRoots: pins.GoogleAttestationRoots()}
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			chain := readRealChain(t, f)
			for i, der := range chain {
				c, err := x509.ParseCertificate(der)
				if err != nil {
					t.Fatalf("certificate %d: %v", i, err)
				}
				var kd, rkp bool
				for _, e := range c.Extensions {
					kd = kd || e.Id.Equal(devattest.OIDKeyDescription)
					rkp = rkp || e.Id.Equal(oidProvisioningInfo)
				}
				t.Logf("certificate %d: ca=%v (basicConstraints %v) pathLen=%d keyUsage=%#x keyDescription=%v provisioningInfo=%v criticalUnhandled=%d",
					i, c.IsCA, c.BasicConstraintsValid, c.MaxPathLen, int(c.KeyUsage), kd, rkp, len(c.UnhandledCriticalExtensions))
			}
			if err := devattest.CheckAndroidChain(p, chain, nil); err != nil {
				t.Fatalf("a real chain is refused: %v", err)
			}
			leaf, _ := x509.ParseCertificate(chain[0])
			n := 0
			for _, e := range leaf.Extensions {
				if e.Id.Equal(devattest.OIDKeyDescription) {
					n++
					if err := devattest.ParseKeyDescription(e.Value); err != nil {
						t.Fatalf("key description: %v", err)
					}
				}
			}
			if n != 1 {
				t.Fatalf("%d attestation extensions on the leaf", n)
			}
		})
	}
}
