package enclave_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/vettid/vettid-vault/client"
	"github.com/vettid/vettid-vault/vms/altchan"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/pins"
)

// sizedAttester attests with a chain of given certificate sizes (opaque
// bytes: only the request's size is measured here).
type sizedAttester struct {
	client.Attester
	sizes []int
}

func sizedChain(sizes []int) [][]byte {
	var out [][]byte
	for i, n := range sizes {
		c := make([]byte, n)
		for j := range c {
			c[j] = byte(i*31 + j)
		}
		out = append(out, c)
	}
	return out
}

func (s sizedAttester) Attest([32]byte) (*altchan.DeviceAttest, error) {
	return &altchan.DeviceAttest{Platform: altchan.PlatformAndroid, Chain: sizedChain(s.sizes)}, nil
}

func equal(n, size int) []int {
	out := make([]int, n)
	for i := range out {
		out[i] = size
	}
	return out
}

// largest returns the largest certificate size (n equal certificates)
// for which build fits the request's padded size.
func largest(t *testing.T, n int, build func(sizes []int) error) int {
	t.Helper()
	lo, hi := 0, altchan.RequestPaddedSize
	for lo < hi {
		mid := (lo + hi + 1) / 2
		err := build(equal(n, mid))
		switch {
		case err == nil:
			lo = mid
		case errors.Is(err, envelope.ErrTooLarge) || errors.Is(err, altchan.ErrDeviceAttest):
			hi = mid - 1
		default:
			t.Fatalf("building with %d certificates of %d bytes: %v", n, mid, err)
		}
	}
	return lo
}

// VAULT-MESSAGING 0.27.0 §15 item 35, "Not verified": that the unlock
// request still fits its 12,288 padded bytes with a `chain` and a
// `release_update` together. Measured here with the reference client's
// own request builder and the largest values of every other member (a
// 32-digit PIN, a 36-character user_guid, 16-digit sequence numbers, a
// release approval, cancel_recovery), for chains of 3 to 10 certificates.
//
// The result: the unlock has more room for the chain than the requests
// that carried the chain when it was attested over the alternate channel
// (enrollment and a recovery's register hold the app's 1,216-byte KEM key
// and more beside it). So every chain that was accepted there fits the
// unlock that re-sends it, whatever the device's chain looks like.
func TestUnlockWithChainAndReleaseUpdateFits(t *testing.T) {
	f := newFx(t)
	guid := strings.Repeat("u", 36)
	longPIN := strings.Repeat("7", 32)
	a := f.newApp(guid, android(0x91))
	if r := f.enroll(a, pin); !r.OK {
		t.Fatal(r.Code)
	}
	f.lock(a)
	f.startRelease(r4)
	e, _ := f.enclaveFor(a, "", false)
	_, m, err := a.dev.VerifyManifest(f.w.Served(), f.trust)
	if err != nil {
		t.Fatal(err)
	}
	unlock := func(sizes []int) error {
		_, err := a.dev.BuildUnlock(guid, longPIN, e, m, a.att, client.UnlockOptions{Chain: sizedChain(sizes),
			Approve: &client.Approval{To: r4.PCR0Hex(), ToRelease: 4}, CancelRecovery: true})
		return err
	}
	enrollNew := func(sizes []int) error {
		b := f.newApp(guid, sizedAttester{Attester: android(0x92), sizes: sizes})
		ee, _ := f.enclaveFor(b, "", true)
		_, err := b.dev.BuildEnroll(guid, longPIN, ee, m, b.att)
		return err
	}
	register := func(sizes []int) error {
		b := f.newApp(guid, sizedAttester{Attester: android(0x93), sizes: sizes})
		b.vid = a.vid
		qr := &altchan.RecoveryCode{VaultID: a.vid, RecoveryID: "01JB2Z6V9K3M4N5P6Q7R8S9T0V", Code: strings.Repeat("A", 32)}
		_, err := b.dev.BuildRecoveryRegister(guid, qr, e, b.att)
		return err
	}
	for _, n := range []int{3, 4, 5, 10} {
		u, en, rg := largest(t, n, unlock), largest(t, n, enrollNew), largest(t, n, register)
		t.Logf("%2d certificates: the unlock with chain + release_update + cancel_recovery fits %5d bytes of DER (%4d each); "+
			"enrollment fits %5d; a recovery's register fits %5d", n, n*u, u, n*en, n*rg)
		if u < en || u < rg {
			t.Errorf("%d certificates: the unlock fits less chain (%d bytes each) than enrollment (%d) or register (%d): "+
				"a chain accepted at attestation might not fit the unlock that re-sends it", n, u, en, rg)
		}
	}
	// Chains as phones produce them. The pinned roots' sizes are real
	// (vms/pins); the other certificates are sized generously: a leaf
	// with the attestation extension, and RSA-4096 or P-384 intermediates.
	root := 0
	for _, r := range pins.GoogleAttestationRoots() {
		if len(r.Raw) > root {
			root = len(r.Raw)
		}
	}
	if root < 500 {
		t.Fatalf("pinned Google root of %d bytes", root)
	}
	for name, sizes := range map[string][]int{
		"remotely provisioned, 5 certificates (EC)":      {1100, 700, 750, 900, root},
		"factory provisioned, 4 certificates (RSA)":      {1500, 1400, 2000, root},
		"factory provisioned, 5 certificates (RSA)":      {1500, 1400, 1400, 2000, root},
		"the test PKI's own chain (what CI's apps send)": nil,
	} {
		chain := sizedChain(sizes)
		if sizes == nil {
			chain, _ = a.dev.AttestChain()
		}
		total := 0
		for _, c := range chain {
			total += len(c)
		}
		_, err := a.dev.BuildUnlock(guid, longPIN, e, m, a.att, client.UnlockOptions{Chain: chain,
			Approve: &client.Approval{To: r4.PCR0Hex(), ToRelease: 4}, CancelRecovery: true})
		if err != nil {
			t.Errorf("%s (%d bytes of DER): %v", name, total, err)
		} else {
			t.Logf("fits: %s, %d bytes of DER", name, total)
		}
	}
	// The limit is real: ten certificates of 1,200 bytes do not fit (nor
	// did they fit an enrollment), and nothing here changes a limit. (A
	// chain attested in a transfer's hs.init travelled in a handshake
	// envelope, whose limit is larger: such a chain above about 8,100
	// bytes of DER could not be re-sent. No vault from before 0.27.0
	// needs that outside staging, and real chains are about half of it.)
	if err := unlock(equal(10, 1200)); !errors.Is(err, envelope.ErrTooLarge) {
		t.Fatalf("12,000 bytes of chain: %v", err)
	}
	if altchan.RequestPaddedSize != 12288 || altchan.MaxChain != 10 {
		t.Fatal("limits changed")
	}
}
