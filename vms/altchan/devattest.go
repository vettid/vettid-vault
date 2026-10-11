package altchan

import (
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/vettid/vettid-vault/internal/strictjson"
)

// ErrDeviceAttest is returned for a malformed device_attest or
// device_assertion object.
var ErrDeviceAttest = errors.New("altchan: malformed device attestation")

// Device attestation platforms (§11.7).
const (
	PlatformAndroid = "android"
	PlatformIOS     = "ios"
)

// MaxChain bounds the Android certificate chain (§11.7: 1–10 certificates).
const MaxChain = 10

// maxBlob bounds each decoded attestation value.
const maxBlob = 16 * 1024

// DeviceAttest is the `device_attest` member of enrollment (§11.3) and app
// pairing hs.init (§6.7). The attestation itself is verified in the enclave
// (phase V3); this type carries the wire shape.
type DeviceAttest struct {
	Platform string
	// Android: DER certificates, leaf first.
	Chain [][]byte
	// iOS: App Attest key id and CBOR attestation object.
	KeyID       []byte
	Attestation []byte
}

// DeviceAssertion is the `device_assertion` member of vault.unlock (§11.4).
type DeviceAssertion struct {
	Platform  string
	Sig       []byte // Android: DER ECDSA P-256 signature over the challenge
	Assertion []byte // iOS: CBOR assertion
	// Chain (Android, optional; 0.27.0, §11.7.1) is the certificate chain
	// of the bound device key, the certificates the app sent at
	// attestation: an app sends it with an unlock while the vault has not
	// recorded its signer. It is not part of any signing string. Nil when
	// absent.
	Chain [][]byte
}

func blobMember(o strictjson.Object, name string) ([]byte, error) {
	b, err := o.Base64(name, -1)
	if err != nil || len(b) == 0 || len(b) > maxBlob {
		return nil, ErrDeviceAttest
	}
	return b, nil
}

// ParseDeviceAttest parses `device_attest` strictly (§11.7).
func ParseDeviceAttest(raw json.RawMessage) (*DeviceAttest, error) {
	o, err := strictjson.ParseObject(raw)
	if err != nil {
		return nil, ErrDeviceAttest
	}
	p, err := o.String("platform")
	if err != nil {
		return nil, ErrDeviceAttest
	}
	d := &DeviceAttest{Platform: p}
	switch p {
	case PlatformAndroid:
		if d.Chain, err = chainMember(o); err != nil {
			return nil, err
		}
	case PlatformIOS:
		if d.KeyID, err = blobMember(o, "key_id"); err != nil {
			return nil, err
		}
		if d.Attestation, err = blobMember(o, "attestation"); err != nil {
			return nil, err
		}
	default:
		return nil, ErrDeviceAttest
	}
	return d, nil
}

// chainMember reads `chain`: 1 to MaxChain certificates, base64 DER,
// leaf first.
func chainMember(o strictjson.Object) ([][]byte, error) {
	arr, err := o.Array("chain")
	if err != nil || len(arr) == 0 || len(arr) > MaxChain {
		return nil, ErrDeviceAttest
	}
	var chain [][]byte
	for _, r := range arr {
		var s string
		if len(r) == 0 || r[0] != '"' || json.Unmarshal(r, &s) != nil {
			return nil, ErrDeviceAttest
		}
		c, err := strictjson.DecodeStd(s, -1)
		if err != nil || len(c) == 0 || len(c) > maxBlob {
			return nil, ErrDeviceAttest
		}
		chain = append(chain, c)
	}
	return chain, nil
}

func chainJSON(chain [][]byte) []byte {
	arr := []byte{'['}
	for i, c := range chain {
		if i > 0 {
			arr = append(arr, ',')
		}
		arr = append(arr, strictjson.MarshalString(b64(c))...)
	}
	return append(arr, ']')
}

// Marshal encodes the object.
func (d *DeviceAttest) Marshal() ([]byte, error) {
	b := strictjson.NewBuilder().String("platform", d.Platform)
	switch d.Platform {
	case PlatformAndroid:
		if len(d.Chain) == 0 || len(d.Chain) > MaxChain {
			return nil, ErrDeviceAttest
		}
		b.Raw("chain", chainJSON(d.Chain))
	case PlatformIOS:
		if len(d.KeyID) == 0 || len(d.Attestation) == 0 {
			return nil, ErrDeviceAttest
		}
		b.Base64("key_id", d.KeyID).Base64("attestation", d.Attestation)
	default:
		return nil, ErrDeviceAttest
	}
	return b.Bytes(), nil
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// ParseDeviceAssertion parses `device_assertion` strictly (§11.7).
func ParseDeviceAssertion(raw json.RawMessage) (*DeviceAssertion, error) {
	o, err := strictjson.ParseObject(raw)
	if err != nil {
		return nil, ErrDeviceAttest
	}
	p, err := o.String("platform")
	if err != nil {
		return nil, ErrDeviceAttest
	}
	a := &DeviceAssertion{Platform: p}
	switch p {
	case PlatformAndroid:
		if a.Sig, err = blobMember(o, "sig"); err != nil {
			return nil, err
		}
		if o.Has("chain") {
			// Present: well-formed, or the object is rejected (§11.7).
			if a.Chain, err = chainMember(o); err != nil {
				return nil, err
			}
		}
	case PlatformIOS:
		if a.Assertion, err = blobMember(o, "assertion"); err != nil {
			return nil, err
		}
	default:
		return nil, ErrDeviceAttest
	}
	return a, nil
}

// Marshal encodes the object.
func (a *DeviceAssertion) Marshal() ([]byte, error) {
	b := strictjson.NewBuilder().String("platform", a.Platform)
	switch a.Platform {
	case PlatformAndroid:
		if len(a.Sig) == 0 {
			return nil, ErrDeviceAttest
		}
		b.Base64("sig", a.Sig)
		if a.Chain != nil {
			if len(a.Chain) == 0 || len(a.Chain) > MaxChain {
				return nil, ErrDeviceAttest
			}
			b.Raw("chain", chainJSON(a.Chain))
		}
	case PlatformIOS:
		if len(a.Assertion) == 0 {
			return nil, ErrDeviceAttest
		}
		b.Base64("assertion", a.Assertion)
	default:
		return nil, ErrDeviceAttest
	}
	return b.Bytes(), nil
}
