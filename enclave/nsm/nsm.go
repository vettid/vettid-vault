// Package nsm talks to the AWS Nitro Security Module through /dev/nsm
// (VAULT-PLAN V3): attestation documents and the enclave's PCRs.
//
// The NSM API is a CBOR request and a CBOR response passed in one ioctl
// (the Linux nsm driver's NSM_IOCTL_REQUEST). Requests are encoded and
// responses decoded with the strict in-repo CBOR codec (internal/cbor)
// instead of a third-party NSM library and its general CBOR dependency.
//
// It implements enclave.NSM. The fake NSM for development lives in
// internal/enclavetest, which release builds cannot link.
package nsm

import (
	"encoding/hex"
	"errors"
	"sync"

	"github.com/vettid/vettid-vault/internal/cbor"
	"github.com/vettid/vettid-vault/vms/nitro"
)

// Limits of the NSM driver (NSM_REQUEST_MAX_SIZE, NSM_RESPONSE_MAX_SIZE)
// and of the attestation fields (§11.2: user_data, nonce, public_key).
const (
	maxRequest  = 0x1000
	maxResponse = 0x3000
	maxField    = 1024
)

// Errors. NSM error codes are reported by name only.
var (
	ErrDevice   = errors.New("nsm: device unavailable")
	ErrResponse = errors.New("nsm: malformed response")
	ErrField    = errors.New("nsm: attestation field too large")
)

// Error is an error code returned by the NSM.
type Error struct{ Code string }

func (e *Error) Error() string { return "nsm: " + e.Code }

// device is one request/response exchange with the NSM.
type device interface {
	call(req []byte) ([]byte, error)
	close() error
}

// NSM is an open Nitro Security Module.
type NSM struct {
	mu  sync.Mutex
	dev device
}

// Open opens /dev/nsm.
func Open() (*NSM, error) {
	d, err := openDevice("/dev/nsm")
	if err != nil {
		return nil, ErrDevice
	}
	return &NSM{dev: d}, nil
}

// Close closes the device.
func (n *NSM) Close() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.dev.close()
}

func (n *NSM) do(req []byte, op string) (*cbor.Value, error) {
	if len(req) > maxRequest {
		return nil, ErrField
	}
	n.mu.Lock()
	resp, err := n.dev.call(req)
	n.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return decodeResponse(resp, op)
}

// decodeResponse returns the body of {op: body}, or the NSM error of
// {"Error": code}.
func decodeResponse(resp []byte, op string) (*cbor.Value, error) {
	v, err := cbor.Decode(resp)
	if err != nil || v.Kind != cbor.KindMap || len(v.Map) != 1 || v.Map[0].Key.Kind != cbor.KindText {
		return nil, ErrResponse
	}
	k, body := v.Map[0].Key.Text, v.Map[0].Value
	if k == "Error" {
		if body.Kind != cbor.KindText || len(body.Text) > 64 {
			return nil, ErrResponse
		}
		return nil, &Error{Code: body.Text}
	}
	if k != op || body.Kind != cbor.KindMap {
		return nil, ErrResponse
	}
	return &body, nil
}

func optField(e *cbor.Encoder, name string, b []byte) {
	e.Text(name)
	if b == nil {
		e.Null()
	} else {
		e.ByteString(b)
	}
}

// attestationRequest encodes {"Attestation": {"user_data", "nonce",
// "public_key"}} with absent fields as null.
func attestationRequest(userData, nonce, publicKey []byte) []byte {
	var e cbor.Encoder
	e.Map(1).Text("Attestation").Map(3)
	optField(&e, "user_data", userData)
	optField(&e, "nonce", nonce)
	optField(&e, "public_key", publicKey)
	return e.Bytes()
}

// Attest implements enclave.NSM: an attestation document carrying the
// optional fields.
func (n *NSM) Attest(userData, nonce, publicKey []byte) ([]byte, error) {
	if len(userData) > maxField || len(nonce) > maxField || len(publicKey) > maxField*2 {
		return nil, ErrField
	}
	body, err := n.do(attestationRequest(userData, nonce, publicKey), "Attestation")
	if err != nil {
		return nil, err
	}
	doc, err := body.BytesAt("document")
	if err != nil || len(doc) == 0 || len(doc) > nitro.MaxDocument {
		return nil, ErrResponse
	}
	return append([]byte(nil), doc...), nil
}

func describePCRRequest(i uint16) []byte {
	var e cbor.Encoder
	e.Map(1).Text("DescribePCR").Map(1).Text("index").Uint(uint64(i))
	return e.Bytes()
}

// PCR returns PCR i (48 bytes, SHA-384).
func (n *NSM) PCR(i uint16) ([]byte, error) {
	body, err := n.do(describePCRRequest(i), "DescribePCR")
	if err != nil {
		return nil, err
	}
	data, err := body.BytesAt("data")
	if err != nil || len(data) != nitro.PCRSize {
		return nil, ErrResponse
	}
	return append([]byte(nil), data...), nil
}

// Measurements implements enclave.NSM: PCR0, PCR1 and PCR2.
func (n *NSM) Measurements() (nitro.Measurements, error) {
	var p [3]string
	for i := range p {
		b, err := n.PCR(uint16(i))
		if err != nil {
			return nitro.Measurements{}, err
		}
		p[i] = hex.EncodeToString(b)
	}
	return nitro.Measurements{PCR0: p[0], PCR1: p[1], PCR2: p[2]}, nil
}
