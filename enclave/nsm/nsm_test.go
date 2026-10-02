package nsm

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/vettid/vettid-vault/internal/cbor"
)

// fakeDevice answers like the NSM, after checking the request encoding.
type fakeDevice struct {
	t    *testing.T
	pcrs map[uint64][]byte
	fail string
	raw  []byte
}

func (f *fakeDevice) close() error { return nil }

func (f *fakeDevice) call(req []byte) ([]byte, error) {
	if f.raw != nil {
		return f.raw, nil
	}
	v, err := cbor.Decode(req)
	if err != nil || v.Kind != cbor.KindMap || len(v.Map) != 1 {
		f.t.Fatalf("request: %v", err)
	}
	var e cbor.Encoder
	if f.fail != "" {
		return e.Map(1).Text("Error").Text(f.fail).Bytes(), nil
	}
	body := v.Map[0].Value
	switch v.Map[0].Key.Text {
	case "Attestation":
		ud, _ := body.Lookup("user_data")
		nonce, _ := body.Lookup("nonce")
		pk, _ := body.Lookup("public_key")
		if ud == nil || nonce == nil || pk == nil || len(body.Map) != 3 {
			f.t.Fatal("attestation request fields")
		}
		// Echo the fields so the test can check them.
		doc := append(append(append([]byte{}, ud.Raw...), nonce.Raw...), pk.Raw...)
		return e.Map(1).Text("Attestation").Map(1).Text("document").ByteString(doc).Bytes(), nil
	case "DescribePCR":
		i, err := body.UintAt("index")
		if err != nil {
			f.t.Fatal("index")
		}
		return e.Map(1).Text("DescribePCR").Map(2).Text("lock").Bool(true).Text("data").ByteString(f.pcrs[i]).Bytes(), nil
	}
	f.t.Fatalf("unknown request %q", v.Map[0].Key.Text)
	return nil, nil
}

func TestAttest(t *testing.T) {
	n := &NSM{dev: &fakeDevice{t: t}}
	doc, err := n.Attest([]byte{1, 2}, nil, []byte{3})
	if err != nil {
		t.Fatal(err)
	}
	// user_data bytes(2), nonce null, public_key bytes(1)
	if !bytes.Equal(doc, []byte{0x42, 1, 2, 0xf6, 0x41, 3}) {
		t.Fatalf("encoding %x", doc)
	}
	if _, err := n.Attest(make([]byte, 2000), nil, nil); !errors.Is(err, ErrField) {
		t.Fatal("oversized user_data")
	}
}

func TestMeasurements(t *testing.T) {
	pcrs := map[uint64][]byte{0: bytes.Repeat([]byte{0xa3}, 48), 1: bytes.Repeat([]byte{0x13}, 48), 2: bytes.Repeat([]byte{0x23}, 48)}
	n := &NSM{dev: &fakeDevice{t: t, pcrs: pcrs}}
	m, err := n.Measurements()
	if err != nil {
		t.Fatal(err)
	}
	if m.PCR0 != hex.EncodeToString(pcrs[0]) || m.PCR2 != hex.EncodeToString(pcrs[2]) {
		t.Fatal("pcrs")
	}
	n = &NSM{dev: &fakeDevice{t: t, pcrs: map[uint64][]byte{0: {1, 2}}}}
	if _, err := n.Measurements(); !errors.Is(err, ErrResponse) {
		t.Fatal("short PCR accepted")
	}
}

func TestErrors(t *testing.T) {
	n := &NSM{dev: &fakeDevice{t: t, fail: "InvalidIndex"}}
	var ne *Error
	if _, err := n.PCR(40); !errors.As(err, &ne) || ne.Code != "InvalidIndex" {
		t.Fatalf("error: %v", err)
	}
	var e cbor.Encoder
	for _, raw := range [][]byte{{0xff}, e.Map(1).Text("DescribePCR").Text("x").Bytes(), (&cbor.Encoder{}).Map(1).Text("Attestation").Map(0).Bytes()} {
		n = &NSM{dev: &fakeDevice{t: t, raw: raw}}
		if _, err := n.PCR(0); err == nil {
			t.Fatalf("accepted %x", raw)
		}
	}
}

func TestIoctlNumber(t *testing.T) {
	// _IOWR(0x0A, 0, 32 bytes) on 64-bit Linux, as in the nsm driver.
	if ioctlNumber() != 0xc0200a00 {
		t.Fatalf("ioctl %#x", ioctlNumber())
	}
}

func FuzzDecodeResponse(f *testing.F) {
	var e cbor.Encoder
	f.Add(e.Map(1).Text("Attestation").Map(1).Text("document").ByteString([]byte{1}).Bytes())
	f.Add([]byte{0xa1, 0x65, 'E', 'r', 'r', 'o', 'r', 0x61, 'x'})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = decodeResponse(b, "Attestation")
	})
}
