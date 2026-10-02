package handshake

import (
	"bytes"
	"testing"
)

// §13.6: envelope and inner parsers MUST be fuzzed. These cover the
// handshake message bodies and the rotation statement; envelope and inner
// parsers are fuzzed in package envelope.

func FuzzParseInit(f *testing.F) {
	for _, p := range []Purpose{PurposeApp, PurposeConnection, PurposeRekey, PurposeReconnect} {
		b, err := sampleInit(f, p).Marshal()
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		in, err := ParseInit(b)
		if err != nil {
			return
		}
		// Anything accepted re-encodes, and re-parses to the same encoding.
		out, err := in.Marshal()
		if err != nil {
			t.Fatalf("accepted body does not re-marshal: %v", err)
		}
		in2, err := ParseInit(out)
		if err != nil {
			t.Fatalf("re-marshalled body rejected: %v", err)
		}
		out2, _ := in2.Marshal()
		if !bytes.Equal(out, out2) {
			t.Fatal("marshal not stable")
		}
	})
}

func FuzzParseResp(f *testing.F) {
	r := &Resp{Token: tokC, ReconnectToken: tokD, Suite: 2, Sig: make([]byte, 64)}
	b, _ := r.Marshal(PurposeConnection)
	f.Add(b, uint8(0))
	f.Add([]byte(`{"suite":2,"sig":""}`), uint8(4))
	purposes := []Purpose{PurposeApp, PurposeDesktop, PurposeAgent, PurposeConnection, PurposeRekey, PurposeReconnect}
	f.Fuzz(func(t *testing.T, b []byte, pi uint8) {
		p := purposes[int(pi)%len(purposes)]
		r, err := ParseResp(b, p)
		if err != nil {
			return
		}
		out, err := r.Marshal(p)
		if err != nil {
			t.Fatalf("accepted body does not re-marshal: %v", err)
		}
		if _, err := ParseResp(out, p); err != nil {
			t.Fatalf("re-marshalled body rejected: %v", err)
		}
	})
}

func FuzzParseFin(f *testing.F) {
	b, _ := MarshalFin(make([]byte, 64))
	f.Add(b)
	f.Fuzz(func(t *testing.T, b []byte) {
		sig, err := ParseFin(b)
		if err == nil && len(sig) != 64 {
			t.Fatal("bad sig length accepted")
		}
	})
}

func FuzzParseRotation(f *testing.F) {
	p := newParty(f, 0x10)
	newIK := newParty(f, 0x40)
	r, err := NewRotation(p.ik, newIK.ik, newIK.kem.Public())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(r.Marshal())
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := ParseRotation(b)
		if err != nil {
			return
		}
		_ = r.Verify()
		if _, err := ParseRotation(r.Marshal()); err != nil {
			t.Fatal("accepted statement does not round-trip")
		}
	})
}

// FuzzHandshakeOpen feeds arbitrary bytes to the responder and initiator
// entry points, which parse envelopes before any decryption.
func FuzzHandshakeOpen(f *testing.F) {
	i, r := newParty(f, 0x10), newParty(f, 0x20)
	ini, err := NewInitiator(initCfg(i, r, PurposeConnection))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(ini.Envelope())
	f.Add([]byte{2, 2, 2, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		if p, err := OpenInit(b, r.lookup, t0); err == nil && p.Init() == nil {
			t.Fatal("nil body")
		}
	})
}
