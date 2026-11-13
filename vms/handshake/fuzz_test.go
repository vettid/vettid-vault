package handshake

import (
	"bytes"
	"testing"

	"github.com/vettid/vettid-vault/vms/strictjson"
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
	r := &Resp{Token: tokC, Suite: 2, SASNonce: make([]byte, 32), Sig: make([]byte, 64)}
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
	b, _ := (&Fin{Sig: make([]byte, 64), SASNonce: make([]byte, 32)}).Marshal(PurposeConnection)
	f.Add(b, uint8(3))
	b, _ = (&Fin{Sig: make([]byte, 64)}).Marshal(PurposeRekey)
	f.Add(b, uint8(4))
	purposes := []Purpose{PurposeApp, PurposeDesktop, PurposeAgent, PurposeConnection, PurposeRekey, PurposeReconnect}
	f.Fuzz(func(t *testing.T, b []byte, pi uint8) {
		p := purposes[int(pi)%len(purposes)]
		fin, err := ParseFin(b, p)
		if err != nil {
			return
		}
		if len(fin.Sig) != 64 || p.HasSAS() != (len(fin.SASNonce) == 32) {
			t.Fatal("bad hs.fin accepted")
		}
		out, err := fin.Marshal(p)
		if err != nil {
			t.Fatalf("accepted body does not re-marshal: %v", err)
		}
		if _, err := ParseFin(out, p); err != nil {
			t.Fatalf("re-marshalled body rejected: %v", err)
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

// The relay link chain verifier (0.90.0 rule U, §6.2): any input either
// parses and verifies as a chain from its first old to its last new, or is
// refused; nothing panics.
func FuzzRelayChain(f *testing.F) {
	a, b, c := relayKey(0x61), relayKey(0x62), relayKey(0x63)
	ch := relayChain(f, a, b, c)
	f.Add(append(append(append([]byte{'['}, ch[0].Marshal()...), ','), append(ch[1].Marshal(), ']')...))
	f.Add([]byte(`[]`))
	f.Add([]byte(`[{"old":"","new":"","sig_old":"","sig_new":""}]`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		arr, err := strictjson.AsArray(raw)
		if err != nil {
			return
		}
		ls, err := ParseRelayLinks(arr)
		if err != nil {
			return
		}
		first, last := ls[0].Old, ls[len(ls)-1].New
		if VerifyRelayChain(first, last, ls) != nil {
			return
		}
		for i, l := range ls {
			if l.Verify() != nil || i > 0 && !bytes.Equal(l.Old, ls[i-1].New) {
				t.Fatal("a chain that does not hold verified")
			}
		}
		again, err := ParseRelayLinks(arr)
		if err != nil || !bytes.Equal(MarshalRelayLinks(again), MarshalRelayLinks(ls)) {
			t.Fatal("re-parse differs")
		}
	})
}
