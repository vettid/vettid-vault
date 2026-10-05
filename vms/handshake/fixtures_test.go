package handshake

import (
	"bytes"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/suite"
)

// Test-only keys derived from fixed public seeds.

var t0 = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func seed(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

type party struct {
	ik      ed25519.PrivateKey
	kem     *suite.PrivateKey
	relay   ed25519.PrivateKey
	retired *suite.PrivateKey
	addr    RelayAddr
}

func newParty(t testing.TB, base byte) *party {
	t.Helper()
	kem, err := suite.NewPrivateKey(seed(base + 1))
	if err != nil {
		t.Fatal(err)
	}
	rk := ed25519.NewKeyFromSeed(seed(base + 2))
	pk := rk.Public().(ed25519.PublicKey)
	return &party{
		ik:    ed25519.NewKeyFromSeed(seed(base)),
		kem:   kem,
		relay: rk,
		addr:  RelayAddr{URL: "https://relay.example.org", Mailbox: MailboxID(pk), PK: pk},
	}
}

func (p *party) pub() ed25519.PublicKey     { return p.ik.Public().(ed25519.PublicKey) }
func (p *party) relayPK() ed25519.PublicKey { return p.relay.Public().(ed25519.PublicKey) }
func (p *party) lookup(kid suite.Kid) *suite.PrivateKey {
	if kid.Equal(p.kem.Public().Kid()) {
		return p.kem
	}
	return nil
}

const (
	tokA = "v4.public.VEVTVC1PTkxZLUE"
	tokB = "v4.public.VEVTVC1PTkxZLUI"
	tokC = "v4.public.VEVTVC1PTkxZLUM"
	tokD = "v4.public.VEVTVC1PTkxZLUQ"
)

const testInviteID = "01JB2Z6V9K3M4N5P6Q7R8S9T0V"

// initCfg returns an initiator config from i to r.
func initCfg(i, r *party, purpose Purpose) InitiatorConfig {
	c := InitiatorConfig{
		Purpose:           purpose,
		Ctx:               testInviteID,
		Identity:          i.ik,
		StaticKEM:         i.kem.Public(),
		Relay:             i.addr,
		Token:             tokA,
		ResponderIK:       r.pub(),
		ResponderEK:       r.kem.Public(),
		ResponderRelayKey: r.relayPK(),
		Policy:            PolicyVaultToVault,
		Now:               t0,
	}
	if purpose == PurposeReconnect {
		c.ReconnectToken = tokB
	}
	return c
}

func respCfg(i, r *party, purpose Purpose) ResponderConfig {
	c := ResponderConfig{
		Identity:      r.ik,
		Token:         tokC,
		Policy:        PolicyVaultToVault,
		CollectSender: i.relayPK(),
		Now:           t0,
	}
	if purpose == PurposeReconnect {
		c.ReconnectToken = tokD
	}
	return c
}

// runHandshake performs a full handshake and returns both epochs.
func runHandshake(t testing.TB, i, r *party, purpose Purpose) (*Epoch, *Epoch) {
	t.Helper()
	ini, err := NewInitiator(initCfg(i, r, purpose))
	if err != nil {
		t.Fatalf("NewInitiator: %v", err)
	}
	p, err := OpenInit(ini.Envelope(), r.lookup, t0)
	if err != nil {
		t.Fatalf("OpenInit: %v", err)
	}
	resp, respEnv, err := p.Respond(respCfg(i, r, purpose))
	if err != nil {
		t.Fatalf("Respond: %v", err)
	}
	res, err := ini.HandleResp(respEnv, r.relayPK(), t0)
	if err != nil {
		t.Fatalf("HandleResp: %v", err)
	}
	fr, err := resp.HandleFin(res.Fin, i.relayPK(), t0)
	if err != nil {
		t.Fatalf("HandleFin: %v", err)
	}
	if fr.SAS != res.SAS || purpose.HasSAS() != (len(res.SAS) == 6) {
		t.Fatalf("SAS %q vs %q", res.SAS, fr.SAS)
	}
	return res.Epoch, fr.Epoch
}
