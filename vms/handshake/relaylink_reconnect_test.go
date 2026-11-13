package handshake

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"
)

// §3.4.2 RK8 (VAULT-MESSAGING 0.90.4): a reconnect hs.init deposited with
// a key earlier than from.relay.pk carries relay links; with LinkedSender
// the responder accepts it from the deposit key when the links connect it
// to from.relay.pk, and expects the hs.fin from the deposit key.
func TestReconnectLinkedSender(t *testing.T) {
	i, r := newParty(t, 0x10), newParty(t, 0x20)
	ei, _ := runHandshake(t, i, r, PurposeConnection)
	k1 := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x77}, 32))
	k2 := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x78}, 32))
	link := func(a, b ed25519.PrivateKey) *RelayLink {
		l, err := NewRelayLink(a, b)
		if err != nil {
			t.Fatal(err)
		}
		return l
	}
	run := func(links []*RelayLink, linked bool) (*Responder, error) {
		cfg := initCfg(i, r, PurposeReconnect)
		cfg.Ctx = EpochCtx(ei.ID())
		cfg.Relay = RelayAddr{URL: i.addr.URL, Mailbox: MailboxID(links[len(links)-1].New), PK: links[len(links)-1].New}
		cfg.RelayLinks = links
		ini, err := NewInitiator(cfg)
		if err != nil {
			t.Fatal(err)
		}
		p, err := OpenInit(ini.Envelope(), r.lookup, t0)
		if err != nil {
			t.Fatal(err)
		}
		rcfg := respCfg(i, r, PurposeReconnect)
		rcfg.RecordRelayKey, rcfg.KnownInitiatorIK = i.relayPK(), i.pub()
		rcfg.ExpectedCtx = EpochCtx(ei.ID())
		rcfg.LinkedSender = linked
		resp, _, err := p.Respond(rcfg)
		return resp, err
	}
	resp, err := run([]*RelayLink{link(i.relay, k1)}, true)
	if err != nil {
		t.Fatalf("linked: %v", err)
	}
	if !bytes.Equal(resp.CollectSender(), i.relayPK()) {
		t.Fatal("the hs.fin is not expected from the deposit key")
	}
	if _, err := run([]*RelayLink{link(i.relay, k1)}, false); !errors.Is(err, ErrSender) {
		t.Fatalf("without LinkedSender: %v", err)
	}
	if _, err := run([]*RelayLink{link(k2, k1)}, true); !errors.Is(err, ErrSender) {
		t.Fatalf("links not from the deposit key: %v", err)
	}
}
