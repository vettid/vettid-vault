package vault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"
	"github.com/vettid/vettid-relay/relayclient"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/suite"
)

// The responder of a reconnect checks the initiator's rotation chain
// against what it already followed (VAULT-MESSAGING §3.4, §6.6): the
// initiator sends every rotation since its last epoch, while the responder
// may already have followed some of them from identity.rotate, so the links
// it knows are skipped and only the rest are followed. A known prefix must
// end at the stored key (never a rollback), and a second successor of a
// followed key still suspends the connection (one successor per key).

type rcKeys struct {
	ik  ed25519.PrivateKey
	kem *suite.PrivateKey
}

func rcKey(t *testing.T, b byte) rcKeys {
	t.Helper()
	kem, err := suite.NewPrivateKey(bytes.Repeat([]byte{b + 1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return rcKeys{ik: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{b}, 32)), kem: kem}
}

func rcLink(t *testing.T, from, to rcKeys) *handshake.Rotation {
	t.Helper()
	r, err := handshake.NewRotation(from.ik, to.ik, to.kem.Public())
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func rawLinks(rs ...*handshake.Rotation) []json.RawMessage {
	var out []json.RawMessage
	for _, r := range rs {
		out = append(out, r.Marshal())
	}
	return out
}

// rcReconnect makes a connection whose stored key is stored and whose
// followed chain is chain, then delivers a reconnect hs.init from a peer
// that is now at keys cur and sends rotations sent. It reports whether the
// vault answered (an hs.resp is awaiting its hs.fin).
func rcReconnect(t *testing.T, stored rcKeys, chain []json.RawMessage, cur rcKeys, sent []*handshake.Rotation) (answered bool, d *devFixture, p *Peer) {
	t.Helper()
	d = newDevFixture(t)
	m := d.m
	n := newNewcomer(t, 0x70)
	epoch := bytes.Repeat([]byte{0xe1}, 16)
	p = &Peer{ID: "c1", Kind: KindConnection, Name: "Peer", State: PeerActive, CreatedAt: time.Now(),
		IK: stored.ik.Public().(ed25519.PublicKey), KEM: stored.kem.Public().Bytes(), Chain: chain, LastEpochID: epoch,
		Relay: PeerRelay{URL: n.addr.URL, Mailbox: n.addr.Mailbox, PK: n.addr.PK}}
	m.mu.Lock()
	m.st.Connections[p.ID] = p
	m.mu.Unlock()

	vaultPK := m.keys.relay.Public().(ed25519.PublicKey)
	rc := relayclient.New(n.addr.URL, n.relay)
	mint := func() string {
		tok, err := rc.MintToken(relayauth.EncodeKey(vaultPK), n.addr.URL, relayclient.TokenOptions{TTL: 24 * time.Hour})
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	now := m.now().UTC().Truncate(time.Millisecond)
	id, _ := envelope.NewULID(now)
	ini, err := handshake.NewInitiator(handshake.InitiatorConfig{
		Purpose: handshake.PurposeReconnect, Ctx: handshake.EpochCtx(epochIDOf(epoch)),
		Identity: cur.ik, StaticKEM: cur.kem.Public(), Relay: n.addr, Token: mint(), ReconnectToken: mint(),
		Rotations:   sent,
		ResponderIK: m.keys.ik.Public().(ed25519.PublicKey), ResponderEK: m.keys.kem.Public(), ResponderRelayKey: vaultPK,
		Policy: policyFor(KindConnection), Now: now, ID: id,
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = m.ProcessBatch(context.Background(), &fakeCollector{}, []Message{{MsgID: "rc1", Sender: relayauth.EncodeKey(n.addr.PK), Payload: ini.Envelope()}})
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.st.Awaiting) > 0, d, p
}

func TestReconnectChainKnown(t *testing.T) {
	k0, k1, k2 := rcKey(t, 0x10), rcKey(t, 0x20), rcKey(t, 0x30)
	r1, r2 := rcLink(t, k0, k1), rcLink(t, k1, k2)

	t.Run("not yet followed", func(t *testing.T) {
		ok, _, p := rcReconnect(t, k0, nil, k1, []*handshake.Rotation{r1})
		if !ok || !bytes.Equal(p.IK, k1.ik.Public().(ed25519.PublicKey)) || len(p.Chain) != 1 {
			t.Fatalf("answered=%v chain=%d", ok, len(p.Chain))
		}
	})
	t.Run("single link already followed", func(t *testing.T) {
		ok, d, p := rcReconnect(t, k1, rawLinks(r1), k1, []*handshake.Rotation{r1})
		if !ok || d.audited("reconnect_refused") || len(p.Chain) != 1 {
			t.Fatalf("answered=%v chain=%d refused=%v", ok, len(p.Chain), d.audited("reconnect_refused"))
		}
	})
	t.Run("first of two links already followed", func(t *testing.T) {
		ok, _, p := rcReconnect(t, k1, rawLinks(r1), k2, []*handshake.Rotation{r1, r2})
		if !ok || !bytes.Equal(p.IK, k2.ik.Public().(ed25519.PublicKey)) || len(p.Chain) != 2 ||
			!bytes.Equal(p.KEM, k2.kem.Public().Bytes()) {
			t.Fatalf("answered=%v chain=%d", ok, len(p.Chain))
		}
	})
	t.Run("both links already followed", func(t *testing.T) {
		ok, _, p := rcReconnect(t, k2, rawLinks(r1, r2), k2, []*handshake.Rotation{r1, r2})
		if !ok || len(p.Chain) != 2 {
			t.Fatalf("answered=%v chain=%d", ok, len(p.Chain))
		}
	})
	t.Run("known prefix does not end at the stored key", func(t *testing.T) {
		// Followed r1 and r2; a reconnect carrying only r1 would roll the
		// identity back to k1.
		ok, d, p := rcReconnect(t, k2, rawLinks(r1, r2), k1, []*handshake.Rotation{r1})
		if ok || !d.audited("reconnect_refused") || !bytes.Equal(p.IK, k2.ik.Public().(ed25519.PublicKey)) || p.Conflict != nil {
			t.Fatalf("rolled back: answered=%v", ok)
		}
	})
	t.Run("unrelated chain", func(t *testing.T) {
		x0, x1 := rcKey(t, 0x50), rcKey(t, 0x60)
		ok, d, p := rcReconnect(t, k1, rawLinks(r1), x1, []*handshake.Rotation{rcLink(t, x0, x1)})
		if ok || !d.audited("reconnect_refused") || p.Conflict != nil || !bytes.Equal(p.IK, k1.ik.Public().(ed25519.PublicKey)) {
			t.Fatalf("unrelated chain accepted: answered=%v", ok)
		}
	})
	t.Run("second successor suspends", func(t *testing.T) {
		kb := rcKey(t, 0x40)
		ok, _, p := rcReconnect(t, k1, rawLinks(r1), kb, []*handshake.Rotation{rcLink(t, k0, kb)})
		if ok || p.Conflict == nil {
			t.Fatalf("answered=%v conflict=%v", ok, p.Conflict != nil)
		}
		if !bytes.Equal(p.IK, k1.ik.Public().(ed25519.PublicKey)) {
			t.Fatal("stored key changed")
		}
	})
}
