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

// rcSetup makes a vault with one connection whose stored key is stored and
// whose followed chain is chain.
func rcSetup(t *testing.T, stored rcKeys, chain []json.RawMessage) (d *devFixture, p *Peer, n *newcomer) {
	t.Helper()
	d = newDevFixture(t)
	n = newNewcomer(t, 0x70)
	p = &Peer{ID: "c1", Kind: KindConnection, Name: "Peer", State: PeerActive, CreatedAt: time.Now(),
		IK: stored.ik.Public().(ed25519.PublicKey), KEM: stored.kem.Public().Bytes(), Chain: chain,
		LastEpochID: bytes.Repeat([]byte{0xe1}, 16),
		Relay:       PeerRelay{URL: n.addr.URL, Mailbox: n.addr.Mailbox, PK: n.addr.PK}}
	d.m.mu.Lock()
	d.m.st.Connections[p.ID] = p
	d.m.mu.Unlock()
	return d, p, n
}

// rcDeliver delivers a reconnect hs.init from n, now at keys cur and
// sending rotations sent, and reports whether the vault answered (an hs.resp
// is awaiting its hs.fin).
func rcDeliver(t *testing.T, d *devFixture, p *Peer, n *newcomer, cur rcKeys, sent []*handshake.Rotation, msgID string) bool {
	t.Helper()
	m := d.m
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
		Purpose: handshake.PurposeReconnect, Ctx: handshake.EpochCtx(epochIDOf(p.LastEpochID)),
		Identity: cur.ik, StaticKEM: cur.kem.Public(), Relay: n.addr, Token: mint(), ReconnectToken: mint(),
		Rotations:   sent,
		ResponderIK: m.keys.ik.Public().(ed25519.PublicKey), ResponderEK: m.keys.kem.Public(), ResponderRelayKey: vaultPK,
		Policy: policyFor(KindConnection), Now: now, ID: id,
	})
	if err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	before := len(m.st.Awaiting)
	m.mu.Unlock()
	_ = m.ProcessBatch(context.Background(), &fakeCollector{}, []Message{{MsgID: msgID, Sender: relayauth.EncodeKey(n.addr.PK), Payload: ini.Envelope()}})
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.st.Awaiting) > before
}

// rcReconnect is rcSetup and one rcDeliver.
func rcReconnect(t *testing.T, stored rcKeys, chain []json.RawMessage, cur rcKeys, sent []*handshake.Rotation) (answered bool, d *devFixture, p *Peer) {
	t.Helper()
	d, p, n := rcSetup(t, stored, chain)
	return rcDeliver(t, d, p, n, cur, sent, "rc1"), d, p
}

func TestReconnectChainKnown(t *testing.T) {
	k0, k1, k2 := rcKey(t, 0x10), rcKey(t, 0x20), rcKey(t, 0x30)
	r1, r2 := rcLink(t, k0, k1), rcLink(t, k1, k2)

	t.Run("not yet followed", func(t *testing.T) {
		// 0.72.0: answered, but nothing is followed before sig_I verifies at
		// hs.fin (TestReconnectChangesNothingBeforeFin finishes it).
		ok, d, p := rcReconnect(t, k0, nil, k1, []*handshake.Rotation{r1})
		if !ok || !bytes.Equal(p.IK, k0.ik.Public().(ed25519.PublicKey)) || len(p.Chain) != 0 {
			t.Fatalf("answered=%v chain=%d", ok, len(p.Chain))
		}
		for _, aw := range d.m.st.Awaiting {
			if aw.Reconnect == nil || len(aw.Reconnect.Rotations) != 1 {
				t.Fatal("the link to follow is not held for hs.fin")
			}
		}
	})
	t.Run("single link already followed", func(t *testing.T) {
		ok, d, p := rcReconnect(t, k1, rawLinks(r1), k1, []*handshake.Rotation{r1})
		if !ok || d.audited("reconnect_refused") || len(p.Chain) != 1 {
			t.Fatalf("answered=%v chain=%d refused=%v", ok, len(p.Chain), d.audited("reconnect_refused"))
		}
	})
	t.Run("first of two links already followed", func(t *testing.T) {
		ok, d, p := rcReconnect(t, k1, rawLinks(r1), k2, []*handshake.Rotation{r1, r2})
		if !ok || !bytes.Equal(p.IK, k1.ik.Public().(ed25519.PublicKey)) || len(p.Chain) != 1 {
			t.Fatalf("answered=%v chain=%d", ok, len(p.Chain))
		}
		for _, aw := range d.m.st.Awaiting {
			if aw.Reconnect == nil || len(aw.Reconnect.Rotations) != 2 { // every rotation sent; the links to follow are worked out at hs.fin
				t.Fatal("the link to follow is not held for hs.fin")
			}
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

	t.Run("same new_ik, different new_kem is refused without rollback", func(t *testing.T) {
		other := rcKeys{ik: k1.ik, kem: rcKey(t, 0x44).kem}
		r1b := rcLink(t, k0, other)
		ok, d, p := rcReconnect(t, k1, rawLinks(r1), other, []*handshake.Rotation{r1b})
		if ok || !d.audited("reconnect_refused") || p.Conflict != nil || !bytes.Equal(p.KEM, k1.kem.Public().Bytes()) {
			t.Fatalf("answered=%v", ok)
		}
	})
	t.Run("duplicate links", func(t *testing.T) {
		for name, c := range map[string]struct {
			stored rcKeys
			chain  []json.RawMessage
		}{"unfollowed": {k0, nil}, "followed": {k1, rawLinks(r1)}} {
			ok, _, p := rcReconnect(t, c.stored, c.chain, k1, []*handshake.Rotation{r1, r1})
			if ok || len(p.Chain) != len(c.chain) {
				t.Fatalf("%s: answered=%v chain=%d", name, ok, len(p.Chain))
			}
		}
	})
	t.Run("conflicting statement deeper in the chain suspends", func(t *testing.T) {
		kb := rcKey(t, 0x40)
		ok, _, p := rcReconnect(t, k2, rawLinks(r1, r2), kb, []*handshake.Rotation{r1, rcLink(t, k1, kb)})
		if ok || p.Conflict == nil || !bytes.Equal(p.IK, k2.ik.Public().(ed25519.PublicKey)) {
			t.Fatalf("answered=%v conflict=%v", ok, p.Conflict != nil)
		}
	})
	t.Run("a suspended connection is not reconnected", func(t *testing.T) {
		d, p, n := rcSetup(t, k1, rawLinks(r1))
		p.Conflict = &RotationConflict{OldIK: k0.ik.Public().(ed25519.PublicKey), At: time.Now()}
		if rcDeliver(t, d, p, n, k1, []*handshake.Rotation{r1}, "rc1") || !d.audited("reconnect_refused") {
			t.Fatal("answered a suspended connection")
		}
	})
	t.Run("a conflict suspends whatever the ctx (0.72.1)", func(t *testing.T) {
		// §6.6 "Replay": a valid second successor in the rotations suspends
		// at once and is not answered, though the ctx names another epoch.
		kb := rcKey(t, 0x40)
		d, p, n := rcSetup(t, k1, rawLinks(r1))
		p2 := *p
		p2.LastEpochID = bytes.Repeat([]byte{0xe2}, 16) // the sender's ctx is another epoch
		if rcDeliver(t, d, &p2, n, kb, []*handshake.Rotation{rcLink(t, k0, kb)}, "rc1") || p.Conflict == nil {
			t.Fatal("a reconnect for another epoch with a second successor did not suspend")
		}
	})
	t.Run("a reconnect from another relay key cannot suspend", func(t *testing.T) {
		// The collect sender check comes before the conflict check.
		kb := rcKey(t, 0x40)
		d, p, n := rcSetup(t, k1, rawLinks(r1))
		other := newNewcomer(t, 0x90)
		p.Relay = PeerRelay{URL: other.addr.URL, Mailbox: other.addr.Mailbox, PK: other.addr.PK} // the record names another key
		if rcDeliver(t, d, p, n, kb, []*handshake.Rotation{rcLink(t, k0, kb)}, "rc1") || p.Conflict != nil {
			t.Fatal("a reconnect from a key that is not on record suspended the connection")
		}
	})
	t.Run("a resolved-away successor does not suspend again", func(t *testing.T) {
		kb := rcKey(t, 0x40)
		rb := rcLink(t, k0, kb)
		d, p, n := rcSetup(t, k1, rawLinks(r1))
		if rcDeliver(t, d, p, n, kb, []*handshake.Rotation{rb}, "rc1") || p.Conflict == nil {
			t.Fatal("no suspension")
		}
		// The holder keeps k1.
		d.m.mu.Lock()
		s := d.m.session(d.m.now())
		s.from = PeerInfo{ID: "app1", Kind: KindApp}
		_, err := d.m.hRotationResolve(context.Background(), s, testInner(`{"connection_id":"c1","new_ik":"`+b64(k1.ik.Public().(ed25519.PublicKey))+`"}`))
		d.m.mu.Unlock()
		if err != nil || p.Conflict != nil {
			t.Fatalf("resolve: %v", err)
		}
		// The dropped copy reconnects again, and sends identity.rotate.
		if rcDeliver(t, d, p, n, kb, []*handshake.Rotation{rb}, "rc2") || p.Conflict != nil || !d.audited("reconnect_refused") && !d.audited("rotation_rejected") {
			t.Fatal("the dropped copy suspended the connection again or was answered")
		}
		d.m.mu.Lock()
		again := d.m.rotationConflict(p, rb, d.m.now())
		d.m.mu.Unlock()
		if !again || p.Conflict != nil {
			t.Fatal("identity.rotate from the dropped copy: not refused, or a new conflict")
		}
		// The kept key still reconnects.
		if !rcDeliver(t, d, p, n, k1, []*handshake.Rotation{r1}, "rc3") {
			t.Fatal("the kept key was refused")
		}
	})
}

// The vault as the initiator of a reconnect (§6.6): the responder's chain
// is checked against what the vault followed, and a suspended connection is
// not reconnected.
func TestReconnectInitiatorChain(t *testing.T) {
	k0, k1, kb := rcKey(t, 0x10), rcKey(t, 0x20), rcKey(t, 0x40)
	r1, rb := rcLink(t, k0, k1), rcLink(t, k0, kb)

	// start makes the vault start a reconnect to a peer that stored k1 and
	// returns the peer's side of the hs.init.
	start := func(t *testing.T, conflict bool) (*devFixture, *Peer, *handshake.PendingInit) {
		d, p, _ := rcSetup(t, k1, rawLinks(r1))
		p.Reconnect = HeldToken{Token: "v4.public.VEVTVA", Exp: time.Now().Add(24 * time.Hour)}
		if conflict {
			p.Conflict = &RotationConflict{OldIK: k0.ik.Public().(ed25519.PublicKey), At: time.Now()}
		}
		m := d.m
		m.mu.Lock()
		m.startReconnect(p, m.now())
		m.drainOutbox(context.Background())
		m.mu.Unlock()
		d.relay.mu.Lock()
		defer d.relay.mu.Unlock()
		for _, dep := range d.relay.deposits {
			if dep.mailbox != p.Relay.Mailbox {
				continue
			}
			pi, err := handshake.OpenInit(dep.payload, func(kid suite.Kid) *suite.PrivateKey {
				if kid.Equal(k1.kem.Public().Kid()) {
					return k1.kem
				}
				return nil
			}, m.now())
			if err != nil {
				t.Fatal(err)
			}
			return d, p, pi
		}
		return d, p, nil
	}
	reply := func(t *testing.T, d *devFixture, p *Peer, pi *handshake.PendingInit, id rcKeys, rots []*handshake.Rotation) {
		t.Helper()
		m := d.m
		env, err := func() ([]byte, error) {
			_, e, err := pi.Respond(handshake.ResponderConfig{
				Identity: id.ik, Token: "v4.public.VEVTVA", ReconnectToken: "v4.public.VEVTVA", Policy: policyFor(KindConnection), CollectSender: m.keys.relay.Public().(ed25519.PublicKey),
				RecordRelayKey: m.keys.relay.Public().(ed25519.PublicKey), KnownInitiatorIK: m.keys.ik.Public().(ed25519.PublicKey),
				ExpectedCtx: handshake.EpochCtx(epochIDOf(p.LastEpochID)), Rotations: rots, Now: m.now(),
			})
			return e, err
		}()
		if err != nil {
			t.Fatal(err)
		}
		// Delivered on the standing token the vault issued for the peer.
		jti := ""
		m.mu.Lock()
		for _, og := range m.st.Outgoing {
			for _, it := range og.Issued {
				if it.Kind == TokStanding {
					jti = it.JTI
				}
			}
		}
		m.mu.Unlock()
		if jti == "" {
			t.Fatal("no standing token issued")
		}
		_ = m.ProcessBatch(context.Background(), &fakeCollector{}, []Message{{MsgID: "rp1", Sender: relayauth.EncodeKey(p.Relay.PK), JTI: jti, Payload: env}})
	}

	t.Run("a forked responder chain is dropped", func(t *testing.T) {
		d, p, pi := start(t, false)
		if pi == nil {
			t.Fatal("no hs.init")
		}
		reply(t, d, p, pi, kb, []*handshake.Rotation{rb})
		if !d.audited("hs_resp_dropped") && !d.audited("hs_resp_aborted") || !bytes.Equal(p.IK, k1.ik.Public().(ed25519.PublicKey)) || len(p.Chain) != 1 || p.Conflict != nil {
			t.Fatalf("forked chain followed: chain=%d audit=%v conflict=%v out=%d", len(p.Chain), d.m.Audit(), p.Conflict != nil, len(d.m.st.Outgoing))
		}
	})
	t.Run("an already followed responder chain is answered", func(t *testing.T) {
		d, p, pi := start(t, false)
		reply(t, d, p, pi, k1, []*handshake.Rotation{r1})
		if d.audited("hs_resp_dropped") || len(p.Chain) != 1 || len(d.m.st.Outgoing) != 0 {
			t.Fatal("known chain refused")
		}
	})
	t.Run("a suspended connection starts no reconnect", func(t *testing.T) {
		if _, _, pi := start(t, true); pi != nil {
			t.Fatal("reconnect started on a suspended connection")
		}
	})
	t.Run("a reply cannot activate a suspended connection", func(t *testing.T) {
		d, p, pi := start(t, false)
		p.Conflict = &RotationConflict{OldIK: k0.ik.Public().(ed25519.PublicKey), At: time.Now()}
		before := p.LastEpochID
		reply(t, d, p, pi, k1, []*handshake.Rotation{r1})
		if !d.audited("hs_resp_dropped") || !bytes.Equal(before, p.LastEpochID) || len(d.m.st.Outgoing) != 0 {
			t.Fatal("suspended connection activated")
		}
	})
}
