package vault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/invite"
)

// serviceLinkFor makes a connection invitation as a service vault would
// (§6.4 "Service connections", 0.69.0): the bundle declares peer_kind. A
// member vault never declares it itself; this mirrors createInvite.
func serviceLinkFor(t *testing.T, d *devFixture, ttl time.Duration, kind string) string {
	t.Helper()
	m := d.m
	m.mu.Lock()
	defer m.mu.Unlock()
	ctx := context.Background()
	now := m.now()
	id, jti := m.newID(now), m.newID(now)
	tok, err := m.relay.MintOpenToken(ttl, jti)
	if err != nil {
		t.Fatal(err)
	}
	exp := now.UTC().Truncate(time.Second).Add(-min(tokenBackdate, ttl/2)).Add(ttl)
	b := &invite.Bundle{Kind: "connection", InviteID: id, Remote: invite.IsRemote(ttl), PeerKind: kind,
		Vault: handshake.Principal{IK: m.keys.ik.Public().(ed25519.PublicKey), KEM: m.keys.kem.Public(), Relay: m.ownAddr()},
		Token: tok, Exp: exp}
	bj, err := b.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	blob, kb, h, err := invite.SealBundle(bj)
	if err != nil {
		t.Fatal(err)
	}
	claimID, _, err := m.relay.PutClaim(ctx, blob, ttl)
	if err != nil {
		t.Fatal(err)
	}
	q := &invite.QR{Kind: invite.KindConnection, Relay: m.st.Relay.URL, ClaimID: claimID, Hash: h, Key: kb, Exp: exp.Unix()}
	link, err := q.Link()
	if err != nil {
		t.Fatal(err)
	}
	m.st.Invites[id] = &Invite{ID: id, Kind: KindConnection, Remote: b.Remote, Exp: exp, OpenJTI: jti, ClaimID: claimID, CreatedBy: "dev1"}
	return link
}

// The marker is read from the invitation bundle at connection.invite.accept,
// shown with the SAS before approval, copied into the connection at
// activation and listed; only "service" counts (§6.4 "Service connections",
// §10.4, 0.69.0); the epoch history starts with the first epoch.
func TestPeerKindFromBundleToConnection(t *testing.T) {
	for _, c := range []struct {
		kind string
		want string
	}{{"service", "service"}, {"", ""}} {
		t.Run("bundle "+c.kind, func(t *testing.T) {
			a, b := newVaultPair(t)
			link := serviceLinkFor(t, a, time.Hour, c.kind)
			r, _ := b.request(t, "connection.invite.accept", `{"link":"`+link+`"}`)
			if r.Status != envelope.StatusOK {
				t.Fatalf("accept: %+v %s", r, r.Body)
			}
			if got := strings.Contains(string(r.Body), `"peer_kind":"service"`); got != (c.want == "service") {
				t.Fatalf("accept answer: %s", r.Body)
			}
			cid := bodyStr(t, r, "connection_id")
			if l, _ := b.request(t, "connection.request.list", `{}`); strings.Contains(string(l.Body), `"peer_kind":"service"`) != (c.want == "service") {
				t.Fatalf("request list: %s", l.Body)
			}
			pump(t, b, a)
			pump(t, a, b)
			out := event(b.appInbox(), "connection.request.outgoing")
			if out == nil || strings.Contains(string(out.Body), `"peer_kind":"service"`) != (c.want == "service") {
				t.Fatalf("request.outgoing: %+v", out)
			}
			pump(t, b, a)
			aPend := event(a.appInbox(), "connection.request.pending")
			if aPend == nil || strings.Contains(string(aPend.Body), "peer_kind") {
				t.Fatal("the inviter's view of the accepter carries a peer_kind")
			}
			a.request(t, "connection.approve", `{"pending_id":"`+bodyStr(t, aPend, "pending_id")+`"}`)
			pump(t, a, b)
			b.request(t, "connection.approve", `{"connection_id":"`+cid+`"}`)
			pump(t, b, a)
			p := b.m.st.Connections[cid]
			if p == nil || p.State != PeerActive || p.PeerKind != c.want {
				t.Fatalf("connection: %+v", p)
			}
			if (len(p.History) == 1) != (c.want == "service") || len(p.History) > 1 ||
				(len(p.History) == 1 && !bytes.Equal(p.History[0].ID, p.LastEpochID)) {
				t.Fatalf("history: %+v", p.History)
			}
			if l, _ := b.request(t, "connection.list", `{}`); strings.Contains(string(l.Body), `"peer_kind":"service"`) != (c.want == "service") {
				t.Fatalf("connection.list: %s", l.Body)
			}
			// The inviter's record of the accepter is a person's.
			for _, pa := range a.m.st.Connections {
				if pa.PeerKind != "" || len(pa.History) != 0 {
					t.Fatal("the inviter marked the accepter")
				}
			}
		})
	}
}

// A service's later claims change nothing: the marker is fixed at connect
// time (§6.4): a reconnect, a rekey and an identity rotation never set or
// clear it.
func TestPeerKindNeverChanges(t *testing.T) {
	f := newSvcFx(t, "")
	f.build(1)
	if f.p.PeerKind != "" || len(f.p.History) != 0 {
		t.Fatal("a reconnect marked a person connection")
	}
	g := newSvcFx(t, "service")
	g.build(1)
	if g.p.PeerKind != "service" {
		t.Fatal("a reconnect cleared the marker")
	}
}
