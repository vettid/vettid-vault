package vault

import (
	"crypto/ed25519"
	"strconv"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayclient"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/suite"
)

// inviterBlocked reports whether d holds exactly one block, on a's identity
// (its ik and relay key, as its invitation gave them).
func inviterBlocked(d, a *devFixture) bool {
	if len(d.m.st.Blocks) != 1 {
		return false
	}
	for _, b := range d.m.st.Blocks {
		return suite.EqualPublic(b.IK, a.m.keys.ik.Public().(ed25519.PublicKey)) &&
			suite.EqualPublic(b.RelayPK, a.m.keys.relay.Public().(ed25519.PublicKey)) && b.ConnectionID == ""
	}
	return false
}

// requestTokensDenied is allDenied for a vault with more owner devices: the
// tokens of every request (not of a device) are denylisted at its relay.
func requestTokensDenied(t *testing.T, d *devFixture) {
	t.Helper()
	for _, it := range d.m.st.Issued {
		if d.m.st.Devices[it.PeerID] != nil {
			continue
		}
		if it.Kind == TokRequest || it.Kind == TokStanding || it.Kind == TokReconnect {
			if !it.Denied || !d.relayRevoked("jti", it.JTI) {
				t.Fatalf("%s token %s not denylisted", it.Kind, it.JTI)
			}
		}
	}
}

// (§6.4 "Who approves", §10.4 Block list) The app's connection.remove or
// block.add{connection_id} of its own outgoing request whose SAS is known
// withdraws it exactly as connection.decline does: connection.declined goes
// on the inviter's request token, and the inviter sees peer_declined.
// block.add also blocks the inviter's identity as the request holds it,
// and the peer cannot tell it from a decline.
func TestOwnOutgoingRequestWithdrawnByRemoveOrBlock(t *testing.T) {
	for _, typ := range []string{"connection.remove", "block.add"} {
		a, b, pid, cid := requested(t)
		desk, _ := accessed(t, b)
		b.inbox(b.self(), desk)
		r, _ := b.request(t, typ, `{"connection_id":"`+cid+`"}`)
		if r.Status != envelope.StatusOK {
			t.Fatalf("%s: %+v %s", typ, r, r.Body)
		}
		deps, jtis := outTo(t, b, a)
		if len(deps) != 1 || a.m.issuedKind(jtis[0]) != TokRequest {
			t.Fatalf("%s: connection.declined not on the inviter's request token", typ)
		}
		pump(t, b, a)
		if !syncState(t, b.inbox(b.self(), desk)["desk1"], "connection_id", cid, requestStateDeclined) {
			t.Fatalf("%s: the member's other devices not told", typ)
		}
		if evs := a.appInbox(); !syncState(t, evs, "pending_id", pid, "peer_declined") {
			t.Fatalf("%s: no peer_declined at the inviter: %+v", typ, evs)
		}
		if rq, waiting := b.m.connRequest(cid, ReqOut); rq != nil || waiting || len(b.m.st.Connections) != 0 {
			t.Fatalf("%s: the request is left", typ)
		}
		requestTokensDenied(t, b)
		switch typ {
		case "connection.remove":
			if len(b.m.st.Blocks) != 0 || !b.hasActivity("connection.request.declined") {
				t.Fatal("remove: not exactly a decline")
			}
		case "block.add":
			if bodyStr(t, r, "block_id") == "" || !inviterBlocked(b, a) || !b.hasActivity("connection.blocked") {
				t.Fatal("block.add: the inviter's identity not blocked")
			}
			// The block applies as any other: a new invitation from A is refused.
			_, link := a.linkFor(t, time.Hour)
			if r, _ := b.request(t, "connection.invite.accept", `{"link":"`+link+`"}`); errCode(r) != "blocked" {
				t.Fatalf("accept from a blocked inviter: %+v", r)
			}
		}
	}
}

// The same for a request still waiting for the inviter's hs.resp: it is
// dropped and its tokens denied, and nothing more is sent (the inviter
// never showed it), as connection.decline does (the baseline here);
// block.add blocks the identity the invitation gave.
func TestOwnWaitingRequestWithdrawnByRemoveOrBlock(t *testing.T) {
	for _, typ := range []string{"connection.decline", "connection.remove", "block.add"} {
		a, b := newVaultPair(t)
		sinkOf(b)
		_, link := a.linkFor(t, time.Hour)
		r, _ := b.request(t, "connection.invite.accept", `{"link":"`+link+`"}`)
		cid := bodyStr(t, r, "connection_id")
		if rq, waiting := b.m.connRequest(cid, ReqOut); rq != nil || !waiting {
			t.Fatal("not a waiting request")
		}
		before, _ := outTo(t, b, a) // the hs.init
		b.m.mu.Lock()
		b.m.st.Outgoing[b.m.waitingOutgoing(cid)].Name = "Alice's hint" // the invitation's hint.name
		b.m.mu.Unlock()
		r, _ = b.request(t, typ, `{"connection_id":"`+cid+`"}`)
		if r.Status != envelope.StatusOK {
			t.Fatalf("%s: %+v %s", typ, r, r.Body)
		}
		if rq, waiting := b.m.connRequest(cid, ReqOut); rq != nil || waiting {
			t.Fatalf("%s: the waiting request is left", typ)
		}
		if deps, _ := outTo(t, b, a); len(deps) != len(before) {
			t.Fatalf("%s: %d more deposits to the inviter", typ, len(deps)-len(before))
		}
		allDenied(t, b)
		if blocked := inviterBlocked(b, a); blocked != (typ == "block.add") {
			t.Fatalf("%s: blocked %v", typ, blocked)
		}
		if typ == "block.add" {
			for _, bl := range b.m.st.Blocks {
				if bl.Name != "Alice's hint" {
					t.Fatalf("the block's name %q, not the invitation's hint", bl.Name)
				}
			}
		}
	}
}

// block.add of the own outgoing request when the inviter's identity is
// already blocked: exists, and the request is left as it was. Of an id
// that is neither a connection nor a request: not_found.
func TestOwnOutgoingRequestBlockExists(t *testing.T) {
	a, b, _, cid := requested(t)
	b.m.mu.Lock()
	b.m.st.Blocks["pre"] = &Block{ID: "pre", IK: append([]byte(nil), a.m.keys.ik.Public().(ed25519.PublicKey)...)}
	b.m.mu.Unlock()
	if r, _ := b.request(t, "block.add", `{"connection_id":"`+cid+`"}`); errCode(r) != "exists" {
		t.Fatalf("block of an already blocked inviter: %+v", r)
	}
	if rq, _ := b.m.connRequest(cid, ReqOut); rq == nil || len(b.m.st.Blocks) != 1 {
		t.Fatal("an exists answer changed the request or the blocks")
	}
	for _, typ := range []string{"block.add", "connection.remove"} {
		if r, _ := b.request(t, typ, `{"connection_id":"nope"}`); errCode(r) != "not_found" {
			t.Fatalf("%s of nothing: %+v", typ, r)
		}
	}
}

// A waiting request withdrawn (or declined) before its hs.init reached the
// relay: the hs.init is not sent afterwards (nothing would take the
// hs.resp, and a block.add's inviter is one the member just blocked).
// The same for one that expires.
func TestWithdrawnWaitingRequestSendsNoHsInit(t *testing.T) {
	for _, typ := range []string{"connection.decline", "connection.remove", "block.add", "expiry"} {
		a, b := newVaultPair(t)
		sinkOf(b)
		_, link := a.linkFor(t, time.Hour)
		b.relay.mu.Lock() // the inviter's mailbox is out of reach: the hs.init waits
		b.relay.failMailbox = map[string]error{a.m.st.Relay.Mailbox: &relayclient.Error{Status: 503, Code: "unavailable"}}
		b.relay.mu.Unlock()
		r, _ := b.request(t, "connection.invite.accept", `{"link":"`+link+`"}`)
		cid := bodyStr(t, r, "connection_id")
		before, _ := outTo(t, b, a)
		if typ == "expiry" {
			b.m.mu.Lock()
			b.m.expireRequests(b.m.now().Add(OutgoingRequestTTL + time.Minute))
			b.m.mu.Unlock()
		} else if r, _ := b.request(t, typ, `{"connection_id":"`+cid+`"}`); r.Status != envelope.StatusOK {
			t.Fatalf("%s: %+v %s", typ, r, r.Body)
		}
		if rq, waiting := b.m.connRequest(cid, ReqOut); rq != nil || waiting {
			t.Fatalf("%s: the request is left", typ)
		}
		b.relay.mu.Lock()
		b.relay.failMailbox = nil
		b.relay.mu.Unlock()
		if deps, _ := outTo(t, b, a); len(deps) != len(before) {
			t.Fatalf("%s: the hs.init went to the inviter after the request ended", typ)
		}
	}
}

// At the block limit, block.add of the own outgoing request is refused
// first, and the request is left as it was.
func TestOwnOutgoingRequestBlockAtTheLimit(t *testing.T) {
	_, b, _, cid := requested(t)
	b.m.mu.Lock()
	for i := range MaxBlocks {
		id := "full" + strconv.Itoa(i)
		b.m.st.Blocks[id] = &Block{ID: id, IK: []byte{byte(i), byte(i >> 8)}}
	}
	b.m.mu.Unlock()
	if r, _ := b.request(t, "block.add", `{"connection_id":"`+cid+`"}`); errCode(r) != "limit" {
		t.Fatalf("block at the limit: %+v %s", r, r.Body)
	}
	if rq, _ := b.m.connRequest(cid, ReqOut); rq == nil {
		t.Fatal("a refused block withdrew the request")
	}
}
