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
		rq, _ := b.m.connRequest(cid, ReqOut)
		if rq == nil || rq.Peer == nil {
			t.Fatal("no outgoing request")
		}
		const name = "Alice" // the name the request holds of the inviter
		b.m.mu.Lock()
		rq.Peer.Name = name
		b.m.mu.Unlock()
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
			for _, bl := range b.m.st.Blocks {
				if bl.Name != name {
					t.Fatalf("block.add: the block's name %q, not the request's", bl.Name)
				}
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

// Of an id that is neither a connection nor a request: not_found.
func TestOwnOutgoingRequestUnknownID(t *testing.T) {
	_, b, _, _ := requested(t)
	for _, typ := range []string{"block.add", "connection.remove"} {
		if r, _ := b.request(t, typ, `{"connection_id":"nope"}`); errCode(r) != "not_found" {
			t.Fatalf("%s of nothing: %+v", typ, r)
		}
	}
}

// A block.add of the own outgoing request that is refused (the inviter's
// identity already blocked: exists; the block limit, judged first) changes
// nothing, in both states: the request, its handshake and live initiator,
// its tokens, a queued hs.init, the blocks and the audit stay as they were,
// and nothing reaches the inviter.
func TestOwnOutgoingRequestBlockRefusedChangesNothing(t *testing.T) {
	for _, state := range []string{"sas_known", "waiting"} {
		for _, refusal := range []string{"exists", "limit"} {
			name := state + "/" + refusal
			var a, b *devFixture
			var cid string
			if state == "sas_known" {
				a, b, _, cid = requested(t)
			} else {
				a, b = newVaultPair(t)
				sinkOf(b)
				_, link := a.linkFor(t, time.Hour)
				b.relay.mu.Lock() // the hs.init stays queued
				b.relay.failMailbox = map[string]error{a.m.st.Relay.Mailbox: &relayclient.Error{Status: 503, Code: "unavailable"}}
				b.relay.mu.Unlock()
				r, _ := b.request(t, "connection.invite.accept", `{"link":"`+link+`"}`)
				cid = bodyStr(t, r, "connection_id")
			}
			b.m.mu.Lock()
			if refusal == "exists" {
				b.m.st.Blocks["pre"] = &Block{ID: "pre", IK: append([]byte(nil), a.m.keys.ik.Public().(ed25519.PublicKey)...)}
			} else {
				for i := range MaxBlocks {
					id := "full" + strconv.Itoa(i)
					b.m.st.Blocks[id] = &Block{ID: id, IK: []byte{byte(i), byte(i >> 8)}}
				}
			}
			b.m.mu.Unlock()
			before, _ := outTo(t, b, a)
			was := ownRequestState(b, cid)
			if was.request == was.waiting { // sas_known: a request; waiting: none, waiting
				t.Fatalf("%s: not the state under test: %+v", name, was)
			}
			if r, _ := b.request(t, "block.add", `{"connection_id":"`+cid+`"}`); errCode(r) != refusal {
				t.Fatalf("%s: %+v %s", name, r, r.Body)
			}
			if now := ownRequestState(b, cid); now != was {
				t.Fatalf("%s: a refused block changed\n%+v\nto\n%+v", name, was, now)
			}
			if deps, _ := outTo(t, b, a); len(deps) != len(before) {
				t.Fatalf("%s: %d deposits to the inviter", name, len(deps)-len(before))
			}
		}
	}
}

// What a refused withdrawal must leave as it was.
type ownRequest struct {
	request, waiting, handshake, initiator, initQueued bool
	denied, blocks, audit                              int
}

func ownRequestState(d *devFixture, cid string) ownRequest {
	rq, waiting := d.m.connRequest(cid, ReqOut)
	d.m.mu.Lock()
	defer d.m.mu.Unlock()
	o := ownRequest{request: rq != nil, waiting: waiting, blocks: len(d.m.st.Blocks), audit: len(sinkOf(d).got)}
	if oid := d.m.waitingOutgoing(cid); oid != "" {
		o.handshake = d.m.st.Outgoing[oid] != nil
		o.initiator = d.m.outgoing[oid] != nil
		for _, e := range d.m.st.Outbox {
			o.initQueued = o.initQueued || e.ID == d.m.st.Outgoing[oid].InitOutbox && !e.Done
		}
	}
	for _, it := range d.m.st.Issued {
		if it.Denied {
			o.denied++
		}
	}
	return o
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
		b.m.mu.Lock()
		initID := b.m.st.Outgoing[b.m.waitingOutgoing(cid)].InitOutbox
		b.m.mu.Unlock()
		if initID == "" || !outboxPending(b, initID) {
			t.Fatalf("%s: no hs.init waiting in the outbox", typ)
		}
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
		// The drain's backoff after the failed try would hide a leftover entry
		// below, so the entry itself is looked at.
		if outboxPending(b, initID) {
			t.Fatalf("%s: the hs.init is still in the outbox", typ)
		}
		b.relay.mu.Lock()
		b.relay.failMailbox = nil
		b.relay.mu.Unlock()
		readyNow(b) // past the failed try's backoff, so a leftover entry would go out
		if deps, _ := outTo(t, b, a); len(deps) != len(before) {
			t.Fatalf("%s: the hs.init went to the inviter after the request ended", typ)
		}
	}
}

// readyNow makes every outbox entry due now (past a failed try's backoff).
func readyNow(d *devFixture) {
	d.m.mu.Lock()
	defer d.m.mu.Unlock()
	for _, e := range d.m.st.Outbox {
		e.NotBefore = time.Time{}
	}
}

// A waiting request withdrawn after its hs.init was delivered: the
// inviter's hs.resp then finds no record and is dropped, and nothing is sent
// back (no hs.fin), so the inviter never shows the request.
func TestWithdrawnWaitingRequestDropsTheLateHsResp(t *testing.T) {
	for _, typ := range []string{"connection.remove", "block.add"} {
		a, b := newVaultPair(t)
		sinkOf(a)
		sinkOf(b)
		_, link := a.linkFor(t, time.Hour)
		r, _ := b.request(t, "connection.invite.accept", `{"link":"`+link+`"}`)
		cid := bodyStr(t, r, "connection_id")
		pump(t, b, a) // the hs.init reaches A, whose hs.resp is queued
		if r, _ := b.request(t, typ, `{"connection_id":"`+cid+`"}`); r.Status != envelope.StatusOK {
			t.Fatalf("%s: %+v %s", typ, r, r.Body)
		}
		before, _ := outTo(t, b, a)
		pump(t, a, b) // the hs.resp reaches B
		if deps, _ := outTo(t, b, a); len(deps) != len(before) {
			t.Fatalf("%s: B answered the late hs.resp", typ)
		}
		if rq, waiting := b.m.connRequest(cid, ReqOut); rq != nil || waiting || len(b.m.st.Connections) != 0 {
			t.Fatalf("%s: the late hs.resp brought the request back", typ)
		}
		if event(a.appInbox(), "connection.request.pending") != nil || len(a.m.st.Requests) != 0 {
			t.Fatalf("%s: the inviter shows the request", typ)
		}
	}
}

// block.add of an outgoing request the member already approved: the
// standing and reconnect tokens its connection.approved carried are denied
// too, and the inviter's approval after it activates nothing.
func TestBlockOfAnApprovedOutgoingRequest(t *testing.T) {
	a, b, pid, cid := requested(t)
	if r, _ := b.request(t, "connection.approve", `{"connection_id":"`+cid+`"}`); r.Status != envelope.StatusOK {
		t.Fatalf("B approve: %+v", r)
	}
	pump(t, b, a) // A: peer_approved
	a.appInbox()
	var standing bool
	for _, it := range b.m.st.Issued {
		standing = standing || it.Kind == TokStanding
	}
	if !standing {
		t.Fatal("the approval issued no standing token")
	}
	if r, _ := b.request(t, "block.add", `{"connection_id":"`+cid+`"}`); r.Status != envelope.StatusOK {
		t.Fatalf("block: %+v %s", r, r.Body)
	}
	requestTokensDenied(t, b)                                      // the request, standing and reconnect tokens
	a.request(t, "connection.approve", `{"pending_id":"`+pid+`"}`) // crossing the decline
	pump(t, b, a)
	pump(t, a, b)
	if len(b.m.st.Connections) != 0 || b.m.sessions[cid] != nil {
		t.Fatalf("the blocked request activated: %d connections, session %v", len(b.m.st.Connections), b.m.sessions[cid] != nil)
	}
	if !inviterBlocked(b, a) {
		t.Fatal("the inviter's identity not blocked")
	}
}

// Whether the outbox holds entry id, not done.
func outboxPending(f *devFixture, id string) bool {
	f.m.mu.Lock()
	defer f.m.mu.Unlock()
	for _, e := range f.m.st.Outbox {
		if e.ID == id && !e.Done {
			return true
		}
	}
	return false
}
