package vault

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/envelope"
)

// agentHeldForWipe refers an agent's request for the member's approval and
// returns its approval id, the request's inner id and the stored inner.
func agentHeldForWipe(t *testing.T) (d *devFixture, pol *policyType, ag, app *tdev, aid, reqID string, stored []byte) {
	t.Helper()
	d = newDevFixture(t)
	app = d.self()
	pol = &policyType{decision: AgentAsk}
	d.m.addFeature(pol)
	ag = d.addDevice(t, "agent1", KindAgent, 0x70)
	ag.peer.Access = &AccessSession{ID: "s", Expires: time.Now().Add(time.Hour)}
	reqID = d.sendAs(ag, "test.agent", `{"secret":"held for approval"}`)
	ap := find(d.inbox(app, ag)["dev1"], ofType("approval.pending"))
	if ap == nil {
		t.Fatal("setup: not referred")
	}
	aid = bodyStr(t, ap, "approval_id")
	h := d.m.st.Held[aid]
	if h == nil || !bytes.Contains(h.Inner, []byte("held for approval")) {
		t.Fatal("setup: no held request")
	}
	return d, pol, ag, app, aid, reqID, h.Inner
}

// An approved held request runs as its sender's and is answered; its
// stored plaintext and the copy parsed to run it are wiped after.
func TestApprovedHeldRequestWiped(t *testing.T) {
	d, pol, ag, app, aid, reqID, stored := agentHeldForWipe(t)
	pol.decision = AgentAllow
	w := recordWipedInners(t)
	d.sendAs(app, "approval.decide", `{"approval_id":"`+aid+`","approve":true}`)
	if r := find(d.inbox(ag)["agent1"], reply(reqID)); r == nil || r.Status != envelope.StatusOK || pol.ran != 1 {
		t.Fatalf("the approved request did not run: %+v (ran %d)", r, pol.ran)
	}
	if len(pol.bodies) != 1 || string(pol.bodies[0]) != `{"secret":"held for approval"}` {
		t.Fatalf("the handler did not read the held body intact: %q", pol.bodies)
	}
	w.wiped(reqID)
	if _, ok := d.m.st.Held[aid]; ok || !wipedBytes(stored) {
		t.Fatal("the held request's stored plaintext was not wiped")
	}
}

// A denied held request is answered denied; its stored plaintext and the
// copy parsed to answer it are wiped.
func TestDeniedHeldRequestWiped(t *testing.T) {
	d, _, ag, app, aid, reqID, stored := agentHeldForWipe(t)
	w := recordWipedInners(t)
	d.sendAs(app, "approval.decide", `{"approval_id":"`+aid+`","approve":false}`)
	if r := find(d.inbox(ag)["agent1"], reply(reqID)); errCode(r) != "denied" {
		t.Fatalf("the denied request's answer: %+v", r)
	}
	w.wiped(reqID)
	if !wipedBytes(stored) {
		t.Fatal("the held request's stored plaintext was not wiped")
	}
}

// One that expires is answered approval_timeout and wiped the same way.
func TestExpiredHeldRequestWiped(t *testing.T) {
	d, _, ag, _, aid, reqID, stored := agentHeldForWipe(t)
	w := recordWipedInners(t)
	d.m.mu.Lock()
	d.m.st.Held[aid].Expires = time.Now().Add(-time.Second)
	d.m.expireAccess(time.Now())
	d.m.mu.Unlock()
	_ = ag
	w.wiped(reqID)
	if _, ok := d.m.st.Held[aid]; ok || !wipedBytes(stored) {
		t.Fatal("the expired held request's stored plaintext was not wiped")
	}
}

// pending.list reads each held request to list it: the parsed copy is
// wiped, and the stored one stays intact (the request still waits).
func TestPendingListWipesItsParse(t *testing.T) {
	d, _, _, _, aid, reqID, stored := agentHeldForWipe(t)
	w := recordWipedInners(t)
	d.m.mu.Lock()
	asks := d.m.pendingAsks(KindApp, time.Now())
	d.m.mu.Unlock()
	if len(asks) != 1 || asks[0].ID != aid || !bytes.Contains(asks[0].Body, []byte("held for approval")) {
		t.Fatalf("the listed ask: %+v", asks)
	}
	w.wiped(reqID)
	if wipedBytes(stored) || !bytes.Contains(stored, []byte("held for approval")) {
		t.Fatal("listing wiped the stored request, which still waits")
	}
}

// wipedBytes: b was not empty and is all zeros now.
func wipedBytes(b []byte) bool { return len(b) > 0 && bytes.Count(b, []byte{0}) == len(b) }

// A retransmission is answered from the cache: the parsed copy is wiped,
// the answer goes out intact, and the cached one stays (it may be asked
// for again). An expired cached answer, and one replaced under its key,
// are wiped.
func TestCachedAnswerWipes(t *testing.T) {
	d := newDevFixture(t)
	f := &cacheAsFeature{}
	d.m.addFeature(f)
	app := d.self()
	id := d.sendAs(app, "test.secret", `{}`)
	r := find(d.inbox(app)["dev1"], reply(id))
	key := "dev1|" + id
	cached := d.m.st.Responses[key].Inner
	if r == nil || len(cached) == 0 {
		t.Fatal("setup: no cached answer")
	}
	w := recordWipedInners(t)
	d.sendID(app, id, "test.secret", `{}`)
	again := find(d.inbox(app)["dev1"], reply(id))
	if again == nil || string(again.Body) != `{"v":"public"}` || again.ID != r.ID {
		t.Fatalf("the resent answer: %+v", again)
	}
	w.wiped(r.ID)
	if wipedBytes(cached) || !bytes.Contains(cached, []byte("public")) {
		t.Fatal("the resend wiped the cached answer")
	}

	// Replaced under its key: the older answer is wiped.
	d.m.mu.Lock()
	req := &envelope.Inner{ID: id, Type: "test.secret"}
	d.m.sendResponseCached(d.devPeer, req, key, &envelope.Inner{Type: req.Type, Re: id, Status: envelope.StatusOK, Body: []byte(`{"v":"newer"}`)}, nil, time.Now())
	newer := d.m.st.Responses[key].Inner
	d.m.mu.Unlock()
	if !wipedBytes(cached) || !bytes.Contains(newer, []byte("newer")) {
		t.Fatal("the replaced cached answer was not wiped")
	}

	// Expired: pruned and wiped.
	d.m.mu.Lock()
	c := d.m.st.Responses[key]
	c.Expires = time.Now().Add(-time.Second)
	d.m.st.Responses[key] = c
	d.m.prune()
	_, kept := d.m.st.Responses[key]
	d.m.mu.Unlock()
	if kept || !wipedBytes(newer) {
		t.Fatal("the expired cached answer was not wiped")
	}
}

// A held outbox entry (its plaintext kept across a key change) is wiped
// when it is sealed again, when its exp passes, and when it is not
// delivered; each parse of it is wiped too. A resealed one arrives intact.
func TestHeldOutboxEntryWipes(t *testing.T) {
	hold := func(t *testing.T, note string) (*r29Fx, *OutboxEntry, *envelope.Inner, []byte) {
		f := newR29Fx(t)
		f.longTokens()
		e, in := f.waitingNote(0, note)
		f.do(0, func(m *Manager, p *Peer) { m.reholdAt(p, m.sessions[p.ID].Current(), true, f.clk) })
		if e.Held == nil {
			t.Fatal("setup: not held")
		}
		return f, e, in, e.Held
	}
	t.Run("sealed again", func(t *testing.T) {
		f, e, in, held := hold(t, "resealed")
		w := recordWipedInners(t)
		f.do(0, func(m *Manager, p *Peer) { m.sealHeld(p) })
		w.wiped(in.ID)
		if e.Held != nil || len(e.Payload) == 0 || !wipedBytes(held) {
			t.Fatal("the held plaintext was not wiped when sealed again")
		}
		testWipeInnerHook = nil
		f.release(0)
		f.settle()
		if n := f.arrived(1, `{"n":"resealed"}`); n != 1 {
			t.Fatalf("arrived %d times, want 1", n)
		}
	})
	t.Run("expired", func(t *testing.T) {
		f, e, in, held := hold(t, "expired")
		w := recordWipedInners(t)
		f.do(0, func(m *Manager, p *Peer) {
			e.HeldExp, e.InnerID = f.clk.Add(-time.Second), "" // its id read from the held copy (heldID)
			m.sealHeld(p)
		})
		w.wiped(in.ID)
		if !e.Done || e.InnerID != in.ID || !wipedBytes(held) {
			t.Fatal("the expired held entry's plaintext was not wiped")
		}
	})
	t.Run("not delivered", func(t *testing.T) {
		f, e, in, held := hold(t, "late")
		w := recordWipedInners(t)
		f.advance(17 * 24 * time.Hour)
		f.do(0, func(m *Manager, p *Peer) {
			e.Tried = true             // its ts is kept, and now past the 16 days
			e.InnerID, e.Type = "", "" // read from the held copy, before it is wiped
			m.sealHeld(p)
		})
		w.wiped(in.ID)
		// Each parse of it is wiped: the seal's, heldID's and entryType's.
		if n := w.count(in.ID); n != 3 {
			t.Fatalf("%d parses of the held entry wiped, want 3", n)
		}
		if !e.Done || !wipedBytes(held) {
			t.Fatal("the undelivered held entry's plaintext was not wiped")
		}
		if a := f.m(0).st.Audit[len(f.m(0).st.Audit)-1]; a.Ref != in.ID {
			t.Fatalf("audited with ref %q, want the inner id read before the wipe", a.Ref)
		}
	})
}

// Every way a held request is dropped wipes its stored plaintext: the end
// of its device's access, and the owner check's hold (expiry and the
// member's decision are tested above).
func TestDroppedHeldRequestWiped(t *testing.T) {
	for name, drop := range map[string]func(d *devFixture, ag *tdev){
		"end of access": func(d *devFixture, ag *tdev) {
			d.m.endAccess(context.Background(), ag.peer, false, "ended", "", time.Now())
		},
		"the hold": func(d *devFixture, _ *tdev) { d.m.enterHold(time.Now()) },
	} {
		t.Run(name, func(t *testing.T) {
			d, _, ag, _, aid, _, stored := agentHeldForWipe(t)
			d.m.mu.Lock()
			drop(d, ag)
			_, kept := d.m.st.Held[aid]
			d.m.mu.Unlock()
			if kept || !wipedBytes(stored) {
				t.Fatal("the dropped held request's plaintext was not wiped")
			}
		})
	}
}

// A held outbox entry whose exp passed before its epoch could seal it is
// discarded by the drain and wiped there too; a done entry still holding
// plaintext is wiped when the outbox is compacted.
func TestHeldOutboxEntryDrainAndCompaction(t *testing.T) {
	held := func(t *testing.T, note string) (*r29Fx, *OutboxEntry, []byte) {
		f := newR29Fx(t)
		f.longTokens()
		e, _ := f.waitingNote(0, note)
		f.do(0, func(m *Manager, p *Peer) { m.reholdAt(p, m.sessions[p.ID].Current(), true, f.clk) })
		if e.Held == nil {
			t.Fatal("setup: not held")
		}
		return f, e, e.Held
	}
	t.Run("expired at the drain", func(t *testing.T) {
		f, e, b := held(t, "drained")
		var want string
		f.do(0, func(m *Manager, p *Peer) {
			want = e.InnerID
			e.HeldExp, e.InnerID = f.clk.Add(-time.Second), "" // its id read from the held copy, before it is wiped
			m.drainOutbox(context.Background())
		})
		if !e.Done || !wipedBytes(b) {
			t.Fatal("the expired held entry's plaintext was not wiped at the drain")
		}
		if e.InnerID != want {
			t.Fatalf("inner id %q after the drain, want %q read before the wipe", e.InnerID, want)
		}
	})
	t.Run("done, then compacted", func(t *testing.T) {
		f, e, b := held(t, "compacted")
		f.do(0, func(m *Manager, p *Peer) {
			e.Done = true // a path that marks it done and keeps Held
			m.prune()
		})
		if !wipedBytes(b) {
			t.Fatal("the compacted entry's held plaintext was not wiped")
		}
	})
}

// A held entry whose epoch is still demoted stays held, intact: only the
// parse made to seal it is wiped.
func TestHeldEntryKeptWhileDemoted(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	e, in := f.waitingNote(0, "still-demoted")
	f.do(0, func(m *Manager, p *Peer) { m.reholdAt(p, m.sessions[p.ID].Current(), true, f.clk) })
	held := e.Held
	w := recordWipedInners(t)
	f.do(0, func(m *Manager, p *Peer) {
		id := m.sessions[p.ID].Current().ID()
		p.epochMeta(id[:]).Demoted = true
		m.sealHeld(p)
	})
	w.wiped(in.ID)
	if e.Held == nil || wipedBytes(held) || !bytes.Contains(e.Held, []byte(`"n":"still-demoted"`)) {
		t.Fatal("a held entry was wiped while its epoch is still demoted")
	}
}

// A held upkeep message (vault.held) not delivered tells the member
// nothing: its type is read from the held copy before it is wiped.
func TestUndeliveredUpkeepTellsNobody(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	e, _ := f.waitingNote(0, "upkeep")
	f.do(0, func(m *Manager, p *Peer) {
		// The same entry as an upkeep message, held unsealed and not typed.
		c := envelope.Inner{ID: e.InnerID, Type: "vault.held", TS: f.clk, Body: []byte(`{"n":"upkeep"}`)}
		raw, err := c.Marshal(envelope.ModeSealed)
		if err != nil {
			t.Fatal(err)
		}
		e.Payload, e.Held, e.Type, e.InnerID = nil, raw, "", ""
	})
	f.advance(17 * 24 * time.Hour)
	ref := ""
	f.do(0, func(m *Manager, p *Peer) { ref = heldID(e.Held) })
	f.do(0, func(m *Manager, p *Peer) {
		e.Tried = true
		m.sealHeld(p)
	})
	if !e.Done {
		t.Fatal("not ended")
	}
	if n := f.activityCount(0, NoticeNotDelivered, ref) + f.activityCount(0, NoticeUnconfirmed, ref); n != 0 {
		t.Fatalf("an upkeep message told the member (%d notices)", n)
	}
}

// A held request whose device is gone is not answered, and its parse is
// wiped all the same.
func TestHeldRequestOfAGoneDeviceWiped(t *testing.T) {
	d, _, ag, _, aid, reqID, _ := agentHeldForWipe(t)
	w := recordWipedInners(t)
	d.m.mu.Lock()
	delete(d.m.st.Devices, ag.peer.ID)
	d.m.answerHeld(d.m.st.Held[aid], "denied", time.Now())
	d.m.mu.Unlock()
	w.wiped(reqID)
}

// count is how many times the inner with this id was wiped.
func (w *wipedInners) count(id string) int {
	n := 0
	for _, in := range w.seen {
		if in.ID == id {
			n++
		}
	}
	return n
}
