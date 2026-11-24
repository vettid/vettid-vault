package vault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/handshake"
)

// The older copies of handshake secrets the vault holds are wiped: the
// snapshots it replaces at a write or drops with their record, an hs.init
// once handled (its inner plaintext and a transfer's secrets), and an
// hs.resp's plaintext once read.

func zeroed(b []byte) bool { return len(b) > 0 && bytes.Count(b, []byte{0}) == len(b) }

// checkWiped fails unless every slice in got is non-empty and zero.
func checkWiped(t *testing.T, what string, got ...[]byte) {
	t.Helper()
	for i, b := range got {
		if !zeroed(b) {
			t.Fatalf("%s: secret %d of %d was not wiped", what, i+1, len(got))
		}
	}
}

func initSecrets(s handshake.InitiatorState) [][]byte { return [][]byte{s.EphSeed, s.Ks, s.Body} }
func respSecrets(s handshake.ResponderState) [][]byte { return [][]byte{s.Ks, s.Ke, s.PRK, s.RK} }
func epochSecrets(s handshake.EpochState) [][]byte    { return [][]byte{s.RecvKey} }

// intact fails if a secret of a fresh snapshot is missing or zero.
func intact(t *testing.T, got ...[]byte) {
	t.Helper()
	for i, b := range got {
		if len(b) == 0 || zeroed(b) {
			t.Fatalf("the new snapshot's secret %d of %d is missing or wiped", i+1, len(got))
		}
	}
}

// onlyID is the one key of m, failing for none or several.
func onlyID[V any](t *testing.T, m map[string]V) string {
	t.Helper()
	if len(m) != 1 {
		t.Fatalf("%d records, want 1", len(m))
	}
	for k := range m {
		return k
	}
	return ""
}

// contactStage is how far a first contact from b to a's invitation has
// gone.
type contactStage int

const (
	bSentInit  contactStage = iota // b holds the outgoing handshake
	aAnswered                      // a holds the awaiting handshake, b has not read the hs.resp
	aRequested                     // the handshake is done, a holds the request (approval)
	connected                      // both approved
)

// firstContact runs a first contact up to stage.
func firstContact(t *testing.T, stage contactStage) (a, b *devFixture) {
	t.Helper()
	a, b = newVaultPair(t)
	_, link := a.linkFor(t, time.Hour)
	r, _ := b.request(t, "connection.invite.accept", `{"link":"`+link+`"}`)
	if stage == bSentInit {
		return a, b
	}
	pump(t, b, a)
	if stage == aAnswered {
		return a, b
	}
	pump(t, a, b)
	b.appInbox()
	pump(t, b, a)
	aPend := event(a.appInbox(), "connection.request.pending")
	if aPend == nil {
		t.Fatal("setup: a was not asked to approve")
	}
	if stage == aRequested {
		return a, b
	}
	a.request(t, "connection.approve", `{"pending_id":"`+bodyStr(t, aPend, "pending_id")+`"}`)
	pump(t, a, b)
	b.request(t, "connection.approve", `{"connection_id":"`+bodyStr(t, r, "connection_id")+`"}`)
	pump(t, b, a)
	if len(a.m.st.Connections) != 1 || len(b.m.st.Connections) != 1 {
		t.Fatal("setup: not connected")
	}
	return a, b
}

// locked runs f under d's lock.
func locked(d *devFixture, f func(m *Manager)) {
	d.m.mu.Lock()
	defer d.m.mu.Unlock()
	f(d.m)
}

// Each place a handshake record goes wipes its snapshot: the outgoing one
// (dropped, abandoned, answered), the awaiting one (abandoned, dropped,
// finished, not restored), the request (activated, dropped, not restored),
// and a removed peer's sessions.
func TestDroppedSnapshotsWiped(t *testing.T) {
	now := func(d *devFixture) time.Time { return d.m.now() }
	t.Run("outgoing dropped", func(t *testing.T) {
		_, b := firstContact(t, bSentInit)
		locked(b, func(m *Manager) {
			id := onlyID(t, m.st.Outgoing)
			got := initSecrets(m.st.Outgoing[id].Init)
			m.dropOutgoing(id)
			checkWiped(t, "dropOutgoing", got...)
		})
	})
	t.Run("outgoing abandoned", func(t *testing.T) {
		_, b := firstContact(t, bSentInit)
		locked(b, func(m *Manager) {
			id := onlyID(t, m.st.Outgoing)
			got := initSecrets(m.st.Outgoing[id].Init)
			m.abandonOutgoing(id, now(b))
			checkWiped(t, "abandonOutgoing", got...)
		})
	})
	t.Run("outgoing answered", func(t *testing.T) {
		a, b := firstContact(t, aAnswered)
		var got [][]byte
		locked(b, func(m *Manager) { got = initSecrets(m.st.Outgoing[onlyID(t, m.st.Outgoing)].Init) })
		var inners [][]byte
		testRespResultHook = func(r *handshake.Result) { inners = append(inners, r.Inner.Body) }
		defer func() { testRespResultHook = nil }()
		pump(t, a, b)
		checkWiped(t, "the answered handshake's record", got...)
		if len(inners) != 1 {
			t.Fatalf("%d hs.resp read", len(inners))
		}
		checkWiped(t, "the hs.resp read", inners...)
	})
	t.Run("outgoing aborted", func(t *testing.T) {
		// a answers under another identity key than its invitation named:
		// sig_R fails, and b's handshake is aborted.
		a, b := firstContact(t, bSentInit)
		locked(a, func(m *Manager) { m.keys.ik = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x77}, 32)) })
		pump(t, b, a)
		var got [][]byte
		locked(b, func(m *Manager) { got = initSecrets(m.st.Outgoing[onlyID(t, m.st.Outgoing)].Init) })
		pump(t, a, b)
		if !auditedIn(b.m, "hs_resp_aborted") || len(b.m.st.Outgoing) != 0 {
			t.Fatal("setup: the handshake was not aborted")
		}
		checkWiped(t, "the aborted handshake's record", got...)
	})
	t.Run("awaiting abandoned", func(t *testing.T) {
		a, _ := firstContact(t, aAnswered)
		locked(a, func(m *Manager) {
			id := onlyID(t, m.st.Awaiting)
			got := respSecrets(m.st.Awaiting[id].Resp)
			m.abandonAwaiting(id, now(a))
			checkWiped(t, "abandonAwaiting", got...)
		})
	})
	t.Run("awaiting dropped", func(t *testing.T) {
		a, _ := firstContact(t, aAnswered)
		locked(a, func(m *Manager) {
			id := onlyID(t, m.st.Awaiting)
			got := respSecrets(m.st.Awaiting[id].Resp)
			m.dropAwaiting(id, "test", now(a))
			checkWiped(t, "dropAwaiting", got...)
		})
	})
	t.Run("awaiting finished", func(t *testing.T) {
		a, b := firstContact(t, aAnswered)
		pump(t, a, b)
		b.appInbox()
		var got [][]byte
		locked(a, func(m *Manager) { got = respSecrets(m.st.Awaiting[onlyID(t, m.st.Awaiting)].Resp) })
		pump(t, b, a) // the hs.fin
		checkWiped(t, "the finished handshake's record", got...)
	})
	t.Run("awaiting not restored", func(t *testing.T) {
		a, _ := firstContact(t, aAnswered)
		locked(a, func(m *Manager) {
			aw := m.st.Awaiting[onlyID(t, m.st.Awaiting)]
			got := respSecrets(aw.Resp)
			aw.Resp.EpochID = []byte{1} // a snapshot that does not restore
			m.awaiting = map[string]*handshake.Responder{}
			_ = m.restoreLive()
			checkWiped(t, "the awaiting record not restored", got...)
		})
	})
	t.Run("request activated", func(t *testing.T) {
		// a approves, then b's approval activates a's request.
		a, b := newVaultPair(t)
		_, link := a.linkFor(t, time.Hour)
		r, _ := b.request(t, "connection.invite.accept", `{"link":"`+link+`"}`)
		pump(t, b, a)
		pump(t, a, b)
		b.appInbox()
		pump(t, b, a)
		aPend := event(a.appInbox(), "connection.request.pending")
		a.request(t, "connection.approve", `{"pending_id":"`+bodyStr(t, aPend, "pending_id")+`"}`)
		pump(t, a, b)
		b.request(t, "connection.approve", `{"connection_id":"`+bodyStr(t, r, "connection_id")+`"}`)
		var got [][]byte
		locked(a, func(m *Manager) { got = epochSecrets(m.st.Requests[onlyID(t, m.st.Requests)].Epoch) })
		pump(t, b, a)
		if len(a.m.st.Requests) != 0 {
			t.Fatal("setup: the request was not activated")
		}
		checkWiped(t, "the activated request", got...)
	})
	t.Run("request dropped", func(t *testing.T) {
		a, _ := firstContact(t, aRequested)
		locked(a, func(m *Manager) {
			r := m.st.Requests[onlyID(t, m.st.Requests)]
			got := epochSecrets(r.Epoch)
			m.dropRequest(r, now(a))
			checkWiped(t, "dropRequest", got...)
		})
	})
	t.Run("request not restored", func(t *testing.T) {
		a, _ := firstContact(t, aRequested)
		locked(a, func(m *Manager) {
			r := m.st.Requests[onlyID(t, m.st.Requests)]
			got := epochSecrets(r.Epoch)
			r.Epoch.ID = []byte{1} // a snapshot that does not restore
			m.reqEpochs = map[string]*handshake.Epoch{}
			_ = m.restoreLive()
			checkWiped(t, "the request not restored", got...)
		})
	})
	t.Run("peer removed", func(t *testing.T) {
		a, _ := firstContact(t, connected)
		locked(a, func(m *Manager) {
			p := m.st.Connections[onlyID(t, m.st.Connections)]
			got := epochSecrets(*p.Sessions.Current)
			m.removePeer(p, "", now(a))
			checkWiped(t, "the removed peer's sessions", got...)
		})
	})
}

// A write replaces each live snapshot with a fresh one and wipes the one it
// replaces: the sessions, an outgoing and an awaiting handshake, a request.
func TestReplacedSnapshotsWiped(t *testing.T) {
	write := func(t *testing.T, d *devFixture) {
		t.Helper()
		locked(d, func(m *Manager) { m.dirty = true; m.flushThenDrain(context.Background()) })
	}
	t.Run("sessions", func(t *testing.T) {
		a, _ := firstContact(t, connected)
		var got [][]byte
		locked(a, func(m *Manager) {
			got = epochSecrets(*m.st.Connections[onlyID(t, m.st.Connections)].Sessions.Current)
		})
		write(t, a)
		checkWiped(t, "the replaced sessions", got...)
		locked(a, func(m *Manager) {
			intact(t, epochSecrets(*m.st.Connections[onlyID(t, m.st.Connections)].Sessions.Current)...)
		})
	})
	t.Run("outgoing", func(t *testing.T) {
		_, b := firstContact(t, bSentInit)
		var got [][]byte
		locked(b, func(m *Manager) { got = initSecrets(m.st.Outgoing[onlyID(t, m.st.Outgoing)].Init) })
		write(t, b)
		checkWiped(t, "the replaced outgoing snapshot", got...)
		locked(b, func(m *Manager) { intact(t, initSecrets(m.st.Outgoing[onlyID(t, m.st.Outgoing)].Init)...) })
	})
	t.Run("awaiting", func(t *testing.T) {
		a, _ := firstContact(t, aAnswered)
		var got [][]byte
		locked(a, func(m *Manager) { got = respSecrets(m.st.Awaiting[onlyID(t, m.st.Awaiting)].Resp) })
		write(t, a)
		checkWiped(t, "the replaced awaiting snapshot", got...)
		locked(a, func(m *Manager) { intact(t, respSecrets(m.st.Awaiting[onlyID(t, m.st.Awaiting)].Resp)...) })
	})
	t.Run("request", func(t *testing.T) {
		a, _ := firstContact(t, aRequested)
		var got [][]byte
		locked(a, func(m *Manager) { got = epochSecrets(m.st.Requests[onlyID(t, m.st.Requests)].Epoch) })
		write(t, a)
		checkWiped(t, "the replaced request snapshot", got...)
		locked(a, func(m *Manager) { intact(t, epochSecrets(m.st.Requests[onlyID(t, m.st.Requests)].Epoch)...) })
	})
}

// zeroize wipes every snapshot in the state: the sessions, the outgoing
// and awaiting handshakes and the requests.
func TestZeroizeWipesSnapshots(t *testing.T) {
	for _, c := range []struct {
		name  string
		stage contactStage
		at    func(d *devFixture) *devFixture // which vault, given (a, b)
		take  func(t *testing.T, m *Manager) [][]byte
	}{
		{"sessions", connected, nil, func(t *testing.T, m *Manager) [][]byte {
			return epochSecrets(*m.st.Connections[onlyID(t, m.st.Connections)].Sessions.Current)
		}},
		{"outgoing", bSentInit, func(b *devFixture) *devFixture { return b }, func(t *testing.T, m *Manager) [][]byte {
			return initSecrets(m.st.Outgoing[onlyID(t, m.st.Outgoing)].Init)
		}},
		{"awaiting", aAnswered, nil, func(t *testing.T, m *Manager) [][]byte {
			return respSecrets(m.st.Awaiting[onlyID(t, m.st.Awaiting)].Resp)
		}},
		{"request", aRequested, nil, func(t *testing.T, m *Manager) [][]byte {
			return epochSecrets(m.st.Requests[onlyID(t, m.st.Requests)].Epoch)
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			a, b := firstContact(t, c.stage)
			d := a
			if c.at != nil {
				d = c.at(b)
			}
			var got [][]byte
			locked(d, func(m *Manager) { got = c.take(t, m) })
			d.m.Crash()
			checkWiped(t, "zeroize", got...)
		})
	}
}

// An hs.init is discarded once handled: its inner plaintext and a
// transfer's app key and unlock secret are wiped; what the vault keeps of
// them (the new app's key, the unlock secret in memory) is its own copy.
func TestHandledInitDiscarded(t *testing.T) {
	d := newDevFixture(t)
	attestAs(d, androidBinding(sigVettID, "vettid"))
	inv := d.transferInvite(t)
	var pis []*handshake.PendingInit
	var inner, ak, us []byte
	defer func() { testPendingInitHook = nil }()
	testPendingInitHook = func(pi *handshake.PendingInit) {
		pis = append(pis, pi)
		inner, ak, us = pi.Inner().Body, pi.Init().APIKey, pi.Init().UnlockSecret
	}
	newNewcomer(t, 0x50).hsInitAttest(t, d.m, handshake.PurposeApp, inv.ID, "t0", testAttest)
	if len(pis) != 1 {
		t.Fatalf("%d hs.init handled", len(pis))
	}
	checkWiped(t, "the handled hs.init", inner, ak, us)
	d.m.mu.Lock()
	defer d.m.mu.Unlock()
	if len(d.m.transferSecret) == 0 || zeroed(d.m.transferSecret) {
		t.Fatal("the transfer's unlock secret was not kept")
	}
	aw := d.m.st.Awaiting[onlyID(t, d.m.st.Awaiting)]
	if aw.New == nil || len(aw.New.APIKey) == 0 || zeroed(aw.New.APIKey) {
		t.Fatal("the new app's key was not kept")
	}
}

// A rekey hs.init is discarded once handled too.
func TestHandledRekeyInitDiscarded(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	f.rekey(0)
	var inners [][]byte
	testPendingInitHook = func(pi *handshake.PendingInit) { inners = append(inners, pi.Inner().Body) }
	defer func() { testPendingInitHook = nil }()
	if f.deliver(0, 1, kHSInit) != 1 {
		t.Fatal("setup: no rekey hs.init")
	}
	if len(inners) != 1 {
		t.Fatalf("%d rekey hs.init handled", len(inners))
	}
	checkWiped(t, "the handled rekey hs.init", inners...)
}

// peekResp's result (an earlier key's answer, tried on a copy) has its
// hs.resp plaintext wiped once judged.
func TestPeekedRespWiped(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	f.rekey(0)
	if f.deliver(0, 1, kHSInit) != 1 {
		t.Fatal("setup: no rekey hs.init")
	}
	resp := f.rkTake(kHSResp, rkAfter)
	f.rkFollow()
	var inners [][]byte
	testRespResultHook = func(r *handshake.Result) { inners = append(inners, r.Inner.Body) }
	defer func() { testRespResultHook = nil }()
	f.process(0, resp)
	if len(inners) != 1 {
		t.Fatalf("%d hs.resp peeked", len(inners))
	}
	checkWiped(t, "the peeked hs.resp", inners...)
}

// An app hs.init sent in session mode (over a connection, as a rekey
// would be) is parsed for its links before its purpose is checked: the
// app key and unlock secret it decodes are wiped all the same.
func TestSessionInitSecretsWiped(t *testing.T) {
	a, b := firstContact(t, connected)
	n := newNewcomer(t, 0x50)
	locked(b, func(m *Manager) {
		ini, err := handshake.NewInitiator(handshake.InitiatorConfig{Purpose: handshake.PurposeApp, Ctx: "01JB2Z6V9K3M4N5P6Q7R8S9T0V",
			Identity: n.ik, StaticKEM: n.kem.Public(), Relay: n.addr, Token: "v4.public.VEVTVA",
			APIKey: testAppKeyDER(t, 0x51), UnlockSecret: bytes.Repeat([]byte{0x5a}, 32),
			ResponderIK: n.ik.Public().(ed25519.PublicKey), ResponderEK: n.kem.Public(), ResponderRelayKey: n.addr.PK,
			Policy: policyFor(KindApp), Now: m.now()})
		if err != nil {
			t.Fatal(err)
		}
		st, err := ini.Export()
		if err != nil {
			t.Fatal(err)
		}
		// Sealed in the connection's session, on b's standing token.
		m.sendTo(m.st.Connections[onlyID(t, m.st.Connections)], handshake.TypeInit, st.Body, m.now())
	})
	var secrets [][]byte
	drops := 0
	testParsedInitHook = func(b *handshake.Init) {
		drops++
		for _, s := range [][]byte{b.APIKey, b.UnlockSecret} {
			if s != nil {
				secrets = append(secrets, s)
			}
		}
	}
	defer func() { testParsedInitHook = nil }()
	pump(t, b, a)
	// Two parse it: the links' check (identity links) and the rekey's
	// precheck, which refuses its purpose. Each drops what it parsed. (The
	// two later parses run only for a rekey body, which can hold no
	// secrets.)
	if drops != 2 || len(secrets) != 4 {
		t.Fatalf("%d bodies dropped with %d secrets, want 2 with 4", drops, len(secrets))
	}
	if len(secrets) == 0 {
		var evs []string
		for _, e := range a.m.Audit() {
			evs = append(evs, e.Event)
		}
		t.Fatalf("the body was not parsed for its links; audit %v", evs)
	}
	checkWiped(t, "a session-mode hs.init's secrets", secrets...)
}
