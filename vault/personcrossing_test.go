package vault

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
)

// Crossing reconnects between two persons (VAULT-MESSAGING 0.74.0, §6.6
// "Between two persons"): the hs.init with the lower th1 wins, a verified
// hs.fin comes first, and each side completes at most one of the two.
//
// The tests drive the four messages one at a time (pumpOnly), so that the
// arrival orders really happen. Side 0 is L, the owner of the lower th1;
// side 1 is H.

type crossFx struct {
	t     *testing.T
	d     [2]*devFixture
	id    [2]string         // each side's connection id
	label map[string]string // jti -> "init" or "answer"
	owner map[string]int    // jti -> the side that issued it
}

func (c *crossFx) peer(s int) *Peer { return c.d[s].m.st.Connections[c.id[s]] }

// newCrossFx connects two vaults and has both start a reconnect, retrying
// until side 0's th1 is the lower one. aFirst says whether the inviter is L.
func newCrossFx(t *testing.T, inviterIsL bool) *crossFx {
	a, b := newVaultPair(t)
	_, link := a.linkFor(t, time.Hour)
	r, _ := b.request(t, "connection.invite.accept", `{"link":"`+link+`"}`)
	cid := bodyStr(t, r, "connection_id")
	pump(t, b, a)
	pump(t, a, b)
	b.appInbox()
	pump(t, b, a)
	aPend := event(a.appInbox(), "connection.request.pending")
	a.request(t, "connection.approve", `{"pending_id":"`+bodyStr(t, aPend, "pending_id")+`"}`)
	pump(t, a, b)
	b.request(t, "connection.approve", `{"connection_id":"`+cid+`"}`)
	pump(t, b, a)
	c := &crossFx{t: t, label: map[string]string{}, owner: map[string]int{}}
	if inviterIsL {
		c.d = [2]*devFixture{a, b}
	} else {
		c.d = [2]*devFixture{b, a}
	}
	for s, d := range c.d {
		for id, p := range d.m.st.Connections {
			c.id[s] = id
			if p.State != PeerActive {
				t.Fatal("not connected")
			}
		}
		d.appInbox()
	}
	for try := 0; ; try++ {
		if try > 200 {
			t.Fatal("could not get the wanted th1 order")
		}
		var ogs [2]*OutgoingHS
		for s, d := range c.d {
			d.m.mu.Lock()
			d.m.startReconnect(c.peer(s), d.m.now())
			for _, og := range d.m.st.Outgoing {
				if og.Purpose == handshake.PurposeReconnect {
					ogs[s] = og
				}
			}
			d.m.mu.Unlock()
			if ogs[s] == nil {
				t.Fatal("no reconnect started")
			}
		}
		if string(ogs[0].Th1) < string(ogs[1].Th1) {
			break
		}
		for s, d := range c.d {
			d.m.mu.Lock()
			d.m.abandonOutgoing(ogs[s].ID, d.m.now())
			d.m.mu.Unlock()
		}
	}
	for _, d := range c.d {
		d.m.mu.Lock()
		d.m.drainOutbox(context.Background()) // both hs.init are on the relay
		d.m.mu.Unlock()
	}
	c.snapshot()
	return c
}

// snapshot records the tokens carried by the reconnects open on each side:
// those of its own hs.init and those of its answers.
func (c *crossFx) snapshot() {
	for s, d := range c.d {
		d.m.mu.Lock()
		for _, og := range d.m.st.Outgoing {
			if og.Purpose == handshake.PurposeReconnect {
				for _, tk := range og.Issued {
					c.label[tk.JTI], c.owner[tk.JTI] = "init", s
				}
			}
		}
		for _, aw := range d.m.st.Awaiting {
			if aw.Purpose == handshake.PurposeReconnect {
				for _, tk := range aw.Issued {
					c.label[tk.JTI], c.owner[tk.JTI] = "answer", s
				}
			}
		}
		d.m.mu.Unlock()
	}
}

type msgKind int

const (
	kInit msgKind = iota
	kResp
	kFin
)

func (k msgKind) String() string { return [...]string{"init", "resp", "fin"}[k] }

func (c *crossFx) pred(to *devFixture, k msgKind) func(*envelope.Envelope) bool {
	return func(env *envelope.Envelope) bool {
		sealed := env.Mode() == envelope.ModeSealed
		static := sealed && to.m.lookupKEM(env.RecipientKid()) != nil
		switch k {
		case kInit:
			return static
		case kResp:
			return sealed && !static
		}
		return !sealed
	}
}

// step delivers what from has on the relay of the given kind to to. from
// first sends what it has queued.
func (c *crossFx) step(from, to int, k msgKind) int {
	c.t.Helper()
	f := c.d[from]
	f.m.mu.Lock()
	f.m.drainOutbox(context.Background())
	f.m.mu.Unlock()
	n := pumpOnly(c.t, f, c.d[to], c.pred(c.d[to], k))
	c.snapshot()
	return n
}

func (c *crossFx) restart(s int) {
	c.t.Helper()
	d := c.d[s]
	old := d.relay
	if err := d.m.Lock(context.Background()); err != nil {
		c.t.Fatal(err)
	}
	m2, _, err := d.unlock(testPIN, 0, 0)
	if err != nil {
		c.t.Fatal(err)
	}
	d.m = m2
	// The relay outlives the vault; the fixture's stub is made afresh at
	// every unlock, so what was on it is carried over.
	old.mu.Lock()
	d.relay.mu.Lock()
	d.relay.deposits, d.relay.revoked, d.relay.claims, d.relay.blobs = old.deposits, old.revoked, old.claims, old.blobs
	d.relay.mu.Unlock()
	old.mu.Unlock()
}

func (c *crossFx) revoked(jti string) bool {
	return c.d[c.owner[jti]].relayRevoked("jti", jti)
}

func tokenJTI(tok string, issuer *devFixture) string {
	cl, err := relayauth.ParseToken(tok, issuer.m.keys.relay.Public().(ed25519.PublicKey))
	if err != nil {
		return ""
	}
	return cl.Jti
}

// settle sends everything that is left and checks the end state: winner is
// the side whose hs.init made the epoch both ended on.
func (c *crossFx) settle(winner int) {
	c.t.Helper()
	for i := 0; i < 8; i++ {
		pump(c.t, c.d[0], c.d[1])
		pump(c.t, c.d[1], c.d[0])
		c.snapshot()
	}
	for _, d := range c.d {
		d.m.mu.Lock()
		d.m.drainOutbox(context.Background())
		d.m.mu.Unlock()
	}
	for s, d := range c.d {
		p := c.peer(s)
		if d.m.hasOutgoing(p.ID, handshake.PurposeReconnect) {
			c.t.Fatalf("side %d: a reconnect is still open", s)
		}
		if n := len(d.m.answeredReconnects(p)); n != 0 {
			c.t.Fatalf("side %d: %d answers still await hs.fin", s, n)
		}
		if p.State != PeerActive || p.Fork != nil || p.suspended() {
			c.t.Fatalf("side %d: state %v fork %v", s, p.State, p.Fork)
		}
	}
	if string(c.peer(0).LastEpochID) != string(c.peer(1).LastEpochID) {
		c.t.Fatal("the two sides ended on different epochs")
	}
	// The tokens of the winning hs.init and of its answer are valid, those
	// of the other pair are revoked (denylisted at the issuer's relay).
	for jti, lab := range c.label {
		wantValid := (lab == "init" && c.owner[jti] == winner) || (lab == "answer" && c.owner[jti] != winner)
		if wantValid == c.revoked(jti) {
			c.t.Fatalf("token %s (%s of side %d, winner %d): revoked=%v", jti, lab, c.owner[jti], winner, c.revoked(jti))
		}
	}
	// What each side holds for the other is a token of the winning pair and
	// is not revoked.
	for s := 0; s < 2; s++ {
		p := c.peer(s)
		for _, tok := range []string{p.Standing.Token, p.Reconnect.Token} {
			jti := tokenJTI(tok, c.d[1-s])
			if jti == "" || c.d[1-s].relayRevoked("jti", jti) {
				c.t.Fatalf("side %d holds a revoked or unreadable token", s)
			}
		}
	}
	// Messages are readable both ways.
	for from := 0; from < 2; from++ {
		to := 1 - from
		nAudit := len(c.d[to].m.Audit())
		c.d[from].m.mu.Lock()
		id := c.d[from].m.sendTo(c.peer(from), "x.test", []byte(`{}`), c.d[from].m.now())
		c.d[from].m.mu.Unlock()
		if id == "" {
			c.t.Fatal("nothing sent")
		}
		pump(c.t, c.d[from], c.d[to])
		if _, seen := c.d[to].m.st.SeenInner[c.id[to]+"|"+id]; !seen || len(c.d[to].m.Audit()) != nAudit {
			c.t.Fatalf("side %d did not read side %d (audit: %v)", to, from, c.d[to].m.Audit()[nAudit:])
		}
	}
}

type crossStep struct {
	from, to int
	kind     msgKind
}

var crossOrders = []struct {
	name   string
	steps  []crossStep
	winner int
}{
	{"each sees the other's hs.init, H's hs.resp first", []crossStep{{0, 1, kInit}, {1, 0, kInit}, {1, 0, kResp}, {0, 1, kResp}, {0, 1, kFin}}, 0},
	{"each sees the other's hs.init, L's hs.resp first", []crossStep{{0, 1, kInit}, {1, 0, kInit}, {0, 1, kResp}, {1, 0, kResp}, {0, 1, kFin}}, 0},
	{"H's hs.init first", []crossStep{{1, 0, kInit}, {0, 1, kInit}, {1, 0, kResp}, {0, 1, kResp}, {0, 1, kFin}}, 0},
	{"L completes before seeing H's hs.init", []crossStep{{0, 1, kInit}, {1, 0, kResp}, {1, 0, kInit}, {0, 1, kFin}}, 0},
	{"L completes, its hs.fin before H's hs.init", []crossStep{{0, 1, kInit}, {1, 0, kResp}, {0, 1, kFin}, {1, 0, kInit}}, 0},
	{"H completes before seeing L's hs.init", []crossStep{{1, 0, kInit}, {0, 1, kResp}, {0, 1, kInit}, {1, 0, kFin}}, 1},
	{"H completes, its hs.fin before L's hs.init", []crossStep{{1, 0, kInit}, {0, 1, kResp}, {1, 0, kFin}, {0, 1, kInit}}, 1},
}

// Every arrival order of the four messages, both assignments of the lower
// th1 to the inviter, and a lock and restart of either side after any step.
func TestPersonCrossingEveryOrder(t *testing.T) {
	for _, inviterL := range []bool{true, false} {
		for _, o := range crossOrders {
			for restartAfter := -1; restartAfter < len(o.steps); restartAfter++ {
				for rs := 0; rs < 2; rs++ {
					if restartAfter < 0 && rs > 0 {
						continue
					}
					name := fmt.Sprintf("inviterL=%v/%s/restart=%d,%d", inviterL, o.name, restartAfter, rs)
					t.Run(name, func(t *testing.T) {
						c := newCrossFx(t, inviterL)
						for i, st := range o.steps {
							c.step(st.from, st.to, st.kind)
							if i == restartAfter {
								c.restart(rs)
							}
						}
						c.settle(o.winner)
					})
				}
			}
		}
	}
}

// What a refused or dropped message looks like on the sides, and that the
// loser's hs.init is not answered and sends no hs.fin.
func TestPersonCrossingDecisions(t *testing.T) {
	t.Run("the higher th1 abandons its own when it answers", func(t *testing.T) {
		c := newCrossFx(t, true)
		c.step(0, 1, kInit) // H answers L's hs.init with its own open
		h := c.d[1]
		if h.m.hasOutgoing(c.id[1], handshake.PurposeReconnect) || len(h.m.answeredReconnects(c.peer(1))) != 1 {
			t.Fatal("H kept its own reconnect or did not answer")
		}
		// ... and starts no new one while the answer awaits hs.fin.
		h.m.mu.Lock()
		h.m.startReconnect(c.peer(1), h.m.now())
		h.m.mu.Unlock()
		if h.m.hasOutgoing(c.id[1], handshake.PurposeReconnect) {
			t.Fatal("a reconnect was started while an answer awaits hs.fin")
		}
		// L's own stays open: its th1 is the lower.
		c.d[0].relay.mu.Lock()
		c.d[0].relay.failWith = errors.New("relay down") // L's answer stays queued
		c.d[0].relay.mu.Unlock()
		c.step(1, 0, kInit)
		c.d[0].relay.mu.Lock()
		c.d[0].relay.failWith = nil
		c.d[0].relay.mu.Unlock()
		if !c.d[0].m.hasOutgoing(c.id[0], handshake.PurposeReconnect) || len(c.d[0].m.answeredReconnects(c.peer(0))) != 1 {
			t.Fatal("L did not keep its own and answer")
		}
		// H's hs.resp to L's hs.init completes L's own, which drops L's answer
		// before it was ever deposited.
		c.step(1, 0, kResp)
		if c.d[0].m.hasOutgoing(c.id[0], handshake.PurposeReconnect) || len(c.d[0].m.answeredReconnects(c.peer(0))) != 0 {
			t.Fatal("L did not complete its own and drop its answer")
		}
		if c.step(0, 1, kResp) != 0 {
			t.Fatal("L's dropped answer was deposited")
		}
		c.settle(0)
	})
	t.Run("a release-23 peer's hs.fin for a dropped answer is acked and dropped", func(t *testing.T) {
		// H plays release 23: it completes its own whatever the th1 (its th1
		// is set lower than any, so that it yields to nothing). L's own
		// completes first and L's answer is dropped, so the hs.fin that H
		// sends for it finds nothing: acked, dropped, no fork evidence.
		c := newCrossFx(t, true)
		hm := c.d[1].m
		hm.mu.Lock()
		for _, og := range hm.st.Outgoing {
			og.Th1 = make([]byte, 32)
		}
		hm.mu.Unlock()
		c.step(0, 1, kInit)
		c.step(1, 0, kInit)
		c.step(0, 1, kResp) // L's answer reaches H, which completes its own
		c.step(1, 0, kResp) // H's answer reaches L, which completes its own and drops its answer
		l := c.d[0]
		if l.m.hasOutgoing(c.id[0], handshake.PurposeReconnect) || len(l.m.answeredReconnects(c.peer(0))) != 0 {
			t.Fatal("L did not complete its own and drop its answer")
		}
		epoch := string(c.peer(0).LastEpochID)
		nAudit := len(l.m.Audit())
		if c.step(1, 0, kFin) == 0 { // H's hs.fin for L's answer
			t.Fatal("setup: H sent no hs.fin")
		}
		var unknown bool
		for _, a := range l.m.Audit()[nAudit:] {
			unknown = unknown || a.Event == "unknown_kid"
		}
		if !unknown || c.peer(0).Fork != nil || c.peer(0).State != PeerActive || string(c.peer(0).LastEpochID) != epoch {
			t.Fatalf("the hs.fin for the dropped answer was not dropped quietly (audit %v)", l.m.Audit()[nAudit:])
		}
		for jti, lab := range c.label {
			if lab == "answer" && c.owner[jti] == 0 && !c.revoked(jti) {
				t.Fatal("a token of the dropped answer is still valid")
			}
		}
	})
	t.Run("an hs.resp to an own reconnect abandoned for the peer's takes nothing", func(t *testing.T) {
		// The defence in handleResp: our own was left open although an
		// answer with a lower th1 exists (a record the answer path did not
		// see). The hs.resp is dropped, audited, before it takes tokens.
		c := newCrossFx(t, false)
		hm := c.d[1].m
		hm.mu.Lock()
		var hog *OutgoingHS
		for _, og := range hm.st.Outgoing {
			hog = og
		}
		real := hog.Th1
		hog.Th1 = make([]byte, 32) // lower than anything: kept when it answers
		hm.mu.Unlock()
		c.step(0, 1, kInit)
		if !hm.hasOutgoing(c.id[1], handshake.PurposeReconnect) {
			t.Fatal("setup: H abandoned its own")
		}
		hm.mu.Lock()
		hog.Th1 = real
		before := *c.peer(1)
		hm.mu.Unlock()
		// L answered? L has not seen H's hs.init: H's own gets its hs.resp
		// from L, which answers it.
		c.step(1, 0, kInit)
		c.step(0, 1, kResp)
		if hm.hasOutgoing(c.id[1], handshake.PurposeReconnect) {
			t.Fatal("H kept its own")
		}
		after := c.peer(1)
		if after.Standing != before.Standing || after.Reconnect != before.Reconnect || string(after.LastEpochID) != string(before.LastEpochID) {
			t.Fatal("the dropped hs.resp changed the connection")
		}
		if !c.d[1].audited("hs_resp_dropped") {
			t.Fatal("the dropped hs.resp was not audited")
		}
		// H's own hs.init tokens are revoked.
		for jti, lab := range c.label {
			if lab == "init" && c.owner[jti] == 1 && !c.revoked(jti) {
				t.Fatal("a token of the abandoned hs.init is still valid")
			}
		}
	})
}
