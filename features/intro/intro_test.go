package intro

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/featuretest"
	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
)

var t0 = time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)

// Connection ids as each vault has them on record.
const (
	bA = "01JB2Z6V9K3M4N5P6Q7R8S9AAA" // B's id for A
	bC = "01JB2Z6V9K3M4N5P6Q7R8S9CCC" // B's id for C
	aB = "01JB2Z6V9K3M4N5P6Q7R8S9BBA" // A's id for B
	cB = "01JB2Z6V9K3M4N5P6Q7R8S9BBC" // C's id for B
)

type side struct {
	f   *Feature
	h   *featuretest.Host
	now time.Time
}

func ik(b byte) ed25519.PublicKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{b}, 32)).Public().(ed25519.PublicKey)
}

// world returns the introducer B and the two parties A and C.
func world() (a, b, c *side) {
	mk := func() *side { return &side{f: New(), h: featuretest.NewHost(), now: t0} }
	a, b, c = mk(), mk(), mk()
	b.h.Conns[bA] = vault.PeerInfo{ID: bA, Kind: vault.KindConnection, State: vault.PeerActive, IK: ik(0xa)}
	b.h.Conns[bC] = vault.PeerInfo{ID: bC, Kind: vault.KindConnection, State: vault.PeerActive, IK: ik(0xc)}
	a.h.Conns[aB] = vault.PeerInfo{ID: aB, Kind: vault.KindConnection, State: vault.PeerActive, IK: ik(0xb)}
	c.h.Conns[cB] = vault.PeerInfo{ID: cB, Kind: vault.KindConnection, State: vault.PeerActive, IK: ik(0xb)}
	return
}

func (x *side) call(kind, typ, body string) featuretest.Result {
	x.now = x.now.Add(time.Millisecond)
	return featuretest.Call(x.f, x.h, x.now, kind, typ, body)
}

func (x *side) ok(t *testing.T, kind, typ, body string) strictjson.Object {
	t.Helper()
	r := x.call(kind, typ, body)
	if !r.OK() {
		t.Fatalf("%s %s: %s", typ, body, r.Code)
	}
	return r.Obj(t)
}

// deliver hands what from queued for connection `to` to dst, as if it
// arrived from dst's connection `as`.
func deliver(t *testing.T, from *side, to string, dst *side, as string) []featuretest.Sent {
	t.Helper()
	var got []featuretest.Sent
	sent := from.h.Sent
	from.h.Sent = nil
	for _, s := range sent {
		if s.To != to {
			from.h.Sent = append(from.h.Sent, s)
			continue
		}
		got = append(got, s)
		if r := dst.call("connection:"+as, s.Type, string(s.Body)); !r.OK() {
			t.Fatalf("deliver %s: %s", s.Type, r.Code)
		}
	}
	return got
}

func str(t *testing.T, raw []byte, k string) string {
	t.Helper()
	o, err := strictjson.ParseObject(raw)
	if err != nil {
		t.Fatal(err)
	}
	v, _ := o.String(k)
	return v
}

func lastSent(t *testing.T, h *featuretest.Host, typ string) featuretest.Sent {
	t.Helper()
	s := h.SentOfType(typ)
	if len(s) == 0 {
		t.Fatalf("no %s in %+v", typ, h.Sent)
	}
	return s[len(s)-1]
}

const createBody = `{"a":"` + bA + `","c":"` + bC + `","to_a":{"name":"Carol","note":"my sister"},"to_c":{"name":"Alice"}}`

// start makes B introduce A and C and delivers the offers.
func start(t *testing.T, a, b, c *side) string {
	t.Helper()
	o := b.ok(t, vault.KindApp, "intro.create", createBody)
	id, _ := o.String("intro_id")
	deliver(t, b, bA, a, aB)
	deliver(t, b, bC, c, cB)
	return id
}

func allSent(h *featuretest.Host) string {
	var sb strings.Builder
	for _, s := range h.Sent {
		sb.WriteString(s.Type)
		sb.Write(s.Body)
	}
	return sb.String()
}

// §10.15: who may send what.
func TestAuthorization(t *testing.T) {
	_, b, _ := world()
	specs := map[string]vault.TypeSpec{}
	for _, ts := range b.f.Types() {
		specs[ts.Type] = ts
		if ts.Allows(vault.KindAgent) {
			t.Errorf("%s allowed for agents", ts.Type)
		}
	}
	if !specs["intro.create"].DesktopApproval || !specs["intro.accept"].DesktopApproval || specs["intro.decline"].DesktopApproval {
		t.Fatal("desktop step-up flags")
	}
	for _, c := range []struct{ kind, typ string }{
		{"connection:" + bA, "intro.create"}, {"connection:" + bA, "intro.list"}, {"connection:" + bA, "intro.accept"},
		{"connection:" + bA, "intro.cancel"}, {vault.KindAgent, "intro.create"}, {vault.KindAgent, "intro.list"},
		{vault.KindApp, "intro.offer"}, {vault.KindApp, "intro.answer"}, {vault.KindDesktop, "intro.link"},
	} {
		if r := b.call(c.kind, c.typ, `{}`); r.Code != "forbidden" {
			t.Errorf("%s %s: %q", c.kind, c.typ, r.Code)
		}
	}
	// No type asks to be introduced or lists the member's connections.
	if r := b.call("connection:"+bA, "intro.request", `{}`); r.Code != "unsupported_type" {
		t.Fatalf("intro.request: %q", r.Code)
	}
}

// §10.15: both accept → A's invitation bound to C's ik → relayed to C →
// C accepts it once; nothing about C reaches A before that, and A never
// gets C's ik or the link.
func TestBothAccept(t *testing.T) {
	a, b, c := world()
	id := start(t, a, b, c)
	pa := lastSent(t, a.h, "intro.pending")
	if str(t, pa.Body, "connection_id") != aB || !strings.Contains(string(pa.Body), `"name":"Carol"`) ||
		!strings.Contains(string(pa.Body), `"note":"my sister"`) {
		t.Fatalf("A's pending: %s", pa.Body)
	}
	if pc := lastSent(t, c.h, "intro.pending"); !strings.Contains(string(pc.Body), `"name":"Alice"`) {
		t.Fatalf("C's pending: %s", pc.Body)
	}
	if !a.h.HasActivity("intro.request") || !a.h.HasActivity("intro.offered") {
		t.Fatal("feed or audit")
	}
	a.ok(t, vault.KindApp, "intro.accept", `{"intro_id":"`+id+`"}`)
	deliver(t, a, aB, b, bA)
	if ev := lastSent(t, b.h, "intro.event"); str(t, ev.Body, "event") != "accepted" || str(t, ev.Body, "connection_id") != bA {
		t.Fatalf("B's event: %s", ev.Body)
	}
	if len(b.h.SentOfType("intro.connect")) != 0 {
		t.Fatal("connect before both accepted")
	}
	c.ok(t, vault.KindDesktop, "intro.accept", `{"intro_id":"`+id+`"}`)
	deliver(t, c, cB, b, bC)
	conn := deliver(t, b, bA, a, aB)
	if len(conn) != 1 || conn[0].Type != "intro.connect" {
		t.Fatalf("connect: %+v", conn)
	}
	if len(a.h.IntroInvites) != 1 || !bytes.Equal(a.h.IntroInvites[0].ExpectIK, ik(0xc)) || a.h.IntroInvites[0].IntroBy != aB {
		t.Fatalf("A's invitation: %+v", a.h.IntroInvites)
	}
	link := a.h.IntroInvites[0].Link
	deliver(t, a, aB, b, bA) // intro.invite
	if m := b.f.MadeList()[0]; m.State != StateLinked {
		t.Fatalf("B's state %s", m.State)
	}
	got := deliver(t, b, bC, c, cB) // intro.link
	if len(got) != 1 || got[0].Type != "intro.link" || len(c.h.AcceptedLinks) != 1 || c.h.AcceptedLinks[0] != link {
		t.Fatalf("C's link: %+v %v", got, c.h.AcceptedLinks)
	}
	// A repeated link is not used twice.
	c.ok(t, "connection:"+cB, "intro.link", string(got[0].Body))
	if len(c.h.AcceptedLinks) != 1 {
		t.Fatal("link used twice")
	}
	for _, x := range []*side{a, c} {
		if ev := lastSent(t, x.h, "intro.event"); str(t, ev.Body, "event") != "connecting" {
			t.Fatalf("party event: %s", ev.Body)
		}
	}
	// A never learned C's key or the answer of C; C never got A's link
	// from anyone but B, and nothing else about A.
	ikC := base64.StdEncoding.EncodeToString(ik(0xc))
	if strings.Contains(allSent(a.h), ikC) || strings.Contains(allSent(c.h), base64.StdEncoding.EncodeToString(ik(0xa))) {
		t.Fatal("a party's key reached the other party's devices")
	}
	if !b.h.HasActivity("intro.connecting") || !a.h.HasActivity("intro.connecting") {
		t.Fatal("audit")
	}
	// State survives a flush.
	g := New()
	featuretest.RoundTrip(t, a.f, g)
	if len(g.ReceivedList()) != 1 {
		t.Fatal("lost in a flush")
	}
}

// §10.15: a decline closes it for both, without a reason; A gets nothing
// of C; no invitation is made.
func TestDecline(t *testing.T) {
	a, b, c := world()
	id := start(t, a, b, c)
	a.ok(t, vault.KindApp, "intro.accept", `{"intro_id":"`+id+`"}`)
	deliver(t, a, aB, b, bA)
	c.ok(t, vault.KindApp, "intro.decline", `{"intro_id":"`+id+`"}`)
	deliver(t, c, cB, b, bC)
	if ev := b.h.SentOfType("intro.event"); !strings.Contains(string(ev[len(ev)-2].Body), "declined") {
		t.Fatalf("B's events: %+v", ev)
	}
	toA := deliver(t, b, bA, a, aB)
	if len(toA) != 1 || toA[0].Type != "intro.closed" || string(toA[0].Body) != `{"intro_id":"`+id+`"}` {
		t.Fatalf("to A: %+v", toA)
	}
	if len(deliver(t, b, bC, c, cB)) != 0 {
		t.Fatal("the decliner was told again")
	}
	if len(a.h.IntroInvites) != 0 || len(b.h.SentOfType("intro.connect")) != 0 {
		t.Fatal("an invitation was made")
	}
	if ev := lastSent(t, a.h, "intro.event"); str(t, ev.Body, "event") != "closed" || strings.Contains(string(ev.Body), "decline") {
		t.Fatalf("A's event: %s", ev.Body)
	}
	if strings.Contains(allSent(a.h), base64.StdEncoding.EncodeToString(ik(0xc))) {
		t.Fatal("C's key reached A")
	}
	if r := a.call(vault.KindApp, "intro.accept", `{"intro_id":"`+id+`"}`); r.Code != "not_found" {
		t.Fatalf("accept after close: %q", r.Code)
	}
}

// §10.15: cancel, expiry, and the closing of an invitation already made.
func TestCancelAndExpiry(t *testing.T) {
	a, b, c := world()
	id := start(t, a, b, c)
	b.ok(t, vault.KindApp, "intro.cancel", `{"intro_id":"`+id+`"}`)
	if len(deliver(t, b, bA, a, aB)) != 1 || len(deliver(t, b, bC, c, cB)) != 1 {
		t.Fatal("parties not told")
	}
	if r := b.call(vault.KindApp, "intro.cancel", `{"intro_id":"`+id+`"}`); r.Code != "not_found" {
		t.Fatalf("cancel twice: %q", r.Code)
	}
	if a.f.ReceivedList()[0].State != StateClosed {
		t.Fatal("A's offer still open")
	}

	// Expiry on both sides (lazily, at the next message).
	a, b, c = world()
	start(t, a, b, c)
	b.now = b.now.Add(TTL + time.Minute)
	b.ok(t, vault.KindApp, "intro.list", `{}`)
	if b.f.MadeList()[0].State != StateClosed || len(b.h.SentOfType("intro.closed")) != 2 {
		t.Fatal("not expired")
	}
	a.now = a.now.Add(TTL + time.Minute)
	a.ok(t, vault.KindApp, "intro.list", `{}`)
	if a.f.ReceivedList()[0].State != StateClosed {
		t.Fatal("A's offer not expired")
	}

	// A closed introduction cancels A's invitation if not yet used.
	a, b, c = world()
	id = start(t, a, b, c)
	a.ok(t, vault.KindApp, "intro.accept", `{"intro_id":"`+id+`"}`)
	a.h.Sent = nil
	a.ok(t, "connection:"+aB, "intro.connect", `{"intro_id":"`+id+`","peer_ik":"`+base64.StdEncoding.EncodeToString(ik(0xc))+`"}`)
	a.f.d.Received[id].State = StateAccepted // as if the link were not out yet
	a.ok(t, "connection:"+aB, "intro.closed", `{"intro_id":"`+id+`"}`)
	if len(a.h.Cancelled) != 1 || a.h.Cancelled[0] != a.h.IntroInvites[0].ID {
		t.Fatalf("invitation not cancelled: %v", a.h.Cancelled)
	}
}

// §10.15 authority: only the right party for an intro_id; anything else
// is dropped and audited, and changes nothing.
func TestWrongParty(t *testing.T) {
	a, b, c := world()
	id := start(t, a, b, c)
	b.h.Conns["01JB2Z6V9K3M4N5P6Q7R8S9XXX"] = vault.PeerInfo{ID: "01JB2Z6V9K3M4N5P6Q7R8S9XXX", Kind: vault.KindConnection, State: vault.PeerActive, IK: ik(0xd)}
	b.h.Activities = nil
	// A stranger answers or posts an invitation for B's introduction.
	b.ok(t, "connection:01JB2Z6V9K3M4N5P6Q7R8S9XXX", "intro.answer", `{"intro_id":"`+id+`","accept":true}`)
	b.ok(t, "connection:01JB2Z6V9K3M4N5P6Q7R8S9XXX", "intro.invite", `{"intro_id":"`+id+`","link":"x"}`)
	// C posts an invitation (only A makes it).
	b.ok(t, "connection:"+bC, "intro.invite", `{"intro_id":"`+id+`","link":"x"}`)
	// An unknown id.
	b.ok(t, "connection:"+bA, "intro.answer", `{"intro_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V","accept":true}`)
	n := 0
	for _, x := range b.h.Activities {
		if x.Kind == "drop.intro" {
			n++
		}
	}
	if n != 4 || len(b.h.SentOfType("intro.link")) != 0 || b.f.MadeList()[0].Answers[bA] != "" {
		t.Fatalf("drops %d, sent %+v", n, b.h.Sent)
	}
	// A party: connect or link from someone other than the introducer, or
	// before the member accepted.
	a.h.Activities = nil
	a.h.Conns["01JB2Z6V9K3M4N5P6Q7R8S9YYY"] = vault.PeerInfo{ID: "01JB2Z6V9K3M4N5P6Q7R8S9YYY", Kind: vault.KindConnection, State: vault.PeerActive}
	pik := base64.StdEncoding.EncodeToString(ik(0xc))
	a.ok(t, "connection:01JB2Z6V9K3M4N5P6Q7R8S9YYY", "intro.connect", `{"intro_id":"`+id+`","peer_ik":"`+pik+`"}`)
	a.ok(t, "connection:"+aB, "intro.connect", `{"intro_id":"`+id+`","peer_ik":"`+pik+`"}`) // not accepted yet
	a.ok(t, "connection:"+aB, "intro.link", `{"intro_id":"`+id+`","link":"x"}`)
	if len(a.h.IntroInvites) != 0 || len(a.h.AcceptedLinks) != 0 || !a.h.HasActivity("drop.intro") {
		t.Fatal("acted for the wrong party or before acceptance")
	}
	// An offer reusing an id this vault made is refused.
	b.ok(t, "connection:"+bA, "intro.offer", `{"intro_id":"`+id+`","peer":{"name":"x"},"exp":"2026-10-04T12:00:00.000Z"}`)
	if len(b.f.ReceivedList()) != 0 {
		t.Fatal("own id accepted as an offer")
	}
}

// §10.15 limits and idempotency.
func TestLimitsAndIdempotency(t *testing.T) {
	a, b, c := world()
	id := start(t, a, b, c)
	if r := b.call(vault.KindApp, "intro.create", `{"a":"`+bC+`","c":"`+bA+`","to_a":{"name":"x"},"to_c":{"name":"y"}}`); r.Code != "exists" {
		t.Fatalf("second open introduction of the pair: %q", r.Code)
	}
	for name, body := range map[string]string{
		"same":       `{"a":"` + bA + `","c":"` + bA + `","to_a":{"name":"x"},"to_c":{"name":"y"}}`,
		"no name":    `{"a":"` + bA + `","c":"` + bC + `","to_a":{"name":""},"to_c":{"name":"y"}}`,
		"long name":  `{"a":"` + bA + `","c":"` + bC + `","to_a":{"name":"` + strings.Repeat("n", MaxName+1) + `"},"to_c":{"name":"y"}}`,
		"long note":  `{"a":"` + bA + `","c":"` + bC + `","to_a":{"name":"x","note":"` + strings.Repeat("n", MaxNote+1) + `"},"to_c":{"name":"y"}}`,
		"no to_c":    `{"a":"` + bA + `","c":"` + bC + `","to_a":{"name":"x"}}`,
		"not object": `[]`,
	} {
		if r := b.call(vault.KindApp, "intro.create", body); r.Code != "bad_request" {
			t.Errorf("%s: %q", name, r.Code)
		}
	}
	if r := b.call(vault.KindApp, "intro.create", `{"a":"`+bA+`","c":"nobody","to_a":{"name":"x"},"to_c":{"name":"y"}}`); r.Code != "not_found" {
		t.Fatalf("unknown connection: %q", r.Code)
	}
	// A repeated offer and a repeated answer change nothing.
	off := `{"intro_id":"` + id + `","peer":{"name":"Z"},"exp":"2026-10-05T12:00:00.000Z"}`
	a.ok(t, "connection:"+aB, "intro.offer", off)
	if a.f.ReceivedList()[0].Peer.Name != "Carol" {
		t.Fatal("repeated offer replaced the first")
	}
	a.ok(t, vault.KindApp, "intro.accept", `{"intro_id":"`+id+`"}`)
	ans := deliver(t, a, aB, b, bA)
	b.ok(t, "connection:"+bA, "intro.answer", `{"intro_id":"`+id+`","accept":false}`)
	if b.f.MadeList()[0].Answers[bA] != answerAccept || b.f.MadeList()[0].State != StateOffered {
		t.Fatal("a second answer counted")
	}
	_ = ans
	// Receiving limits: 4 open offers per introducer, 16 in all.
	x := New()
	h := featuretest.NewHost()
	h.Conns[aB] = vault.PeerInfo{ID: aB, Kind: vault.KindConnection, State: vault.PeerActive}
	for i := 0; i < MaxOffersPerIntroducer+1; i++ {
		oid := "01JB2Z6V9K3M4N5P6Q7R8S9T0" + string(rune('A'+i))
		featuretest.Call(x, h, t0, "connection:"+aB, "intro.offer", `{"intro_id":"`+oid+`","peer":{"name":"p"},"exp":"2026-10-05T12:00:00.000Z"}`)
	}
	if len(x.ReceivedList()) != MaxOffersPerIntroducer || !h.HasActivity("drop.intro_limit") {
		t.Fatalf("per-introducer limit: %d", len(x.ReceivedList()))
	}
	// Introducer limit: 16 open.
	bb := New()
	hb := featuretest.NewHost()
	for i := 0; i < 2*MaxOpen+2; i++ {
		id := "01JB2Z6V9K3M4N5P6Q7R8S9" + string(rune('A'+i/26)) + string(rune('A'+i%26)) + "Z"
		hb.Conns[id] = vault.PeerInfo{ID: id, Kind: vault.KindConnection, State: vault.PeerActive, IK: ik(1)}
	}
	ids := make([]string, 0, len(hb.Conns))
	for id := range hb.Conns {
		ids = append(ids, id)
	}
	var code string
	for i := 0; i+1 < len(ids) && code == ""; i += 2 {
		r := featuretest.Call(bb, hb, t0, vault.KindApp, "intro.create", `{"a":"`+ids[i]+`","c":"`+ids[i+1]+`","to_a":{"name":"x"},"to_c":{"name":"y"}}`)
		code = r.Code
	}
	if code != "limit" || len(bb.MadeList()) != MaxOpen {
		t.Fatalf("introducer limit: %q %d", code, len(bb.MadeList()))
	}
}

// §10.15: removing a connection closes what it takes part in.
func TestConnectionRemoved(t *testing.T) {
	a, b, c := world()
	start(t, a, b, c)
	b.h.Sent = nil
	b.f.ConnectionRemoved(vault.NewSession(context.TODO(), b.h, vault.PeerInfo{}, t0, nil), bA)
	cl := b.h.SentOfType("intro.closed")
	if len(cl) != 1 || cl[0].To != bC || b.f.MadeList()[0].State != StateClosed {
		t.Fatalf("closed: %+v", cl)
	}
	a.f.ConnectionRemoved(vault.NewSession(context.TODO(), a.h, vault.PeerInfo{}, t0, nil), aB)
	if len(a.f.ReceivedList()) != 0 {
		t.Fatal("offer kept after its introducer was removed")
	}
}

func TestBadPeerBodies(t *testing.T) {
	_, b, _ := world()
	for _, typ := range []string{"intro.offer", "intro.answer", "intro.connect", "intro.invite", "intro.link", "intro.closed"} {
		b.h.Activities = nil
		if r := b.call("connection:"+bA, typ, `{"intro_id":"bad"}`); !r.OK() {
			t.Fatalf("%s answered: %q", typ, r.Code)
		}
		if !b.h.HasActivity("drop.intro") || len(b.h.Sent) != 0 {
			t.Fatalf("%s: not dropped and audited", typ)
		}
	}
	for _, typ := range []string{"intro.accept", "intro.decline", "intro.cancel"} {
		if r := b.call(vault.KindApp, typ, `{"intro_id":1}`); r.Code != "bad_request" {
			t.Errorf("%s: %q", typ, r.Code)
		}
	}
}

func FuzzParseCreate(f *testing.F) {
	f.Add([]byte(createBody))
	f.Fuzz(func(t *testing.T, b []byte) {
		if c, err := ParseCreate(b); err == nil && (c.A == c.C || c.ToA.Name == "" || len(c.ToC.Note) > MaxNote) {
			t.Fatal("accepted a bad create")
		}
	})
}

func FuzzParseOffer(f *testing.F) {
	f.Add([]byte(`{"intro_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V","peer":{"name":"Carol","note":"n"},"exp":"2026-10-05T12:00:00.000Z"}`))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = ParseOffer(b) })
}

func FuzzParseAnswer(f *testing.F) {
	f.Add([]byte(`{"intro_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V","accept":true}`))
	f.Fuzz(func(t *testing.T, b []byte) { _, _, _ = ParseAnswer(b) })
}

func FuzzParseConnect(f *testing.F) {
	f.Add([]byte(`{"intro_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V","peer_ik":"` + base64.StdEncoding.EncodeToString(ik(1)) + `"}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if _, k, err := ParseConnect(b); err == nil && len(k) != ed25519.PublicKeySize {
			t.Fatal("bad key size")
		}
	})
}

func FuzzParseLink(f *testing.F) {
	f.Add([]byte(`{"intro_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V","link":"vettid://x"}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if _, l, err := ParseLink(b); err == nil && (l == "" || len(l) > MaxLink) {
			t.Fatal("bad link accepted")
		}
	})
}

func FuzzParseID(f *testing.F) {
	f.Add([]byte(`{"intro_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V"}`))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = ParseID(b) })
}

// FuzzPeerMessage feeds any body of any introduction type from a
// connection: never an answer, never a panic.
func FuzzPeerMessage(f *testing.F) {
	types := []string{"intro.offer", "intro.answer", "intro.connect", "intro.invite", "intro.link", "intro.closed"}
	f.Add(uint8(0), []byte(`{"intro_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V","peer":{"name":"x"},"exp":"2026-10-05T12:00:00.000Z"}`))
	f.Fuzz(func(t *testing.T, ti uint8, body []byte) {
		_, b, _ := world()
		if r := b.call("connection:"+bA, types[int(ti)%len(types)], string(body)); !r.OK() {
			t.Fatalf("answered %q", r.Code)
		}
	})
}
