package connauth

import (
	"fmt"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/featuretest"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/peerwire"
)

// --- long-lived approval challenges (0.82.0, §10.4, §10.4.1) ---

// recvFrom delivers to b a challenge from connection conn with the given
// purpose (written raw, so an unknown one can be tried) and envelope exp.
func recvFrom(t *testing.T, b *side, conn, id, purpose string, at, exp time.Time) string {
	t.Helper()
	id = fmt.Sprintf("01HZ%022X", []byte(id)) // a ULID of the name; callers use the returned id
	wc, err := peerwire.NewConnAuthChallenge(id, "example.org")
	if err != nil {
		t.Fatal(err)
	}
	body := string(wc.Marshal())
	if purpose != "" {
		body = body[:len(body)-1] + `,"purpose":"` + purpose + `"}`
	}
	if r := featuretest.CallExp(b.f, b.h, at, exp, "connection:"+conn, "connection.authenticate.challenge", body); !r.OK() {
		t.Fatalf("challenge %s: %s", id, r.Code)
	}
	return id
}

func recv(t *testing.T, b *side, id, purpose string, at, exp time.Time) string {
	t.Helper()
	return recvFrom(t, b, "cA", id, purpose, at, exp)
}

// heldExp is the exp of the open challenge id (zero if not held).
func heldExp(b *side, id string) time.Time {
	b.f.mu.Lock()
	defer b.f.mu.Unlock()
	if c := b.f.d.In[id]; c != nil {
		return c.Exp
	}
	return time.Time{}
}

// serviceSide is a receiver whose connection cA is a service (§6.4).
func serviceSide() (*side, *side) {
	a, b := pair()
	b.h.Conns["cA"] = vault.PeerInfo{ID: "cA", Kind: vault.KindConnection, State: vault.PeerActive, IK: a.h.IK, PeerKind: "service"}
	return a, b
}

// The lifetime on receipt: exp clamped, never dropped; 24 h only for an
// approval from a service connection, 10 minutes for the rest.
func TestChallengeLifetime(t *testing.T) {
	h := time.Hour
	m10 := 10 * time.Minute
	for _, c := range []struct {
		name, purpose string
		service       bool
		exp, want     time.Duration
	}{
		{"service approval 23h kept", "approval", true, 23 * h, 23 * h},
		{"service approval 30h clamped to 24h", "approval", true, 30 * h, 24 * h},
		{"service approval 24h kept", "approval", true, 24 * h, 24 * h},
		{"service approval 5m kept", "approval", true, 5 * time.Minute, 5 * time.Minute},
		{"service signin 1h", "signin", true, h, m10},
		{"service no purpose 1h", "", true, h, m10},
		{"service unknown purpose 1h", "vote", true, h, m10},
		{"person approval 1h", "approval", false, h, m10},
		{"person approval 5m", "approval", false, 5 * time.Minute, 5 * time.Minute},
		{"person signin 1h", "signin", false, h, m10},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, b := pair()
			if c.service {
				_, b = serviceSide()
			}
			id := recv(t, b, "c1", c.purpose, t0, t0.Add(c.exp))
			if got := heldExp(b, id); !got.Equal(t0.Add(c.want)) {
				t.Fatalf("exp +%v, want +%v", heldExp(b, id).Sub(t0), c.want)
			}
		})
	}
	// A zero exp is capped from arrival, by the same rule.
	_, b := serviceSide()
	if got := heldExp(b, recv(t, b, "z", "approval", t0, time.Time{})); !got.Equal(t0.Add(peerwire.ApprovalChallengeMaxTTL)) {
		t.Fatalf("zero exp: +%v", got.Sub(t0))
	}
	_, b = serviceSide()
	if got := heldExp(b, recv(t, b, "z", "signin", t0, time.Time{})); !got.Equal(t0.Add(peerwire.ConnAuthChallengeTTL)) {
		t.Fatalf("zero exp signin: +%v", got.Sub(t0))
	}
}

// The ask, the pending event and pending.list carry the clamped exp; a
// long challenge is listed while unexpired and gone after.
func TestLongChallengeAskAndPendingList(t *testing.T) {
	_, b := serviceSide()
	b.h.AsksOn = true
	id := recv(t, b, "c1", "approval", t0, t0.Add(30*time.Hour))
	want := t0.Add(24 * time.Hour)
	if got := field(t, last(t, b.h, "connection.authenticate.pending").Body, "exp"); got != envelope.FormatTS(want) {
		t.Fatalf("pending exp %s", got)
	}
	for _, at := range []time.Time{t0.Add(time.Hour), t0.Add(23 * time.Hour)} {
		got := b.f.OpenAsks(at)
		if len(got) != 1 || got[0].ID != id || !got[0].Exp.Equal(want) {
			t.Fatalf("pending.list at +%v: %+v", at.Sub(t0), got)
		}
	}
	if got := b.f.OpenAsks(want); len(got) != 0 {
		t.Fatalf("listed at exp: %+v", got)
	}
}

// At most 2 long-lived challenges are held per connection; a third is
// clamped to 10 minutes, not dropped. A withdraw and an expiry free a place;
// a short one takes none; another connection counts apart.
func TestLongLivedSubCap(t *testing.T) {
	_, b := serviceSide()
	b.h.Conns["cZ"] = vault.PeerInfo{ID: "cZ", Kind: vault.KindConnection, State: vault.PeerActive, PeerKind: "service"}
	long := 20 * time.Hour
	short := peerwire.ConnAuthChallengeTTL
	at := t0
	recv(t, b, "s1", "approval", at, at.Add(5*time.Minute)) // short: takes no place
	l1 := recv(t, b, "l1", "approval", at, at.Add(long))
	l2 := recv(t, b, "l2", "approval", at, at.Add(long))
	if !heldExp(b, l1).Equal(at.Add(long)) || !heldExp(b, l2).Equal(at.Add(long)) {
		t.Fatal("the first two are not long")
	}
	// s1 expires at +5 min, which frees a pending place (MaxPendingIn 4).
	at = t0.Add(6 * time.Minute)
	l3 := recv(t, b, "l3", "approval", at, at.Add(long))
	if got := heldExp(b, l3); !got.Equal(at.Add(short)) {
		t.Fatalf("third long: +%v, want 10 min", got.Sub(at))
	}
	// A withdraw of l1 frees a long place.
	if r := withdraw(b, "cA", at, withdrawBody(l1)); !r.OK() {
		t.Fatal(r.Code)
	}
	at = t0.Add(7 * time.Minute)
	l4 := recv(t, b, "l4", "approval", at, at.Add(long))
	if got := heldExp(b, l4); !got.Equal(at.Add(long)) {
		t.Fatalf("after a withdraw: +%v", got.Sub(at))
	}
	// l2 and l4 are long again: the next is clamped.
	at = t0.Add(8 * time.Minute)
	l5 := recv(t, b, "l5", "approval", at, at.Add(long))
	if got := heldExp(b, l5); !got.Equal(at.Add(short)) {
		t.Fatalf("fifth: +%v, want 10 min", got.Sub(at))
	}
	// Another connection has its own two.
	if got := heldExp(b, recvFrom(t, b, "cZ", "z1", "approval", at, at.Add(long))); !got.Equal(at.Add(long)) {
		t.Fatalf("other connection: +%v", got.Sub(at))
	}
	// l2 expires (l4 is still held): a new one is long again.
	at = t0.Add(long).Add(time.Second)
	l6 := recv(t, b, "l6", "approval", at, at.Add(long)) // the receipt expires l2 first
	if !heldExp(b, l2).IsZero() || heldExp(b, l4).IsZero() {
		t.Fatal("expected l2 expired and l4 held")
	}
	if got := heldExp(b, l6); !got.Equal(at.Add(long)) {
		t.Fatalf("after an expiry: +%v", got.Sub(at))
	}
}

// The neutral answer of a suppressed long challenge is due within 20
// minutes of arrival, not near its exp.
func TestLongSuppressedAnswerStaysSoon(t *testing.T) {
	_, b := serviceSide()
	b.h.AsksOn = true
	b.h.AskRand = func(n int64) int64 { return n - 1 } // the longest delay
	b.h.Asks = map[string]*vault.AskState{"cA": {Muted: true}}
	recv(t, b, "c1", "approval", t0, t0.Add(24*time.Hour))
	held := b.h.Asks["cA"].Held
	if len(held) != 1 {
		t.Fatalf("held %+v", held)
	}
	if d := held[0].Due.Sub(t0); d < time.Minute || d > 20*time.Minute {
		t.Fatalf("due in %v", d)
	}
	if got := b.f.OpenAsks(t0); len(got) != 0 {
		t.Fatalf("a suppressed ask is listed: %+v", got)
	}
}

// A held vault (§3.6.3, the owner check past its deadline) takes a long
// approval challenge like any other; when the member passes the check
// more than 10 minutes later, it is still in pending.list and the member
// can approve it, with a signed response to the service.
func TestLongChallengeSurvivesHold(t *testing.T) {
	_, b := serviceSide()
	b.w.open = true
	b.h.Hold = vault.OwnerCheckHeld
	id := recv(t, b, "c1", "approval", t0, t0.Add(23*time.Hour))
	passed := t0.Add(45 * time.Minute) // well after 10 minutes
	b.h.Reset()
	b.h.OwnerCheckPassed(nil, true, "app", passed)
	if b.h.Hold != "" {
		t.Fatal("check not passed")
	}
	got := b.f.OpenAsks(passed)
	if len(got) != 1 || got[0].ID != id || got[0].Kind != vault.PendingAuthenticate || !got[0].Exp.Equal(t0.Add(23*time.Hour)) {
		t.Fatalf("pending.list after the check: %+v", got)
	}
	if r := featuretest.Call(b.f, b.h, passed, "app", "connection.authenticate.approve", `{"request_id":"`+id+`"}`); !r.OK() {
		t.Fatalf("approve: %s", r.Code)
	}
	resp := last(t, b.h, "connection.authenticate.response")
	if resp.To != "cA" || field(t, resp.Body, "request_id") != id || field(t, resp.Body, "purpose") != "approval" ||
		field(t, resp.Body, "sig") == "" {
		t.Fatalf("response: %+v %s", resp, resp.Body)
	}
	if got := b.f.OpenAsks(passed); len(got) != 0 {
		t.Fatalf("still listed after the answer: %+v", got)
	}
}

// The long mark survives a save and load, so the sub-cap holds across a
// restart.
func TestLongFlagPersists(t *testing.T) {
	_, b := serviceSide()
	recv(t, b, "l1", "approval", t0, t0.Add(20*time.Hour))
	raw, err := b.f.Save()
	if err != nil {
		t.Fatal(err)
	}
	g := New(nil)
	if err := g.Load(raw); err != nil {
		t.Fatal(err)
	}
	if g.countLong("cA") != 1 {
		t.Fatalf("long after load: %d", g.countLong("cA"))
	}
}
