package calls

import (
	"context"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/featuretest"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/callwire"
)

// (C2, VAULT-MESSAGING §14.2 trigger 5) CallRinging says whether a call's
// wake may still go: an incoming call ringing before its offer's exp; not
// an outgoing one, one answered or ended, one past its exp, or one unknown.
func TestCallRinging(t *testing.T) {
	now := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	f := New(Options{})
	f.calls["in"] = &Call{ID: "in", Dir: DirIn, State: StateRinging, Exp: now.Add(30 * time.Second)}
	f.calls["out"] = &Call{ID: "out", Dir: DirOut, State: StateRinging, Exp: now.Add(30 * time.Second)}
	f.calls["active"] = &Call{ID: "active", Dir: DirIn, State: StateActive, Exp: now.Add(30 * time.Second)}
	f.calls["ended"] = &Call{ID: "ended", Dir: DirIn, State: StateEnded, Exp: now.Add(30 * time.Second)}
	f.calls["late"] = &Call{ID: "late", Dir: DirIn, State: StateRinging, Exp: now}
	for _, c := range f.calls {
		f.syncRinging(c)
	}
	// A call that rang and then ended no longer rings.
	f.calls["was"] = &Call{ID: "was", Dir: DirIn, State: StateRinging, Exp: now.Add(30 * time.Second)}
	f.syncRinging(f.calls["was"])
	f.notRinging("was")
	for id, want := range map[string]bool{"was": false, "in": true, "out": false, "active": false, "ended": false, "late": false, "nobody": false} {
		if got := f.CallRinging(id, now); got != want {
			t.Errorf("%s: %v", id, got)
		}
	}
}

// (C2) The ringing set follows the call state through the real handlers:
// an offer that rings is ringing; each way a ringing call stops makes it
// not ringing; an offer that rings no device (held, limited, busy) never
// is; an outgoing call never is; a Save and Load keeps a ringing call
// ringing. Asked at a time before the offer's exp, so that only the set
// decides.
func TestCallRingingFollowsTheHandlers(t *testing.T) {
	sk, _ := callwire.NewOfferKey()
	ek := sk.Public().Bytes()
	ask := t0.Add(time.Second)
	ring := func(t *testing.T, b *side, conn string, at time.Time) string {
		t.Helper()
		id := newCallID(conn)
		featuretest.CallExp(b.f, b.h, at, at.Add(OfferTTL), "connection:"+conn, "call.offer", peerOffer(conn, id, "audio", ek))
		return id
	}
	rings := func(t *testing.T, b *side, at time.Time) string {
		t.Helper()
		id := ring(t, b, "cA", at)
		if !b.f.CallRinging(id, ask) {
			t.Fatal("an offer that rings is not ringing")
		}
		return id
	}
	stops := map[string]func(b *side, id string){
		"declined on a device": func(b *side, id string) {
			featuretest.Call(b.f, b.h, ask, "app", "call.end", `{"call_id":"`+id+`","reason":"decline"}`)
		},
		"answered on a device": func(b *side, id string) {
			enc, _, _ := callwire.Answer(ek, id)
			if r := featuretest.Call(b.f, b.h, ask, "app", "call.answer", answerBody("dev-app", id, enc)); !r.OK() {
				t.Fatalf("answer: %s", r.Code)
			}
		},
		"ended by the caller": func(b *side, id string) {
			featuretest.Call(b.f, b.h, ask, "connection:cA", "call.end", `{"call_id":"`+id+`","reason":"hangup"}`)
		},
		"timed out": func(b *side, id string) {
			b.f.Tick(vault.NewSession(context.Background(), b.h, vault.PeerInfo{}, t0.Add(OfferTTL+time.Second), nil))
		},
		"the hold began": func(b *side, id string) {
			b.h.Hold = vault.OwnerCheckHeld
			b.f.OwnerHoldStarted(vault.NewSession(context.Background(), b.h, vault.PeerInfo{}, ask, nil))
		},
		"calls turned off": func(b *side, id string) {
			if r := featuretest.Call(b.f, b.h, ask, "app", "call.permission.set", `{"connection_id":"cA","allowed":false}`); !r.OK() {
				t.Fatal(r.Code)
			}
		},
	}
	for name, stop := range stops {
		t.Run(name, func(t *testing.T) {
			b := newSide("cA")
			id := rings(t, b, t0)
			stop(b, id)
			if c, _ := b.f.Get(id); c.State == StateRinging {
				t.Fatalf("still ringing in the record: %+v", c)
			}
			if b.f.CallRinging(id, ask) {
				t.Fatal("still in the ringing set")
			}
		})
	}
	t.Run("held offer", func(t *testing.T) {
		b := newSide("cA")
		b.h.Hold = vault.OwnerCheckHeld
		if id := ring(t, b, "cA", t0); b.f.CallRinging(id, ask) {
			t.Fatal("a held vault's offer rings")
		}
	})
	t.Run("limited offer", func(t *testing.T) {
		b := newSide("cA")
		for i := 0; i < LimitShort; i++ {
			missOne(t, b, t0.Add(time.Duration(i)*time.Minute))
		}
		at := t0.Add(time.Duration(LimitShort) * time.Minute)
		if id := ring(t, b, "cA", at); b.f.CallRinging(id, at.Add(time.Second)) {
			t.Fatal("a limited offer rings")
		}
	})
	t.Run("busy offer", func(t *testing.T) {
		b := newSide("cA")
		b.addConn("cC")
		first := rings(t, b, t0)
		if id := ring(t, b, "cC", t0); b.f.CallRinging(id, ask) {
			t.Fatal("a busy offer rings")
		}
		if !b.f.CallRinging(first, ask) {
			t.Fatal("the first call stopped ringing")
		}
	})
	t.Run("outgoing call answered by the peer", func(t *testing.T) {
		a := newSide("cB")
		id := newCallID("cB")
		if r := featuretest.Call(a.f, a.h, t0, "app", "call.start", startBodyID("cB", id, ek)); !r.OK() {
			t.Fatal(r.Code)
		}
		if a.f.CallRinging(id, ask) {
			t.Fatal("an outgoing call is in the ringing set")
		}
		enc, _, _ := callwire.Answer(ek, id)
		featuretest.Call(a.f, a.h, ask, "connection:cB", "call.answer", peerAnswer("cB", id, enc))
		if c, _ := a.f.Get(id); c.State != StateActive {
			t.Fatalf("not answered: %+v", c)
		}
		if a.f.CallRinging(id, ask) {
			t.Fatal("an answered outgoing call is in the ringing set")
		}
	})
	t.Run("saved and loaded", func(t *testing.T) {
		b := newSide("cA")
		id := rings(t, b, t0)
		data, err := b.f.Save()
		if err != nil {
			t.Fatal(err)
		}
		g := New(Options{})
		if err := g.Load(data); err != nil {
			t.Fatal(err)
		}
		if !g.CallRinging(id, ask) {
			t.Fatal("a ringing call does not ring after a Load")
		}
	})
}
