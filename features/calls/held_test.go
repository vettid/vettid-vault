package calls

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/featuretest"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/callwire"
	"github.com/vettid/vettid-vault/vms/strictjson"
	"github.com/vettid/vettid-vault/vms/suite"
)

// 0.97.0 §10.10 (owner decision b, GC #19349): a call.start answer with a TURN entry is held in memory for its call
// (never in the stored outbox); its cached copy has no credential and carries withheld: true; the live answer
// never carries withheld.
func TestStartHeldForTheCallWithTURN(t *testing.T) {
	is := &fakeIssuer{exp: t0.Add(5 * time.Hour)}
	p := poolWith(is)
	prime(p, t0)
	f := New(Options{ICE: p})
	h := featuretest.NewHost()
	h.AddConnection("c1")
	h.AddDevice("dev-app", "app")
	sk, _ := suite.GeneratePrivateKey()
	r := featuretest.Call(f, h, t0, "app", "call.start", startBody("c1", sk.Public().Bytes()))
	if !r.OK() {
		t.Fatal(r.Code)
	}
	id := str(t, r.Body, "call_id")
	if r.HeldForCall != id || r.SentOnce {
		t.Fatalf("held for %q (sent once %v), want %q", r.HeldForCall, r.SentOnce, id)
	}
	if !strings.Contains(string(r.Body), `"username"`) && !strings.Contains(string(mustCfg(t, r.Body)), "username") {
		t.Fatal("the live answer has no TURN entry: the check proves nothing")
	}
	if o, _ := strictjson.ParseObject(r.Body); o["withheld"] != nil {
		t.Fatalf("the live answer carries withheld: %s", r.Body)
	}
	co, err := strictjson.ParseObject(r.Cached)
	if err != nil {
		t.Fatal(err)
	}
	if w, err := co.Bool("withheld"); err != nil || !w {
		t.Fatalf("cached copy without withheld: %s", r.Cached)
	}
	if c := mustCfg(t, r.Cached); strings.Contains(string(c), "username") || strings.Contains(string(c), "credential") {
		t.Fatalf("cached copy holds the credential: %s", c)
	}
}

// stunSource gives every configuration the STUN entry alone (a pool with no usable credential).
type stunSource struct{}

func (stunSource) Servers(*vault.Session, string, time.Time) ([]callwire.ICEServer, time.Time, error) {
	return []callwire.ICEServer{{URLs: []string{"stun:stun.example:3478"}}}, t0.Add(ICETTL), nil
}
func (stunSource) Retire(string)                   {}
func (stunSource) Drop(string)                     {}
func (stunSource) Prime(*vault.Session, time.Time) {}

// Without a TURN entry (no usable credential: no servers, or the STUN entry alone) the answer is not held and is
// cached as it is, without withheld; the offers are queued as before.
func TestStartWithoutTURNNotHeld(t *testing.T) {
	for name, src := range map[string]ICESource{"none": nil, "stun": stunSource{}} {
		f := New(Options{ICE: src})
		h := featuretest.NewHost()
		h.AddConnection("c1")
		h.AddDevice("dev-app", "app")
		sk, _ := suite.GeneratePrivateKey()
		r := featuretest.Call(f, h, t0, "app", "call.start", startBody("c1", sk.Public().Bytes()))
		if !r.OK() {
			t.Fatal(name, r.Code)
		}
		if name == "stun" && !strings.Contains(string(mustCfg(t, r.Body)), "stun:") {
			t.Fatal("no STUN entry: the check proves nothing")
		}
		if r.HeldForCall != "" || r.Cached != nil || strings.Contains(string(r.Body), "withheld") {
			t.Fatalf("%s: held %q, cached %s, body %s", name, r.HeldForCall, r.Cached, r.Body)
		}
		b := newSide("cA")
		b.f = New(Options{ICE: src})
		ok, _ := callwire.NewOfferKey()
		featuretest.CallExp(b.f, b.h, t0, t0.Add(OfferTTL), "connection:cA", "call.offer", peerOffer("cA", newCallID("cA"), "audio", ok.Public().Bytes()))
		for _, sent := range b.h.Sent {
			if sent.Type == "call.offer" && sent.Opt.Call != "" {
				t.Fatalf("%s: an offer without TURN is held", name)
			}
		}
	}
}

// The V→D offers are held for their call when they carry a TURN entry, and queued as before when they don't.
func TestOfferHeldForTheCallWithTURN(t *testing.T) {
	for _, turn := range []bool{true, false} {
		b := newSide("cA")
		if turn {
			is := &fakeIssuer{exp: t0.Add(6 * time.Hour)}
			p := poolWith(is)
			prime(p, t0)
			b.f = New(Options{ICE: p})
		}
		sk, _ := callwire.NewOfferKey()
		id := newCallID("cA")
		featuretest.CallExp(b.f, b.h, t0, t0.Add(OfferTTL), "connection:cA", "call.offer", peerOffer("cA", id, "audio", sk.Public().Bytes()))
		n := 0
		for _, s := range b.h.Sent {
			if s.Type != "call.offer" {
				continue
			}
			n++
			hasCred := strings.Contains(string(mustCfg(t, s.Body)), "username")
			if hasCred != turn {
				t.Fatalf("turn %v: the offer's configuration %s", turn, mustCfg(t, s.Body))
			}
			if want := map[bool]string{true: id, false: ""}[turn]; s.Opt.Call != want || !s.Opt.Exp.Equal(t0.Add(OfferTTL)) {
				t.Fatalf("turn %v: held for %q (exp %v)", turn, s.Opt.Call, s.Opt.Exp)
			}
		}
		if n != 1 {
			t.Fatalf("turn %v: %d offers", turn, n)
		}
	}
}

// CallHeld (vault.CallKeeper): an outgoing call's answer while the call lasts, an offer while it rings and its exp
// has not passed; nothing for an ended or unknown call.
func TestCallHeldWhileTheCallLasts(t *testing.T) {
	b := newSide("cA")
	sk, _ := callwire.NewOfferKey()
	ek := sk.Public().Bytes()
	id := newCallID("cA")
	featuretest.CallExp(b.f, b.h, t0, t0.Add(OfferTTL), "connection:cA", "call.offer", peerOffer("cA", id, "audio", ek))
	at := t0.Add(time.Second)
	if !b.f.CallHeld(id, true, at) || !b.f.CallHeld(id, false, at) {
		t.Fatal("a ringing call is not held")
	}
	if b.f.CallHeld(id, true, t0.Add(OfferTTL)) || b.f.CallHeld(id, false, t0.Add(OfferTTL)) {
		t.Fatal("held past the offer's exp unanswered")
	}
	enc, _, _ := callwire.Answer(ek, id)
	if r := featuretest.Call(b.f, b.h, at, "app", "call.answer", answerBody("dev-app", id, enc)); !r.OK() {
		t.Fatalf("answer: %s", r.Code)
	}
	later := t0.Add(OfferTTL + time.Minute)
	if b.f.CallHeld(id, true, at) || !b.f.CallHeld(id, false, later) {
		t.Fatalf("answered: offer %v, answer %v", b.f.CallHeld(id, true, at), b.f.CallHeld(id, false, later))
	}
	featuretest.Call(b.f, b.h, later, "app", "call.end", `{"call_id":"`+id+`","reason":"hangup"}`)
	if b.f.CallHeld(id, false, later) || b.f.CallHeld(id, true, later) {
		t.Fatal("an ended call is held")
	}
	if b.f.CallHeld(newCallID("cA"), false, at) {
		t.Fatal("an unknown call is held")
	}
}

// mustCfg is the decoded ice_config of an answer or offer body.
func mustCfg(t *testing.T, body []byte) []byte {
	t.Helper()
	o, err := strictjson.ParseObject(body)
	if err != nil {
		t.Fatal(err)
	}
	c, err := o.Base64("ice_config", -1)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// The configuration with the credential, and the offer's bytes, are wiped once used (in start and in offer); the
// copy without the credential needn't be.
func TestStartAndOfferWipeTheCredential(t *testing.T) {
	is := &fakeIssuer{exp: t0.Add(6 * time.Hour)}
	p := poolWith(is)
	prime(p, t0)
	f := New(Options{ICE: p})
	h := featuretest.NewHost()
	h.AddConnection("c1")
	h.AddDevice("dev-app", "app")
	sk, _ := suite.GeneratePrivateKey()
	if r := featuretest.Call(f, h, t0, "app", "call.start", startBody("c1", sk.Public().Bytes())); !r.OK() || r.HeldForCall == "" {
		t.Fatalf("%s: not held, the check proves nothing", r.Code)
	}
	wiped := func(what string, bs [][]byte) {
		t.Helper()
		zero := 0
		for _, b := range bs {
			if bytes.Contains(b, []byte(`"credential"`)) || bytes.Contains(b, []byte(`"username"`)) {
				t.Fatalf("%s: a configuration with the credential was not wiped: %s", what, b)
			}
			if len(b) > 0 && bytes.Equal(b, make([]byte, len(b))) {
				zero++
			}
		}
		if zero == 0 {
			t.Fatalf("%s: nothing wiped: the check proves nothing", what)
		}
	}
	wiped("start", h.Signed)

	b := newSide("cA")
	b.f = New(Options{ICE: p})
	ok, _ := callwire.NewOfferKey()
	featuretest.CallExp(b.f, b.h, t0, t0.Add(OfferTTL), "connection:cA", "call.offer", peerOffer("cA", newCallID("cA"), "audio", ok.Public().Bytes()))
	wiped("offer", b.h.Signed)
	for _, s := range b.h.Sent {
		if s.Type == "call.offer" && !bytes.Equal(s.Given, make([]byte, len(s.Given))) {
			t.Fatal("the offer's bytes were not wiped")
		}
	}
}
