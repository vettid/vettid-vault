package calls

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/featuretest"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/callswire"
	"github.com/vettid/vettid-vault/vms/callwire"
	"github.com/vettid/vettid-vault/vms/suite"
)

// fakeIssuer answers each request with count fresh credentials expiring at exp, or with err.
type fakeIssuer struct {
	mu     sync.Mutex
	counts []int
	exp    time.Time
	err    error
	n      int
	extra  int // credentials beyond count in each answer
}

func (f *fakeIssuer) Credentials(_ context.Context, count int) (*callswire.Answer, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.counts = append(f.counts, count)
	if f.err != nil {
		return nil, f.err
	}
	a := &callswire.Answer{STUN: []string{"stun:calls.example.org:3478"}, TURN: []string{"turn:calls.example.org:3478?transport=udp"}}
	for range count + f.extra {
		f.n++
		a.Credentials = append(a.Credentials, callswire.Credential{Username: "u" + strconv.Itoa(f.n), Credential: "c", Exp: f.exp})
	}
	return a, nil
}

func (f *fakeIssuer) set(exp time.Time, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.exp, f.err = exp, err
}

func (f *fakeIssuer) asked() []int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]int(nil), f.counts...)
}

func poolWith(is vault.CallsIssuer) *Pool {
	return &Pool{Issuer: func(*vault.Session) vault.CallsIssuer { return is }, Jitter: func() float64 { return 0 }}
}

// prime asks and waits for the request it may start.
func prime(p *Pool, now time.Time) {
	p.Prime(nil, now)
	p.mu.Lock()
	d := p.done
	p.mu.Unlock()
	if d != nil {
		<-d
	}
}

func turnOf(servers []callwire.ICEServer) (callwire.ICEServer, bool) {
	for _, s := range servers {
		if strings.HasPrefix(s.URLs[0], "turn:") {
			return s, true
		}
	}
	return callwire.ICEServer{}, false
}

// Without an issuer (no calls_url) every configuration has an empty list and exp = now + 6 h, as before C2.
func TestPoolWithoutIssuer(t *testing.T) {
	p := poolWith(nil)
	servers, exp, err := p.Servers(nil, "call-1", t0)
	if err != nil || len(servers) != 0 || !exp.Equal(t0.Add(ICETTL)) {
		t.Fatalf("%v %v %v", servers, exp, err)
	}
}

// §10.10: 4 credentials at unlock; a configuration has the STUN entry and one TURN entry with one credential, and
// the credential's exp; one call keeps its credential.
func TestPoolGivesOneCredentialPerCall(t *testing.T) {
	is := &fakeIssuer{exp: t0.Add(5 * time.Hour)} // not now + ICETTL, so the credential's exp is told apart
	p := poolWith(is)
	prime(p, t0)
	if got := is.asked(); len(got) != 1 || got[0] != PoolSize {
		t.Fatalf("asked %v at unlock", got)
	}
	servers, exp, _ := p.Servers(nil, "call-1", t0)
	tu, ok := turnOf(servers)
	if len(servers) != 2 || !ok || tu.Username != "u1" || !exp.Equal(is.exp) || servers[0].Username != "" {
		t.Fatalf("%+v exp %v", servers, exp)
	}
	again, _, _ := p.Servers(nil, "call-1", t0)
	if tu2, _ := turnOf(again); tu2.Username != "u1" {
		t.Fatal("a call's configuration made again took another credential")
	}
}

// A credential is retired once its call was placed or answered here; one that only went out with an unanswered
// offer is given again. A call that was never given one retires nothing.
func TestPoolRetire(t *testing.T) {
	is := &fakeIssuer{exp: t0.Add(6 * time.Hour)}
	p := poolWith(is)
	prime(p, t0)
	s1, _, _ := p.Servers(nil, "unanswered", t0)
	s2, _, _ := p.Servers(nil, "next", t0)
	if a, _ := turnOf(s1); a.Username != "u1" {
		t.Fatal(a.Username)
	}
	if b, _ := turnOf(s2); b.Username != "u1" {
		t.Fatal("an unanswered call's credential was not given again")
	}
	p.Retire("next")
	p.Retire("never-given")
	s3, _, _ := p.Servers(nil, "third", t0)
	if c, _ := turnOf(s3); c.Username != "u2" {
		t.Fatalf("after retiring u1: %s", c.Username)
	}
	if len(p.creds) != 3 {
		t.Fatalf("%d credentials left", len(p.creds))
	}
}

// Below 2 usable credentials the pool asks for as many as are missing; a credential whose exp is 2 h or less away
// is no longer given (a device never gets one in its last 2 hours).
func TestPoolRefillAndUsable(t *testing.T) {
	is := &fakeIssuer{exp: t0.Add(6 * time.Hour)}
	p := poolWith(is)
	prime(p, t0)
	for _, id := range []string{"a", "b", "c"} {
		_, _, _ = p.Servers(nil, id, t0)
		p.Retire(id)
	}
	prime(p, t0)
	if got := is.asked(); len(got) != 2 || got[1] != PoolSize-1 {
		t.Fatalf("refill asked %v", got)
	}
	// 4 h later every credential has exactly 2 h left: none is usable, and the pool asks for 4.
	is.set(t0.Add(10*time.Hour), nil)
	late := t0.Add(4 * time.Hour)
	servers, exp, _ := p.Servers(nil, "late", late)
	if _, ok := turnOf(servers); ok || !exp.Equal(late.Add(ICETTL)) {
		// The refill runs in the background: this configuration has STUN only.
		t.Fatalf("a credential in its last 2 h was given: %+v", servers)
	}
	prime(p, late)
	if got := is.asked(); got[len(got)-1] != PoolSize {
		t.Fatalf("asked %v", got)
	}
}

// The vault's limits: 4 requests in an hour, 24 in a day (an issuer that answers with no credentials leaves the
// pool short, so it asks at every chance).
func TestPoolLimits(t *testing.T) {
	is := &fakeIssuer{}
	p := poolWith(&emptyIssuer{is})
	for range 10 {
		prime(p, t0)
	}
	if n := len(is.asked()); n != RequestsPerHour {
		t.Fatalf("%d requests in an hour", n)
	}
	for h := range 20 { // all within the day of the first request
		for range 10 {
			prime(p, t0.Add(time.Duration(h+1)*time.Hour))
		}
	}
	if n := len(is.asked()); n != RequestsPerDay {
		t.Fatalf("%d requests in a day", n)
	}
	// A day after the first requests they no longer count.
	prime(p, t0.Add(24*time.Hour+time.Minute))
	if n := len(is.asked()); n != RequestsPerDay+1 {
		t.Fatalf("after a day: %d", n)
	}
}

type emptyIssuer struct{ *fakeIssuer }

func (e *emptyIssuer) Credentials(ctx context.Context, n int) (*callswire.Answer, error) {
	_, _ = e.fakeIssuer.Credentials(ctx, n)
	return &callswire.Answer{}, nil
}

// After a failed attempt the pool waits 1, 5 and 15 minutes (±20 %), then 30 minutes between attempts; the STUN
// URLs it last learned stay; a success ends the waits.
func TestPoolBackoff(t *testing.T) {
	is := &fakeIssuer{exp: t0.Add(6 * time.Hour), err: errors.New("unreachable")}
	p := poolWith(is)
	// Attempts at 0, 1, 6 and 21 minutes (the waits 1, 5, 15); the next wait (30) would allow 51, but the hour's 4
	// requests hold it to 60; then 30 minutes between attempts.
	for i, at := range []time.Duration{0, time.Minute, 6 * time.Minute, 21 * time.Minute, 60 * time.Minute, 90 * time.Minute} {
		n := len(is.asked())
		if at > 0 {
			prime(p, t0.Add(at-time.Second))
			if len(is.asked()) != n {
				t.Fatalf("attempt %d: asked before %v", i+1, at)
			}
		}
		prime(p, t0.Add(at))
		if len(is.asked()) != n+1 {
			t.Fatalf("attempt %d: not asked at %v", i+1, at)
		}
	}
	// Jitter stretches or shortens a wait by up to 20 %; a success ends the waits.
	j := poolWith(is)
	j.Jitter = func() float64 { return 0.2 }
	prime(j, t0)
	n := len(is.asked())
	prime(j, t0.Add(time.Minute+11*time.Second))
	if len(is.asked()) != n {
		t.Fatal("+20 % not waited")
	}
	is.set(t0.Add(6*time.Hour), nil)
	prime(j, t0.Add(time.Minute+12*time.Second))
	if len(j.creds) != PoolSize || !j.next.IsZero() || j.failures != 0 {
		t.Fatalf("a success: %d credentials, next %v, failures %d", len(j.creds), j.next, j.failures)
	}
}

// An issuer that cannot be reached leaves the STUN URLs last learned, and no TURN entry.
func TestPoolKeepsSTUNWhenUnreachable(t *testing.T) {
	is := &fakeIssuer{exp: t0.Add(6 * time.Hour)}
	p := poolWith(is)
	prime(p, t0)
	p.mu.Lock()
	p.creds = nil // used up
	p.mu.Unlock()
	is.set(t0.Add(6*time.Hour), errors.New("unreachable"))
	prime(p, t0.Add(time.Hour))
	servers, _, _ := p.Servers(nil, "x", t0.Add(time.Hour))
	if len(servers) != 1 || !strings.HasPrefix(servers[0].URLs[0], "stun:") || servers[0].Username != "" {
		t.Fatalf("unreachable issuer: %+v", servers)
	}
}

// An answer with more credentials than asked for fills the pool to 4 at most.
func TestPoolCap(t *testing.T) {
	is := &fakeIssuer{exp: t0.Add(6 * time.Hour), extra: 3}
	p := poolWith(is)
	prime(p, t0)
	if len(p.creds) != PoolSize {
		t.Fatalf("%d credentials", len(p.creds))
	}
}

// The calls feature gives the caller's devices a configuration with a credential at call.start and retires it
// (placed); the callee's devices get one with the offer, retired when this side answers.
func TestFeatureUsesThePool(t *testing.T) {
	is := &fakeIssuer{exp: t0.Add(6 * time.Hour)}
	p := poolWith(is)
	prime(p, t0)
	f := New(Options{ICE: p})
	h := featuretest.NewHost()
	h.AddConnection("c1")
	h.AddDevice("dev-app", "app")
	sk, _ := suite.GeneratePrivateKey()
	r := featuretest.Call(f, h, t0, "app", "call.start", startBody("c1", sk.Public().Bytes()))
	cfg, _ := r.Obj(t).Base64("ice_config", -1)
	if !strings.Contains(string(cfg), `"username":"u1"`) || !strings.Contains(string(cfg), "turn:calls.example.org") {
		t.Fatalf("config %s", cfg)
	}
	if len(p.creds) != PoolSize-1 {
		t.Fatalf("a placed call's credential was not retired: %d left", len(p.creds))
	}
}

// The callee's devices get a credential with the offer; it stays in use while the call only rings, and is retired
// when this side answers.
func TestFeatureRetiresTheAnsweredCallsCredential(t *testing.T) {
	is := &fakeIssuer{exp: t0.Add(6 * time.Hour)}
	p := poolWith(is)
	prime(p, t0)
	b := newSide("cA")
	b.f = New(Options{ICE: p})
	sk, _ := callwire.NewOfferKey()
	ek := sk.Public().Bytes()
	id := newCallID("cA")
	featuretest.CallExp(b.f, b.h, t0, t0.Add(OfferTTL), "connection:cA", "call.offer", peerOffer("cA", id, "audio", ek))
	if len(p.creds) != PoolSize {
		t.Fatalf("a ringing call's credential was retired: %d left", len(p.creds))
	}
	if u := p.given[id]; u != "u1" {
		t.Fatalf("offer went out with %q", u)
	}
	enc, _, _ := callwire.Answer(ek, id)
	if r := featuretest.Call(b.f, b.h, t0.Add(time.Second), "app", "call.answer", answerBody("dev-app", id, enc)); !r.OK() {
		t.Fatalf("answer: %s", r.Code)
	}
	if len(p.creds) != PoolSize-1 || p.creds[0].Username == "u1" {
		t.Fatalf("the answered call's credential was not retired: %+v", p.creds)
	}
}

// The feature primes the pool at the opening (UnlockObserver) and at each tick (TickObserver).
func TestFeaturePrimesAtUnlockAndTick(t *testing.T) {
	is := &fakeIssuer{exp: t0.Add(6 * time.Hour)}
	p := poolWith(is)
	f := New(Options{ICE: p})
	h := featuretest.NewHost()
	sess := func(at time.Time) *vault.Session {
		return vault.NewSession(context.Background(), h, vault.PeerInfo{}, at, nil)
	}
	wait := func() {
		p.mu.Lock()
		d := p.done
		p.mu.Unlock()
		if d != nil {
			<-d
		}
	}
	f.Unlocked(sess(t0))
	wait()
	if got := is.asked(); len(got) != 1 || got[0] != PoolSize {
		t.Fatalf("unlock asked %v", got)
	}
	p.mu.Lock()
	p.creds = nil
	p.mu.Unlock()
	f.Tick(sess(t0.Add(time.Minute)))
	wait()
	if got := is.asked(); len(got) != 2 {
		t.Fatalf("tick asked %v", got)
	}
}
