package calls

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/featuretest"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/callswire"
	"github.com/vettid/vettid-vault/vms/callwire"
	"github.com/vettid/vettid-vault/vms/strictjson"
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
	// hold, when set, keeps a request from being answered until it is
	// closed (a background refill that must not finish yet).
	hold chan struct{}
}

func (f *fakeIssuer) Credentials(_ context.Context, count int) (*callswire.Answer, error) {
	f.mu.Lock()
	hold := f.hold
	f.mu.Unlock()
	if hold != nil {
		<-hold
	}
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
	// The refill Servers starts must not answer before Servers has picked:
	// it runs in the background, and a fresh credential would be given.
	hold := make(chan struct{})
	is.mu.Lock()
	is.hold = hold
	is.mu.Unlock()
	late := t0.Add(4 * time.Hour)
	servers, exp, _ := p.Servers(nil, "late", late)
	close(hold)
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

// The feature primes the pool at the opening (OpenObserver) and at each tick (TickObserver).
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
	f.Opened(sess(t0))
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

// A start whose offer could not be sent placed nothing: its credential stays in use (the device never got the
// configuration). An answer that reached the vault retires its call's credential even when it could not be passed
// on, and so does one the vault refuses: the answering device has already allocated with it.
func TestFailedSendsAndTheCredential(t *testing.T) {
	is := &fakeIssuer{exp: t0.Add(6 * time.Hour)}
	p := poolWith(is)
	prime(p, t0)
	f := New(Options{ICE: p})
	h := featuretest.NewHost()
	h.AddConnection("c1")
	h.AddDevice("dev-app", "app")
	h.DownConns["c1"] = true
	sk, _ := suite.GeneratePrivateKey()
	if r := featuretest.Call(f, h, t0, "app", "call.start", startBody("c1", sk.Public().Bytes())); r.OK() {
		t.Fatal("a start to a connection that is down succeeded")
	}
	if len(p.creds) != PoolSize {
		t.Fatalf("a start that sent nothing retired a credential: %d left", len(p.creds))
	}
	b := newSide("cA")
	b.f = New(Options{ICE: p})
	ok, _ := callwire.NewOfferKey()
	ek := ok.Public().Bytes()
	id := newCallID("cA")
	featuretest.CallExp(b.f, b.h, t0, t0.Add(OfferTTL), "connection:cA", "call.offer", peerOffer("cA", id, "audio", ek))
	b.h.DownConns["cA"] = true
	enc, _, _ := callwire.Answer(ek, id)
	featuretest.Call(b.f, b.h, t0.Add(time.Second), "app", "call.answer", answerBody("dev-app", id, enc))
	if len(p.creds) != PoolSize-1 {
		t.Fatalf("an answer that was not delivered kept its credential: %d left", len(p.creds))
	}
	// An answer the vault refuses (the call is over by then) still retires the credential its offer carried.
	id2 := newCallID("cA")
	b.h.DownConns["cA"] = false
	featuretest.CallExp(b.f, b.h, t0.Add(2*time.Second), t0.Add(2*time.Second+OfferTTL), "connection:cA", "call.offer",
		peerOffer("cA", id2, "audio", ek))
	enc2, _, _ := callwire.Answer(ek, id2)
	if _, ok := p.given[id2]; !ok {
		t.Fatal("the second offer was given no credential")
	}
	featuretest.Call(b.f, b.h, t0.Add(2*time.Second+OfferTTL+time.Second), "app", "call.answer", answerBody("dev-app", id2, enc2))
	if len(p.creds) != PoolSize-2 {
		t.Fatalf("a refused answer kept its credential: %d left", len(p.creds))
	}
}

// The day's window: a request exactly 24 h old no longer counts.
func TestPoolDayWindowEdge(t *testing.T) {
	is := &fakeIssuer{}
	p := poolWith(&emptyIssuer{is})
	for h := range 6 {
		for range 10 {
			prime(p, t0.Add(time.Duration(h)*time.Hour))
		}
	}
	if n := len(is.asked()); n != RequestsPerDay {
		t.Fatalf("%d requests", n)
	}
	prime(p, t0.Add(24*time.Hour-time.Second))
	if n := len(is.asked()); n != RequestsPerDay {
		t.Fatal("asked before the first request was a day old")
	}
	prime(p, t0.Add(24*time.Hour))
	if n := len(is.asked()); n != RequestsPerDay+1 {
		t.Fatalf("at exactly a day: %d", n)
	}
}

// An answer with no TURN URLs gives no TURN entry, whatever credentials it carries.
func TestPoolWithoutTURNURLs(t *testing.T) {
	p := poolWith(&noTurnIssuer{})
	prime(p, t0)
	servers, exp, _ := p.Servers(nil, "x", t0)
	if len(servers) != 1 || servers[0].Username != "" || !exp.Equal(t0.Add(ICETTL)) {
		t.Fatalf("%+v %v", servers, exp)
	}
}

type noTurnIssuer struct{}

func (noTurnIssuer) Credentials(context.Context, int) (*callswire.Answer, error) {
	return &callswire.Answer{STUN: []string{"stun:h:3478"},
		Credentials: []callswire.Credential{{Username: "u", Credential: "c", Exp: t0.Add(6 * time.Hour)}}}, nil
}

// The calls whose credential is remembered are bounded (MaxGiven): the oldest is forgotten (its retire then does
// nothing), and a retire still finds the newest.
func TestPoolGivenIsBounded(t *testing.T) {
	is := &fakeIssuer{exp: t0.Add(6 * time.Hour)}
	p := poolWith(is)
	prime(p, t0)
	for i := range MaxGiven + 1 {
		_, _, _ = p.Servers(nil, "call-"+strconv.Itoa(i), t0)
	}
	if len(p.given) != MaxGiven || len(p.givenOrder) != MaxGiven {
		t.Fatalf("%d given, %d in order", len(p.given), len(p.givenOrder))
	}
	p.Retire("call-0")
	if len(p.creds) != PoolSize {
		t.Fatal("a forgotten call retired a credential")
	}
	p.Retire("call-" + strconv.Itoa(MaxGiven))
	if len(p.creds) != PoolSize-1 || len(p.givenOrder) != MaxGiven-1 {
		t.Fatalf("the newest call's retire: %d credentials, %d in order", len(p.creds), len(p.givenOrder))
	}
}

// The default jitter stays within ±20 %, and an injected one is held to it.
func TestJitterRange(t *testing.T) {
	w := 10 * time.Minute
	for range 1000 {
		if d := jittered(w, nil); d < 8*time.Minute || d > 12*time.Minute {
			t.Fatalf("%v", d)
		}
	}
	if d := jittered(w, func() float64 { return 0.9 }); d != 12*time.Minute {
		t.Fatalf("clamp: %v", d)
	}
}

// An answer is taken up to the count asked for, and a username already held (or repeated in the answer) is not
// taken twice.
func TestPoolTakesCountAndNoUsernameTwice(t *testing.T) {
	p := poolWith(&repeatIssuer{})
	p.creds = []callswire.Credential{{Username: "held", Credential: "c", Exp: t0.Add(6 * time.Hour)}}
	p.turn = []string{"turn:h:3478"} // the same servers as the answer's
	prime(p, t0)
	var names []string
	for _, c := range p.creds {
		names = append(names, c.Username)
	}
	if want := []string{"held", "a", "b", "c"}; !slices.Equal(names, want) {
		t.Fatalf("%v, want %v", names, want)
	}
}

type repeatIssuer struct{}

func (repeatIssuer) Credentials(_ context.Context, count int) (*callswire.Answer, error) {
	e := t0.Add(6 * time.Hour)
	a := &callswire.Answer{STUN: []string{"stun:h:3478"}, TURN: []string{"turn:h:3478"}}
	for _, u := range []string{"held", "a", "a", "b", "c", "d"} {
		a.Credentials = append(a.Credentials, callswire.Credential{Username: u, Credential: "c", Exp: e})
	}
	if count != 3 {
		panic(count)
	}
	return a, nil
}

// bigIssuer answers with URLs that pass the vault's checks but make a configuration too large to sign (each " or \
// is escaped to two bytes): 4 TURN URLs, and as many STUN URLs as stun says, all of 512 bytes.
type bigIssuer struct{ stun int }

func (b bigIssuer) Credentials(_ context.Context, count int) (*callswire.Answer, error) {
	url := func(scheme string) string { return `"` + scheme + strings.Repeat(`\\`, 512-len(scheme)) + `"` }
	var stun, turn []string
	for range b.stun {
		stun = append(stun, url("stun:"))
	}
	for range 4 {
		turn = append(turn, url("turn:"))
	}
	var creds []string
	for i := range count {
		creds = append(creds, `{"username":"u`+strconv.Itoa(i)+`","credential":"c","exp":`+strconv.FormatInt(t0.Add(5*time.Hour).Unix(), 10)+`}`)
	}
	body := `{"stun":[` + strings.Join(stun, ",") + `],"turn":[` + strings.Join(turn, ",") + `],"credentials":[` +
		strings.Join(creds, ",") + `]}`
	return callswire.ParseAnswer([]byte(body), t0)
}

// An issuer's answer that passes its checks but makes a configuration too large to sign does not break calls
// (CALLING-SERVICE §7.5): the configuration falls back to the STUN entry (4 escaped URLs always fit), and the
// credential is dropped.
func TestOversizedServersFallBack(t *testing.T) {
	for _, tc := range []struct {
		name string
		stun int
		want int // servers in the configuration
	}{{"4 STUN and 4 TURN URLs", 4, 1}} {
		p := poolWith(bigIssuer{stun: tc.stun})
		prime(p, t0)
		if len(p.creds) != PoolSize {
			t.Fatalf("%s: the answer was not taken: %d", tc.name, len(p.creds))
		}
		f := New(Options{ICE: p})
		h := featuretest.NewHost()
		h.AddConnection("c1")
		h.AddDevice("dev-app", "app")
		sk, _ := suite.GeneratePrivateKey()
		r := featuretest.Call(f, h, t0, "app", "call.start", startBody("c1", sk.Public().Bytes()))
		if !r.OK() {
			t.Fatalf("%s: call.start failed: %s", tc.name, r.Body)
		}
		raw, _ := r.Obj(t).Base64("ice_config", -1)
		c, err := callwire.ParseICEConfig(raw)
		if err != nil || len(c.Servers) != tc.want || !c.Exp.Equal(t0.Add(ICETTL)) {
			t.Fatalf("%s: %v %+v", tc.name, err, c)
		}
		for _, sv := range c.Servers {
			if sv.Username != "" {
				t.Fatalf("%s: a credential went out", tc.name)
			}
		}
		if len(p.creds) != PoolSize-1 {
			t.Fatalf("%s: the credential was not dropped: %d left", tc.name, len(p.creds))
		}
		// An incoming offer's configuration too: its credential is dropped although nobody answered.
		b := newSide("cA")
		b.f = New(Options{ICE: p})
		ok, _ := callwire.NewOfferKey()
		featuretest.CallExp(b.f, b.h, t0, t0.Add(OfferTTL), "connection:cA", "call.offer",
			peerOffer("cA", newCallID("cA"), "audio", ok.Public().Bytes()))
		if len(p.creds) != PoolSize-2 {
			t.Fatalf("%s: the offer's credential was not dropped: %d left", tc.name, len(p.creds))
		}
	}
}

// A call's configuration expires with its credential, not 6 h from now.
func TestConfigurationExpiresWithTheCredential(t *testing.T) {
	is := &fakeIssuer{exp: t0.Add(5*time.Hour + 17*time.Second)}
	p := poolWith(is)
	prime(p, t0)
	f := New(Options{ICE: p})
	h := featuretest.NewHost()
	h.AddConnection("c1")
	h.AddDevice("dev-app", "app")
	sk, _ := suite.GeneratePrivateKey()
	r := featuretest.Call(f, h, t0, "app", "call.start", startBody("c1", sk.Public().Bytes()))
	raw, _ := r.Obj(t).Base64("ice_config", -1)
	c, err := callwire.ParseICEConfig(raw)
	if err != nil || !c.Exp.Equal(is.exp) {
		t.Fatalf("%v %+v", err, c)
	}
}

// blockingIssuer holds each request until released.
type blockingIssuer struct {
	*fakeIssuer
	release chan struct{}
}

func (b *blockingIssuer) Credentials(ctx context.Context, n int) (*callswire.Answer, error) {
	select {
	case <-b.release:
	case <-ctx.Done():
		_, _ = b.fakeIssuer.Credentials(ctx, n)
		return nil, ctx.Err()
	}
	return b.fakeIssuer.Credentials(ctx, n)
}

// While a request is in flight no second one goes; Servers asks the issuer itself when the pool is short.
func TestPoolOneRequestInFlight(t *testing.T) {
	is := &fakeIssuer{exp: t0.Add(6 * time.Hour)}
	b := &blockingIssuer{fakeIssuer: is, release: make(chan struct{})}
	p := poolWith(b)
	// Servers primes: the request starts from it.
	if servers, _, _ := p.Servers(nil, "x", t0); len(servers) != 0 {
		t.Fatalf("%+v", servers)
	}
	p.mu.Lock()
	fromServers := p.inFlight
	p.mu.Unlock()
	if !fromServers {
		t.Fatal("Servers did not ask the issuer for a short pool")
	}
	p.Prime(nil, t0.Add(time.Second))
	p.Prime(nil, t0.Add(2*time.Second))
	p.mu.Lock()
	inFlight, sent, d := p.inFlight, len(p.sent), p.done
	p.mu.Unlock()
	if !inFlight || sent != 1 {
		t.Fatalf("in flight %v, %d requests", inFlight, sent)
	}
	close(b.release)
	<-d
	if got := is.asked(); len(got) != 1 || got[0] != PoolSize {
		t.Fatalf("asked %v", got)
	}
}

// At lock the pool forgets its credentials and URLs, a request in flight is cancelled and its answer not taken, and
// nothing more is asked for.
func TestPoolZeroizedAtLock(t *testing.T) {
	is := &fakeIssuer{exp: t0.Add(6 * time.Hour)}
	p := poolWith(is)
	prime(p, t0)
	_, _, _ = p.Servers(nil, "x", t0)
	f := New(Options{ICE: p})
	var z vault.Zeroizer = f
	z.Zeroize()
	if len(p.creds) != 0 || p.stun != nil || p.turn != nil || len(p.given) != 0 {
		t.Fatal("the pool kept something at lock")
	}
	prime(p, t0.Add(time.Hour))
	if len(is.asked()) != 1 {
		t.Fatal("a zeroized pool asked again")
	}
	if servers, _, _ := p.Servers(nil, "y", t0.Add(time.Hour)); len(servers) != 0 {
		t.Fatalf("%+v", servers)
	}

	// A request in flight at the lock: cancelled, and its answer not taken.
	b := &blockingIssuer{fakeIssuer: &fakeIssuer{exp: t0.Add(6 * time.Hour)}, release: make(chan struct{})}
	q := poolWith(b)
	q.Prime(nil, t0)
	q.mu.Lock()
	d := q.done
	q.mu.Unlock()
	q.Zeroize()
	select {
	case <-d:
	case <-time.After(2 * time.Second):
		t.Fatal("the request in flight was not cancelled at the lock")
	}
	if len(q.creds) != 0 {
		t.Fatal("an answer came in after the lock")
	}

	// An issuer that answers whatever the cancellation: its answer is not taken after the lock.
	st := &stubbornIssuer{fakeIssuer: &fakeIssuer{exp: t0.Add(6 * time.Hour)}, release: make(chan struct{})}
	r := poolWith(st)
	r.Prime(nil, t0)
	r.mu.Lock()
	d = r.done
	r.mu.Unlock()
	r.Zeroize()
	close(st.release)
	<-d
	if len(r.creds) != 0 || r.turn != nil {
		t.Fatal("an answer that came after the lock was taken")
	}
}

type stubbornIssuer struct {
	*fakeIssuer
	release chan struct{}
}

func (s *stubbornIssuer) Credentials(ctx context.Context, n int) (*callswire.Answer, error) {
	<-s.release
	return s.fakeIssuer.Credentials(ctx, n)
}

// New TURN URLs drop the credentials of the earlier answer: they never go out with other servers.
func TestPoolNewTURNURLsDropOldCredentials(t *testing.T) {
	is := &fakeIssuer{exp: t0.Add(6 * time.Hour)}
	p := poolWith(is)
	prime(p, t0)
	for _, id := range []string{"a", "b", "c"} {
		_, _, _ = p.Servers(nil, id, t0)
		p.Retire(id)
	}
	if len(p.creds) != 1 {
		t.Fatalf("%d", len(p.creds))
	}
	old := p.creds[0].Username
	p.Issuer = func(*vault.Session) vault.CallsIssuer { return movedIssuer{is} }
	p.issuerSeen = false
	prime(p, t0.Add(time.Minute))
	for _, c := range p.creds {
		if c.Username == old {
			t.Fatal("a credential of the earlier servers was kept")
		}
	}
	if !slices.Equal(p.turn, []string{"turn:moved.example.org:3478"}) {
		t.Fatal(p.turn)
	}
}

type movedIssuer struct{ *fakeIssuer }

func (m movedIssuer) Credentials(ctx context.Context, n int) (*callswire.Answer, error) {
	a, err := m.fakeIssuer.Credentials(ctx, n)
	if a != nil {
		a.TURN = []string{"turn:moved.example.org:3478"}
	}
	return a, err
}

// The pool prints none of what it holds.
func TestPoolPrintsNothing(t *testing.T) {
	p := poolWith(&fakeIssuer{exp: t0.Add(6 * time.Hour)})
	prime(p, t0)
	for _, f := range []string{"%v", "%+v", "%#v", "%s"} {
		if s := fmt.Sprintf(f, p); strings.Contains(s, "u1") || strings.Contains(s, "calls.example.org") {
			t.Fatalf("%s: %s", f, s)
		}
	}
}

// The backoff counts from the failure, not from the attempt's start: an attempt that took 7 s waits a minute from
// then.
func TestPoolBackoffFromTheFailure(t *testing.T) {
	is := &fakeIssuer{}
	is.set(time.Time{}, errors.New("down"))
	p := poolWith(is)
	p.Since = func(time.Time) time.Duration { return 7 * time.Second }
	prime(p, t0)
	prime(p, t0.Add(time.Minute+6*time.Second))
	if n := len(is.asked()); n != 1 {
		t.Fatalf("asked again before a minute after the failure: %d", n)
	}
	prime(p, t0.Add(time.Minute+7*time.Second))
	if n := len(is.asked()); n != 2 {
		t.Fatalf("not asked a minute after the failure: %d", n)
	}
}

// §10.10 (0.90.15): call.start's answer is sent with its TURN entry, and cached for a retransmission without it:
// the same call id and exp, STUN only, signed again with ik.
func TestStartCachedWithoutTheCredential(t *testing.T) {
	is := &fakeIssuer{exp: t0.Add(5 * time.Hour)}
	p := poolWith(is)
	prime(p, t0)
	f := New(Options{ICE: p})
	h := featuretest.NewHost()
	h.AddConnection("c1")
	h.AddDevice("dev-app", "app")
	sk, _ := suite.GeneratePrivateKey()
	r := featuretest.Call(f, h, t0, "app", "call.start", startBody("c1", sk.Public().Bytes()))
	if !r.OK() || r.Cached == nil {
		t.Fatalf("%s: cached %v", r.Code, r.Cached != nil)
	}
	id := str(t, r.Body, "call_id")
	sent := func(b []byte) *callwire.ICEConfig {
		o, err := strictjson.ParseObject(b)
		if err != nil {
			t.Fatal(err)
		}
		cfg, _ := o.Base64("ice_config", -1)
		sig, _ := o.Base64("ice_sig", -1)
		c, err := callwire.VerifyICE(h.IK, cfg, sig, id, t0)
		if err != nil {
			t.Fatalf("%v", err)
		}
		return c
	}
	first, cached := sent(r.Body), sent(r.Cached)
	if len(first.Servers) != 2 || first.Servers[1].Username == "" {
		t.Fatalf("the first answer lost its TURN entry: %+v", first.Servers)
	}
	if len(cached.Servers) != 1 || cached.Servers[0].Username != "" || !cached.Exp.Equal(first.Exp) || cached.CallID != first.CallID {
		t.Fatalf("cached %+v, first %+v", cached, first)
	}
	// The cached configuration's bytes (decoded) hold no username or credential.
	co, _ := strictjson.ParseObject(r.Cached)
	ccfg, _ := co.Base64("ice_config", -1)
	if strings.Contains(string(ccfg), "username") || strings.Contains(string(ccfg), "credential") || str(t, r.Cached, "exp") != str(t, r.Body, "exp") {
		t.Fatalf("cached %s", ccfg)
	}
}

// While the vault is held for the owner check the pool asks for nothing (a held vault makes no calls); once the
// hold ends it asks again.
func TestPoolSkipsWhileHeld(t *testing.T) {
	is := &fakeIssuer{exp: t0.Add(6 * time.Hour)}
	p := poolWith(is)
	h := featuretest.NewHost()
	h.Hold = vault.OwnerCheckHeld
	prime(p, t0) // a nil session knows no hold: the pool fills
	p.mu.Lock()
	p.creds = nil
	p.mu.Unlock()
	p.Prime(vault.NewSession(context.Background(), h, vault.PeerInfo{}, t0.Add(time.Hour), nil), t0.Add(time.Hour))
	p.mu.Lock()
	asked := p.inFlight || len(p.sent) != 1
	p.mu.Unlock()
	if asked {
		t.Fatal("a held vault's pool asked")
	}
	h.Hold = ""
	prime2 := vault.NewSession(context.Background(), h, vault.PeerInfo{}, t0.Add(time.Hour), nil)
	p.Prime(prime2, t0.Add(time.Hour))
	p.mu.Lock()
	d := p.done
	p.mu.Unlock()
	<-d
	if n := len(is.asked()); n != 2 {
		t.Fatalf("not asked once the hold ended: %d", n)
	}
}
