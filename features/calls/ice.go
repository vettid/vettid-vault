package calls

import (
	"context"
	"math/rand/v2"
	"slices"
	"sync"
	"time"

	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/callswire"
	"github.com/vettid/vettid-vault/vms/callwire"
)

// ICESource gives each call's ICE configuration its servers (VAULT-MESSAGING §10.10 "Servers and credentials").
// *Pool is the release's; tests may supply another.
type ICESource interface {
	// Servers returns the servers for callID's configuration and the configuration's exp. It never waits for
	// the issuer (§10.10 "Never waiting, almost": the wait is a MAY, and a handler holds the vault's lock).
	Servers(s *vault.Session, callID string, now time.Time) ([]callwire.ICEServer, time.Time, error)
	// Retire takes the credential callID was given out of use: the call was placed (call.start succeeded), or any
	// device's call.answer for it reached the vault (delivered onward or not: that device has allocated with it).
	// A credential that only went out with offers nobody answered stays in use.
	Retire(callID string)
	// Drop takes the credential callID was given out of use because the configuration it went into could not be
	// made (it would have been too large to sign): it is not offered again.
	Drop(callID string)
	// Prime asks the issuer for credentials when the pool is short and the limits allow: at unlock, at each
	// tick, and before a configuration is made.
	Prime(s *vault.Session, now time.Time)
}

// The pool's numbers (§10.10).
const (
	// PoolSize is the most credentials the vault keeps; it asks for 4 at unlock.
	PoolSize = 4
	// PoolLow: below this many usable credentials, the vault asks for as many as are missing.
	PoolLow = 2
	// UsableFor: a credential is usable while its exp is more than this away (a device never gets one in its
	// last 2 hours).
	UsableFor = 2 * time.Hour
	// RequestsPerHour and RequestsPerDay are the vault's own limits, in memory, reset at unlock.
	RequestsPerHour = 4
	RequestsPerDay  = 24
	// RequestTime bounds each attempt, in its own context, from the vault process's side: the 10 s of §10.10, as the
	// supervisor's own bound.
	RequestTime = 10 * time.Second
	// MaxGiven bounds the calls whose credential the pool remembers (to retire it when the call is placed or
	// answered); an older call's credential simply stays in use.
	MaxGiven = 16
)

// backoff is the wait after the nth failed attempt in a row (each ±20 %), then 30 minutes between attempts (not
// jittered: §10.10 jitters the first three only).
var backoff = []time.Duration{time.Minute, 5 * time.Minute, 15 * time.Minute}

const backoffAfter = 30 * time.Minute

// Pool is the vault's TURN credentials from the calling service's issuer (§10.10 "The pool"): up to PoolSize in
// memory only, never in the state or a flush, gone with the feature at lock. A feature value lives for one
// opening of the vault, and so does its pool.
type Pool struct {
	// Issuer returns the issuer for a session (default: the session's, vault.Options.Calls); nil: none, and
	// every configuration's server list is empty.
	Issuer func(*vault.Session) vault.CallsIssuer
	// Jitter returns a factor in [-0.2, 0.2] for a wait (default: random).
	Jitter func() float64
	// Since is how long has passed since a time of the monotonic clock (default: time.Since; tests).
	Since func(time.Time) time.Duration

	mu         sync.Mutex
	issuer     vault.CallsIssuer
	issuerSeen bool
	stun, turn []string
	creds      []callswire.Credential
	given      map[string]string // call id → the username it was given
	givenOrder []string
	sent       []time.Time // this opening's requests (within the last day)
	failures   int         // failed attempts in a row
	next       time.Time   // no request before
	inFlight   bool
	cancel     context.CancelFunc // the request in flight's
	done       chan struct{}      // closed when the request in flight ends (tests)
	closed     bool               // zeroized at lock: nothing is asked for or taken any more
}

// String keeps the pool's credentials out of logs and errors.
func (p *Pool) String() string { return "calls.Pool" }

// GoString is String, for %#v.
func (p *Pool) GoString() string { return p.String() }

// Zeroize forgets everything the pool holds and closes it (the vault locks): the credentials, the URLs and the
// calls given them; a request in flight is cancelled, and its answer, if it still comes, is not taken.
func (p *Pool) Zeroize() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	if p.cancel != nil {
		p.cancel()
	}
	clear(p.creds)
	p.creds, p.stun, p.turn, p.given, p.givenOrder = nil, nil, nil, nil, nil
}

func (p *Pool) issuerFor(s *vault.Session) vault.CallsIssuer {
	if !p.issuerSeen {
		p.issuerSeen = true
		if p.Issuer != nil {
			p.issuer = p.Issuer(s)
		} else if s != nil {
			p.issuer = s.CallsIssuer()
		}
	}
	return p.issuer
}

// usable drops the credentials whose exp is UsableFor or less away; under mu.
func (p *Pool) usable(now time.Time) {
	p.creds = slices.DeleteFunc(p.creds, func(c callswire.Credential) bool { return c.Exp.Sub(now) <= UsableFor })
}

// allowed reports whether a request may go now (the backoff and the hour's and day's limits); under mu.
func (p *Pool) allowed(now time.Time) bool {
	if now.Before(p.next) {
		return false
	}
	p.sent = slices.DeleteFunc(p.sent, func(t time.Time) bool { return now.Sub(t) >= 24*time.Hour })
	hour := 0
	for _, t := range p.sent {
		if now.Sub(t) < time.Hour {
			hour++
		}
	}
	return hour < RequestsPerHour && len(p.sent) < RequestsPerDay
}

// Prime implements ICESource.
func (p *Pool) Prime(s *vault.Session, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	// While the vault is held for the owner check it may skip (§3.6.3): a held vault makes no calls.
	if p.closed || p.inFlight || (s != nil && s.OwnerHeld()) {
		return
	}
	is := p.issuerFor(s)
	if is == nil {
		return
	}
	p.usable(now)
	if len(p.creds) >= PoolLow || !p.allowed(now) {
		return
	}
	p.inFlight = true
	p.done = make(chan struct{})
	p.sent = append(p.sent, now)
	ctx, cancel := context.WithTimeout(context.Background(), RequestTime)
	p.cancel = cancel
	go p.fetch(ctx, cancel, is, PoolSize-len(p.creds), now, p.done)
}

// fetch makes one attempt and takes its answer: the URLs, and the credentials up to PoolSize. A failure is not
// audited and creates no feed item; it only sets the wait before the next attempt.
func (p *Pool) fetch(ctx context.Context, cancel context.CancelFunc, is vault.CallsIssuer, count int, at time.Time,
	done chan struct{}) {
	defer close(done)
	defer cancel()
	start := time.Now()
	a, err := is.Credentials(ctx, count)
	// The time of the failure on the vault's clock: the attempt's start plus what it took (monotonic, in whole
	// seconds).
	since := time.Since
	if p.Since != nil {
		since = p.Since
	}
	failedAt := at.Add(since(start).Truncate(time.Second))
	p.mu.Lock()
	defer p.mu.Unlock()
	p.inFlight, p.cancel = false, nil
	if p.closed {
		return // locked meanwhile: nothing is kept
	}
	if err != nil {
		w := backoffAfter
		if p.failures < len(backoff) {
			w = jittered(backoff[p.failures], p.Jitter)
		}
		p.failures++
		p.next = failedAt.Add(w) // counted from the failure, not the attempt's start
		return
	}
	p.failures, p.next = 0, time.Time{}
	// New TURN URLs: the credentials of the earlier answer are for the earlier servers, and never go out with
	// these.
	if !slices.Equal(p.turn, a.TURN) {
		clear(p.creds)
		p.creds = nil
	}
	// The STUN URLs last learned stay when the issuer cannot be reached; an answer replaces them.
	p.stun, p.turn = a.STUN, a.TURN
	// At most the count asked for, and no username twice (in the answer or the pool): a retire takes out the
	// credential its call went out with by username.
	took := 0
	for _, c := range a.Credentials {
		if took == count || len(p.creds) >= PoolSize {
			break
		}
		if slices.ContainsFunc(p.creds, func(h callswire.Credential) bool { return h.Username == c.Username }) {
			continue
		}
		p.creds = append(p.creds, c)
		took++
	}
}

// jittered is w stretched or shortened by jitter() (default: random), a factor kept within [-0.2, 0.2].
func jittered(w time.Duration, jitter func() float64) time.Duration {
	j := rand.Float64()*0.4 - 0.2
	if jitter != nil {
		j = jitter()
	}
	j = max(-0.2, min(0.2, j))
	return time.Duration(float64(w) * (1 + j))
}

// Servers implements ICESource: one entry with the STUN URLs and, if the pool has a usable credential and TURN
// URLs, one entry with the TURN URLs and that credential. The configuration's exp is the credential's, or
// now + ICETTL without one.
func (p *Pool) Servers(s *vault.Session, callID string, now time.Time) ([]callwire.ICEServer, time.Time, error) {
	p.Prime(s, now)
	p.mu.Lock()
	defer p.mu.Unlock()
	exp := now.Add(ICETTL)
	var out []callwire.ICEServer
	if len(p.stun) > 0 {
		out = append(out, callwire.ICEServer{URLs: slices.Clone(p.stun)})
	}
	p.usable(now)
	if len(p.turn) == 0 || len(p.creds) == 0 {
		return out, exp, nil
	}
	// The first usable credential: credentials are only appended and taken out, so a call made again gets the
	// one it had while that is still in the pool.
	c := p.creds[0]
	p.give(callID, c.Username)
	out = append(out, callwire.ICEServer{URLs: slices.Clone(p.turn), Username: c.Username, Credential: c.Credential})
	return out, c.Exp, nil
}

// give records which credential callID went out with; under mu.
func (p *Pool) give(callID, user string) {
	if p.given == nil {
		p.given = map[string]string{}
	}
	if _, ok := p.given[callID]; !ok {
		p.givenOrder = append(p.givenOrder, callID)
		if len(p.givenOrder) > MaxGiven {
			delete(p.given, p.givenOrder[0])
			p.givenOrder = p.givenOrder[1:]
		}
	}
	p.given[callID] = user
}

// Drop implements ICESource: the credential goes as a retired one does.
func (p *Pool) Drop(callID string) { p.Retire(callID) }

// Retire implements ICESource.
func (p *Pool) Retire(callID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	u, ok := p.given[callID]
	if !ok {
		return
	}
	delete(p.given, callID)
	p.givenOrder = slices.DeleteFunc(p.givenOrder, func(id string) bool { return id == callID })
	p.creds = slices.DeleteFunc(p.creds, func(c callswire.Credential) bool { return c.Username == u })
}
