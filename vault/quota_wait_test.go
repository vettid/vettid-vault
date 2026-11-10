package vault

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayclient"
	"github.com/vettid/vettid-vault/vms/peerwire"
)

// A deposit refused for its standing token's quota (§8.6 quota_exceeded,
// `token`; RELAY-PROTOCOL §7.1: never retried unchanged) asks for a fresh
// token (§7.2) and is tried once more with it. Later deposits under the
// standing token wait behind it in order; the refresh and deposits with a
// token of their own go (GC #6774: a refused note held the reconnect's
// hs.resp and the refresh back for good).

// qNotes records each test.note a test queued, by its sealed payload.
type qNotes map[string]string

// send queues a test.note with body {"n":"<body>"} on side s and records it.
func (q qNotes) send(f *r29Fx, s int, body string) {
	f.do(s, func(m *Manager, p *Peer) {
		n := len(m.st.Outbox)
		m.sendTo(p, "test.note", []byte(`{"n":"`+body+`"}`), f.clk)
		if len(m.st.Outbox) != n+1 {
			f.t.Fatal("the note was not queued")
		}
		q[string(m.st.Outbox[n].Payload)] = body
	})
}

// entry is side s's outbox entry for the note with body, or nil.
func (q qNotes) entry(f *r29Fx, s int, body string) *OutboxEntry {
	for _, e := range f.m(s).st.Outbox {
		if !e.Done && q[string(e.Payload)] == body {
			return e
		}
	}
	return nil
}

// quotaRelay makes side s's relay refuse the recorded notes whose body is
// in refuse with quota_exceeded (and quota, "" for a relay before 0.9.2),
// counting the refusals.
func (f *r29Fx) quotaRelay(s int, q qNotes, quota string, refuse map[string]bool) *int {
	return f.quotaRelayBy(s, q, func(_, body string) error {
		if refuse[body] {
			return &relayclient.Error{Status: 429, Code: CodeQuotaExceeded, Quota: quota}
		}
		return nil
	})
}

// quotaRelayBy makes side s's relay answer each deposit with refuse(token,
// body) (body "" for one not a recorded note), counting the refusals.
func (f *r29Fx) quotaRelayBy(s int, q qNotes, refuse func(tok, body string) error) *int {
	n := new(int)
	r := f.d[s].relay
	r.mu.Lock()
	defer r.mu.Unlock()
	r.checkPayload = func(_, tok string, payload []byte) error {
		if err := refuse(tok, q[string(payload)]); err != nil {
			*n++
			return err
		}
		return nil
	}
	return n
}

func (f *r29Fx) quotaEntries(s int) []*OutboxEntry {
	var out []*OutboxEntry
	for _, e := range f.m(s).st.Outbox {
		if !e.Done && e.QuotaWait {
			out = append(out, e)
		}
	}
	return out
}

func TestQuotaRefusedNoteAsksForATokenAndKeepsTheOrder(t *testing.T) {
	f := newR29Fx(t)
	q := qNotes{}
	refusals := f.quotaRelay(0, q, relayclient.QuotaToken, map[string]bool{"big": true})
	q.send(f, 0, "big")
	if *refusals != 1 {
		t.Fatalf("%d refusals, want 1", *refusals)
	}
	w := f.quotaEntries(0)
	if len(w) != 1 || w[0] != q.entry(f, 0, "big") || w[0].QuotaTok != tokenTag(f.p(0).Standing.Token) {
		t.Fatalf("quota-waiting entries %+v", w)
	}
	if !f.m(0).requestPending(f.p(0).ID, tokenRefreshType) {
		t.Fatal("no relay.token.refresh asked")
	}
	q.send(f, 0, "small") // waits behind the refused one: the order is kept
	if n := f.deliver(0, 1, kNote); n != 0 {
		t.Fatalf("%d notes delivered ahead of the refused one", n)
	}
	f.advance(time.Minute) // a fresh token is adopted only with a later exp
	if n := f.deliver(0, 1, kOther); n != 1 {
		t.Fatalf("%d other deposits, want the refresh past the wait", n)
	}
	// The refresh reaches side 1, its fresh token side 0, and the refused
	// note goes once more under it.
	f.quotaRelay(0, q, relayclient.QuotaToken, nil)
	f.settle()
	if got := strings.Join(f.got[1], " "); got != `{"n":"big"} {"n":"small"}` {
		t.Fatalf("side 1 got %s", got)
	}
	if len(f.quotaEntries(0)) != 0 {
		t.Fatal("an entry still waits for a token")
	}
}

func TestQuotaWithoutQuotaFieldIsTheMailboxAfterAFreshToken(t *testing.T) {
	f := newR29Fx(t)
	q := qNotes{}
	refusals := f.quotaRelay(0, q, "", map[string]bool{"big": true})
	q.send(f, 0, "big")
	if len(f.quotaEntries(0)) != 1 {
		t.Fatal("the first refusal without quota is not read as the token's")
	}
	tok := f.p(0).Standing.Token
	f.advance(time.Minute)
	f.settle() // the refresh goes, a fresh token comes, the note is tried with it
	if f.p(0).Standing.Token == tok {
		t.Fatal("no fresh standing token")
	}
	if *refusals != 2 {
		t.Fatalf("%d refusals, want 2 (once more with the fresh token)", *refusals)
	}
	e := q.entry(f, 0, "big")
	if e == nil || e.QuotaWait {
		t.Fatalf("entry %+v: want it kept, read as the mailbox's quota (backoff), not waiting for a token", e)
	}
	if f.m(0).requestPending(f.p(0).ID, tokenRefreshType) {
		t.Fatal("a second refresh asked for the mailbox's quota")
	}
	// Opus review H1: after the backoff, refused again with no quota under
	// the same fresh token, it is still the mailbox's: no wait, no refresh.
	f.advance(time.Minute)
	f.tick(0)
	if *refusals != 3 {
		t.Fatalf("%d refusals, want 3 (retried with the backoff)", *refusals)
	}
	if e := q.entry(f, 0, "big"); e == nil || e.QuotaWait || f.m(0).requestPending(f.p(0).ID, tokenRefreshType) {
		t.Fatalf("entry %+v: the mailbox's quota read as the token's again", e)
	}
	// Another note refused with no quota under that token: the mailbox's too.
	q.send(f, 0, "other") // queued behind big: tried once big goes
	f.quotaRelay(0, q, "", map[string]bool{"other": true})
	f.advance(time.Minute)
	f.tick(0)
	if e := q.entry(f, 0, "other"); e == nil || e.QuotaWait || f.m(0).requestPending(f.p(0).ID, tokenRefreshType) {
		t.Fatalf("entry %+v: a later entry's no-quota refusal read as the token's under a mailbox-read token", e)
	}
}

// Opus review M1: an entry refused for its token's quota is not sent again
// under that token (RELAY-PROTOCOL §7.1); when due it asks for a refresh
// again, once an hour.
func TestQuotaNotResentUnderTheRefusedToken(t *testing.T) {
	f := newR29Fx(t)
	q := qNotes{}
	refusals := f.quotaRelay(0, q, relayclient.QuotaToken, map[string]bool{"big": true})
	q.send(f, 0, "big")
	if n := f.lose(0, 1, kOther); n != 1 {
		t.Fatalf("%d refreshes lost, want 1", n)
	}
	for i, d := range []time.Duration{time.Hour + time.Minute, 30 * time.Minute, 31 * time.Minute} {
		f.advance(d)
		f.tick(0)
		if *refusals != 1 {
			t.Fatalf("step %d: %d refusals: sent again under the refused token", i, *refusals)
		}
		want := []int{1, 0, 1}[i]
		if n := f.lose(0, 1, kOther); n != want {
			t.Fatalf("step %d: %d refreshes asked, want %d", i, n, want)
		}
	}
}

// Opus review M2: a too_soon answer's allowed_after is honoured.
func TestQuotaTooSoonIsHonoured(t *testing.T) {
	f := newR29Fx(t)
	q := qNotes{}
	refusals := f.quotaRelay(0, q, relayclient.QuotaToken, map[string]bool{"big": true})
	f.m(1).st.attach().Refreshed[f.p(1).ID] = f.clk // the issuer granted one just now
	q.send(f, 0, "big")
	f.settle() // the refresh reaches side 1; too_soon comes back
	after := f.m(0).quotaAsk[f.p(0).ID].after
	if want := f.clk.Add(24 * time.Hour); !after.Equal(want) {
		t.Fatalf("allowed_after %v, want %v", after, want)
	}
	f.advance(2 * time.Hour)
	f.tick(0)
	if n := f.lose(0, 1, kOther); n != 0 {
		t.Fatalf("%d refreshes asked before allowed_after", n)
	}
	if e := q.entry(f, 0, "big"); e == nil || !e.NotBefore.Equal(after) {
		t.Fatalf("entry %+v: not due at allowed_after", e)
	}
	f.advance(22*time.Hour + time.Minute)
	f.quotaRelay(0, q, relayclient.QuotaToken, nil)
	f.tick(0)
	f.settle()
	if strings.Join(f.got[1], " ") != `{"n":"big"}` {
		t.Fatalf("side 1 got %v", f.got[1])
	}
	if *refusals != 1 {
		t.Fatalf("%d refusals, want 1", *refusals)
	}
}

// Opus review M3, owner decision of 2026-11-10 (GC #6840, a): the refresh
// itself refused for the token's quota (its msgs spent) starts a reconnect
// at once; the note goes under the reconnect's fresh standing token, in
// time (a wait for the issuer's re-mint would outlast MaxDurableAge).
func TestQuotaRefreshRefusedForTheTokenReconnects(t *testing.T) {
	f := newR29Fx(t)
	q := qNotes{}
	spent := f.p(0).Standing.Token
	refusals := f.quotaRelayBy(0, q, func(tok, _ string) error {
		if tok == spent {
			return &relayclient.Error{Status: 429, Code: CodeQuotaExceeded, Quota: relayclient.QuotaToken}
		}
		return nil
	})
	q.send(f, 0, "big")
	f.advance(time.Minute)
	f.settle()
	if *refusals != 2 {
		t.Fatalf("%d refusals, want 2 (the note, then its refresh)", *refusals)
	}
	if !f.audited(0, "quota_refresh_refused") {
		t.Fatal("the refused refresh is not noted")
	}
	if f.m(0).requestPending(f.p(0).ID, tokenRefreshType) {
		t.Fatal("the refused refresh's request is still pending")
	}
	f.advance(time.Minute)
	f.tick(0)
	f.settle()
	if f.p(0).Standing.Token == spent {
		f.dump()
		t.Fatal("no fresh standing token: no reconnect")
	}
	if got := strings.Join(f.got[1], " "); got != `{"n":"big"}` {
		t.Fatalf("side 1 got %s", got)
	}
	if *refusals != 2 {
		t.Fatalf("%d refusals: sent again under the spent token", *refusals)
	}
}

// quota: mailbox is the mailbox's quota: retried with the backoff, no
// refresh asked, nothing waits as for a token.
func TestQuotaMailboxBacksOff(t *testing.T) {
	f := newR29Fx(t)
	q := qNotes{}
	refusals := f.quotaRelay(0, q, relayclient.QuotaMailbox, map[string]bool{"big": true})
	q.send(f, 0, "big")
	if e := q.entry(f, 0, "big"); e == nil || e.QuotaWait || f.m(0).requestPending(f.p(0).ID, tokenRefreshType) {
		t.Fatalf("entry %+v: the mailbox's quota read as the token's", e)
	}
	f.advance(time.Minute)
	f.tick(0)
	if *refusals != 2 {
		t.Fatalf("%d refusals, want 2 (the backoff)", *refusals)
	}
	f.quotaRelay(0, q, "", nil)
	f.advance(time.Minute)
	f.settle()
	if got := strings.Join(f.got[1], " "); got != `{"n":"big"}` {
		t.Fatalf("side 1 got %s", got)
	}
}

// Opus review L3: the wait is persisted, the asks are not: after a restart
// the due entry asks again, and goes under the fresh token.
func TestQuotaWaitAcrossARestart(t *testing.T) {
	f := newR29Fx(t)
	q := qNotes{}
	tok := f.p(0).Standing.Token
	f.quotaRelayBy(0, q, func(t, body string) error {
		if t == tok && body == "big" {
			return &relayclient.Error{Status: 429, Code: CodeQuotaExceeded, Quota: relayclient.QuotaToken}
		}
		return nil
	})
	q.send(f, 0, "big")
	f.lose(0, 1, kOther) // the refresh is lost
	f.restart(0)
	if len(f.quotaEntries(0)) != 1 {
		t.Fatal("the wait did not survive the restart")
	}
	f.advance(time.Hour + time.Minute)
	f.tick(0)
	f.settle()
	if got := strings.Join(f.got[1], " "); got != `{"n":"big"}` {
		t.Fatalf("side 1 got %s", got)
	}
}

// Opus review L1: tried under a fresh token and failed for another reason
// (a 503), the entry is no longer waiting for a token: it holds the later
// deposits as any failed one (blocked), and they keep the order.
func TestQuotaTransientAfterAFreshToken(t *testing.T) {
	f := newR29Fx(t)
	q := qNotes{}
	tok := f.p(0).Standing.Token
	down := false
	f.quotaRelayBy(0, q, func(t, body string) error {
		switch {
		case t == tok && body == "big":
			return &relayclient.Error{Status: 429, Code: CodeQuotaExceeded, Quota: relayclient.QuotaToken}
		case down && body != "":
			return &relayclient.Error{Status: 503}
		}
		return nil
	})
	q.send(f, 0, "big")
	q.send(f, 0, "small")
	down = true
	f.advance(time.Minute)
	f.settle() // the refresh goes (not a note), the fresh token comes, big fails 503
	if f.p(0).Standing.Token == tok {
		t.Fatal("no fresh token")
	}
	if e := q.entry(f, 0, "big"); e == nil || e.QuotaWait {
		t.Fatalf("entry %+v: still waiting for a token after a transient error", e)
	}
	down = false
	f.advance(time.Minute)
	f.settle()
	if got := strings.Join(f.got[1], " "); got != `{"n":"big"} {"n":"small"}` {
		t.Fatalf("side 1 got %s", got)
	}
}

// TestQuotaSeeds: the random pair's seeds that ended quota-stuck before
// this (GC #6774), with both modes on.
func TestQuotaSeeds(t *testing.T) {
	old := rpRunModes
	rpRunModes = rpModes{shuffle: true, refresh: true}
	t.Cleanup(func() { rpRunModes = old })
	for _, seed := range []uint64{13894595740220335007, 9200229175364500436} {
		t.Run(strconv.FormatUint(seed, 10), func(t *testing.T) {
			if v, _ := rpRun(t, seed, 40, false, false); v != "" {
				t.Fatalf("verdict %q, want converged", v)
			}
		})
	}
}

// refreshes counts side s's undone quota-refresh entries.
func (f *r29Fx) refreshes(s int) int {
	n := 0
	for _, e := range f.m(s).st.Outbox {
		if !e.Done && e.QuotaRefresh {
			n++
		}
	}
	return n
}

// Re-review M1: a refresh still queued (the relay down) is not asked
// again beside it; its request is the only one open.
func TestQuotaRefreshesDoNotPileUp(t *testing.T) {
	f := newR29Fx(t)
	q := qNotes{}
	down := true
	f.quotaRelayBy(0, q, func(_, body string) error {
		switch {
		case body == "big":
			return &relayclient.Error{Status: 429, Code: CodeQuotaExceeded, Quota: relayclient.QuotaToken}
		case down:
			return &relayclient.Error{Status: 503}
		}
		return nil
	})
	q.send(f, 0, "big")
	for i := 0; i < 6; i++ {
		f.advance(time.Hour + time.Minute)
		f.tick(0)
	}
	if n := f.refreshes(0); n != 1 {
		t.Fatalf("%d refresh entries queued, want 1", n)
	}
	if n := len(f.p(0).QuotaReqs); n != 1 {
		t.Fatalf("%d quota refresh requests open, want 1", n)
	}
	down = false
	f.quotaRelay(0, q, relayclient.QuotaToken, nil)
	f.advance(time.Hour + time.Minute)
	f.tick(0)
	f.settle()
	if got := strings.Join(f.got[1], " "); got != `{"n":"big"}` {
		t.Fatalf("side 1 got %s", got)
	}
}

// Re-review M4: a refresh still queued when another fresh token came is
// not sent under it (it would spend the issuer's daily quota refresh).
func TestQuotaLeftoverRefreshIsNotSentUnderANewToken(t *testing.T) {
	f := newR29Fx(t)
	q := qNotes{}
	old := f.p(0).Standing.Token
	sent := 0
	f.quotaRelayBy(0, q, func(tok, body string) error {
		switch {
		case tok == old && body == "big":
			return &relayclient.Error{Status: 429, Code: CodeQuotaExceeded, Quota: relayclient.QuotaToken}
		case tok == old:
			return &relayclient.Error{Status: 503}
		case body == "":
			sent++
		}
		return nil
	})
	q.send(f, 0, "big")
	if f.refreshes(0) != 1 {
		t.Fatal("no refresh queued")
	}
	f.do(0, func(m *Manager, p *Peer) { // another fresh token (as the issuer's re-mint)
		p.Standing.Token = "fresh." + old
		m.retryPeer(p.ID)
	})
	f.advance(time.Minute)
	f.tick(0)
	if sent != 0 || f.refreshes(0) != 0 {
		t.Fatalf("the leftover refresh: %d sent, %d queued", sent, f.refreshes(0))
	}
	if f.m(0).requestPending(f.p(0).ID, tokenRefreshType) {
		t.Fatal("its request is still pending")
	}
}

// Re-review L1: refused for its quota past the token's exp (the relay's
// clock behind), the entry is not resent with the backoff: a reconnect.
func TestQuotaRefusalPastTheExpReconnects(t *testing.T) {
	f := newR29Fx(t)
	q := qNotes{}
	old := f.p(0).Standing.Token
	refusals := f.quotaRelayBy(0, q, func(tok, body string) error {
		if tok == old && body == "big" {
			return &relayclient.Error{Status: 429, Code: CodeQuotaExceeded, Quota: relayclient.QuotaToken}
		}
		return nil
	})
	f.do(0, func(_ *Manager, p *Peer) { p.Standing.Exp = f.clk.Add(-time.Minute) })
	q.send(f, 0, "big")
	n := *refusals
	for i := 0; i < 5; i++ {
		f.advance(time.Minute)
		f.tick(0)
	}
	if *refusals != n {
		t.Fatalf("%d refusals after %d: resent under the refused token", *refusals, n)
	}
	if f.openReconnect(0) == nil {
		t.Fatal("no reconnect")
	}
	if f.m(0).requestPending(f.p(0).ID, tokenRefreshType) {
		t.Fatal("a refresh asked under an expired token")
	}
}

// Re-review M2: a refresh the relay refused (not for its quota) ends its
// request: requestPending is not held by it.
func TestQuotaRefusedRefreshEndsItsRequest(t *testing.T) {
	f := newR29Fx(t)
	q := qNotes{}
	f.quotaRelayBy(0, q, func(_, body string) error {
		if body == "big" {
			return &relayclient.Error{Status: 429, Code: CodeQuotaExceeded, Quota: relayclient.QuotaToken}
		}
		return &relayclient.Error{Status: 403, Code: "forbidden"}
	})
	q.send(f, 0, "big")
	f.advance(time.Minute)
	f.tick(0)
	if f.refreshes(0) != 0 {
		t.Fatal("the refused refresh is still queued")
	}
	if f.m(0).requestPending(f.p(0).ID, tokenRefreshType) {
		t.Fatal("the refused refresh's request is still pending")
	}
}

// Re-review M3: the mailbox reading is persisted: after a restart, a no-
// quota refusal under the same token is still the mailbox's.
func TestQuotaMailboxReadingSurvivesARestart(t *testing.T) {
	f := newR29Fx(t)
	q := qNotes{}
	f.quotaRelay(0, q, "", map[string]bool{"big": true})
	q.send(f, 0, "big")
	f.advance(time.Minute)
	f.settle() // fresh token; refused again: the mailbox's
	if f.p(0).QuotaMailbox != tokenTag(f.p(0).Standing.Token) {
		t.Fatal("the mailbox reading is not on the peer")
	}
	f.restart(0)
	f.quotaRelay(0, q, "", map[string]bool{"other": true})
	q.send(f, 0, "other")
	f.advance(time.Minute)
	f.tick(0)
	if e := q.entry(f, 0, "other"); e == nil || e.QuotaWait || f.m(0).requestPending(f.p(0).ID, tokenRefreshType) {
		t.Fatalf("entry %+v: read as the token's after a restart", e)
	}
}

// Nit 1: the hourly bound on its own: made due again within the hour
// (retryPeer), the entry asks for no second refresh.
func TestQuotaAskedAtMostHourly(t *testing.T) {
	f := newR29Fx(t)
	q := qNotes{}
	f.quotaRelay(0, q, relayclient.QuotaToken, map[string]bool{"big": true})
	q.send(f, 0, "big")
	f.lose(0, 1, kOther)
	f.advance(30 * time.Minute)
	f.do(0, func(m *Manager, p *Peer) { m.retryPeer(p.ID) })
	f.tick(0)
	if n := f.lose(0, 1, kOther); n != 0 {
		t.Fatalf("%d refreshes asked within the hour", n)
	}
}

// Nit 2: a reconnect's hs.init (its own token) passes a quota wait.
func TestQuotaWaitLetsTheHandshakePass(t *testing.T) {
	f := newR29Fx(t)
	q := qNotes{}
	f.quotaRelay(0, q, relayclient.QuotaToken, map[string]bool{"big": true})
	q.send(f, 0, "big")
	f.do(0, func(m *Manager, p *Peer) { m.startReconnect(p, f.clk) })
	if n := f.deliver(0, 1, kHSInit); n != 1 {
		t.Fatalf("%d hs.init delivered past the wait, want 1", n)
	}
}

// Re-review L2: a too_soon answer to a refresh that was not a quota
// refresh (the near-end one) sets no allowed_after.
func TestQuotaTooSoonOnlyForAQuotaRefresh(t *testing.T) {
	f := newR29Fx(t)
	f.do(0, func(m *Manager, p *Peer) {
		m.quotaFor(p.ID)
		m.quotaTooSoon(p, "not-a-quota-refresh", peerwire.TooSoonBody(f.clk.Add(time.Hour)), f.clk)
		if !m.quotaAsk[p.ID].after.IsZero() {
			t.Fatal("allowed_after set by another refresh's too_soon")
		}
	})
}

// Re-review 3 H1, scenario A: the issuer was slow; the waiting entry asked
// again an hour later. The issuer grants the first refresh and answers the
// second too_soon: the first one's token is taken, the note goes at once.
func TestQuotaFirstRefreshAnsweredAfterASecondIsAsked(t *testing.T) {
	f := newR29Fx(t)
	q := qNotes{}
	old := f.p(0).Standing.Token
	f.quotaRelayBy(0, q, func(tok, body string) error {
		if tok == old && body == "big" {
			return &relayclient.Error{Status: 429, Code: CodeQuotaExceeded, Quota: relayclient.QuotaToken}
		}
		return nil
	})
	q.send(f, 0, "big")
	f.tick(0)
	r1 := f.takeKind(0, 1, kOther)
	f.advance(time.Hour + time.Minute)
	f.tick(0)
	f.tick(0)
	r2 := f.takeKind(0, 1, kOther)
	if len(r1) != 1 || len(r2) != 1 {
		t.Fatalf("refreshes: %d then %d, want 1 and 1", len(r1), len(r2))
	}
	f.process(1, r1[0])
	f.process(1, r2[0])
	f.settle()
	f.tick(0)
	f.settle()
	if f.p(0).Standing.Token == old {
		t.Fatal("the first refresh's token was not taken")
	}
	if got := strings.Join(f.got[1], " "); got != `{"n":"big"}` {
		t.Fatalf("side 1 got %s", got)
	}
}

// Re-review 3 H1, scenario B: the vault restarted before the refresh's
// answer came; the answer is still taken.
func TestQuotaRefreshAnsweredAfterARestart(t *testing.T) {
	f := newR29Fx(t)
	q := qNotes{}
	old := f.p(0).Standing.Token
	f.quotaRelayBy(0, q, func(tok, body string) error {
		if tok == old && body == "big" {
			return &relayclient.Error{Status: 429, Code: CodeQuotaExceeded, Quota: relayclient.QuotaToken}
		}
		return nil
	})
	q.send(f, 0, "big")
	f.tick(0)
	r1 := f.takeKind(0, 1, kOther)
	if len(r1) != 1 {
		t.Fatalf("%d refreshes, want 1", len(r1))
	}
	f.restart(0)
	f.advance(time.Minute)
	f.process(1, r1[0])
	f.settle()
	f.tick(0)
	f.settle()
	if f.p(0).Standing.Token == old {
		t.Fatal("the answer after the restart was dropped")
	}
	if got := strings.Join(f.got[1], " "); got != `{"n":"big"}` {
		t.Fatalf("side 1 got %s", got)
	}
}

// Re-review 3 L2: the refresh refused for the token's quota before its exp
// with no reconnect token held: no reconnect, so the connection is not
// made stale (the issuer's re-mint may still come).
func TestQuotaRefreshRefusedWithoutAReconnectTokenWaits(t *testing.T) {
	f := newR29Fx(t)
	q := qNotes{}
	spent := f.p(0).Standing.Token
	f.quotaRelayBy(0, q, func(tok, _ string) error {
		if tok == spent {
			return &relayclient.Error{Status: 429, Code: CodeQuotaExceeded, Quota: relayclient.QuotaToken}
		}
		return nil
	})
	f.do(0, func(_ *Manager, p *Peer) { p.Reconnect.Token = "" })
	q.send(f, 0, "big")
	f.advance(time.Minute)
	f.settle()
	if f.p(0).State == PeerStale {
		t.Fatal("made stale before the token's exp")
	}
	if q.entry(f, 0, "big") == nil {
		t.Fatal("the note was dropped")
	}
}
