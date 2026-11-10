package vault

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayclient"
)

// A deposit refused for its standing token's quota (§8.6 quota_exceeded,
// `token`; RELAY-PROTOCOL §7.1: never retried unchanged) asks for a fresh
// token (§7.2) and is tried once more with it; nothing behind it waits for
// it (GC #6774: a refused note held the reconnect's hs.resp and the token
// re-mints back for good).

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
	n := new(int)
	r := f.d[s].relay
	r.mu.Lock()
	defer r.mu.Unlock()
	r.checkPayload = func(_, _ string, payload []byte) error {
		if refuse[q[string(payload)]] {
			*n++
			return &relayclient.Error{Status: 429, Code: CodeQuotaExceeded, Quota: quota}
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

func TestQuotaRefusedNoteAsksForATokenAndHoldsNothing(t *testing.T) {
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
	q.send(f, 0, "small") // not held behind the refused one
	if n := f.deliver(0, 1, kNote); n != 1 {
		t.Fatalf("%d notes delivered, want the small one", n)
	}
	// The refresh reaches side 1, its fresh token side 0, and the refused
	// note goes once more under it.
	f.quotaRelay(0, q, relayclient.QuotaToken, nil)
	f.advance(time.Minute) // a fresh token is adopted only with a later exp
	f.settle()
	if got := strings.Join(f.got[1], " "); got != `{"n":"small"} {"n":"big"}` {
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
