package vault

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// askSource is a feature with open asks (connauth, actions and location
// are the real ones, tested in their packages and end to end).
type askSource struct {
	recSink
	asks []PendingAsk
}

func (a *askSource) OpenAsks(now time.Time) []PendingAsk {
	var out []PendingAsk
	for _, k := range a.asks {
		if now.Before(k.Exp) {
			out = append(out, k)
		}
	}
	return out
}

type pendingPage struct {
	kinds []string
	ids   []string
	next  string
}

func (d *devFixture) pendingList(t *testing.T, p *tdev, body string) (*envelope.Inner, pendingPage) {
	t.Helper()
	id := d.sendAs(p, "pending.list", body)
	r := find(d.inbox(p)[p.peer.ID], reply(id))
	if r == nil {
		t.Fatal("no answer")
	}
	var pg pendingPage
	if r.Status != envelope.StatusOK {
		return r, pg
	}
	o, err := strictjson.ParseObject(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	arr, err := o.Array("asks")
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range arr {
		e, err := strictjson.ParseObject(raw)
		if err != nil {
			t.Fatal(err)
		}
		k, _ := e.String("kind")
		pg.kinds = append(pg.kinds, k)
		b, err := strictjson.ParseObject(e["body"])
		if err != nil {
			t.Fatal(err)
		}
		for _, n := range []string{"request_id", "approval_id", "invocation_id"} {
			if v, err := b.String(n); err == nil {
				pg.ids = append(pg.ids, v)
			}
		}
	}
	pg.next, _ = o.String("next")
	return r, pg
}

// §10.4.2: an app lists all five kinds, each as the body of its event;
// a desktop only the three it receives; an agent is forbidden; sorted by
// exp then id; expired and decided asks are not listed; listing changes
// nothing.
func TestPendingListKindsAndRoles(t *testing.T) {
	d := newDevFixture(t)
	app := d.self()
	desk := d.addDevice(t, "desk1", KindDesktop, 0x60)
	ag := d.addDevice(t, "agent1", KindAgent, 0x70)
	desk.peer.Access = &AccessSession{ID: "s", Expires: time.Now().Add(time.Hour)}
	ag.peer.Access = &AccessSession{ID: "s", Expires: time.Now().Add(time.Hour)}

	now := time.Now().UTC().Truncate(time.Millisecond)
	src := &askSource{asks: []PendingAsk{
		{Kind: PendingLocation, ID: "L1", Exp: now.Add(40 * time.Minute), Body: []byte(`{"request_id":"L1"}`)},
		{Kind: PendingAuthenticate, ID: "A1", Exp: now.Add(30 * time.Minute), Body: []byte(`{"request_id":"A1"}`)},
		{Kind: PendingAction, ID: "X1", Exp: now.Add(50 * time.Minute), Body: []byte(`{"invocation_id":"X1"}`)},
		{Kind: PendingAuthenticate, ID: "gone", Exp: now.Add(-time.Minute), Body: []byte(`{"request_id":"gone"}`)},
	}}
	d.m.addFeature(src)

	// A session request from the desktop, and a held approval.
	id := d.sendAs(desk, "device.session.request", `{"seconds":600}`)
	in := d.inbox(app, desk)
	if r := find(in["desk1"], reply(id)); r == nil || r.Status != envelope.StatusOK {
		t.Fatal("request refused")
	}
	sessEv := find(in["dev1"], ofType("device.session.pending"))
	id = d.sendAs(desk, "settings.set", `{"version":0,"set":{"app.theme":"dark"}}`)
	_ = id
	appEv := find(d.inbox(app, desk)["dev1"], ofType("approval.pending"))
	if sessEv == nil || appEv == nil {
		t.Fatal("no events")
	}

	r, pg := d.pendingList(t, app, `{}`)
	if r.Status != envelope.StatusOK {
		t.Fatalf("app: %+v", r)
	}
	// Soonest first: the approval (5 min), the session (10 min), then 30, 40, 50.
	if got := strings.Join(pg.kinds, ","); got != "approval,session,authenticate,location,action" {
		t.Fatalf("kinds/order: %s", got)
	}
	// The bodies are the events' bodies, byte for byte.
	for _, ev := range []*envelope.Inner{sessEv, appEv} {
		if !strings.Contains(string(r.Body), string(ev.Body)) {
			t.Fatalf("event body %s not in %s", ev.Body, r.Body)
		}
	}

	// A desktop: the three kinds it receives.
	_, pg = d.pendingList(t, desk, `{}`)
	if got := strings.Join(pg.kinds, ","); got != "authenticate,location,action" {
		t.Fatalf("desktop kinds: %s", got)
	}
	// An agent: forbidden.
	if r, _ := d.pendingList(t, ag, `{}`); errCode(r) != "forbidden" {
		t.Fatalf("agent: %+v", r)
	}

	// Listing changed nothing: the session request and the held request stand.
	if len(d.m.st.AccessRequests) != 1 || len(d.m.st.Held) != 1 {
		t.Fatal("listing changed the asks")
	}
	// Decided: no longer listed.
	d.sendAs(app, "approval.decide", `{"approval_id":"`+bodyStr(t, appEv, "approval_id")+`","approve":false}`)
	d.sendAs(app, "device.session.deny", `{"request_id":"`+bodyStr(t, sessEv, "request_id")+`"}`)
	d.inbox(app, desk)
	if _, pg = d.pendingList(t, app, `{}`); strings.Join(pg.kinds, ",") != "authenticate,location,action" {
		t.Fatalf("after decisions: %v", pg.kinds)
	}
	// Past the expiry: gone.
	d.m.now = func() time.Time { return now.Add(35 * time.Minute) }
	_, pg = d.pendingList(t, app, `{}`)
	d.m.now = time.Now
	if strings.Join(pg.kinds, ",") != "location,action" {
		t.Fatalf("after expiry: %v", pg.kinds)
	}
}

// §10.4.2: limit 1-100 (default 50), bad bodies, paging by an opaque
// cursor, and a cursor that names no position starts again.
func TestPendingListPaging(t *testing.T) {
	d := newDevFixture(t)
	app := d.self()
	now := time.Now().UTC().Truncate(time.Millisecond)
	src := &askSource{}
	for i := 0; i < 7; i++ {
		id := fmt.Sprintf("A%02d", i)
		src.asks = append(src.asks, PendingAsk{Kind: PendingAuthenticate, ID: id, Exp: now.Add(time.Hour), // equal exp: the id orders
			Body: []byte(`{"request_id":"` + id + `"}`)})
	}
	d.m.addFeature(src)
	for _, bad := range []string{`{"limit":0}`, `{"limit":101}`, `{"limit":"3"}`, `{"after":5}`, `{"extra":1,"limit":"x"}`} {
		if r, _ := d.pendingList(t, app, bad); errCode(r) != "bad_request" {
			t.Fatalf("%s: %+v", bad, r)
		}
	}
	_, pg := d.pendingList(t, app, `{"limit":3}`)
	var all []string
	all = append(all, pg.ids...)
	if len(pg.ids) != 3 || pg.next == "" {
		t.Fatalf("page 1: %+v", pg)
	}
	for pg.next != "" {
		_, pg = d.pendingList(t, app, `{"limit":3,"after":"`+pg.next+`"}`)
		all = append(all, pg.ids...)
	}
	if strings.Join(all, ",") != "A00,A01,A02,A03,A04,A05,A06" || pg.next != "" {
		t.Fatalf("paged: %v", all)
	}
	_, pg = d.pendingList(t, app, `{"after":"bm9uZQ"}`)
	if len(pg.ids) != 7 {
		t.Fatalf("a cursor naming no position: %v", pg.ids)
	}
	_, pg = d.pendingList(t, app, `{}`)
	if len(pg.ids) != 7 || pg.next != "" {
		t.Fatalf("default: %+v", pg)
	}
}

// §10.4.2: a page holds at most 131,072 bytes and always at least one
// entry (an entry is never split or dropped).
func TestPendingListByteCap(t *testing.T) {
	d := newDevFixture(t)
	app := d.self()
	now := time.Now().UTC().Truncate(time.Millisecond)
	pad := strings.Repeat("x", 1000)
	src := &askSource{}
	for i := 0; i < 5; i++ {
		id := fmt.Sprintf("A%02d", i)
		src.asks = append(src.asks, PendingAsk{Kind: PendingAction, ID: id, Exp: now.Add(time.Hour),
			Body: []byte(`{"invocation_id":"` + id + `","params":"` + pad + `"}`)})
	}
	d.m.addFeature(src)
	old := pendingPageBytes
	defer func() { pendingPageBytes = old }()
	pendingPageBytes = 2500 // two entries fit, three do not
	r, pg := d.pendingList(t, app, `{}`)
	if len(pg.ids) != 2 || pg.next == "" || len(r.Body) > pendingPageBytes {
		t.Fatalf("page: %d entries, %d bytes, next %q", len(pg.ids), len(r.Body), pg.next)
	}
	pendingPageBytes = 10 // smaller than one entry: still one
	_, pg = d.pendingList(t, app, `{}`)
	if len(pg.ids) != 1 || pg.next == "" {
		t.Fatalf("one entry: %+v", pg)
	}
	var all []string
	for {
		all = append(all, pg.ids...)
		if pg.next == "" {
			break
		}
		_, pg = d.pendingList(t, app, `{"after":"`+pg.next+`"}`)
	}
	if len(all) != 5 {
		t.Fatalf("all pages: %v", all)
	}
}

// The cap holds for every page whatever the kinds (their cursors differ in
// length), both when the bytes end the page and when the limit does; a page
// over the cap holds exactly one entry.
func TestPendingListByteCapMixedKinds(t *testing.T) {
	d := newDevFixture(t)
	app := d.self()
	now := time.Now().UTC().Truncate(time.Millisecond)
	src := &askSource{}
	kinds := []string{PendingAuthenticate, PendingAction, PendingLocation, PendingAuthenticate, PendingAction, PendingLocation}
	for i, k := range kinds {
		id := fmt.Sprintf("A%02d", i)
		src.asks = append(src.asks, PendingAsk{Kind: k, ID: id, Exp: now.Add(time.Hour),
			Body: []byte(`{"request_id":"` + id + `","params":"` + strings.Repeat("x", 30) + `"}`)})
	}
	d.m.addFeature(src)
	old := pendingPageBytes
	defer func() { pendingPageBytes = old }()
	for _, limit := range []int{2, 100} {
		for cap := 150; cap < 450; cap++ {
			pendingPageBytes = cap
			var got []string
			after := ""
			for pages := 0; ; pages++ {
				body := `{"limit":` + fmt.Sprint(limit)
				if after != "" {
					body += `,"after":"` + after + `"`
				}
				r, pg := d.pendingList(t, app, body+`}`)
				if len(pg.ids) == 0 || pages > 20 {
					t.Fatalf("cap %d limit %d: page %d has %d entries", cap, limit, pages, len(pg.ids))
				}
				if len(r.Body) > cap && len(pg.ids) != 1 {
					t.Fatalf("cap %d limit %d: %d bytes in %d entries", cap, limit, len(r.Body), len(pg.ids))
				}
				got = append(got, pg.ids...)
				if pg.next == "" {
					break
				}
				after = pg.next
			}
			if len(got) != len(kinds) {
				t.Fatalf("cap %d limit %d: %v", cap, limit, got)
			}
		}
	}
}

// The cursor names a position, not an entry: when the last ask of a page is
// decided or expires before the next page, the list resumes after it.
func TestPendingListCursorSurvivesItsEntryGoing(t *testing.T) {
	d := newDevFixture(t)
	app := d.self()
	now := time.Now().UTC().Truncate(time.Millisecond)
	src := &askSource{}
	for i := 0; i < 5; i++ {
		id := fmt.Sprintf("A%02d", i)
		src.asks = append(src.asks, PendingAsk{Kind: PendingAuthenticate, ID: id, Exp: now.Add(time.Duration(i+1) * time.Hour),
			Body: []byte(`{"request_id":"` + id + `"}`)})
	}
	d.m.addFeature(src)
	_, pg := d.pendingList(t, app, `{"limit":2}`)
	if strings.Join(pg.ids, ",") != "A00,A01" || pg.next == "" {
		t.Fatalf("%+v", pg)
	}
	src.asks = src.asks[2:] // A00 and A01 were decided
	_, pg = d.pendingList(t, app, `{"limit":2,"after":"`+pg.next+`"}`)
	if strings.Join(pg.ids, ",") != "A02,A03" {
		t.Fatalf("resumed at %v", pg.ids)
	}
	src.asks = src.asks[1:]
	src.asks = src.asks[1:] // A02, A03 gone too
	_, pg = d.pendingList(t, app, `{"limit":2,"after":"`+pg.next+`"}`)
	if strings.Join(pg.ids, ",") != "A04" || pg.next != "" {
		t.Fatalf("after the entry went: %+v", pg)
	}
}

// Listing reads only: no audit entry, nothing for the asker's or any other
// device's inbox, no cached response (volatile, §8.2).
func TestPendingListChangesNothing(t *testing.T) {
	d := newDevFixture(t)
	app := d.self()
	desk := d.addDevice(t, "desk1", KindDesktop, 0x60)
	sink := &recSink{}
	d.m.addFeature(sink)
	now := time.Now().UTC().Truncate(time.Millisecond)
	d.m.addFeature(&askSource{asks: []PendingAsk{{Kind: PendingAuthenticate, ID: "A1", Exp: now.Add(time.Hour), Body: []byte(`{"request_id":"A1"}`)}}})
	d.inbox(app, desk)
	nAudit, nCached := len(d.m.st.Audit), len(d.m.st.Responses)
	sink.got = nil
	id := d.sendAs(app, "pending.list", `{}`)
	in := d.inbox(app, desk)
	if r := find(in["dev1"], reply(id)); r == nil || r.Status != envelope.StatusOK {
		t.Fatalf("%+v", r)
	}
	// (Housekeeping's token reissue is not the listing's.)
	for _, ms := range in {
		for _, m := range ms {
			if m.Type != "pending.list" && m.Type != "relay.token.issued" {
				t.Fatalf("listing sent %s", m.Type)
			}
		}
	}
	if len(sink.got) != 0 || len(d.m.st.Audit) != nAudit {
		t.Fatalf("activity written: %+v", sink.got)
	}
	if d.cached(id) || len(d.m.st.Responses) != nCached {
		t.Fatal("the response was cached")
	}
}

// A desktop needs an access session; while the vault is held every owner
// device is refused owner_check_required (§3.6.3), the desktop and an app
// alike, at dispatch.
func TestPendingListSessionAndHold(t *testing.T) {
	d := newDevFixture(t)
	desk := d.addDevice(t, "desk1", KindDesktop, 0x60)
	if r, _ := d.pendingList(t, desk, `{}`); errCode(r) != "session_required" {
		t.Fatalf("desktop without a session: %+v", r)
	}

	f := newOCFixture(t)
	f.pastDeadline()
	f.req(t, f.app, "settings.get", `{}`) // enters the hold
	for _, td := range []*tdev{f.app, f.desk} {
		if r := f.req(t, td, "pending.list", `{}`); errCode(r) != "owner_check_required" {
			t.Fatalf("%s while held: %+v", td.peer.ID, r)
		}
	}
}
