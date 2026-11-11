package calls

import (
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
)

// Permission and limits (VAULT-MESSAGING §10.10 "Permission and limits",
// C2, CALLS-PLAN V5, decisions D6, D7, D22).
const (
	// MissedMergeWindow: a missed call from a connection whose call.missed
	// item is still active and younger than this updates that item.
	MissedMergeWindow = 24 * time.Hour
	// The unanswered-call limit: this many incoming calls that ended
	// unanswered within the window, from one connection, silence the next.
	LimitShort, LimitShortWindow = 3, 10 * time.Minute
	LimitLong, LimitLongWindow   = 10, 24 * time.Hour
)

var errCallsOff = vault.NewError("calls_off", "")

// state is the feature's DEK state: the calls, the connections whose calls
// are off, each connection's unanswered incoming calls (at most LimitLong
// times), and the connections last announced as limited.
type state struct {
	V          int                    `json:"v"`
	Calls      map[string]*Call       `json:"calls"`
	Off        map[string]bool        `json:"off,omitempty"`
	Unanswered map[string][]time.Time `json:"unanswered,omitempty"`
	Limited    map[string]bool        `json:"limited,omitempty"`
}

const stateVersion = 2

// loadState reads the state, also the earlier form (the calls map alone,
// keyed by call_id, which never has a key "v").
func loadState(data json.RawMessage) (*state, error) {
	st := &state{Calls: map[string]*Call{}}
	if len(data) == 0 || string(data) == "null" {
		return st, nil
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, err
	}
	if _, ok := probe["v"]; !ok {
		if err := json.Unmarshal(data, &st.Calls); err != nil {
			return nil, err
		}
		return st, nil
	}
	if err := json.Unmarshal(data, st); err != nil {
		return nil, err
	}
	if st.V > stateVersion {
		return nil, errors.New("calls: state from a later release") // never drop what it doesn't know
	}
	if st.Calls == nil {
		st.Calls = map[string]*Call{}
	}
	return st, nil
}

// limited reports whether conn is at the unanswered-call limit at now:
// LimitShort in LimitShortWindow, or LimitLong in LimitLongWindow.
func (f *Feature) limited(conn string, now time.Time) bool {
	short, long := 0, 0
	ts := f.unanswered[conn]
	for i, t := range ts {
		// A count from before the clock went back is moved to now once, so
		// it ages from there: a step back doesn't lengthen a limit.
		if t.After(now) {
			ts[i], t = now, now
		}
		if now.Sub(t) < LimitLongWindow {
			long++
			if now.Sub(t) < LimitShortWindow {
				short++
			}
		}
	}
	return short >= LimitShort || long >= LimitLong
}

// noteUnanswered counts an incoming call from conn that ended without being
// answered (missed, declined, busy, or suppressed by the limit).
func (f *Feature) noteUnanswered(s *vault.Session, conn string, now time.Time) {
	if _, ok := s.Connection(conn); !ok {
		return // the connection is gone (its counts go with it)
	}
	var keep []time.Time
	for _, t := range f.unanswered[conn] {
		if t.After(now) {
			t = now // as in limited
		}
		if now.Sub(t) < LimitLongWindow {
			keep = append(keep, t)
		}
	}
	keep = append(keep, now)
	if len(keep) > LimitLong {
		keep = keep[len(keep)-LimitLong:]
	}
	f.unanswered[conn] = keep
	f.announceLimited(s, conn, now)
}

// clearUnanswered clears conn's counts: an answered call from it, or a
// call the member places to it.
func (f *Feature) clearUnanswered(s *vault.Session, conn string, now time.Time) {
	if len(f.unanswered[conn]) == 0 {
		return
	}
	delete(f.unanswered, conn)
	f.announceLimited(s, conn, now)
}

// announceLimited tells the owner devices when conn's limited changes.
func (f *Feature) announceLimited(s *vault.Session, conn string, now time.Time) {
	l := f.limited(conn, now)
	if l == f.limitedSent[conn] {
		return
	}
	if l {
		f.limitedSent[conn] = true
	} else {
		delete(f.limitedSent, conn)
	}
	permissionEvent(s, conn)
}

// sweepLimited announces the connections whose limit has lapsed with time
// (housekeeping).
func (f *Feature) sweepLimited(s *vault.Session, now time.Time) {
	for _, conn := range sortedKeys(f.limitedSent) {
		f.announceLimited(s, conn, now)
	}
}

func permissionEvent(s *vault.Session, conn string) {
	s.NotifyAllDevices("sync.event", strictjson.NewBuilder().String("kind", "call.permission").String("connection_id", conn).Bytes())
}

// setPermission is call.permission.set {connection_id, allowed}: calls from
// and to the connection are allowed (the default) or off.
func (f *Feature) setPermission(s *vault.Session, body []byte) (json.RawMessage, error) {
	if k := s.From().Kind; k != vault.KindApp && k != vault.KindDesktop {
		return nil, vault.NewError("forbidden", "") // the owner's own devices only; not delegable
	}
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	conn, err := o.String("connection_id")
	if err != nil || conn == "" {
		return nil, errBad
	}
	allowed, err := o.Bool("allowed")
	if err != nil {
		return nil, errBad
	}
	if _, ok := s.Connection(conn); !ok {
		return nil, errNotFound
	}
	if allowed == !f.off[conn] {
		return strictjson.NewBuilder().Bytes(), nil // no change
	}
	kind := "call.permission_on"
	if allowed {
		delete(f.off, conn)
	} else {
		f.off[conn] = true
		kind = "call.permission_off"
	}
	s.Record(vault.Activity{Kind: kind, ConnectionID: conn, Audit: true})
	permissionEvent(s, conn)
	return strictjson.NewBuilder().Bytes(), nil
}

// listPermissions is call.permission.list: the connections that differ from
// the default (calls off, or limited now).
func (f *Feature) listPermissions(s *vault.Session, body []byte) (json.RawMessage, error) {
	if k := s.From().Kind; k != vault.KindApp && k != vault.KindDesktop {
		return nil, vault.NewError("forbidden", "")
	}
	if o, err := strictjson.ParseObject(body); err != nil || len(o) != 0 {
		return nil, errBad // {} only
	}
	now := s.Now()
	seen := map[string]bool{}
	for c := range f.off {
		seen[c] = true
	}
	for c := range f.unanswered {
		if f.limited(c, now) {
			seen[c] = true
		}
	}
	arr := []byte{'['}
	for i, c := range sortedKeys(seen) {
		if i > 0 {
			arr = append(arr, ',')
		}
		arr = append(arr, strictjson.NewBuilder().String("connection_id", c).Bool("allowed", !f.off[c]).Bool("limited", f.limited(c, now)).Bytes()...)
	}
	return strictjson.NewBuilder().Raw("connections", append(arr, ']')).Bytes(), nil
}

// dropConnection forgets a removed connection's permission and counts.
func (f *Feature) dropConnection(conn string) {
	delete(f.off, conn)
	delete(f.unanswered, conn)
	delete(f.limitedSent, conn)
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
