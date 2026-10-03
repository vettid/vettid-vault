package location

import (
	"encoding/json"
	"sort"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// The member's own location log (§10.16, owner decision of 2026-10-03):
// off by default (location.history.enabled); when on, the vault records
// the positions the member's devices report, at most one per
// location.history.interval_seconds, for location.history.retention_days.
// It is shown only to the member's own devices and never leaves the
// vault except as a snapshot the member sends through one of their
// existing location shares (location.history.share).

// Log limits (§10.16): with thinning, a year at the finest cadence stays
// under MaxLogPoints (about 1,440 for the last day, 576 for the six days
// before, then 8 a day), so the log never exceeds about 400 KB of state.
const (
	MaxLogPoints    = 5000
	FineWindow      = 24 * time.Hour // full cadence
	MediumWindow    = 7 * 24 * time.Hour
	MediumBucket    = 15 * time.Minute // one point per bucket, 1–7 days old
	CoarseBucket    = 3 * time.Hour    // one point per bucket, older
	MaxLogList      = 1000
	DefaultLogList  = 500
	MaxSnapshot     = 500
	MaxSnapshotRecv = 500
	compactEvery    = time.Hour
)

// LogPoint is one position in the member's log: no altitude, speed or
// heading; latitude and longitude to 5 decimals.
type LogPoint struct {
	At       time.Time `json:"t"`
	Lat      float64   `json:"a"`
	Lon      float64   `json:"o"`
	Accuracy float64   `json:"r,omitempty"`
}

func (p LogPoint) sample() *Sample {
	return &Sample{Lat: p.Lat, Lon: p.Lon, Accuracy: p.Accuracy, At: p.At}
}

// record adds a device's position to the log when the member enabled it
// and the cadence allows (§10.16).
func (f *Feature) record(s *vault.Session, sm *Sample) {
	set := s.Settings()
	if !set.LocationHistoryEnabled() {
		return
	}
	iv := set.LocationHistoryInterval()
	if n := len(f.d.Log); n > 0 && sm.At.Sub(f.d.Log[n-1].At) < iv*9/10 {
		return
	}
	r := Reduce(sm, Exact)
	p := LogPoint{At: ts(sm.At), Lat: r.Lat, Lon: r.Lon, Accuracy: r.Accuracy}
	f.d.Log = append(f.d.Log, p)
	if n := len(f.d.Log); n > 1 && f.d.Log[n-2].At.After(p.At) {
		sort.SliceStable(f.d.Log, func(i, j int) bool { return f.d.Log[i].At.Before(f.d.Log[j].At) })
	}
	if s.Now().Sub(f.d.LogCompacted) >= compactEvery || len(f.d.Log) > MaxLogPoints {
		f.compact(s.Now(), set.LocationHistoryRetention())
	}
}

// compact applies the retention, thins older points (one per 15 minutes
// after a day, one per 3 hours after a week) and caps the log.
func (f *Feature) compact(now time.Time, retention time.Duration) {
	kept := f.d.Log[:0]
	lastBucket := int64(-1)
	for _, p := range f.d.Log {
		age := now.Sub(p.At)
		if age > retention {
			continue
		}
		var b time.Duration
		switch {
		case age > MediumWindow:
			b = CoarseBucket
		case age > FineWindow:
			b = MediumBucket
		}
		if b > 0 {
			k := p.At.UnixNano()/int64(b)*2 + boolInt(b == CoarseBucket)
			if k == lastBucket {
				continue
			}
			lastBucket = k
		} else {
			lastBucket = -1
		}
		kept = append(kept, p)
	}
	if len(kept) > MaxLogPoints {
		kept = kept[len(kept)-MaxLogPoints:]
	}
	f.d.Log = append([]LogPoint(nil), kept...)
	f.d.LogCompacted = ts(now)
}

func boolInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// SettingsChanged implements vault.SettingsObserver: turning the log off
// deletes it; a shorter retention applies at once.
func (f *Feature) SettingsChanged(s *vault.Session, next vault.Settings) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !next.LocationHistoryEnabled() {
		if len(f.d.Log) > 0 {
			s.Record(vault.Activity{Kind: "location.history.deleted", Ref: uitoa(uint64(len(f.d.Log))), Audit: true})
		}
		f.d.Log = nil
		return
	}
	f.compact(s.Now(), next.LocationHistoryRetention())
}

func uitoa(v uint64) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// Range is a parsed time range of the log's types.
type Range struct {
	From, To   time.Time // zero: open
	After      time.Time // list: points after this one
	Limit      int
	ShareID    string
	HasFrom    bool
	HasTo      bool
	HasAfter   bool
	HasShareID bool
}

func optTS(o strictjson.Object, name string) (time.Time, bool, error) {
	v, present, err := o.OptString(name)
	if err != nil {
		return time.Time{}, false, errBad
	}
	if !present {
		return time.Time{}, false, nil
	}
	t, err := envelope.ParseTS(v)
	if err != nil {
		return time.Time{}, false, errBad
	}
	return t, true, nil
}

// ParseRange parses location.history.list (list), .delete and .share
// (share: share_id required) bodies strictly.
func ParseRange(body []byte, list, share bool) (*Range, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	r := &Range{Limit: DefaultLogList}
	if r.From, r.HasFrom, err = optTS(o, "from"); err != nil {
		return nil, err
	}
	if r.To, r.HasTo, err = optTS(o, "to"); err != nil {
		return nil, err
	}
	if r.HasFrom && r.HasTo && r.To.Before(r.From) {
		return nil, errBad
	}
	if list {
		if r.After, r.HasAfter, err = optTS(o, "after"); err != nil {
			return nil, err
		}
		n, present, err := o.OptUint("limit", 1, MaxLogList)
		if err != nil {
			return nil, errBad
		}
		if present {
			r.Limit = int(n)
		}
	} else if o.Has("after") || o.Has("limit") {
		return nil, errBad
	}
	if share {
		if r.ShareID, err = ulid(o, "share_id"); err != nil {
			return nil, err
		}
		if !r.HasFrom || !r.HasTo {
			return nil, errBad // a snapshot is an explicit range
		}
	} else if o.Has("share_id") {
		return nil, errBad
	}
	return r, nil
}

func (r *Range) in(t time.Time) bool {
	return (!r.HasFrom || !t.Before(r.From)) && (!r.HasTo || !t.After(r.To))
}

func pointJSON(p LogPoint) []byte {
	return strictjson.NewBuilder().Raw("lat", fmtNum(p.Lat)).Raw("lon", fmtNum(p.Lon)).Raw("accuracy_m", fmtNum(p.Accuracy)).
		String("at", envelope.FormatTS(p.At)).Bytes()
}

// historyList returns the log, oldest first, paged by `after`.
func (f *Feature) historyList(s *vault.Session, body []byte) (json.RawMessage, error) {
	r, err := ParseRange(body, true, false)
	if err != nil {
		return nil, err
	}
	set := s.Settings()
	arr := []byte{'['}
	n := 0
	var last time.Time
	more := false
	for _, p := range f.d.Log {
		if !r.in(p.At) || r.HasAfter && !p.At.After(r.After) {
			continue
		}
		if n == r.Limit {
			more = true
			break
		}
		if n > 0 {
			arr = append(arr, ',')
		}
		arr = append(arr, pointJSON(p)...)
		last = p.At
		n++
	}
	b := strictjson.NewBuilder().Bool("enabled", set.LocationHistoryEnabled()).
		Uint("retention_days", uint64(set.LocationHistoryRetention()/(24*time.Hour))).
		Uint("interval_seconds", uint64(set.LocationHistoryInterval()/time.Second)).
		Uint("count", uint64(len(f.d.Log))).Raw("points", append(arr, ']'))
	if more {
		b.String("next", envelope.FormatTS(last))
	}
	return b.Bytes(), nil
}

func (f *Feature) historyDelete(s *vault.Session, body []byte) (json.RawMessage, error) {
	r, err := ParseRange(body, false, false)
	if err != nil {
		return nil, err
	}
	kept := f.d.Log[:0]
	deleted := 0
	for _, p := range f.d.Log {
		if r.in(p.At) {
			deleted++
			continue
		}
		kept = append(kept, p)
	}
	f.d.Log = append([]LogPoint(nil), kept...)
	if deleted > 0 {
		s.Record(vault.Activity{Kind: "location.history.deleted", DeviceID: s.From().ID, Ref: uitoa(uint64(deleted)), Audit: true})
		s.SyncEvent("location.history.changed", strictjson.NewBuilder().Uint("count", uint64(len(f.d.Log))).Bytes())
	}
	return strictjson.NewBuilder().Uint("deleted", uint64(deleted)).Bytes(), nil
}

// historyShare sends the connection of an active outgoing share a
// snapshot of the log in a range, reduced to the share's precision: the
// only way the log leaves the vault (§10.16).
func (f *Feature) historyShare(s *vault.Session, body []byte) (json.RawMessage, error) {
	r, err := ParseRange(body, false, true)
	if err != nil {
		return nil, err
	}
	o := f.d.Out[r.ShareID]
	if o == nil {
		return nil, errNotFound
	}
	var sel []LogPoint
	for _, p := range f.d.Log {
		if r.in(p.At) {
			sel = append(sel, p)
		}
	}
	if len(sel) > MaxSnapshot {
		sel = sel[len(sel)-MaxSnapshot:] // the newest
	}
	arr := []byte{'['}
	for i, p := range sel {
		if i > 0 {
			arr = append(arr, ',')
		}
		arr = append(arr, Reduce(p.sample(), o.Precision).json("", "", false)...)
	}
	b := strictjson.NewBuilder().String("share_id", o.ID).Raw("points", append(arr, ']'))
	if err := s.SendToConnection(o.Conn, "location.snapshot", b.Bytes()); err != nil {
		return nil, errConn
	}
	s.Record(vault.Activity{Kind: "location.history.shared", ConnectionID: o.Conn, Ref: o.ID, Direction: "out", Audit: true})
	return strictjson.NewBuilder().Uint("sent", uint64(len(sel))).Bytes(), nil
}

// ParseSnapshot parses a connection's location.snapshot body strictly.
func ParseSnapshot(body []byte) (string, []Sample, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return "", nil, errBad
	}
	id, err := ulid(o, "share_id")
	if err != nil {
		return "", nil, err
	}
	arr, err := o.Array("points")
	if err != nil || len(arr) > MaxSnapshotRecv {
		return "", nil, errBad
	}
	out := make([]Sample, 0, len(arr))
	for _, raw := range arr {
		_, sm, err := ParseSample(raw, false)
		if err != nil {
			return "", nil, errBad
		}
		out = append(out, *sm)
	}
	return id, out, nil
}

// snapshot keeps a snapshot the sharer sent with its incoming share
// (deleted with it).
func (f *Feature) snapshot(s *vault.Session, body []byte) {
	conn := s.From().ID
	id, pts, err := ParseSnapshot(body)
	if err != nil {
		f.drop(s, "drop.location_malformed")
		return
	}
	sh := f.d.In[id]
	if sh == nil || sh.Conn != conn {
		f.drop(s, "drop.location")
		return
	}
	now := ts(s.Now())
	for i := range pts {
		pts[i].Received = now
	}
	sh.Snapshot = pts
	s.NotifyAllDevices("location.event", event("snapshot", "in", conn, id).Uint("points", uint64(len(pts))).Bytes())
	s.Record(vault.Activity{Kind: "location.history.received", ConnectionID: conn, Ref: id, Direction: "in", Audit: true})
}
