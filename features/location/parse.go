package location

import (
	"math"
	"strconv"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/envelope"
)

var (
	errBad      = vault.NewError("bad_request", "")
	errNotFound = vault.NewError("not_found", "")
	errLimit    = vault.NewError("limit", "")
	errConn     = vault.NewError("connection_unavailable", "")
)

func ulid(o strictjson.Object, name string) (string, error) {
	v, err := o.String(name)
	if err != nil || !envelope.ValidULID(v) {
		return "", errBad
	}
	return v, nil
}

func connID(o strictjson.Object) (string, error) {
	v, err := o.String("connection_id")
	if err != nil || v == "" || len(v) > 64 {
		return "", errBad
	}
	return v, nil
}

// number parses an optional JSON number member within [min, max].
func number(o strictjson.Object, name string, min, max float64) (float64, bool, error) {
	raw, ok := o[name]
	if !ok {
		return 0, false, nil
	}
	if len(raw) == 0 || len(raw) > 32 || !(raw[0] == '-' || raw[0] >= '0' && raw[0] <= '9') {
		return 0, true, errBad
	}
	v, err := strconv.ParseFloat(string(raw), 64)
	if err != nil || math.IsNaN(v) || math.IsInf(v, 0) || v < min || v > max {
		return 0, true, errBad
	}
	if v == 0 {
		v = 0 // no negative zero
	}
	return v, true, nil
}

func fmtNum(v float64) []byte { return []byte(strconv.FormatFloat(v, 'f', -1, 64)) }

// cleanText reports whether s has no control characters.
func cleanText(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return false
		}
	}
	return true
}

// Sample is one location fix.
type Sample struct {
	Lat      float64   `json:"lat"`
	Lon      float64   `json:"lon"`
	Accuracy float64   `json:"accuracy_m"`
	Altitude *float64  `json:"altitude_m,omitempty"`
	Speed    *float64  `json:"speed_mps,omitempty"`
	Heading  *float64  `json:"heading_deg,omitempty"`
	At       time.Time `json:"at"`
	Received time.Time `json:"received_at,omitempty"`
}

// Ranges of a sample (§10.16).
const (
	MaxAccuracy = 1e6
	MaxAltitude = 1e5
	MaxSpeed    = 1e4
	MaxFuture   = 5 * time.Minute
	MaxAge      = time.Hour
)

// ParseSample parses a device's location.update body, or (peer true) a
// connection's, which also carries share_id. It checks shapes and ranges;
// the caller checks `at` against the clock.
func ParseSample(body []byte, peer bool) (string, *Sample, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return "", nil, errBad
	}
	shareID := ""
	if peer {
		if shareID, err = ulid(o, "share_id"); err != nil {
			return "", nil, err
		}
	}
	sm := &Sample{}
	var ok bool
	if sm.Lat, ok, err = number(o, "lat", -90, 90); err != nil || !ok {
		return "", nil, errBad
	}
	if sm.Lon, ok, err = number(o, "lon", -180, 180); err != nil || !ok {
		return "", nil, errBad
	}
	if sm.Accuracy, _, err = number(o, "accuracy_m", 0, MaxAccuracy); err != nil {
		return "", nil, errBad
	}
	opt := func(name string, min, max float64, dst **float64) error {
		v, ok, err := number(o, name, min, max)
		if err != nil {
			return errBad
		}
		if ok {
			*dst = &v
		}
		return nil
	}
	if err := opt("altitude_m", -MaxAltitude, MaxAltitude, &sm.Altitude); err != nil {
		return "", nil, err
	}
	if err := opt("speed_mps", 0, MaxSpeed, &sm.Speed); err != nil {
		return "", nil, err
	}
	if err := opt("heading_deg", 0, 359.999999, &sm.Heading); err != nil {
		return "", nil, err
	}
	at, err := o.String("at")
	if err != nil {
		return "", nil, errBad
	}
	if sm.At, err = envelope.ParseTS(at); err != nil {
		return "", nil, errBad
	}
	return shareID, sm, nil
}

// json encodes a sample; shareID and conn are added when not empty.
func (sm *Sample) json(conn, shareID string, received bool) []byte {
	b := strictjson.NewBuilder()
	if conn != "" {
		b.String("connection_id", conn)
	}
	if shareID != "" {
		b.String("share_id", shareID)
	}
	b.Raw("lat", fmtNum(sm.Lat)).Raw("lon", fmtNum(sm.Lon)).Raw("accuracy_m", fmtNum(sm.Accuracy))
	if sm.Altitude != nil {
		b.Raw("altitude_m", fmtNum(*sm.Altitude))
	}
	if sm.Speed != nil {
		b.Raw("speed_mps", fmtNum(*sm.Speed))
	}
	if sm.Heading != nil {
		b.Raw("heading_deg", fmtNum(*sm.Heading))
	}
	b.String("at", envelope.FormatTS(sm.At))
	if received && !sm.Received.IsZero() {
		b.String("received_at", envelope.FormatTS(sm.Received))
	}
	return b.Bytes()
}

// Precisions (§10.16).
const (
	Exact       = "exact"
	Approximate = "approximate"
	City        = "city"
)

func validPrecision(p string) bool { return p == Exact || p == Approximate || p == City }

func round(v float64, decimals int) float64 {
	p := math.Pow(10, float64(decimals))
	return math.Round(v*p) / p
}

func clamp(v, lo, hi float64) float64 { return math.Max(lo, math.Min(hi, v)) }

// snap moves v to the centre of its cell of size cell degrees.
func snap(v, cell float64, decimals int, lo, hi float64) float64 {
	c := math.Floor(v/cell)*cell + cell/2
	return clamp(round(c, decimals), lo, hi)
}

// Reduce applies a share's precision to a sample (§10.16): exact keeps
// about a metre; approximate and city snap to the centre of a 0.01° or
// 0.1° cell, raise the accuracy to 1 km or 10 km and drop altitude,
// speed and heading.
func Reduce(sm *Sample, precision string) *Sample {
	out := &Sample{At: sm.At, Accuracy: sm.Accuracy}
	switch precision {
	case Approximate, City:
		cell, dec, acc := 0.01, 3, 1000.0
		if precision == City {
			cell, dec, acc = 0.1, 2, 10000.0
		}
		out.Lat = snap(sm.Lat, cell, dec, -90, 90)
		out.Lon = snap(sm.Lon, cell, dec, -180, 180)
		out.Accuracy = math.Max(sm.Accuracy, acc)
	default:
		out.Lat = clamp(round(sm.Lat, 5), -90, 90)
		out.Lon = clamp(round(sm.Lon, 5), -180, 180)
		out.Altitude, out.Speed, out.Heading = sm.Altitude, sm.Speed, sm.Heading
	}
	return out
}

// Modes.
const (
	Once       = "once"
	Continuous = "continuous"
)

// Limits (§10.16).
const (
	OnceTTL          = 15 * time.Minute
	MinDuration      = 300
	MaxDuration      = 7 * 24 * 3600
	DefaultDuration  = 3600
	MinInterval      = 10
	MaxInterval      = 3600
	DefaultInterval  = 60
	MaxOutgoing      = 64
	MaxIncoming      = 256
	MaxHistory       = 1000
	MaxNote          = 256
	MaxRequestsIn    = 16
	RequestTTL       = 24 * time.Hour
	RequestEvery     = 10 * time.Minute
	MinPeerGap       = 5 * time.Second
	MaxUpdateExpSkew = 24 * time.Hour
)

// Start is a parsed location.share.start body.
type Start struct {
	ConnectionID string
	Mode         string
	Precision    string
	Duration     time.Duration
	Interval     time.Duration
	History      bool
	RequestID    string
}

// ParseStart parses location.share.start strictly.
func ParseStart(body []byte) (*Start, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	st := &Start{Precision: Approximate} // owner decision 2026-10-03: approximate by default
	if st.ConnectionID, err = connID(o); err != nil {
		return nil, err
	}
	if st.Mode, err = o.String("mode"); err != nil || st.Mode != Once && st.Mode != Continuous {
		return nil, errBad
	}
	if p, present, err := o.OptString("precision"); err != nil || present && !validPrecision(p) {
		return nil, errBad
	} else if present {
		st.Precision = p
	}
	d, hasD, err := o.OptUint("duration_seconds", MinDuration, MaxDuration)
	if err != nil {
		return nil, errBad
	}
	iv, hasI, err := o.OptUint("interval_seconds", MinInterval, MaxInterval)
	if err != nil {
		return nil, errBad
	}
	if st.Mode == Once {
		if hasD || hasI {
			return nil, errBad
		}
		st.Duration = OnceTTL
	} else {
		if !hasD {
			d = DefaultDuration
		}
		if !hasI {
			iv = DefaultInterval
		}
		st.Duration, st.Interval = time.Duration(d)*time.Second, time.Duration(iv)*time.Second
	}
	if o.Has("history") {
		if st.History, err = o.Bool("history"); err != nil {
			return nil, errBad
		}
	}
	if id, present, err := o.OptString("request_id"); err != nil || present && !envelope.ValidULID(id) {
		return nil, errBad
	} else {
		st.RequestID = id
	}
	return st, nil
}

// Shared is a parsed location.shared body (from a connection).
type Shared struct {
	ShareID   string
	Mode      string
	Precision string
	Interval  time.Duration
	History   bool
	Expires   time.Time
}

// ParseShared parses a connection's location.shared strictly (the caller
// checks expires_at against the clock).
func ParseShared(body []byte) (*Shared, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	sh := &Shared{}
	if sh.ShareID, err = ulid(o, "share_id"); err != nil {
		return nil, err
	}
	if sh.Mode, err = o.String("mode"); err != nil || sh.Mode != Once && sh.Mode != Continuous {
		return nil, errBad
	}
	if sh.Precision, err = o.String("precision"); err != nil || !validPrecision(sh.Precision) {
		return nil, errBad
	}
	iv, hasI, err := o.OptUint("interval_seconds", MinInterval, MaxInterval)
	if err != nil || hasI != (sh.Mode == Continuous) {
		return nil, errBad
	}
	sh.Interval = time.Duration(iv) * time.Second
	if sh.History, err = o.Bool("history"); err != nil {
		return nil, errBad
	}
	exp, err := o.String("expires_at")
	if err != nil {
		return nil, errBad
	}
	if sh.Expires, err = envelope.ParseTS(exp); err != nil {
		return nil, errBad
	}
	return sh, nil
}

// ParseShareID parses {share_id} (location.share.stop, location.stopped).
func ParseShareID(body []byte) (string, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return "", errBad
	}
	return ulid(o, "share_id")
}

// Get is a parsed location.get body.
type Get struct {
	ConnectionID string
	History      bool
}

// ParseGet parses location.get strictly.
func ParseGet(body []byte) (*Get, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	g := &Get{}
	if g.ConnectionID, err = connID(o); err != nil {
		return nil, err
	}
	if o.Has("history") {
		if g.History, err = o.Bool("history"); err != nil {
			return nil, errBad
		}
	}
	return g, nil
}

// Request is a parsed location.request body (from a device) or
// location.requested body (from a connection, with request_id).
type Request struct {
	ConnectionID string
	RequestID    string
	Note         string
}

// ParseRequest parses location.request (peer false) or
// location.requested (peer true) strictly.
func ParseRequest(body []byte, peer bool) (*Request, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	r := &Request{}
	if peer {
		if r.RequestID, err = ulid(o, "request_id"); err != nil {
			return nil, err
		}
	} else if r.ConnectionID, err = connID(o); err != nil {
		return nil, err
	}
	n, _, err := o.OptString("note")
	if err != nil || len(n) > MaxNote || !cleanText(n) {
		return nil, errBad
	}
	r.Note = n
	return r, nil
}

func emptyObject(body []byte) error {
	if _, err := strictjson.ParseObject(body); err != nil {
		return errBad
	}
	return nil
}
