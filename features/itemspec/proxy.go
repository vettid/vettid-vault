package itemspec

import (
	"errors"
	"time"

	"github.com/vettid/vettid-vault/vms/strictjson"
)

// Limits of an item.proxy request (VAULT-MESSAGING §10.11, 0.42.0).
const (
	MinProxySeconds     = 60
	MaxProxySeconds     = 3600
	DefaultProxySeconds = 900
)

// ProxyRequest is a parsed item.proxy request, without its item_id.
type ProxyRequest struct {
	FieldID string
	Host    string
	// Seconds is the asked lifetime, DefaultProxySeconds when absent.
	Seconds uint64
}

// ErrProxy is a malformed item.proxy (bad_request).
var ErrProxy = errors.New("itemspec: bad item.proxy")

// ParseProxyRequest parses an item.proxy request's members other than op
// and item_id (§10.11): field_id; host, a proxy host by the binding's
// rule (whether the item binds it is JudgeProxy's); seconds, 60–3,600,
// default 900.
func ParseProxyRequest(o strictjson.Object) (*ProxyRequest, error) {
	p := &ProxyRequest{}
	var err error
	if p.FieldID, err = o.String("field_id"); err != nil || !ValidFieldID(p.FieldID) {
		return nil, ErrProxy
	}
	if p.Host, err = o.String("host"); err != nil || !ValidProxyHost(p.Host) {
		return nil, ErrProxy
	}
	secs, present, err := o.OptUint("seconds", MinProxySeconds, MaxProxySeconds)
	if err != nil {
		return nil, ErrProxy
	}
	p.Seconds = DefaultProxySeconds
	if present {
		p.Seconds = secs
	}
	return p, nil
}

// ProxyJudgement is the decision on an item.proxy under an item's
// settings (§10.11).
type ProxyJudgement struct {
	// Refusal is "way_not_allowed" (the settings do not hold proxy) or
	// "host_not_bound" (host is not one of the item's hosts, answered
	// bad_request), or "" when allowed. An allowed proxy is always
	// referred to an app.
	Refusal string
	// Host is the bound host as the settings hold it, Header and Prefix
	// the settings' (when allowed).
	Host, Header, Prefix string
}

// RefusalHostNotBound is JudgeProxy's refusal of a host the item does not
// bind. The spec names no code for it, so it is answered bad_request.
const RefusalHostNotBound = "host_not_bound"

// JudgeProxy gives the decision on p under the item's settings w (nil:
// ["use"]). Hosts compare with the default port made explicit (HostKey),
// as the binding's do.
func JudgeProxy(w *ItemWays, p *ProxyRequest) ProxyJudgement {
	if !w.Has(WayProxy) || w.Proxy == nil {
		return ProxyJudgement{Refusal: "way_not_allowed"}
	}
	for _, h := range w.Proxy.Hosts {
		if HostKey(h) == HostKey(p.Host) {
			return ProxyJudgement{Host: h, Header: w.Proxy.Header, Prefix: w.Proxy.Prefix}
		}
	}
	return ProxyJudgement{Refusal: RefusalHostNotBound}
}

// HeaderSafe reports whether a value can go in an HTTP header: visible
// ASCII and spaces only (§10.11). No CR, LF, NUL or other control
// character, and nothing outside ASCII, so it cannot end the field or
// start another.
func HeaderSafe(v string) bool {
	for i := 0; i < len(v); i++ {
		if v[i] < 0x20 || v[i] > 0x7e {
			return false
		}
	}
	return true
}

// ProxyExpiry is when a proxy asked at now for secs seconds ends: now +
// secs, cut to the access session's end (§10.11). ok is false when there
// is no session left (sessionEnd zero or not after now): the proxy is not
// given.
func ProxyExpiry(now time.Time, secs uint64, sessionEnd time.Time) (time.Time, bool) {
	if sessionEnd.IsZero() || !now.Before(sessionEnd) {
		return time.Time{}, false
	}
	end := now.Add(time.Duration(secs) * time.Second)
	if sessionEnd.Before(end) {
		end = sessionEnd
	}
	return end.UTC().Truncate(time.Millisecond), true
}
