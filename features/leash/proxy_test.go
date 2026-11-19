package leash

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/features/itemspec"
	"github.com/vettid/vettid-vault/internal/featuretest"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/strictjson"
)

// proxyBody is an item.proxy of the item's field with host; extra members
// are spliced in as given (`,"seconds":60`).
func proxyBody(item, field, host, extra string) string {
	return `{"op":"item.proxy","item_id":"` + item + `","field_id":"` + field + `","host":"` + host + `"` + extra + `}`
}

// setProxy gives the agent's item the proxy way.
func (r *rig) setProxy(item string, version uint64, header, prefix string, hosts ...string) {
	if r.it.ways == nil {
		r.it.ways = map[[2]string]*itemspec.ItemWays{}
	}
	r.it.ways[[2]string{agent, item}] = &itemspec.ItemWays{Version: version, Ways: []string{itemspec.WayUse, itemspec.WayProxy},
		Proxy: &itemspec.ProxyWays{Hosts: hosts, Header: header, Prefix: prefix}}
}

// session gives the agent an access session ending at end (zero: none).
func (r *rig) session(end time.Time) {
	p := r.h.Devices[agent]
	p.SessionExpires = end
	r.h.Devices[agent] = p
}

// proxyRig is a rig whose agent's rule includes wifi, bound to
// api.example.com with Authorization: Bearer, and a session of an hour.
func proxyRig(t *testing.T) *rig {
	r := newRig(t)
	r.rule(t, Auto, 0, 60, r.wifi)
	r.setProxy(r.wifi, 3, "Authorization", "Bearer ", "api.example.com")
	r.session(t0.Add(time.Hour))
	return r
}

// heldNote is what an item.proxy for wifi on api.example.com is held with.
const heldNote = `{"host":"api.example.com","header":"Authorization","prefix":"Bearer "}`

// §10.11: an item.proxy is always referred, even under an auto rule
// within its windows, held with a note of the host, header and prefix;
// sent to the handler without an approval it is forbidden, nothing read.
func TestProxyAlwaysReferred(t *testing.T) {
	r := proxyRig(t)
	body := proxyBody(r.wifi, "f1", "api.example.com", "")
	d, s := r.decideS(t0, body)
	if d != vault.AgentAsk {
		t.Fatalf("decided %v", d)
	}
	if a := s.HeldApproval(); string(a.Note) != heldNote || len(a.Flags) != 0 || a.PreviousSHA256 != "" {
		t.Fatalf("held with %+v", a)
	}
	if r.f.d.Agents[agent].Referred != 1 {
		t.Fatalf("referral not counted")
	}
	if res := featuretest.Call(r.f, r.h, t0, vault.KindAgent, "agent.request", body); res.Code != "forbidden" || r.it.used[r.wifi] != 0 {
		t.Fatalf("unapproved: %q, used %d", res.Code, r.it.used[r.wifi])
	}
	// Past the referral cap: throttled, nothing counted in the windows.
	rc := proxyRig(t)
	rc.f.agent(vault.NewSession(context.Background(), rc.h, vault.PeerInfo{}, t0, nil), agent).Referred = MaxReferralsPerHour
	if d, _ := rc.decideS(t0, proxyBody(rc.wifi, "f1", "api.example.com", "")); d != vault.AgentDeny || !rc.h.HasActivity("leash.referrals_limited") {
		t.Fatalf("past the cap: %v", d)
	}
}

// §10.11: approved, the answer carries the value, the header, the prefix,
// the bound host and expires_at; it is audited as leash.item.proxy
// (summarised) and counted as a use.
func TestProxyApproved(t *testing.T) {
	r := proxyRig(t)
	res, err := r.approved(t0, proxyBody(r.wifi, "f1", "api.example.com", ""), json.RawMessage(heldNote))
	want := `{"item_id":"` + r.wifi + `","field_id":"f1","value":"hunter22","header":"Authorization","prefix":"Bearer ",` +
		`"host":"api.example.com","expires_at":"2026-10-03T12:15:00.000Z"}`
	if err != nil || string(res) != want {
		t.Fatalf("%v %s\nwant %s", err, res, want)
	}
	if r.it.used[r.wifi] != 1 || !r.h.HasActivity(KindProxy) {
		t.Fatalf("used %d, audited %v", r.it.used[r.wifi], r.h.HasActivity(KindProxy))
	}
	// The host with its default port written out is the same bound host;
	// the answer names it as the settings do.
	res, err = r.approved(t0, proxyBody(r.wifi, "f1", "api.example.com:443", ""), json.RawMessage(heldNote))
	if err != nil || !strings.Contains(string(res), `"host":"api.example.com"`) {
		t.Fatalf(":443: %v %s", err, res)
	}
}

// §10.11: settings without the proxy way are way_not_allowed {ways}, and
// a host the item does not bind bad_request; each counted as refused with
// the cooldown, and refused alike at approval, nothing read.
func TestProxyRefusals(t *testing.T) {
	cases := []struct {
		name, host, code, body string
		setup                  func(r *rig)
	}{
		{"absent settings", "api.example.com", "way_not_allowed", `{"ways":["use"]}`, func(r *rig) { r.it.ways = nil }},
		{"no proxy way", "api.example.com", "way_not_allowed", `{"ways":["use","reveal"]}`, func(r *rig) { r.reveal(r.wifi) }},
		{"another host", "evil.example.com", "bad_request", "", func(r *rig) {}},
		{"another port", "api.example.com:8443", "bad_request", "", func(r *rig) {}},
		{"a subdomain", "x.api.example.com", "bad_request", "", func(r *rig) {}},
	}
	for _, c := range cases {
		r := proxyRig(t)
		c.setup(r)
		body := proxyBody(r.wifi, "f1", c.host, "")
		d, s := r.decideS(t0, body)
		if d != vault.AgentDeny || s.AgentRefusal() == nil || s.AgentRefusal().Code != c.code || c.body != "" && string(s.AgentRefusal().Body) != c.body {
			t.Fatalf("%s: %v %+v", c.name, d, s.AgentRefusal())
		}
		if !r.h.HasActivity(KindRefused) {
			t.Fatalf("%s: not counted as refused", c.name)
		}
		if cl := r.f.d.Agents[agent].Cool[ScopeItems]; cl == nil || !t0.Before(cl.Until) {
			t.Fatalf("%s: no cooldown", c.name)
		}
		if _, err := r.approved(t0, body, json.RawMessage(heldNote)); codeOf(err) != c.code {
			t.Fatalf("%s at approval: %v", c.name, err)
		}
		if r.it.used[r.wifi] != 0 {
			t.Fatalf("%s: read", c.name)
		}
	}
}

// §10.11: seconds is 60–3,600 (bad_request otherwise), default 900, and
// the proxy is cut to the access session's end; with no session left it
// is session_required, nothing read. A member item.proxy does not define
// (a header or a prefix the approval would show) is bad_request too.
func TestProxySeconds(t *testing.T) {
	r := proxyRig(t)
	for _, extra := range []string{`,"seconds":59`, `,"seconds":3601`, `,"seconds":0`, `,"seconds":-1`, `,"seconds":"900"`, `,"seconds":900.5`,
		`,"header":"X-Harmless"`, `,"prefix":""`, `,"value":"x"`, `,"fields":["f1"]`} {
		if res := featuretest.Call(r.f, r.h, t0, vault.KindAgent, "agent.request", proxyBody(r.wifi, "f1", "api.example.com", extra)); res.Code != "bad_request" {
			t.Fatalf("%s: %q", extra, res.Code)
		}
	}
	expiry := func(r *rig, extra string) (string, string) {
		res, err := r.approved(t0, proxyBody(r.wifi, "f1", "api.example.com", extra), json.RawMessage(heldNote))
		if err != nil {
			return "", codeOf(err)
		}
		o, _ := strictjson.ParseObject(res)
		v, _ := o.String("expires_at")
		return v, ""
	}
	cases := []struct {
		name, extra string
		session     time.Time
		want, code  string
	}{
		{"60", `,"seconds":60`, t0.Add(time.Hour), "2026-10-03T12:01:00.000Z", ""},
		{"3600", `,"seconds":3600`, t0.Add(2 * time.Hour), "2026-10-03T13:00:00.000Z", ""},
		{"cut to the session", `,"seconds":3600`, t0.Add(10 * time.Minute), "2026-10-03T12:10:00.000Z", ""},
		{"default cut", "", t0.Add(30 * time.Second), "2026-10-03T12:00:30.000Z", ""},
		{"session ended", "", t0, "", "session_required"},
		{"no session", "", time.Time{}, "", "session_required"},
	}
	for _, c := range cases {
		r := proxyRig(t)
		r.session(c.session)
		got, code := expiry(r, c.extra)
		if got != c.want || code != c.code {
			t.Fatalf("%s: %q %q", c.name, got, code)
		}
		if c.code != "" && r.it.used[r.wifi] != 0 {
			t.Fatalf("%s: read", c.name)
		}
	}
}

// §10.11: a value that is not visible ASCII and spaces cannot go in a
// header (bad_request, the value not sent, nothing audited as a proxy);
// an address field is not_found.
func TestProxyHeaderSafeValue(t *testing.T) {
	for _, v := range []string{"a\r\nX-Evil: 1", "a\nb", "tab\there", "nul\x00", "del\x7f", "ünïcode"} {
		r := proxyRig(t)
		r.it.items[r.wifi].Fields[0].Value = json.RawMessage(strictjson.MarshalString(v))
		res, err := r.approved(t0, proxyBody(r.wifi, "f1", "api.example.com", ""), json.RawMessage(heldNote))
		// The use is counted: the value was read to be judged (lead's call).
		if codeOf(err) != "bad_request" || res != nil || r.h.HasActivity(KindProxy) || r.it.used[r.wifi] != 1 {
			t.Fatalf("%q: %v %s used=%d", v, err, res, r.it.used[r.wifi])
		}
	}
	r := proxyRig(t)
	r.it.items[r.wifi].Fields[0].Value = json.RawMessage(strictjson.MarshalString(" visible ~ ascii and spaces "))
	if _, err := r.approved(t0, proxyBody(r.wifi, "f1", "api.example.com", ""), json.RawMessage(heldNote)); err != nil {
		t.Fatalf("safe value: %v", err)
	}
	if _, err := r.approved(t0, proxyBody(r.wifi, "f2", "api.example.com", ""), json.RawMessage(heldNote)); codeOf(err) != "not_found" {
		t.Fatalf("address field: %v", err)
	}
}

// §10.11: settings that change while a proxy waits. A host no longer
// bound, or the way dropped, is refused at approval; a header or prefix
// the approval did not show is referred again as a new approval (never the
// value on the old one); an approval with no note is forbidden.
func TestProxyChangedWhileHeld(t *testing.T) {
	body := func(r *rig) string { return proxyBody(r.wifi, "f1", "api.example.com", "") }
	r := proxyRig(t)
	r.setProxy(r.wifi, 4, "Authorization", "Bearer ", "other.example.com")
	if _, err := r.approved(t0, body(r), json.RawMessage(heldNote)); codeOf(err) != "bad_request" {
		t.Fatalf("host dropped: %v", err)
	}
	for _, c := range []struct{ name, header, prefix string }{
		{"header", "X-Api-Key", "Bearer "},
		{"header case", "authorization", "Bearer "},
		{"prefix", "Authorization", "Token "},
	} {
		r := proxyRig(t)
		r.setProxy(r.wifi, 4, c.header, c.prefix, "api.example.com")
		_, err := r.approved(t0, body(r), json.RawMessage(heldNote))
		var ra *vault.ReferAgainError
		if !errors.As(err, &ra) {
			t.Fatalf("%s: %v", c.name, err)
		}
		var n proxyNote
		if json.Unmarshal(ra.Approval.Note, &n) != nil || n.Header != c.header || n.Prefix != c.prefix {
			t.Fatalf("%s: new note %s", c.name, ra.Approval.Note)
		}
		if r.it.used[r.wifi] != 0 || r.f.d.Agents[agent].Referred != 1 {
			t.Fatalf("%s: read %d, referred %d", c.name, r.it.used[r.wifi], r.f.d.Agents[agent].Referred)
		}
	}
	// Referred again past the cap: forbidden, throttled.
	rc := proxyRig(t)
	rc.setProxy(rc.wifi, 4, "X-Api-Key", "", "api.example.com")
	rc.f.agent(vault.NewSession(context.Background(), rc.h, vault.PeerInfo{}, t0, nil), agent).Referred = MaxReferralsPerHour
	if _, err := rc.approved(t0, body(rc), json.RawMessage(heldNote)); codeOf(err) != "forbidden" || !rc.h.HasActivity("leash.referrals_limited") {
		t.Fatalf("past the cap: %v", err)
	}
	for _, note := range []string{"", "{}", `{"host":""}`, "not json"} {
		r := proxyRig(t)
		if _, err := r.approved(t0, body(r), json.RawMessage(note)); codeOf(err) != "forbidden" || r.it.used[r.wifi] != 0 {
			t.Fatalf("note %q: %v", note, err)
		}
	}
}
