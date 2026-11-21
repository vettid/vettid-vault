package handshake

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/strictjson"
)

// An hs.resp the initiator opens and then refuses (sig_R, the clock) has
// its body, which carries the request token, wiped; an accepted one is
// handed on in the Result with its body intact.
func TestDroppedRespWiped(t *testing.T) {
	wipedBody := func(b []byte) bool { return len(b) > 0 && bytes.Count(b, []byte{0}) == len(b) }
	for _, c := range []struct {
		name    string
		mallory bool
		at      time.Time
		want    error
	}{
		{"sig_R refused", true, t0, ErrSigResp},
		{"refused for the clock", false, t0.Add(envelope.MaxDurableAge + time.Hour), envelope.ErrClockPast},
		{"accepted", false, t0, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			i, r, mallory := newParty(t, 0x10), newParty(t, 0x20), newParty(t, 0x30)
			ini, err := NewInitiator(initCfg(i, r, PurposeConnection))
			if err != nil {
				t.Fatal(err)
			}
			p, err := OpenInit(ini.Envelope(), r.lookup, t0)
			if err != nil {
				t.Fatal(err)
			}
			rc := respCfg(i, r, PurposeConnection)
			if c.mallory {
				rc.Identity = mallory.ik
			}
			_, respEnv, err := p.Respond(rc)
			if err != nil {
				t.Fatal(err)
			}
			var drops []*envelope.Inner
			testDropHook = func(in *envelope.Inner) { drops = append(drops, in) }
			defer func() { testDropHook = nil }()
			res, err := ini.HandleResp(respEnv, r.relayPK(), c.at)
			if !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
			if c.want == nil {
				if len(drops) != 0 || res.Inner == nil || wipedBody(res.Inner.Body) {
					t.Fatal("an accepted hs.resp was dropped or wiped")
				}
				return
			}
			if len(drops) != 1 || drops[0].Type != TypeResp || !wipedBody(drops[0].Body) {
				t.Fatalf("drops = %d, want one wiped hs.resp", len(drops))
			}
		})
	}
}

// ParseResp wipes its parsed members, the token's copy included.
func TestParseRespWipesItsCopies(t *testing.T) {
	i, r := newParty(t, 0x10), newParty(t, 0x20)
	ini, err := NewInitiator(initCfg(i, r, PurposeConnection))
	if err != nil {
		t.Fatal(err)
	}
	p, err := OpenInit(ini.Envelope(), r.lookup, t0)
	if err != nil {
		t.Fatal(err)
	}
	_, respEnv, err := p.Respond(respCfg(i, r, PurposeConnection))
	if err != nil {
		t.Fatal(err)
	}
	var seen []strictjson.Object
	testRespParsedHook = func(o strictjson.Object) { seen = append(seen, o) }
	defer func() { testRespParsedHook = nil }()
	if _, err := ini.HandleResp(respEnv, r.relayPK(), t0); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 1 || !seen[0].Has("sig") {
		t.Fatalf("%d parses of hs.resp seen", len(seen))
	}
	for k, v := range seen[0] {
		if bytes.Count(v, []byte{0}) != len(v) {
			t.Fatalf("member %q kept its value", k)
		}
	}
}
