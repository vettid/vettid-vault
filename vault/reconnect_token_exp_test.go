package vault

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"

	"github.com/vettid/vettid-vault/vms/peerwire"
)

// relay.token.issued{kind: reconnect} replaces the held reconnect token only
// if its exp is later (as §6.3.1 adopts a carried token). Side 0 holds a
// reconnect token from side 1; side 1 (or an old copy of it, side 2) sends
// tokens with chosen exps.

// reconnectTokenFrom mints a reconnect-sized deposit token from side s's
// mailbox (s may be the copy, which holds side 1's relay key) for side 0,
// expiring at exp.
func (f *r29Fx) reconnectTokenFrom(s int, exp time.Time, jti string) string {
	f.t.Helper()
	held := f.p(0).Relay // side 1's address on side 0's record
	tok, err := relayauth.MintToken(f.m(s).keys.relay, relayauth.Claims{Iss: held.Mailbox,
		Sub: relayauth.EncodeKey(f.m(0).keys.relay.Public().(ed25519.PublicKey)), Aud: held.URL,
		Iat: f.clk.Add(-time.Minute), Exp: exp, Jti: jti})
	if err != nil {
		f.t.Fatal(err)
	}
	return tok
}

// sendReconnectToken has side s send side 0 relay.token.issued{reconnect}.
func (f *r29Fx) sendReconnectToken(s int, tok string) {
	f.t.Helper()
	f.do(s, func(m *Manager, p *Peer) {
		m.sendTo(p, tokenIssuedType, json.RawMessage(peerwire.TokenIssuedBody(TokReconnect, tok)), f.clk)
	})
	if f.deliver(s, 0, kAny) == 0 {
		f.t.Fatal("setup: nothing delivered")
	}
}

func (f *r29Fx) auditedCount(s int, ev string) int {
	n := 0
	for _, a := range f.m(s).st.Audit {
		if a.Event == ev {
			n++
		}
	}
	return n
}

func TestReconnectTokenAdoptedOnlyIfLater(t *testing.T) {
	t.Run("later is adopted", func(t *testing.T) {
		f := newR29Fx(t)
		held := f.p(0).Reconnect
		tok := f.reconnectTokenFrom(1, held.Exp.Add(24*time.Hour), "rc-later")
		f.sendReconnectToken(1, tok)
		if f.p(0).Reconnect.Token != tok {
			t.Fatal("a reconnect token with a later exp was not adopted")
		}
		if f.audited(0, "issued_token_not_newer") {
			t.Fatal("a later token audited as refused")
		}
	})
	t.Run("earlier is refused", func(t *testing.T) {
		f := newR29Fx(t)
		held := f.p(0).Reconnect
		tok := f.reconnectTokenFrom(1, held.Exp.Add(-24*time.Hour), "rc-earlier")
		f.sendReconnectToken(1, tok)
		if f.p(0).Reconnect != held {
			t.Fatal("a reconnect token with an earlier exp replaced the held one")
		}
		if f.auditedCount(0, "issued_token_not_newer") != 1 {
			t.Fatal("the refusal was not audited")
		}
	})
	t.Run("same exp is refused", func(t *testing.T) {
		f := newR29Fx(t)
		held := f.p(0).Reconnect
		tok := f.reconnectTokenFrom(1, held.Exp, "rc-same")
		f.sendReconnectToken(1, tok)
		if f.p(0).Reconnect != held {
			t.Fatal("a reconnect token with the same exp replaced the held one")
		}
	})
	t.Run("exp in the past is refused", func(t *testing.T) {
		f := newR29Fx(t)
		held := f.p(0).Reconnect
		if !f.clk.Before(held.Exp) {
			t.Fatal("setup: the held token is not valid")
		}
		tok := f.reconnectTokenFrom(1, f.clk.Add(-time.Hour), "rc-past")
		f.sendReconnectToken(1, tok)
		if f.p(0).Reconnect != held {
			t.Fatal("an expired reconnect token replaced the valid held one")
		}
		if noReconnectToken(f.p(0), f.clk) {
			t.Fatal("side 0 lost its valid reconnect token")
		}
	})
	t.Run("old copy cannot shorten it", func(t *testing.T) {
		f := newR29Fx(t)
		snap := f.snapshot(1)
		f.startCopy(1, snap)
		held := f.p(0).Reconnect
		// the copy holds side 1's relay key and the current epoch's keys
		tok := f.reconnectTokenFrom(2, f.clk.Add(time.Hour), "rc-copy")
		f.sendReconnectToken(2, tok)
		if f.p(0).Reconnect != held {
			t.Fatal("an old copy's shorter-lived reconnect token replaced the held one")
		}
		if f.auditedCount(0, "issued_token_not_newer") != 1 {
			t.Fatal("the refusal was not audited")
		}
	})
}
